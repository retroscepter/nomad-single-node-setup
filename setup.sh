#!/bin/bash

if [ "$(id -u)" != "0" ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

if ! grep -E 'Ubuntu|Debian' /etc/os-release >/dev/null; then
  echo "This script can only be run on Ubuntu/Debian servers"
  exit 1
fi

command_exists() {
  command -v "$@" >/dev/null 2>&1
}

get_ip() {
  # Try to get IPv4
  local ipv4=$(curl -4s https://ifconfig.io 2>/dev/null)

  if [ -n "$ipv4" ]; then
    echo "$ipv4"
  else
    # Try to get IPv6
    local ipv6=$(curl -6s https://ifconfig.io 2>/dev/null)
    if [ -n "$ipv6" ]; then
      echo "$ipv6"
    fi
  fi
}

format_ip_for_url() {
  local ip="$1"
  if echo "$ip" | grep -q ':'; then
    # IPv6
    echo "[${ip}]"
  else
    # IPv4
    echo "${ip}"
  fi
}

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

if command_exists docker; then
  echo "Docker already installed"
else
  curl -sSL https://get.docker.com | sh
fi

echo "Setting up network settings..."

echo "49152 65535" >/proc/sys/net/ipv4/ip_local_port_range

for setting in bridge-nf-call-arptables bridge-nf-call-ip6tables bridge-nf-call-iptables; do
  echo 1 >/proc/sys/net/bridge/$setting
done

cat <<EOF >/etc/sysctl.d/98-hashicorp-nomad.conf
net.bridge.bridge-nf-call-arptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sysctl --system

if ! command -v nomad &>/dev/null; then
  echo "Installing Nomad..."

  groupdel nomad >/dev/null 2>&1 || true
  userdel nomad >/dev/null 2>&1 || true

  apt-get update
  apt-get install -y wget gpg coreutils

  if ! test -f /usr/share/keyrings/hashicorp-archive-keyring.gpg; then
    wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  fi
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" >/etc/apt/sources.list.d/hashicorp.list
  apt-get update && apt-get install -y nomad
else
  echo "Nomad is already installed"
fi

echo "Installing CNI plugins..."

CNI_URL="https://github.com/containernetworking/plugins/releases/download/v1.0.0/cni-plugins-linux-$([ $(uname -m) = aarch64 ] && echo arm64 || echo amd64)-v1.0.0.tgz"
curl -L -o cni-plugins.tgz "$CNI_URL"
mkdir -p /opt/cni/bin
tar -C /opt/cni/bin -xzf cni-plugins.tgz
rm cni-plugins.tgz

echo "Creating systemd unit file..."

cat <<EOF >/etc/systemd/system/nomad.service
[Unit]
Description=Nomad
Documentation=https://www.nomadproject.io/docs/
Wants=network-online.target
After=network-online.target

[Service]
User=root
Group=root
ExecReload=/bin/kill -HUP \$MAINPID
ExecStart=/bin/nomad agent -config /etc/nomad.d
KillMode=process
KillSignal=SIGINT
LimitNOFILE=65536
LimitNPROC=infinity
Restart=on-failure
RestartSec=2
TasksMax=infinity
OOMScoreAdjust=-1000

[Install]
WantedBy=multi-user.target
EOF

echo "Creating Nomad config files..."

mkdir -p /opt/cni/bin /opt/nomad/{plugins,data} /etc/nomad.d
touch /etc/nomad.d/{nomad,server,client}.hcl

chmod 700 /etc/nomad.d
chown -R nomad:nomad /etc/nomad.d /opt/nomad

cat <<EOF >/etc/nomad.d/nomad.hcl
datacenter = "dc1"
bind_addr = "0.0.0.0"
data_dir = "/opt/nomad/data"
leave_on_interrupt = true
leave_on_terminate = true 
log_level = "INFO"
log_file = "/var/log/nomad.log"
log_rotate_bytes = 10485760
log_rotate_max_files = 5
EOF

cat <<EOF >/etc/nomad.d/server.hcl
server {
  enabled = true
  bootstrap_expect = 1
}
EOF

cat <<EOF >/etc/nomad.d/client.hcl
client {
  enabled = true
  servers = ["127.0.0.1"]
  host_volume "traefik" {
    path = "/opt/traefik/data"
    read_only = false
  }
}
EOF

echo "Creating Traefik data dir..."

mkdir -p /opt/traefik/data
chown -R nomad:nomad /opt/traefik/data

echo "Starting Nomad..."

systemctl daemon-reload
systemctl unmask nomad
systemctl enable --now nomad

echo "Waiting for Nomad agent to be ready..."

until [ ! -z "$(nomad node status 2>/dev/null)" ]; do
  sleep 5
done

echo "Deploying Traefik..."

mkdir -p ~/nomad

advertise_addr=$(get_ip)
formatted_addr=$(format_ip_for_url "$advertise_addr")

cat <<EOF >~/nomad/traefik.nomad
job "traefik" {
  datacenters = ["dc1"]
  type = "service"

  group "traefik" {
    count = 1

    network {
      mode = "bridge"

      port "http" {
        static = 80
      }
      port "https" {
        static = 443
      }
      port "admin" {
        static = 8080
      }
    }

    service {
      name = "traefik-http"
      provider = "nomad"
      port = "http"
    }

    service {
      name = "traefik-https"
      provider = "nomad"
      port = "https"
    }

    volume "traefik" {
      type = "host"
      read_only = false
      source = "traefik"
    }

    task "server" {
      driver = "docker"

      config {
        image = "traefik"
        ports = ["admin", "http", "https"]
        args = [
          "--api.dashboard=true",
          "--api.insecure=true",
          "--entrypoints.web.address=:${NOMAD_PORT_http}",
          "--entrypoints.websecure.address=:${NOMAD_PORT_https}",
          "--entrypoints.traefik.address=:${NOMAD_PORT_admin}",
          "--certificatesresolvers.letsencrypt.acme.email=youremail@example.com",
          "--certificatesresolvers.letsencrypt.acme.storage=/opt/traefik/data/acme.json",
          "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web",
          "--providers.nomad=true",
          "--providers.nomad.endpoint.address=http://${formatted_addr}:4646",
          "--log.level=DEBUG",
        ]
      }

      volume_mount {
        volume = "traefik"
        destination = "/opt/traefik/data"
        read_only = false
      }
    }
  }
}
EOF

nomad job run ~/nomad/traefik.nomad

echo ""
printf "${GREEN}Congratulations, Nomad is installed!${NC}\n"
printf "${YELLOW}Nomad UI is available at http://${formatted_addr}:4646${NC}\n"
printf "${YELLOW}Traefik UI is available at http://${formatted_addr}:8080${NC}\n\n"
echo ""
