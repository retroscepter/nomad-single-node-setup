#!/bin/bash

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

if ! grep -E 'Ubuntu|Debian' /etc/os-release > /dev/null; then
  echo "This script can only be run on Ubuntu/Debian servers"
  exit 1
fi

echo "Checking for Docker installation"

if ! command -v docker &> /dev/null; then
  echo "Docker not found, installing..."

  for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    apt-get remove -y $pkg || true
  done

  apt-get update
  apt-get install -y ca-certificates curl

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list

  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  echo "Docker is already installed"
fi

echo "Setting up network settings"

echo "49152 65535" > /proc/sys/net/ipv4/ip_local_port_range

for setting in bridge-nf-call-arptables bridge-nf-call-ip6tables bridge-nf-call-iptables; do
  echo 1 > /proc/sys/net/bridge/$setting
done

cat <<EOF > /etc/sysctl.d/98-hashicorp-nomad.conf
net.bridge.bridge-nf-call-arptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOF

sysctl --system

echo "Checking for Nomad installation"

if ! command -v nomad &> /dev/null; then
  echo "Nomad not found, installing..."

  groupdel nomad || true
  userdel nomad || true

  apt-get update
  apt-get install -y wget gpg coreutils

  if ! test -f /usr/share/keyrings/hashicorp-archive-keyring.gpg; then
    wget -O- https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
  fi
  echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" > /etc/apt/sources.list.d/hashicorp.list
  apt-get update && apt-get install -y nomad
else
  echo "Nomad is already installed"
fi

echo "Creating Nomad users"

groupadd -r nomad || true
useradd --system --home /etc/nomad.d -s /bin/false -g nomad nomad || true

echo "Installing CNI plugins"

CNI_URL="https://github.com/containernetworking/plugins/releases/download/v1.0.0/cni-plugins-linux-$( [ $(uname -m) = aarch64 ] && echo arm64 || echo amd64)-v1.0.0.tgz"
curl -L -o cni-plugins.tgz "$CNI_URL"
mkdir -p /opt/cni/bin
tar -C /opt/cni/bin -xzf cni-plugins.tgz
rm cni-plugins.tgz

echo "Creating systemd unit file"

cat <<EOF > /etc/systemd/system/nomad.service
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

echo "Creating Nomad config files"

mkdir -p /opt/cni/bin /opt/nomad/{plugins,data} /etc/nomad.d
touch /etc/nomad.d/{nomad,server,client}.hcl

chmod 700 /etc/nomad.d
chown -R nomad:nomad /etc/nomad.d /opt/nomad

cat <<EOF > /etc/nomad.d/nomad.hcl
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

cat <<EOF > /etc/nomad.d/server.hcl
server {
  enabled = true
  bootstrap_expect = 1
}
EOF

cat <<EOF > /etc/nomad.d/client.hcl
client {
  enabled = true
  servers = ["127.0.0.1"]
  host_volume "traefik" {
    path = "/opt/traefik/data"
    read_only = false
  }
}
EOF

echo "Creating Traefik data dir"

mkdir -p /opt/traefik/data
chown -R nomad:nomad /opt/traefik/data

echo "Starting Nomad"

systemctl daemon-reload
systemctl unmask nomad
systemctl enable --now nomad

echo "Waiting for Nomad agent to be ready"

until nomad node status &> /dev/null; do
  echo "Nomad agent is not ready, waiting..."
  sleep 5
done

echo "Deploying Traefik"

mkdir -p ~/nomad

cat <<EOF > ~/nomad/traefik.nomad
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
        ports = ["admin", "http"]
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
          "--providers.nomad.endpoint.address=http://135.148.136.163:4646", ### IP to your nomad server
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