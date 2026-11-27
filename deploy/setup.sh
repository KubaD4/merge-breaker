#!/usr/bin/env bash
# One-shot provisioning for a fresh Vultr Ubuntu 24.04 instance. Run as root:
#   bash deploy/setup.sh <public-hostname>        e.g. 203-0-113-10.sslip.io
set -euo pipefail
HOST="${1:?usage: setup.sh <hostname, e.g. 1-2-3-4.sslip.io>}"
APP=/opt/merge-breaker

apt-get update -y
apt-get install -y ca-certificates curl gnupg git python3-venv ufw debian-keyring debian-archive-keyring apt-transport-https

# Docker
if ! command -v docker >/dev/null; then curl -fsSL https://get.docker.com | sh; fi

# gVisor (runsc), registered as a Docker runtime. Opt in with MB_RUNTIME=runsc in .env
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y && apt-get install -y runsc
fi
runsc install || true
systemctl restart docker

# Caddy (automatic HTTPS)
if ! command -v caddy >/dev/null; then
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y && apt-get install -y caddy
fi
cat > /etc/caddy/Caddyfile <<CADDY
$HOST {
  reverse_proxy 127.0.0.1:8080 {
    flush_interval -1
  }
}
CADDY
systemctl restart caddy

# Firewall: only SSH + web
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable

# Containers may never reach the VM itself, private networks or the cloud metadata service
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  iptables -C DOCKER-USER -d $net -m conntrack --ctstate NEW -j DROP 2>/dev/null || iptables -I DOCKER-USER -d $net -m conntrack --ctstate NEW -j DROP
done

# App
cd $APP
python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
docker build -t merge-breaker-sandbox:latest sandbox/
cp deploy/merge-breaker.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now merge-breaker
systemctl restart merge-breaker
echo "Done: https://$HOST"
