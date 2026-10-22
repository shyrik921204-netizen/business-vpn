#!/bin/sh
# Installs or updates the Sane4ek agent. Files are uploaded to /tmp/sane4ek-build first.
set -e
PORT=47443
sudo mkdir -p /opt/sane4ek/build
sudo cp /tmp/sane4ek-build/agent.py /tmp/sane4ek-build/Dockerfile /opt/sane4ek/build/

sudo docker build -q -t sane4ek-agent /opt/sane4ek/build >/dev/null

if [ ! -f /opt/sane4ek/cert.pem ] || [ ! -f /opt/sane4ek/key.pem ]; then
  sudo docker run --rm -v /opt/sane4ek:/data --entrypoint openssl sane4ek-agent \
    req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 7300 \
    -subj "/CN=sane4ek" -keyout /data/key.pem -out /data/cert.pem 2>/dev/null
  sudo chmod 600 /opt/sane4ek/key.pem
fi

sudo docker rm -f sane4ek-agent >/dev/null 2>&1 || true
sudo docker run -d --restart always --log-driver none --name sane4ek-agent \
  -p $PORT:$PORT/tcp \
  -v /opt/sane4ek:/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  sane4ek-agent >/dev/null

# open the port if a host firewall is active
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q "Status: active"; then
  sudo ufw allow $PORT/tcp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1 && sudo firewall-cmd --state >/dev/null 2>&1; then
  sudo firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null 2>&1 && sudo firewall-cmd --reload >/dev/null 2>&1 || true
fi

echo "SANE4EK_CERT_BEGIN"
sudo cat /opt/sane4ek/cert.pem
echo "SANE4EK_CERT_END"
sudo rm -rf /tmp/sane4ek-build
