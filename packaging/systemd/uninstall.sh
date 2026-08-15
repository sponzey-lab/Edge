#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall must run as root" >&2
  exit 2
fi

systemctl disable --now sponzey-edge.service || true
rm -f /etc/systemd/system/sponzey-edge.service
rm -f /usr/local/bin/edge-proxy
systemctl daemon-reload
echo "Preserved /var/lib/sponzey-edge data and /etc/sponzey-edge config. Remove them manually only after backup verification."
