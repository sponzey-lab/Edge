#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "uninstall must run as root" >&2
  exit 2
fi

systemctl disable --now sponzey-edge.service || true
rm -f /etc/systemd/system/sponzey-edge.service
rm -f /usr/local/bin/edge-proxy
rm -f /usr/local/libexec/sponzey-edge/upgrade-helper
rmdir /usr/local/libexec/sponzey-edge 2>/dev/null || true
systemctl daemon-reload
echo "Preserved /var/lib/sponzey-edge data and /etc/sponzey-edge config. Remove them manually only after backup verification."
