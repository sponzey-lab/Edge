#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install must run as root" >&2
  exit 2
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
archive_dir=$(dirname -- "$package_dir")
binary=${1:-"$archive_dir/edge-proxy"}
config=${2:-"$archive_dir/current.toml"}

"$package_dir/preflight.sh"

if [ ! -x "$binary" ] || [ ! -f "$config" ]; then
  echo "expected executable and current.toml at the archive root, or pass both paths" >&2
  exit 2
fi

if ! getent passwd edge >/dev/null; then
  useradd --system --home-dir /var/lib/sponzey-edge --create-home --shell /usr/sbin/nologin edge
fi

install -d -o edge -g edge -m 0750 /var/lib/sponzey-edge/data
install -d -o root -g root -m 0755 /etc/sponzey-edge
install -d -o root -g root -m 0755 /usr/local/libexec/sponzey-edge
install -o root -g root -m 0755 "$binary" /usr/local/bin/edge-proxy
install -o root -g root -m 0755 "$package_dir/upgrade-helper" /usr/local/libexec/sponzey-edge/upgrade-helper
install -o root -g root -m 0644 "$config" /etc/sponzey-edge/current.toml
install -o root -g root -m 0644 "$package_dir/sponzey-edge.service" /etc/systemd/system/sponzey-edge.service
systemctl daemon-reload
systemctl enable --now sponzey-edge.service
