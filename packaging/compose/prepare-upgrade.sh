#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Compose upgrade preparation must run as root" >&2; exit 2; }

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -o root -g root -m 0755 /etc/sponzey-edge/compose
install -d -o root -g root -m 0755 /usr/local/libexec/sponzey-edge
install -o root -g root -m 0644 "$package_dir/docker-compose.yml" /etc/sponzey-edge/compose/docker-compose.yml
install -o root -g root -m 0644 "$package_dir/docker-compose.upgrade.yml" /etc/sponzey-edge/compose/docker-compose.upgrade.yml
install -o root -g root -m 0755 "$package_dir/compose-upgrade-helper" /usr/local/libexec/sponzey-edge/compose-upgrade-helper
