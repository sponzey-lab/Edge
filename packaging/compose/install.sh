#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Compose upgrade helper install must run as root" >&2; exit 2; }
[ "$#" -eq 4 ] && [ "$1" = "--image-tag" ] && [ "$3" = "--image-digest" ] || { echo "usage: install.sh --image-tag vMAJOR.MINOR.PATCH --image-digest SHA256" >&2; exit 2; }
case "$2" in v[0-9]*.[0-9]*.[0-9]*) ;; *) echo "invalid image tag" >&2; exit 2 ;; esac
digest=${4#sha256:}
[ "${#digest}" -eq 64 ] || { echo "invalid image digest" >&2; exit 2; }
case "$digest" in *[!0123456789abcdef]*|'') echo "invalid image digest" >&2; exit 2 ;; esac

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install -d -o root -g root -m 0755 /etc/sponzey-edge/compose
install -d -o root -g root -m 0755 /usr/local/libexec/sponzey-edge
install -o root -g root -m 0644 "$package_dir/docker-compose.yml" /etc/sponzey-edge/compose/docker-compose.yml
install -o root -g root -m 0644 "$package_dir/docker-compose.upgrade.yml" /etc/sponzey-edge/compose/docker-compose.upgrade.yml
umask 077
printf 'SPONZEY_EDGE_TAG=%s\nSPONZEY_EDGE_DIGEST=%s\n' "$2" "$digest" > /etc/sponzey-edge/compose/runtime.env.tmp
chmod 0644 /etc/sponzey-edge/compose/runtime.env.tmp
mv /etc/sponzey-edge/compose/runtime.env.tmp /etc/sponzey-edge/compose/runtime.env
install -o root -g root -m 0755 "$package_dir/compose-upgrade-helper" /usr/local/libexec/sponzey-edge/compose-upgrade-helper
