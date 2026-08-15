#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64|aarch64) ;;
  *) echo "unsupported architecture: $(uname -m); supported: x86_64, aarch64" >&2; exit 2 ;;
esac

if ! command -v systemctl >/dev/null || ! systemctl --version >/dev/null 2>&1; then
  echo "systemd/systemctl is required" >&2
  exit 2
fi

if ! command -v ps >/dev/null || [ "$(ps -p 1 -o comm= 2>/dev/null)" != "systemd" ]; then
  echo "systemd must be PID 1" >&2
  exit 2
fi

if ! command -v getent >/dev/null || ! command -v useradd >/dev/null; then
  echo "getent and useradd are required for dedicated service account setup" >&2
  exit 2
fi

if command -v ss >/dev/null && ss -ltn | grep -F '127.0.0.1:9443' >/dev/null; then
  echo "Admin bind 127.0.0.1:9443 is already in use" >&2
  exit 1
fi

echo "preflight ok: architecture=$(uname -m) admin_bind=127.0.0.1:9443"
