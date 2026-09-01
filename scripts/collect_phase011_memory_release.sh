#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

exec cargo run -p edge-memory-harness --bin edge-phase011-memory-release -- collect "$@"
