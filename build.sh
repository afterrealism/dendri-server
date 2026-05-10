#!/usr/bin/env bash
# dendri-server build
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
MODE="${1:-release}"
if [[ "$MODE" == "release" ]]; then
  cargo build --release
else
  cargo build
fi
echo "dendri-server: built ($MODE)."
