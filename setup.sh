#!/usr/bin/env bash
# dendri-server setup — fetch Rust dependencies
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
cargo fetch
echo "dendri-server: dependencies fetched."
