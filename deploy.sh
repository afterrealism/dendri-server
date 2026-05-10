#!/usr/bin/env bash
# dendri-server deploy — build Docker image and push
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
IMAGE="${1:-dendri/signal:latest}"
echo "Building $IMAGE ..."
podman build -t "$IMAGE" -f Dockerfile . 2>/dev/null || docker build -t "$IMAGE" -f Dockerfile .
echo "dendri-server: image built — $IMAGE"
echo ""
echo "To deploy to production:"
echo "  podman push $IMAGE <registry>"
echo "  OR: ssh into host and run:"
echo "    cd /opt/dendri/dendri-server && git pull && podman build -t dendri/signal:local . && systemctl restart dendri-signal"
