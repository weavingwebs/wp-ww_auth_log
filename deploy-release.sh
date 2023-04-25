#!/bin/bash

set -eux

# Run from the project root (assume same dir as this script).
ROOT="$(cd "$(dirname "$0")"; pwd -P)"
cd "$ROOT"

# Load .env file.
if [ -f .env ]; then
  set -o allexport
  source .env
  set +o allexport
fi

# Build release.
./build-release.sh

# Deploy release.
rsync -Pz \
  dist/details.json dist/ww_auth_log.zip \
  "$DEPLOY_HOST":"$DEPLOY_PATH"
ssh "$DEPLOY_HOST" -C "$POST_DEPLOY_CMD"
