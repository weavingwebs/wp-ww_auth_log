#!/bin/bash

set -eux

# Run from the project root (assume same dir as this script).
ROOT="$(cd "$(dirname "$0")"; pwd -P)"
cd "$ROOT"

# Download GeoIP DB. @todo this no longer works, you must manually download it.
#curl -O http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
#gunzip --force GeoLite2-Country.mmdb.gz

# Install composer deps.
#composer install --no-dev

# Build ZIP.
rm -rf dist/ww_auth_log.zip dist/ww_auth_log
mkdir -p dist/ww_auth_log
rsync -r \
  --delete \
  --exclude=".idea" \
  --exclude=".git" \
  --exclude="build-release.sh" \
  --exclude="dist" \
  . \
  dist/ww_auth_log
cd dist
zip -r ww_auth_log.zip ww_auth_log
