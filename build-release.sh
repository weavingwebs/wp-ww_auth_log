#!/bin/bash

set -eux

# Run from the project root (assume same dir as this script).
ROOT="$(cd "$(dirname "$0")"; pwd -P)"
cd "$ROOT"

# Download GeoIP DB.
curl -O http://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.mmdb.gz
gunzip --force GeoLite2-Country.mmdb.gz

# Install composer deps.
composer install --no-dev

# Build ZIP.
rm dist/ww_auth_log.zip
zip -r \
  --exclude=".idea/*" \
  --exclude=".git/*" \
  --exclude="build-release.sh" \
  --exclude="dist/*" \
  dist/ww_auth_log.zip .
