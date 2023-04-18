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

# Download GeoIP DB.
# https://www.maxmind.com/en/account
TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"
wget -O GeoLite2-Country.mmdb.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
tar --wildcards -xzf GeoLite2-Country.mmdb.tar.gz GeoLite2-Country_*/GeoLite2-Country.mmdb
mv GeoLite2-Country_*/GeoLite2-Country.mmdb "$ROOT"
rm -rf "$TMP_DIR"

cd "$ROOT"

# Install composer deps.
#composer install --no-dev

# Build ZIP.
rm -rf dist/ww_auth_log.zip dist/ww_auth_log
mkdir -p dist/ww_auth_log
cp -rv \
  src \
  vendor \
  wp-ww_auth_log.php \
  LICENSE \
  GeoLite2-Country.mmdb \
  dist/ww_auth_log
cd dist
zip -r ww_auth_log.zip ww_auth_log
rm -rf ww_auth_log
