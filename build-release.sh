#!/bin/bash

set -eu

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
composer install --no-dev

# Build plugin directory.
rm -rf dist/ww_auth_log.zip dist/ww_auth_log
mkdir -p dist/ww_auth_log
cp -rv \
  src \
  vendor \
  wp-ww_auth_log.php \
  LICENSE \
  GeoLite2-Country.mmdb \
  dist/ww_auth_log

# Write details.json.
DETAILS_JSON='{
 	"name" : "WW Auth Log",
 	"version" : "",
 	"download_url" : "https:\/\/www.weavingwebs.co.uk\/wordpress-plugins\/ww_auth_log\/ww_auth_log.zip",
	"requires" : "5.8",
	"tested" : "6.2.0",
	"requires_php" : "7.0",
	"last_updated" : "",
 	"sections" : {
 		"description" : "<h2>Weaving Webs Additional Security.</h2>This is for Weaving Webs Hosted Customers Only."
 	}
}'
# i.e. 2024-06-06 09:00:00
LAST_UPDATED=$(date +'%Y-%m-%d %H:%M:%S')
VERSION=$(grep '* Version: ' "$ROOT"/wp-ww_auth_log.php | cut -d' ' -f3)
echo "$DETAILS_JSON" | jq \
  --arg last_updated "$LAST_UPDATED" \
  --arg version "$VERSION" \
  '.version = $version |
  .last_updated = $last_updated' \
  > "$ROOT"/dist/details.json

echo "Wrote details.json (version: $VERSION)"
