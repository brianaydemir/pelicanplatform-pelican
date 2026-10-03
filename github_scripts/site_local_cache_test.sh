#!/bin/bash -xe
#
# Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License.  You may
# obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This tests site-local cache mode, in which a cache runs without fully
# joining its configured federation: it neither registers with the registry
# nor advertises to the director.
#
# It starts a federation (director + registry + origin + cache) and a
# site-local cache, which shares the federation's exported settings,
# including its database and its cache's storage. It then checks that the
# site-local cache neither registered nor advertised, and that a public
# object can be downloaded through it.
#
# The test keeps to a temporary directory of its own, which it removes on
# exit, and its servers listen on ports that the OS picks, so that it can
# run alongside other tests.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# shellcheck source=github_scripts/e2e_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/e2e_common.sh"

require_binaries ./pelican ./pelican-server
setup_test_root site-local

export PELICAN_SERVER_ENABLEUI=false
export PELICAN_TLSSKIPVERIFY=true

# Give the registry OIDC client credentials, which this test never uses.
echo "placeholder-oidc-client-secret" > "${TEST_ROOT}/oidc-client-secret"
export PELICAN_OIDC_CLIENTID="placeholder-oidc-client-id"
export PELICAN_OIDC_CLIENTSECRETFILE="${TEST_ROOT}/oidc-client-secret"

ORIGIN_DIR="${TEST_ROOT}/origin"
mkdir -p "${ORIGIN_DIR}"
if [ "$(id -u)" -eq 0 ]; then
    chown xrootd: "${ORIGIN_DIR}"
fi

export PELICAN_ORIGIN_PORT=0
export PELICAN_ORIGIN_RUNLOCATION="${TEST_ROOT}/origin-run"
export PELICAN_ORIGIN_FEDERATIONPREFIX="/test"
export PELICAN_ORIGIN_STORAGEPREFIX="${ORIGIN_DIR}"
export PELICAN_ORIGIN_ENABLEDIRECTREADS=true
export PELICAN_ORIGIN_ENABLEPUBLICREADS=true
export PELICAN_ORIGIN_ENABLEVOMS=false
export PELICAN_REGISTRY_REQUIRECACHEAPPROVAL=false
export PELICAN_REGISTRY_REQUIREORIGINAPPROVAL=false

FED_CACHE_DATA="${TEST_ROOT}/cache-data"
mkdir -p "${FED_CACHE_DATA}"
chmod 777 "${FED_CACHE_DATA}"

export PELICAN_CACHE_PORT=0
export PELICAN_CACHE_RUNLOCATION="${TEST_ROOT}/cache-run"
export PELICAN_CACHE_STORAGELOCATION="${FED_CACHE_DATA}"

SITE_LOCAL_DIR="${TEST_ROOT}/site-local"
mkdir -p "${SITE_LOCAL_DIR}/config" "${SITE_LOCAL_DIR}/runtime"
chmod 755 "${SITE_LOCAL_DIR}"

# ---------------------------------------------------------------------------
# 1. Start the federation
# ---------------------------------------------------------------------------

echo "This is test content for site-local cache testing" > "${ORIGIN_DIR}/test_file.txt"

./pelican-server serve --module director --module registry --module origin --module cache -d &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "federation" "${PIDS[-1]}"
FED_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
FED_HOSTPORT="${FED_WEB_URL#https://}"
wait_for_healthy "${FED_WEB_URL}" "federation"

export PELICAN_FEDERATION_DIRECTORURL="${FED_WEB_URL}"
export PELICAN_FEDERATION_REGISTRYURL="${FED_WEB_URL}"

# ---------------------------------------------------------------------------
# 2. Start the site-local cache
# ---------------------------------------------------------------------------

# The site-local cache inherits the federation's exported settings, which
# take precedence over its configuration file, so the file sets only what
# the environment does not, or sets to the same value.
cat > "${SITE_LOCAL_DIR}/config/pelican.yaml" <<EOF
RuntimeDir: ${SITE_LOCAL_DIR}/runtime
Server:
  WebPort: 0
  EnableUI: false
Cache:
  Port: 0
  EnableSiteLocalMode: true
Federation:
  DirectorUrl: ${FED_WEB_URL}
  RegistryUrl: ${FED_WEB_URL}
EOF

# The exported PELICAN_RUNTIMEDIR would take precedence over the
# configuration file, and the address files must not collide.
PELICAN_RUNTIMEDIR="${SITE_LOCAL_DIR}/runtime" \
    ./pelican-server cache serve --config "${SITE_LOCAL_DIR}/config/pelican.yaml" -d &
PIDS+=($!)

wait_for_address_file "${SITE_LOCAL_DIR}/runtime/pelican.addresses" "site-local cache" "${PIDS[-1]}"
SITE_LOCAL_WEB_URL="$(read_address "${SITE_LOCAL_DIR}/runtime/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
SITE_LOCAL_CACHE_URL="$(read_address "${SITE_LOCAL_DIR}/runtime/pelican.addresses" CACHE_URL)"
wait_for_healthy "${SITE_LOCAL_WEB_URL}" "site-local cache"

# ---------------------------------------------------------------------------
# 3. Check that the site-local cache did not register with the registry
# ---------------------------------------------------------------------------

REGISTRY_RESPONSE="$(e2e_curl "${FED_WEB_URL}/api/v1.0/registry_ui/servers")"
echo "Registry servers: ${REGISTRY_RESPONSE}"

# Only the federation's cache should be registered.
REGISTERED_CACHES="$(echo "${REGISTRY_RESPONSE}" | grep -o '"is_cache":true' | wc -l)"
if [ "${REGISTERED_CACHES}" -ne 1 ]; then
    echo "TEST FAILED: Expected 1 cache in the registry, but found ${REGISTERED_CACHES}"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Check that the site-local cache did not advertise to the director
# ---------------------------------------------------------------------------

# Caches advertise periodically, so wait for at least one cycle.
sleep 8

DIRECTOR_ALL_RESPONSE="$(e2e_curl "${FED_WEB_URL}/api/v1.0/director_ui/servers")"
echo "Director servers: ${DIRECTOR_ALL_RESPONSE}"
DIRECTOR_CACHE_RESPONSE="$(e2e_curl "${FED_WEB_URL}/api/v1.0/director_ui/servers?server_type=Cache")"
echo "Director caches: ${DIRECTOR_CACHE_RESPONSE}"

# Only the federation's cache should be advertised. Count the caches in the
# filtered response, or in the unfiltered one if the former has none.
ADVERTISED_CACHES="$(echo "${DIRECTOR_CACHE_RESPONSE}" | grep -o '"type":"Cache"' | wc -l)"
if [ "${ADVERTISED_CACHES}" -eq 0 ]; then
    ADVERTISED_CACHES="$(echo "${DIRECTOR_ALL_RESPONSE}" | grep -o '"type":"Cache"' | wc -l)"
fi
if [ "${ADVERTISED_CACHES}" -ne 1 ]; then
    echo "TEST FAILED: Expected 1 cache advertised to the director, but found ${ADVERTISED_CACHES}"
    exit 1
fi

# ---------------------------------------------------------------------------
# 5. Download an object through the site-local cache
# ---------------------------------------------------------------------------

if ! ./pelican object get "pelican://${FED_HOSTPORT}/test/test_file.txt" "${TEST_ROOT}/output.txt" \
    -d -L "${TEST_ROOT}/get.log" \
    --cache "${SITE_LOCAL_CACHE_URL}" \
    || ! grep -q "HTTP Transfer was successful" "${TEST_ROOT}/get.log"; then
    cat "${TEST_ROOT}/get.log"
    echo "TEST FAILED: The download through the site-local cache did not succeed"
    exit 1
fi

if ! cmp "${ORIGIN_DIR}/test_file.txt" "${TEST_ROOT}/output.txt"; then
    echo "TEST FAILED: The downloaded object differs from the original"
    exit 1
fi

echo "TEST PASSED"
