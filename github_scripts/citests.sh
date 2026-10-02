#!/bin/bash -xe
#
# Copyright (C) 2024, University of Nebraska-Lincoln
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

# This tests stashcp and the HTCondor file transfer plugin against the real
# OSDF, both directly and through a local cache.
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
setup_test_root citests

# The pelican binary acts as stashcp or the plugin when run under that name.
mkdir -p "${TEST_ROOT}/bin"
cp ./pelican "${TEST_ROOT}/bin/stashcp"
cp ./pelican "${TEST_ROOT}/bin/stash_plugin"

OBJECT_URL="osdf:///pelicanplatform/test/hello-world.txt"

# The number of failed checks that did not stop the test.
FAILURES=0

# ---------------------------------------------------------------------------
# 1. Download an object with stashcp
# ---------------------------------------------------------------------------

"${TEST_ROOT}/bin/stashcp" -d "${OBJECT_URL}" "${TEST_ROOT}/stashcp-output"

# ---------------------------------------------------------------------------
# 2. Use the plugin interface
# ---------------------------------------------------------------------------

classad_output="$("${TEST_ROOT}/bin/stash_plugin" -classad)"

if [[ "${classad_output}" != *'PluginType = "FileTransfer"'* ]]; then
    echo "CHECK FAILED: PluginType is not in the classad output"
    FAILURES=$((FAILURES + 1))
fi

if [[ "${classad_output}" != *'SupportedMethods = "stash, osdf, pelican"'* ]]; then
    echo "CHECK FAILED: SupportedMethods is not in the classad output"
    FAILURES=$((FAILURES + 1))
fi

plugin_output="$("${TEST_ROOT}/bin/stash_plugin" "${OBJECT_URL}" "${TEST_ROOT}/plugin-output")"

if [[ "${plugin_output}" != *"TransferUrl = \"${OBJECT_URL}\""* ]]; then
    echo "CHECK FAILED: TransferUrl is not in the plugin output"
    FAILURES=$((FAILURES + 1))
fi

if [[ "${plugin_output}" != *"TransferSuccess = true"* ]]; then
    echo "CHECK FAILED: TransferSuccess is not in the plugin output"
    FAILURES=$((FAILURES + 1))
fi

cat > "${TEST_ROOT}/plugin-infile" <<EOF
[ LocalFileName = "${TEST_ROOT}/plugin-infile-output"; Url = "${OBJECT_URL}" ]
EOF

"${TEST_ROOT}/bin/stash_plugin" -infile "${TEST_ROOT}/plugin-infile" -outfile "${TEST_ROOT}/plugin-outfile"

# ---------------------------------------------------------------------------
# 3. Start a local cache in front of the OSDF
# ---------------------------------------------------------------------------

export PELICAN_SERVER_ENABLEUI=false
export PELICAN_LOCALCACHE_RUNLOCATION="${TEST_ROOT}/localcache"
export PELICAN_LOCALCACHE_SOCKET="${PELICAN_LOCALCACHE_RUNLOCATION}/cache.sock"
export PELICAN_LOCALCACHE_DATALOCATION="${PELICAN_LOCALCACHE_RUNLOCATION}/cache"

./pelican-server serve -d -f osg-htc.org --module localcache &
PIDS+=($!)

wait_for_address_file "${PELICAN_RUNTIMEDIR}/pelican.addresses" "local cache" "${PIDS[-1]}"
LOCAL_CACHE_WEB_URL="$(read_address "${PELICAN_RUNTIMEDIR}/pelican.addresses" SERVER_EXTERNAL_WEB_URL)"
wait_for_healthy "${LOCAL_CACHE_WEB_URL}" "local cache"

# The local cache opens its socket only after writing its address file.
if ! retry_for 10 0.5 test -e "${PELICAN_LOCALCACHE_SOCKET}"; then
    echo "TEST FAILED: The local cache did not open its socket within 10 seconds"
    exit 1
fi

# ---------------------------------------------------------------------------
# 4. Download an object through the local cache
# ---------------------------------------------------------------------------

# Print the HTTP status that the local cache returns for an object without
# fetching it.
cached_status() {
    e2e_curl -o /dev/null -w "%{http_code}" \
        --unix-socket "${PELICAN_LOCALCACHE_SOCKET}" \
        -H "Cache-Control: only-if-cached" \
        -X HEAD "http://localhost$1"
}

OBJECT_PATH="/pelicanplatform/test/hello-world.txt"

if [ "$(cached_status "${OBJECT_PATH}")" != "504" ]; then
    echo "TEST FAILED: The local cache did not return 504 before the first download"
    exit 1
fi

NEAREST_CACHE="unix://${PELICAN_LOCALCACHE_SOCKET}" \
    "${TEST_ROOT}/bin/stash_plugin" -d "${OBJECT_URL}" /dev/null

if [ "$(cached_status "${OBJECT_PATH}")" != "200" ]; then
    echo "TEST FAILED: The object is not in the local cache after the download"
    exit 1
fi

PELICAN_PREFFERREDCACHES="unix://${PELICAN_LOCALCACHE_SOCKET}" \
    "${TEST_ROOT}/bin/stash_plugin" -d "${OBJECT_URL}" /dev/null

if [ "$(cached_status "${OBJECT_PATH}")" != "200" ]; then
    echo "TEST FAILED: The object is not in the local cache after the second download"
    exit 1
fi

# ---------------------------------------------------------------------------
# 5. Run the plugin without a usable home directory
# ---------------------------------------------------------------------------

if ! env -u HOME "${TEST_ROOT}/bin/stash_plugin" -classad; then
    echo "CHECK FAILED: The plugin failed when HOME was unset"
    FAILURES=$((FAILURES + 1))
fi

mkdir "${TEST_ROOT}/unwritable-home"
chmod a-w "${TEST_ROOT}/unwritable-home"
if ! HOME="${TEST_ROOT}/unwritable-home" "${TEST_ROOT}/bin/stash_plugin" -classad; then
    echo "CHECK FAILED: The plugin failed when HOME was an unwritable directory"
    FAILURES=$((FAILURES + 1))
fi

if [ "${FAILURES}" -gt 0 ]; then
    echo "TEST FAILED: ${FAILURES} checks failed"
    exit 1
fi

echo "TEST PASSED"
