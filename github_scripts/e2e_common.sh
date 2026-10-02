# shellcheck shell=bash
#
# Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
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

# The setup, cleanup, and helpers that the end-to-end scripts in this
# directory share. Each script sources this file before doing anything else.
#
# Every wait has a deadline, and every request made with curl has a time
# limit, so that a server that hangs fails the test instead of stalling it.

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Stop the test unless each of the given binaries exists.
require_binaries() {
    local bin
    for bin in "$@"; do
        if [ ! -f "${bin}" ]; then
            echo "TEST FAILED: ${bin} does not exist in the current directory"
            exit 1
        fi
    done
}

# Create the test's temporary directory, TEST_ROOT, which is removed on
# exit, and point Pelican's files and ports into it.
setup_test_root() {
    # XRootD and the local cache limit the length of the paths to their
    # sockets, so keep this short.
    TEST_ROOT="$(mktemp -d "/tmp/pelican-$1.XXXXXX")"
    trap cleanup EXIT
    # The xrootd user must be able to reach the directories that XRootD
    # uses.
    chmod 755 "${TEST_ROOT}"

    # Keep Pelican's files and ports apart from those of other tests. Run as
    # root, Pelican would otherwise use system-wide paths, such as
    # /etc/pelican and /var/lib/pelican.
    export PELICAN_CONFIG="${TEST_ROOT}/pelican.yaml"
    export PELICAN_CONFIGBASE="${TEST_ROOT}/config"
    export PELICAN_RUNTIMEDIR="${TEST_ROOT}/runtime"
    export PELICAN_SERVER_DBLOCATION="${TEST_ROOT}/pelican.sqlite"
    export PELICAN_SERVER_DATABASEBACKUP_LOCATION="${TEST_ROOT}/backups"
    export PELICAN_MONITORING_DATALOCATION="${TEST_ROOT}/monitoring"
    export PELICAN_SERVER_WEBPORT=0
    touch "${PELICAN_CONFIG}"
    mkdir -p "${PELICAN_CONFIGBASE}" "${PELICAN_RUNTIMEDIR}"
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# The PIDs of the servers that the test starts.
PIDS=()

# Print the PIDs of a process, its children, and its grandchildren, such as
# the XRootD processes that a Pelican server starts.
tree_pids() {
    local child
    echo "$1"
    for child in $(pgrep -P "$1" || true); do
        echo "${child}"
        pgrep -P "${child}" || true
    done
}

# Succeed if a process has exited.
has_exited() {
    ! kill -0 "$1" 2>/dev/null
}

# Stop a process and its descendants. Send SIGINT first, so that Pelican can
# shut down cleanly, and then SIGKILL to whatever remains after 10 seconds.
# XRootD would keep running if only its parent were killed.
stop_tree() {
    local pids
    pids="$(tree_pids "$1")"
    kill -INT "$1" 2>/dev/null || true
    retry_for 10 0.5 has_exited "$1" || true
    # shellcheck disable=SC2086
    kill -9 ${pids} 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

# shellcheck disable=SC2329  # invoked indirectly via trap
cleanup() {
    local pid
    for pid in "${PIDS[@]}"; do
        stop_tree "${pid}"
    done
    rm -rf "${TEST_ROOT}"
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Run curl quietly, without verifying the servers' certificates, and with a
# time limit, so that a server that accepts a connection but never answers
# can't stall the test.
e2e_curl() {
    curl --connect-timeout 5 --max-time 10 -k -s "$@"
}

# Usage: retry_for SECONDS INTERVAL COMMAND [ARG...]
#
# Run a command until it succeeds, sleeping INTERVAL seconds between
# attempts, and return 1 if it has not succeeded after SECONDS seconds.
# Bash ignores errexit while running the command, so a function used as the
# command must return the status that it means to.
retry_for() {
    local deadline=$((SECONDS + $1)) interval="$2"
    shift 2
    until "$@"; do
        if [ "${SECONDS}" -ge "${deadline}" ]; then
            return 1
        fi
        sleep "${interval}"
    done
}

# Succeed if a server has written its address file, and stop the test if
# the server has exited.
address_file_written() {
    local file="$1" label="$2" pid="$3"
    if [ -f "${file}" ]; then
        return 0
    fi
    if has_exited "${pid}"; then
        echo "TEST FAILED: The ${label} exited before writing its address file"
        exit 1
    fi
    return 1
}

# Wait up to 30 seconds for a server to write its address file.
wait_for_address_file() {
    local file="$1" label="$2" pid="$3"
    echo "Waiting for the ${label} to write its address file: ${file}"
    if ! retry_for 30 0.5 address_file_written "${file}" "${label}" "${pid}"; then
        echo "TEST FAILED: The ${label} did not write its address file within 30 seconds"
        exit 1
    fi
}

# Print the value of a key in an address file. Reading it this way, rather
# than sourcing it, keeps one server's addresses from replacing another's.
read_address() {
    local value
    value="$(sed -n "s/^$2=//p" "$1")"
    if [ -z "${value}" ]; then
        echo "TEST FAILED: $1 has no $2" >&2
        return 1
    fi
    echo "${value}"
}

# Succeed if a server's health check does.
is_healthy() {
    [ "$(e2e_curl -o /dev/null -w "%{http_code}" "$1/api/v1.0/health")" = "200" ]
}

# Wait up to 30 seconds for a server's health check to succeed.
wait_for_healthy() {
    local url="$1" label="$2"
    echo "Waiting for the ${label} to become healthy: ${url}/api/v1.0/health"
    if ! retry_for 30 0.5 is_healthy "${url}"; then
        echo "TEST FAILED: The ${label} did not become healthy within 30 seconds"
        exit 1
    fi
}
