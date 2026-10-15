//go:build linux

/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

package xrootd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kernel.org/pub/linux/libs/security/libcap/cap"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/test_utils"
)

// Look up a field, such as CapAmb, in the contents of /proc/<pid>/status
func procStatusField(t *testing.T, status string, field string) string {
	for _, line := range strings.Split(status, "\n") {
		if value, found := strings.CutPrefix(line, field+":"); found {
			return strings.TrimSpace(value)
		}
	}
	require.Failf(t, "missing status field", "%s not found in:\n%s", field, status)
	return ""
}

// Look up a capability mask, such as CapAmb, in the contents of /proc/<pid>/status
func procStatusCapMask(t *testing.T, status string, field string) uint64 {
	mask, err := strconv.ParseUint(procStatusField(t, status, field), 16, 64)
	require.NoError(t, err)
	return mask
}

// Verify that a privileged xrootd, launched as the unprivileged daemon user
// through libcap, holds CAP_NET_BIND_SERVICE as an ambient capability
// and has a bounding set limited to the capabilities it was granted
func TestPrivilegedLaunchGrantsNetBindService(t *testing.T) {
	test_utils.SkipUnlessPrivileged(t)
	uid, err := config.GetDaemonUID()
	if err != nil {
		t.Skipf("Unable to determine the daemon user: %v", err)
	}
	// Containers often lower the threshold so that 443 is unprivileged
	sysctl := filepath.Join(t.TempDir(), "ip_unprivileged_port_start")
	require.NoError(t, os.WriteFile(sysctl, []byte("1024\n"), 0644))
	t.Cleanup(daemon.SetUnprivilegedPortStartPathForTest(sysctl))
	if !daemon.ShouldGrantNetBindService("xrootd", 443) {
		t.Skip("Unable to grant CAP_NET_BIND_SERVICE")
	}

	// The daemon user must be able to run the fake xrootd
	// and write its status, but t.TempDir is accessible only to us
	binDir, err := os.MkdirTemp("", "TestPrivilegedLaunchGrantsNetBindService")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(binDir) })
	require.NoError(t, os.Chmod(binDir, 0755))
	statusPath := filepath.Join(binDir, "status")
	require.NoError(t, os.WriteFile(statusPath, nil, 0666))
	require.NoError(t, os.Chmod(statusPath, 0666))
	script := fmt.Sprintf("#!/bin/sh\nexec cat /proc/self/status > %s\n", statusPath)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "xrootd"), []byte(script), 0755))
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	launcher := PrivilegedXrootdLauncher{"xrootd", "/fake/xrootd.cfg", [2]int{-1, -1}, binDir, 443}
	launchCtx, _, err := launcher.Launch(ctx)
	require.NoError(t, err)
	select {
	case <-launchCtx.Done():
	case <-time.After(10 * time.Second):
		require.Fail(t, "timed out waiting for the fake xrootd to exit")
	}
	// The launcher cancels its context with a nil cause when the daemon succeeds
	require.Equal(t, context.Canceled, context.Cause(launchCtx))

	data, err := os.ReadFile(statusPath)
	require.NoError(t, err)
	status := string(data)
	want := uint64(1)<<cap.SETUID | uint64(1)<<cap.SETGID | uint64(1)<<cap.NET_BIND_SERVICE
	assert.Equal(t, strconv.Itoa(uid), strings.Fields(procStatusField(t, status, "Uid"))[0], "UID")
	assert.Equal(t, want, procStatusCapMask(t, status, "CapAmb"), "CapAmb")
	assert.Equal(t, want, procStatusCapMask(t, status, "CapBnd"), "CapBnd")
}
