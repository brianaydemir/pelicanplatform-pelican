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

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/pelicanplatform/pelican/test_utils"
)

// Point portNeedsNetBindService at a fake sysctl with the given contents,
// or at a missing file if contents is empty
func setUnprivilegedPortStart(t *testing.T, contents string) {
	path := filepath.Join(t.TempDir(), "ip_unprivileged_port_start")
	if contents != "" {
		require.NoError(t, os.WriteFile(path, []byte(contents+"\n"), 0644))
	}
	t.Cleanup(SetUnprivilegedPortStartPathForTest(path))
}

func TestPortNeedsNetBindService(t *testing.T) {
	tests := []struct {
		name   string
		sysctl string
		port   int
		want   bool
	}{
		{"ephemeral port", "1024", 0, false},
		{"privileged port", "1024", 443, true},
		{"highest privileged port", "1024", 1023, true},
		{"unprivileged port", "1024", 8443, false},
		{"lowered threshold", "0", 443, false},
		{"raised threshold", "10000", 8443, true},
		{"missing sysctl, privileged port", "", 443, true},
		{"missing sysctl, unprivileged port", "", 1024, false},
		{"unparsable sysctl", "bogus", 443, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setUnprivilegedPortStart(t, tc.sysctl)
			assert.Equal(t, tc.want, portNeedsNetBindService(tc.port))
		})
	}
}

func TestGrantNetBindService(t *testing.T) {
	setUnprivilegedPortStart(t, "1024")
	grantable := checkNetBindServiceGrantable(true) == nil

	t.Run("unprivileged port", func(t *testing.T) {
		cmd := exec.Command("true")
		grantNetBindService(cmd, "test", 8443)
		assert.Nil(t, cmd.SysProcAttr)
	})

	t.Run("privileged port", func(t *testing.T) {
		cred := &syscall.Credential{Uid: 65534, Gid: 65534}
		cmd := exec.Command("true")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
		grantNetBindService(cmd, "test", 443)
		assert.Same(t, cred, cmd.SysProcAttr.Credential)
		if grantable {
			assert.Equal(t, []uintptr{unix.CAP_NET_BIND_SERVICE}, cmd.SysProcAttr.AmbientCaps)
		} else {
			assert.Empty(t, cmd.SysProcAttr.AmbientCaps)
		}
	})
}

// Verify that a daemon launched as an unprivileged user
// really does hold CAP_NET_BIND_SERVICE as an ambient capability
func TestGrantNetBindServiceLaunch(t *testing.T) {
	// Switching to an unprivileged user requires CAP_SETUID and CAP_SETGID
	test_utils.SkipUnlessPrivileged(t)
	if err := checkNetBindServiceGrantable(true); err != nil {
		t.Skipf("Unable to grant CAP_NET_BIND_SERVICE: %v", err)
	}
	setUnprivilegedPortStart(t, "1024")

	cmd := exec.Command("cat", "/proc/self/status")
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	grantNetBindService(cmd, "test", 443)
	output, err := cmd.Output()
	require.NoError(t, err)

	var ambient uint64
	for _, line := range strings.Split(string(output), "\n") {
		if value, found := strings.CutPrefix(line, "CapAmb:"); found {
			ambient, err = strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			require.NoError(t, err)
		}
	}
	assert.Equal(t, uint64(1)<<unix.CAP_NET_BIND_SERVICE, ambient)
}
