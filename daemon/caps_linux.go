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
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// The sysctl holding the lowest port that can be bound
// without CAP_NET_BIND_SERVICE; a variable so that tests can override it
var unprivilegedPortStartPath = "/proc/sys/net/ipv4/ip_unprivileged_port_start"

// Point the check for privileged ports at a fake sysctl,
// returning a function that restores the real one.
// This is for tests in other packages.
func SetUnprivilegedPortStartPathForTest(path string) (restore func()) {
	orig := unprivilegedPortStartPath
	unprivilegedPortStartPath = path
	return func() { unprivilegedPortStartPath = orig }
}

// Determine whether binding to the given port requires CAP_NET_BIND_SERVICE.
// Port 0 lets the kernel pick an (unprivileged) ephemeral port.
func portNeedsNetBindService(port int) bool {
	if port <= 0 {
		return false
	}
	// Kernels older than 4.11 lack the sysctl and always use 1024
	start := 1024
	if data, err := os.ReadFile(unprivilegedPortStartPath); err == nil {
		if value, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
			start = value
		}
	}
	return port < start
}

// Determine whether this process can pass CAP_NET_BIND_SERVICE on to a child
// as an ambient capability, returning an error that explains why not.
// The checks mirror what the child does between fork and exec,
// where any failure aborts the launch.
// Set needKeepCaps if the child must be able to set PR_SET_KEEPCAPS,
// as with syscall.SysProcAttr.AmbientCaps;
// libcap's cap.Launcher ignores a failure to set it.
func checkNetBindServiceGrantable(needKeepCaps bool) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = errors.Errorf("unable to determine the process's capabilities: %v", rec)
		}
	}()

	if _, err := cap.GetAmbient(cap.NET_BIND_SERVICE); err != nil {
		return errors.Wrap(err, "the kernel does not support ambient capabilities")
	}
	secbits := cap.GetSecbits()
	if secbits&cap.SecbitNoCapAmbientRaise != 0 {
		return errors.New("the process's securebits forbid raising ambient capabilities")
	}
	if needKeepCaps && secbits&cap.SecbitKeepCapsLocked != 0 {
		return errors.New("the process's securebits forbid setting PR_SET_KEEPCAPS")
	}

	if permitted, err := cap.GetProc().GetFlag(cap.Permitted, cap.NET_BIND_SERVICE); err != nil {
		return err
	} else if !permitted {
		return errors.New("the process does not hold the capability")
	}
	// A capability outside the bounding set cannot be made inheritable,
	// which is a prerequisite for making it ambient
	if bound, err := cap.GetBound(cap.NET_BIND_SERVICE); err != nil {
		return err
	} else if !bound {
		return errors.New("the capability is not in the process's bounding set")
	}
	return nil
}

// Determine whether the named daemon, which listens on the given port,
// should be granted CAP_NET_BIND_SERVICE:
// that is, whether binding to the port requires the capability
// and this process can pass it on.
// See checkNetBindServiceGrantable for needKeepCaps.
func shouldGrantNetBindService(daemonName string, port int, needKeepCaps bool) bool {
	if !portNeedsNetBindService(port) {
		return false
	}
	if err := checkNetBindServiceGrantable(needKeepCaps); err != nil {
		log.Warningf("Daemon %q may be unable to listen on privileged port %d because it cannot be granted "+
			"CAP_NET_BIND_SERVICE: %v", daemonName, port, err)
		return false
	}
	log.Infof("Will launch daemon %q with CAP_NET_BIND_SERVICE so that it can listen on port %d", daemonName, port)
	return true
}

// Determine whether the named daemon, which listens on the given port
// and is launched by libcap's cap.Launcher,
// should be granted CAP_NET_BIND_SERVICE.
func ShouldGrantNetBindService(daemonName string, port int) bool {
	return shouldGrantNetBindService(daemonName, port, false)
}

// Pass CAP_NET_BIND_SERVICE on to the daemon as an ambient capability,
// if it should have it, so that it retains the capability
// across the switch to an unprivileged user.
func grantNetBindService(cmd *exec.Cmd, daemonName string, port int) {
	if !shouldGrantNetBindService(daemonName, port, true) {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, unix.CAP_NET_BIND_SERVICE)
}
