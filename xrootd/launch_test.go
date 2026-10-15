//go:build !windows

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/daemon"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

// writeCertWithEKUs generates a self-signed PEM certificate with the given
// extended key usages, writes it to a temp file inside dir, and returns its path.
func writeCertWithEKUs(t *testing.T, dir string, ekus []x509.ExtKeyUsage) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	f, err := os.CreateTemp(dir, "cert-*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}))
	require.NoError(t, f.Close())
	return f.Name()
}

// TestMakeUnprivilegedXrootdLauncher_DisableClientX509 verifies that
// makeUnprivilegedXrootdLauncher correctly sets the XRD_CURLDISABLEX509
// environment variable, and that it returns a fatal error when
// Cache.DisableClientX509 is false and the configured cert is missing the
// clientAuth EKU.
func TestMakeUnprivilegedXrootdLauncher_DisableClientX509(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	tests := []struct {
		name              string
		disableClientX509 bool
		// certEKUs is the EKU set written into the temp cert.  When nil and
		// disableClientX509 is false, no cert path is configured.
		certEKUs    []x509.ExtKeyUsage
		wantEnvVar  bool   // expect XRD_CURLDISABLEX509=1 in ExtraEnv
		wantErr     bool   // expect makeUnprivilegedXrootdLauncher to return an error
		errContains string // substring the error message should contain
	}{
		{
			name:              "param true (default): sets XRD_CURLDISABLEX509=1, no error",
			disableClientX509: true,
			wantEnvVar:        true,
			wantErr:           false,
		},
		{
			name:              "param false, cert has clientAuth and serverAuth: no env var, no error",
			disableClientX509: false,
			certEKUs:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			wantEnvVar:        false,
			wantErr:           false,
		},
		{
			name:              "param false, cert has only serverAuth (typical Let's Encrypt): fatal error",
			disableClientX509: false,
			certEKUs:          []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			wantEnvVar:        false,
			wantErr:           true,
			errContains:       "clientAuth Extended Key Usage",
		},
		{
			name:              "param false, no cert configured: no env var, no error",
			disableClientX509: false,
			certEKUs:          nil,
			wantEnvVar:        false,
			wantErr:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			t.Cleanup(func() {
				// Reset global FD state written by makeUnprivilegedXrootdLauncher.
				g_cache_fds = [2]int{-1, -1}
				server_utils.ResetTestState()
			})

			runDir := t.TempDir()
			require.NoError(t, param.Cache_RunLocation.Set(runDir))
			require.NoError(t, param.Server_DropPrivileges.Set(false))
			require.NoError(t, param.Cache_DisableClientX509.Set(tc.disableClientX509))

			if !tc.disableClientX509 && tc.certEKUs != nil {
				certPath := writeCertWithEKUs(t, runDir, tc.certEKUs)
				require.NoError(t, param.Server_TLSCertificateChain.Set(certPath))
			}

			launcher, err := makeUnprivilegedXrootdLauncher("xrootd", runDir, "/fake/xrootd.cfg", true)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() {
				syscall.Close(launcher.fds[0])
				syscall.Close(launcher.fds[1])
			})

			if tc.wantEnvVar {
				assert.True(t, slices.Contains(launcher.ExtraEnv, "XRD_CURLDISABLEX509=1"),
					"expected XRD_CURLDISABLEX509=1 in ExtraEnv; got: %v", launcher.ExtraEnv)
			} else {
				assert.False(t, slices.Contains(launcher.ExtraEnv, "XRD_CURLDISABLEX509=1"),
					"expected XRD_CURLDISABLEX509=1 to be absent; got: %v", launcher.ExtraEnv)
			}
		})
	}
}

// TestConfigureLaunchers_ListenPort verifies that both kinds of launchers
// give xrootd, but not cmsd, the configured port, which determines whether
// the daemon is granted CAP_NET_BIND_SERVICE.
func TestConfigureLaunchers_ListenPort(t *testing.T) {
	t.Cleanup(test_utils.SetupTestLogging(t))

	listenPort := func(t *testing.T, launcher daemon.Launcher) int {
		switch l := launcher.(type) {
		case PrivilegedXrootdLauncher:
			return l.listenPort
		case UnprivilegedXrootdLauncher:
			return l.ListenPort
		}
		require.Failf(t, "unexpected launcher type", "%T", launcher)
		return 0
	}

	// Caches never use the privileged launcher
	tests := []struct {
		privileged  bool
		enableCache bool
	}{
		{false, false},
		{false, true},
		{true, false},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("privileged=%t,cache=%t", tc.privileged, tc.enableCache), func(t *testing.T) {
			server_utils.ResetTestState()
			var launchers []daemon.Launcher
			t.Cleanup(func() {
				// Close the FDs held in globals by ConfigureLaunchers,
				// plus those of the privileged cmsd, which it does not
				// save anywhere.
				setOriginFds([2]int{-1, -1})
				setCacheFds([2]int{-1, -1})
				for _, launcher := range launchers {
					if l, ok := launcher.(PrivilegedXrootdLauncher); ok && l.daemonName == "cmsd" {
						closePairFds(l.fds)
					}
				}
				server_utils.ResetTestState()
			})

			runDir := t.TempDir()
			require.NoError(t, param.Origin_RunLocation.Set(runDir))
			require.NoError(t, param.Cache_RunLocation.Set(runDir))
			require.NoError(t, param.Server_DropPrivileges.Set(false))
			require.NoError(t, param.Cache_DisableClientX509.Set(true))
			require.NoError(t, param.Origin_Port.Set(443))
			require.NoError(t, param.Cache_Port.Set(444))
			wantPort := 443
			if tc.enableCache {
				wantPort = 444
			}

			var err error
			launchers, err = ConfigureLaunchers(tc.privileged, "/fake/xrootd.cfg", true, tc.enableCache)
			require.NoError(t, err)
			require.Len(t, launchers, 2)
			assert.Equal(t, wantPort, listenPort(t, launchers[0]), "xrootd port")
			assert.Equal(t, 0, listenPort(t, launchers[1]), "cmsd port")
		})
	}
}
