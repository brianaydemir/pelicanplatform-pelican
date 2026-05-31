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

package test_utils

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/config/configtest"
	"github.com/pelicanplatform/pelican/logging"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
)

func TestContext(ictx context.Context, t testing.TB) (ctx context.Context, cancel context.CancelFunc, egrp *errgroup.Group) {
	type deadliner interface {
		Deadline() (time.Time, bool)
	}
	if d, ok := t.(deadliner); ok {
		if deadline, ok := d.Deadline(); ok {
			ctx, cancel = context.WithDeadline(ictx, deadline)
		} else {
			ctx, cancel = context.WithCancel(ictx)
		}
	} else {
		ctx, cancel = context.WithCancel(ictx)
	}
	egrp, ctx = errgroup.WithContext(ctx)
	ctx = context.WithValue(ctx, config.EgrpKey, egrp)
	return
}

// Creates a buffer of at least 1MB
func makeBigBuffer() []byte {
	byteBuff := []byte("Hello, World!")
	for {
		byteBuff = append(byteBuff, []byte("Hello, World!")...)
		if len(byteBuff) > 1024*1024 {
			break
		}
	}
	return byteBuff
}

// Writes a file at least the specified size in MB
func WriteBigBuffer(t *testing.T, fp io.WriteCloser, sizeMB int) (size int) {
	defer fp.Close()
	byteBuff := makeBigBuffer()
	size = 0
	for {
		n, err := fp.Write(byteBuff)
		require.NoError(t, err)
		size += n
		if size > sizeMB*1024*1024 {
			break
		}
	}
	return
}

// GenerateJWK generates an RSA JWK private key, its corresponding public JWKS,
// and the JSON-encoded public JWKS string.
func GenerateJWK() (jwk.Key, jwk.Set, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", err
	}

	jwkKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return nil, nil, "", err
	}
	_ = jwkKey.Set(jwk.KeyIDKey, "mykey")
	_ = jwkKey.Set(jwk.AlgorithmKey, "RS256")
	_ = jwkKey.Set(jwk.KeyUsageKey, "sig")

	publicKey, err := jwk.PublicKeyOf(jwkKey)
	if err != nil {
		return nil, nil, "", err
	}

	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		return nil, nil, "", err
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, nil, "", err
	}

	return jwkKey, jwks, string(jwksBytes), nil
}

func GenerateJWKS() (string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", errors.Wrap(err, "Error generating private key")
	}

	pKey, err := jwk.FromRaw(privateKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to convert ecdsa.PrivateKey to jwk.Key")
	}

	err = jwk.AssignKeyID(pKey)
	if err != nil {
		return "", errors.Wrap(err, "Error assigning kid to private key")
	}

	err = pKey.Set(jwk.AlgorithmKey, jwa.ES256)
	if err != nil {
		return "", errors.Wrap(err, "Unable to set algorithm for pKey")
	}

	publicKey, err := pKey.PublicKey()
	if err != nil {
		return "", errors.Wrap(err, "Unable to get the public key from private key")
	}

	jwks := jwk.NewSet()
	err = jwks.AddKey(publicKey)
	if err != nil {
		return "", errors.Wrap(err, "Unable to add public key to the jwks")
	}

	jsonData, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return "", errors.Wrap(err, "Unable to marshal the json into string")
	}
	jsonData = append(jsonData, '\n')

	return string(jsonData), nil
}

// RegistryMockup returns an HTTP test server that responds to registry
// lookups for prefix with a fixed jwks_uri. Each server is bound to one
// prefix; create a new one to switch prefixes.
func RegistryMockup(t *testing.T, prefix string) *httptest.Server {
	registryUrl, _ := url.Parse("https://registry.com:8446")
	path, err := url.JoinPath("/api/v1.0/registry", prefix, ".well-known/issuer.jwks")
	if err != nil {
		t.Fatalf("Failed to parse key path for prefix %s", prefix)
	}
	registryUrl.Path = path

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse := `{"jwks_uri": "` + registryUrl.String() + `"}`
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jsonResponse))
	}))
	t.Cleanup(server.Close)
	return server
}

// ClearFederationURLsForTest sets all five federation URL parameters
// to "" at viper's override priority, suppressing any values loaded from
// other config sources.
//
// InitClientForTest and InitServerForTest call this automatically.
//
// Call this directly only in tests that cannot import test_utils
// (e.g., tests in the config package, which would create an import cycle).
func ClearFederationURLsForTest(t testing.TB) {
	t.Helper()
	require.NoError(t, param.Federation_DiscoveryUrl.Set(""))
	// Federation_Director/Registry/Jwk/BrokerUrl are opaque params
	// with no typed setter; they must be set via param.Set.
	require.NoError(t, param.Set(param.Federation_DirectorUrl, ""))
	require.NoError(t, param.Set(param.Federation_RegistryUrl, ""))
	require.NoError(t, param.Set(param.Federation_JwkUrl, ""))
	require.NoError(t, param.Set(param.Federation_BrokerUrl, ""))
}

// applyInitCfg sets the parameters from initCfg using
// each param's typed setter where possible (StringParam, BoolParam, etc.),
// falling back to param.Set for opaque or unknown types.
// Panics from type mismatches are caught and reported as test failures.
func applyInitCfg(t *testing.T, caller string, initCfg map[param.Param]any) {
	t.Helper()
	for p, val := range initCfg {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: panic setting param %q to %v (%T): %v", caller, p.GetName(), val, val, r)
				}
			}()
			var err error
			switch tp := p.(type) {
			case param.StringParam:
				err = tp.Set(val.(string))
			case param.BoolParam:
				err = tp.Set(val.(bool))
			case param.IntParam:
				err = tp.Set(val.(int))
			case param.StringSliceParam:
				err = tp.Set(val.([]string))
			case param.DurationParam:
				switch v := val.(type) {
				case string:
					err = tp.SetString(v)
				case time.Duration:
					err = tp.SetString(v.String())
				default:
					t.Fatalf("%s: unsupported value type %T for DurationParam %q", caller, val, p.GetName())
				}
			default:
				err = param.Set(p, val)
			}
			require.NoError(t, err, "%s: failed to set param %q", caller, p.GetName())
		}()
	}
}

// InitClientForTest initializes the Pelican client for a unit test.
//
// It resets config, points ConfigDir at a temporary directory,
// shadows any system-wide pelican.yaml with an empty local one,
// clears federation URL overrides, provisions test-owned TLS files,
// and initializes the client.
//
// The initCfg map uses typed param constants as keys; values are set
// through the param's typed Set method where possible.
func InitClientForTest(t *testing.T, initCfg map[param.Param]any) {
	t.Helper()
	config.ResetConfig()
	t.Cleanup(config.ResetConfig)
	cfgDir := t.TempDir()
	require.NoError(t, param.ConfigDir.Set(cfgDir))

	// Pelican configures itself using the first `pelican.yaml` file
	// it finds, and ConfigDir is the first place it looks.
	// By writing an empty pelican.yaml into ConfigDir, Pelican will
	// never fall through to /etc/pelican/pelican.yaml.
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "pelican.yaml"), []byte{}, 0600))

	// InitClient merges OSDF defaults before reading pelican.yaml,
	// so clear federation URLs here to avoid live discovery lookups
	// during tests.
	ClearFederationURLsForTest(t)

	// Apply caller params before cert generation and InitClient
	// so that they can influence inputs such as Server.Hostname
	// and Client.IsPlugin.
	applyInitCfg(t, "InitClientForTest", initCfg)

	// Use localhost unless the caller chose a specific hostname.
	// The generated host cert must match the name later used for
	// TLS validation.
	if !param.Server_Hostname.IsSet() {
		require.NoError(t, param.Server_Hostname.Set("localhost"))
	}

	// GenerateCert writes the test CA and host cert to test-owned
	// paths, and InitClient must run afterward so its shared transport
	// trusts that CA.
	InitServerTLSForTest(t, cfgDir)
	require.NoError(t, config.GenerateCert())
	require.NoError(t, config.InitClient())

	// Re-apply caller params because InitClient may overwrite
	// some of them via SetClientDefaults.
	applyInitCfg(t, "InitClientForTest", initCfg)
}

// GetUniqueAvailablePorts returns count unique, available localhost ports.
// Warning: there is a brief window between identifying a port and the caller
// binding to it; another process may claim a port in that interval.
func GetUniqueAvailablePorts(count int) ([]int, error) {
	ports := make(map[int]struct{}, count)
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()

	for len(ports) < count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}

		addr := ln.Addr().(*net.TCPAddr)
		port := addr.Port

		if _, exists := ports[port]; exists {
			ln.Close()
			continue
		}

		ports[port] = struct{}{}
		listeners = append(listeners, ln)
	}

	portList := make([]int, 0, count)
	for port := range ports {
		portList = append(portList, port)
	}

	return portList, nil
}

// NewTLSServerForTest starts an HTTPS server with an ephemeral localhost leaf
// certificate signed by an already-provisioned test CA.
//
// The CA must already exist on disk: Server.TLSCACertificateFile and
// Server.TLSCAKey must be set, and both files must be present at those paths.
func NewTLSServerForTest(t testing.TB, handler http.Handler) *httptest.Server {
	t.Helper()
	return configtest.NewTLSServerForTest(t, handler)
}

// MockFederationRoot starts a TLS test server that serves federation
// discovery metadata and the issuer JWKS, then points discovery config at it.
//
// fInfo overrides individual fields of the default discovery response;
// nil uses built-in fake URLs for director, registry, and broker.
// kSet overrides the issuer key set; nil derives keys from IssuerKeysDirectory.
//
// Call this only after InitClientForTest or InitServerForTest, which set
// up the TLS paths, generate the CA, and establish client transport trust.
// Subsequent discovery lookups will use the mock server.
func MockFederationRoot(t *testing.T, fInfo *pelican_url.FederationDiscovery, kSet *jwk.Set) {
	// Clear any federation URL params already set in Viper
	// so that discoverFederationImpl does not short-circuit
	// and skip querying the mock.
	ClearFederationURLsForTest(t)

	var pKeySetInternal jwk.Set
	var err error
	if kSet == nil {
		keysDir := param.IssuerKeysDirectory.GetString()
		if keysDir == "" {
			keysDir = filepath.Join(t.TempDir(), "testKeyDir")
			require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))
		}
		pKeySetInternal, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock federation root")
	} else {
		pKeySetInternal = *kSet
	}
	kSetBytes, err := json.Marshal(pKeySetInternal)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock federation root")

	// Response values are resolved lazily (via getInternalFInfo)
	// so the server URL can be embedded in the discovery document.
	var getInternalFInfo func() pelican_url.FederationDiscovery
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("I only understand GET requests, but you sent me " + r.Method))
			require.NoError(t, err)
			return
		}

		path := r.URL.Path
		switch path {
		case "/.well-known/pelican-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)

			discoveryMetadata := pelican_url.FederationDiscovery{
				DiscoveryEndpoint:          getInternalFInfo().DiscoveryEndpoint,
				DirectorEndpoint:           getInternalFInfo().DirectorEndpoint,
				RegistryEndpoint:           getInternalFInfo().RegistryEndpoint,
				BrokerEndpoint:             getInternalFInfo().BrokerEndpoint,
				JwksUri:                    getInternalFInfo().JwksUri,
				DirectorAdvertiseEndpoints: getInternalFInfo().DirectorAdvertiseEndpoints,
			}

			discoveryJSONBytes, err := json.Marshal(discoveryMetadata)
			require.NoError(t, err, "Failed to marshal discovery metadata")
			_, err = w.Write(discoveryJSONBytes)
			require.NoError(t, err)
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(kSetBytes))
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("I don't understand this path: " + path))
			require.NoError(t, err)
		}
	}

	server := NewTLSServerForTest(t, http.HandlerFunc(responseHandler))
	serverUrl := server.URL
	getInternalFInfo = func() pelican_url.FederationDiscovery {
		internalFInfo := pelican_url.FederationDiscovery{
			DiscoveryEndpoint: serverUrl,
			DirectorEndpoint:  "https://fake-director.com",
			RegistryEndpoint:  "https://fake-registry.com",
			BrokerEndpoint:    "https://fake-broker.com",
			JwksUri:           fmt.Sprintf("%s/.well-known/issuer.jwks", serverUrl),
		}

		if fInfo != nil {
			if fInfo.DirectorEndpoint != "" {
				internalFInfo.DirectorEndpoint = fInfo.DirectorEndpoint
			}
			if fInfo.RegistryEndpoint != "" {
				internalFInfo.RegistryEndpoint = fInfo.RegistryEndpoint
			}
			if fInfo.BrokerEndpoint != "" {
				internalFInfo.BrokerEndpoint = fInfo.BrokerEndpoint
			}
			if fInfo.JwksUri != "" {
				internalFInfo.JwksUri = fInfo.JwksUri
			}
			if fInfo.DirectorAdvertiseEndpoints != nil {
				internalFInfo.DirectorAdvertiseEndpoints = fInfo.DirectorAdvertiseEndpoints
			}
		}
		return internalFInfo
	}

	require.NoError(t, param.Federation_DiscoveryUrl.Set(serverUrl))

	// Reset the cached discovery result so the next GetFederation call
	// queries this mock server rather than returning a cached result from
	// InitServerForTest's eager GetFederation call.
	config.ResetFederationForTest()
}

// MockIssuer starts an HTTP test server that answers OIDC discovery requests
// and returns the server URL for use as an issuer URL in tests.
//
// kSet overrides the issuer key set;
// nil generates a fresh key set in IssuerKeysDirectory.
func MockIssuer(t *testing.T, kSet *jwk.Set) string {
	var pKeySetInternal jwk.Set
	var err error
	if kSet == nil {
		keysDir := filepath.Join(t.TempDir(), "testKeyDir")
		require.NoError(t, param.IssuerKeysDirectory.Set(keysDir))
		pKeySetInternal, err = config.GetIssuerPublicJWKS()
		require.NoError(t, err, "Failed to load public JWKS while creating mock federation root")
	} else {
		pKeySetInternal = *kSet
	}
	kSetBytes, err := json.Marshal(pKeySetInternal)
	require.NoError(t, err, "Failed to marshal public JWKS while creating mock federation root")

	var getMyUrl func() string
	responseHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, err := w.Write([]byte("I only understand GET requests, but you sent me " + r.Method))
			require.NoError(t, err)
			return
		}

		path := r.URL.Path
		switch path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			OIDCConfig := fmt.Sprintf(`{"jwks_uri":"%s/.well-known/issuer.jwks"}`, getMyUrl())
			_, err = w.Write([]byte(OIDCConfig))
			require.NoError(t, err)
		case "/.well-known/issuer.jwks":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(kSetBytes)
			require.NoError(t, err)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write([]byte("I don't understand this path: " + path))
			require.NoError(t, err)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(responseHandler))
	serverUrl := server.URL
	getMyUrl = func() string {
		return serverUrl
	}

	t.Cleanup(server.Close)

	return serverUrl
}

// TestLogHook forwards log entries to the test log buffer so they appear under the
// test's output (visible with -v or on failure) and never hit stdout/stderr directly.
type TestLogHook struct {
	t testing.TB
}

var (
	globalLogBuffer   bytes.Buffer
	globalLogMu       sync.Mutex
	globalHookEnabled atomic.Bool
)

// globalBufferHook captures log entries emitted before any test runs —
// e.g., during package-level init — into a shared buffer so that they can
// be replayed under the first test's logger.
type globalBufferHook struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (h *globalBufferHook) Levels() []logrus.Level { return logrus.AllLevels }

func (h *globalBufferHook) Fire(entry *logrus.Entry) error {
	if !globalHookEnabled.Load() {
		return nil
	}
	if msg, err := entry.String(); err == nil {
		h.mu.Lock()
		h.buf.WriteString(msg)
		h.mu.Unlock()
	}
	return nil
}

// NewTestLogHook creates a TestLogHook that routes log entries into t's log buffer.
func NewTestLogHook(t testing.TB) *TestLogHook {
	return &TestLogHook{t: t}
}

func (hook *TestLogHook) Fire(entry *logrus.Entry) error {
	hook.t.Helper()
	hook.t.Log(formatEntry(entry))
	return nil
}

func (hook *TestLogHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

// SetupGlobalTestLogging redirects logrus output away from stdout/stderr
// for the duration of a test binary run.
// Intended for use in TestMain;
// the returned function restores the original configuration.
func SetupGlobalTestLogging() func() {
	originalOut := logrus.StandardLogger().Out
	originalHooks := logrus.StandardLogger().Hooks
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller
	globalHookEnabled.Store(true)

	globalLogMu.Lock()
	globalLogBuffer.Reset()
	globalLogMu.Unlock()

	logrus.SetOutput(&globalLogBuffer)
	logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	logrus.SetReportCaller(true)
	logrus.AddHook(&globalBufferHook{buf: &globalLogBuffer, mu: &globalLogMu})

	return func() {
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().ReplaceHooks(originalHooks)
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
	}
}

// SetupTestLogging redirects logrus output into t's log buffer
// for duration of the test.
// Use as: t.Cleanup(test_utils.SetupTestLogging(t)).
func SetupTestLogging(t testing.TB) func() {
	previousGlobalHookState := globalHookEnabled.Swap(false)
	originalOut := logrus.StandardLogger().Out
	originalHooks := logrus.StandardLogger().Hooks
	originalFormatter := logrus.StandardLogger().Formatter
	originalReportCaller := logrus.StandardLogger().ReportCaller

	// Flush any buffered pre-test logs into the hook (visible on failure).
	var bufferedLogs string
	globalLogMu.Lock()
	if globalLogBuffer.Len() > 0 {
		bufferedLogs = globalLogBuffer.String()
		globalLogBuffer.Reset()
	}
	globalLogMu.Unlock()

	// Reset hooks that config initialization might have added.
	config.ResetGlobalLoggingHooks()

	// Disable standard output and use only the test hook.
	logrus.SetOutput(io.Discard)
	logrus.StandardLogger().ReplaceHooks(make(logrus.LevelHooks))
	logrus.SetReportCaller(true)
	hook := NewTestLogHook(t)
	logrus.AddHook(hook)

	if strings.TrimSpace(bufferedLogs) != "" {
		hook.t.Helper()
		for _, line := range strings.Split(strings.TrimSuffix(bufferedLogs, "\n"), "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				hook.t.Log(trimmed)
			}
		}
	}

	return func() {
		logging.ResetGlobalManager()
		// Reset hooks so they don't fire during subsequent config initialization.
		config.ResetGlobalLoggingHooks()
		logrus.SetOutput(originalOut)
		logrus.StandardLogger().ReplaceHooks(originalHooks)
		logrus.SetFormatter(originalFormatter)
		logrus.SetReportCaller(originalReportCaller)
		globalHookEnabled.Store(previousGlobalHookState)
	}
}

// formatEntry turns a logrus entry into a concise string that includes caller information.
// This avoids the testing.T log location (which would otherwise point to the hook) and instead
// surfaces the originating call site to make test output readable.
func formatEntry(entry *logrus.Entry) string {
	loc := ""
	if entry.HasCaller() && entry.Caller != nil {
		loc = fmt.Sprintf("%s:%d: ", filepath.Base(entry.Caller.File), entry.Caller.Line)
	}

	var keys []string
	for k := range entry.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	msg := entry.Message
	if len(keys) > 0 {
		var fields []string
		for _, k := range keys {
			fields = append(fields, fmt.Sprintf("%s=%v", k, entry.Data[k]))
		}
		msg = fmt.Sprintf("%s [%s]", msg, strings.Join(fields, " "))
	}

	return fmt.Sprintf("%s %s%s %s", entry.Time.Format(time.RFC3339Nano), loc, entry.Level, msg)
}

// InitServerTLSForTest redirects all TLS key and certificate parameters
// to paths inside dir, isolating tests from host configuration.
// Call before any function that generates or reads TLS credentials.
func InitServerTLSForTest(t testing.TB, dir string) {
	t.Helper()
	configtest.InitServerTLSForTest(t, dir)
}

// InitServerForTest prepares a test-owned server configuration
// and calls config.InitServer.
// Must be called after ResetTestState.
//
// If the caller has not set param.ConfigDir,
// a fresh t.TempDir() is allocated and assigned to it.
//
// It writes an empty pelican.yaml into ConfigDir to shadow
// /etc/pelican/pelican.yaml, and clears all federation URL overrides.
//
// Unless the caller has already set Server.Hostname,
// this helper pins it to "localhost" so that generated TLS certificates
// and hostname validation are consistent.
//
// config.InitServer calls GetFederation eagerly; ErrNoDiscoveryEndpoint
// (returned when no federation URL is configured) is treated as a clean
// "no federation" state. Call MockFederationRoot afterward to add one.
func InitServerForTest(t testing.TB, ctx context.Context, serverType server_structs.ServerType) {
	t.Helper()

	// param.ConfigDir.GetString() always returns "" —
	// ConfigDir is a special internal key absent from parameters.yaml
	// and therefore absent from the typed string accessors.
	cfgDir := viper.GetString("ConfigDir")
	if cfgDir == "" {
		// Allocate an isolated ConfigDir on the caller's behalf
		// rather than silently writing pelican.yaml to the current
		// working directory.
		cfgDir = t.TempDir()
		require.NoError(t, param.ConfigDir.Set(cfgDir))
	}
	require.NoError(t, os.MkdirAll(cfgDir, 0700))

	// Pelican configures itself using the first `pelican.yaml` file
	// it finds, and ConfigDir is the first place it looks.
	// By writing an empty pelican.yaml into ConfigDir, Pelican will
	// never fall through to /etc/pelican/pelican.yaml.
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "pelican.yaml"), []byte{}, 0600))

	// However, the empty file is not sufficient on its own.
	//
	// InitConfigInternal (called by InitServer) first calls
	// SetBaseDefaultsInConfig, which merges osdf.yaml when the OSDF
	// prefix is active.
	//
	// That merge injects Federation.DiscoveryUrl = https://osg-htc.org
	// at config-file priority,
	// before our empty pelican.yaml is even read.
	//
	// Without clearing the federation URLs, any subsequent call
	// to GetFederation() would attempt a live HTTP discovery call to
	// osg-htc.org.
	ClearFederationURLsForTest(t)

	// Lock the hostname to "localhost" so that generated TLS certificates
	// match the hostname used for validation, unless the caller has already
	// chosen a specific hostname.
	// Without this, Pelican defaults to os.Hostname().
	if !param.Server_Hostname.IsSet() {
		require.NoError(t, param.Server_Hostname.Set("localhost"))
	}

	InitServerTLSForTest(t, cfgDir)
	err := config.InitServer(ctx, serverType)
	if errors.Is(err, config.ErrNoDiscoveryEndpoint) {
		config.SetFederation(pelican_url.FederationDiscovery{})
		return
	}
	require.NoError(t, err)
}

// GetTmpStoragePrefixDir returns a 0777 temporary directory suitable
// for use as an origin export StoragePrefix.
// The XRootD daemon process runs as a different user,
// so it requires world-readable, -writable, and -executable permissions.
func GetTmpStoragePrefixDir(t *testing.T) string {
	tmpDir := t.TempDir() + "/tmpdir"

	err := os.MkdirAll(tmpDir, 0777)
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	err = os.Chmod(tmpDir, 0777)
	if err != nil {
		t.Fatalf("Failed to set directory permissions: %v", err)
	}

	return tmpDir
}
