/***************************************************************
 *
 * Copyright (C) 2025, Pelican Project, Morgridge Institute for Research
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

package director

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/pelican_url"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/server_utils"
	"github.com/pelicanplatform/pelican/test_utils"
)

const (
	mockDirUrlWoPort = "https://example.director.com"
	mockDirUrlWPort  = "https://example.director.com:8444"

	mockRawDirUrlHTTP = "http://example.director.com"
	mockRawDirUrl443  = "https://example.director.com:443"

	mockRegUrlWoPort = "https://example.registry.com"
	mockRegUrlWPort  = "https://example.registry.com:8444"

	mockRawRegUrlHTTP = "http://example.registry.com"
	mockRawRegUrl443  = "https://example.registry.com:443"
)

func TestFederationDiscoveryHandler(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	router := gin.Default()
	router.GET("/test", federationDiscoveryHandler)

	tests := []struct {
		name        string
		dirUrl      string
		regUrl      string
		expectedDir string
		expectedReg string
		statusCode  int
	}{
		{
			name:        "reg-dir-without-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-non-443-port",
			dirUrl:      mockDirUrlWPort,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-443-port",
			dirUrl:      mockRawDirUrl443,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "dir-with-http",
			dirUrl:      mockRawDirUrlHTTP,
			regUrl:      mockRegUrlWoPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		// registry url tests
		{
			name:        "reg-with-non-443-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRegUrlWPort,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWPort,
			statusCode:  200,
		},
		{
			name:        "reg-with-443-port",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRawRegUrl443,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
		{
			name:        "reg-with-http",
			dirUrl:      mockDirUrlWoPort,
			regUrl:      mockRawRegUrlHTTP,
			expectedDir: mockDirUrlWoPort,
			expectedReg: mockRegUrlWoPort,
			statusCode:  200,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			fedInfo := pelican_url.FederationDiscovery{DirectorEndpoint: tc.dirUrl, RegistryEndpoint: tc.regUrl}
			test_utils.MockFederationRoot(t, &fedInfo, nil)
			test_utils.InitClient(t, map[param.Param]any{
				param.Federation_DiscoveryUrl: param.Federation_DiscoveryUrl.GetString(),
				param.Federation_DirectorUrl:  tc.dirUrl,
				param.Federation_RegistryUrl:  tc.regUrl,
				param.TLSSkipVerify:           true,
			})

			// Enable federation metadata hosting for the test -- must be done _after_
			// the test client initialization because that function blows out any existing params
			require.NoError(t, param.Director_EnableFederationMetadataHosting.Set(true))
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			router.ServeHTTP(w, req)

			require.Equal(t, tc.statusCode, w.Result().StatusCode)
			body, err := io.ReadAll(w.Result().Body)
			require.NoError(t, err)
			dis := pelican_url.FederationDiscovery{}
			err = json.Unmarshal(body, &dis)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedDir, dis.DirectorEndpoint)
			assert.Equal(t, tc.expectedReg, dis.RegistryEndpoint)
		})
	}
}

// config.GetFederation memoizes discovery -- and its error -- for the life
// of the process, so whichever caller runs it first decides the value for
// every later caller.  That is why the caller's context bounds only that
// caller's wait: a handler may hand over the request context, and a client
// that disconnects while discovery is in flight then fails its own request
// without caching context.Canceled as the federation for everybody.
//
// LaunchModules leaves exactly this window open when Server.WebPort is 0:
// UpdateConfigFromListener re-arms discovery once the listener binds, and
// the web engine serves before LaunchModules next calls GetFederation.
// This test drives that window directly.
func TestFederationDiscoveryHandlerRequestCancellationIsCallerLocal(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	router := gin.Default()
	router.GET("/test", federationDiscoveryHandler)

	server_utils.ResetTestState()
	test_utils.MockFederationRoot(t, nil, nil)
	// Deliberately leave the director, registry, broker, and JWKS endpoints
	// unset: discoverFederationImpl short-circuits without a network call
	// when all of them are already configured, and this test needs the real
	// query to happen.
	test_utils.InitClient(t, map[param.Param]any{
		param.Federation_DiscoveryUrl: param.Federation_DiscoveryUrl.GetString(),
		param.TLSSkipVerify:           true,
	})
	require.NoError(t, param.Director_EnableFederationMetadataHosting.Set(true))

	// Re-arm discovery so that this request is the one that starts it.
	config.ResetFederationForTest()

	// An already-cancelled request context is the deterministic stand-in
	// for a client that disconnects while discovery is in flight.
	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(cancelledCtx, http.MethodGet, "/test", nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// This one request fails, which is the right answer for a client that
	// is no longer listening for it.
	require.Equal(t, http.StatusInternalServerError, w.Result().StatusCode)

	// The discovery it abandoned still runs, and everybody else still gets
	// what the federation root served.
	fedInfo, err := config.GetFederation(context.Background())
	require.NoError(t, err, "an abandoned request poisoned the memoized federation")
	assert.Equal(t, "https://fake-director.com", fedInfo.DirectorEndpoint)
	assert.Equal(t, "https://fake-registry.com", fedInfo.RegistryEndpoint)
}

func TestOidcDiscoveryHandler(t *testing.T) {
	setGinTestMode()
	t.Cleanup(test_utils.SetupTestLogging(t))
	router := gin.Default()
	server_utils.RegisterOIDCAPI(router.Group("/test"), true)

	tests := []struct {
		name           string
		dirUrl         string
		expectedIssuer string
		expectedJwks   string
		statusCode     int
	}{
		{
			name:           "dir-without-port",
			dirUrl:         mockDirUrlWoPort,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-443-port",
			dirUrl:         mockRawDirUrl443,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-non-443-port",
			dirUrl:         mockDirUrlWPort,
			expectedIssuer: mockDirUrlWPort,
			expectedJwks:   mockDirUrlWPort + directorJWKSPath,
			statusCode:     200,
		},
		{
			name:           "dir-with-http",
			dirUrl:         mockRawDirUrlHTTP,
			expectedIssuer: mockDirUrlWoPort,
			expectedJwks:   mockDirUrlWoPort + directorJWKSPath,
			statusCode:     200,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server_utils.ResetTestState()
			fedInfo := pelican_url.FederationDiscovery{DirectorEndpoint: tc.dirUrl}
			test_utils.MockFederationRoot(t, &fedInfo, nil)
			test_utils.InitClient(t, map[param.Param]any{
				param.Federation_DiscoveryUrl: param.Federation_DiscoveryUrl.GetString(),
				param.Federation_DirectorUrl:  tc.dirUrl,
				param.TLSSkipVerify:           true,
			})

			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test"+oidcDiscoveryPath, nil)
			router.ServeHTTP(w, req)

			require.Equal(t, tc.statusCode, w.Result().StatusCode)
			body, err := io.ReadAll(w.Result().Body)
			require.NoError(t, err)
			dis := server_structs.OpenIdDiscoveryResponse{}
			err = json.Unmarshal(body, &dis)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedIssuer, dis.Issuer)
			assert.Equal(t, tc.expectedJwks, dis.JwksUri)
		})
	}
}
