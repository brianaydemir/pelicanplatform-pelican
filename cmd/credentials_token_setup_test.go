//go:build client || server

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

package main

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

func TestFindSavedTokenEntry(t *testing.T) {
	const fedURL = "https://federation.example.org"

	withTokens := func(tokens ...config.TokenEntry) config.FederationCredentials {
		return config.FederationCredentials{
			OauthClient: []config.PrefixEntry{{Prefix: "/foo", Tokens: tokens}},
		}
	}

	tests := []struct {
		name         string
		credConfig   config.CredentialConfig
		discoveryURL string
		wantRefresh  string
		wantNil      bool
	}{
		{
			name: "refresh token present",
			credConfig: config.CredentialConfig{OSDF: withTokens(
				config.TokenEntry{AccessToken: "other", RefreshToken: "other-refresh"},
				config.TokenEntry{AccessToken: "access", RefreshToken: "refresh"},
			)},
			wantRefresh: "refresh",
		},
		{
			name: "refresh token empty",
			credConfig: config.CredentialConfig{OSDF: withTokens(
				config.TokenEntry{AccessToken: "access"},
			)},
		},
		{
			name: "no matching access token",
			credConfig: config.CredentialConfig{OSDF: withTokens(
				config.TokenEntry{AccessToken: "other", RefreshToken: "other-refresh"},
			)},
			wantNil: true,
		},
		{
			name: "no entry for the prefix",
			credConfig: config.CredentialConfig{OSDF: config.FederationCredentials{
				OauthClient: []config.PrefixEntry{{Prefix: "/bar", Tokens: []config.TokenEntry{
					{AccessToken: "access", RefreshToken: "refresh"},
				}}},
			}},
			wantNil: true,
		},
		{
			name: "federation lookup falls back to the OSDF section",
			credConfig: config.CredentialConfig{OSDF: withTokens(
				config.TokenEntry{AccessToken: "access", RefreshToken: "refresh"},
			)},
			discoveryURL: fedURL,
			wantRefresh:  "refresh",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := findSavedTokenEntry(&tt.credConfig, tt.discoveryURL, "/foo", "access")
			if tt.wantNil {
				assert.Nil(t, entry)
				return
			}
			if assert.NotNil(t, entry) {
				assert.Equal(t, "access", entry.AccessToken)
				assert.Equal(t, tt.wantRefresh, entry.RefreshToken)
			}
		})
	}
}

func TestSavedTokenEntry(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	credFile := filepath.Join(t.TempDir(), "credentials.pem")
	require.NoError(t, param.Client_CredentialFile.Set(credFile))

	t.Run("missing file", func(t *testing.T) {
		_, err := savedTokenEntry(credFile, "", "/foo", "access")
		assert.ErrorContains(t, err, "was not saved")
		// Reading a missing file can create it after a password prompt.
		assert.NoFileExists(t, credFile)
	})

	credConfig := config.CredentialConfig{OSDF: config.FederationCredentials{
		OauthClient: []config.PrefixEntry{{Prefix: "/foo", Tokens: []config.TokenEntry{
			{AccessToken: "access", RefreshToken: "refresh"},
		}}},
	}}
	require.NoError(t, config.SaveConfigContentsToFile(&credConfig, credFile, false))

	t.Run("token saved", func(t *testing.T) {
		entry, err := savedTokenEntry(credFile, "", "/foo", "access")
		require.NoError(t, err)
		assert.Equal(t, "refresh", entry.RefreshToken)
	})

	t.Run("token not saved", func(t *testing.T) {
		_, err := savedTokenEntry(credFile, "", "/foo", "other")
		assert.ErrorContains(t, err, "was not saved")
	})
}

func TestCheckNoPasswordTarget(t *testing.T) {
	server_utils.ResetTestState()
	t.Cleanup(server_utils.ResetTestState)

	tests := []struct {
		name    string
		create  func(t *testing.T, path string)
		wantErr bool
	}{
		{name: "missing file"},
		{
			name: "unprotected file",
			create: func(t *testing.T, path string) {
				require.NoError(t, config.SaveConfigContentsToFile(&config.CredentialConfig{}, path, false))
			},
		},
		{
			name: "protected file",
			create: func(t *testing.T, path string) {
				block := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("key")})
				require.NoError(t, os.WriteFile(path, block, 0600))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credFile := filepath.Join(t.TempDir(), "credentials.pem")
			require.NoError(t, param.Client_CredentialFile.Set(credFile))
			if tt.create != nil {
				tt.create(t, credFile)
			}

			err := checkNoPasswordTarget(credFile)
			if tt.wantErr {
				assert.ErrorContains(t, err, credFile)
				assert.ErrorContains(t, err, "PELICAN_CLIENT_CREDENTIALFILE")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWarnIfNoRefreshToken(t *testing.T) {
	expiration := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

	tests := []struct {
		name     string
		entry    config.TokenEntry
		wantWarn bool
		wantText string
	}{
		{
			name:  "refresh token present",
			entry: config.TokenEntry{RefreshToken: "refresh", Expiration: expiration.Unix()},
		},
		{
			name:     "no refresh token, known expiration",
			entry:    config.TokenEntry{Expiration: expiration.Unix()},
			wantWarn: true,
			wantText: "expires at " + time.Unix(expiration.Unix(), 0).Format(time.RFC1123) + ".",
		},
		{
			name:     "no refresh token, unknown expiration",
			entry:    config.TokenEntry{},
			wantWarn: true,
			wantText: "when the current token expires.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			warnIfNoRefreshToken(&buf, "/foo", &tt.entry)
			if !tt.wantWarn {
				assert.Empty(t, buf.String())
				return
			}
			assert.Contains(t, buf.String(), "WARNING: No refresh token was saved for /foo")
			assert.Contains(t, buf.String(), tt.wantText)
		})
	}
}
