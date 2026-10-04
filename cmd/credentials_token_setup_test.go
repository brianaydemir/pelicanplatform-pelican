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
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_utils"
)

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
