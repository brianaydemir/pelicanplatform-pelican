/***************************************************************
 *
 * Copyright (C) 2024, Pelican Project, Morgridge Institute for Research
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

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pelicanplatform/pelican/param"
)

func init() {
	DisableKernelKeyringForTesting()
}

func TestGetSecret(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})
	t.Run("generate-32B-hash", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		require.NoError(t, param.IssuerKeysDirectory.Set(keyDir))

		currentIssuerKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		get, err := GetSecret(currentIssuerKey)
		require.NoError(t, err)
		assert.Len(t, get, 32)
	})
}

func TestEncryptString(t *testing.T) {
	ResetConfig()

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("encrypt-without-err", func(t *testing.T) {
		tmp := t.TempDir()
		keyDir := filepath.Join(tmp, "issuer-keys")
		require.NoError(t, param.IssuerKeysDirectory.Set(keyDir))

		encrypted, err := EncryptString("Some secret to encrypt")
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		// Verify format is $KEYID.$NONCE.$MESSAGE
		parts := strings.Split(encrypted, ".")
		require.Len(t, parts, 3)
		assert.NotEmpty(t, parts[0]) // keyID
		assert.NotEmpty(t, parts[1]) // nonce
		assert.NotEmpty(t, parts[2]) // message
	})
}

func TestDecryptString(t *testing.T) {
	ResetConfig()

	tmp := t.TempDir()
	keyDir := filepath.Join(tmp, "issuer-keys")
	require.NoError(t, param.IssuerKeysDirectory.Set(keyDir))

	t.Cleanup(func() {
		ResetConfig()
	})

	t.Run("decrypt-without-err", func(t *testing.T) {
		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		decrypted, _, err := DecryptString(encrypted)
		require.NoError(t, err)
		assert.Equal(t, secret, decrypted)
	})

	t.Run("decrypt-with-another-invalid-key", func(t *testing.T) {
		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)

		// Mock key rotation after encryption: change the key ID in the encrypted string
		parts := strings.Split(encrypted, ".")
		parts[0] = "another-valid-key-id"
		encrypted = strings.Join(parts, ".")

		_, _, err = DecryptString(encrypted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "the key used for encryption (with ID another-valid-key-id) is not found")
	})

	t.Run("decrypt-with-invalid-format", func(t *testing.T) {
		_, _, err := DecryptString("invalid.format")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid encrypted string format")
	})

	t.Run("decrypt-with-invalid-nonce", func(t *testing.T) {
		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)

		// Change the nonce in the encrypted string
		parts := strings.Split(encrypted, ".")
		parts[1] = "invalid-nonce"
		encrypted = strings.Join(parts, ".")

		_, _, err = DecryptString(encrypted)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode nonce")
	})

	t.Run("decrypt-with-multiple-keys", func(t *testing.T) {
		firstKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		firstKeyID := firstKey.KeyID()

		// Encrypt with the first key
		secret := "Some secret to encrypt"
		encrypted, err := EncryptString(secret)
		require.NoError(t, err)
		assert.NotEmpty(t, encrypted)

		// Simulate key rotation
		// 1. rename the first key file to increase its lexical order
		keyFiles, err := os.ReadDir(keyDir)
		require.NoError(t, err)
		require.Len(t, keyFiles, 1)
		// Note: Pelican generates key files with current timestamp + random number, e.g. pelican_generated_1746649043717835139_2388454454.pem
		err = os.Rename(filepath.Join(keyDir, keyFiles[0].Name()), filepath.Join(keyDir, "pelican_generated_2.pem"))
		require.NoError(t, err)

		// 2. add a new key to the issuer keys directory
		_, err = GeneratePEM(keyDir)
		require.NoError(t, err)

		// Note: Pelican uses the lexical order of the key files to determine current key (lower lexical order is the current key)
		keyChanged, err := RefreshKeys()
		require.NoError(t, err)
		assert.True(t, keyChanged)

		secondKey, err := GetIssuerPrivateJWK()
		require.NoError(t, err)
		secondKeyID := secondKey.KeyID()
		assert.NotEqual(t, firstKeyID, secondKeyID)

		// Now DecryptString should still be able to decrypt using the old key
		decrypted, keyIdUsedInEncryption, err := DecryptString(encrypted)
		require.NoError(t, err)
		assert.Equal(t, firstKeyID, keyIdUsedInEncryption)
		assert.Equal(t, secret, decrypted)
	})
}

// TestSaveConfigContentsEmptyPasswordIgnoresCachedPassword verifies that an
// explicitly empty password (e.g., `credentials token setup --no-password`)
// wins over a password cached in the session keyring. Otherwise the file is
// silently saved encrypted, and an unattended job that later reads it fails
// because it cannot prompt for the password.
func TestSaveConfigContentsEmptyPasswordIgnoresCachedPassword(t *testing.T) {
	forgetCachedPassword(t)
	ResetConfig()
	t.Cleanup(func() {
		setEmptyPassword.Store(false)
		ForgetPassword()
		ResetConfig()
	})

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "credentials.pem")
	require.NoError(t, param.Client_CredentialFile.Set(filePath))
	require.NoError(t, param.ConfigBase.Set(tmpDir))

	require.NoError(t, SavePassword([]byte("cached-password")))
	SetEmptyPassword()

	cfg := CredentialConfig{
		OSDF: FederationCredentials{
			OauthClient: []PrefixEntry{{Prefix: "/foo"}},
		},
	}
	require.NoError(t, SaveConfigContents(&cfg))

	contents, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(contents), "-----BEGIN PRIVATE KEY-----")
	assert.NotContains(t, string(contents), "ENCRYPTED PRIVATE KEY")

	// With no password available, the file must still be readable.
	setEmptyPassword.Store(false)
	ForgetPassword()
	readBack, err := GetCredentialConfigContents()
	require.NoError(t, err)
	require.Len(t, readBack.OSDF.OauthClient, 1)
	assert.Equal(t, "/foo", readBack.OSDF.OauthClient[0].Prefix)
}

// TestSaveConfigContentsEmptyPasswordKeepsProtectedFileEncrypted verifies
// that an explicitly empty password does not strip the password from an
// existing protected file, which would expose every secret already in it.
func TestSaveConfigContentsEmptyPasswordKeepsProtectedFileEncrypted(t *testing.T) {
	forgetCachedPassword(t)
	ResetConfig()
	t.Cleanup(func() {
		setEmptyPassword.Store(false)
		ForgetPassword()
		ResetConfig()
	})

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "credentials.pem")
	require.NoError(t, param.Client_CredentialFile.Set(filePath))
	require.NoError(t, param.ConfigBase.Set(tmpDir))

	pemBytes, err := marshalEncryptedConfig(&CredentialConfig{
		OSDF: FederationCredentials{
			OauthClient: []PrefixEntry{{Prefix: "/existing"}},
		},
	}, []byte("wallet-password"))
	require.NoError(t, err)
	require.NoError(t, saveToFile(pemBytes, filePath))

	// Simulate a process that decrypted the file and cached the password.
	require.NoError(t, SavePassword([]byte("wallet-password")))
	SetEmptyPassword()

	cfg, err := GetCredentialConfigContents()
	require.NoError(t, err)
	cfg.OSDF.OauthClient = append(cfg.OSDF.OauthClient, PrefixEntry{Prefix: "/new"})
	require.NoError(t, SaveConfigContents(&cfg))

	contents, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(contents), "-----BEGIN ENCRYPTED PRIVATE KEY-----")

	readBack, err := GetCredentialConfigContents()
	require.NoError(t, err)
	require.Len(t, readBack.OSDF.OauthClient, 2)
	assert.Equal(t, "/new", readBack.OSDF.OauthClient[1].Prefix)
}

// TestResetPasswordPromptsForUnprotectedFile verifies that reset-password
// prompts for a new password even though reading an unprotected file sets
// the empty-password flag; otherwise there is no way to add a password.
func TestResetPasswordPromptsForUnprotectedFile(t *testing.T) {
	forgetCachedPassword(t)
	ResetConfig()
	t.Cleanup(func() {
		setEmptyPassword.Store(false)
		ResetConfig()
	})

	// Make sure that the prompt fails rather than waits on a real terminal.
	stdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = stdin
		r.Close()
		w.Close()
	})

	filePath := filepath.Join(t.TempDir(), "credentials.pem")
	require.NoError(t, param.Client_CredentialFile.Set(filePath))
	require.NoError(t, SaveConfigContentsToFile(&CredentialConfig{}, filePath, false))

	err = ResetPassword()
	assert.ErrorContains(t, err, "not connected to a terminal")

	contents, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Contains(t, string(contents), "-----BEGIN PRIVATE KEY-----")
}

// forgetCachedPassword clears the password cache before and after the test.
func forgetCachedPassword(t *testing.T) {
	ForgetPassword()
	t.Cleanup(ForgetPassword)
}
