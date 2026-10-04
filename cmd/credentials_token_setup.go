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
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/pelicanplatform/pelican/client"
	"github.com/pelicanplatform/pelican/config"
)

var (
	tokenSetupNoPassword     bool
	tokenSetupCredentialFile string
	tokenSetupRead           bool
	tokenSetupWrite          bool
)

// addCredentialsTokenSetupCommand adds the "setup" subcommand to the given
// credentials token command.
func addCredentialsTokenSetupCommand(credentialsTokenCmd *cobra.Command) {
	setupCmd := &cobra.Command{
		Use:   "setup <pelican-url>",
		Short: "Set up a credential file containing tokens for a Pelican namespace",
		Long: `Acquire a token for the specified Pelican namespace and save it to a
credential file on disk. The credential file contains the access token,
refresh token, and OAuth2 client credentials needed to obtain fresh tokens
later without re-authenticating.

By default, the credential file is password-protected. Use --no-password to
save the file without encryption, which is useful for non-interactive contexts
where password prompts would fail.

Use --credential-file to specify an alternative path for the credential file.

Examples:
  # Set up credentials for reading from a namespace
  pelican credentials token setup --read pelican://federation.example.org/namespace/path

  # Set up credentials for reading and writing
  pelican credentials token setup --write pelican://federation.example.org/namespace/path

  # Set up credentials without password protection
  pelican credentials token setup --no-password --read pelican://federation.example.org/namespace/path

  # Set up credentials to a specific file
  pelican credentials token setup --credential-file /path/to/creds.pem --read pelican://federation.example.org/namespace/path`,
		RunE:         credentialsTokenSetupMain,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
	}

	setupCmd.Flags().BoolVar(&tokenSetupNoPassword, "no-password", false, "Save the credential file without password protection")
	setupCmd.Flags().BoolVarP(&tokenSetupRead, "read", "r", false, "Request a read token")
	setupCmd.Flags().BoolVarP(&tokenSetupWrite, "write", "w", false, "Request a write token (implies read)")

	setupCmd.Flags().StringVar(&tokenSetupCredentialFile, "credential-file", "", "Path to the credential file to write")
	if err := viper.BindPFlag("Client.CredentialFile", setupCmd.Flags().Lookup("credential-file")); err != nil {
		panic(err)
	}

	credentialsTokenCmd.AddCommand(setupCmd)
}

func credentialsTokenSetupMain(cmd *cobra.Command, args []string) error {
	err := config.InitClient()
	if err != nil {
		return errors.Wrap(err, "failed to initialize client configuration")
	}

	// Parse the Pelican URL
	rawUrl := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pUrl, err := client.ParseRemoteAsPUrl(ctx, rawUrl)
	if err != nil {
		return errors.Wrapf(err, "failed to parse URL: %s", rawUrl)
	}

	// Default to read if neither --read nor --write is specified
	if !tokenSetupRead && !tokenSetupWrite {
		tokenSetupRead = true
	}

	// Determine the HTTP method based on access mode
	httpMethod := http.MethodGet
	if tokenSetupWrite {
		httpMethod = http.MethodPut
	}

	// Get director info for the path
	dirResp, err := client.GetDirectorInfoForPath(ctx, pUrl, httpMethod, "")
	if err != nil {
		return errors.Wrapf(err, "failed to get director info for %s", rawUrl)
	}

	// Public prefixes don't require tokens
	if !dirResp.XPelNsHdr.RequireToken {
		fmt.Fprintln(os.Stderr, "The specified namespace does not require tokens; no credential file is needed.")
		return nil
	}

	// Determine the operation type.
	// --write implies read: request all scopes so the token works for both.
	var operation config.TokenOperation
	if tokenSetupWrite {
		operation.Set(config.TokenWrite)
		operation.Set(config.TokenDelete)
	}
	operation.Set(config.TokenRead)
	operation.Set(config.TokenList)

	credFilePath, err := config.GetEncryptedConfigName()
	if err != nil {
		return errors.Wrap(err, "failed to determine credential file path")
	}

	// Acquire a token (this will also register the OAuth2 client and save
	// credentials to the credential file as a side effect).
	//
	// If --no-password was requested, tell the config layer to skip
	// password prompts *before* token acquisition so the credential file
	// is saved unencrypted on the write.
	if tokenSetupNoPassword {
		// Refuse up front, before the user approves access in a browser,
		// rather than strip the password from an existing protected file.
		if err := checkNoPasswordTarget(credFilePath); err != nil {
			return err
		}
		config.SetEmptyPassword()
	}

	opts := config.TokenGenerationOpts{
		Operation: operation,
	}

	token, err := client.AcquireToken(pUrl.GetRawUrl(), dirResp, opts)
	if err != nil {
		return errors.Wrap(err, "failed to acquire token")
	}

	if token == "" {
		return errors.New("acquired token is empty")
	}

	// AcquireToken only logs a failure to save the credential file, so
	// confirm that the token actually reached it.
	entry, err := savedTokenEntry(credFilePath, opts.DiscoveryURL, dirResp.XPelNsHdr.Namespace, token)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Successfully set up credentials for %s\n", dirResp.XPelNsHdr.Namespace)
	fmt.Fprintf(os.Stderr, "Credential file: %s\n", credFilePath)

	warnIfNoRefreshToken(os.Stderr, dirResp.XPelNsHdr.Namespace, entry)
	return nil
}

// checkNoPasswordTarget returns an error if the credential file at
// credFilePath is password-protected, since --no-password cannot be used
// with it.
func checkNoPasswordTarget(credFilePath string) error {
	protected, err := config.HasEncryptedPassword()
	if err != nil {
		return errors.Wrapf(err, "failed to check whether %s is password-protected", credFilePath)
	}
	if protected {
		return errors.Errorf("--no-password cannot be used with %s because it is password-protected; "+
			"set PELICAN_CLIENT_CREDENTIALFILE to the path of a separate credential file", credFilePath)
	}
	return nil
}

// warnIfNoRefreshToken writes a warning to w if entry, the token saved for
// prefix, has no refresh token.
func warnIfNoRefreshToken(w io.Writer, prefix string, entry *config.TokenEntry) {
	// The point of a credential file is to keep working without anyone
	// approving access again, which needs a refresh token. The issuer may
	// decline the offline_access scope, so check what was actually saved.
	if entry.RefreshToken != "" {
		return
	}
	fmt.Fprintf(w, "WARNING: No refresh token was saved for %s, so Pelican cannot renew access.\n", prefix)
	if entry.Expiration > 0 {
		fmt.Fprintf(w, "Anything using this credential file will stop working when the current token expires at %s.\n",
			time.Unix(entry.Expiration, 0).Format(time.RFC1123))
	} else {
		fmt.Fprintln(w, "Anything using this credential file will stop working when the current token expires.")
	}
}

// savedTokenEntry returns the token entry for prefix that was saved to the
// configured credential file, or an error if none was saved. It reads
// whichever file config.GetEncryptedConfigName names; credFilePath must be
// that file's path and is used only in error messages.
func savedTokenEntry(credFilePath, discoveryURL, prefix, accessToken string) (*config.TokenEntry, error) {
	// AcquireToken also leaves the file alone when it mints the token from
	// a local issuer key, and it doesn't say which happened. Such a host
	// mints its own tokens on every run, so name both causes.
	notSaved := errors.Errorf("the token for %s was not saved to %s; "+
		"this host may issue its own tokens for %s and need no credential file, "+
		"or the file could not be written (see any warning above)", prefix, credFilePath, prefix)

	// Reading a missing credential file would create it and prompt for a
	// new password, so check that the file exists first.
	exists, err := config.EncryptedConfigExists()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to check whether %s exists", credFilePath)
	}
	if !exists {
		return nil, notSaved
	}
	credConfig, err := config.GetCredentialConfigContents()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read %s", credFilePath)
	}
	entry := findSavedTokenEntry(&credConfig, discoveryURL, prefix, accessToken)
	if entry == nil {
		return nil, notSaved
	}
	return entry, nil
}

// findSavedTokenEntry returns the token entry saved for prefix whose access
// token is accessToken, or nil if there is none.
func findSavedTokenEntry(credConfig *config.CredentialConfig, discoveryURL, prefix, accessToken string) *config.TokenEntry {
	fc, idx := credConfig.FindOauthClient(discoveryURL, prefix)
	if idx < 0 {
		return nil
	}
	for i := range fc.OauthClient[idx].Tokens {
		if fc.OauthClient[idx].Tokens[i].AccessToken == accessToken {
			return &fc.OauthClient[idx].Tokens[i]
		}
	}
	return nil
}
