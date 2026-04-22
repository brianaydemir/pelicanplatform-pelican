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

package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pkg/errors"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/param"
)

// UserIdentity encapsulates all available information about a user's identity.
type UserIdentity struct {
	Username string
	ID       string
	Sub      string // OIDC Subject
	Groups   []string
}

// extractUserFromBearerToken parses and verifies a Bearer token, extracting user info.
// Uses early-exit pattern for cleaner flow control.
func extractUserFromBearerToken(ctx *gin.Context, tokenStr string) (user string, userId string, groups []string, err error) {
	// Parse token without verification first to check issuer
	parsed, err := jwt.Parse([]byte(tokenStr), jwt.WithVerify(false))
	if err != nil {
		return "", "", nil, err
	}

	// Verify issuer matches local issuer
	serverURL := param.Server_ExternalWebUrl.GetString()
	if parsed.Issuer() != serverURL {
		return "", "", nil, errors.New("token issuer does not match server URL")
	}

	// Verify signature
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return "", "", nil, err
	}

	verified, err := jwt.Parse([]byte(tokenStr), jwt.WithKeySet(jwks))
	if err != nil {
		return "", "", nil, err
	}

	if err = jwt.Validate(verified); err != nil {
		return "", "", nil, err
	}

	// Extract user from subject
	user = verified.Subject()
	if user == "" {
		return "", "", nil, errors.New("token has empty subject")
	}

	// Extract userId claim
	if userIdIface, ok := verified.Get("user_id"); ok {
		if userIdStr, ok := userIdIface.(string); ok && userIdStr != "" {
			userId = userIdStr
		}
	}

	// Extract oidc_sub claim for admin checks against UIAdminUsers
	if oidcSubIface, ok := verified.Get("oidc_sub"); ok {
		if oidcSub, ok := oidcSubIface.(string); ok && oidcSub != "" {
			ctx.Set("OIDCSub", oidcSub)
		}
	}

	// Extract groups
	groupsIface, ok := verified.Get("wlcg.groups")
	if ok {
		if groupsTmp, ok := groupsIface.([]interface{}); ok {
			groups = make([]string, 0, len(groupsTmp))
			for _, groupObj := range groupsTmp {
				if groupStr, ok := groupObj.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		}
	}

	// Set in context for later use
	ctx.Set("User", user)
	if userId != "" {
		ctx.Set("UserId", userId)
	}
	if len(groups) > 0 {
		ctx.Set("Groups", groups)
	}

	return user, userId, groups, nil
}

// GetUserGroups returns the username, user ID, and groups for the current request.
//
// It checks, in order: a previously set gin context value, a Bearer token in
// the Authorization header, and the "login" session cookie.
func GetUserGroups(ctx *gin.Context) (user string, userId string, groups []string, err error) {
	// First check if user info was already set in context (e.g., from Bearer token verification)
	if userIface, exists := ctx.Get("User"); exists {
		if userStr, ok := userIface.(string); ok && userStr != "" {
			user = userStr
			// Extract userId from context if available
			if userIdIface, exists := ctx.Get("UserId"); exists {
				if userIdStr, ok := userIdIface.(string); ok {
					userId = userIdStr
				}
			}
			// Extract groups from context if available
			if groupsIface, exists := ctx.Get("Groups"); exists {
				if groupsSlice, ok := groupsIface.([]string); ok {
					groups = groupsSlice
				}
			}
			return
		}
	}

	// Check for Bearer token in Authorization header
	headerToken := ctx.Request.Header["Authorization"]
	if len(headerToken) > 0 {
		tokenStr, found := strings.CutPrefix(headerToken[0], "Bearer ")
		if found && tokenStr != "" {
			user, userId, groups, err = extractUserFromBearerToken(ctx, tokenStr)
			if err == nil && user != "" {
				return
			}
			// Bearer token failed, fall through to cookie check
		}
	}

	var token string
	token, err = ctx.Cookie("login")
	if err != nil {
		if err == http.ErrNoCookie {
			err = nil
			return
		} else {
			return
		}
	}
	if token == "" {
		err = errors.New("Login cookie is empty")
		return
	}
	jwks, err := config.GetIssuerPublicJWKS()
	if err != nil {
		return
	}
	parsed, err := jwt.Parse([]byte(token), jwt.WithKeySet(jwks))
	if err != nil {
		return
	}
	if err = jwt.Validate(parsed); err != nil {
		return
	}
	user = parsed.Subject()

	// Extract userId claim
	userIdIface, ok := parsed.Get("user_id")
	if !ok {
		err = errors.New("Missing user_id claim")
		return
	}
	userId, ok = userIdIface.(string)
	if !ok {
		err = errors.New("Invalid user_id claim")
		return
	}

	// Extract oidc_sub claim (the OIDC subject identifier)
	// This is set in context so admin checks can match against UIAdminUsers
	if oidcSubIface, ok := parsed.Get("oidc_sub"); ok {
		if oidcSub, ok := oidcSubIface.(string); ok && oidcSub != "" {
			ctx.Set("OIDCSub", oidcSub)
		}
	}

	groupsIface, ok := parsed.Get("wlcg.groups")
	if ok {
		if groupsTmp, ok := groupsIface.([]interface{}); ok {
			groups = make([]string, 0, len(groupsTmp))
			for _, groupObj := range groupsTmp {
				if groupStr, ok := groupObj.(string); ok {
					groups = append(groups, groupStr)
				}
			}
		}
	}
	return
}

// CheckAdmin checks if a user has admin privilege.
//
// It returns a boolean and a message indicating the reason for failure.
// The check proceeds in this order:
//  1. If user == "admin" (built-in admin)
//  2. If any of the user's groups match Server.AdminGroups
//  3. If any of the user's identifiers (Username, ID, Sub) match Server.UIAdminUsers
func CheckAdmin(identity UserIdentity) (isAdmin bool, message string) {
	if identity.Username == "admin" {
		return true, ""
	}

	// Check admin groups if groups are provided
	if len(identity.Groups) > 0 {
		adminGroups := param.Server_AdminGroups.GetStringSlice()
		if param.Server_AdminGroups.IsSet() && len(adminGroups) > 0 {
			for _, userGroup := range identity.Groups {
				for _, adminGroup := range adminGroups {
					if userGroup == adminGroup {
						return true, ""
					}
				}
			}
		}
	}

	// Check admin users against all user identifiers
	adminList := param.Server_UIAdminUsers.GetStringSlice()
	if param.Server_UIAdminUsers.IsSet() {
		// Build list of all identifiers to check
		identifiers := []string{identity.Username, identity.ID, identity.Sub}

		for _, admin := range adminList {
			for _, identifier := range identifiers {
				if identifier != "" && identifier == admin {
					return true, ""
				}
			}
		}
	}

	// If neither admin groups nor admin users are configured, and user is not "admin", deny access
	if !param.Server_AdminGroups.IsSet() && !param.Server_UIAdminUsers.IsSet() {
		return false, "Server.UIAdminUsers and Server.UIAdminGroups are not set, and user is not root user. Admin check returns false"
	}

	return false, "You don't have permission to perform this action"
}
