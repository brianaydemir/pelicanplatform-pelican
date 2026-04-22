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

package middleware

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui/auth"
)

const oauthLoginPath = "/api/v1.0/auth/oauth/login"

// Check if user is authenticated by checking if the "login" cookie is present and set the user identity to ctx
func AuthHandler(ctx *gin.Context) {
	user, userId, groups, err := auth.GetUserGroups(ctx)
	if user == "" || err != nil {
		if err != nil {
			log.Errorln("Invalid user cookie or unable to parse user cookie:", err)
		}
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication required to perform this operation",
			})
	} else {
		ctx.Set("User", user)
		ctx.Set("UserId", userId)
		ctx.Set("Groups", groups)
		ctx.Next()
	}
}

// Require auth; if missing, redirect to the login endpoint.
//
// The current implementation forces the OAuth2 endpoint; future work may instead use a generic
// login page.
func RequireAuthMiddleware(ctx *gin.Context) {
	user, userId, groups, err := auth.GetUserGroups(ctx)
	if user == "" || err != nil {
		origPath := ctx.Request.URL.RequestURI()
		redirUrl := url.URL{
			Path:     oauthLoginPath,
			RawQuery: "nextUrl=" + url.QueryEscape(origPath),
		}
		ctx.Redirect(http.StatusTemporaryRedirect, redirUrl.String())
		ctx.Abort()
	} else {
		ctx.Set("User", user)
		ctx.Set("UserId", userId)
		ctx.Set("Groups", groups)
		ctx.Next()
	}
}

// AdminAuthHandler checks the admin status of a logged-in user. This middleware
// should be cascaded behind the [AuthHandler]
func AdminAuthHandler(ctx *gin.Context) {
	user := ctx.GetString("User")
	// This should be done by a regular auth handler from the upstream, but we check here just in case
	if user == "" {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login required to view this page",
			})
		return
	}
	// Get groups from context if available
	var groups []string
	if groupsIface, exists := ctx.Get("Groups"); exists {
		if groupsSlice, ok := groupsIface.([]string); ok {
			groups = groupsSlice
		}
	}

	identity := auth.UserIdentity{
		Username: user,
		Groups:   groups,
		ID:       ctx.GetString("UserId"),
		Sub:      ctx.GetString("OIDCSub"),
	}

	isAdmin, msg := auth.CheckAdmin(identity)
	if isAdmin {
		ctx.Next()
		return
	} else {
		ctx.AbortWithStatusJSON(http.StatusForbidden,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    msg,
			})
	}
}

// DowntimeAuthHandler allows EITHER:
// 1. Admin cookie authentication (req from this server itself), OR
// 2. Server bearer token authentication (req from another server, i.e. origin/cache)
func DowntimeAuthHandler(ctx *gin.Context) {
	// First, try cookie-based admin auth (this block consolidates AuthHandler and AdminAuthHandler)
	user, userId, groups, err := auth.GetUserGroups(ctx)
	if user != "" && err == nil {
		identity := auth.UserIdentity{
			Username: user,
			ID:       userId,
			Groups:   groups,
			Sub:      ctx.GetString("OIDCSub"),
		}

		// User has valid cookie, check if admin
		isAdmin, _ := auth.CheckAdmin(identity)
		if isAdmin {
			ctx.Set("User", user)
			ctx.Set("UserId", userId)
			ctx.Set("Groups", groups)
			ctx.Set("AuthMethod", "admin-cookie")
			ctx.Next()
			return
		}
	}

	// If not admin cookie, try bearer token from header
	var requiredScope token_scopes.TokenScope
	switch ctx.Request.Method {
	case http.MethodPost:
		requiredScope = token_scopes.Pelican_DowntimeCreate
	case http.MethodPut:
		requiredScope = token_scopes.Pelican_DowntimeModify
	case http.MethodDelete:
		requiredScope = token_scopes.Pelican_DowntimeDelete
	default:
		// Fallback: require create/modify/delete not for GETs (which don't hit this handler).
		requiredScope = token_scopes.Pelican_DowntimeModify
	}
	status, ok, err := token.Verify(ctx, token.AuthOption{
		Sources: []token.TokenSource{token.Header},
		Issuers: []token.TokenIssuer{token.RegisteredServer},
		Scopes:  []token_scopes.TokenScope{requiredScope},
	})
	if !ok || err != nil {
		ctx.AbortWithStatusJSON(status, server_structs.SimpleApiResp{
			Status: server_structs.RespFailed,
			Msg:    fmt.Sprint("Failed to verify the token: ", err),
		})
		return
	}

}
