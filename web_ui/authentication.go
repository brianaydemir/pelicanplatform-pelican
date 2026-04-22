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

package web_ui

import (
	"bufio"
	"context"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/csrf"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/go-htpasswd"
	"go.uber.org/atomic"
	"golang.org/x/sync/errgroup"

	"github.com/pelicanplatform/pelican/config"
	"github.com/pelicanplatform/pelican/database"
	"github.com/pelicanplatform/pelican/param"
	"github.com/pelicanplatform/pelican/server_structs"
	"github.com/pelicanplatform/pelican/token"
	"github.com/pelicanplatform/pelican/token_scopes"
	"github.com/pelicanplatform/pelican/web_ui/auth"
	"github.com/pelicanplatform/pelican/web_ui/middleware"
)

type (
	UserRole string
	Login    struct {
		User     string `form:"user"`
		Password string `form:"password"`
	}

	InitLogin struct {
		Code string `form:"code"`
	}

	PasswordReset struct {
		Password string `form:"password"`
	}

	WhoAmIRes struct {
		Authenticated bool     `json:"authenticated"`
		Role          UserRole `json:"role"`
		User          string   `json:"user"`
	}

	OIDCEnabledServerRes struct {
		ODICEnabledServers []string `json:"oidc_enabled_servers"`
	}
)

var (
	authDB       atomic.Pointer[htpasswd.File]
	currentCode  atomic.Pointer[string]
	previousCode atomic.Pointer[string]
)

const (
	AdminRole    UserRole = "admin"
	NonAdminRole UserRole = "user"
)

// Periodically re-read the htpasswd file used for password-based authentication
func periodicAuthDBReload(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Debug("Reloading the auth database")
			_ = doReload()
		case <-ctx.Done():
			return nil
		}
	}
}

func configureAuthDB() error {
	fileName := param.Server_UIPasswordFile.GetString()
	if fileName == "" {
		return errors.New("Location of password file not set")
	}
	fp, err := os.Open(fileName)
	if err != nil {
		return err
	}
	defer fp.Close()
	scanner := bufio.NewScanner(fp)
	scanner.Split(bufio.ScanLines)
	hasAdmin := false
	for scanner.Scan() {
		user := strings.Split(scanner.Text(), ":")[0]
		if user == "admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return errors.New("AuthDB does not have 'admin' user")
	}

	auth, err := htpasswd.New(fileName, []htpasswd.PasswdParser{htpasswd.AcceptBcrypt}, nil)
	if err != nil {
		return err
	}
	authDB.Store(auth)

	return nil
}

// Create a JWT and set the "login" cookie to store that JWT
func setLoginCookie(ctx *gin.Context, userRecord *database.User, groups []string) {

	// Lifetime of the login token and the cookie that stores it
	loginLifetime := 16 * time.Hour

	loginCookieTokenCfg := token.NewWLCGToken()
	loginCookieTokenCfg.Lifetime = loginLifetime
	loginCookieTokenCfg.Issuer = param.Server_ExternalWebUrl.GetString()
	loginCookieTokenCfg.AddAudiences(param.Server_ExternalWebUrl.GetString())
	loginCookieTokenCfg.Subject = userRecord.Username
	loginCookieTokenCfg.AddScopes(token_scopes.WebUi_Access)
	loginCookieTokenCfg.AddGroups(groups...)

	// For backwards compatibility (see #398), add additional scopes
	// for expert admins who extract the login cookie from their browser
	// and use it to query monitoring endpoints directly.
	identity := auth.UserIdentity{
		Username: loginCookieTokenCfg.Subject,
		ID:       userRecord.ID,
		Sub:      userRecord.Sub,
		Groups:   groups,
	}
	if isAdmin, _ := auth.CheckAdmin(identity); isAdmin {
		loginCookieTokenCfg.AddScopes(token_scopes.Monitoring_Query, token_scopes.Monitoring_Scrape)
	}

	// Add claims for unique user resolution using userId
	loginCookieTokenCfg.Claims = map[string]string{
		"user_id":  userRecord.ID,
		"oidc_sub": userRecord.Sub,
		"oidc_iss": userRecord.Issuer,
	}

	// CreateToken also handles validation for us
	tok, err := loginCookieTokenCfg.CreateToken()
	if err != nil {
		log.Errorln("Failed to create login cookie token:", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Unable to create login cookies",
			})
		return
	}

	// One cookie should be used for all path
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie("login", tok, int(loginLifetime.Seconds()), "/", "", true, true)
}

// Handle regular username/password based login
func loginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db == nil {
		newPath := path.Join(ctx.Request.URL.Path, "..", "initLogin")
		initUrl := ctx.Request.URL
		initUrl.Path = newPath
		ctx.Redirect(307, initUrl.String())
		return
	}

	login := Login{}
	if ctx.ShouldBind(&login) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Missing user/password in form data",
			})
		return
	}
	if strings.TrimSpace(login.User) == "" {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "User is required",
			})
		return
	}
	if strings.TrimSpace(login.Password) == "" {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Password is required",
			})
		return
	}
	if !db.Match(login.User, login.Password) {
		ctx.JSON(401,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Password and user didn't match",
			})
		return
	}

	groups, err := generateGroupInfo(login.User)
	if err != nil {
		log.Errorf("Failed to generate group info for user %s: %s", login.User, err)
		groups = nil
	}

	// Get or create the user in the database
	// For password-based login, we use the username as both sub and issuer with server URL
	externalUrl := param.Server_ExternalWebUrl.GetString()
	userRecord, err := database.GetOrCreateUser(database.ServerDatabase, login.User, login.User, externalUrl)
	if err != nil {
		log.Errorf("Failed to get or create user %s: %s", login.User, err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to create user session",
			})
		return
	}

	setLoginCookie(ctx, userRecord, groups)

	// Return nextUrl in the response so clients can redirect after login.
	// The frontend login page sends nextUrl when it wants the user redirected
	// back to a specific page (e.g. the device code verification page).
	nextUrl := ctx.Query("nextUrl")
	resp := gin.H{
		"status": server_structs.RespOK,
		"msg":    "success",
	}
	if nextUrl != "" {
		resp["nextUrl"] = nextUrl
	}
	ctx.JSON(http.StatusOK, resp)
}

// Handle initial code-based login for admin
func initLoginHandler(ctx *gin.Context) {
	db := authDB.Load()
	if db != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Authentication is already initialized",
			})
		return
	}
	curCode := currentCode.Load()
	if curCode == nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Code-based login is not available",
			})
		return
	}
	prevCode := previousCode.Load()

	code := InitLogin{}
	if ctx.ShouldBind(&code) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Login code not provided",
			})
		return
	}

	if code.Code != *curCode && (prevCode == nil || code.Code != *prevCode) {
		ctx.JSON(401,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid login code",
			})
		return
	}

	groups, err := generateGroupInfo("admin")
	if err != nil {
		log.Errorln("Failed to generate group info for admin:", err)
		groups = nil
	}

	// Get or create the admin user in the database
	externalUrl := param.Server_ExternalWebUrl.GetString()
	userRecord, err := database.GetOrCreateUser(database.ServerDatabase, "admin", "admin", externalUrl)
	if err != nil {
		log.Errorf("Failed to get or create admin user: %s", err)
		ctx.JSON(http.StatusInternalServerError,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to create admin session",
			})
		return
	}

	setLoginCookie(ctx, userRecord, groups)
}

// Handle reset password
func resetLoginHandler(ctx *gin.Context) {
	passwordReset := PasswordReset{}
	if ctx.ShouldBind(&passwordReset) != nil {
		ctx.JSON(400,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Invalid password reset request",
			})
		return
	}

	user := ctx.GetString("User")

	if err := WritePasswordEntry(user, passwordReset.Password); err != nil {
		log.Errorf("Password reset for user %s failed: %s", user, err)
		ctx.JSON(500,
			server_structs.SimpleApiResp{
				Status: server_structs.RespFailed,
				Msg:    "Failed to reset password",
			})
	} else {
		log.Infof("Password reset for user %s was successful", user)
		ctx.JSON(http.StatusOK,
			server_structs.SimpleApiResp{
				Status: server_structs.RespOK,
				Msg:    "success",
			})
	}
	if err := configureAuthDB(); err != nil {
		log.Errorln("Error in reloading authDB:", err)
	}
}

func logoutHandler(ctx *gin.Context) {
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie("pelican-session", "", -1, "/", "", true, true)
	ctx.SetCookie("login", "", -1, "/", "", true, true)
	ctx.Set("User", "")
	ctx.JSON(http.StatusOK,
		server_structs.SimpleApiResp{
			Status: server_structs.RespOK,
			Msg:    "success",
		})
}

// Returns the authentication status of the current user, including user id and role
func whoamiHandler(ctx *gin.Context) {
	res := WhoAmIRes{}
	if user, userId, groups, err := auth.GetUserGroups(ctx); err != nil || user == "" {
		res.Authenticated = false
		ctx.JSON(http.StatusOK, res)
	} else {
		res.Authenticated = true
		res.User = user

		// Set header to carry CSRF token
		ctx.Header("X-CSRF-Token", csrf.Token(ctx.Request))
		identity := auth.UserIdentity{
			Username: user,
			ID:       userId,
			Groups:   groups,
			Sub:      ctx.GetString("OIDCSub"),
		}
		isAdmin, _ := auth.CheckAdmin(identity)
		if isAdmin {
			res.Role = AdminRole
		} else {
			res.Role = NonAdminRole
		}
		ctx.JSON(http.StatusOK, res)
	}
}

func listOIDCEnabledServersHandler(ctx *gin.Context) {
	// Registry has OIDC enabled by default
	res := OIDCEnabledServerRes{ODICEnabledServers: []string{strings.ToLower(server_structs.RegistryType.String())}}
	if param.Origin_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.OriginType.String()))
	}
	if param.Cache_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.CacheType.String()))
	}
	if param.Director_EnableOIDC.GetBool() {
		res.ODICEnabledServers = append(res.ODICEnabledServers, strings.ToLower(server_structs.DirectorType.String()))
	}
	ctx.JSON(http.StatusOK, res)
}

// Configure the authentication endpoints for the server web UI
func RegisterAuthEndpoints(ctx context.Context, routerGroup *gin.RouterGroup, egrp *errgroup.Group) error {
	if routerGroup == nil {
		return errors.New("Web engine configuration passed a nil pointer")
	}

	if err := configureAuthDB(); err != nil {
		log.Infoln("Authorization not configured (non-fatal):", err)
	}

	csrfHandler, err := config.GetCSRFHandler()
	if err != nil {
		return err
	}

	// Configure login rate limit middleware with the specified limit
	limit := param.Server_UILoginRateLimit.GetInt()
	loginRateMiddleware := middleware.LoginRateLimitMiddleware(limit)

	routerGroup.POST("/login", loginRateMiddleware, loginHandler)
	routerGroup.POST("/logout", middleware.AuthHandler, logoutHandler)
	routerGroup.POST("/initLogin", middleware.ReadOnlyMiddleware, initLoginHandler)
	routerGroup.POST("/resetLogin", middleware.ReadOnlyMiddleware, middleware.AuthHandler, middleware.AdminAuthHandler, resetLoginHandler)
	// Pass csrfhanlder only to the whoami route to generate CSRF token
	// while leaving other routes free of CSRF check (we might want to do it some time in the future)
	routerGroup.GET("/whoami", csrfHandler, whoamiHandler)
	routerGroup.GET("/loginInitialized", func(ctx *gin.Context) {
		db := authDB.Load()
		if db == nil {
			ctx.JSON(200, gin.H{"initialized": false})
		} else {
			ctx.JSON(200, gin.H{"initialized": true})
		}
	})
	routerGroup.GET("/oauth", listOIDCEnabledServersHandler)

	egrp.Go(func() error { return periodicAuthDBReload(ctx) })

	return nil
}
