package dash

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"

	"github.com/seaweedfs/seaweedfs/weed/credential"
	"github.com/seaweedfs/seaweedfs/weed/glog"
	"github.com/seaweedfs/seaweedfs/weed/iam/oidc"
	"github.com/seaweedfs/seaweedfs/weed/pb/iam_pb"
)

// Native Admin UI OIDC login (Refresquito addition, Phase 1 of the planned
// native-OIDC-login feature -- see project memory
// seaweedfs-oidc-native-admin-plan.md). Distinct from TrustedProxyAutoLogin
// (auth_middleware.go): here `weed admin` itself is the OAuth2/OIDC relying
// party running its own Authorization Code + PKCE flow, not a middleware
// trusting headers set by an external oauth2-proxy. A "Sign in with
// Keycloak" button appears on the native login page (see
// weed/admin/view/layout/layout.templ's LoginForm) whenever
// WEED_ADMIN_OIDC_ENABLED=true and an issuer/client ID are configured.
//
// Phase 1 scope only: get a real per-person session established (same
// session shape as native login / TrustedProxyAutoLogin -- authenticated,
// username, role). It deliberately does NOT yet JIT-provision a persisted
// Identity into the Object Store Users credential store; that's Phase 2.
//
// Token verification reuses weed/iam/oidc.OIDCProvider -- the same
// production-tested JWKS/issuer/audience validation already used by the S3
// STS AssumeRoleWithWebIdentity path -- rather than adding a new OIDC
// client dependency (coreos/go-oidc). Only the Authorization Code exchange
// itself (authorization_endpoint/token_endpoint, PKCE) is new code, built on
// golang.org/x/oauth2 which was already a transitive dependency.
const (
	oidcSessionStateKey    = "oidc_state"
	oidcSessionVerifierKey = "oidc_verifier"
)

// oidcLoginConfig holds Phase-1 admin-login OIDC settings, read fresh on
// every request (cheap os.Getenv calls) so a config change just needs a pod
// restart, matching how TrustedProxyAutoLogin's env vars are read.
type oidcLoginConfig struct {
	enabled       bool
	issuer        string
	clientID      string
	clientSecret  string
	redirectURL   string // optional override; derived from the request when empty
	scopes        []string
	usernameClaim string
	adminGroup    string
	viewerGroup   string
}

func loadOIDCLoginConfig() oidcLoginConfig {
	cfg := oidcLoginConfig{
		enabled:       os.Getenv("WEED_ADMIN_OIDC_ENABLED") == "true",
		issuer:        strings.TrimSuffix(os.Getenv("WEED_ADMIN_OIDC_ISSUER"), "/"),
		clientID:      os.Getenv("WEED_ADMIN_OIDC_CLIENT_ID"),
		clientSecret:  os.Getenv("WEED_ADMIN_OIDC_CLIENT_SECRET"),
		redirectURL:   os.Getenv("WEED_ADMIN_OIDC_REDIRECT_URL"),
		usernameClaim: os.Getenv("WEED_ADMIN_OIDC_USERNAME_CLAIM"),
		adminGroup:    os.Getenv("WEED_ADMIN_OIDC_ADMIN_GROUP"),
		viewerGroup:   os.Getenv("WEED_ADMIN_OIDC_VIEWER_GROUP"),
	}
	if cfg.usernameClaim == "" {
		cfg.usernameClaim = "preferred_username"
	}
	if cfg.adminGroup == "" {
		cfg.adminGroup = "seaweedfs-admin"
	}
	if cfg.viewerGroup == "" {
		cfg.viewerGroup = "seaweedfs-viewer"
	}
	if scopes := os.Getenv("WEED_ADMIN_OIDC_SCOPES"); scopes != "" {
		for _, s := range strings.Split(scopes, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.scopes = append(cfg.scopes, s)
			}
		}
	}
	if len(cfg.scopes) == 0 {
		cfg.scopes = []string{"openid", "profile", "email", "groups"}
	}
	return cfg
}

func (c oidcLoginConfig) configured() bool {
	return c.enabled && c.issuer != "" && c.clientID != ""
}

// OIDCLoginEnabled reports whether native OIDC admin login is configured, for
// the login template to decide whether to render the "Sign in with
// Keycloak" button.
func OIDCLoginEnabled() bool {
	return loadOIDCLoginConfig().configured()
}

// oidcDiscoveryDoc is the subset of the OIDC discovery document Phase 1
// needs. weed/iam/oidc.OIDCProvider does its own (unexported) discovery for
// JWKS resolution; this is a separate, minimal fetch for the two
// authorization-flow endpoints that package has no reason to expose.
type oidcDiscoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func discoverOIDCEndpoints(ctx context.Context, issuer string) (*oidcDiscoveryDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}
	var doc oidcDiscoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing authorization_endpoint/token_endpoint")
	}
	return &doc, nil
}

// redirectURLFromRequest derives this deployment's own callback URL from the
// incoming request (honoring a reverse proxy's X-Forwarded-* headers, same
// as the rest of the Admin UI's URL-prefix handling), unless an operator
// override is configured.
func redirectURLFromRequest(r *http.Request, override string) string {
	if override != "" {
		return override
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fp := r.Header.Get("X-Forwarded-Proto"); fp != "" {
		scheme = fp
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host + P(r.Context(), "/login/oidc/callback")
}

func oauthConfigFor(cfg oidcLoginConfig, doc *oidcDiscoveryDoc, r *http.Request) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.clientID,
		ClientSecret: cfg.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  doc.AuthorizationEndpoint,
			TokenURL: doc.TokenEndpoint,
		},
		RedirectURL: redirectURLFromRequest(r, cfg.redirectURL),
		Scopes:      cfg.scopes,
	}
}

// oidcLoginError redirects to the native login form with a user-facing
// message, after logging the real error server-side -- mirrors the existing
// HandleLogin/TrustedProxyAutoLogin error-handling style in
// auth_middleware.go.
func oidcLoginError(w http.ResponseWriter, r *http.Request, logMsg string, err error, userMsg string) {
	if err != nil {
		glog.Errorf("OIDC login: %s: %v", logMsg, err)
	} else {
		glog.Warningf("OIDC login: %s", logMsg)
	}
	http.Redirect(w, r, P(r.Context(), "/login?error="+userMsg), http.StatusSeeOther)
}

// HandleOIDCStart begins the Authorization Code + PKCE flow, redirecting the
// browser to the configured identity provider's own login page.
func (s *AdminServer) HandleOIDCStart(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := loadOIDCLoginConfig()
		if !cfg.configured() {
			oidcLoginError(w, r, "start called but OIDC login is not configured", nil, "OIDC login is not configured")
			return
		}

		doc, err := discoverOIDCEndpoints(r.Context(), cfg.issuer)
		if err != nil {
			oidcLoginError(w, r, "discovery failed", err, "Unable to reach the identity provider. Please try again or contact administrator.")
			return
		}

		state := oauth2.GenerateVerifier() // 32 bytes of URL-safe randomness; reused as an opaque anti-CSRF state value, not just a PKCE verifier
		verifier := oauth2.GenerateVerifier()

		session, err := store.Get(r, sessionName)
		if err != nil {
			oidcLoginError(w, r, "failed to create pre-auth session", err, "Unable to create session. Please try again or contact administrator.")
			return
		}
		session.Values[oidcSessionStateKey] = state
		session.Values[oidcSessionVerifierKey] = verifier
		if err := session.Save(r, w); err != nil {
			oidcLoginError(w, r, "failed to save pre-auth session", err, "Unable to create session. Please try again or contact administrator.")
			return
		}

		authURL := oauthConfigFor(cfg, doc, r).AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, authURL, http.StatusSeeOther)
	}
}

// HandleOIDCCallback completes the flow: exchanges the authorization code,
// verifies the returned ID token against weed/iam/oidc's production token
// validator, maps the token's `groups` claim to an admin/readonly role using
// the same convention as TrustedProxyAutoLogin, JIT-provisions a persisted
// Identity for first-time logins (Phase 2), and establishes a native
// session.
func (s *AdminServer) HandleOIDCCallback(store sessions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := loadOIDCLoginConfig()
		if !cfg.configured() {
			oidcLoginError(w, r, "callback called but OIDC login is not configured", nil, "OIDC login is not configured")
			return
		}

		if errParam := r.URL.Query().Get("error"); errParam != "" {
			oidcLoginError(w, r, fmt.Sprintf("provider returned error=%s description=%s", errParam, r.URL.Query().Get("error_description")), nil, "Login was cancelled or denied by the identity provider")
			return
		}

		session, err := store.Get(r, sessionName)
		if err != nil {
			oidcLoginError(w, r, "failed to load session", err, "Unable to load session. Please try again or contact administrator.")
			return
		}

		expectedState, _ := session.Values[oidcSessionStateKey].(string)
		verifier, _ := session.Values[oidcSessionVerifierKey].(string)
		delete(session.Values, oidcSessionStateKey)
		delete(session.Values, oidcSessionVerifierKey)

		gotState := r.URL.Query().Get("state")
		if expectedState == "" || gotState == "" || subtle.ConstantTimeCompare([]byte(expectedState), []byte(gotState)) != 1 {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "state mismatch", nil, "Invalid or expired login attempt. Please try again.")
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "callback missing authorization code", nil, "Login failed. Please try again or contact administrator.")
			return
		}

		doc, err := discoverOIDCEndpoints(r.Context(), cfg.issuer)
		if err != nil {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "discovery failed on callback", err, "Unable to reach the identity provider. Please try again or contact administrator.")
			return
		}

		token, err := oauthConfigFor(cfg, doc, r).Exchange(r.Context(), code, oauth2.VerifierOption(verifier))
		if err != nil {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "code exchange failed", err, "Login failed. Please try again or contact administrator.")
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "token response missing id_token", nil, "Login failed. Please try again or contact administrator.")
			return
		}

		provider := oidc.NewOIDCProvider("admin-ui-login")
		if err := provider.Initialize(&oidc.OIDCConfig{Issuer: cfg.issuer, ClientID: cfg.clientID}); err != nil {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "provider init failed", err, "Login failed. Please try again or contact administrator.")
			return
		}

		claims, err := provider.ValidateToken(r.Context(), rawIDToken)
		if err != nil {
			_ = session.Save(r, w)
			oidcLoginError(w, r, "id_token validation failed", err, "Login failed: could not verify identity token")
			return
		}

		username, _ := claims.GetClaimString(cfg.usernameClaim)
		if username == "" {
			username, _ = claims.GetClaimString("email")
		}
		if username == "" {
			username = claims.Subject
		}
		email, _ := claims.GetClaimString("email")
		displayName, _ := claims.GetClaimString("name")
		if displayName == "" {
			displayName = username
		}

		groups, _ := claims.GetClaimStringSlice("groups")
		var role string
		for _, g := range groups {
			switch strings.TrimSpace(g) {
			case cfg.adminGroup:
				role = "admin"
			case cfg.viewerGroup:
				if role == "" {
					role = "readonly"
				}
			}
		}
		if role == "" {
			_ = session.Save(r, w)
			http.Error(w, "Forbidden: no recognized SeaweedFS admin/viewer group in your OIDC groups claim", http.StatusForbidden)
			return
		}

		// Phase 2: JIT-provision a persisted Identity for first-time logins, so
		// this person shows up in Object Store -> Users exactly like a static
		// access-key user and can be assigned to a Group from the Admin UI
		// (Phase 3, already-working, zero code). Best-effort: a provisioning
		// hiccup (e.g. a transient filer/grpc error) must not lock a
		// group-authorized person out of the session Phase 1 already granted
		// them -- it only means they won't appear in Users until the next
		// successful login. `credentials` is deliberately left empty (verified
		// legitimate in Phase 0) and `is_static` defaults to false, marking this
		// as a federated-only identity distinct from the static config file.
		// Account.Id/DisplayName are set from the token's own claims so this
		// identity, like every other one, has a stable id usable for object
		// ownership attribution (see jitProvisionOIDCUser's doc comment).
		s.jitProvisionOIDCUser(r.Context(), username, displayName, email)

		for key := range session.Values {
			delete(session.Values, key)
		}
		session.Values["authenticated"] = true
		session.Values["username"] = username
		session.Values["role"] = role
		csrfToken, err := generateCSRFToken()
		if err != nil {
			oidcLoginError(w, r, "failed to generate post-login CSRF token", err, "Unable to create session. Please try again or contact administrator.")
			return
		}
		session.Values[sessionCSRFTokenKey] = csrfToken
		if err := session.Save(r, w); err != nil {
			oidcLoginError(w, r, "failed to save authenticated session for "+username, err, "Unable to create session. Please try again or contact administrator.")
			return
		}

		http.Redirect(w, r, P(r.Context(), "/admin"), http.StatusSeeOther)
	}
}

// jitProvisionOIDCUser ensures a persisted Identity exists for a
// group-authorized OIDC login (Phase 2). GetUser-else-CreateUser, matching
// the plan's exact shape: a federated-only Identity with zero Credentials
// (Phase 0 confirmed the credential store's proto and CreateUser/GetUser
// path both accept that -- no HMAC access-key/secret-key pair is created or
// needed, this identity is only reachable by signing in through Keycloak).
// Errors are logged, not surfaced -- see the call site's comment on why this
// must stay best-effort.
//
// Every identity this creates gets a stable Account.Id (Refresquito
// addition, object-ownership work) -- displayName/email come from the OIDC
// token's own `name`/`email` claims when present, falling back to the
// username. This is what lets an uploaded file's owner be attributed to a
// real, permanent id instead of silently having none (see
// setObjectOwnerFromRequest / uploadFileGrpc).
func (s *AdminServer) jitProvisionOIDCUser(ctx context.Context, username, displayName, email string) {
	if s.credentialManager == nil {
		glog.Warningf("OIDC login: credential manager not available, skipping JIT provisioning for %s", username)
		return
	}

	if existing, err := s.credentialManager.GetUser(ctx, username); err == nil {
		// Already provisioned (either from a prior OIDC login, or a static/
		// access-key user that happens to share this username). Backfill an
		// Account for identities JIT-provisioned before this field existed --
		// best-effort, same as the rest of this function.
		if existing.Account == nil {
			existing.Account = &iam_pb.Account{Id: generateAccountId(), DisplayName: displayName, EmailAddress: email}
			if err := s.credentialManager.UpdateUser(ctx, username, existing); err != nil {
				glog.Errorf("OIDC login: failed to backfill Account for existing user %s: %v", username, err)
			}
		}
		return
	} else if !errors.Is(err, credential.ErrUserNotFound) {
		glog.Errorf("OIDC login: GetUser failed while checking JIT provisioning for %s: %v", username, err)
		return
	}

	identity := &iam_pb.Identity{
		Name:    username,
		Account: &iam_pb.Account{Id: generateAccountId(), DisplayName: displayName, EmailAddress: email},
	}
	if err := s.credentialManager.CreateUser(ctx, identity); err != nil && !errors.Is(err, credential.ErrUserAlreadyExists) {
		glog.Errorf("OIDC login: JIT provisioning (CreateUser) failed for %s: %v", username, err)
	}
}
