package dash

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/seaweedfs/seaweedfs/weed/glog"
)

// ShowLogin displays the login page.
func (s *AdminServer) ShowLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, P(r.Context(), "/login"), http.StatusSeeOther)
}

// HandleLogin handles login form submission.
func (s *AdminServer) HandleLogin(store sessions.Store, adminUser, adminPassword, readOnlyUser, readOnlyPassword string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := URLPrefixFromContext(r.Context())
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, prefix+"/login?error=Invalid form submission", http.StatusSeeOther)
			return
		}
		session, err := store.Get(r, sessionName)
		if err != nil {
			http.Redirect(w, r, prefix+"/login?error=Unable to create session. Please try again or contact administrator.", http.StatusSeeOther)
			return
		}

		if err := ValidateSessionCSRFToken(session, r); err != nil {
			http.Redirect(w, r, prefix+"/login?error=Invalid CSRF token", http.StatusSeeOther)
			return
		}

		loginUsername := r.FormValue("username")
		loginPassword := r.FormValue("password")

		var role string
		var authenticated bool

		// Check admin credentials.
		if adminPassword != "" && loginUsername == adminUser && subtle.ConstantTimeCompare([]byte(loginPassword), []byte(adminPassword)) == 1 {
			role = "admin"
			authenticated = true
		} else if readOnlyPassword != "" && loginUsername == readOnlyUser && subtle.ConstantTimeCompare([]byte(loginPassword), []byte(readOnlyPassword)) == 1 {
			// Check read-only credentials.
			role = "readonly"
			authenticated = true
		}

		if authenticated {
			for key := range session.Values {
				delete(session.Values, key)
			}
			session.Values["authenticated"] = true
			session.Values["username"] = loginUsername
			session.Values["role"] = role
			csrfToken, err := generateCSRFToken()
			if err != nil {
				http.Redirect(w, r, prefix+"/login?error=Unable to create session. Please try again or contact administrator.", http.StatusSeeOther)
				return
			}
			session.Values[sessionCSRFTokenKey] = csrfToken
			if err := session.Save(r, w); err != nil {
				// Log the detailed error server-side for diagnostics.
				glog.Errorf("Failed to save session for user %s: %v", loginUsername, err)
				http.Redirect(w, r, prefix+"/login?error=Unable to create session. Please try again or contact administrator.", http.StatusSeeOther)
				return
			}

			http.Redirect(w, r, prefix+"/admin", http.StatusSeeOther)
			return
		}

		// Authentication failed.
		http.Redirect(w, r, prefix+"/login?error=Invalid credentials", http.StatusSeeOther)
	}
}

// HandleLogout handles user logout.
func (s *AdminServer) HandleLogout(store sessions.Store, w http.ResponseWriter, r *http.Request) {
	prefix := URLPrefixFromContext(r.Context())
	session, err := store.Get(r, sessionName)
	if err != nil {
		http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
		return
	}
	for key := range session.Values {
		delete(session.Values, key)
	}
	session.Options.MaxAge = -1
	if err := session.Save(r, w); err != nil {
		glog.Warningf("Failed to save session during logout: %v", err)
	}
	http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
}

// TrustedProxyAutoLogin auto-establishes an authenticated admin-session
// (Refresquito addition) from trusted reverse-proxy headers -- X-Forwarded-User
// and X-Forwarded-Groups, as emitted by oauth2-proxy after a real upstream
// (Keycloak) login -- instead of requiring weed admin's own separate
// username/password form. This lets a single Keycloak login carry through to
// a real, per-person weed-admin session (session.Values["username"] becomes
// the actual Keycloak username, not the shared "admin"/"readonly" account
// name), so actions taken in the Admin UI (file uploads, deletes, etc.) can
// be attributed to the real person instead of a generic shared account.
//
// Only takes effect when WEED_ADMIN_TRUSTED_PROXY_ENABLED=true. Any request
// that doesn't carry both trusted headers falls through unchanged to the
// next handler in the chain (normally RequireAuth/RequireAuthAPI), which
// then serves the native login form as before -- so the native
// adminUser/readOnlyUser accounts remain a working break-glass path if the
// proxy/IdP is ever unavailable, matching the same coexistence model
// documented for SeaweedFS Enterprise's own Admin UI OIDC feature.
//
// Security: this function does NOT itself verify that the request actually
// came through the trusted proxy -- there is no shared-secret or signature
// check here by design. It MUST only be enabled behind a network boundary
// that guarantees these two headers cannot be set by anything other than
// the trusted reverse proxy (e.g. a NetworkPolicy restricting this
// Service/Deployment to accept traffic only from the proxy's own pod). The
// network boundary IS the trust boundary; do not enable
// WEED_ADMIN_TRUSTED_PROXY_ENABLED without one.
func TrustedProxyAutoLogin(store sessions.Store) mux.MiddlewareFunc {
	adminGroup := os.Getenv("WEED_ADMIN_TRUSTED_PROXY_ADMIN_GROUP")
	if adminGroup == "" {
		adminGroup = "seaweedfs-admin"
	}
	viewerGroup := os.Getenv("WEED_ADMIN_TRUSTED_PROXY_VIEWER_GROUP")
	if viewerGroup == "" {
		viewerGroup = "seaweedfs-viewer"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if os.Getenv("WEED_ADMIN_TRUSTED_PROXY_ENABLED") != "true" {
				next.ServeHTTP(w, r)
				return
			}

			session, err := store.Get(r, sessionName)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Already have a real session (native login, or a previous pass
			// through this same middleware earlier in this browser session)
			// -- nothing to do.
			if authenticated, _ := session.Values["authenticated"].(bool); authenticated {
				next.ServeHTTP(w, r)
				return
			}

			forwardedUser := r.Header.Get("X-Forwarded-User")
			forwardedGroups := r.Header.Get("X-Forwarded-Groups")
			if forwardedUser == "" || forwardedGroups == "" {
				next.ServeHTTP(w, r)
				return
			}

			var role string
			for _, g := range strings.Split(forwardedGroups, ",") {
				switch strings.TrimSpace(g) {
				case adminGroup:
					role = "admin"
				case viewerGroup:
					if role == "" {
						role = "readonly"
					}
				}
			}
			if role == "" {
				// Authenticated by the proxy, but not a member of either
				// recognized group -- deny explicitly rather than silently
				// falling through to an unauthenticated native-login
				// prompt, which would look like a bug rather than the
				// intended denial.
				http.Error(w, "Forbidden: no recognized SeaweedFS admin/viewer group in X-Forwarded-Groups", http.StatusForbidden)
				return
			}

			for key := range session.Values {
				delete(session.Values, key)
			}
			session.Values["authenticated"] = true
			session.Values["username"] = forwardedUser
			session.Values["role"] = role
			csrfToken, err := generateCSRFToken()
			if err != nil {
				glog.Errorf("TrustedProxyAutoLogin: failed to generate CSRF token for %s: %v", forwardedUser, err)
				next.ServeHTTP(w, r)
				return
			}
			session.Values[sessionCSRFTokenKey] = csrfToken
			if err := session.Save(r, w); err != nil {
				glog.Errorf("TrustedProxyAutoLogin: failed to save session for %s: %v", forwardedUser, err)
				next.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
