package dash

import (
	"net/http"
	"os"
	"strings"
)

// IsFileBrowserOnlyHost reports whether the request's hostname is one of
// WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS -- the same check RestrictFileBrowserOnlyHosts
// uses to gate routes, exposed so view templates can also adapt their chrome
// (e.g. hide the full admin sidebar) for these hosts. Reads the env var fresh
// on every call (cheap: a short comma-separated list) rather than caching it,
// so tests can reconfigure it per case via t.Setenv.
func IsFileBrowserOnlyHost(r *http.Request) bool {
	hosts := parseFileBrowserOnlyHosts(os.Getenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS"))
	_, restricted := hosts[effectiveHostname(r)]
	return restricted
}

// RestrictFileBrowserOnlyHosts restricts specific public hostnames
// (Refresquito addition) to ONLY the File Browser surface -- everything
// else the Admin UI normally serves (the dashboard, cluster/storage/plugin
// management, Object Store administration pages) returns 404 for these
// hosts, and the root path (/ or /admin) redirects to /files instead of the
// dashboard. Every other hostname is completely unaffected.
//
// Configured via WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS: a comma-separated list
// of bare hostnames (no scheme/port), e.g.
// "seaweedfs.example.com,files.example.com". Empty/unset disables this
// entirely (the default -- existing deployments see no behavior change).
//
// This exists because a second public hostname can share this exact same
// weed-admin backend process (see the Refresquito seaweedfs-oneke chart's
// oauth2-proxy.yaml, whose "filer" instance now proxies here instead of the
// raw, unauthenticated Filer UI -- AUTHZ.md § seaweedfs-oneke #13) while
// being intended purely as a bucket-browsing surface for less-trusted
// users, distinct from the fully administrative host
// (admin-seaweedfs.example.com), which must keep seeing everything.
func RestrictFileBrowserOnlyHosts() func(http.Handler) http.Handler {
	hosts := parseFileBrowserOnlyHosts(os.Getenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS"))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(hosts) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			if _, restricted := hosts[effectiveHostname(r)]; !restricted {
				next.ServeHTTP(w, r)
				return
			}

			prefix := URLPrefixFromContext(r.Context())
			path := strings.TrimPrefix(r.URL.Path, prefix)

			if path == "/" || path == "/admin" {
				http.Redirect(w, r, prefix+"/files", http.StatusSeeOther)
				return
			}
			if isFileBrowserOnlyAllowedPath(path) {
				next.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		})
	}
}

// isFileBrowserOnlyAllowedPath lists everything a restricted host must still
// reach: the File Browser page itself, its supporting API, the login/logout
// flow (both native and OIDC -- a restricted host still needs a real login),
// static assets the page renders with, and the two unauthenticated
// housekeeping routes (health check, favicon).
func isFileBrowserOnlyAllowedPath(path string) bool {
	switch path {
	case "/files", "/login", "/logout", "/login/oidc/start", "/login/oidc/callback", "/health", "/favicon.ico":
		return true
	}
	return strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, "/api/files/")
}

// effectiveHostname returns the request's public-facing hostname (honoring
// a reverse proxy's X-Forwarded-Host, same convention as
// redirectURLFromRequest in oidc_login.go), lowercased and stripped of any
// port, since WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS is configured as bare
// hostnames.
func effectiveHostname(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if idx := strings.IndexByte(host, ':'); idx != -1 {
		host = host[:idx]
	}
	return strings.ToLower(host)
}

func parseFileBrowserOnlyHosts(raw string) map[string]struct{} {
	hosts := make(map[string]struct{})
	for _, h := range strings.Split(raw, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			hosts[h] = struct{}{}
		}
	}
	return hosts
}
