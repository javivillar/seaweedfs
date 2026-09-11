package dash

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func withFileBrowserOnlyHostsEnv(t *testing.T, value string) {
	t.Helper()
	old, had := os.LookupEnv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS")
	if value == "" {
		os.Unsetenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS")
	} else {
		os.Setenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS", value)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS", old)
		} else {
			os.Unsetenv("WEED_ADMIN_FILE_BROWSER_ONLY_HOSTS")
		}
	})
}

func passthroughHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestRestrictFileBrowserOnlyHostsDisabledByDefault(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	r := httptest.NewRequest(http.MethodGet, "http://seaweedfs.example.com/plugin", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected pass-through when unconfigured, got status %d", w.Code)
	}
}

func TestRestrictFileBrowserOnlyHostsUnaffectedHostPassesThrough(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "seaweedfs.example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	r := httptest.NewRequest(http.MethodGet, "http://admin-seaweedfs.example.com/plugin", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected a non-restricted host to see every route, got status %d", w.Code)
	}
}

func TestRestrictFileBrowserOnlyHostsBlocksOtherAdminPages(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "seaweedfs.example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	for _, path := range []string{"/plugin", "/cluster/masters", "/object-store/buckets", "/mq/brokers"} {
		r := httptest.NewRequest(http.MethodGet, "http://seaweedfs.example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("path %q: expected 404 on a restricted host, got status %d", path, w.Code)
		}
	}
}

func TestRestrictFileBrowserOnlyHostsRedirectsRootToFiles(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "seaweedfs.example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	for _, path := range []string{"/", "/admin"} {
		r := httptest.NewRequest(http.MethodGet, "http://seaweedfs.example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusSeeOther {
			t.Errorf("path %q: expected a redirect, got status %d", path, w.Code)
			continue
		}
		if got := w.Header().Get("Location"); got != "/files" {
			t.Errorf("path %q: redirect Location = %q, want /files", path, got)
		}
	}
}

func TestRestrictFileBrowserOnlyHostsAllowsFileBrowserAndSupportingRoutes(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "seaweedfs.example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	allowed := []string{
		"/files",
		"/login",
		"/logout",
		"/login/oidc/start",
		"/login/oidc/callback",
		"/health",
		"/favicon.ico",
		"/static/css/bootstrap.min.css",
		"/api/files/upload",
		"/api/files/properties",
	}
	for _, path := range allowed {
		r := httptest.NewRequest(http.MethodGet, "http://seaweedfs.example.com"+path, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("path %q: expected to be allowed through, got status %d", path, w.Code)
		}
	}
}

func TestRestrictFileBrowserOnlyHostsHonorsXForwardedHost(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "seaweedfs.example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	// Direct Host header says something unrestricted, but the reverse
	// proxy's X-Forwarded-Host (what real traffic actually presents) is the
	// restricted one -- must still be gated.
	r := httptest.NewRequest(http.MethodGet, "http://internal-service:23646/plugin", nil)
	r.Header.Set("X-Forwarded-Host", "seaweedfs.example.com")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected X-Forwarded-Host to be honored, got status %d", w.Code)
	}
}

func TestRestrictFileBrowserOnlyHostsCaseAndPortInsensitive(t *testing.T) {
	withFileBrowserOnlyHostsEnv(t, "SeaweedFS.Example.com")
	mw := RestrictFileBrowserOnlyHosts()
	handler := mw(passthroughHandler())

	r := httptest.NewRequest(http.MethodGet, "http://seaweedfs.example.com:8080/plugin", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected hostname matching to be case- and port-insensitive, got status %d", w.Code)
	}
}

func TestParseFileBrowserOnlyHosts(t *testing.T) {
	got := parseFileBrowserOnlyHosts(" Seaweedfs.example.com , files.example.com,,")
	want := map[string]struct{}{"seaweedfs.example.com": {}, "files.example.com": {}}
	if len(got) != len(want) {
		t.Fatalf("parseFileBrowserOnlyHosts() = %v, want %v", got, want)
	}
	for h := range want {
		if _, ok := got[h]; !ok {
			t.Errorf("expected host %q in parsed set", h)
		}
	}
}
