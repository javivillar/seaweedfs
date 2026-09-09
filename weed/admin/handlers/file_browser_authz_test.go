package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/admin/dash"
)

func TestBucketIndexPath(t *testing.T) {
	cases := map[string]bool{
		"/":                  true,
		"/buckets":           true,
		"/buckets/":          true,
		"buckets":            true,
		"/buckets/mybucket":  false,
		"/buckets/mybucket/": false,
		"/some/other/path":   false,
	}
	for path, want := range cases {
		if got := bucketIndexPath(path); got != want {
			t.Errorf("bucketIndexPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestAuthorizeBucketActionAllowsIndexRegardlessOfRole(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	r = r.WithContext(dash.WithAuthContext(r.Context(), "someone", "readonly", ""))
	w := httptest.NewRecorder()

	if !h.authorizeBucketAction(w, r, dash.ActionListBucket, "/buckets") {
		t.Errorf("expected the bucket index to be allowed regardless of role")
	}
	if w.Code != 0 && w.Code != http.StatusOK {
		t.Errorf("expected no error response written, got status %d", w.Code)
	}
}

func TestAuthorizeBucketActionAdminBypassesEvenWithoutCredentialManager(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	r = r.WithContext(dash.WithAuthContext(r.Context(), "admin-user", "admin", ""))
	w := httptest.NewRecorder()

	if !h.authorizeBucketAction(w, r, dash.ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected admin role to bypass bucket authorization")
	}
}

func TestAuthorizeBucketActionDeniesReadonlyWithoutPolicy(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	r = r.WithContext(dash.WithAuthContext(r.Context(), "viewer-user", "readonly", ""))
	w := httptest.NewRecorder()

	if h.authorizeBucketAction(w, r, dash.ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected deny-by-default for a readonly user with no credential manager/policies")
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("expected a 403 response to be written, got status %d", w.Code)
	}
}

func TestAuthorizeBucketActionDeniesNonBucketPathForReadonly(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/files", nil)
	r = r.WithContext(dash.WithAuthContext(r.Context(), "viewer-user", "readonly", ""))
	w := httptest.NewRecorder()

	if h.authorizeBucketAction(w, r, dash.ActionGetObject, "/some/raw/filer/path.txt") {
		t.Errorf("expected deny for a non-bucket path")
	}
}
