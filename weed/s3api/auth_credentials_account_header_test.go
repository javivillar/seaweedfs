package s3api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
)

// Regression test for a real nil-pointer panic: identity.Account is nil for
// any identity that predates object-ownership work (a static config-file
// identity with no email, or one JIT-provisioned before Account became
// mandatory in the Admin UI's native OIDC login). setAmzAccountIdHeader must
// tolerate that instead of dereferencing identity.Account.Id directly, which
// is what authRequestWithAuthType/AuthSignatureOnly used to do inline at
// three call sites.
func TestSetAmzAccountIdHeaderNilIdentityDoesNotPanic(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	setAmzAccountIdHeader(r, nil) // must not panic
	if got := r.Header.Get(s3_constants.AmzAccountId); got != "" {
		t.Errorf("expected no header set for a nil identity, got %q", got)
	}
}

func TestSetAmzAccountIdHeaderNilAccountDoesNotPanic(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	identity := &Identity{Name: "admin"} // Account intentionally nil
	setAmzAccountIdHeader(r, identity)   // must not panic
	if got := r.Header.Get(s3_constants.AmzAccountId); got != "" {
		t.Errorf("expected no header set for an identity with a nil Account, got %q", got)
	}
}

func TestSetAmzAccountIdHeaderSetsAccountId(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	identity := &Identity{
		Name:    "pepe",
		Account: &Account{Id: "100000000042", DisplayName: "pepe"},
	}
	setAmzAccountIdHeader(r, identity)
	if got := r.Header.Get(s3_constants.AmzAccountId); got != "100000000042" {
		t.Errorf("AmzAccountId header = %q, want 100000000042", got)
	}
}
