package dash

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/credential"
	_ "github.com/seaweedfs/seaweedfs/weed/credential/memory" // registers the "memory" store used by these tests
	"github.com/seaweedfs/seaweedfs/weed/pb/iam_pb"
)

func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		old, had := os.LookupEnv(k)
		if v == "" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestLoadOIDCLoginConfigDefaults(t *testing.T) {
	withEnv(t, map[string]string{
		"WEED_ADMIN_OIDC_ENABLED":        "true",
		"WEED_ADMIN_OIDC_ISSUER":         "https://iam.example.com/realms/refresquito/",
		"WEED_ADMIN_OIDC_CLIENT_ID":      "seaweedfs-admin",
		"WEED_ADMIN_OIDC_CLIENT_SECRET":  "",
		"WEED_ADMIN_OIDC_USERNAME_CLAIM": "",
		"WEED_ADMIN_OIDC_ADMIN_GROUP":    "",
		"WEED_ADMIN_OIDC_VIEWER_GROUP":   "",
		"WEED_ADMIN_OIDC_SCOPES":         "",
	})

	cfg := loadOIDCLoginConfig()

	if !cfg.configured() {
		t.Fatalf("expected configured() to be true")
	}
	if cfg.issuer != "https://iam.example.com/realms/refresquito" {
		t.Errorf("issuer trailing slash not trimmed: %q", cfg.issuer)
	}
	if cfg.usernameClaim != "preferred_username" {
		t.Errorf("usernameClaim default = %q, want preferred_username", cfg.usernameClaim)
	}
	if cfg.adminGroup != "seaweedfs-admin" {
		t.Errorf("adminGroup default = %q, want seaweedfs-admin", cfg.adminGroup)
	}
	if cfg.viewerGroup != "seaweedfs-viewer" {
		t.Errorf("viewerGroup default = %q, want seaweedfs-viewer", cfg.viewerGroup)
	}
	want := []string{"openid", "profile", "email", "groups"}
	if len(cfg.scopes) != len(want) {
		t.Fatalf("scopes default = %v, want %v", cfg.scopes, want)
	}
	for i, s := range want {
		if cfg.scopes[i] != s {
			t.Errorf("scopes[%d] = %q, want %q", i, cfg.scopes[i], s)
		}
	}
}

func TestLoadOIDCLoginConfigNotConfiguredWhenDisabled(t *testing.T) {
	withEnv(t, map[string]string{
		"WEED_ADMIN_OIDC_ENABLED":   "false",
		"WEED_ADMIN_OIDC_ISSUER":    "https://iam.example.com/realms/refresquito",
		"WEED_ADMIN_OIDC_CLIENT_ID": "seaweedfs-admin",
	})

	if loadOIDCLoginConfig().configured() {
		t.Fatalf("expected configured() to be false when WEED_ADMIN_OIDC_ENABLED=false")
	}
}

func TestLoadOIDCLoginConfigNotConfiguredWhenMissingIssuerOrClientID(t *testing.T) {
	cases := []map[string]string{
		{"WEED_ADMIN_OIDC_ENABLED": "true", "WEED_ADMIN_OIDC_ISSUER": "", "WEED_ADMIN_OIDC_CLIENT_ID": "seaweedfs-admin"},
		{"WEED_ADMIN_OIDC_ENABLED": "true", "WEED_ADMIN_OIDC_ISSUER": "https://iam.example.com/realms/refresquito", "WEED_ADMIN_OIDC_CLIENT_ID": ""},
	}
	for _, env := range cases {
		withEnv(t, env)
		if loadOIDCLoginConfig().configured() {
			t.Fatalf("expected configured() to be false for env %v", env)
		}
	}
}

func TestLoadOIDCLoginConfigCustomScopes(t *testing.T) {
	withEnv(t, map[string]string{
		"WEED_ADMIN_OIDC_SCOPES": "openid, profile ,  email",
	})

	cfg := loadOIDCLoginConfig()
	want := []string{"openid", "profile", "email"}
	if len(cfg.scopes) != len(want) {
		t.Fatalf("scopes = %v, want %v", cfg.scopes, want)
	}
	for i, s := range want {
		if cfg.scopes[i] != s {
			t.Errorf("scopes[%d] = %q, want %q", i, cfg.scopes[i], s)
		}
	}
}

func TestRedirectURLFromRequestOverride(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://admin.internal/login/oidc/start", nil)
	got := redirectURLFromRequest(r, "https://override.example.com/callback")
	if got != "https://override.example.com/callback" {
		t.Errorf("redirectURLFromRequest() = %q, want override honored", got)
	}
}

func TestRedirectURLFromRequestDerivedFromProxyHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://internal-service/login/oidc/start", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "seaweedfs.refresquito.com")

	got := redirectURLFromRequest(r, "")
	want := "https://seaweedfs.refresquito.com/login/oidc/callback"
	if got != want {
		t.Errorf("redirectURLFromRequest() = %q, want %q", got, want)
	}
}

func TestRedirectURLFromRequestDerivedFromPlainRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://admin.internal/login/oidc/start", nil)
	got := redirectURLFromRequest(r, "")
	want := "http://admin.internal/login/oidc/callback"
	if got != want {
		t.Errorf("redirectURLFromRequest() = %q, want %q", got, want)
	}
}

func TestRedirectURLFromRequestHonorsURLPrefix(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://admin.internal/seaweedfs/login/oidc/start", nil)
	r = r.WithContext(WithURLPrefix(r.Context(), "/seaweedfs"))
	got := redirectURLFromRequest(r, "")
	want := "http://admin.internal/seaweedfs/login/oidc/callback"
	if got != want {
		t.Errorf("redirectURLFromRequest() = %q, want %q", got, want)
	}
}

func TestDiscoverOIDCEndpointsSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected discovery path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": "https://iam.example.com/auth",
			"token_endpoint":         "https://iam.example.com/token",
		})
	}))
	defer srv.Close()

	doc, err := discoverOIDCEndpoints(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("discoverOIDCEndpoints() error = %v", err)
	}
	if doc.AuthorizationEndpoint != "https://iam.example.com/auth" || doc.TokenEndpoint != "https://iam.example.com/token" {
		t.Errorf("unexpected discovery doc: %+v", doc)
	}
}

func TestDiscoverOIDCEndpointsMissingFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"authorization_endpoint": "https://iam.example.com/auth"})
	}))
	defer srv.Close()

	if _, err := discoverOIDCEndpoints(context.Background(), srv.URL); err == nil {
		t.Fatalf("expected error for discovery document missing token_endpoint")
	}
}

func TestDiscoverOIDCEndpointsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := discoverOIDCEndpoints(context.Background(), srv.URL); err == nil {
		t.Fatalf("expected error for non-200 discovery response")
	}
}

func TestOIDCLoginEnabled(t *testing.T) {
	withEnv(t, map[string]string{
		"WEED_ADMIN_OIDC_ENABLED":   "true",
		"WEED_ADMIN_OIDC_ISSUER":    "https://iam.example.com/realms/refresquito",
		"WEED_ADMIN_OIDC_CLIENT_ID": "seaweedfs-admin",
	})
	if !OIDCLoginEnabled() {
		t.Fatalf("expected OIDCLoginEnabled() to be true")
	}
}

// sanity check that state/verifier generation and query-encoding of AuthCodeURL
// don't blow up given a real-shaped config (no network call involved).
func TestOAuthConfigForBuildsSaneAuthURL(t *testing.T) {
	cfg := oidcLoginConfig{
		enabled:  true,
		issuer:   "https://iam.example.com/realms/refresquito",
		clientID: "seaweedfs-admin",
		scopes:   []string{"openid", "profile", "email", "groups"},
	}
	doc := &oidcDiscoveryDoc{
		AuthorizationEndpoint: "https://iam.example.com/auth",
		TokenEndpoint:         "https://iam.example.com/token",
	}
	r := httptest.NewRequest(http.MethodGet, "http://admin.internal/login/oidc/start", nil)

	oauthCfg := oauthConfigFor(cfg, doc, r)
	authURL := oauthCfg.AuthCodeURL("teststate")

	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("AuthCodeURL produced an unparseable URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "seaweedfs-admin" {
		t.Errorf("client_id = %q, want seaweedfs-admin", q.Get("client_id"))
	}
	if q.Get("state") != "teststate" {
		t.Errorf("state = %q, want teststate", q.Get("state"))
	}
	if q.Get("redirect_uri") != "http://admin.internal/login/oidc/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
}

// newTestAdminServerWithCredentialManager builds a bare AdminServer wired to
// an isolated in-memory credential store, sufficient for exercising
// jitProvisionOIDCUser without a real filer/grpc backend.
func newTestAdminServerWithCredentialManager(t *testing.T) *AdminServer {
	t.Helper()
	cm, err := credential.NewCredentialManagerWithDefaults(credential.StoreTypeMemory)
	if err != nil {
		t.Fatalf("failed to create memory credential manager: %v", err)
	}
	return &AdminServer{credentialManager: cm}
}

func TestJITProvisionOIDCUserCreatesFederatedIdentity(t *testing.T) {
	s := newTestAdminServerWithCredentialManager(t)
	ctx := context.Background()

	s.jitProvisionOIDCUser(ctx, "alice@example.com", "Alice Example", "alice@example.com")

	identity, err := s.credentialManager.GetUser(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("expected user to be provisioned, GetUser error = %v", err)
	}
	if identity.Name != "alice@example.com" {
		t.Errorf("identity.Name = %q, want alice@example.com", identity.Name)
	}
	if len(identity.Credentials) != 0 {
		t.Errorf("expected zero Credentials on a JIT-provisioned identity, got %d", len(identity.Credentials))
	}
	if identity.IsStatic {
		t.Errorf("expected IsStatic=false on a JIT-provisioned identity")
	}
	if identity.Account == nil || identity.Account.Id == "" {
		t.Fatalf("expected a stable Account.Id to be assigned, got %+v", identity.Account)
	}
	if identity.Account.DisplayName != "Alice Example" {
		t.Errorf("Account.DisplayName = %q, want Alice Example", identity.Account.DisplayName)
	}
	if identity.Account.EmailAddress != "alice@example.com" {
		t.Errorf("Account.EmailAddress = %q, want alice@example.com", identity.Account.EmailAddress)
	}
}

func TestJITProvisionOIDCUserIdempotentOnRepeatedLogin(t *testing.T) {
	s := newTestAdminServerWithCredentialManager(t)
	ctx := context.Background()

	s.jitProvisionOIDCUser(ctx, "bob@example.com", "Bob Example", "bob@example.com")
	s.jitProvisionOIDCUser(ctx, "bob@example.com", "Bob Example", "bob@example.com") // second login, must not error/panic

	identity, err := s.credentialManager.GetUser(ctx, "bob@example.com")
	if err != nil {
		t.Fatalf("GetUser after repeated provisioning error = %v", err)
	}
	if identity.Name != "bob@example.com" {
		t.Errorf("identity.Name = %q, want bob@example.com", identity.Name)
	}
}

func TestJITProvisionOIDCUserRepeatedLoginKeepsSameAccountId(t *testing.T) {
	s := newTestAdminServerWithCredentialManager(t)
	ctx := context.Background()

	s.jitProvisionOIDCUser(ctx, "eve@example.com", "Eve Example", "eve@example.com")
	first, err := s.credentialManager.GetUser(ctx, "eve@example.com")
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	firstId := first.Account.Id

	s.jitProvisionOIDCUser(ctx, "eve@example.com", "Eve Example", "eve@example.com")
	second, err := s.credentialManager.GetUser(ctx, "eve@example.com")
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if second.Account.Id != firstId {
		t.Errorf("Account.Id changed across logins: %q -> %q -- object-ownership stamps from earlier uploads would orphan", firstId, second.Account.Id)
	}
}

func TestJITProvisionOIDCUserLeavesExistingUserCredentialsAndPoliciesUntouched(t *testing.T) {
	s := newTestAdminServerWithCredentialManager(t)
	ctx := context.Background()

	// Pre-existing user with real access-key credentials and policies, as an
	// admin might have created manually before this person's first OIDC login.
	// No Account set, simulating an identity created before Account became
	// mandatory -- this is also the backfill case exercised below.
	preexisting := &iam_pb.Identity{
		Name:        "carol@example.com",
		PolicyNames: []string{"S3ReadOnlyPolicy"},
		Credentials: []*iam_pb.Credential{{AccessKey: "AKIAEXISTING", SecretKey: "shh"}},
	}
	if err := s.credentialManager.CreateUser(ctx, preexisting); err != nil {
		t.Fatalf("failed to seed pre-existing user: %v", err)
	}

	s.jitProvisionOIDCUser(ctx, "carol@example.com", "Carol Example", "carol@example.com")

	identity, err := s.credentialManager.GetUser(ctx, "carol@example.com")
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if len(identity.Credentials) != 1 || identity.Credentials[0].AccessKey != "AKIAEXISTING" {
		t.Errorf("pre-existing credentials were disturbed: %+v", identity.Credentials)
	}
	if len(identity.PolicyNames) != 1 || identity.PolicyNames[0] != "S3ReadOnlyPolicy" {
		t.Errorf("pre-existing policy names were disturbed: %+v", identity.PolicyNames)
	}
	// The backfill this function is also responsible for.
	if identity.Account == nil || identity.Account.Id == "" {
		t.Errorf("expected Account to be backfilled on an existing identity that predates it, got %+v", identity.Account)
	}
}

func TestJITProvisionOIDCUserNilCredentialManagerDoesNotPanic(t *testing.T) {
	s := &AdminServer{}
	s.jitProvisionOIDCUser(context.Background(), "dave@example.com", "Dave Example", "dave@example.com") // must not panic
}
