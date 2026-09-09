package dash

import (
	"context"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/credential"
	_ "github.com/seaweedfs/seaweedfs/weed/credential/memory" // registers the "memory" store used by these tests
	"github.com/seaweedfs/seaweedfs/weed/pb/iam_pb"
	"github.com/seaweedfs/seaweedfs/weed/s3api/policy_engine"
)

func newTestAdminServerForAuthz(t *testing.T) *AdminServer {
	t.Helper()
	cm, err := credential.NewCredentialManagerWithDefaults(credential.StoreTypeMemory)
	if err != nil {
		t.Fatalf("failed to create memory credential manager: %v", err)
	}
	return &AdminServer{credentialManager: cm}
}

func mustParsePolicy(t *testing.T, jsonDoc string) policy_engine.PolicyDocument {
	t.Helper()
	doc, err := policy_engine.ParsePolicy(jsonDoc)
	if err != nil {
		t.Fatalf("ParsePolicy failed: %v", err)
	}
	return *doc
}

func TestBucketAndKeyFromPath(t *testing.T) {
	cases := []struct {
		in         string
		wantBucket string
		wantKey    string
		wantOk     bool
	}{
		{"/buckets/mybucket", "mybucket", "", true},
		{"/buckets/mybucket/", "mybucket", "", true},
		{"/buckets/mybucket/dir/file.txt", "mybucket", "dir/file.txt", true},
		{"buckets/mybucket/file.txt", "mybucket", "file.txt", true},
		{"/buckets", "", "", false},
		{"/buckets/", "", "", false},
		{"/", "", "", false},
		{"/some/other/path", "", "", false},
	}
	for _, tc := range cases {
		bucket, key, ok := bucketAndKeyFromPath(tc.in)
		if ok != tc.wantOk || bucket != tc.wantBucket || key != tc.wantKey {
			t.Errorf("bucketAndKeyFromPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, bucket, key, ok, tc.wantBucket, tc.wantKey, tc.wantOk)
		}
	}
}

func TestResourceArn(t *testing.T) {
	if got := resourceArn("my-bucket", ""); got != "arn:aws:s3:::my-bucket" {
		t.Errorf("resourceArn(bucket only) = %q", got)
	}
	if got := resourceArn("my-bucket", "dir/file.txt"); got != "arn:aws:s3:::my-bucket/dir/file.txt" {
		t.Errorf("resourceArn(with key) = %q", got)
	}
}

func TestCanAccessPathAdminAlwaysBypasses(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	// No identity, no policies at all -- admin role must still pass.
	if !s.CanAccessPath(context.Background(), "someone", "admin", ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected admin role to bypass bucket authz entirely")
	}
	// Even for a path with no bucket concept at all.
	if !s.CanAccessPath(context.Background(), "someone", "admin", ActionGetObject, "/raw/filer/path.txt") {
		t.Errorf("expected admin role to bypass even for non-bucket paths")
	}
}

func TestCanAccessPathDenyByDefaultNoPolicies(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "gina"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	if s.CanAccessPath(ctx, "gina", "readonly", ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected deny-by-default for a readonly user with zero attached policies")
	}
}

func TestCanAccessPathDeniesNonBucketPathsForNonAdmin(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "helen"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// Even a wide-open policy can't help -- there's no bucket to resolve.
	if err := s.credentialManager.CreatePolicy(ctx, "AllowAll", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.AttachUserPolicy(ctx, "helen", "AllowAll"); err != nil {
		t.Fatalf("attach policy: %v", err)
	}

	if s.CanAccessPath(ctx, "helen", "readonly", ActionGetObject, "/some/raw/filer/path.txt") {
		t.Errorf("expected deny for a non-/buckets/ path regardless of policy")
	}
}

func TestCanAccessPathAllowedByAttachedPolicy(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "irene"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.credentialManager.CreatePolicy(ctx, "ReportsReadWrite", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Action": ["s3:GetObject", "s3:PutObject"],
			"Resource": "arn:aws:s3:::reports/*"
		}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.AttachUserPolicy(ctx, "irene", "ReportsReadWrite"); err != nil {
		t.Fatalf("attach policy: %v", err)
	}

	if !s.CanAccessPath(ctx, "irene", "readonly", ActionGetObject, "/buckets/reports/q1.pdf") {
		t.Errorf("expected allow: policy grants s3:GetObject on reports/*")
	}
	if !s.CanAccessPath(ctx, "irene", "readonly", ActionPutObject, "/buckets/reports/q2.pdf") {
		t.Errorf("expected allow: policy grants s3:PutObject on reports/*")
	}
	if s.CanAccessPath(ctx, "irene", "readonly", ActionDeleteObject, "/buckets/reports/q1.pdf") {
		t.Errorf("expected deny: policy does not grant s3:DeleteObject")
	}
	if s.CanAccessPath(ctx, "irene", "readonly", ActionGetObject, "/buckets/other-bucket/file.txt") {
		t.Errorf("expected deny: policy only covers the reports bucket")
	}
}

func TestCanAccessPathAllowedViaGroupPolicy(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "bob"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.credentialManager.CreatePolicy(ctx, "MarketingRead", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::marketing/*"}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.CreateGroup(ctx, &iam_pb.Group{
		Name:        "marketing-team",
		Members:     []string{"bob"},
		PolicyNames: []string{"MarketingRead"},
	}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if !s.CanAccessPath(ctx, "bob", "readonly", ActionGetObject, "/buckets/marketing/brief.pdf") {
		t.Errorf("expected allow via group-attached policy")
	}
	// Not a member of the group that grants this -- must stay denied.
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "carol"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if s.CanAccessPath(ctx, "carol", "readonly", ActionGetObject, "/buckets/marketing/brief.pdf") {
		t.Errorf("expected deny: carol is not a member of marketing-team")
	}
}

func TestCanAccessPathDisabledGroupPolicyIgnored(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "dave"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.credentialManager.CreatePolicy(ctx, "OpsAll", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::ops/*"}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.CreateGroup(ctx, &iam_pb.Group{
		Name:        "ops-team",
		Members:     []string{"dave"},
		PolicyNames: []string{"OpsAll"},
		Disabled:    true,
	}); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if s.CanAccessPath(ctx, "dave", "readonly", ActionGetObject, "/buckets/ops/report.pdf") {
		t.Errorf("expected deny: the granting group is disabled")
	}
}

func TestCanAccessPathExplicitDenyOverridesAllow(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "erin"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.credentialManager.CreatePolicy(ctx, "FinanceReadAllow", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::finance/*"}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.CreatePolicy(ctx, "FinanceSecretsDeny", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::finance/secrets/*"}]
	}`)); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := s.credentialManager.AttachUserPolicy(ctx, "erin", "FinanceReadAllow"); err != nil {
		t.Fatalf("attach policy: %v", err)
	}
	if err := s.credentialManager.AttachUserPolicy(ctx, "erin", "FinanceSecretsDeny"); err != nil {
		t.Fatalf("attach policy: %v", err)
	}

	if !s.CanAccessPath(ctx, "erin", "readonly", ActionGetObject, "/buckets/finance/q1.pdf") {
		t.Errorf("expected allow: only the broad Allow policy applies here")
	}
	if s.CanAccessPath(ctx, "erin", "readonly", ActionGetObject, "/buckets/finance/secrets/payroll.pdf") {
		t.Errorf("expected explicit Deny to override the broader Allow")
	}
}

func TestCanAccessPathInlinePolicy(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	ctx := context.Background()
	if err := s.credentialManager.CreateUser(ctx, &iam_pb.Identity{Name: "frank"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if err := s.credentialManager.PutUserInlinePolicy(ctx, "frank", "InlineOnly", mustParsePolicy(t, `{
		"Version": "2012-10-17",
		"Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::personal"}]
	}`)); err != nil {
		t.Fatalf("put inline policy: %v", err)
	}

	if !s.CanAccessPath(ctx, "frank", "readonly", ActionListBucket, "/buckets/personal") {
		t.Errorf("expected allow via inline user policy")
	}
}

func TestCanAccessPathNoUsernameDenied(t *testing.T) {
	s := newTestAdminServerForAuthz(t)
	if s.CanAccessPath(context.Background(), "", "readonly", ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected deny for an empty username")
	}
}

func TestCanAccessPathNilCredentialManagerDoesNotPanic(t *testing.T) {
	s := &AdminServer{}
	if s.CanAccessPath(context.Background(), "alice", "readonly", ActionGetObject, "/buckets/mybucket/file.txt") {
		t.Errorf("expected deny when credential manager is unavailable")
	}
}
