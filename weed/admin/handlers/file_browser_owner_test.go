package handlers

import (
	"context"
	"testing"

	"github.com/seaweedfs/seaweedfs/weed/admin/dash"
	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
)

// resolveUploaderOwner's real-Account branch (a matching iam_pb.Identity with
// a persisted Account) is exercised indirectly by weed/admin/dash's
// TestJITProvisionOIDCUser* tests plus the live end-to-end verification --
// building a FileBrowserHandlers backed by a real credential manager isn't
// possible from this package (dash.AdminServer's credentialManager field is
// unexported and NewAdminServer talks to a real filer). These tests cover
// the fallback paths that are reachable here.

func TestResolveUploaderOwnerNoUsernameReturnsEmpty(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	id, name := h.resolveUploaderOwner(context.Background())
	if id != "" || name != "" {
		t.Errorf("resolveUploaderOwner() = (%q, %q), want (\"\", \"\") for an unauthenticated context", id, name)
	}
}

func TestResolveUploaderOwnerFallsBackToUsernameWhenNoCredentialManager(t *testing.T) {
	h := &FileBrowserHandlers{adminServer: &dash.AdminServer{}}
	ctx := dash.WithAuthContext(context.Background(), "admin", "admin", "")
	id, name := h.resolveUploaderOwner(ctx)
	if id != "admin" || name != "admin" {
		t.Errorf("resolveUploaderOwner() = (%q, %q), want (\"admin\", \"admin\") when no credential manager is wired", id, name)
	}
}

func TestStampOwnerSetsExtendedKeys(t *testing.T) {
	entry := &filer_pb.Entry{Name: "report.pdf"}
	stampOwner(entry, "100000000042", "seaweedfs-admin-test")

	if got := string(entry.Extended[s3_constants.ExtAmzOwnerKey]); got != "100000000042" {
		t.Errorf("ExtAmzOwnerKey = %q, want 100000000042", got)
	}
	if got := string(entry.Extended[s3_constants.ExtAmzOwnerNameKey]); got != "seaweedfs-admin-test" {
		t.Errorf("ExtAmzOwnerNameKey = %q, want seaweedfs-admin-test", got)
	}
}

func TestStampOwnerNoopWhenOwnerIdEmpty(t *testing.T) {
	entry := &filer_pb.Entry{Name: "report.pdf"}
	stampOwner(entry, "", "irrelevant")

	if entry.Extended != nil {
		t.Errorf("expected Extended to remain nil when ownerId is empty, got %+v", entry.Extended)
	}
}

func TestStampOwnerOmitsNameKeyWhenNameEmpty(t *testing.T) {
	entry := &filer_pb.Entry{Name: "report.pdf"}
	stampOwner(entry, "100000000042", "")

	if _, ok := entry.Extended[s3_constants.ExtAmzOwnerNameKey]; ok {
		t.Errorf("expected ExtAmzOwnerNameKey to be absent when ownerName is empty")
	}
	if got := string(entry.Extended[s3_constants.ExtAmzOwnerKey]); got != "100000000042" {
		t.Errorf("ExtAmzOwnerKey = %q, want 100000000042", got)
	}
}
