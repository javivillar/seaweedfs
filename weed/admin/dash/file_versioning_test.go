package dash

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
	"github.com/seaweedfs/seaweedfs/weed/s3api"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
	grpc "google.golang.org/grpc"
)

// fakeFilerClient is a minimal in-memory filer_pb.SeaweedFilerClient, keyed
// by "directory/name", covering just the RPCs file_versioning.go uses.
// Any other method panics via the embedded nil interface -- a deliberate
// guardrail so an accidental new dependency fails loudly in tests.
type fakeFilerClient struct {
	filer_pb.SeaweedFilerClient
	entries map[string]*filer_pb.Entry
}

func newFakeFilerClient() *fakeFilerClient {
	return &fakeFilerClient{entries: make(map[string]*filer_pb.Entry)}
}

func entryKey(dir, name string) string { return dir + "/" + name }

func (c *fakeFilerClient) put(dir string, entry *filer_pb.Entry) {
	c.entries[entryKey(dir, entry.Name)] = entry
}

func (c *fakeFilerClient) LookupDirectoryEntry(_ context.Context, req *filer_pb.LookupDirectoryEntryRequest, _ ...grpc.CallOption) (*filer_pb.LookupDirectoryEntryResponse, error) {
	e, ok := c.entries[entryKey(req.Directory, req.Name)]
	if !ok {
		return nil, filer_pb.ErrNotFound
	}
	return &filer_pb.LookupDirectoryEntryResponse{Entry: e}, nil
}

func (c *fakeFilerClient) CreateEntry(_ context.Context, req *filer_pb.CreateEntryRequest, _ ...grpc.CallOption) (*filer_pb.CreateEntryResponse, error) {
	c.put(req.Directory, req.Entry)
	return &filer_pb.CreateEntryResponse{}, nil
}

func (c *fakeFilerClient) UpdateEntry(_ context.Context, req *filer_pb.UpdateEntryRequest, _ ...grpc.CallOption) (*filer_pb.UpdateEntryResponse, error) {
	c.put(req.Directory, req.Entry)
	return &filer_pb.UpdateEntryResponse{}, nil
}

func (c *fakeFilerClient) ListEntries(_ context.Context, req *filer_pb.ListEntriesRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[filer_pb.ListEntriesResponse], error) {
	prefix := req.Directory + "/"
	var matched []*filer_pb.Entry
	for key, e := range c.entries {
		rest := strings.TrimPrefix(key, prefix)
		if rest == key || strings.Contains(rest, "/") {
			continue // not a direct child of req.Directory
		}
		matched = append(matched, e)
	}
	return &fakeListEntriesStream{entries: matched}, nil
}

type fakeListEntriesStream struct {
	grpc.ClientStream
	entries []*filer_pb.Entry
	i       int
}

func (s *fakeListEntriesStream) Recv() (*filer_pb.ListEntriesResponse, error) {
	if s.i >= len(s.entries) {
		return nil, io.EOF
	}
	e := s.entries[s.i]
	s.i++
	return &filer_pb.ListEntriesResponse{Entry: e}, nil
}

func fileEntry(name string, size uint64) *filer_pb.Entry {
	return &filer_pb.Entry{
		Name:       name,
		Attributes: &filer_pb.FuseAttributes{FileSize: size, Mtime: time.Now().Unix()},
	}
}

func TestIsBucketVersioningEnabled(t *testing.T) {
	client := newFakeFilerClient()

	if enabled, err := IsBucketVersioningEnabled(client, "missing-bucket"); err != nil || enabled {
		t.Errorf("missing bucket: got (%v, %v), want (false, nil)", enabled, err)
	}

	bucketEntry := &filer_pb.Entry{Name: "mybucket", IsDirectory: true}
	client.put("/buckets", bucketEntry)
	if enabled, err := IsBucketVersioningEnabled(client, "mybucket"); err != nil || enabled {
		t.Errorf("no versioning set: got (%v, %v), want (false, nil)", enabled, err)
	}

	if err := s3api.StoreVersioningInExtended(bucketEntry, true); err != nil {
		t.Fatalf("StoreVersioningInExtended: %v", err)
	}
	client.put("/buckets", bucketEntry)
	if enabled, err := IsBucketVersioningEnabled(client, "mybucket"); err != nil || !enabled {
		t.Errorf("versioning enabled: got (%v, %v), want (true, nil)", enabled, err)
	}
}

func TestSnapshotCurrentVersionNoCurrentEntry(t *testing.T) {
	client := newFakeFilerClient()
	versionId, err := SnapshotCurrentVersion(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if versionId != "" {
		t.Errorf("expected no-op (empty versionId) when there's no current entry, got %q", versionId)
	}
}

func TestSnapshotCurrentVersionAndListVersions(t *testing.T) {
	client := newFakeFilerClient()
	client.put("/buckets/mybucket", fileEntry("foo.txt", 100))

	versionId, err := SnapshotCurrentVersion(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("SnapshotCurrentVersion: %v", err)
	}
	if versionId == "" {
		t.Fatal("expected a non-empty version ID")
	}

	versions, err := ListVersions(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(versions))
	}
	if versions[0].VersionId != versionId {
		t.Errorf("VersionId = %q, want %q", versions[0].VersionId, versionId)
	}
	if versions[0].Size != 100 {
		t.Errorf("Size = %d, want 100", versions[0].Size)
	}
	if versions[0].VersionNumber != 1 {
		t.Errorf("VersionNumber = %d, want 1 (the only stored version so far)", versions[0].VersionNumber)
	}
	if got := CurrentVersionNumber(versions); got != 2 {
		t.Errorf("CurrentVersionNumber = %d, want 2 (one stored version + the current one)", got)
	}

	// A second overwrite snapshots a second version; both show up, newest first.
	client.put("/buckets/mybucket", fileEntry("foo.txt", 200))
	secondVersionId, err := SnapshotCurrentVersion(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("second SnapshotCurrentVersion: %v", err)
	}
	versions, err = ListVersions(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("ListVersions after second snapshot: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	if versions[0].VersionId != secondVersionId {
		t.Errorf("newest-first: versions[0] = %q, want the second snapshot %q", versions[0].VersionId, secondVersionId)
	}
	if versions[0].VersionNumber != 2 || versions[1].VersionNumber != 1 {
		t.Errorf("VersionNumbers = [%d, %d], want [2, 1] (newest-first, oldest is 1)", versions[0].VersionNumber, versions[1].VersionNumber)
	}
	if got := CurrentVersionNumber(versions); got != 3 {
		t.Errorf("CurrentVersionNumber = %d, want 3", got)
	}
}

func TestListVersionsEmpty(t *testing.T) {
	client := newFakeFilerClient()
	client.put("/buckets/mybucket", fileEntry("nooverwrite.txt", 42))

	versions, err := ListVersions(client, "/buckets/mybucket/nooverwrite.txt")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 0 {
		t.Fatalf("expected 0 versions for a file never overwritten, got %d", len(versions))
	}
	if got := CurrentVersionNumber(versions); got != 1 {
		t.Errorf("CurrentVersionNumber = %d, want 1 for a file with no stored history", got)
	}
}

func TestRestoreVersion(t *testing.T) {
	client := newFakeFilerClient()
	client.put("/buckets/mybucket", fileEntry("foo.txt", 100))

	oldVersionId, err := SnapshotCurrentVersion(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("SnapshotCurrentVersion: %v", err)
	}
	// Simulate an overwrite of the current entry after the snapshot.
	client.put("/buckets/mybucket", fileEntry("foo.txt", 999))

	if err := RestoreVersion(client, "/buckets/mybucket/foo.txt", oldVersionId); err != nil {
		t.Fatalf("RestoreVersion: %v", err)
	}

	current, err := lookupCurrentEntry(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("lookupCurrentEntry: %v", err)
	}
	if current.Attributes.GetFileSize() != 100 {
		t.Errorf("current size after restore = %d, want 100 (the restored version's size)", current.Attributes.GetFileSize())
	}

	// The 999-byte version that was current before the restore should now
	// itself be a version, so restoring never loses data.
	versions, err := ListVersions(client, "/buckets/mybucket/foo.txt")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions (the original + the pre-restore content), got %d", len(versions))
	}
}

func TestRestoreVersionNotFound(t *testing.T) {
	client := newFakeFilerClient()
	client.put("/buckets/mybucket", fileEntry("foo.txt", 100))
	if err := RestoreVersion(client, "/buckets/mybucket/foo.txt", "does-not-exist"); err == nil {
		t.Error("expected an error restoring a nonexistent version")
	}
}

func TestIsLockedAndApplyGovernanceLock(t *testing.T) {
	entry := fileEntry("locked.txt", 10)
	if IsLocked(entry) {
		t.Error("a fresh entry should not be locked")
	}

	ApplyGovernanceLock(entry, time.Now().Add(24*time.Hour))
	if !IsLocked(entry) {
		t.Error("expected entry to be locked after ApplyGovernanceLock with a future retain-until date")
	}
	if string(entry.Extended[s3_constants.ExtObjectLockModeKey]) != "GOVERNANCE" {
		t.Errorf("ExtObjectLockModeKey = %q, want GOVERNANCE", entry.Extended[s3_constants.ExtObjectLockModeKey])
	}

	expired := fileEntry("expired.txt", 10)
	ApplyGovernanceLock(expired, time.Now().Add(-24*time.Hour))
	if IsLocked(expired) {
		t.Error("an entry with a retain-until date in the past should no longer be considered locked")
	}
}

func TestCheckNotLocked(t *testing.T) {
	client := newFakeFilerClient()
	locked := fileEntry("locked.txt", 10)
	ApplyGovernanceLock(locked, time.Now().Add(24*time.Hour))
	client.put("/buckets/mybucket", locked)
	client.put("/buckets/mybucket", fileEntry("unlocked.txt", 10))

	if err := CheckNotLocked(client, "/buckets/mybucket/locked.txt", "viewer"); err == nil {
		t.Error("expected an error: non-admin overwriting/deleting a locked entry")
	}
	if err := CheckNotLocked(client, "/buckets/mybucket/locked.txt", "admin"); err != nil {
		t.Errorf("admin should bypass the lock, got error: %v", err)
	}
	if err := CheckNotLocked(client, "/buckets/mybucket/unlocked.txt", "viewer"); err != nil {
		t.Errorf("unlocked entry should never be blocked, got error: %v", err)
	}
	if err := CheckNotLocked(client, "/buckets/mybucket/does-not-exist.txt", "viewer"); err != nil {
		t.Errorf("a nonexistent entry (first upload) should never be blocked, got error: %v", err)
	}
}
