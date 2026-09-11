package dash

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strconv"
	"time"

	"github.com/seaweedfs/seaweedfs/weed/pb/filer_pb"
	"github.com/seaweedfs/seaweedfs/weed/s3api"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_constants"
	"github.com/seaweedfs/seaweedfs/weed/s3api/s3_objectlock"
)

// File Browser version history + GOVERNANCE lock (Refresquito addition).
//
// Reuses the S3 API's own on-disk representation -- a ".versions" sibling
// directory (s3_constants.VersionsFolder) plus Extended-attribute keys
// (s3_constants.Ext*) -- so a bucket stays correctly readable via the S3
// API regardless of whether it was touched through the File Browser or
// through S3 clients. Deliberately does NOT reuse the S3 API's
// "latest version" cache keys (ExtLatestVersion*) on the .versions
// directory entry: those are a read-side optimization for
// ListObjectVersionsHandler, not a correctness requirement, and getting
// their exact update semantics subtly wrong would risk corrupting what the
// S3 API caches. This package's own ListVersions lists the directory
// directly instead. Full interop with the raw S3 API's version-listing
// views for File-Browser-created versions is an explicit non-goal for now.

// IsBucketVersioningEnabled reports whether the given bucket has S3 object
// versioning enabled, reading the same Extended attribute the S3 API
// itself reads/writes (s3api.GetVersioningStatus).
func IsBucketVersioningEnabled(client filer_pb.SeaweedFilerClient, bucketName string) (bool, error) {
	resp, err := filer_pb.LookupEntry(context.Background(), client, &filer_pb.LookupDirectoryEntryRequest{
		Directory: "/buckets",
		Name:      bucketName,
	})
	if err != nil {
		if err == filer_pb.ErrNotFound {
			return false, nil
		}
		return false, err
	}
	return s3api.GetVersioningStatus(resp.Entry) == s3_constants.VersioningEnabled, nil
}

// IsObjectLockAvailable reports whether Object Lock can be used on this
// bucket -- same rule the S3 API enforces: it requires versioning.
func IsObjectLockAvailable(client filer_pb.SeaweedFilerClient, bucketName string) (bool, error) {
	return IsBucketVersioningEnabled(client, bucketName)
}

// versionsDirPath returns the ".versions" sibling directory for a File
// Browser object path, plus its bare directory/name split.
func versionsDirPath(filerPath string) (dir, name, versionsDir string) {
	dir = path.Dir(filerPath)
	name = path.Base(filerPath)
	versionsDir = path.Join(dir, name+s3_constants.VersionsFolder)
	return
}

// VersionInfo describes one stored version of a File Browser object, newest
// first.
type VersionInfo struct {
	VersionId string `json:"version_id"`
	// VersionNumber is a simple incremental counter (1 = the oldest stored
	// version), assigned by ListVersions in upload order -- easier for a
	// person to reference than the opaque VersionId. The entry currently
	// live at the object's path (not included in this list -- see
	// ListVersions) is implicitly version len(versions)+1.
	VersionNumber int       `json:"version_number"`
	Size          int64     `json:"size"`
	ModTime       time.Time `json:"mod_time"`
	OwnerName     string    `json:"owner_name"`
}

// lookupCurrentEntry fetches the entry currently at filerPath, or nil (no
// error) if there isn't one yet.
func lookupCurrentEntry(client filer_pb.SeaweedFilerClient, filerPath string) (*filer_pb.Entry, error) {
	dir, name := path.Dir(filerPath), path.Base(filerPath)
	resp, err := filer_pb.LookupEntry(context.Background(), client, &filer_pb.LookupDirectoryEntryRequest{
		Directory: dir,
		Name:      name,
	})
	if err != nil {
		if err == filer_pb.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return resp.Entry, nil
}

// SnapshotCurrentVersion copies the entry currently at filerPath into a new
// entry under its ".versions" sibling directory, using a fresh, real S3 API
// version ID (s3api.GenerateVersionId). No-ops (returns "", nil) if
// filerPath has no current entry yet (e.g. the very first upload to that
// path). Returns an error if the current entry is a directory.
func SnapshotCurrentVersion(client filer_pb.SeaweedFilerClient, filerPath string) (versionId string, err error) {
	current, err := lookupCurrentEntry(client, filerPath)
	if err != nil {
		return "", err
	}
	if current == nil {
		return "", nil
	}
	if current.IsDirectory {
		return "", fmt.Errorf("%s is a directory, not a file", filerPath)
	}

	_, name, versionsDir := versionsDirPath(filerPath)
	versionId = s3api.GenerateVersionId(true)
	now := time.Now()

	versionEntry := &filer_pb.Entry{
		Name:   name + "." + versionId,
		Chunks: current.Chunks,
		Attributes: &filer_pb.FuseAttributes{
			FileSize: current.Attributes.GetFileSize(),
			Mime:     current.Attributes.GetMime(),
			Mtime:    now.Unix(),
			Crtime:   now.Unix(),
		},
		Extended: current.Extended,
	}
	if _, err := client.CreateEntry(context.Background(), &filer_pb.CreateEntryRequest{
		Directory: versionsDir,
		Entry:     versionEntry,
	}); err != nil {
		return "", fmt.Errorf("failed to snapshot version: %w", err)
	}
	return versionId, nil
}

// ListVersions lists the stored versions of a File Browser object, newest
// first. Does not include the current entry -- callers that want it should
// fetch it separately (e.g. via GetFileProperties).
func ListVersions(client filer_pb.SeaweedFilerClient, filerPath string) ([]VersionInfo, error) {
	_, _, versionsDir := versionsDirPath(filerPath)

	var versions []VersionInfo
	stream, err := client.ListEntries(context.Background(), &filer_pb.ListEntriesRequest{
		Directory: versionsDir,
		Limit:     1000,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			break // EOF or the directory doesn't exist yet -- either way, no versions
		}
		entry := resp.Entry
		if entry == nil || entry.IsDirectory {
			continue
		}
		versionId := versionIdFromFileName(entry.Name)
		if versionId == "" {
			continue
		}
		ownerName := ""
		if entry.Extended != nil {
			ownerName = string(entry.Extended[s3_constants.ExtAmzOwnerNameKey])
		}
		versions = append(versions, VersionInfo{
			VersionId: versionId,
			Size:      int64(entry.Attributes.GetFileSize()),
			ModTime:   time.Unix(entry.Attributes.GetMtime(), 0),
			OwnerName: ownerName,
		})
	}

	// Sort by version ID, not ModTime: GenerateVersionId(true) uses an
	// inverted timestamp specifically so a plain ascending string sort
	// already returns newest-first, and it's nanosecond-precision --
	// unlike ModTime (Unix seconds), it stays correctly ordered even for
	// versions created within the same second.
	sort.Slice(versions, func(i, j int) bool { return versions[i].VersionId < versions[j].VersionId })

	// Assign incremental numbers in upload order: oldest = 1. versions[0]
	// is newest (just sorted above), so it gets the highest number.
	for i := range versions {
		versions[i].VersionNumber = len(versions) - i
	}
	return versions, nil
}

// CurrentVersionNumber returns the version number implied for the entry
// currently live at the object's path, given its stored version history
// (from ListVersions) -- always one more than the highest stored version
// number.
func CurrentVersionNumber(versions []VersionInfo) int {
	return len(versions) + 1
}

// versionIdFromFileName extracts the version ID from a ".versions" entry's
// file name ("<name>.<versionId>"), matching SnapshotCurrentVersion's
// naming. Version IDs are fixed-length (32 hex chars, s3api.GenerateVersionId),
// so the split is unambiguous even if the original file name itself
// contains dots.
func versionIdFromFileName(fileName string) string {
	const versionIdLen = 32
	if len(fileName) <= versionIdLen+1 {
		return ""
	}
	suffix := fileName[len(fileName)-versionIdLen:]
	if fileName[len(fileName)-versionIdLen-1] != '.' {
		return ""
	}
	return suffix
}

// RestoreVersion makes a stored version the current entry at filerPath,
// snapshotting whatever is currently there first (so restoring never loses
// data -- the version being replaced becomes restorable too).
func RestoreVersion(client filer_pb.SeaweedFilerClient, filerPath, versionId string) error {
	dir, name, versionsDir := versionsDirPath(filerPath)

	versionLookup, err := filer_pb.LookupEntry(context.Background(), client, &filer_pb.LookupDirectoryEntryRequest{
		Directory: versionsDir,
		Name:      name + "." + versionId,
	})
	if err != nil {
		if err == filer_pb.ErrNotFound {
			return fmt.Errorf("version %s not found", versionId)
		}
		return err
	}
	oldVersion := versionLookup.Entry

	if _, err := SnapshotCurrentVersion(client, filerPath); err != nil {
		return fmt.Errorf("failed to snapshot current version before restoring: %w", err)
	}

	restored := &filer_pb.Entry{
		Name:   name,
		Chunks: oldVersion.Chunks,
		Attributes: &filer_pb.FuseAttributes{
			FileSize: oldVersion.Attributes.GetFileSize(),
			Mime:     oldVersion.Attributes.GetMime(),
			Mtime:    time.Now().Unix(),
			Crtime:   oldVersion.Attributes.GetCrtime(),
		},
		Extended: oldVersion.Extended,
	}
	if _, err := client.UpdateEntry(context.Background(), &filer_pb.UpdateEntryRequest{
		Directory: dir,
		Entry:     restored,
	}); err != nil {
		return fmt.Errorf("failed to restore version: %w", err)
	}
	return nil
}

// IsLocked reports whether entry has an active (unexpired) Object Lock
// retention or legal hold -- reuses the exact same check the S3 API itself
// uses (s3_objectlock.EntryHasActiveLock), so a File Browser lock is
// respected by direct S3 API access too, and vice versa.
func IsLocked(entry *filer_pb.Entry) bool {
	if entry == nil {
		return false
	}
	return s3_objectlock.EntryHasActiveLock(entry, time.Now())
}

// ApplyGovernanceLock sets a GOVERNANCE-mode retention on entry until
// retainUntil, using the same Extended-attribute keys the S3 API's own
// PutObjectRetentionHandler writes (s3api_object_retention.go).
func ApplyGovernanceLock(entry *filer_pb.Entry, retainUntil time.Time) {
	if entry.Extended == nil {
		entry.Extended = make(map[string][]byte)
	}
	entry.Extended[s3_constants.ExtObjectLockModeKey] = []byte("GOVERNANCE")
	entry.Extended[s3_constants.ExtRetentionUntilDateKey] = []byte(strconv.FormatInt(retainUntil.Unix(), 10))
}

// CheckNotLocked fetches the entry currently at filerPath (if any) and
// returns an error if it's under an active Object Lock and role isn't
// "admin". Simplified MVP bypass rule: the S3 API's real bypass path
// (x-amz-bypass-governance-retention + a per-identity
// s3:BypassGovernanceRetention IAM grant) is SigV4-request-shaped and not
// reachable from the File Browser's session-based auth, so admin-role
// bypass stands in for it here -- matches the existing CanAccessPath
// admin-superuser convention (bucket_authz.go) already used for bucket
// authz. Full per-identity bypass is out of scope for this pass.
func CheckNotLocked(client filer_pb.SeaweedFilerClient, filerPath, role string) error {
	if role == "admin" {
		return nil
	}
	entry, err := lookupCurrentEntry(client, filerPath)
	if err != nil {
		return err
	}
	if IsLocked(entry) {
		return fmt.Errorf("%s is locked (Object Lock retention active) and cannot be overwritten or deleted", path.Base(filerPath))
	}
	return nil
}
