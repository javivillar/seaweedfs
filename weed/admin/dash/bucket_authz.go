package dash

import (
	"context"
	"path"
	"strings"

	"github.com/seaweedfs/seaweedfs/weed/glog"
	"github.com/seaweedfs/seaweedfs/weed/s3api/policy_engine"
)

// Bucket-level authorization for the Admin UI's File Browser (Refresquito
// addition -- see AUTHZ.md § seaweedfs-oneke #13). Deliberately reuses the
// exact action names and resource-ARN convention the S3 API's own IAM
// policies already use (weed/s3api/policy_engine, a standalone package with
// no dependency on the S3ApiServer's private runtime state) -- a policy
// written for S3 bucket access applies identically here. One policy model,
// one source of truth, regardless of whether someone reaches a bucket via
// the S3 API or the Admin UI.
const (
	ActionListBucket   = "s3:ListBucket"
	ActionGetObject    = "s3:GetObject"
	ActionPutObject    = "s3:PutObject"
	ActionDeleteObject = "s3:DeleteObject"
)

// bucketAndKeyFromPath splits a File Browser path into its bucket and
// object key, for paths under /buckets/<name>/... (the filer convention S3
// buckets already live under, per s3api_bucket_handlers.go). Paths outside
// that prefix have no S3 resource, so ok is false -- CanAccessPath denies
// non-admins on those since there's no policy vocabulary for them.
func bucketAndKeyFromPath(filerPath string) (bucket, key string, ok bool) {
	clean := path.Clean("/" + strings.TrimPrefix(filerPath, "/"))
	const prefix = "/buckets/"
	if !strings.HasPrefix(clean+"/", prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(clean, prefix)
	if rest == "" || rest == "." {
		return "", "", false
	}
	parts := strings.SplitN(rest, "/", 2)
	bucket = parts[0]
	if bucket == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		key = parts[1]
	}
	return bucket, key, true
}

// resourceArn builds the AWS-style S3 resource ARN policies already use
// (arn:aws:s3:::bucket or arn:aws:s3:::bucket/key), matching
// policy_engine/examples.go's convention exactly.
func resourceArn(bucket, key string) string {
	if key == "" {
		return "arn:aws:s3:::" + bucket
	}
	return "arn:aws:s3:::" + bucket + "/" + key
}

// collectApplicablePolicies gathers every PolicyDocument that could grant
// (or deny) username access: policies attached directly to the identity,
// the identity's own inline policies, and the attached + inline policies of
// every non-disabled group the identity belongs to. Best-effort: a lookup
// failure for one policy/group is logged and skipped rather than failing
// the whole request -- consistent with this file's deny-by-default posture,
// a missing policy just means less access is granted, never more.
func (s *AdminServer) collectApplicablePolicies(ctx context.Context, username string) []*policy_engine.PolicyDocument {
	if s.credentialManager == nil {
		return nil
	}
	var docs []*policy_engine.PolicyDocument

	addPolicy := func(name string, get func() (*policy_engine.PolicyDocument, error)) {
		doc, err := get()
		if err != nil {
			glog.V(2).Infof("collectApplicablePolicies: skipping policy %q for %s: %v", name, username, err)
			return
		}
		if doc != nil {
			docs = append(docs, doc)
		}
	}

	identity, err := s.credentialManager.GetUser(ctx, username)
	if err != nil {
		glog.V(2).Infof("collectApplicablePolicies: GetUser(%s) failed: %v", username, err)
		return nil
	}
	for _, name := range identity.PolicyNames {
		n := name
		addPolicy(n, func() (*policy_engine.PolicyDocument, error) { return s.credentialManager.GetPolicy(ctx, n) })
	}
	if inlineNames, err := s.credentialManager.ListUserInlinePolicies(ctx, username); err == nil {
		for _, name := range inlineNames {
			n := name
			addPolicy(n, func() (*policy_engine.PolicyDocument, error) {
				return s.credentialManager.GetUserInlinePolicy(ctx, username, n)
			})
		}
	}

	groupNames, err := s.credentialManager.ListGroups(ctx)
	if err != nil {
		glog.V(2).Infof("collectApplicablePolicies: ListGroups failed: %v", err)
		return docs
	}
	for _, gName := range groupNames {
		group, err := s.credentialManager.GetGroup(ctx, gName)
		if err != nil || group.Disabled {
			continue
		}
		isMember := false
		for _, member := range group.Members {
			if member == username {
				isMember = true
				break
			}
		}
		if !isMember {
			continue
		}
		for _, name := range group.PolicyNames {
			n := name
			addPolicy(n, func() (*policy_engine.PolicyDocument, error) { return s.credentialManager.GetPolicy(ctx, n) })
		}
		if inlineNames, err := s.credentialManager.ListGroupInlinePolicies(ctx, gName); err == nil {
			for _, name := range inlineNames {
				n, g := name, gName
				addPolicy(n, func() (*policy_engine.PolicyDocument, error) {
					return s.credentialManager.GetGroupInlinePolicy(ctx, g, n)
				})
			}
		}
	}

	return docs
}

// CanAccessPath decides whether a File Browser request may perform action
// on filerPath.
//
//   - The global admin role (session role=="admin", the same role
//     RequireWriteAccess already checks) always bypasses this check --
//     matches real AWS semantics (an effectively-unrestricted principal
//     needs no per-bucket grant) and keeps today's admin workflows
//     unchanged. This is a deliberate product decision, not an oversight:
//     bucket policies exist to grant/restrict NON-admin identities, not to
//     further constrain admins.
//   - Every other identity is deny-by-default: touching a bucket's
//     contents requires an explicit Allow, from a policy attached to the
//     identity itself or to a group it belongs to, for that action and
//     resource. An explicit Deny anywhere always wins over any Allow --
//     all applicable policies' statements are merged into one document
//     before evaluation so policy_engine's own (already-correct)
//     deny-overrides-allow logic handles this in a single pass, rather
//     than reimplementing per-policy precedence here.
//   - Paths outside /buckets/ (raw filer paths with no S3 concept) are
//     denied for non-admins -- there is no policy vocabulary for them.
func (s *AdminServer) CanAccessPath(ctx context.Context, username, role, action, filerPath string) bool {
	if role == "admin" {
		return true
	}
	if s.credentialManager == nil || username == "" {
		return false
	}

	bucket, key, ok := bucketAndKeyFromPath(filerPath)
	if !ok {
		return false
	}

	docs := s.collectApplicablePolicies(ctx, username)
	if len(docs) == 0 {
		return false
	}

	merged := &policy_engine.PolicyDocument{Version: "2012-10-17"}
	for _, doc := range docs {
		merged.Statement = append(merged.Statement, doc.Statement...)
	}

	compiled, err := policy_engine.CompilePolicy(merged)
	if err != nil {
		glog.Warningf("CanAccessPath: failed to compile merged policy set for %s: %v", username, err)
		return false
	}

	allowed, _ := compiled.EvaluatePolicy(&policy_engine.PolicyEvaluationArgs{
		Action:    action,
		Resource:  resourceArn(bucket, key),
		Principal: username,
	})
	return allowed
}
