package storage

import "time"

// ClientCertStore is the storage boundary for mTLS client certificate enrollment.
// Fingerprint format: hex(SHA-256(leaf_cert_DER)).
type ClientCertStore interface {
	// IsEnrolled returns true if the fingerprint is enrolled and not revoked for the org.
	IsEnrolled(orgID string, fingerprint string) (bool, error)
	// LookupOrgIDByFingerprint returns the org_id for this enrolled, non-revoked fingerprint.
	// Returns sql.ErrNoRows if not enrolled.
	LookupOrgIDByFingerprint(fingerprint string) (string, error)
	// Enroll enrolls a fingerprint for an org (idempotent for same fingerprint).
	Enroll(orgID string, name string, fingerprint string) error
	// Revoke marks a fingerprint as revoked for an org.
	Revoke(orgID string, fingerprint string) (bool, error)
	// List returns enrolled client certs for an org, newest first.
	List(orgID string, limit int, includeRevoked bool) ([]ClientCertRecord, error)
}

type ClientCertRecord struct {
	Name        string     `json:"name"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}
