package storage

import (
	"errors"
	"time"
)

var (
	// ErrAgentCertMismatch indicates an agent_id is already bound to a different active fingerprint.
	ErrAgentCertMismatch = errors.New("agent cert mismatch")
	// ErrFingerprintAlreadyBound indicates the fingerprint is already bound to a different agent_id in the org.
	ErrFingerprintAlreadyBound = errors.New("fingerprint already bound")
)

// AgentCertStore binds (org_id, agent_id) to an mTLS client cert fingerprint.
// Fingerprint format: hex(SHA-256(leaf_cert_DER)).
type AgentCertStore interface {
	// EnsureBound ensures org+agent is bound to fingerprint.
	// If no binding exists (or it was revoked), it creates/refreshes the binding.
	// If an active binding exists with a different fingerprint, returns ErrAgentCertMismatch.
	EnsureBound(orgID string, agentID string, fingerprint string) error
	// Revoke marks the binding for org+agent as revoked.
	Revoke(orgID string, agentID string) (bool, error)
	// List returns agent cert bindings for an org, newest first.
	List(orgID string, limit int, includeRevoked bool) ([]AgentCertRecord, error)
}

type AgentCertRecord struct {
	AgentID     string     `json:"agent_id"`
	Fingerprint string     `json:"fingerprint"`
	CreatedAt   time.Time  `json:"created_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}
