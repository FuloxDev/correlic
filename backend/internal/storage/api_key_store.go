package storage

// APIKeyInfo contains the resolved user and org info for an API key
type APIKeyInfo struct {
	OrgID  string
	UserID string
	Role   string
}

type APIKeyStore interface {
	// LookupOrgID looks up an organization ID by a hashed API key
	LookupOrgID(keyHash string) (string, error)
	// LookupKeyInfo looks up full API key info (org, user, role)
	LookupKeyInfo(keyHash string) (*APIKeyInfo, error)
}
