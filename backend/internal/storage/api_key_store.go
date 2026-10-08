package storage

// API key types as stored in api_keys.key_type.
const (
	APIKeyTypeService = "service"
	APIKeyTypeAgent   = "agent"
)

// APIKeyInfo contains the resolved user and org info for an API key.
type APIKeyInfo struct {
	OrgID  string
	UserID string
	// Role is the org_users.role of the key's owner, or "" when the owner has
	// no org_users row. It is ignored for agent keys, which always act as the
	// "agent" role.
	Role string
	// KeyType is api_keys.key_type: "service" or "agent".
	KeyType string
}

type APIKeyStore interface {
	// LookupOrgID looks up an organization ID by a hashed API key
	LookupOrgID(keyHash string) (string, error)
	// LookupKeyInfo looks up full API key info (org, user, role, key type)
	LookupKeyInfo(keyHash string) (*APIKeyInfo, error)
}
