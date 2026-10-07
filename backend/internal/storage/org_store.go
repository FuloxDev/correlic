package storage

import "time"

// LocalOrgID is the default org ID for local-first single-user mode
const LocalOrgID = "00000000-0000-0000-0000-000000000001"
const LocalOrgName = "Local"

type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type OrgStore interface {
	Get(orgID string) (*Organization, error)
	CreateOrg(orgID, name string) error
	// GetOrCreate returns the org if it exists, or creates it with the given name
	GetOrCreate(orgID, name string) (*Organization, error)
}
