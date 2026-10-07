package ai_pack

import "github.com/correlic/correlic-backend/internal/detection"

// NewAIPack returns all AI detection rules as a slice ready for engine registration.
func NewAIPack() []detection.Detection {
	return []detection.Detection{
		&AICredentialAccess{},
		&AIUnexpectedNetwork{},
		&AIUnauthorizedExec{},
		&AIDataExfiltration{},
		&AIExcessiveWrites{},
		&AISuspiciousDNS{},
		&AIPersistence{},
		&AIPrivilegeEscalation{},
		&AICodeTampering{},
		&AIContainerEscape{},
		&AIDiscovery{},
		&AICommandActivity{},
		&AIFileActivity{},
	}
}
