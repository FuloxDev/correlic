package tier

import (
	"os"
	"strings"
)

type Tier string

const (
	TierFree  Tier = "free"
	TierTrial Tier = "trial"
	TierPro   Tier = "pro"
)

type Limits struct {
	// Retention defaults (can still be overridden by env in maintenance).
	TelemetryRetentionDays int `json:"telemetry_retention_days"`

	// AI proof limits.
	AIProofEvidenceLimit int `json:"ai_proof_evidence_limit"`

	// Feature flags.
	NetworkAllowlistEnabled     bool `json:"network_allowlist_enabled"`
	SupplyChainAllowlistEnabled bool `json:"supply_chain_allowlist_enabled"`
}

func Current() Tier {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("CORRELIC_TIER")))
	switch raw {
	case "pro":
		return TierPro
	case "trial":
		return TierTrial
	default:
		return TierFree
	}
}

func IsPaid(t Tier) bool { return t == TierPro || t == TierTrial }

func LimitsFor(t Tier) Limits {
	if IsPaid(t) {
		return Limits{
			TelemetryRetentionDays:      90,
			AIProofEvidenceLimit:        500,
			NetworkAllowlistEnabled:     true,
			SupplyChainAllowlistEnabled: true,
		}
	}
	return Limits{
		TelemetryRetentionDays:      14,
		AIProofEvidenceLimit:        200,
		NetworkAllowlistEnabled:     false,
		SupplyChainAllowlistEnabled: false,
	}
}
