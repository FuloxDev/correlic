# Tier / Subscription System

Controls feature availability and limits based on the deployment tier.

## Tiers

| Tier | Env Value | Description |
|------|-----------|-------------|
| `free` | (default) | Self-hosted free tier |
| `trial` | `trial` | Paid trial period |
| `pro` | `pro` | Full paid tier |

Set via `CORRELIC_TIER` environment variable (case-insensitive, trimmed).

## Limits by Tier

| Limit | Free | Trial/Pro |
|-------|------|-----------|
| Telemetry retention (days) | 14 | 90 |
| AI proof evidence limit | 200 | 500 |
| Network allowlist | disabled | enabled |
| Supply chain allowlist | disabled | enabled |

**Note:** Retention limits here are defaults that can still be overridden by the `RETENTION_*` env vars in `maintenance/retention.go`.

## API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/tier` | Returns current tier + limits for the org |

## Key Files

| File | Purpose |
|------|---------|
| `internal/tier/tier.go` | `Tier` type, `Current()`, `IsPaid()`, `LimitsFor()` |
| `internal/api/tier.go` | HTTP handler returning tier + limits JSON |

## Types

```go
type Tier string // "free" | "trial" | "pro"

type Limits struct {
    TelemetryRetentionDays      int  `json:"telemetry_retention_days"`
    AIProofEvidenceLimit        int  `json:"ai_proof_evidence_limit"`
    NetworkAllowlistEnabled     bool `json:"network_allowlist_enabled"`
    SupplyChainAllowlistEnabled bool `json:"supply_chain_allowlist_enabled"`
}
```
