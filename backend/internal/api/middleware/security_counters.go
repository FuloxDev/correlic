package middleware

import "expvar"

// Security gate counters, exported via /debug/vars (when enabled).
// Names are stable for dashboards/alerting.

var (
	MTLSMissingCertTotal    = expvar.NewInt("mtls_missing_cert_total")
	MTLSUnenrolledCertTotal = expvar.NewInt("mtls_unenrolled_cert_total")
	AgentCertMismatchTotal  = expvar.NewInt("agent_cert_mismatch_total")
)
