package telemetry

import "expvar"

var (
	IngestAcceptedTotal = expvar.NewInt("telemetry_ingest_accepted_total")
	IngestRejectedTotal = expvar.NewInt("telemetry_ingest_rejected_total")
)
