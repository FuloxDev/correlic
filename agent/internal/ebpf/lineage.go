package ebpf

// Re-export LineageTracker from the shared lineage package.
// This shim maintains backward compatibility while the canonical implementation
// lives in internal/lineage/ (platform-agnostic, importable by macOS code).

import "github.com/correlic/correlic-agent/internal/lineage"

// LineageTracker is an alias for the shared lineage.LineageTracker.
type LineageTracker = lineage.LineageTracker

// GetLineageTracker delegates to the shared lineage package singleton.
var GetLineageTracker = lineage.GetLineageTracker
