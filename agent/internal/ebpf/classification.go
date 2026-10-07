package ebpf

import "github.com/correlic/correlic-agent/internal/classify"

// CheckRole delegates to the shared classify package.
var CheckRole = classify.CheckRole
