package normalize

import (
	"testing"
)

func TestShouldDropExec(t *testing.T) {
	tests := []struct {
		name           string
		class          string
		role           string
		normalized     bool
		expectedDrop   bool
		expectedReason string
	}{
		{"primary entrypoint keep", "primary", "entrypoint", true, false, ""},
		{"shell ephemeral drop", "shell", "ephemeral", true, true, "exec_ephemeral"},
		{"runtime ephemeral drop", "runtime", "ephemeral", true, true, "exec_ephemeral"},
		{"helper fork drop", "helper", "fork", true, true, "exec_helper_burst"},
		{"unknown unknown keep", "unknown", "unknown", true, false, ""},
		{"not normalized keep", "helper", "fork", false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := map[string]any{
				"exec_class":      tt.class,
				"exec_role":       tt.role,
				"exec_normalized": tt.normalized,
			}
			got := ShouldDropExec(ctx)
			if got.Drop != tt.expectedDrop {
				t.Errorf("Drop: got %v want %v", got.Drop, tt.expectedDrop)
			}
			if tt.expectedReason != "" && got.Reason != tt.expectedReason {
				t.Errorf("Reason: got %q want %q", got.Reason, tt.expectedReason)
			}
		})
	}
}
