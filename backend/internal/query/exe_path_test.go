package query

import (
	"testing"
)

func TestSanitizeExePathForResponse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"normal", "/usr/bin/bash", "/usr/bin/bash"},
		{"with spaces", "/usr/bin/foo bar", "/usr/bin/foo bar"},
		{"non-printable NUL", "/bin/foo\x00", "unknown"},
		{"bell", "\u0007", "unknown"},
		{"mixed", "/usr/bin/\u0007", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeExePathForResponse(tt.in)
			if got != tt.want {
				t.Errorf("SanitizeExePathForResponse(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
