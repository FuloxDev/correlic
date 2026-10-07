package query

// SanitizeExePathForResponse returns exe_path suitable for API response: unchanged if all printable ASCII, else "unknown".
// Use only when building response payloads; do not alter storage or correlation.
func SanitizeExePathForResponse(s string) string {
	for _, r := range s {
		if r < 32 || r > 126 {
			return "unknown"
		}
	}
	return s
}
