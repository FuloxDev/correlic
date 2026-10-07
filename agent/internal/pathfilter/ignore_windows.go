//go:build windows

package pathfilter

import "strings"

// ShouldIgnorePath returns true if the path is high-volume/low-value noise on Windows.
// All paths are expected to already be forward-slash normalised (backslashes replaced).
func ShouldIgnorePath(path string) bool {
	// Case-insensitive: Windows paths may be C:/Windows/, C:/WINDOWS/, C:/windows/
	lower := strings.ToLower(path)

	// 1. Windows system directories — reading system binaries is not security-relevant
	if strings.HasPrefix(lower, "c:/windows/") {
		return true
	}

	// 2. Program Files — reading installed program binaries is noise
	// (executing them is tracked by ai.command_activity, not file_activity)
	if strings.HasPrefix(lower, "c:/program files/") || strings.HasPrefix(lower, "c:/program files (x86)/") {
		return true
	}

	// 3. Temp and cache directories
	if strings.Contains(lower, "/appdata/local/temp/") {
		return true
	}
	if strings.Contains(lower, "/appdata/local/microsoft/windows/") {
		return true
	}

	// 4. Common runtime noise (shared with other platforms)
	if strings.Contains(lower, "__pycache__") || strings.HasSuffix(lower, ".pyc") {
		return true
	}
	if strings.Contains(path, "/node_modules/") {
		return true
	}
	if strings.Contains(path, "/.git/") {
		return true
	}

	// 5. ProgramData noise (Norton, antivirus, system config)
	if strings.HasPrefix(lower, "c:/programdata/") {
		return true
	}

	return false
}
