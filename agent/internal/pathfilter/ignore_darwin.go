//go:build darwin

package pathfilter

import "strings"

// ShouldIgnorePath returns true if the path is high-volume/low-value noise on macOS.
func ShouldIgnorePath(path string) bool {
	// 1. System frameworks and libraries
	if strings.HasPrefix(path, "/System/") {
		return true
	}
	if strings.HasPrefix(path, "/usr/lib/") || strings.HasPrefix(path, "/usr/bin/") || strings.HasPrefix(path, "/usr/share/") {
		return true
	}

	// 2. System caches and temp
	if strings.HasPrefix(path, "/Library/Caches/") {
		return true
	}
	if strings.HasPrefix(path, "/private/var/folders/") {
		return true
	}
	if strings.HasPrefix(path, "/private/tmp/") || strings.HasPrefix(path, "/tmp/") {
		return true
	}

	// 3. Spotlight and metadata
	if strings.Contains(path, ".Spotlight-V100") {
		return true
	}
	if strings.Contains(path, ".fseventsd") {
		return true
	}
	if strings.Contains(path, ".DS_Store") {
		return true
	}

	// 4. Runtime noise (shared with Linux)
	if strings.Contains(path, "__pycache__") || strings.Contains(path, ".pyc") {
		return true
	}
	if strings.Contains(path, "/node_modules/") {
		return true
	}
	if strings.Contains(path, "/.git/") {
		return true
	}

	return false
}
