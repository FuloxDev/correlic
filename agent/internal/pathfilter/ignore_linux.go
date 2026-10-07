//go:build linux

package pathfilter

import "strings"

// ShouldIgnorePath returns true if the path is high-volume/low-value noise on Linux.
func ShouldIgnorePath(path string) bool {
	// 1. Procfs / Sysfs / Dev (Kernel interfaces)
	// Exception: /proc/*/environ contains secrets — let credential_access detect it.
	if strings.HasPrefix(path, "/proc") {
		if !strings.HasSuffix(path, "/environ") {
			return true
		}
	}
	if strings.HasPrefix(path, "/sys") ||
		strings.HasPrefix(path, "/dev") {
		return true
	}

	// 2. Common libraries and executables (read-only system files)
	if strings.HasPrefix(path, "/usr") {
		if strings.Contains(path, "/lib/") || strings.Contains(path, "/bin/") || strings.Contains(path, "/share/") {
			return true
		}
	}
	if strings.HasPrefix(path, "/lib") {
		return true
	}

	// 3. Graphics / Cache noise
	if strings.Contains(path, "/.config/vulkan/explicit_layer.d") {
		return true
	}
	if strings.Contains(path, "/.cache/mesa_shader_cache") {
		return true
	}
	if strings.Contains(path, "/.nv/ComputeCache") || strings.Contains(path, "/.cache/nvidia") {
		return true
	}

	// 4. Runtime noise
	if strings.Contains(path, "__pycache__") || strings.Contains(path, ".pyc") {
		return true
	}
	if strings.Contains(path, "/node_modules/") {
		return true
	}
	if strings.Contains(path, "/.git/") {
		return true
	}

	// 5. Temporary files
	if strings.HasPrefix(path, "/tmp") {
		return true
	}

	return false
}
