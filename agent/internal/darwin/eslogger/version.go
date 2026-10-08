package eslogger

import (
	"fmt"
	"strconv"
	"strings"
)

// MinMacOSMajor is the first macOS release that ships /usr/bin/eslogger
// (Ventura).
const MinMacOSMajor = 13

// parseVersion parses a macOS product version such as "14.3.1" or "13.0".
func parseVersion(s string) (major, minor int, err error) {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) == 0 || parts[0] == "" {
		return 0, 0, fmt.Errorf("cannot parse macOS version %q", s)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("cannot parse macOS version %q", s)
	}
	if len(parts) > 1 {
		minor, err = strconv.Atoi(parts[1])
		if err != nil {
			return 0, 0, fmt.Errorf("cannot parse macOS version %q", s)
		}
	}
	return major, minor, nil
}

// checkVersion returns ErrUnsupportedVersion when version parses and is
// older than MinMacOSMajor. An unparsable version is not an error: the
// presence of the binary is the better signal and the caller logs it.
func checkVersion(version string) error {
	major, _, err := parseVersion(version)
	if err != nil {
		return nil
	}
	if major < MinMacOSMajor {
		return fmt.Errorf("%w: running macOS %s", ErrUnsupportedVersion, strings.TrimSpace(version))
	}
	return nil
}
