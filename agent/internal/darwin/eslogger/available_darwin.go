//go:build darwin

package eslogger

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// Available reports whether eslogger can be used on this host: the agent
// runs as root, Binary exists and is executable, and macOS is 13 or newer.
// Full Disk Access cannot be checked without running the tool; a missing
// grant surfaces as ErrNotPermitted from Collector.Start.
func Available(logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("%w: running as uid %d", ErrNotRoot, os.Geteuid())
	}
	st, err := os.Stat(Binary)
	if err != nil {
		return fmt.Errorf("%w: %s (%v)", ErrNotFound, Binary, err)
	}
	if st.IsDir() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("%w: %s is not executable", ErrNotFound, Binary)
	}
	version := productVersion()
	if version == "" {
		logger.Debug("could not determine the macOS version; relying on the presence of eslogger")
		return nil
	}
	if err := checkVersion(version); err != nil {
		return err
	}
	return nil
}

// productVersion returns the macOS product version ("14.3.1"), first from
// the kern.osproductversion sysctl and then from sw_vers; "" when neither
// works.
func productVersion() string {
	if v, err := unix.Sysctl("kern.osproductversion"); err == nil && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
