package hook

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-agent/internal/hostid"
	"github.com/google/uuid"
)

// ResolveHostID returns the host id hook events carry, in order:
//
//  1. the host_id config override;
//  2. the agent's host id file (hostid.StateDir()/host_id, e.g.
//     /var/lib/correlic/host_id) when it is readable, so hook events and
//     kernel events from the same machine share one host;
//  3. a stable per-user id kept in ~/.correlic/host_id (created on first use).
//
// The agent's state directory is root-only on Linux and macOS, so a hook
// running as an unprivileged user normally lands on (3); on Windows
// C:\ProgramData\Correlic is usually readable and (2) applies. The fallback
// is never written into the agent's directory.
func ResolveHostID(override string, userDir string) (string, error) {
	if id := strings.TrimSpace(override); id != "" {
		return id, nil
	}
	if b, err := os.ReadFile(filepath.Join(hostid.StateDir(), "host_id")); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	return perUserHostID(userDir)
}

func perUserHostID(dir string) (string, error) {
	path := filepath.Join(dir, "host_id")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	id := uuid.NewString()
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}
