package hostid

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

func GetOrCreate() (string, error) {
	hostIDFile := filepath.Join(hostIDDir, "host_id")
	if b, err := os.ReadFile(hostIDFile); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(hostIDFile), 0700); err != nil {
		return "", err
	}

	id := uuid.NewString()
	if err := os.WriteFile(hostIDFile, []byte(id), 0600); err != nil {
		return "", err
	}

	return id, nil
}
