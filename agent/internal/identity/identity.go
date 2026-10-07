package identity

import (
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

const agentIDFile = ".correlic-agent-id"

/*
LoadOrCreate loads the agent identity from file or creates a new one if it doesn't exist.
*/
func LoadOrCreate() (string, error) {
	var dir string
	if cfg := os.Getenv("CORRELIC_CONFIG"); cfg != "" {
		dir = filepath.Dir(cfg)
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = home
	}

	// construct agent ID file path
	path := filepath.Join(dir, agentIDFile)

	// try to read existing agent ID
	if data, err := os.ReadFile(path); err == nil {
		return string(data), nil
	}

	id := uuid.New().String()
	err := os.WriteFile(path, []byte(id), 0600)
	if err != nil {
		return "", err
	}

	// return a new agent ID
	return id, nil
}
