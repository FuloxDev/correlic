package identity

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

const agentIDFile = ".correlic-agent-id"

/*
LoadOrCreate loads the agent identity from file or creates a new one if it doesn't exist.
The state file lives next to the config file named by CORRELIC_CONFIG, otherwise in
the user's home directory.
*/
func LoadOrCreate() (string, error) {
	return LoadOrCreateFrom("")
}

// LoadOrCreateFrom is LoadOrCreate with an explicit config path (e.g. from
// --config) whose directory holds the agent id file. An empty path falls back
// to CORRELIC_CONFIG, then the home directory.
func LoadOrCreateFrom(configPath string) (string, error) {
	var dir string
	switch {
	case strings.TrimSpace(configPath) != "":
		dir = filepath.Dir(configPath)
	case os.Getenv("CORRELIC_CONFIG") != "":
		dir = filepath.Dir(os.Getenv("CORRELIC_CONFIG"))
	default:
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
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}

	id := uuid.New().String()
	err := os.WriteFile(path, []byte(id), 0600)
	if err != nil {
		return "", err
	}

	// return a new agent ID
	return id, nil
}
