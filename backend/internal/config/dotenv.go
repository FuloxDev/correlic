package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LoadDotEnvIfPresent loads KEY=VALUE pairs from the given file into the current
// process environment, without overriding already-set environment variables.
//
// This is intentionally lightweight (no external deps) and is meant for local dev.
// In production, environment should be provided by the runtime (systemd, k8s, etc).
func LoadDotEnvIfPresent(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return LoadDotEnv(path)
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("stat %s: %w", path, err)
}

// LoadDotEnv loads KEY=VALUE pairs from the given file into the current process
// environment, without overriding already-set environment variables.
func LoadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		val := strings.TrimSpace(v)
		if len(val) >= 2 {
			// Handle simple quoted values: KEY="value" or KEY='value'
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if _, already := os.LookupEnv(key); already {
			continue
		}
		if setErr := os.Setenv(key, val); setErr != nil {
			return fmt.Errorf("setenv %s: %w", key, setErr)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", path, err)
	}
	return nil
}
