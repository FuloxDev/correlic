package migrate

import (
	"database/sql"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/migrations"
)

// AppliedMigration is one row of schema_migrations.
type AppliedMigration struct {
	Version   string
	AppliedAt time.Time
}

// ensureTable creates schema_migrations if it does not exist.
func ensureTable(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	return nil
}

// EmbeddedVersions returns the embedded migration file names in apply order.
func EmbeddedVersions() ([]string, error) {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations dir: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

// ListApplied returns the migrations recorded in schema_migrations, oldest first.
func ListApplied(db *sql.DB) ([]AppliedMigration, error) {
	if err := ensureTable(db); err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT version, applied_at FROM schema_migrations ORDER BY applied_at ASC, version ASC`)
	if err != nil {
		return nil, fmt.Errorf("list schema_migrations: %w", err)
	}
	defer rows.Close()

	var out []AppliedMigration
	for rows.Next() {
		var m AppliedMigration
		if err := rows.Scan(&m.Version, &m.AppliedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Pending returns the embedded migrations not yet recorded in schema_migrations.
func Pending(db *sql.DB) ([]string, error) {
	applied, err := ListApplied(db)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(applied))
	for _, m := range applied {
		seen[m.Version] = true
	}
	files, err := EmbeddedVersions()
	if err != nil {
		return nil, err
	}
	var pending []string
	for _, f := range files {
		if !seen[f] {
			pending = append(pending, f)
		}
	}
	return pending, nil
}

// ApplyEmbedded applies all embedded migrations (migrations/*.sql) in lexical order.
// It records applied migrations in schema_migrations.
func ApplyEmbedded(db *sql.DB) error {
	if err := ensureTable(db); err != nil {
		return err
	}

	files, err := EmbeddedVersions()
	if err != nil {
		return err
	}

	for _, fname := range files {
		// Skip already-applied migrations.
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, fname).Scan(&exists); err != nil {
			return fmt.Errorf("check migration %s: %w", fname, err)
		}
		if exists {
			continue
		}

		sqlBytes, err := migrations.FS.ReadFile(path.Join(".", fname))
		if err != nil {
			return fmt.Errorf("read migration %s: %w", fname, err)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", fname, err)
		}

		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", fname, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, fname); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", fname, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", fname, err)
		}
	}

	return nil
}
