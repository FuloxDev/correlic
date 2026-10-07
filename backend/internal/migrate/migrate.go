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

type AppliedMigration struct {
	Version   string
	AppliedAt time.Time
}

// ApplyEmbedded applies all embedded migrations (migrations/*.sql) in lexical order.
// It records applied migrations in schema_migrations.
func ApplyEmbedded(db *sql.DB) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read embedded migrations dir: %w", err)
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
