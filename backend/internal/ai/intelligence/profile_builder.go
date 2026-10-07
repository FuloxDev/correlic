package intelligence

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/user"
	"runtime"
	"strings"
)

type ProfileBuilder struct {
	db    *sql.DB
	store *Store
}

func NewProfileBuilder(db *sql.DB, store *Store) *ProfileBuilder {
	return &ProfileBuilder{db: db, store: store}
}

// Build creates or updates the system profile for a host.
// Called incrementally when baselines/agents change, and periodically (hourly) for full refresh.
func (b *ProfileBuilder) Build(ctx context.Context, orgID, hostID string) error {
	profile := SystemProfile{}

	// Host info
	profile.Host.OS = runtime.GOOS + " " + runtime.GOARCH
	if u, err := user.Current(); err == nil {
		profile.Host.User = u.Username
	}
	// Hostname from events
	var hostname string
	_ = b.db.QueryRowContext(ctx,
		`SELECT DISTINCT host_id FROM events WHERE host_id = $1 LIMIT 1`, hostID).Scan(&hostname)
	profile.Host.Hostname = hostID

	// AI agents from sessions
	// ai_agent_sessions uses agent_id (not host_id), agent_type (not ai_type), root_comm (not root_exe)
	rows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT agent_type, root_comm, MIN(started_at)
		FROM ai_agent_sessions
		WHERE org_id = $1
		GROUP BY agent_type, root_comm
	`, orgID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a AgentInfo
			var rootComm string
			var started sql.NullTime
			if err := rows.Scan(&a.Type, &rootComm, &started); err == nil {
				if started.Valid {
					a.FirstSeen = started.Time.Format("2006-01-02")
				}
				// Look up install path from recent events
				var exePath sql.NullString
				_ = b.db.QueryRowContext(ctx, `
					SELECT actor->>'exe_path' FROM events
					WHERE host_id = $1 AND type = 'process_exec' AND actor->>'comm' = $2
					ORDER BY ts DESC LIMIT 1
				`, hostID, rootComm).Scan(&exePath)
				if exePath.Valid && exePath.String != "" {
					a.InstallPath = exePath.String
				} else {
					a.InstallPath = rootComm
				}
				profile.AIAgents = append(profile.AIAgents, a)
			}
		}
	}

	// Normal network from baselines
	netRows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT pattern FROM behavioral_baselines
		WHERE org_id = $1 AND signal_type = 'network_dest'
		ORDER BY pattern LIMIT 100
	`, orgID)
	if err == nil {
		defer netRows.Close()
		for netRows.Next() {
			var p string
			if netRows.Scan(&p) == nil {
				profile.NormalNetwork = append(profile.NormalNetwork, p)
			}
		}
	}

	// Normal binaries from baselines
	binRows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT pattern FROM behavioral_baselines
		WHERE org_id = $1 AND signal_type = 'binary'
		ORDER BY pattern LIMIT 50
	`, orgID)
	if err == nil {
		defer binRows.Close()
		for binRows.Next() {
			var p string
			if binRows.Scan(&p) == nil {
				profile.NormalBinaries = append(profile.NormalBinaries, p)
			}
		}
	}

	// Installed tools — detect from unique exe paths in recent process_exec events
	toolRows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT actor->>'exe_path' as exe
		FROM events
		WHERE host_id = $1 AND type = 'process_exec' AND ts > NOW() - INTERVAL '24 hours'
		LIMIT 100
	`, hostID)
	if err == nil {
		defer toolRows.Close()
		seen := make(map[string]bool)
		for toolRows.Next() {
			var exe sql.NullString
			if toolRows.Scan(&exe) == nil && exe.Valid {
				tool := extractToolName(exe.String)
				if tool != "" && !seen[tool] {
					seen[tool] = true
					profile.InstalledTools = append(profile.InstalledTools, tool)
				}
			}
		}
	}

	// Working directories — most-accessed directories from file baselines
	dirRows, err := b.db.QueryContext(ctx, `
		SELECT DISTINCT pattern FROM behavioral_baselines
		WHERE org_id = $1 AND signal_type = 'file_pattern' AND pattern LIKE '%/**'
		ORDER BY hit_count DESC LIMIT 10
	`, orgID)
	if err == nil {
		defer dirRows.Close()
		for dirRows.Next() {
			var p string
			if dirRows.Scan(&p) == nil {
				dir := strings.TrimSuffix(p, "/**")
				profile.WorkingDirs = append(profile.WorkingDirs, dir)
			}
		}
	}

	// PATH directories from environment (helps distinguish PATHEXT probes from real accesses)
	if pathEnv := os.Getenv("PATH"); pathEnv != "" {
		sep := ":"
		if strings.Contains(runtime.GOOS, "windows") || strings.Contains(profile.Host.OS, "windows") {
			sep = ";"
		}
		for _, dir := range strings.Split(pathEnv, sep) {
			dir = strings.TrimSpace(dir)
			if dir != "" {
				// Normalize to forward slash for consistency
				dir = strings.ReplaceAll(dir, "\\", "/")
				profile.PathDirs = append(profile.PathDirs, dir)
			}
		}
	}

	// Baseline summary counts
	_ = b.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE signal_type = 'file_pattern') as files,
			COUNT(*) FILTER (WHERE signal_type = 'network_dest') as network,
			COUNT(*) FILTER (WHERE signal_type = 'binary') as binaries
		FROM behavioral_baselines WHERE org_id = $1
	`, orgID).Scan(
		&profile.BaselineSummary.FilePatterns,
		&profile.BaselineSummary.NetworkDests,
		&profile.BaselineSummary.Binaries,
	)

	if err := b.store.UpsertProfile(ctx, orgID, hostID, profile); err != nil {
		log.Printf("WARN: profile build failed for %s/%s: %v", orgID, hostID, err)
		return err
	}

	log.Printf("AI system profile updated for host %s (agents=%d, tools=%d, baselines=%d)",
		hostID, len(profile.AIAgents), len(profile.InstalledTools),
		profile.BaselineSummary.FilePatterns+profile.BaselineSummary.NetworkDests)
	return nil
}

// extractToolName extracts a human-readable tool name from an exe path.
func extractToolName(exePath string) string {
	// Skip system binaries
	lower := strings.ToLower(exePath)
	if strings.Contains(lower, "/windows/system32/") || strings.Contains(lower, "/windows/syswow64/") {
		return ""
	}
	// Extract "Go 1.24" from "C:/Program Files/Go/bin/go.exe"
	parts := strings.Split(strings.ReplaceAll(exePath, "\\", "/"), "/")
	for i, p := range parts {
		lp := strings.ToLower(p)
		if lp == "program files" || lp == "program files (x86)" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}
