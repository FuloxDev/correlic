package intelligence

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"time"
)

// reconBinaries are commands commonly used for system reconnaissance.
var reconBinaries = map[string]bool{
	"whoami": true, "hostname": true, "ipconfig": true, "ifconfig": true,
	"systeminfo": true, "tasklist": true, "netstat": true, "net": true,
	"nslookup": true, "arp": true, "route": true, "wmic": true,
	"uname": true, "id": true, "env": true, "printenv": true, "set": true,
}

// credentialPaths are file paths that indicate credential access.
var credentialPaths = []string{
	"/.ssh/", "/.aws/", "/.azure/", "/.kube/", "/.config/gcloud/",
	"/etc/shadow", "/etc/passwd", ".env", "credentials", "token",
}

type ContextBuilder struct {
	db    *sql.DB
	store *Store
}

func NewContextBuilder(db *sql.DB, store *Store) *ContextBuilder {
	return &ContextBuilder{db: db, store: store}
}

// BuildMinuteSnapshot creates a 1-minute context window from canonical events.
func (b *ContextBuilder) BuildMinuteSnapshot(ctx context.Context, orgID, hostID string, windowStart time.Time) error {
	windowEnd := windowStart.Add(1 * time.Minute)

	summary := ContextSummary{
		EventSlots: make([]int, 6), // 6 x 10-second slots
	}

	binSet := make(map[string]bool)
	destSet := make(map[string]bool)
	domainSet := make(map[string]bool)
	pidSet := make(map[int]bool)
	probeSet := make(map[string]bool) // PATHEXT probe dedup by basename

	// Query canonical events in this 1-minute window
	rows, err := b.db.QueryContext(ctx, `
		SELECT type, actor, target, context, ts
		FROM events
		WHERE host_id = $1 AND ts >= $2 AND ts < $3
		ORDER BY ts ASC
	`, hostID, windowStart, windowEnd)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var evType string
		var actor, target, evCtx sql.NullString
		var ts time.Time
		if err := rows.Scan(&evType, &actor, &target, &evCtx, &ts); err != nil {
			continue
		}

		// Temporal slot (10-second buckets within the minute)
		slot := int(ts.Sub(windowStart).Seconds()) / 10
		if slot >= 0 && slot < 6 {
			summary.EventSlots[slot]++
		}

		switch evType {
		case "process_exec":
			summary.ProcessExecCount++
			if actor.Valid {
				comm := extractJSONField(actor.String, "comm")
				pid := extractJSONFieldInt(actor.String, "pid")
				exe := extractJSONField(actor.String, "exe_path")
				if comm != "" {
					binSet[comm] = true
				}
				if pid > 0 {
					pidSet[pid] = true
				}
				if reconBinaries[strings.ToLower(comm)] {
					summary.ReconCommands++
				}
				_ = exe // available for notable events
			}

		case "file_open":
			summary.FileOpenCount++
			// Track file exists vs not-found with PATHEXT dedup.
			// Windows PATHEXT probes generate dozens of file_open events for the same
			// logical command (config.exe, config.bat, config.cmd...). Dedup by basename
			// so these count as ONE probe, not thirteen.
			fileExists := evCtx.Valid && extractJSONField(evCtx.String, "file_exists") == "true"
			if fileExists {
				summary.FileExistsCount++
			} else if target.Valid {
				fp := extractJSONField(target.String, "file_path")
				if fp != "" {
					base := filepath.Base(fp)
					lowerBase := strings.ToLower(base)
					// Strip PATHEXT suffix to get the real command name
					for _, ext := range []string{".exe", ".bat", ".cmd", ".com", ".lnk", ".vbs", ".vbe", ".wsf", ".wsh", ".msc", ".ps1"} {
						if strings.HasSuffix(lowerBase, ext) {
							base = base[:len(base)-len(ext)]
							break
						}
					}
					probeKey := filepath.Dir(fp) + "/" + base
					if !probeSet[probeKey] {
						probeSet[probeKey] = true
						summary.FileNotFoundCount++
					}
				} else {
					summary.FileNotFoundCount++
				}
			}
			if target.Valid {
				fp := extractJSONField(target.String, "file_path")
				for _, cred := range credentialPaths {
					if strings.Contains(strings.ToLower(fp), strings.ToLower(cred)) {
						summary.CredentialAccesses++
						summary.SensitiveFiles = appendUnique(summary.SensitiveFiles, fp)
						break
					}
				}
			}

		case "net_connect":
			summary.NetConnectCount++
			if target.Valid {
				ip := extractJSONField(target.String, "ip")
				port := extractJSONField(target.String, "port")
				if ip != "" {
					dest := ip
					if port != "" {
						dest = ip + ":" + port
					}
					destSet[dest] = true
				}
			}
			if evCtx.Valid {
				domain := extractJSONField(evCtx.String, "domain")
				if domain != "" {
					domainSet[domain] = true
				}
			}

		case "net_dns":
			summary.DNSQueryCount++
			if evCtx.Valid {
				domain := extractJSONField(evCtx.String, "query_name")
				if domain != "" {
					domainSet[domain] = true
				}
			}
		}

		// Extract PID from actor
		if actor.Valid {
			pid := extractJSONFieldInt(actor.String, "pid")
			if pid > 0 {
				pidSet[pid] = true
			}
		}
	}

	// Convert sets to slices
	for bin := range binSet {
		summary.UniqueBinaries = append(summary.UniqueBinaries, bin)
	}
	for dest := range destSet {
		summary.UniqueDestinations = append(summary.UniqueDestinations, dest)
	}
	for domain := range domainSet {
		summary.UniqueDomains = append(summary.UniqueDomains, domain)
	}
	for pid := range pidSet {
		summary.ActivePIDs = append(summary.ActivePIDs, pid)
	}

	// Count findings generated/suppressed in this window
	_ = b.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE suppressed = false),
			COUNT(*) FILTER (WHERE suppressed = true)
		FROM findings
		WHERE org_id = $1 AND created_at >= $2 AND created_at < $3
	`, orgID, windowStart, windowEnd).Scan(&summary.FindingsGenerated, &summary.FindingsSuppressed)

	// Only store if there were events
	totalEvents := summary.ProcessExecCount + summary.FileOpenCount + summary.NetConnectCount + summary.DNSQueryCount
	if totalEvents == 0 {
		return nil // skip empty windows
	}

	return b.store.InsertContextWindow(ctx, orgID, hostID, "1m", windowStart, windowEnd, summary)
}

// Helper: extract a JSON field value from a raw JSON string (lightweight, no full unmarshal)
func extractJSONField(jsonStr, field string) string {
	key := `"` + field + `"`
	idx := strings.Index(jsonStr, key)
	if idx < 0 {
		return ""
	}
	rest := jsonStr[idx+len(key):]
	// Skip : and whitespace
	rest = strings.TrimLeft(rest, ": \t\n")
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return ""
		}
		return rest[1 : end+1]
	}
	// Number or other
	end := strings.IndexAny(rest, ",}\n ")
	if end < 0 {
		return rest
	}
	return strings.TrimSpace(rest[:end])
}

func extractJSONFieldInt(jsonStr, field string) int {
	s := extractJSONField(jsonStr, field)
	if s == "" {
		return 0
	}
	var n int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// extractBinaryName gets the base name from an exe path.
func extractBinaryName(exePath string) string {
	base := filepath.Base(exePath)
	return strings.TrimSuffix(strings.ToLower(base), ".exe")
}
