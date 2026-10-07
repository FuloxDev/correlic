package storage

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// settingsKeySep is the separator between rule_id and setting_key in composite cache keys.
// Uses null byte to avoid collisions with dots in rule IDs (e.g. "ai.credential_access").
const settingsKeySep = "\x00"

// RuleSetting represents one per-org rule threshold entry.
type RuleSetting struct {
	ID           int64
	OrgID        string
	RuleID       string
	SettingKey   string
	SettingValue string
	UpdatedAt    time.Time
}

// RuleSettingsStore caches per-org detection rule settings with a 30s background refresh.
// It implements detection.RuleSettingsReader.
type RuleSettingsStore struct {
	db *sql.DB

	mu    sync.RWMutex
	byOrg map[string]map[string]string // orgID → "rule_id\x00key" → value
	done  chan struct{}
}

// NewRuleSettingsStore creates the store and performs an initial load.
func NewRuleSettingsStore(db *sql.DB) *RuleSettingsStore {
	s := &RuleSettingsStore{
		db:    db,
		byOrg: make(map[string]map[string]string),
		done:  make(chan struct{}),
	}
	if err := s.reload(context.Background()); err != nil {
		log.Printf("WARN: rule_settings_store initial load failed: %v", err)
	}
	go s.backgroundRefresh()
	return s
}

// Stop signals the background refresh goroutine to exit.
func (s *RuleSettingsStore) Stop() {
	close(s.done)
}

func (s *RuleSettingsStore) backgroundRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.reload(context.Background()); err != nil {
				log.Printf("WARN: rule_settings_store refresh failed: %v", err)
			}
		}
	}
}

func (s *RuleSettingsStore) reload(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT org_id, rule_id, setting_key, setting_value FROM detection_rule_settings`)
	if err != nil {
		return fmt.Errorf("query detection_rule_settings: %w", err)
	}
	defer rows.Close()

	byOrg := make(map[string]map[string]string)
	for rows.Next() {
		var orgID, ruleID, key, val string
		if err := rows.Scan(&orgID, &ruleID, &key, &val); err != nil {
			continue
		}
		if byOrg[orgID] == nil {
			byOrg[orgID] = make(map[string]string)
		}
		byOrg[orgID][ruleID+settingsKeySep+key] = val
	}
	if err := rows.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	s.byOrg = byOrg
	s.mu.Unlock()
	return nil
}

// GetFloat returns the float64 setting for an org+rule+key, or def if not set/invalid.
// Implements detection.RuleSettingsReader.
func (s *RuleSettingsStore) GetFloat(orgID, ruleID, key string, def float64) float64 {
	if s == nil {
		return def
	}
	s.mu.RLock()
	val, ok := s.byOrg[orgID][ruleID+settingsKeySep+key]
	s.mu.RUnlock()
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return def
	}
	return f
}

// GetInt returns the int setting for an org+rule+key, or def if not set/invalid.
// Implements detection.RuleSettingsReader.
func (s *RuleSettingsStore) GetInt(orgID, ruleID, key string, def int) int {
	if s == nil {
		return def
	}
	s.mu.RLock()
	val, ok := s.byOrg[orgID][ruleID+settingsKeySep+key]
	s.mu.RUnlock()
	if !ok {
		return def
	}
	n, err := strconv.Atoi(val)
	if err != nil {
		return def
	}
	return n
}

// ListForOrg returns all settings for an org as a flat slice.
func (s *RuleSettingsStore) ListForOrg(orgID string) []RuleSetting {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	settings := s.byOrg[orgID]
	s.mu.RUnlock()

	result := make([]RuleSetting, 0, len(settings))
	for compositeKey, val := range settings {
		parts := strings.SplitN(compositeKey, settingsKeySep, 2)
		if len(parts) != 2 {
			continue
		}
		ruleID, key := parts[0], parts[1]
		result = append(result, RuleSetting{
			OrgID:        orgID,
			RuleID:       ruleID,
			SettingKey:   key,
			SettingValue: val,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		return result[i].SettingKey < result[j].SettingKey
	})
	return result
}

// Upsert inserts or updates a setting and reloads the cache.
func (s *RuleSettingsStore) Upsert(ctx context.Context, orgID, ruleID, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO detection_rule_settings (org_id, rule_id, setting_key, setting_value, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (org_id, rule_id, setting_key) DO UPDATE
		   SET setting_value = EXCLUDED.setting_value, updated_at = NOW()`,
		orgID, ruleID, key, value,
	)
	if err != nil {
		return fmt.Errorf("upsert detection_rule_setting: %w", err)
	}
	_ = s.reload(ctx)
	return nil
}

// Delete removes a setting (resets to default) and reloads.
func (s *RuleSettingsStore) Delete(ctx context.Context, orgID, ruleID, key string) error {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM detection_rule_settings WHERE org_id=$1 AND rule_id=$2 AND setting_key=$3`,
		orgID, ruleID, key,
	)
	if err != nil {
		return fmt.Errorf("delete detection_rule_setting: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("setting %s/%s not found for org %s", ruleID, key, orgID)
	}
	_ = s.reload(ctx)
	return nil
}
