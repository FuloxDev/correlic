package model

import (
	"errors"
	"fmt"
)

type CorrelationPack struct {
	PackID       string               `json:"pack_id"`
	Name         string               `json:"name"`
	Version      string               `json:"version"`
	Description  string               `json:"description"`
	Defaults     *CorrelationDefaults `json:"defaults,omitempty"`
	Policies     []PolicyRule         `json:"policies"`
	Correlations []CorrelationRule    `json:"correlations"`
}

type CorrelationDefaults struct {
	Severity string   `json:"severity"`
	Actions  []string `json:"actions"`
}

type PolicyRule struct {
	ID       string       `json:"id"`
	Signal   string       `json:"signal"`
	Name     string       `json:"name,omitempty"`     // Human-readable name
	Category string       `json:"category,omitempty"` // ssh, aws, git, browser, network
	Enabled  *bool        `json:"enabled,omitempty"`  // Toggle without deleting (default: true)
	Match    MatchClause  `json:"match"`
	Severity string       `json:"severity"`
	Actions  []string     `json:"actions"`
	Tags     []string     `json:"tags"`
	Scopes   *ScopeFilter `json:"scopes,omitempty"` // Filter by repo/branch/user
}

// ScopeFilter limits policy to specific contexts
type ScopeFilter struct {
	Repos     []string `json:"repos,omitempty"`      // ["github.com/org/*"]
	Branches  []string `json:"branches,omitempty"`   // ["main", "release/*"]
	Users     []string `json:"users,omitempty"`      // ["admin", "service-*"]
	FilePaths []string `json:"file_paths,omitempty"` // ["~/.ssh/*"]
	Agents    []string `json:"agents,omitempty"`     // ["agent-prod-*"]
}

// IsEnabled returns true if the policy is enabled (defaults to true if not set)
func (p *PolicyRule) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

type MatchClause struct {
	All  []Condition `json:"all"`
	Any  []Condition `json:"any"`
	None []Condition `json:"none"`
}

type Condition struct {
	Field string      `json:"field"`
	Op    string      `json:"op"`
	Value interface{} `json:"value"`
}

type CorrelationRule struct {
	ID            string   `json:"id"`
	PolicyIDs     []string `json:"policy_ids"`
	WindowMinutes int      `json:"window_minutes"`
	SameActor     bool     `json:"same_actor"`
	SameRepo      bool     `json:"same_repo"`
	SameHost      bool     `json:"same_host"`
	Threshold     int      `json:"threshold"`
	Severity      string   `json:"severity"`
	Actions       []string `json:"actions"`
}

func (p *CorrelationPack) Validate() error {
	if p.PackID == "" || p.Name == "" || p.Version == "" {
		return errors.New("pack_id, name, and version are required")
	}
	if len(p.Policies) == 0 {
		return errors.New("at least one policy is required")
	}
	ids := map[string]struct{}{}
	for _, r := range p.Policies {
		if r.ID == "" || r.Signal == "" {
			return fmt.Errorf("policy id and signal are required")
		}
		if _, exists := ids[r.ID]; exists {
			return fmt.Errorf("duplicate policy id: %s", r.ID)
		}
		ids[r.ID] = struct{}{}
	}
	for _, c := range p.Correlations {
		if c.ID == "" {
			return fmt.Errorf("correlation id is required")
		}
		if len(c.PolicyIDs) == 0 {
			return fmt.Errorf("correlation %s must reference policy_ids", c.ID)
		}
		if c.WindowMinutes <= 0 {
			return fmt.Errorf("correlation %s must have window_minutes > 0", c.ID)
		}
		for _, pid := range c.PolicyIDs {
			if _, ok := ids[pid]; !ok {
				return fmt.Errorf("correlation %s references unknown policy id %s", c.ID, pid)
			}
		}
	}
	return nil
}
