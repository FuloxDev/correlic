package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/transport"
)

// RuleCacheTTL is how long a fetched rule set is reused before the hook asks
// the backend again (with If-None-Match, so unchanged rules cost one 304).
const RuleCacheTTL = 60 * time.Second

// RuleCacheFile is the cache file name under the cache dir.
const RuleCacheFile = "block-rules.json"

// ruleCache is the on-disk form of the cached rule set.
type ruleCache struct {
	Version   string                     `json:"version"`
	Rules     []transport.AgentBlockRule `json:"rules"`
	FetchedAt time.Time                  `json:"fetched_at"`
}

// RuleSource fetches block rules (the transport in production).
type RuleSource interface {
	GetBlockRules(ctx context.Context, ifNoneMatch string) (*transport.BlockRulesResult, error)
}

// LoadRules returns the block rules to evaluate: the cached set when it is
// younger than RuleCacheTTL, else a fresh fetch (falling back to the stale
// cache when the backend cannot be reached). ok is false when no rules are
// available at all, in which case the caller allows the call.
func LoadRules(ctx context.Context, src RuleSource, cacheDir string, now time.Time, logger *slog.Logger) (rules []transport.AgentBlockRule, ok bool) {
	path := filepath.Join(cacheDir, RuleCacheFile)
	cached, cacheErr := readRuleCache(path)
	if cacheErr == nil && now.Sub(cached.FetchedAt) < RuleCacheTTL && !cached.FetchedAt.After(now) {
		return cached.Rules, true
	}

	etag := ""
	if cacheErr == nil {
		etag = cached.Version
	}
	res, err := src.GetBlockRules(ctx, etag)
	switch {
	case err == nil && res.NotModified && cacheErr == nil:
		cached.FetchedAt = now
		writeRuleCache(path, cached)
		return cached.Rules, true
	case err == nil && !res.NotModified:
		writeRuleCache(path, &ruleCache{Version: res.Version, Rules: res.Rules, FetchedAt: now})
		return res.Rules, true
	case err == nil:
		// 304 without a usable cache: fetch without the etag.
		res, err = src.GetBlockRules(ctx, "")
		if err == nil {
			writeRuleCache(path, &ruleCache{Version: res.Version, Rules: res.Rules, FetchedAt: now})
			return res.Rules, true
		}
	}
	if transport.IsAuthError(err) {
		logger.Warn("block rules: backend rejected the API key; allowing", "status", transport.StatusOf(err))
	} else {
		logger.Debug("block rules fetch failed", "error", err)
	}
	if cacheErr == nil {
		return cached.Rules, true // stale but better than nothing
	}
	return nil, false
}

func readRuleCache(path string) (*ruleCache, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c ruleCache
	if err := json.NewDecoder(io.LimitReader(f, 4<<20)).Decode(&c); err != nil {
		return nil, err
	}
	if c.FetchedAt.IsZero() {
		return nil, errors.New("cache has no fetched_at")
	}
	return &c, nil
}

func writeRuleCache(path string, c *ruleCache) {
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, path)
}

// Evaluate matches a blockable event against the rules with the same
// semantics as the agent's enforcer: process_exec rules match the executable
// (basename, case-insensitive) of every simple command in a shell command
// line; file_open rules are globs matched against the file path of a
// read/edit tool and against path-like tokens of a shell command.
// net_connect rules do not apply to hooks.
func Evaluate(ev *ToolEvent, rules []transport.AgentBlockRule, home string) Decision {
	if ev == nil || len(rules) == 0 {
		return Decision{}
	}
	enf := enforcer.New(slog.New(slog.NewTextHandler(io.Discard, nil)), true)
	conv := make([]enforcer.BlockRule, 0, len(rules))
	for _, r := range rules {
		conv = append(conv, enforcer.BlockRule{ID: r.ID, SignalType: r.SignalType, Pattern: r.Pattern, KillTree: r.KillTree, Source: r.Source})
	}
	enf.UpdateRules(conv)

	if ev.Command != "" {
		for _, simple := range ShellCommands(ev.Command) {
			if exe := Executable(simple); exe != "" {
				if blocked, rule := enf.ShouldBlock("process_exec", BaseName(exe)); blocked {
					return Decision{Blocked: true, RuleID: rule.ID, SignalType: "process_exec", Candidate: exe, Pattern: rule.Pattern}
				}
			}
		}
		for _, p := range PathTokens(ev.Command, home) {
			if blocked, rule := enf.ShouldBlock("file_open", p); blocked {
				return Decision{Blocked: true, RuleID: rule.ID, SignalType: "file_open", Candidate: p, Pattern: rule.Pattern}
			}
		}
	}
	if ev.FilePath != "" {
		if blocked, rule := enf.ShouldBlock("file_open", ev.FilePath); blocked {
			return Decision{Blocked: true, RuleID: rule.ID, SignalType: "file_open", Candidate: ev.FilePath, Pattern: rule.Pattern}
		}
	}
	return Decision{}
}

// Reason is the text shown to the user and the AI when a call is denied.
func (d Decision) Reason() string {
	what := "command"
	if d.SignalType == "file_open" {
		what = "file access"
	}
	return fmt.Sprintf("Correlic block rule #%d (%s %q) denied this %s: %s", d.RuleID, d.SignalType, d.Pattern, what, d.Candidate)
}
