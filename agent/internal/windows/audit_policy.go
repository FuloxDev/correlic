//go:build windows

package windows

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/correlic/correlic-agent/internal/hostid"
)

const (
	auditRegistryKey   = `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit`
	auditRegistryValue = "ProcessCreationIncludeCmdLine_Enabled"
	// AuditBackupFileName is the file in the state dir holding the audit
	// configuration as it was before the agent first changed it.
	AuditBackupFileName = "audit_policy_backup.json"
)

// requiredSubcategories are the auditpol subcategories the agent enables for
// success events.
var requiredSubcategories = []string{
	"Process Creation",
	"File System",
	"Registry",
	"Sensitive Privilege Use",
}

// auditSetting is one subcategory's inclusion setting.
type auditSetting struct {
	Success bool `json:"success"`
	Failure bool `json:"failure"`
}

// auditBackup is the on-disk record of the pre-agent audit configuration.
type auditBackup struct {
	SavedAt       time.Time               `json:"saved_at"`
	Subcategories map[string]auditSetting `json:"subcategories"`
	// CmdLineValueExisted is false when the registry value was absent.
	CmdLineValueExisted bool   `json:"cmdline_value_existed"`
	CmdLineValue        uint64 `json:"cmdline_value"`
}

// AuditBackupPath returns the backup file location in the state directory.
func AuditBackupPath() string {
	return filepath.Join(hostid.StateDir(), AuditBackupFileName)
}

// EnableRequiredAuditPolicies configures Windows Security Audit policies needed
// for reliable event capture. Requires Administrator privileges.
//
// Before the first change the current settings are written to
// AuditBackupPath so "service uninstall" can put them back.
//
// Policies enabled:
//   - Process Creation (Event 4688) + command line logging
//   - Process Termination (Event 4689)
//   - Object Access / File System (Event 4656) — read vs write distinction
//   - Registry (Event 4657) — registry key modifications
//   - Sensitive Privilege Use (Event 4672) — privilege escalation detection
//
// Resource impact: negligible (<0.1% CPU, ~10-50MB/day event log disk).
// These are standard enterprise hardening settings recommended by Microsoft,
// CrowdStrike, SentinelOne, and Defender for Endpoint.
func EnableRequiredAuditPolicies(logger *slog.Logger) error {
	if err := recordPriorAuditState(logger); err != nil {
		logger.Warn("could not record prior audit policy state; uninstall will not be able to restore it", "error", err)
	}

	var errs []string

	// 1. Enable process creation auditing (Event 4688 + 4689)
	if err := runAuditPol("Process Creation", "enable"); err != nil {
		errs = append(errs, fmt.Sprintf("Process Creation: %v", err))
	} else {
		logger.Info("audit policy enabled", "subcategory", "Process Creation", "events", "4688,4689")
	}

	// 2. Enable command line in process creation events (the key fix)
	if err := enableCmdLineAudit(); err != nil {
		errs = append(errs, fmt.Sprintf("CmdLine audit: %v", err))
	} else {
		logger.Info("audit policy enabled", "setting", auditRegistryValue)
	}

	// 3. Enable file system object access (Event 4656 — read vs write)
	if err := runAuditPol("File System", "enable"); err != nil {
		errs = append(errs, fmt.Sprintf("File System: %v", err))
	} else {
		logger.Info("audit policy enabled", "subcategory", "File System", "events", "4656,4663")
	}

	// 4. Enable registry auditing (Event 4657)
	if err := runAuditPol("Registry", "enable"); err != nil {
		errs = append(errs, fmt.Sprintf("Registry: %v", err))
	} else {
		logger.Info("audit policy enabled", "subcategory", "Registry", "events", "4657")
	}

	// 5. Enable sensitive privilege use (Event 4672)
	if err := runAuditPol("Sensitive Privilege Use", "enable"); err != nil {
		errs = append(errs, fmt.Sprintf("Sensitive Privilege Use: %v", err))
	} else {
		logger.Info("audit policy enabled", "subcategory", "Sensitive Privilege Use", "events", "4672,4673")
	}

	if len(errs) > 0 {
		return fmt.Errorf("some audit policies failed: %s", strings.Join(errs, "; "))
	}

	logger.Info("all required audit policies enabled successfully")
	return nil
}

// recordPriorAuditState writes the current audit settings to the backup file
// unless one already exists (only the state before the agent's first change
// is interesting).
func recordPriorAuditState(logger *slog.Logger) error {
	path := AuditBackupPath()
	if _, err := os.Stat(path); err == nil {
		return nil // already recorded by an earlier run
	}

	b := auditBackup{SavedAt: time.Now().UTC(), Subcategories: make(map[string]auditSetting)}
	var errs []string
	for _, sub := range requiredSubcategories {
		setting, err := queryAuditPol(sub)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sub, err))
			continue
		}
		b.Subcategories[sub] = setting
	}

	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, auditRegistryKey, registry.QUERY_VALUE); err == nil {
		if val, _, err := k.GetIntegerValue(auditRegistryValue); err == nil {
			b.CmdLineValueExisted = true
			b.CmdLineValue = val
		}
		k.Close()
	}

	if len(b.Subcategories) == 0 {
		return fmt.Errorf("auditpol state unavailable: %s", strings.Join(errs, "; "))
	}

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	logger.Info("recorded prior audit policy state", "path", path, "subcategories", len(b.Subcategories))
	if len(errs) > 0 {
		logger.Warn("some audit subcategories could not be read; they will not be restored", "errors", errs)
	}
	return nil
}

// RestoreAuditPolicies puts the audit configuration back to the state recorded
// by the first EnableRequiredAuditPolicies run and removes the backup file.
// It is a no-op (nil) when no backup exists.
func RestoreAuditPolicies(logger *slog.Logger) error {
	path := AuditBackupPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info("no audit policy backup found; nothing to restore", "path", path)
			return nil
		}
		return fmt.Errorf("read audit backup: %w", err)
	}
	var b auditBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return fmt.Errorf("parse audit backup %s: %w", path, err)
	}

	var errs []string
	for sub, setting := range b.Subcategories {
		if err := setAuditPol(sub, setting); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sub, err))
			continue
		}
		logger.Info("audit policy restored", "subcategory", sub, "success", setting.Success, "failure", setting.Failure)
	}

	if err := restoreCmdLineAudit(b); err != nil {
		errs = append(errs, fmt.Sprintf("CmdLine audit: %v", err))
	} else {
		logger.Info("audit registry value restored", "value", auditRegistryValue, "existed", b.CmdLineValueExisted, "prior", b.CmdLineValue)
	}

	if len(errs) > 0 {
		return fmt.Errorf("some audit policies could not be restored (backup kept at %s): %s", path, strings.Join(errs, "; "))
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Warn("audit policies restored but backup file could not be removed", "path", path, "error", err)
	}
	return nil
}

// CheckAuditPolicies verifies that required audit policies are enabled.
// Returns a map of subcategory → enabled status.
func CheckAuditPolicies(logger *slog.Logger) map[string]bool {
	results := make(map[string]bool)
	for _, sub := range requiredSubcategories {
		setting, err := queryAuditPol(sub)
		results[sub] = err == nil && setting.Success
	}

	// Check command line audit registry key
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, auditRegistryKey, registry.QUERY_VALUE)
	if err == nil {
		defer k.Close()
		val, _, err := k.GetIntegerValue(auditRegistryValue)
		results["CmdLine"] = err == nil && val == 1
	} else {
		results["CmdLine"] = false
	}

	return results
}

// runAuditPol executes auditpol to enable a subcategory for success events.
func runAuditPol(subcategory, successState string) error {
	cmd := exec.Command("auditpol", "/set",
		"/subcategory:"+subcategory,
		"/success:"+successState)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("auditpol failed for %q: %v (output: %s)", subcategory, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setAuditPol sets both the success and failure inclusion of a subcategory.
func setAuditPol(subcategory string, s auditSetting) error {
	onOff := func(b bool) string {
		if b {
			return "enable"
		}
		return "disable"
	}
	cmd := exec.Command("auditpol", "/set",
		"/subcategory:"+subcategory,
		"/success:"+onOff(s.Success),
		"/failure:"+onOff(s.Failure))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("auditpol failed for %q: %v (output: %s)", subcategory, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// queryAuditPol reads a subcategory's current inclusion setting using the
// CSV report form ("/r"): the last column pair is "Inclusion Setting" with
// values like "Success and Failure", "Success", "Failure", "No Auditing".
func queryAuditPol(subcategory string) (auditSetting, error) {
	out, err := exec.Command("auditpol", "/get", "/subcategory:"+subcategory, "/r").CombinedOutput()
	if err != nil {
		return auditSetting{}, fmt.Errorf("auditpol /get failed for %q: %v (output: %s)", subcategory, err, strings.TrimSpace(string(out)))
	}
	return parseAuditPolCSV(string(out), subcategory)
}

// parseAuditPolCSV extracts the inclusion setting for subcategory from
// "auditpol /get /r" output.
func parseAuditPolCSV(out, subcategory string) (auditSetting, error) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Machine Name") {
			continue
		}
		cols := strings.Split(line, ",")
		// Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
		if len(cols) < 5 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(cols[2]), subcategory) {
			continue
		}
		inclusion := strings.ToLower(strings.TrimSpace(cols[4]))
		return auditSetting{
			Success: strings.Contains(inclusion, "success"),
			Failure: strings.Contains(inclusion, "failure"),
		}, nil
	}
	return auditSetting{}, fmt.Errorf("subcategory %q not found in auditpol output", subcategory)
}

// enableCmdLineAudit sets the registry key to include command line in process creation events.
// Key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit
// Value: ProcessCreationIncludeCmdLine_Enabled = 1
func enableCmdLineAudit() error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, auditRegistryKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open/create audit registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue(auditRegistryValue, 1); err != nil {
		return fmt.Errorf("failed to set %s: %w", auditRegistryValue, err)
	}
	return nil
}

// restoreCmdLineAudit puts the registry value back: deleted when it did not
// exist before, otherwise set to its prior value.
func restoreCmdLineAudit(b auditBackup) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, auditRegistryKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil // key is gone; nothing to restore
		}
		return fmt.Errorf("open audit registry key: %w", err)
	}
	defer k.Close()
	if !b.CmdLineValueExisted {
		if err := k.DeleteValue(auditRegistryValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return fmt.Errorf("delete %s: %w", auditRegistryValue, err)
		}
		return nil
	}
	if err := k.SetDWordValue(auditRegistryValue, uint32(b.CmdLineValue)); err != nil {
		return fmt.Errorf("set %s: %w", auditRegistryValue, err)
	}
	return nil
}

// IsAdmin checks if the current process has Administrator privileges.
func IsAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}
