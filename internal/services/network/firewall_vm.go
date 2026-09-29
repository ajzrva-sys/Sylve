// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package network

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/alchemillahq/sylve/internal/logger"
	"github.com/alchemillahq/sylve/pkg/utils"
)

const (
	pfVMAnchorPrefix = "sylve/vm/"
)

var (
	pfVMRulesDir         = "/etc/pf.sylve/vm"
	vmFirewallRunCommand = utils.RunCommand
	vmFirewallMutex      sync.Mutex
)

// VMAnchorName returns the nested PF anchor name for a VM RID.
func VMAnchorName(rid uint) string {
	return pfVMAnchorPrefix + fmt.Sprintf("%d", rid)
}

// VMRulesPath returns the on-disk path for a VM's rendered anchor body.
func VMRulesPath(rid uint) string {
	return filepath.Join(pfVMRulesDir, fmt.Sprintf("%d.conf", rid))
}

// LoadVMAnchor writes the anchor body and loads it with pfctl -a without a
// full PF reload. The caller must hold vmFirewallMutex or firewallMutex.
func (s *Service) LoadVMAnchor(rid uint, rulesContent string) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()
	return s.loadVMAnchorLocked(rid, rulesContent)
}

func (s *Service) loadVMAnchorLocked(rid uint, rulesContent string) error {
	if err := os.MkdirAll(pfVMRulesDir, 0755); err != nil {
		return fmt.Errorf("failed_to_create_vm_rules_dir: %w", err)
	}
	path := VMRulesPath(rid)
	if err := utils.AtomicWriteFile(path, []byte(rulesContent), 0644); err != nil {
		return fmt.Errorf("failed_to_write_vm_rules: %w", err)
	}
	anchor := VMAnchorName(rid)
	if _, err := vmFirewallRunCommand("/sbin/pfctl", "-a", anchor, "-f", path); err != nil {
		return fmt.Errorf("failed_to_load_vm_anchor_%s: %w", anchor, err)
	}
	logger.L.Debug().Uint("rid", rid).Str("anchor", anchor).Msg("loaded VM PF anchor")
	return nil
}

// FlushVMAnchor removes all rules from the VM's nested anchor.
func (s *Service) FlushVMAnchor(rid uint) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()
	return s.flushVMAnchorLocked(rid)
}

func (s *Service) flushVMAnchorLocked(rid uint) error {
	anchor := VMAnchorName(rid)
	if _, err := vmFirewallRunCommand("/sbin/pfctl", "-a", anchor, "-F", "rules"); err != nil {
		return fmt.Errorf("failed_to_flush_vm_anchor_%s: %w", anchor, err)
	}
	// Drop the rendered body so startup reconciliation can detect orphans.
	_ = os.Remove(VMRulesPath(rid))
	logger.L.Debug().Uint("rid", rid).Str("anchor", anchor).Msg("flushed VM PF anchor")
	return nil
}

// ValidateVMAnchor checks the anchor body syntax without loading it.
func (s *Service) ValidateVMAnchor(rid uint, rulesContent string) error {
	tmpDir, err := os.MkdirTemp("", "sylve-vm-pf-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	path := filepath.Join(tmpDir, "rules.conf")
	if err := os.WriteFile(path, []byte(rulesContent), 0644); err != nil {
		return err
	}
	anchor := VMAnchorName(rid)
	if _, err := vmFirewallRunCommand("/sbin/pfctl", "-a", anchor, "-nf", path); err != nil {
		return fmt.Errorf("vm_anchor_syntax_invalid: %w", err)
	}
	return nil
}

// EnsureVMAnchorParent makes sure the main ruleset contains `anchor "sylve/vm/*"`.
// It is a no-op when the anchor is already present. Returns true if a full
// ApplyFirewallConfig is needed (anchor was added).
func (s *Service) EnsureVMAnchorParent() (bool, error) {
	content, err := os.ReadFile(pfMainConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if strings.Contains(string(content), `anchor "sylve/vm/*"`) {
		return false, nil
	}
	// The main config is rendered by buildPFMainConfig; the next Apply will
	// include the anchor. Trigger that apply.
	return true, nil
}

// ReconcileOrphanVMAnchors flushes any on-disk VM rule files that no longer
// correspond to an enabled VM firewall. Call at startup.
func (s *Service) ReconcileOrphanVMAnchors(validRID map[uint]bool) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()

	entries, err := os.ReadDir(pfVMRulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		var rid uint
		if _, err := fmt.Sscanf(entry.Name(), "%d.conf", &rid); err != nil {
			continue
		}
		if validRID[rid] {
			continue
		}
		if err := s.flushVMAnchorLocked(rid); err != nil {
			logger.L.Warn().Err(err).Uint("rid", rid).Msg("failed to flush orphan VM anchor")
		}
	}
	return nil
}

// --- VM firewall counters ---

var pfVMRuleLabelPattern = regexp.MustCompile(`label\s+"sylve_vm_([0-9]+)_trf_([0-9]+)"`)

type vmRuleKey struct {
	RID    uint
	RuleID uint
}

type vmRuleCounterTotals struct {
	Packets   uint64
	Bytes     uint64
	UpdatedAt time.Time
}

// collectVMCountersFromPF runs pfctl -a sylve/vm/<rid> -vvsr for each RID and
// parses label-attributed packet/byte counters.
func collectVMCountersFromPF(rids []uint) map[vmRuleKey]vmRuleCounterTotals {
	out := make(map[vmRuleKey]vmRuleCounterTotals)
	for _, rid := range rids {
		anchor := VMAnchorName(rid)
		output, err := vmFirewallRunCommand("/sbin/pfctl", "-a", anchor, "-vvsr")
		if err != nil {
			continue
		}
		lines := strings.Split(output, "\n")
		for i, line := range lines {
			m := pfVMRuleLabelPattern.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			var labelRID, ruleID uint
			fmt.Sscanf(m[1], "%d", &labelRID)
			fmt.Sscanf(m[2], "%d", &ruleID)
			key := vmRuleKey{RID: labelRID, RuleID: ruleID}
			if _, exists := out[key]; exists {
				continue
			}
			for j := i + 1; j < len(lines) && j < i+8; j++ {
				if pm := pfTrafficRuleCounterPattern.FindStringSubmatch(lines[j]); pm != nil {
					var pkts, byt uint64
					fmt.Sscanf(pm[1], "%d", &pkts)
					fmt.Sscanf(pm[2], "%d", &byt)
					out[key] = vmRuleCounterTotals{Packets: pkts, Bytes: byt, UpdatedAt: time.Now()}
					break
				}
			}
		}
	}
	return out
}
