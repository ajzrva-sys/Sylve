// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMAnchorName(t *testing.T) {
	if got := VMAnchorName(100); got != "sylve/vm/100" {
		t.Errorf("VMAnchorName(100) = %q, want %q", got, "sylve/vm/100")
	}
	if got := VMAnchorName(1); got != "sylve/vm/1" {
		t.Errorf("VMAnchorName(1) = %q, want %q", got, "sylve/vm/1")
	}
}

func TestBuildPFMainConfigIncludesVMAnchor(t *testing.T) {
	cfg := buildPFMainConfig("", "", "", "", "", "", "", "/etc/pf.sylve/nat-rules.conf", "/etc/pf.sylve/traffic-rules.conf")
	if !strings.Contains(cfg, `anchor "sylve/vm/*"`) {
		t.Fatalf("buildPFMainConfig missing VM anchor:\n%s", cfg)
	}
	// VM anchor must come after the traffic-rules anchor.
	idxTraffic := strings.Index(cfg, `anchor "sylve/traffic-rules"`)
	idxVM := strings.Index(cfg, `anchor "sylve/vm/*"`)
	if idxTraffic < 0 || idxVM < 0 || idxVM < idxTraffic {
		t.Errorf("VM anchor must appear after traffic-rules anchor")
	}
}

func TestLoadAndFlushVMAnchor(t *testing.T) {
	var calls []string
	orig := vmFirewallRunCommand
	vmFirewallRunCommand = func(command string, args ...string) (string, error) {
		calls = append(calls, command+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() { vmFirewallRunCommand = orig })

	origDir := pfVMRulesDir
	pfVMRulesDir = t.TempDir()
	t.Cleanup(func() { pfVMRulesDir = origDir })

	svc := &Service{}
	rules := "pass in quick on svm100n1 all no state\n"
	if err := svc.LoadVMAnchor(100, rules); err != nil {
		t.Fatalf("LoadVMAnchor: %v", err)
	}
	found := false
	for _, c := range calls {
		if strings.Contains(c, "pfctl") && strings.Contains(c, "-a") && strings.Contains(c, "sylve/vm/100") && strings.Contains(c, "-f") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pfctl -a sylve/vm/100 -f call, got: %v", calls)
	}

	// Verify the rules file was written.
	written := filepath.Join(pfVMRulesDir, "100.conf")
	if _, err := os.Stat(written); err != nil {
		t.Errorf("expected rules file at %s: %v", written, err)
	}

	calls = nil
	if err := svc.FlushVMAnchor(100); err != nil {
		t.Fatalf("FlushVMAnchor: %v", err)
	}
	found = false
	for _, c := range calls {
		if strings.Contains(c, "-F") && strings.Contains(c, "sylve/vm/100") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pfctl -a sylve/vm/100 -F rules call, got: %v", calls)
	}
	// Flush should remove the rendered body.
	if _, err := os.Stat(written); !os.IsNotExist(err) {
		t.Errorf("expected rules file removed after flush, got err=%v", err)
	}
}

func TestValidateVMAnchor(t *testing.T) {
	var calls []string
	orig := vmFirewallRunCommand
	vmFirewallRunCommand = func(command string, args ...string) (string, error) {
		calls = append(calls, command+" "+strings.Join(args, " "))
		return "", nil
	}
	t.Cleanup(func() { vmFirewallRunCommand = orig })

	svc := &Service{}
	if err := svc.ValidateVMAnchor(100, "pass in quick on svm100n1 all no state\n"); err != nil {
		t.Fatalf("ValidateVMAnchor: %v", err)
	}
	found := false
	for _, c := range calls {
		if strings.Contains(c, "-nf") && strings.Contains(c, "sylve/vm/100") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected pfctl -a sylve/vm/100 -nf call, got: %v", calls)
	}
}

func TestVMRulesPath(t *testing.T) {
	p := VMRulesPath(100)
	if filepath.Base(p) != "100.conf" {
		t.Errorf("VMRulesPath(100) = %q, want base 100.conf", p)
	}
	if filepath.Dir(p) != pfVMRulesDir {
		t.Errorf("VMRulesPath(100) dir = %q, want %q", filepath.Dir(p), pfVMRulesDir)
	}
}

func TestEnsureVMAnchorParentNoExistingFile(t *testing.T) {
	svc := &Service{}
	// With no /etc/pf.conf in test env, should return (false, nil).
	needed, err := svc.EnsureVMAnchorParent()
	if err != nil {
		t.Fatalf("EnsureVMAnchorParent: %v", err)
	}
	if needed {
		// If pf.conf exists in the test environment and lacks the anchor,
		// true is acceptable. Only assert no error.
		t.Log("parent anchor addition needed")
	}
}

func TestReconcileOrphanVMAnchors(t *testing.T) {
	var flushed []string
	orig := vmFirewallRunCommand
	vmFirewallRunCommand = func(command string, args ...string) (string, error) {
		if len(args) >= 3 && args[2] == "-F" {
			flushed = append(flushed, args[1])
		}
		return "", nil
	}
	t.Cleanup(func() { vmFirewallRunCommand = orig })

	origDir := pfVMRulesDir
	pfVMRulesDir = t.TempDir()
	t.Cleanup(func() { pfVMRulesDir = origDir })

	// Plant an orphan (rid=999) and a valid (rid=100) rule file.
	os.WriteFile(filepath.Join(pfVMRulesDir, "999.conf"), []byte("pass all\n"), 0644)
	os.WriteFile(filepath.Join(pfVMRulesDir, "100.conf"), []byte("pass all\n"), 0644)

	svc := &Service{}
	err := svc.ReconcileOrphanVMAnchors(map[uint]bool{100: true})
	if err != nil {
		t.Fatalf("ReconcileOrphanVMAnchors: %v", err)
	}

	if len(flushed) != 1 || flushed[0] != "sylve/vm/999" {
		t.Errorf("expected only sylve/vm/999 flushed, got: %v", flushed)
	}
	// Valid file must survive.
	if _, err := os.Stat(filepath.Join(pfVMRulesDir, "100.conf")); err != nil {
		t.Errorf("valid VM rules file should survive reconcile: %v", err)
	}
	// Orphan file must be gone.
	if _, err := os.Stat(filepath.Join(pfVMRulesDir, "999.conf")); !os.IsNotExist(err) {
		t.Errorf("orphan VM rules file should be removed, got err=%v", err)
	}
}
