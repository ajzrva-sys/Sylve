// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package network

import (
	"strings"
	"testing"
)

func TestCollectVMCountersFromPF(t *testing.T) {
	orig := vmFirewallRunCommand
	defer func() { vmFirewallRunCommand = orig }()

	vmFirewallRunCommand = func(command string, args ...string) (string, error) {
		if strings.Contains(command, "pfctl") {
			return strings.Join([]string{
				"@0 pass in quick on svm100n1 inet proto tcp from any to any port = ssh flags S/SA keep state label \"sylve_vm_100_trf_1\"",
				"  [ Evaluations: 10        Packets: 42         Bytes: 1234        States: 1     ]",
				"@1 block drop in quick on svm100n1 all label \"sylve_vm_100_trf_2\"",
				"  [ Evaluations: 5         Packets: 3          Bytes: 120         States: 0     ]",
			}, "\n"), nil
		}
		return "", nil
	}

	result := collectVMCountersFromPF([]uint{100})
	if len(result) != 2 {
		t.Fatalf("expected 2 counters, got %d: %+v", len(result), result)
	}

	c1, ok := result[vmRuleKey{RID: 100, RuleID: 1}]
	if !ok {
		t.Fatalf("missing counter for rule 1: %+v", result)
	}
	if c1.Packets != 42 || c1.Bytes != 1234 {
		t.Errorf("rule 1 counter = %+v, want packets=42 bytes=1234", c1)
	}

	c2, ok := result[vmRuleKey{RID: 100, RuleID: 2}]
	if !ok {
		t.Fatalf("missing counter for rule 2: %+v", result)
	}
	if c2.Packets != 3 || c2.Bytes != 120 {
		t.Errorf("rule 2 counter = %+v, want packets=3 bytes=120", c2)
	}

	if c1.UpdatedAt.IsZero() {
		t.Error("counter UpdatedAt should be set")
	}
}

func TestVMRuleLabelPattern(t *testing.T) {
	m := pfVMRuleLabelPattern.FindStringSubmatch(`label "sylve_vm_100_trf_5"`)
	if m == nil {
		t.Fatal("pattern did not match")
	}
	if m[1] != "100" || m[2] != "5" {
		t.Errorf("captured rid=%s ruleID=%s, want 100 and 5", m[1], m[2])
	}
	if pfVMRuleLabelPattern.FindStringSubmatch(`label "sylve_trf_5"`) != nil {
		t.Error("pattern should not match host traffic labels")
	}
}

func TestParseRIDFromRuleset(t *testing.T) {
	cases := []struct {
		in  string
		rid uint
		ok  bool
	}{
		{"sylve/vm/100", 100, true},
		{"Sylve/VM/42", 42, true},
		{"sylve/vm/100/nested", 100, true},
		{"vm/100", 100, true},
		{"100", 100, true},
		{"sylve/traffic-rules", 0, false},
		{"sylve/vm/", 0, false},
		{"sylve/vm/abc", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		rid, ok := parseRIDFromRuleset(tc.in)
		if ok != tc.ok || rid != tc.rid {
			t.Errorf("parseRIDFromRuleset(%q) = (%d, %v), want (%d, %v)", tc.in, rid, ok, tc.rid, tc.ok)
		}
	}
}

func TestParseVMRuleNumbersFromPF(t *testing.T) {
	out := strings.Join([]string{
		"@0 pass in quick on svm100n1 inet proto tcp from any to any port = ssh flags S/SA keep state label \"sylve_vm_100_trf_1\"",
		"  [ Evaluations: 10        Packets: 42         Bytes: 1234        States: 1     ]",
		"@3 block drop in quick on svm100n2 all label \"sylve_vm_100_trf_2\"",
		"  [ Evaluations: 5         Packets: 3          Bytes: 120         States: 0     ]",
	}, "\n")

	mapping := parseVMRuleNumbersFromPF(out)
	if mapping[0] != 1 {
		t.Errorf("rule@0 → %d, want 1", mapping[0])
	}
	if mapping[3] != 2 {
		t.Errorf("rule@3 → %d, want 2", mapping[3])
	}
	if len(mapping) != 2 {
		t.Errorf("unexpected mapping size %d: %+v", len(mapping), mapping)
	}
}

func TestResolveFirewallRuleReferenceVM(t *testing.T) {
	s := &Service{}
	rt := s.getFirewallTelemetryRuntime()
	rt.mu.Lock()
	rt.vmRuleNumbers = map[uint]map[int]uint{
		100: {7: 11, 8: 12},
	}
	rt.ruleNames = map[firewallCounterKey]string{
		{RuleType: "vm", RuleID: 11, VMID: 100}: "allow-web",
	}
	rt.mu.Unlock()

	parsed := parsedFirewallLogLine{
		RuleNumber:    7,
		SubruleNumber: 0,
		Ruleset:       "sylve/vm/100",
		Action:        "pass",
	}
	ruleType, ruleID, ruleName, ok := s.resolveFirewallRuleReference(parsed)
	if !ok {
		t.Fatal("expected VM rule to resolve")
	}
	if ruleType != "vm" || ruleID != 11 || ruleName != "allow-web" {
		t.Errorf("got (%s, %d, %q), want (vm, 11, allow-web)", ruleType, ruleID, ruleName)
	}

	// Unknown rid must not resolve.
	parsed.Ruleset = "sylve/vm/999"
	if _, _, _, ok := s.resolveFirewallRuleReference(parsed); ok {
		t.Error("unknown rid must not resolve")
	}

	// Host traffic ruleset must still work and not be captured by the vm/ branch.
	rt.mu.Lock()
	rt.trafficRuleNumbers = map[int]uint{7: 3}
	rt.ruleNames[firewallCounterKey{RuleType: "traffic", RuleID: 3}] = "host-rule"
	rt.mu.Unlock()
	parsed.Ruleset = "sylve/traffic-rules"
	ruleType, ruleID, ruleName, ok = s.resolveFirewallRuleReference(parsed)
	if !ok || ruleType != "traffic" || ruleID != 3 || ruleName != "host-rule" {
		t.Errorf("host traffic resolve got (%s, %d, %q, %v)", ruleType, ruleID, ruleName, ok)
	}
}
