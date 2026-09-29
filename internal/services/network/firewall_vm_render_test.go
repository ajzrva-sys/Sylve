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

	networkModels "github.com/alchemillahq/sylve/internal/db/models/network"
	vmModels "github.com/alchemillahq/sylve/internal/db/models/vm"
)

func TestGuestDirectionToPF(t *testing.T) {
	// Guest outbound = PF in on tap; guest inbound = PF out on tap.
	if got := guestDirectionToPF("in"); got != "out" {
		t.Errorf("guestDirectionToPF(in) = %q, want out", got)
	}
	if got := guestDirectionToPF("out"); got != "in" {
		t.Errorf("guestDirectionToPF(out) = %q, want in", got)
	}
}

func TestRenderVMFirewallRulesDefaultDeny(t *testing.T) {
	settings := vmModels.VMFirewallSettings{
		VMID:            100,
		Enabled:         true,
		DefaultInbound:  "block",
		DefaultOutbound: "pass",
		AllowDHCP:       true,
		AllowNDP:        true,
	}
	taps := map[uint]string{1: "svm100n1"}
	out := RenderVMFirewallRules(100, settings, nil, taps, nil)

	// Guest inbound block = PF out on tap.
	if !strings.Contains(out, "block drop out quick on svm100n1 all") {
		t.Errorf("missing guest-inbound default block:\n%s", out)
	}
	// Guest outbound pass = PF in on tap.
	if !strings.Contains(out, "pass in  quick on svm100n1 all keep state") &&
		!strings.Contains(out, "pass in quick on svm100n1 all keep state") {
		t.Errorf("missing guest-outbound default pass:\n%s", out)
	}
	// DHCP holes present.
	if !strings.Contains(out, "port 68 to any port 67") {
		t.Errorf("missing DHCPv4 hole:\n%s", out)
	}
	// NDP holes present.
	if !strings.Contains(out, "proto ipv6-icmp") {
		t.Errorf("missing NDP hole:\n%s", out)
	}
}

func TestRenderVMFirewallRulesUserRule(t *testing.T) {
	settings := vmModels.VMFirewallSettings{
		VMID:            100,
		DefaultInbound:  "block",
		DefaultOutbound: "block",
	}
	taps := map[uint]string{1: "svm100n1"}
	rules := []vmModels.VMFirewallRule{
		{
			ID:          1,
			VMID:        100,
			Name:        "allow-ssh",
			Enabled:     true,
			Quick:       true,
			Priority:    1,
			Action:      "pass",
			Direction:   "in", // guest inbound = LAN→guest = PF out
			Protocol:    "tcp",
			DstPortsRaw: "22",
		},
	}
	out := RenderVMFirewallRules(100, settings, rules, taps, nil)

	// Guest inbound allow = PF out on tap, keep state.
	if !strings.Contains(out, "pass out quick on svm100n1") {
		t.Errorf("guest-inbound allow must render as PF out on tap:\n%s", out)
	}
	if !strings.Contains(out, "port 22") {
		t.Errorf("missing dest port:\n%s", out)
	}
	if !strings.Contains(out, "keep state") {
		t.Errorf("pass rule must keep state:\n%s", out)
	}
	if !strings.Contains(out, `label "sylve_vm_100_trf_1"`) {
		t.Errorf("missing rule label:\n%s", out)
	}
	// Default deny still present after user rules.
	if !strings.Contains(out, "block drop out quick on svm100n1 all") {
		t.Errorf("missing default inbound block:\n%s", out)
	}
}

func TestRenderVMFirewallRulesBlockNoState(t *testing.T) {
	settings := vmModels.VMFirewallSettings{VMID: 100, DefaultInbound: "block", DefaultOutbound: "block"}
	taps := map[uint]string{1: "svm100n1"}
	rules := []vmModels.VMFirewallRule{
		{ID: 1, VMID: 100, Enabled: true, Quick: true, Action: "block", Direction: "out"},
	}
	out := RenderVMFirewallRules(100, settings, rules, taps, nil)
	// Block rules must not keep state.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "block") && strings.Contains(line, "keep state") {
			t.Errorf("block rule must not keep state: %s", line)
		}
	}
}

func TestRenderVMFirewallRulesObjectSelectors(t *testing.T) {
	settings := vmModels.VMFirewallSettings{VMID: 100, DefaultInbound: "block", DefaultOutbound: "block"}
	taps := map[uint]string{1: "svm100n1"}

	srcObj := &networkModels.Object{
		ID:   5,
		Name: "lab-hosts",
		Type: "Host",
		Entries: []networkModels.ObjectEntry{
			{Value: "192.168.1.10"},
			{Value: "192.168.1.11"},
		},
	}
	dstObj := &networkModels.Object{
		ID:   6,
		Name: "dns-servers",
		Type: "Host",
		Entries: []networkModels.ObjectEntry{
			{Value: "10.0.0.53"},
		},
	}
	portObj := &networkModels.Object{
		ID:   7,
		Name: "web-ports",
		Type: "Port",
		Entries: []networkModels.ObjectEntry{
			{Value: "80"},
			{Value: "443"},
		},
	}

	rules := []vmModels.VMFirewallRule{
		{
			ID:           1,
			VMID:         100,
			Enabled:      true,
			Quick:        true,
			Action:       "pass",
			Direction:    "in",
			Protocol:     "tcp",
			SourceObj:    srcObj,
			SourceObjID:  &srcObj.ID,
			DestObj:      dstObj,
			DestObjID:    &dstObj.ID,
			DstPortObj:   portObj,
			DstPortObjID: &portObj.ID,
		},
	}

	objectTables := map[uint]firewallObjectTable{
		5: {
			ObjectID:   5,
			ObjectName: "lab-hosts",
			InetName:   "sylve_obj_5_inet",
			InetValues: []string{"192.168.1.10", "192.168.1.11"},
		},
		6: {
			ObjectID:   6,
			ObjectName: "dns-servers",
			InetName:   "sylve_obj_6_inet",
			InetValues: []string{"10.0.0.53"},
		},
	}

	out := RenderVMFirewallRules(100, settings, rules, taps, objectTables)

	if !strings.Contains(out, "from <sylve_obj_5_inet>") {
		t.Errorf("missing source object table selector:\n%s", out)
	}
	if !strings.Contains(out, "to <sylve_obj_6_inet>") {
		t.Errorf("missing dest object table selector:\n%s", out)
	}
	// Port objects are inlined, not tabular.
	if !strings.Contains(out, "port { 80, 443 }") && !strings.Contains(out, "port { 80,443 }") {
		t.Errorf("missing inlined port object list:\n%s", out)
	}
	if strings.Contains(out, "sylve_obj_7") {
		t.Errorf("port objects must not produce PF tables:\n%s", out)
	}
}

func TestRenderVMFirewallRulesSkipsEmptyObjectTable(t *testing.T) {
	settings := vmModels.VMFirewallSettings{VMID: 100, DefaultInbound: "block", DefaultOutbound: "block"}
	taps := map[uint]string{1: "svm100n1"}
	emptyObj := &networkModels.Object{ID: 9, Name: "empty", Type: "Host"}
	rules := []vmModels.VMFirewallRule{
		{
			ID:          1,
			VMID:        100,
			Enabled:     true,
			Quick:       true,
			Action:      "pass",
			Direction:   "in",
			SourceObj:   emptyObj,
			SourceObjID: &emptyObj.ID,
		},
	}
	out := RenderVMFirewallRules(100, settings, rules, taps, map[uint]firewallObjectTable{})
	if !strings.Contains(out, "skipped vm rule id=1") {
		t.Errorf("expected skip comment for empty object table:\n%s", out)
	}
	if strings.Contains(out, `label "sylve_vm_100_trf_1"`) {
		t.Errorf("empty object table must not emit a live rule:\n%s", out)
	}
}

func TestVMTapNameMatchesLibvirt(t *testing.T) {
	// Keep in sync with libvirt.VMTapName.
	if got := VMTapName(100, 1); got != "svm100n1" {
		t.Errorf("VMTapName(100,1) = %q, want svm100n1", got)
	}
}
