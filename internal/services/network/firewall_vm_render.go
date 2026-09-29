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
	"sort"
	"strings"

	vmModels "github.com/alchemillahq/sylve/internal/db/models/vm"
)

// VMTapName is re-exported from the libvirt package's naming scheme so the
// renderer does not need a libvirt dependency. Keep in sync with
// libvirt.VMTapName.
func VMTapName(rid uint, networkID uint) string {
	return fmt.Sprintf("svm%dn%d", rid, networkID)
}

// guestDirectionToPF maps guest-centric direction to PF in/out on the tap.
//
//	Guest outbound (guest→LAN) = PF "in  on tap"
//	Guest inbound  (LAN→guest) = PF "out on tap"
//
// This inversion is required because PF sees the host's perspective of the
// tap interface.
func guestDirectionToPF(guestDir string) string {
	if strings.EqualFold(strings.TrimSpace(guestDir), "out") {
		return "in"
	}
	return "out"
}

// RenderVMFirewallRules produces the body of a per-VM nested PF anchor.
// rid is the VM's runtime ID (used in labels and the header); tapNames maps
// network IDs to ifconfig tap names; nil networkID rules are emitted once per
// tap. objectTables carries address-object PF tables so rules can reference
// `<sylve_obj_N_inet>` selectors. Address-object tables are declared at the
// top of the anchor so PF accepts the body even when the host firewall
// service has not created the global table declarations.
func RenderVMFirewallRules(
	rid uint,
	settings vmModels.VMFirewallSettings,
	rules []vmModels.VMFirewallRule,
	tapNames map[uint]string,
	objectTables map[uint]firewallObjectTable,
) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("# sylve vm firewall — generated for RID %d, do not edit\n\n", rid))

	if decl := renderVMObjectTableDecls(objectTables); decl != "" {
		b.WriteString(decl)
		b.WriteString("\n")
	}

	// Built-in holes (before user rules so they can be overridden by quick user rules).
	if settings.AllowDHCP {
		b.WriteString("# DHCPv4\n")
		for _, tap := range sortedTapValues(tapNames) {
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet  proto udp from any port 68 to any port 67 keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet  proto udp from any port 67 to any port 68 keep state\n", tap))
		}
		b.WriteString("# DHCPv6\n")
		for _, tap := range sortedTapValues(tapNames) {
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet6 proto udp from any port 546 to any port 547 keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet6 proto udp from any port 547 to any port 546 keep state\n", tap))
		}
		b.WriteString("\n")
	}
	if settings.AllowNDP {
		b.WriteString("# IPv6 ND/RA/SLAAC\n")
		for _, tap := range sortedTapValues(tapNames) {
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet6 proto ipv6-icmp all keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet6 proto ipv6-icmp all keep state\n", tap))
		}
		b.WriteString("\n")
	}
	if settings.AllowPing {
		b.WriteString("# ping\n")
		for _, tap := range sortedTapValues(tapNames) {
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet  proto icmp all keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet  proto icmp all keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet6 proto ipv6-icmp icmp6-type echoreq keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass in  quick on %s inet6 proto ipv6-icmp icmp6-type echorep keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet6 proto ipv6-icmp icmp6-type echoreq keep state\n", tap))
			b.WriteString(fmt.Sprintf("pass out quick on %s inet6 proto ipv6-icmp icmp6-type echorep keep state\n", tap))
		}
		b.WriteString("\n")
	}

	// User rules, ordered by priority then ID.
	sorted := make([]vmModels.VMFirewallRule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		return sorted[i].ID < sorted[j].ID
	})

	b.WriteString("# user rules\n")
	for _, rule := range sorted {
		if !rule.Enabled {
			continue
		}
		pfDir := guestDirectionToPF(rule.Direction)
		taps := tapsForRule(rule, tapNames)
		for _, tap := range taps {
			b.WriteString(renderVMFirewallRuleLine(rid, rule, pfDir, tap, objectTables))
		}
	}

	// Default policy (always last, always quick so earlier rules win).
	// Guest inbound = PF out on tap; guest outbound = PF in on tap.
	b.WriteString("\n# default policy\n")
	for _, tap := range sortedTapValues(tapNames) {
		logIn := ""
		logOut := ""
		if settings.LogDefault {
			logIn = " log (all)"
			logOut = " log (all)"
		}
		// Guest inbound (LAN→guest) = PF out on tap.
		b.WriteString(defaultRuleLine(settings.DefaultInbound, "out", logOut, tap))
		// Guest outbound (guest→LAN) = PF in on tap.
		b.WriteString(defaultRuleLine(settings.DefaultOutbound, "in", logIn, tap))
	}

	return b.String()
}

// defaultRuleLine renders the trailing default-deny/allow for one tap+direction.
func defaultRuleLine(policy string, pfDir string, logSuffix string, tap string) string {
	p := strings.ToLower(strings.TrimSpace(policy))
	if p == "pass" {
		return fmt.Sprintf("pass %s quick%s on %s all keep state\n", pfDir, logSuffix, tap)
	}
	return fmt.Sprintf("block drop %s quick%s on %s all\n", pfDir, logSuffix, tap)
}

// renderVMObjectTableDecls emits `table <name> persist` lines for address-object
// tables referenced by VM rules so PF accepts the anchor body standalone.
func renderVMObjectTableDecls(objectTables map[uint]firewallObjectTable) string {
	if len(objectTables) == 0 {
		return ""
	}
	ids := make([]int, 0, len(objectTables))
	for id := range objectTables {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	var b strings.Builder
	b.WriteString("# managed by Sylve: object tables used by this VM\n")
	for _, id := range ids {
		table := objectTables[uint(id)]
		if table.InetName != "" && len(table.InetValues) > 0 {
			b.WriteString(fmt.Sprintf("table <%s> persist\n", table.InetName))
		}
		if table.Inet6Name != "" && len(table.Inet6Values) > 0 {
			b.WriteString(fmt.Sprintf("table <%s> persist\n", table.Inet6Name))
		}
	}
	return b.String()
}

func sortedTapValues(m map[uint]string) []string {
	keys := make([]uint, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]string, 0, len(m))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func tapsForRule(rule vmModels.VMFirewallRule, tapNames map[uint]string) []string {
	if rule.NetworkID != nil {
		if name, ok := tapNames[*rule.NetworkID]; ok {
			return []string{name}
		}
		return nil
	}
	return sortedTapValues(tapNames)
}

func renderVMFirewallRuleLine(
	rid uint,
	rule vmModels.VMFirewallRule,
	pfDir string,
	tap string,
	objectTables map[uint]firewallObjectTable,
) string {
	family := rule.Family
	if family == "" {
		family = "any"
	}

	srcSelector, srcSkipped, srcReason := firewallAddressSelector(rule.SourceRaw, rule.SourceObj, family, objectTables)
	if srcSkipped {
		return fmt.Sprintf("# skipped vm rule id=%d name=%q on %s: %s\n", rule.ID, rule.Name, tap, srcReason)
	}
	dstSelector, dstSkipped, dstReason := firewallAddressSelector(rule.DestRaw, rule.DestObj, family, objectTables)
	if dstSkipped {
		return fmt.Sprintf("# skipped vm rule id=%d name=%q on %s: %s\n", rule.ID, rule.Name, tap, dstReason)
	}
	if srcSelector == "" {
		srcSelector = "any"
	}
	if dstSelector == "" {
		dstSelector = "any"
	}

	sourcePort := firewallPortSelector(rule.SrcPortsRaw, rule.SrcPortObj)
	destPort := firewallPortSelector(rule.DstPortsRaw, rule.DstPortObj)

	var b strings.Builder
	b.WriteString(rule.Action)
	b.WriteString(" ")
	b.WriteString(pfDir)
	if rule.Log {
		// log (all) — plain `log` only records the state-establishing packet.
		b.WriteString(" log (all)")
	}
	if rule.Quick {
		b.WriteString(" quick")
	}
	b.WriteString(" on ")
	b.WriteString(tap)
	if family == "inet" || family == "inet6" {
		b.WriteString(" ")
		b.WriteString(family)
	}
	b.WriteString(pfTrafficProtoClause(rule.Protocol))
	b.WriteString(" from ")
	b.WriteString(srcSelector)
	if sourcePort != "" {
		b.WriteString(" port ")
		b.WriteString(sourcePort)
	}
	b.WriteString(" to ")
	b.WriteString(dstSelector)
	if destPort != "" {
		b.WriteString(" port ")
		b.WriteString(destPort)
	}
	if strings.EqualFold(rule.Action, "pass") {
		b.WriteString(" keep state")
	}
	b.WriteString(fmt.Sprintf(" label \"sylve_vm_%d_trf_%d\"", rid, rule.ID))
	b.WriteString("\n")
	return b.String()
}
