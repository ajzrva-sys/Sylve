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
	"strings"

	networkModels "github.com/alchemillahq/sylve/internal/db/models/network"
	vmModels "github.com/alchemillahq/sylve/internal/db/models/vm"
	networkServiceInterfaces "github.com/alchemillahq/sylve/internal/interfaces/services/network"
	"github.com/alchemillahq/sylve/internal/logger"
)

// GetVMFirewallSettings returns the firewall settings for a VM RID,
// creating a disabled default row if none exists.
func (s *Service) GetVMFirewallSettings(rid uint) (vmModels.VMFirewallSettings, error) {
	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return vmModels.VMFirewallSettings{}, fmt.Errorf("vm_not_found: %w", err)
	}
	var settings vmModels.VMFirewallSettings
	err := s.DB.Where("vm_id = ?", vm.ID).First(&settings).Error
	if err != nil {
		// Auto-create a disabled default.
		settings = vmModels.VMFirewallSettings{
			VMID:            vm.ID,
			Enabled:         false,
			DefaultInbound:  "block",
			DefaultOutbound: "pass",
			AllowDHCP:       true,
			AllowNDP:        true,
		}
		if createErr := s.DB.Create(&settings).Error; createErr != nil {
			return settings, fmt.Errorf("failed_to_create_vm_firewall_settings: %w", createErr)
		}
	}
	return settings, nil
}

// UpdateVMFirewallSettings upserts the settings and re-renders the anchor if
// the VM firewall is enabled.
func (s *Service) UpdateVMFirewallSettings(rid uint, patch vmModels.VMFirewallSettings) (vmModels.VMFirewallSettings, error) {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()

	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return vmModels.VMFirewallSettings{}, fmt.Errorf("vm_not_found: %w", err)
	}

	settings, err := s.GetVMFirewallSettings(rid)
	if err != nil {
		return settings, err
	}

	settings.Enabled = patch.Enabled
	settings.DefaultInbound = normalizeVMPolicy(patch.DefaultInbound, "block")
	settings.DefaultOutbound = normalizeVMPolicy(patch.DefaultOutbound, "pass")
	settings.LogDefault = patch.LogDefault
	settings.AllowDHCP = patch.AllowDHCP
	settings.AllowNDP = patch.AllowNDP
	settings.AllowPing = patch.AllowPing

	if err := s.DB.Save(&settings).Error; err != nil {
		return settings, fmt.Errorf("failed_to_save_vm_firewall_settings: %w", err)
	}

	if err := s.applyVMFirewallLocked(rid, vm.ID); err != nil {
		return settings, err
	}
	return settings, nil
}

// ListVMFirewallRules returns rules for a VM RID ordered by priority.
func (s *Service) ListVMFirewallRules(rid uint) ([]vmModels.VMFirewallRule, error) {
	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return nil, fmt.Errorf("vm_not_found: %w", err)
	}
	var rules []vmModels.VMFirewallRule
	if err := s.DB.
		Preload("SourceObj.Entries").
		Preload("DestObj.Entries").
		Preload("SrcPortObj.Entries").
		Preload("DstPortObj.Entries").
		Where("vm_id = ?", vm.ID).Order("priority ASC, id ASC").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("failed_to_list_vm_firewall_rules: %w", err)
	}
	return rules, nil
}

// CreateVMFirewallRule adds a rule and re-renders the anchor.
func (s *Service) CreateVMFirewallRule(rid uint, rule vmModels.VMFirewallRule) (vmModels.VMFirewallRule, error) {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()

	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return rule, fmt.Errorf("vm_not_found: %w", err)
	}
	rule.VMID = vm.ID
	rule.Action = normalizeVMAction(rule.Action)
	rule.Direction = normalizeVMDirection(rule.Direction)
	if err := s.DB.Create(&rule).Error; err != nil {
		return rule, fmt.Errorf("failed_to_create_vm_firewall_rule: %w", err)
	}
	if err := s.applyVMFirewallLocked(rid, vm.ID); err != nil {
		return rule, err
	}
	return rule, nil
}

// UpdateVMFirewallRule updates a rule and re-renders the anchor.
func (s *Service) UpdateVMFirewallRule(rid uint, ruleID uint, patch vmModels.VMFirewallRule) (vmModels.VMFirewallRule, error) {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()

	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return patch, fmt.Errorf("vm_not_found: %w", err)
	}
	var rule vmModels.VMFirewallRule
	if err := s.DB.Where("id = ? AND vm_id = ?", ruleID, vm.ID).First(&rule).Error; err != nil {
		return rule, fmt.Errorf("rule_not_found: %w", err)
	}

	rule.Name = patch.Name
	rule.Description = patch.Description
	rule.Enabled = patch.Enabled
	rule.Log = patch.Log
	rule.Quick = patch.Quick
	rule.Priority = patch.Priority
	rule.Action = normalizeVMAction(patch.Action)
	rule.Direction = normalizeVMDirection(patch.Direction)
	rule.Protocol = patch.Protocol
	rule.Family = patch.Family
	rule.SourceRaw = patch.SourceRaw
	rule.SourceObjID = patch.SourceObjID
	rule.DestRaw = patch.DestRaw
	rule.DestObjID = patch.DestObjID
	rule.SrcPortsRaw = patch.SrcPortsRaw
	rule.SrcPortObjID = patch.SrcPortObjID
	rule.DstPortsRaw = patch.DstPortsRaw
	rule.DstPortObjID = patch.DstPortObjID
	rule.NetworkID = patch.NetworkID

	if err := s.DB.Save(&rule).Error; err != nil {
		return rule, fmt.Errorf("failed_to_update_vm_firewall_rule: %w", err)
	}
	if err := s.applyVMFirewallLocked(rid, vm.ID); err != nil {
		return rule, err
	}
	return rule, nil
}

// DeleteVMFirewallRule removes a rule and re-renders the anchor.
func (s *Service) DeleteVMFirewallRule(rid uint, ruleID uint) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()

	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return fmt.Errorf("vm_not_found: %w", err)
	}
	if err := s.DB.Where("id = ? AND vm_id = ?", ruleID, vm.ID).Delete(&vmModels.VMFirewallRule{}).Error; err != nil {
		return fmt.Errorf("failed_to_delete_vm_firewall_rule: %w", err)
	}
	return s.applyVMFirewallLocked(rid, vm.ID)
}

// ApplyVMFirewall renders and loads the anchor for a VM (call at start).
func (s *Service) ApplyVMFirewall(rid uint) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()
	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return fmt.Errorf("vm_not_found: %w", err)
	}
	return s.applyVMFirewallLocked(rid, vm.ID)
}

// DisableVMFirewall flushes the anchor and disables settings (call at stop).
func (s *Service) DisableVMFirewall(rid uint) error {
	vmFirewallMutex.Lock()
	defer vmFirewallMutex.Unlock()
	return s.flushVMAnchorLocked(rid)
}

func (s *Service) applyVMFirewallLocked(rid uint, vmID uint) error {
	var settings vmModels.VMFirewallSettings
	if err := s.DB.Where("vm_id = ?", vmID).First(&settings).Error; err != nil {
		// No settings row = disabled; ensure anchor is empty.
		return s.flushVMAnchorLocked(rid)
	}
	if !settings.Enabled {
		return s.flushVMAnchorLocked(rid)
	}

	var rules []vmModels.VMFirewallRule
	if err := s.DB.
		Preload("SourceObj.Entries").
		Preload("DestObj.Entries").
		Preload("SrcPortObj.Entries").
		Preload("DstPortObj.Entries").
		Where("vm_id = ?", vmID).Order("priority ASC, id ASC").Find(&rules).Error; err != nil {
		return fmt.Errorf("failed_to_list_vm_firewall_rules: %w", err)
	}

	tapNames := s.tapNamesForVMWithRID(rid, vmID)
	if len(tapNames) == 0 {
		return fmt.Errorf("vm_has_no_enabled_networks: %d", rid)
	}

	objectTables, err := s.buildVMFirewallObjectTables(rules)
	if err != nil {
		return err
	}
	if err := writeFirewallObjectTableEntriesOnly(objectTables, pfObjectTableEntriesDir); err != nil {
		return err
	}
	if err := s.loadFirewallObjectTableEntries(objectTables); err != nil {
		return err
	}

	body := RenderVMFirewallRules(rid, settings, rules, tapNames, objectTables)
	if err := s.ValidateVMAnchor(rid, body); err != nil {
		return err
	}
	if err := s.loadVMAnchorLocked(rid, body); err != nil {
		return err
	}
	s.updateFirewallRuleNames()
	s.sampleVMRuleNumbersLocked()
	logger.L.Info().Uint("rid", rid).Int("rules", len(rules)).Msg("applied VM firewall anchor")
	return nil
}

// buildVMFirewallObjectTables builds PF address-object tables for VM rules'
// SourceObj/DestObj references (port objects are inlined, not tabular).
func (s *Service) buildVMFirewallObjectTables(rules []vmModels.VMFirewallRule) (map[uint]firewallObjectTable, error) {
	objects := make(map[uint]*networkModels.Object)
	addObject := func(obj *networkModels.Object) {
		if obj == nil || obj.ID == 0 {
			return
		}
		if _, exists := objects[obj.ID]; exists {
			return
		}
		objects[obj.ID] = obj
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		addObject(rule.SourceObj)
		addObject(rule.DestObj)
	}
	if len(objects) == 0 {
		return map[uint]firewallObjectTable{}, nil
	}

	dynamicValuesByObject, err := s.loadDynamicValuesForObjects(objects)
	if err != nil {
		return nil, err
	}
	for objectID, values := range dynamicValuesByObject {
		obj := objects[objectID]
		if obj == nil || len(values) == 0 {
			continue
		}
		obj.Resolutions = make([]networkModels.ObjectResolution, 0, len(values))
		for _, value := range values {
			obj.Resolutions = append(obj.Resolutions, networkModels.ObjectResolution{
				ObjectID:      objectID,
				ResolvedValue: value,
			})
		}
	}

	// Reuse the shared table builder so table naming stays identical to host rules.
	return buildFirewallObjectTables(nil, nil, rules), nil
}

// tapNamesForVMWithRID returns networkID → tap name for every enabled NIC.
func (s *Service) tapNamesForVMWithRID(rid uint, vmID uint) map[uint]string {
	var networks []vmModels.Network
	if err := s.DB.Where("vm_id = ? AND enable = ?", vmID, true).
		Order("id ASC").Find(&networks).Error; err != nil {
		return nil
	}
	out := make(map[uint]string, len(networks))
	for _, n := range networks {
		out[n.ID] = VMTapName(rid, n.ID)
	}
	return out
}

func normalizeVMAction(a string) string {
	a = strings.ToLower(strings.TrimSpace(a))
	if a == "block" {
		return "block"
	}
	return "pass"
}

func normalizeVMDirection(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "out" {
		return "out"
	}
	return "in"
}

func normalizeVMPolicy(p string, fallback string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "pass" || p == "block" {
		return p
	}
	return fallback
}

// --- DTO-accepting wrappers for the HTTP layer ---

func (s *Service) UpdateVMFirewallSettingsFromRequest(rid uint, req *networkServiceInterfaces.UpsertVMFirewallSettingsRequest) (vmModels.VMFirewallSettings, error) {
	current, err := s.GetVMFirewallSettings(rid)
	if err != nil {
		return current, err
	}
	patch := current
	if req.Enabled != nil {
		patch.Enabled = *req.Enabled
	}
	if req.DefaultInbound != "" {
		patch.DefaultInbound = normalizeVMPolicy(req.DefaultInbound, "block")
	}
	if req.DefaultOutbound != "" {
		patch.DefaultOutbound = normalizeVMPolicy(req.DefaultOutbound, "pass")
	}
	if req.LogDefault != nil {
		patch.LogDefault = *req.LogDefault
	}
	if req.AllowDHCP != nil {
		patch.AllowDHCP = *req.AllowDHCP
	}
	if req.AllowNDP != nil {
		patch.AllowNDP = *req.AllowNDP
	}
	if req.AllowPing != nil {
		patch.AllowPing = *req.AllowPing
	}
	return s.UpdateVMFirewallSettings(rid, patch)
}

func validateVMFirewallRuleSelectors(req *networkServiceInterfaces.UpsertVMFirewallRuleRequest) error {
	selectors := []struct {
		raw      string
		objectID *uint
		field    string
	}{
		{raw: req.SourceRaw, objectID: req.SourceObjID, field: "source"},
		{raw: req.DestRaw, objectID: req.DestObjID, field: "destination"},
		{raw: req.SrcPortsRaw, objectID: req.SrcPortObjID, field: "source_port"},
		{raw: req.DstPortsRaw, objectID: req.DstPortObjID, field: "destination_port"},
	}
	for _, selector := range selectors {
		if err := validateFirewallTrafficSelectorPair(selector.raw, selector.objectID, selector.field); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) validateVMFirewallRuleObjectRefs(req *networkServiceInterfaces.UpsertVMFirewallRuleRequest) error {
	if err := validateVMFirewallRuleSelectors(req); err != nil {
		return err
	}
	if err := s.validateFirewallTrafficAddressObjectRef(req.SourceObjID, "source"); err != nil {
		return err
	}
	if err := s.validateFirewallTrafficAddressObjectRef(req.DestObjID, "destination"); err != nil {
		return err
	}
	if err := s.validateFirewallTrafficPortObjectRef(req.SrcPortObjID, "source_port"); err != nil {
		return err
	}
	return s.validateFirewallTrafficPortObjectRef(req.DstPortObjID, "destination_port")
}

func (s *Service) CreateVMFirewallRuleFromRequest(rid uint, req *networkServiceInterfaces.UpsertVMFirewallRuleRequest) (vmModels.VMFirewallRule, error) {
	if err := s.validateVMFirewallRuleObjectRefs(req); err != nil {
		return vmModels.VMFirewallRule{}, err
	}
	rule := vmModels.VMFirewallRule{
		Name:         req.Name,
		Description:  req.Description,
		Enabled:      true,
		Quick:        true,
		Priority:     1,
		Action:       normalizeVMAction(req.Action),
		Direction:    normalizeVMDirection(req.Direction),
		Protocol:     req.Protocol,
		Family:       req.Family,
		NetworkID:    req.NetworkID,
		SourceRaw:    req.SourceRaw,
		SourceObjID:  req.SourceObjID,
		DestRaw:      req.DestRaw,
		DestObjID:    req.DestObjID,
		SrcPortsRaw:  req.SrcPortsRaw,
		SrcPortObjID: req.SrcPortObjID,
		DstPortsRaw:  req.DstPortsRaw,
		DstPortObjID: req.DstPortObjID,
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Log != nil {
		rule.Log = *req.Log
	}
	if req.Quick != nil {
		rule.Quick = *req.Quick
	}
	if req.Priority != nil {
		rule.Priority = *req.Priority
	}
	if rule.Protocol == "" {
		rule.Protocol = "any"
	}
	if rule.Family == "" {
		rule.Family = "any"
	}
	return s.CreateVMFirewallRule(rid, rule)
}

func (s *Service) UpdateVMFirewallRuleFromRequest(rid uint, ruleID uint, req *networkServiceInterfaces.UpsertVMFirewallRuleRequest) (vmModels.VMFirewallRule, error) {
	if err := s.validateVMFirewallRuleObjectRefs(req); err != nil {
		return vmModels.VMFirewallRule{}, err
	}
	patch := vmModels.VMFirewallRule{
		Name:         req.Name,
		Description:  req.Description,
		Enabled:      true,
		Quick:        true,
		Priority:     1,
		Action:       normalizeVMAction(req.Action),
		Direction:    normalizeVMDirection(req.Direction),
		Protocol:     req.Protocol,
		Family:       req.Family,
		NetworkID:    req.NetworkID,
		SourceRaw:    req.SourceRaw,
		SourceObjID:  req.SourceObjID,
		DestRaw:      req.DestRaw,
		DestObjID:    req.DestObjID,
		SrcPortsRaw:  req.SrcPortsRaw,
		SrcPortObjID: req.SrcPortObjID,
		DstPortsRaw:  req.DstPortsRaw,
		DstPortObjID: req.DstPortObjID,
	}
	if req.Enabled != nil {
		patch.Enabled = *req.Enabled
	}
	if req.Log != nil {
		patch.Log = *req.Log
	}
	if req.Quick != nil {
		patch.Quick = *req.Quick
	}
	if req.Priority != nil {
		patch.Priority = *req.Priority
	}
	if patch.Protocol == "" {
		patch.Protocol = "any"
	}
	if patch.Family == "" {
		patch.Family = "any"
	}
	return s.UpdateVMFirewallRule(rid, ruleID, patch)
}

// GetVMFirewallRuleCounters returns per-rule counters from the VM's PF anchor.
func (s *Service) GetVMFirewallRuleCounters(rid uint) ([]networkServiceInterfaces.VMFirewallRuleCounter, error) {
	totals := collectVMCountersFromPF([]uint{rid})
	var rules []vmModels.VMFirewallRule
	var vm vmModels.VM
	if err := s.DB.Where("rid = ?", rid).First(&vm).Error; err != nil {
		return nil, fmt.Errorf("vm_not_found: %w", err)
	}
	if err := s.DB.Where("vm_id = ?", vm.ID).Order("id ASC").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("failed_to_list_vm_firewall_rules: %w", err)
	}
	out := make([]networkServiceInterfaces.VMFirewallRuleCounter, 0, len(rules))
	for _, rule := range rules {
		c := networkServiceInterfaces.VMFirewallRuleCounter{ID: rule.ID}
		if t, ok := totals[vmRuleKey{RID: rid, RuleID: rule.ID}]; ok {
			c.Packets = t.Packets
			c.Bytes = t.Bytes
			c.UpdatedAt = t.UpdatedAt
		}
		out = append(out, c)
	}
	return out, nil
}
