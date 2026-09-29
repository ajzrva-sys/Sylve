// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package networkHandlers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/alchemillahq/sylve/internal"
	networkServiceInterfaces "github.com/alchemillahq/sylve/internal/interfaces/services/network"
	"github.com/alchemillahq/sylve/internal/logger"
	"github.com/alchemillahq/sylve/internal/services/network"
	"github.com/alchemillahq/sylve/pkg/utils"
	"github.com/gin-gonic/gin"
)

func bindVMFirewallJSON(c *gin.Context, destination any) bool {
	if err := c.ShouldBindJSON(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			c.JSON(http.StatusRequestEntityTooLarge, internal.APIResponse[any]{
				Status:  "error",
				Message: "vm_firewall_request_too_large",
				Error:   "vm_firewall_request_too_large",
				Data:    nil,
			})
			return false
		}
		c.JSON(http.StatusBadRequest, internal.APIResponse[any]{
			Status:  "error",
			Message: "invalid_request",
			Error:   "invalid_vm_firewall_request",
			Data:    nil,
		})
		return false
	}
	return true
}

func vmFirewallRID(c *gin.Context) (uint, bool) {
	rid, err := utils.ParamUint(c, "rid")
	if err != nil || rid == 0 {
		c.JSON(http.StatusBadRequest, internal.APIResponse[any]{
			Status:  "error",
			Message: "invalid_rid",
			Error:   "invalid_vm_rid",
			Data:    nil,
		})
		return 0, false
	}
	return rid, true
}

func vmFirewallRulePathID(c *gin.Context) (uint, bool) {
	id, err := strconv.ParseUint(c.Param("id"), 10, strconv.IntSize)
	if err != nil || id == 0 {
		c.JSON(http.StatusBadRequest, internal.APIResponse[any]{
			Status:  "error",
			Message: "invalid_id",
			Error:   "invalid_vm_firewall_rule_id",
			Data:    nil,
		})
		return 0, false
	}
	return uint(id), true
}

func writeVMFirewallError(c *gin.Context, message string, fallbackCode string, err error) {
	logger.L.Error().Err(err).Str("operation", message).Msg("vm_firewall_request_failed")
	status := http.StatusInternalServerError
	code := fallbackCode
	if errors.Is(err, network.ErrInvalidFirewallTrafficRule) {
		status = http.StatusBadRequest
		code = "invalid_vm_firewall_rule"
	}
	c.JSON(status, internal.APIResponse[any]{
		Status:  "error",
		Message: message,
		Error:   code,
		Data:    nil,
	})
}

// @Summary Get VM Firewall Settings
// @Description Get the per-VM firewall settings (creates a disabled default if absent)
// @Tags VM
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[vmModels.VMFirewallSettings] "Success"
// @Failure 404 {object} internal.APIResponse[any] "Not Found"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall [get]
func GetVMFirewallSettings(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		settings, err := svc.GetVMFirewallSettings(rid)
		if err != nil {
			writeVMFirewallError(c, "failed_to_get_vm_firewall_settings", "vm_firewall_settings_get_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[any]{
			Status:  "success",
			Message: "vm_firewall_settings_listed",
			Error:   "",
			Data:    settings,
		})
	}
}

// @Summary Update VM Firewall Settings
// @Description Update the per-VM firewall settings and re-render the anchor
// @Tags VM
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Param request body networkServiceInterfaces.UpsertVMFirewallSettingsRequest true "Update VM Firewall Settings Request"
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[any] "Success"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 404 {object} internal.APIResponse[any] "Not Found"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall [put]
func UpdateVMFirewallSettings(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		var req networkServiceInterfaces.UpsertVMFirewallSettingsRequest
		if !bindVMFirewallJSON(c, &req) {
			return
		}
		settings, err := svc.UpdateVMFirewallSettingsFromRequest(rid, &req)
		if err != nil {
			writeVMFirewallError(c, "failed_to_update_vm_firewall_settings", "vm_firewall_settings_update_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[any]{
			Status:  "success",
			Message: "vm_firewall_settings_updated",
			Error:   "",
			Data:    settings,
		})
	}
}

// @Summary List VM Firewall Rules
// @Description List per-VM firewall traffic rules ordered by priority
// @Tags VM
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[[]vmModels.VMFirewallRule] "Success"
// @Failure 404 {object} internal.APIResponse[any] "Not Found"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall/traffic [get]
func ListVMFirewallRules(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		rules, err := svc.ListVMFirewallRules(rid)
		if err != nil {
			writeVMFirewallError(c, "failed_to_list_vm_firewall_rules", "vm_firewall_rule_list_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[any]{
			Status:  "success",
			Message: "vm_firewall_rules_listed",
			Error:   "",
			Data:    rules,
		})
	}
}

// @Summary List VM Firewall Rule Counters
// @Description List cumulative packet and byte counters for VM firewall rules
// @Tags VM
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[[]networkServiceInterfaces.VMFirewallRuleCounter] "Success"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall/traffic/counters [get]
func ListVMFirewallRuleCounters(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		counters, err := svc.GetVMFirewallRuleCounters(rid)
		if err != nil {
			writeVMFirewallError(c, "failed_to_list_vm_firewall_rule_counters", "vm_firewall_rule_counter_list_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[[]networkServiceInterfaces.VMFirewallRuleCounter]{
			Status:  "success",
			Message: "vm_firewall_rule_counters_listed",
			Error:   "",
			Data:    counters,
		})
	}
}

// @Summary Create VM Firewall Rule
// @Description Create and apply a per-VM firewall traffic rule
// @Tags VM
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Param request body networkServiceInterfaces.UpsertVMFirewallRuleRequest true "Create VM Firewall Rule Request"
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 201 {object} internal.APIResponse[uint] "Created"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 413 {object} internal.APIResponse[any] "Payload Too Large"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall/traffic [post]
func CreateVMFirewallRule(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		var req networkServiceInterfaces.UpsertVMFirewallRuleRequest
		if !bindVMFirewallJSON(c, &req) {
			return
		}
		rule, err := svc.CreateVMFirewallRuleFromRequest(rid, &req)
		if err != nil {
			writeVMFirewallError(c, "failed_to_create_vm_firewall_rule", "vm_firewall_rule_create_failed", err)
			return
		}
		c.JSON(http.StatusCreated, internal.APIResponse[uint]{
			Status:  "success",
			Message: "vm_firewall_rule_created",
			Error:   "",
			Data:    rule.ID,
		})
	}
}

// @Summary Update VM Firewall Rule
// @Description Replace and apply an existing per-VM firewall traffic rule
// @Tags VM
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Param id path int true "Rule ID" minimum(1)
// @Param request body networkServiceInterfaces.UpsertVMFirewallRuleRequest true "Update VM Firewall Rule Request"
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[any] "Success"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 404 {object} internal.APIResponse[any] "Not Found"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall/traffic/{id} [put]
func EditVMFirewallRule(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		id, ok := vmFirewallRulePathID(c)
		if !ok {
			return
		}
		var req networkServiceInterfaces.UpsertVMFirewallRuleRequest
		if !bindVMFirewallJSON(c, &req) {
			return
		}
		rule, err := svc.UpdateVMFirewallRuleFromRequest(rid, id, &req)
		if err != nil {
			writeVMFirewallError(c, "failed_to_update_vm_firewall_rule", "vm_firewall_rule_update_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[any]{
			Status:  "success",
			Message: "vm_firewall_rule_updated",
			Error:   "",
			Data:    rule,
		})
	}
}

// @Summary Delete VM Firewall Rule
// @Description Delete a per-VM firewall traffic rule and re-render the anchor
// @Tags VM
// @Produce json
// @Security BearerAuth
// @Param rid path int true "Virtual Machine RID" minimum(1)
// @Param id path int true "Rule ID" minimum(1)
// @Failure 401 {object} internal.APIResponse[any] "Unauthorized"
// @Success 200 {object} internal.APIResponse[any] "Success"
// @Failure 400 {object} internal.APIResponse[any] "Bad Request"
// @Failure 404 {object} internal.APIResponse[any] "Not Found"
// @Failure 500 {object} internal.APIResponse[any] "Internal Server Error"
// @Router /vm/{rid}/firewall/traffic/{id} [delete]
func DeleteVMFirewallRule(svc *network.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		rid, ok := vmFirewallRID(c)
		if !ok {
			return
		}
		id, ok := vmFirewallRulePathID(c)
		if !ok {
			return
		}
		if err := svc.DeleteVMFirewallRule(rid, id); err != nil {
			writeVMFirewallError(c, "failed_to_delete_vm_firewall_rule", "vm_firewall_rule_delete_failed", err)
			return
		}
		c.JSON(http.StatusOK, internal.APIResponse[any]{
			Status:  "success",
			Message: "vm_firewall_rule_deleted",
			Error:   "",
			Data:    nil,
		})
	}
}
