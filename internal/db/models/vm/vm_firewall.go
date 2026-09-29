// SPDX-License-Identifier: BSD-2-Clause
//
// Copyright (c) 2025 The FreeBSD Foundation.
//
// This software was developed by Hayzam Sherif <hayzam@alchemilla.io>
// of Alchemilla Ventures Pvt. Ltd. <hello@alchemilla.io>,
// under sponsorship from the FreeBSD Foundation.

package vmModels

import (
	"time"

	networkModels "github.com/alchemillahq/sylve/internal/db/models/network"
)

// VMFirewallSettings is the per-VM firewall policy (1:1 with VM).
// When Enabled is false the VM has no anchor and traffic is unfiltered.
type VMFirewallSettings struct {
	ID              uint      `json:"id" gorm:"primaryKey"`
	VMID            uint      `json:"vmId" gorm:"uniqueIndex;not null"`
	Enabled         bool      `json:"enabled" gorm:"not null;default:false"`
	DefaultInbound  string    `json:"defaultInbound" gorm:"not null;default:block"` // pass|block (guest inbound)
	DefaultOutbound string    `json:"defaultOutbound" gorm:"not null;default:pass"` // pass|block (guest outbound)
	LogDefault      bool      `json:"logDefault" gorm:"default:false"`
	AllowDHCP       bool      `json:"allowDhcp" gorm:"not null;default:true"`
	AllowNDP        bool      `json:"allowNdp" gorm:"not null;default:true"`
	AllowPing       bool      `json:"allowPing" gorm:"not null;default:false"`
	CreatedAt       time.Time `json:"createdAt"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

func (VMFirewallSettings) TableName() string {
	return "vm_firewall_settings"
}

// VMFirewallRule is a single per-VM filter rule.
// Direction is guest-centric: "in" = guest inbound (LAN→guest), "out" = guest
// outbound (guest→LAN). Rendering inverts to PF `out on tap` / `in on tap`.
type VMFirewallRule struct {
	ID          uint   `json:"id" gorm:"primaryKey"`
	VMID        uint   `json:"vmId" gorm:"index;not null"`
	NetworkID   *uint  `json:"networkId"` // null = all NICs
	Name        string `json:"name" gorm:"not null"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled" gorm:"default:true"`
	Log         bool   `json:"log" gorm:"default:false"`
	Quick       bool   `json:"quick" gorm:"not null;default:true"`
	Priority    int    `json:"priority" gorm:"index;default:1"`
	Action      string `json:"action" gorm:"not null;default:pass"`  // pass|block
	Direction   string `json:"direction" gorm:"not null;default:in"` // in|out (guest)
	Protocol    string `json:"protocol" gorm:"not null;default:any"` // any|tcp|udp|icmp|ipv6-icmp
	Family      string `json:"family" gorm:"not null;default:any"`   // any|inet|inet6

	SourceRaw    string                `json:"sourceRaw"`
	SourceObjID  *uint                 `json:"sourceObjId"`
	SourceObj    *networkModels.Object `json:"sourceObj"`
	DestRaw      string                `json:"destRaw"`
	DestObjID    *uint                 `json:"destObjId"`
	DestObj      *networkModels.Object `json:"destObj"`
	SrcPortsRaw  string                `json:"srcPortsRaw"`
	SrcPortObjID *uint                 `json:"srcPortObjId"`
	SrcPortObj   *networkModels.Object `json:"srcPortObj"`
	DstPortsRaw  string                `json:"dstPortsRaw"`
	DstPortObjID *uint                 `json:"dstPortObjId"`
	DstPortObj   *networkModels.Object `json:"dstPortObj"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func (VMFirewallRule) TableName() string {
	return "vm_firewall_rules"
}
