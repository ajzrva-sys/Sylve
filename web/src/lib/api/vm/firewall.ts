import { APIResponseSchema, type APIResponse } from '$lib/types/common';
import {
	VMFirewallRuleCounterSchema,
	VMFirewallRuleSchema,
	VMFirewallSettingsSchema,
	type VMFirewallRule,
	type VMFirewallRuleCounter,
	type VMFirewallSettings
} from '$lib/types/network/vm_firewall';
import { apiRequest, isAPIResponse } from '$lib/utils/http';
import z from 'zod/v4';

export interface VMFirewallSettingsUpsertRequest {
	enabled?: boolean;
	defaultInbound?: 'pass' | 'block';
	defaultOutbound?: 'pass' | 'block';
	logDefault?: boolean;
	allowDhcp?: boolean;
	allowNdp?: boolean;
	allowPing?: boolean;
}

export interface VMFirewallRuleUpsertRequest {
	name: string;
	description?: string;
	enabled?: boolean;
	log?: boolean;
	quick?: boolean;
	priority?: number;
	action: 'pass' | 'block';
	direction: 'in' | 'out';
	protocol?: 'any' | 'tcp' | 'udp' | 'icmp' | 'ipv6-icmp';
	family?: 'any' | 'inet' | 'inet6';
	networkId?: number | null;
	sourceRaw?: string;
	sourceObjId?: number | null;
	destRaw?: string;
	destObjId?: number | null;
	srcPortsRaw?: string;
	srcPortObjId?: number | null;
	dstPortsRaw?: string;
	dstPortObjId?: number | null;
}

export async function getVMFirewallSettings(
	rid: number,
	opts?: { hostname?: string }
): Promise<APIResponse<VMFirewallSettings>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall`,
		APIResponseSchema(VMFirewallSettingsSchema),
		'GET',
		undefined,
		opts
	);
	return res as APIResponse<VMFirewallSettings>;
}

export async function updateVMFirewallSettings(
	rid: number,
	payload: VMFirewallSettingsUpsertRequest,
	opts?: { hostname?: string }
): Promise<APIResponse<VMFirewallSettings>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall`,
		APIResponseSchema(VMFirewallSettingsSchema),
		'PUT',
		payload,
		opts
	);
	return res as APIResponse<VMFirewallSettings>;
}

export async function getVMFirewallRules(
	rid: number,
	opts?: { hostname?: string }
): Promise<APIResponse<VMFirewallRule[]>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall/traffic`,
		APIResponseSchema(z.array(VMFirewallRuleSchema)),
		'GET',
		undefined,
		opts
	);
	return res as APIResponse<VMFirewallRule[]>;
}

export async function createVMFirewallRule(
	rid: number,
	payload: VMFirewallRuleUpsertRequest,
	opts?: { hostname?: string }
): Promise<APIResponse<number>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall/traffic`,
		APIResponseSchema(z.number()),
		'POST',
		payload,
		opts
	);
	return res as APIResponse<number>;
}

export async function updateVMFirewallRule(
	rid: number,
	ruleId: number,
	payload: VMFirewallRuleUpsertRequest,
	opts?: { hostname?: string }
): Promise<APIResponse<VMFirewallRule>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall/traffic/${ruleId}`,
		APIResponseSchema(VMFirewallRuleSchema),
		'PUT',
		payload,
		opts
	);
	return res as APIResponse<VMFirewallRule>;
}

export async function deleteVMFirewallRule(
	rid: number,
	ruleId: number,
	opts?: { hostname?: string }
): Promise<APIResponse<null>> {
	const res = await apiRequest(
		`/vm/${rid}/firewall/traffic/${ruleId}`,
		APIResponseSchema(z.null()),
		'DELETE',
		undefined,
		opts
	);
	return res as APIResponse<null>;
}

export async function getVMFirewallRuleCounters(
	rid: number,
	opts?: { hostname?: string }
): Promise<APIResponse<VMFirewallRuleCounter[]>> {
	const raw = await apiRequest(
		`/vm/${rid}/firewall/traffic/counters`,
		z.any(),
		'GET',
		undefined,
		opts
	);
	if (isAPIResponse(raw)) {
		const parsed = z.array(VMFirewallRuleCounterSchema).safeParse(raw.data);
		return {
			status: raw.status,
			message: raw.message,
			error: raw.error,
			data: parsed.success ? parsed.data : []
		} as APIResponse<VMFirewallRuleCounter[]>;
	}
	return raw as APIResponse<VMFirewallRuleCounter[]>;
}
