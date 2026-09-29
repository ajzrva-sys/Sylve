import { getVMFirewallRules, getVMFirewallSettings } from '$lib/api/vm/firewall';
import { getVmByIdResult } from '$lib/api/vm/vm';
import { getSwitches } from '$lib/api/network/switch';
import { getNetworkObjects } from '$lib/api/network/object';
import type { APIResponse } from '$lib/types/common';
import { SEVEN_DAYS } from '$lib/utils.js';
import { cachedFetch, isAPIResponse } from '$lib/utils/http';
import { error } from '@sveltejs/kit';

export async function load({ params }) {
	const rid = Number(params.rid);
	const node = params.node;
	if (!Number.isSafeInteger(rid) || rid <= 0) {
		error(404, 'Invalid VM RID');
	}

	const [vmResult, settingsResult, rulesResult, switchesResult, objectsResult] = await Promise.all([
		cachedFetch(
			`vm-${rid}`,
			async () => getVmByIdResult(rid, { hostname: node }),
			SEVEN_DAYS,
			false,
			node
		),
		cachedFetch(
			`vm-fw-settings-${rid}`,
			async () => getVMFirewallSettings(rid, { hostname: node }),
			SEVEN_DAYS,
			false,
			node
		),
		cachedFetch(
			`vm-fw-rules-${rid}`,
			async () => getVMFirewallRules(rid, { hostname: node }),
			SEVEN_DAYS,
			false,
			node
		),
		cachedFetch(
			'network-switches',
			async () => await getSwitches(node),
			SEVEN_DAYS,
			false,
			node
		),
		cachedFetch(
			'network-objects',
			async () => await getNetworkObjects(node),
			SEVEN_DAYS,
			false,
			node
		)
	]);

	if (isAPIResponse(vmResult)) {
		const vmError = Array.isArray(vmResult.error) ? vmResult.error.join(', ') : vmResult.error;
		error(502, vmError || vmResult.message || 'Failed to load virtual machine');
	}

	const loadErrors = [settingsResult, rulesResult].filter(isAPIResponse) as APIResponse[];

	return {
		node,
		rid,
		vm: vmResult,
		settings: isAPIResponse(settingsResult) ? null : settingsResult,
		rules: isAPIResponse(rulesResult) ? [] : rulesResult,
		switches: isAPIResponse(switchesResult) ? null : switchesResult,
		networkObjects: isAPIResponse(objectsResult) ? [] : objectsResult,
		loadErrors
	};
}
