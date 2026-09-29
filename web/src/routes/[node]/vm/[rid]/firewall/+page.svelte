<script lang="ts">
	import {
		createVMFirewallRule,
		deleteVMFirewallRule,
		getVMFirewallRuleCounters,
		getVMFirewallRules,
		getVMFirewallSettings,
		updateVMFirewallRule,
		updateVMFirewallSettings,
		type VMFirewallRuleUpsertRequest,
		type VMFirewallSettingsUpsertRequest
	} from '$lib/api/vm/firewall';
	import AlertDialog from '$lib/components/custom/Dialog/Alert.svelte';
	import Form from '$lib/components/custom/Network/Firewall/VM/Traffic/Form.svelte';
	import SpanWithIcon from '$lib/components/custom/SpanWithIcon.svelte';
	import TreeTable from '$lib/components/custom/TreeTable.svelte';
	import Search from '$lib/components/custom/TreeTable/Search.svelte';
	import Button from '$lib/components/ui/button/button.svelte';
	import * as Select from '$lib/components/ui/select';
	import { Switch } from '$lib/components/ui/switch';
	import type { APIResponse } from '$lib/types/common';
	import type { Column, Row } from '$lib/types/components/tree-table';
	import type {
		VMFirewallRule,
		VMFirewallRuleCounter,
		VMFirewallSettings
	} from '$lib/types/network/vm_firewall';
	import type { SwitchList } from '$lib/types/network/switch';
	import type { NetworkObject } from '$lib/types/network/object';
	import { formatBytesBinary } from '$lib/utils/bytes';
	import { convertDbTime } from '$lib/utils/time';
	import { handleAPIError, updateCache } from '$lib/utils/http';
	import { renderWithIcon } from '$lib/utils/table';
	import { onMount } from 'svelte';
	import type { CellComponent, RowComponent } from 'tabulator-tables';
	import { resource } from 'runed';
	import { toast } from 'svelte-sonner';

	interface Data {
		node: string;
		rid: number;
		vm: any;
		settings: VMFirewallSettings | null;
		rules: VMFirewallRule[] | APIResponse;
		switches: SwitchList | null;
		networkObjects: NetworkObject[];
		loadErrors: APIResponse[];
	}

	let { data }: { data: Data } = $props();

	let lastGoodRules = Array.isArray(data.rules) ? data.rules : ([] as VMFirewallRule[]);
	let lastGoodSettings = data.settings;

	const rulesResource = resource(
		() => `vm-fw-rules-${data.rid}`,
		async (key) => {
			const result = await getVMFirewallRules(data.rid, { hostname: data.node });
			if (!Array.isArray(result)) {
				handleAPIError(result);
				return lastGoodRules;
			}
			lastGoodRules = result;
			updateCache(key, result);
			return result;
		},
		{ initialValue: lastGoodRules }
	);

	const rules = $derived(
		Array.isArray(rulesResource.current) ? (rulesResource.current as VMFirewallRule[]) : []
	);

	let settings = $state<VMFirewallSettings>(
		lastGoodSettings ?? {
			id: 0,
			vmId: 0,
			enabled: false,
			defaultInbound: 'block',
			defaultOutbound: 'pass',
			logDefault: false,
			allowDhcp: true,
			allowNdp: true,
			allowPing: false
		}
	);

	const settingsResource = resource(
		() => `vm-fw-settings-${data.rid}`,
		async (key) => {
			const result = await getVMFirewallSettings(data.rid, { hostname: data.node });
			if (result && 'data' in result && result.data) {
				settings = result.data as VMFirewallSettings;
				updateCache(key, result.data);
			} else if (result && 'id' in result) {
				settings = result as VMFirewallSettings;
				updateCache(key, result);
			}
			return settings;
		},
		{ initialValue: settings }
	);

	let counters = $state<VMFirewallRuleCounter[]>([]);
	let showForm = $state(false);
	let editRule = $state<VMFirewallRule | null>(null);
	let deleteTarget = $state<VMFirewallRule | null>(null);
	let searchTerm = $state('');

	async function refreshSettings() {
		const result = await getVMFirewallSettings(data.rid, { hostname: data.node });
		if (result && 'data' in result && result.data) {
			settings = result.data as VMFirewallSettings;
		} else if (result && 'id' in result) {
			settings = result as VMFirewallSettings;
		}
	}

	async function refreshRules() {
		const result = await getVMFirewallRules(data.rid, { hostname: data.node });
		if (Array.isArray(result)) {
			lastGoodRules = result;
			updateCache(`vm-fw-rules-${data.rid}`, result);
			rulesResource.current = result;
		}
	}

	async function refreshCounters() {
		const result = await getVMFirewallRuleCounters(data.rid, { hostname: data.node });
		if (result && 'data' in result && Array.isArray(result.data)) {
			counters = result.data;
		}
	}

	async function saveSettings(patch: VMFirewallSettingsUpsertRequest) {
		const result = await updateVMFirewallSettings(data.rid, patch, { hostname: data.node });
		if (result && 'data' in result && result.data) {
			settings = result.data as VMFirewallSettings;
			toast.success('Firewall settings updated');
		} else {
			handleAPIError(result as APIResponse);
		}
	}

	async function handleDelete(rule: VMFirewallRule) {
		const result = await deleteVMFirewallRule(data.rid, rule.id, { hostname: data.node });
		if (result && result.status === 'success') {
			toast.success('Rule deleted');
			await refreshRules();
		} else {
			handleAPIError(result as APIResponse);
		}
		deleteTarget = null;
	}

	function directionLabel(dir: string): { text: string; icon: string; color: string } {
		if (dir === 'in') {
			return { text: 'To Guest', icon: 'mdi:arrow-down-circle-outline', color: 'text-blue-500' };
		}
		return { text: 'From Guest', icon: 'mdi:arrow-up-circle-outline', color: 'text-orange-500' };
	}

	function objectName(id: number | null | undefined): string | null {
		if (id == null) return null;
		return data.networkObjects?.find((o) => o.id === id)?.name ?? `object#${id}`;
	}

	function selectorLabel(
		raw: string | null | undefined,
		objId: number | null | undefined
	): string {
		const name = objectName(objId);
		if (name) return name;
		return raw || 'any';
	}

	const filteredRules = $derived(
		searchTerm
			? rules.filter(
					(r) =>
						r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
						(r.description || '').toLowerCase().includes(searchTerm.toLowerCase())
				)
			: rules
	);

	onMount(() => {
		refreshCounters();
		const interval = setInterval(() => {
			if (document.visibilityState === 'visible') {
				refreshCounters();
			}
		}, 5000);
		return () => clearInterval(interval);
	});
</script>

<div class="flex h-full flex-col gap-4 p-4">
	<div class="flex items-center justify-between">
		<h2 class="text-lg font-semibold">VM Firewall</h2>
		<div class="flex items-center gap-2">
			<Button onclick={() => { editRule = null; showForm = true; }} variant="default" size="sm">
				New Rule
			</Button>
		</div>
	</div>

	<!-- Settings panel -->
	<div class="rounded-lg border p-4">
		<div class="flex items-center gap-4">
			<div class="flex items-center gap-2">
				<Switch
					checked={settings.enabled}
					onCheckedChange={(v) => saveSettings({ enabled: v })}
				/>
				<span class="text-sm font-medium">Firewall Enabled</span>
			</div>
			<div class="flex items-center gap-2">
				<span class="text-sm">Default Inbound:</span>
				<Select.Root
					type="single"
					value={settings.defaultInbound}
					onValueChange={(v) => saveSettings({ defaultInbound: v as 'pass' | 'block' })}
				>
					<Select.Trigger class="w-24">
						{settings.defaultInbound === 'block' ? 'Block' : 'Pass'}
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="block">Block</Select.Item>
						<Select.Item value="pass">Pass</Select.Item>
					</Select.Content>
				</Select.Root>
			</div>
			<div class="flex items-center gap-2">
				<span class="text-sm">Default Outbound:</span>
				<Select.Root
					type="single"
					value={settings.defaultOutbound}
					onValueChange={(v) => saveSettings({ defaultOutbound: v as 'pass' | 'block' })}
				>
					<Select.Trigger class="w-24">
						{settings.defaultOutbound === 'pass' ? 'Pass' : 'Block'}
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="pass">Pass</Select.Item>
						<Select.Item value="block">Block</Select.Item>
					</Select.Content>
				</Select.Root>
			</div>
			<div class="flex items-center gap-2">
				<Switch
					checked={settings.allowDhcp}
					onCheckedChange={(v) => saveSettings({ allowDhcp: v })}
				/>
				<span class="text-sm">DHCP</span>
			</div>
			<div class="flex items-center gap-2">
				<Switch
					checked={settings.allowNdp}
					onCheckedChange={(v) => saveSettings({ allowNdp: v })}
				/>
				<span class="text-sm">NDP</span>
			</div>
			<div class="flex items-center gap-2">
				<Switch
					checked={settings.allowPing}
					onCheckedChange={(v) => saveSettings({ allowPing: v })}
				/>
				<span class="text-sm">Ping</span>
			</div>
		</div>
	</div>

	<!-- Rules table -->
	<div class="flex items-center gap-2">
		<Search bind:value={searchTerm} placeholder="Search rules..." />
	</div>

	<div class="flex-1 overflow-auto rounded-lg border">
		<table class="w-full text-sm">
			<thead>
				<tr class="border-b bg-muted/50">
					<th class="p-2 text-left">Enabled</th>
					<th class="p-2 text-left">Priority</th>
					<th class="p-2 text-left">Action</th>
					<th class="p-2 text-left">Direction</th>
					<th class="p-2 text-left">Name</th>
					<th class="p-2 text-left">Protocol</th>
					<th class="p-2 text-left">Source</th>
					<th class="p-2 text-left">Destination</th>
					<th class="p-2 text-left">Hits</th>
					<th class="p-2 text-left">Bytes</th>
					<th class="p-2 text-left">Actions</th>
				</tr>
			</thead>
			<tbody>
				{#each filteredRules as rule (rule.id)}
					{@const dir = directionLabel(rule.direction)}
					{@const counter = counters.find((c) => c.id === rule.id)}
					<tr class="border-b hover:bg-muted/30">
						<td class="p-2">
							{#if rule.enabled}
								<span class="text-green-500">●</span>
							{:else}
								<span class="text-gray-400">○</span>
							{/if}
						</td>
						<td class="p-2">{rule.priority}</td>
						<td class="p-2">
							<span class={rule.action === 'pass' ? 'text-green-600' : 'text-red-600'}>
								{rule.action === 'pass' ? 'Pass' : 'Block'}
							</span>
						</td>
						<td class="p-2">
							<span class="flex items-center gap-1 {dir.color}">
								<span>{dir.text}</span>
							</span>
						</td>
						<td class="p-2">{rule.name}</td>
						<td class="p-2">{rule.protocol}</td>
						<td class="p-2">{selectorLabel(rule.sourceRaw, rule.sourceObjId)}{rule.srcPortsRaw || rule.srcPortObjId ? ' :' + selectorLabel(rule.srcPortsRaw, rule.srcPortObjId) : ''}</td>
						<td class="p-2">{selectorLabel(rule.destRaw, rule.destObjId)}{rule.dstPortsRaw || rule.dstPortObjId ? ' :' + selectorLabel(rule.dstPortsRaw, rule.dstPortObjId) : ''}</td>
						<td class="p-2">{counter?.packets ?? 0}</td>
						<td class="p-2">{formatBytesBinary(counter?.bytes ?? 0)}</td>
						<td class="p-2">
							<div class="flex gap-1">
								<Button
									variant="ghost"
									size="sm"
									onclick={() => { editRule = rule; showForm = true; }}
								>
									Edit
								</Button>
								<Button
									variant="ghost"
									size="sm"
									class="text-red-500"
									onclick={() => (deleteTarget = rule)}
								>
									Delete
								</Button>
							</div>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
</div>

{#if showForm}
	<Form
		rid={data.rid}
		node={data.node}
		rule={editRule}
		networks={data.vm?.networks ?? []}
		switches={data.switches}
		objects={data.networkObjects ?? []}
		onClose={() => { showForm = false; editRule = null; }}
		onSaved={() => { showForm = false; editRule = null; refreshRules(); }}
	/>
{/if}

{#if deleteTarget}
	<AlertDialog
		open={true}
		title="Delete Rule"
		description={`Are you sure you want to delete "${deleteTarget.name}"?`}
		confirmLabel="Delete"
		onConfirm={() => handleDelete(deleteTarget!)}
		onCancel={() => (deleteTarget = null)}
	/>
{/if}
