<script lang="ts">
	import {
		createVMFirewallRule,
		updateVMFirewallRule,
		type VMFirewallRuleUpsertRequest
	} from '$lib/api/vm/firewall';
	import Button from '$lib/components/ui/button/button.svelte';
	import ComboBox from '$lib/components/ui/custom-input/combobox.svelte';
	import * as Dialog from '$lib/components/ui/dialog';
	import { Input } from '$lib/components/ui/input';
	import { Label } from '$lib/components/ui/label';
	import * as Select from '$lib/components/ui/select';
	import { Switch } from '$lib/components/ui/switch';
	import { Textarea } from '$lib/components/ui/textarea';
	import type { NetworkObject } from '$lib/types/network/object';
	import type { SwitchList } from '$lib/types/network/switch';
	import type { VMFirewallRule } from '$lib/types/network/vm_firewall';
	import type { VMNetwork } from '$lib/types/vm/vm';
	import { handleAPIError } from '$lib/utils/http';
	import { toast } from 'svelte-sonner';

	const ALL_NICS = 'all';

	let {
		rid,
		node,
		rule = null,
		networks = [],
		switches = null,
		objects = [],
		onClose,
		onSaved
	}: {
		rid: number;
		node: string;
		rule?: VMFirewallRule | null;
		networks?: VMNetwork[];
		switches?: SwitchList | null;
		objects?: NetworkObject[];
		onClose: () => void;
		onSaved: () => void;
	} = $props();

	function resolveAddr(val: string): { raw: string; objId: number | null } {
		const trimmed = val.trim();
		if (!trimmed) return { raw: '', objId: null };
		const obj = objects.find(
			(o) => ['Host', 'Network', 'FQDN', 'List'].includes(o.type) && String(o.id) === trimmed
		);
		if (obj) return { raw: '', objId: obj.id };
		return { raw: trimmed, objId: null };
	}

	function resolvePort(val: string): { raw: string; objId: number | null } {
		const trimmed = val.trim();
		if (!trimmed) return { raw: '', objId: null };
		const obj = objects.find((o) => o.type === 'Port' && String(o.id) === trimmed);
		if (obj) return { raw: '', objId: obj.id };
		return { raw: trimmed, objId: null };
	}

	function selectorToForm(raw: string | undefined, objId: number | null | undefined): string {
		if (objId) return String(objId);
		return raw ?? '';
	}

	let name = $state(rule?.name ?? '');
	let description = $state(rule?.description ?? '');
	let enabled = $state(rule?.enabled ?? true);
	let log = $state(rule?.log ?? false);
	let quick = $state(rule?.quick ?? true);
	let priority = $state(rule?.priority ?? 1);
	let action = $state<'pass' | 'block'>(rule?.action ?? 'pass');
	let direction = $state<'in' | 'out'>(rule?.direction ?? 'in');
	let protocol = $state(rule?.protocol ?? 'any');
	let family = $state(rule?.family ?? 'any');
	let networkIdValue = $state(rule?.networkId != null ? String(rule.networkId) : ALL_NICS);
	let source = $state(selectorToForm(rule?.sourceRaw, rule?.sourceObjId));
	let dest = $state(selectorToForm(rule?.destRaw, rule?.destObjId));
	let srcPort = $state(selectorToForm(rule?.srcPortsRaw, rule?.srcPortObjId));
	let dstPort = $state(selectorToForm(rule?.dstPortsRaw, rule?.dstPortObjId));
	let saving = $state(false);
	let nicOpen = $state(false);
	let cbOpen = $state({ source: false, dest: false, srcPort: false, dstPort: false });

	function switchNameFor(network: VMNetwork): string {
		if (!switches) return `switch ${network.switchId}`;
		if (network.switchType === 'standard') {
			return (
				switches.standard.find((s) => s.id === network.switchId)?.name ?? `switch ${network.switchId}`
			);
		}
		return (
			switches.manual.find((s) => s.id === network.switchId)?.name ?? `switch ${network.switchId}`
		);
	}

	function nicLabel(network: VMNetwork): string {
		return `${switchNameFor(network)} · ${network.mac} · ${network.emulation}`;
	}

	const nicOptions = $derived.by(() => {
		const options = [
			{ value: ALL_NICS, label: 'All NICs' },
			...networks.map((network) => ({ value: String(network.id), label: nicLabel(network) }))
		];
		if (
			networkIdValue !== ALL_NICS &&
			!options.some((option) => option.value === networkIdValue)
		) {
			options.push({
				value: networkIdValue,
				label: `NIC ${networkIdValue} (removed)`
			});
		}
		return options;
	});

	const addrObjectOptions = $derived(
		objects
			.filter((obj) => ['Host', 'Network', 'FQDN', 'List'].includes(obj.type))
			.map((obj) => ({ label: obj.name, value: String(obj.id) }))
	);

	const portObjectOptions = $derived(
		objects
			.filter((obj) => obj.type === 'Port')
			.map((obj) => ({ label: obj.name, value: String(obj.id) }))
	);

	const showPorts = $derived(
		protocol === 'tcp' || protocol === 'udp' || protocol === 'tcp_udp'
	);

	async function handleSave() {
		if (!name.trim()) {
			toast.error('Name is required');
			return;
		}
		const src = resolveAddr(source);
		const dst = resolveAddr(dest);
		const sp = showPorts ? resolvePort(srcPort) : { raw: '', objId: null };
		const dp = showPorts ? resolvePort(dstPort) : { raw: '', objId: null };
		saving = true;
		const payload: VMFirewallRuleUpsertRequest = {
			name: name.trim(),
			description,
			enabled,
			log,
			quick,
			priority,
			action,
			direction,
			protocol: protocol as any,
			family: family as any,
			networkId: networkIdValue === ALL_NICS ? null : Number(networkIdValue),
			sourceRaw: src.raw,
			sourceObjId: src.objId,
			destRaw: dst.raw,
			destObjId: dst.objId,
			srcPortsRaw: sp.raw,
			srcPortObjId: sp.objId,
			dstPortsRaw: dp.raw,
			dstPortObjId: dp.objId
		};

		const result = rule
			? await updateVMFirewallRule(rid, rule.id, payload, { hostname: node })
			: await createVMFirewallRule(rid, payload, { hostname: node });

		if (result && result.status === 'success') {
			toast.success(rule ? 'Rule updated' : 'Rule created');
			onSaved();
		} else {
			handleAPIError(result as any);
		}
		saving = false;
	}
</script>

<Dialog.Root open={true} onOpenChange={(open) => !open && onClose()}>
	<Dialog.Content class="max-w-lg">
		<Dialog.Title>{rule ? 'Edit Rule' : 'New Rule'}</Dialog.Title>
		<div class="grid gap-4 py-4">
			<div class="grid gap-2">
				<Label for="name">Name</Label>
				<Input id="name" bind:value={name} placeholder="Rule name" />
			</div>
			<div class="grid gap-2">
				<Label for="desc">Description</Label>
				<Textarea id="desc" bind:value={description} placeholder="Optional description" rows={2} />
			</div>
			<div class="grid grid-cols-2 gap-4">
				<div class="grid gap-2">
					<Label>Action</Label>
					<Select.Root type="single" bind:value={action}>
						<Select.Trigger>
							{action === 'pass' ? 'Pass' : 'Block'}
						</Select.Trigger>
						<Select.Content>
							<Select.Item value="pass">Pass</Select.Item>
							<Select.Item value="block">Block</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
				<div class="grid gap-2">
					<Label>Direction (guest)</Label>
					<Select.Root type="single" bind:value={direction}>
						<Select.Trigger>
							{direction === 'in' ? 'To Guest (Inbound)' : 'From Guest (Outbound)'}
						</Select.Trigger>
						<Select.Content>
							<Select.Item value="in">To Guest (Inbound)</Select.Item>
							<Select.Item value="out">From Guest (Outbound)</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
			</div>
			<div class="grid grid-cols-3 gap-4">
				<div class="grid gap-2">
					<Label>Protocol</Label>
					<Select.Root type="single" bind:value={protocol}>
						<Select.Trigger>{protocol}</Select.Trigger>
						<Select.Content>
							<Select.Item value="any">any</Select.Item>
							<Select.Item value="tcp">tcp</Select.Item>
							<Select.Item value="udp">udp</Select.Item>
							<Select.Item value="icmp">icmp</Select.Item>
							<Select.Item value="ipv6-icmp">ipv6-icmp</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
				<div class="grid gap-2">
					<Label>Family</Label>
					<Select.Root type="single" bind:value={family}>
						<Select.Trigger>{family}</Select.Trigger>
						<Select.Content>
							<Select.Item value="any">any</Select.Item>
							<Select.Item value="inet">inet</Select.Item>
							<Select.Item value="inet6">inet6</Select.Item>
						</Select.Content>
					</Select.Root>
				</div>
				<div class="grid gap-2">
					<Label>Priority</Label>
					<Input type="number" bind:value={priority} min={1} max={1024} />
				</div>
			</div>
			<div class="grid gap-2">
				<ComboBox
					bind:open={nicOpen}
					label="Network Interface"
					bind:value={networkIdValue}
					data={nicOptions}
					classes="space-y-2"
					placeholder="All NICs"
					width="w-full"
				/>
			</div>
			<div class="grid grid-cols-2 gap-4">
				<ComboBox
					bind:open={cbOpen.source}
					label="Source"
					bind:value={source}
					data={addrObjectOptions}
					classes="space-y-2"
					placeholder="any - object or 192.168.1.0/24"
					width="w-full"
					allowCustom={true}
				/>
				<ComboBox
					bind:open={cbOpen.dest}
					label="Destination"
					bind:value={dest}
					data={addrObjectOptions}
					classes="space-y-2"
					placeholder="any - object or 10.0.0.0/8"
					width="w-full"
					allowCustom={true}
				/>
			</div>
			{#if showPorts}
				<div class="grid grid-cols-2 gap-4">
					<ComboBox
						bind:open={cbOpen.srcPort}
						label="Source Ports"
						bind:value={srcPort}
						data={portObjectOptions}
						classes="space-y-2"
						placeholder="any - object or 1024:65535"
						width="w-full"
						allowCustom={true}
					/>
					<ComboBox
						bind:open={cbOpen.dstPort}
						label="Destination Ports"
						bind:value={dstPort}
						data={portObjectOptions}
						classes="space-y-2"
						placeholder="any - object or 80, 443"
						width="w-full"
						allowCustom={true}
					/>
				</div>
			{/if}
			<div class="flex items-center gap-6">
				<div class="flex items-center gap-2">
					<Switch bind:checked={enabled} />
					<Label>Enabled</Label>
				</div>
				<div class="flex items-center gap-2">
					<Switch bind:checked={log} />
					<Label>Log</Label>
				</div>
				<div class="flex items-center gap-2">
					<Switch bind:checked={quick} />
					<Label>Quick</Label>
				</div>
			</div>
		</div>
		<Dialog.Footer>
			<Button variant="outline" onclick={onClose}>Cancel</Button>
			<Button onclick={handleSave} disabled={saving}>
				{saving ? 'Saving...' : rule ? 'Update' : 'Create'}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
