import { z } from 'zod/v4';

const nullableString = z
	.string()
	.nullish()
	.transform((value) => value ?? '');

export const VMFirewallSettingsSchema = z.object({
	id: z.number().int(),
	vmId: z.number().int(),
	enabled: z.boolean().optional().default(false),
	defaultInbound: z.enum(['pass', 'block']).optional().default('block'),
	defaultOutbound: z.enum(['pass', 'block']).optional().default('pass'),
	logDefault: z.boolean().nullish().transform((v) => v ?? false),
	allowDhcp: z.boolean().nullish().transform((v) => v ?? true),
	allowNdp: z.boolean().nullish().transform((v) => v ?? true),
	allowPing: z.boolean().nullish().transform((v) => v ?? false),
	createdAt: z.string().optional(),
	updatedAt: z.string().optional()
});

export const VMFirewallRuleSchema = z.object({
	id: z.number().int(),
	vmId: z.number().int(),
	networkId: z.number().int().nullable().optional().default(null),
	name: z.string(),
	description: nullableString,
	enabled: z.boolean().optional().default(true),
	log: z.boolean().nullish().transform((v) => v ?? false),
	quick: z.boolean().nullish().transform((v) => v ?? true),
	priority: z.number().int(),
	action: z.enum(['pass', 'block']),
	direction: z.enum(['in', 'out']),
	protocol: z.enum(['any', 'tcp', 'udp', 'icmp', 'ipv6-icmp']).optional().default('any'),
	family: z.enum(['any', 'inet', 'inet6']).optional().default('any'),
	sourceRaw: nullableString,
	sourceObjId: z.number().int().nullable().optional().default(null),
	destRaw: nullableString,
	destObjId: z.number().int().nullable().optional().default(null),
	srcPortsRaw: nullableString,
	srcPortObjId: z.number().int().nullable().optional().default(null),
	dstPortsRaw: nullableString,
	dstPortObjId: z.number().int().nullable().optional().default(null),
	createdAt: z.string().optional(),
	updatedAt: z.string().optional()
});

export const VMFirewallRuleCounterSchema = z.object({
	id: z.number().int(),
	packets: z.number(),
	bytes: z.number(),
	updatedAt: z.string().optional()
});

export type VMFirewallSettings = z.infer<typeof VMFirewallSettingsSchema>;
export type VMFirewallRule = z.infer<typeof VMFirewallRuleSchema>;
export type VMFirewallRuleCounter = z.infer<typeof VMFirewallRuleCounterSchema>;
