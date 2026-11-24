import { z } from 'zod';
import { Nip46Method } from './nip46.js';

/**
 * The last event kind there is: NIP-01 makes a kind a 16-bit integer. Also well inside the database's
 * 32-bit column, so a stored kind can never fail to insert (which would drop an audit row).
 */
export const MAX_EVENT_KIND = 65535;

export const PermissionDescriptorSchema = z.object({
  method: Nip46Method,
  kind: z.number().int().min(0).max(MAX_EVENT_KIND).optional(),
});
export type PermissionDescriptor = z.infer<typeof PermissionDescriptorSchema>;

/**
 * Conservative default permissions seeded on a newly created connection when neither the client
 * (via the connect request) nor the operator (via the dashboard) supplies an explicit set.
 *
 * Bounded to common signing kinds (profile, note, contacts, DM, reaction). It deliberately grants
 * NO nip04/nip44 decrypt (nor encrypt), so a fresh connection can never act as a blanket decryption
 * oracle on the user's key. The RPC handler is default-deny, so a connection with zero permissions
 * can perform no signing/encryption until these — or explicit permissions — are granted.
 */
export const DEFAULT_CONNECTION_PERMISSIONS: readonly PermissionDescriptor[] = [
  { method: 'sign_event', kind: 0 }, // profile metadata
  { method: 'sign_event', kind: 1 }, // short text note
  { method: 'sign_event', kind: 3 }, // contacts / follow list
  { method: 'sign_event', kind: 4 }, // encrypted direct message
  { method: 'sign_event', kind: 7 }, // reaction
];

export function parsePermissionString(perm: string): PermissionDescriptor {
  const [method, kindStr] = perm.split(':');
  const parsed = Nip46Method.parse(method);
  if (!kindStr) return { method: parsed, kind: undefined };
  // Digits only, in range: "abc", "-4", "1.5" and "3000000000" are refused here (and skipped by
  // parsePermissionList) instead of becoming NaN or a kind that cannot be signed or stored.
  if (!/^\d{1,5}$/.test(kindStr) || Number(kindStr) > MAX_EVENT_KIND) {
    throw new Error(`Invalid event kind in permission: ${kindStr.slice(0, 12)}`);
  }
  return { method: parsed, kind: Number(kindStr) };
}

export function formatPermission(perm: PermissionDescriptor): string {
  return perm.kind !== undefined ? `${perm.method}:${perm.kind}` : perm.method;
}

export function parsePermissionList(perms: string): PermissionDescriptor[] {
  const results: PermissionDescriptor[] = [];
  for (const s of perms.split(',')) {
    const trimmed = s.trim();
    if (!trimmed) continue;
    try {
      results.push(parsePermissionString(trimmed));
    } catch {
      // skip unknown methods
    }
  }
  return results;
}

export function checkPermission(
  granted: PermissionDescriptor[],
  required: PermissionDescriptor,
): boolean {
  return granted.some(
    (g) => g.method === required.method && (g.kind === undefined || g.kind === required.kind),
  );
}

/**
 * The methods the signer gates behind an explicit permission (default-deny). The others (connect,
 * ping, get_public_key, switch_relays) are always available, so they never need granting.
 */
export const GATED_PERMISSION_METHODS = [
  'sign_event',
  'nip04_encrypt',
  'nip04_decrypt',
  'nip44_encrypt',
  'nip44_decrypt',
] as const;

/** True when `method` needs an explicit permission (see GATED_PERMISSION_METHODS). */
export function isGatedMethod(method: string): method is (typeof GATED_PERMISSION_METHODS)[number] {
  return (GATED_PERMISSION_METHODS as readonly string[]).includes(method);
}

/**
 * The event kind clients sign to log in to a website (NIP-98 HTTP auth, e.g. a BIES remote-signer
 * login). Granting it permanently lets the client sign logins for any site, including ones that
 * delete an account, so the UI offers "ask each time" first.
 */
export const LOGIN_EVENT_KIND = 27235;

/** A bound on any permission list that arrives over the API (the picker offers a few dozen at most). */
export const MAX_PERMISSIONS_PER_REQUEST = 64;
