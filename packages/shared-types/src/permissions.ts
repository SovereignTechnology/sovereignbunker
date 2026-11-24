import { z } from 'zod';
import { Nip46Method } from './nip46.js';

export const PermissionDescriptorSchema = z.object({
  method: Nip46Method,
  kind: z.number().int().nonnegative().optional(),
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
  return {
    method: parsed,
    kind: kindStr ? parseInt(kindStr, 10) : undefined,
  };
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
