import {
  DEFAULT_CONNECTION_PERMISSIONS,
  MAX_PERMISSIONS_PER_REQUEST,
  isGatedMethod,
  parsePermissionList,
  type PermissionDescriptor,
} from '@bunker46/shared-types';

/**
 * The permissions to pre-select when importing a nostrconnect:// URI: what the app asked for in the
 * URI's `perms` parameter, narrowed to what the signer actually gates and to well-formed entries.
 * The URI is untrusted input, so this is only a starting point: the operator sees every entry in the
 * picker and can change it before anything is granted. Nothing asked for (or nothing usable) falls
 * back to the same conservative defaults a new connection gets.
 */
export function permissionsFromUri(raw: string | null | undefined): PermissionDescriptor[] {
  if (!raw) return [...DEFAULT_CONNECTION_PERMISSIONS];
  const seen = new Set<string>();
  const picked: PermissionDescriptor[] = [];
  for (const p of parsePermissionList(raw)) {
    // connect, ping, get_public_key and switch_relays need no grant; parseInt can yield NaN.
    if (!isGatedMethod(p.method)) continue;
    if (p.kind !== undefined && !(Number.isInteger(p.kind) && p.kind >= 0)) continue;
    const key = `${p.method}:${p.kind ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    picked.push(p.kind === undefined ? { method: p.method } : { method: p.method, kind: p.kind });
    if (picked.length >= MAX_PERMISSIONS_PER_REQUEST) break;
  }
  return picked.length > 0 ? picked : [...DEFAULT_CONNECTION_PERMISSIONS];
}
