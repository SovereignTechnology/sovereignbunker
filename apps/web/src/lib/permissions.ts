import {
  DEFAULT_CONNECTION_PERMISSIONS,
  MAX_PERMISSIONS_PER_REQUEST,
  grantNeedsConfirmation,
  isGatedMethod,
  parsePermissionList,
  type PermissionDescriptor,
} from '@bunker46/shared-types';

/**
 * What a nostrconnect:// URI asks for in its `perms` parameter, split for the import form.
 *
 * `picked` is what to PRE-TICK: only an ordinary kind (a note, a repost, a reaction: see
 * grantNeedsConfirmation). Everything else is `flagged` instead and needs the operator's own tick:
 * `sign_event` for every kind, any encrypt or decrypt, and every kind that is a wide grant (a login,
 * a profile, deleting events, relay auth, remote-signer messages, ...). The URI is untrusted input
 * and one stray tick would otherwise be a blanket grant, so the form shows what was asked and leaves
 * the choice to the operator. A login stays "ask each time" (the picker's own choice) until then.
 * Both lists are narrowed to what the signer gates and to well-formed entries, and hold each entry
 * once. Nothing pre-tickable falls back to the conservative defaults a new connection gets.
 */
export function splitUriPermissions(raw: string | null | undefined): {
  picked: PermissionDescriptor[];
  flagged: PermissionDescriptor[];
} {
  const picked: PermissionDescriptor[] = [];
  const flagged: PermissionDescriptor[] = [];
  const seen = new Set<string>();
  for (const p of raw ? parsePermissionList(raw) : []) {
    // connect, ping, get_public_key and switch_relays need no grant.
    if (!isGatedMethod(p.method)) continue;
    if (p.kind !== undefined && !(Number.isInteger(p.kind) && p.kind >= 0)) continue;
    const key = `${p.method}:${p.kind ?? ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    if (p.method === 'sign_event' && p.kind !== undefined && !grantNeedsConfirmation(p)) {
      if (picked.length < MAX_PERMISSIONS_PER_REQUEST)
        picked.push({ method: p.method, kind: p.kind });
    } else if (flagged.length < MAX_PERMISSIONS_PER_REQUEST) {
      flagged.push(
        p.kind === undefined ? { method: p.method } : { method: p.method, kind: p.kind },
      );
    }
  }
  return {
    picked: picked.length > 0 ? picked : [...DEFAULT_CONNECTION_PERMISSIONS],
    flagged,
  };
}

/** The permissions to pre-select for a nostrconnect:// URI (see {@link splitUriPermissions}). */
export function permissionsFromUri(raw: string | null | undefined): PermissionDescriptor[] {
  return splitUriPermissions(raw).picked;
}
