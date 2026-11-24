import { describe, it, expect } from 'vitest';
import {
  parsePermissionString,
  formatPermission,
  parsePermissionList,
  checkPermission,
  grantNeedsConfirmation,
  ORDINARY_EVENT_KINDS,
} from './permissions';

describe('permissions', () => {
  it('should parse a simple permission string', () => {
    const perm = parsePermissionString('sign_event');
    expect(perm.method).toBe('sign_event');
    expect(perm.kind).toBeUndefined();
  });

  it('should parse a permission with kind', () => {
    const perm = parsePermissionString('sign_event:1');
    expect(perm.method).toBe('sign_event');
    expect(perm.kind).toBe(1);
  });

  it('should format permission without kind', () => {
    expect(formatPermission({ method: 'nip44_encrypt' })).toBe('nip44_encrypt');
  });

  it('should format permission with kind', () => {
    expect(formatPermission({ method: 'sign_event', kind: 13 })).toBe('sign_event:13');
  });

  it('should parse a permission list', () => {
    const perms = parsePermissionList('nip44_encrypt,sign_event:4,ping');
    expect(perms).toHaveLength(3);
    expect(perms[1]?.method).toBe('sign_event');
    expect(perms[1]?.kind).toBe(4);
  });

  it('should check wildcard permission (no kind restriction)', () => {
    const granted = [{ method: 'sign_event' as const }];
    expect(checkPermission(granted, { method: 'sign_event', kind: 1 })).toBe(true);
    expect(checkPermission(granted, { method: 'sign_event', kind: 42 })).toBe(true);
  });

  it('should reject ungranted permissions', () => {
    const granted = [{ method: 'sign_event' as const, kind: 1 }];
    expect(checkPermission(granted, { method: 'sign_event', kind: 2 })).toBe(false);
  });

  describe('kind range', () => {
    it.each([
      'sign_event:65536',
      'sign_event:3000000000',
      'sign_event:abc',
      'sign_event:-4',
      'sign_event:1.5',
    ])('refuses %s: it could never be signed and would not fit the database', (perm) => {
      expect(() => parsePermissionString(perm)).toThrow();
    });

    it('keeps 0 and 65535', () => {
      expect(parsePermissionString('sign_event:0').kind).toBe(0);
      expect(parsePermissionString('sign_event:65535').kind).toBe(65535);
    });

    it('a list skips the entries it refuses and keeps the rest', () => {
      expect(parsePermissionList('sign_event:1,sign_event:3000000000,nip44_decrypt')).toEqual([
        { method: 'sign_event', kind: 1 },
        { method: 'nip44_decrypt', kind: undefined },
      ]);
    });
  });
});

describe('grantNeedsConfirmation', () => {
  it('the ordinary kinds are 1, 6, 7 and 16, and nothing else', () => {
    expect([...ORDINARY_EVENT_KINDS].sort((a, b) => a - b)).toEqual([1, 6, 7, 16]);
  });

  it.each([1, 6, 7, 16])('a grant of sign_event:%i needs no confirmation', (kind) => {
    expect(grantNeedsConfirmation({ method: 'sign_event', kind })).toBe(false);
  });

  // The rule is inverted on purpose: a list of what is dangerous is always one entry short, so every
  // kind that is not on the short ordinary list needs the second step.
  it.each([
    0, 2, 3, 4, 5, 8, 9, 13, 14, 15, 17, 40, 1059, 1984, 9734, 9735, 10002, 22242, 23194, 23195,
    24133, 24242, 27235, 30023, 30078, 65535,
  ])('a grant of sign_event:%i needs one', (kind) => {
    expect(grantNeedsConfirmation({ method: 'sign_event', kind })).toBe(true);
  });

  it('every kind at once (sign_event with no kind) needs one', () => {
    expect(grantNeedsConfirmation({ method: 'sign_event' })).toBe(true);
  });

  it.each(['nip04_encrypt', 'nip04_decrypt', 'nip44_encrypt', 'nip44_decrypt'] as const)(
    '%s needs one, with or without a kind',
    (method) => {
      expect(grantNeedsConfirmation({ method })).toBe(true);
      expect(grantNeedsConfirmation({ method, kind: 1 })).toBe(true);
    },
  );
});
