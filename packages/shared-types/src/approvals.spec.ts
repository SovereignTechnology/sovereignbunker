import { describe, it, expect } from 'vitest';
import {
  ApprovalModeSchema,
  ApproveApprovalBodySchema,
  PermissionListSchema,
  SetApprovalModeBodySchema,
} from './approvals';
import {
  GATED_PERMISSION_METHODS,
  LOGIN_EVENT_KIND,
  MAX_PERMISSIONS_PER_REQUEST,
  isGatedMethod,
} from './permissions';

describe('ApprovalModeSchema', () => {
  it.each(['DENY', 'ASK'])('accepts %s', (mode) => {
    expect(ApprovalModeSchema.parse(mode)).toBe(mode);
  });

  it.each(['deny', 'ask', 'ALLOW', 'MAYBE', '', 'DENY ', 1, null, undefined, {}])(
    'rejects %j (no case folding, no trimming, no third mode)',
    (value) => {
      expect(ApprovalModeSchema.safeParse(value).success).toBe(false);
    },
  );
});

describe('ApproveApprovalBodySchema', () => {
  it.each(['once', 'always'])('accepts mode %s', (mode) => {
    expect(ApproveApprovalBodySchema.parse({ mode })).toEqual({ mode });
  });

  it.each([
    ['no body', undefined],
    ['null', null],
    ['an empty object', {}],
    ['an unknown mode', { mode: 'forever' }],
    ['a different case', { mode: 'ONCE' }],
    ['a number', { mode: 1 }],
    ['an extra field next to a valid mode', { mode: 'once', connectionId: 'x' }],
  ])('rejects %s', (_name, body) => {
    expect(ApproveApprovalBodySchema.safeParse(body).success).toBe(false);
  });
});

describe('SetApprovalModeBodySchema', () => {
  it('accepts DENY and ASK', () => {
    expect(SetApprovalModeBodySchema.parse({ mode: 'ASK' })).toEqual({ mode: 'ASK' });
    expect(SetApprovalModeBodySchema.parse({ mode: 'DENY' })).toEqual({ mode: 'DENY' });
  });

  it('rejects anything else, and extra fields', () => {
    expect(SetApprovalModeBodySchema.safeParse({ mode: 'ask' }).success).toBe(false);
    expect(SetApprovalModeBodySchema.safeParse({}).success).toBe(false);
    expect(SetApprovalModeBodySchema.safeParse({ mode: 'ASK', extra: 1 }).success).toBe(false);
  });
});

describe('PermissionListSchema', () => {
  it('accepts an empty list: an empty choice is a choice', () => {
    expect(PermissionListSchema.parse([])).toEqual([]);
  });

  it('accepts kind 0 and kind 65535, the first and the last', () => {
    const list = [
      { method: 'sign_event', kind: 0 },
      { method: 'sign_event', kind: 65535 },
    ];
    expect(PermissionListSchema.parse(list)).toEqual(list);
  });

  it('accepts method-level and kind-scoped entries', () => {
    const list = [{ method: 'sign_event', kind: 27235 }, { method: 'nip44_decrypt' }];
    expect(PermissionListSchema.parse(list)).toEqual(list);
  });

  it.each([
    ['a string, as the old perms field was', 'sign_event,nip44_decrypt'],
    ['an object', { method: 'sign_event' }],
    ['an unknown method', [{ method: 'delete_everything' }]],
    ['a negative kind', [{ method: 'sign_event', kind: -1 }]],
    ['a fractional kind', [{ method: 'sign_event', kind: 1.5 }]],
    ['a kind above 65535 (an event kind is 16 bits)', [{ method: 'sign_event', kind: 65536 }]],
    ['a kind beyond the database integer', [{ method: 'sign_event', kind: 3_000_000_000 }]],
    ['a string kind', [{ method: 'sign_event', kind: '1' }]],
    ['a null entry', [null]],
  ])('rejects %s', (_name, value) => {
    expect(PermissionListSchema.safeParse(value).success).toBe(false);
  });

  it(`accepts ${MAX_PERMISSIONS_PER_REQUEST} entries and rejects one more`, () => {
    const entry = (kind: number) => ({ method: 'sign_event', kind });
    const atLimit = Array.from({ length: MAX_PERMISSIONS_PER_REQUEST }, (_, i) => entry(i));
    expect(PermissionListSchema.safeParse(atLimit).success).toBe(true);
    expect(PermissionListSchema.safeParse([...atLimit, entry(9999)]).success).toBe(false);
  });
});

describe('gated methods', () => {
  it('lists the five capability methods', () => {
    expect([...GATED_PERMISSION_METHODS].sort()).toEqual([
      'nip04_decrypt',
      'nip04_encrypt',
      'nip44_decrypt',
      'nip44_encrypt',
      'sign_event',
    ]);
  });

  it.each([...GATED_PERMISSION_METHODS])('isGatedMethod(%s) is true', (method) => {
    expect(isGatedMethod(method)).toBe(true);
  });

  it.each(['connect', 'ping', 'get_public_key', 'switch_relays', '', 'SIGN_EVENT', 'sign_event '])(
    'isGatedMethod(%j) is false',
    (method) => {
      expect(isGatedMethod(method)).toBe(false);
    },
  );

  it('the login event kind is the NIP-98 HTTP auth kind', () => {
    expect(LOGIN_EVENT_KIND).toBe(27235);
  });
});
