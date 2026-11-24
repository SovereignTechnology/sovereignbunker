import { describe, it, expect } from 'vitest';
import { DEFAULT_CONNECTION_PERMISSIONS } from '@bunker46/shared-types';
import { permissionsFromUri } from './permissions.js';

describe('permissionsFromUri', () => {
  it('pre-selects what the app asked for', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:27235,nip44_decrypt')).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'sign_event', kind: 27235 },
      { method: 'nip44_decrypt' },
    ]);
  });

  it.each([null, undefined, ''])(
    'falls back to the defaults when nothing was asked (%j)',
    (raw) => {
      expect(permissionsFromUri(raw)).toEqual([...DEFAULT_CONNECTION_PERMISSIONS]);
    },
  );

  it('falls back to the defaults when nothing usable was asked', () => {
    expect(permissionsFromUri('connect,ping,telepathy')).toEqual([
      ...DEFAULT_CONNECTION_PERMISSIONS,
    ]);
  });

  it('leaves out methods that need no grant, and unknown ones', () => {
    expect(
      permissionsFromUri('connect,ping,get_public_key,switch_relays,sign_event:1,bogus'),
    ).toEqual([{ method: 'sign_event', kind: 1 }]);
  });

  it('drops a kind that is not a non-negative number: it would make the server refuse the list', () => {
    expect(permissionsFromUri('sign_event:abc,sign_event:-4,sign_event:7')).toEqual([
      { method: 'sign_event', kind: 7 },
    ]);
  });

  it('keeps a method-level request method-level (all kinds), as asked', () => {
    expect(permissionsFromUri('sign_event')).toEqual([{ method: 'sign_event' }]);
  });

  it('lists each permission once', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:1,nip44_decrypt,nip44_decrypt')).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'nip44_decrypt' },
    ]);
  });

  it('never returns more than the server accepts', () => {
    const many = Array.from({ length: 200 }, (_, i) => `sign_event:${i}`).join(',');
    expect(permissionsFromUri(many)).toHaveLength(64);
  });
});
