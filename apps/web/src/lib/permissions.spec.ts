import { describe, it, expect } from 'vitest';
import { DEFAULT_CONNECTION_PERMISSIONS } from '@bunker46/shared-types';
import { permissionsFromUri, splitUriPermissions } from './permissions.js';

describe('permissionsFromUri', () => {
  it('pre-selects the kinds the app asked for', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:27235')).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'sign_event', kind: 27235 },
    ]);
  });

  it('does NOT pre-select a decrypt, an encrypt or sign_event for every kind: a link can ask for anything', () => {
    expect(permissionsFromUri('sign_event:1,sign_event,nip44_decrypt,nip04_encrypt')).toEqual([
      { method: 'sign_event', kind: 1 },
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

  it('a URI that asks only for things that are not pre-selected starts from the defaults', () => {
    expect(permissionsFromUri('sign_event,nip44_decrypt')).toEqual([
      ...DEFAULT_CONNECTION_PERMISSIONS,
    ]);
  });

  it('lists each permission once', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:1,nip44_decrypt,nip44_decrypt')).toEqual([
      { method: 'sign_event', kind: 1 },
    ]);
  });

  describe('splitUriPermissions', () => {
    it('ticks the kind-scoped entries and flags the rest, each once, for the operator to see', () => {
      expect(
        splitUriPermissions('sign_event:1,sign_event,nip44_decrypt,sign_event:27235,nip44_decrypt'),
      ).toEqual({
        picked: [
          { method: 'sign_event', kind: 1 },
          { method: 'sign_event', kind: 27235 },
        ],
        flagged: [{ method: 'sign_event' }, { method: 'nip44_decrypt' }],
      });
    });

    it('flags nothing when nothing was asked, and ticks the defaults', () => {
      expect(splitUriPermissions(null)).toEqual({
        picked: [...DEFAULT_CONNECTION_PERMISSIONS],
        flagged: [],
      });
    });
  });

  it('never returns more than the server accepts', () => {
    const many = Array.from({ length: 200 }, (_, i) => `sign_event:${i}`).join(',');
    expect(permissionsFromUri(many)).toHaveLength(64);
  });
});
