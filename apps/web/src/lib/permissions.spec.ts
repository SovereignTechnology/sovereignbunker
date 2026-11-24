import { describe, it, expect } from 'vitest';
import { DEFAULT_CONNECTION_PERMISSIONS } from '@bunker46/shared-types';
import { permissionsFromUri, splitUriPermissions } from './permissions.js';

describe('permissionsFromUri', () => {
  it('pre-selects the ordinary kinds the app asked for: a note, a repost, a reaction', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:6,sign_event:7,sign_event:16')).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'sign_event', kind: 6 },
      { method: 'sign_event', kind: 7 },
      { method: 'sign_event', kind: 16 },
    ]);
  });

  it('does NOT pre-select a login: it stays "ask each time" until the operator ticks it', () => {
    expect(permissionsFromUri('sign_event:1,sign_event:27235')).toEqual([
      { method: 'sign_event', kind: 1 },
    ]);
  });

  // The rule is "everything except the short ordinary list", so a kind nobody thought of is held back
  // too. A link can ask for any of these; none of them is a tick the operator did not make.
  it.each([0, 3, 4, 5, 13, 9734, 10002, 22242, 23194, 24133, 24242, 27235, 30023, 65535])(
    "does NOT pre-select kind %i: it is a wide grant and needs the operator's own tick",
    (kind) => {
      const { picked, flagged } = splitUriPermissions(`sign_event:1,sign_event:${kind}`);
      expect(picked).toEqual([{ method: 'sign_event', kind: 1 }]);
      expect(flagged).toEqual([{ method: 'sign_event', kind }]);
    },
  );

  it('does NOT pre-select a decrypt, an encrypt or sign_event for every kind: a link can ask for anything', () => {
    expect(permissionsFromUri('sign_event:1,sign_event,nip44_decrypt,nip04_encrypt')).toEqual([
      { method: 'sign_event', kind: 1 },
    ]);
    expect(permissionsFromUri('sign_event:7,nip44_encrypt,nip04_decrypt')).toEqual([
      { method: 'sign_event', kind: 7 },
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
    expect(
      splitUriPermissions('sign_event:0,sign_event:0,nip44_decrypt,nip44_decrypt').flagged,
    ).toEqual([{ method: 'sign_event', kind: 0 }, { method: 'nip44_decrypt' }]);
  });

  describe('splitUriPermissions', () => {
    it('ticks the ordinary kinds and flags the rest, each once, for the operator to see', () => {
      expect(
        splitUriPermissions('sign_event:1,sign_event,nip44_decrypt,sign_event:27235,nip44_decrypt'),
      ).toEqual({
        picked: [{ method: 'sign_event', kind: 1 }],
        flagged: [
          { method: 'sign_event' },
          { method: 'nip44_decrypt' },
          { method: 'sign_event', kind: 27235 },
        ],
      });
    });

    it('a link asking only for wide things pre-ticks only the defaults, and flags what it asked', () => {
      const split = splitUriPermissions('sign_event:27235,sign_event:22242,nip04_decrypt');
      expect(split.picked).toEqual([...DEFAULT_CONNECTION_PERMISSIONS]);
      expect(split.flagged).toEqual([
        { method: 'sign_event', kind: 27235 },
        { method: 'sign_event', kind: 22242 },
        { method: 'nip04_decrypt' },
      ]);
    });

    it('flags nothing when nothing was asked, and ticks the defaults', () => {
      expect(splitUriPermissions(null)).toEqual({
        picked: [...DEFAULT_CONNECTION_PERMISSIONS],
        flagged: [],
      });
    });
  });

  it('never returns more than the server accepts', () => {
    // Only four kinds can be pre-ticked, so the bound that matters is on what is listed as asked.
    const many = Array.from({ length: 200 }, (_, i) => `sign_event:${1000 + i}`).join(',');
    const split = splitUriPermissions(many);
    expect(split.flagged).toHaveLength(64);
    expect(split.picked).toEqual([...DEFAULT_CONNECTION_PERMISSIONS]);
    expect(permissionsFromUri(many)).toHaveLength(DEFAULT_CONNECTION_PERMISSIONS.length);
  });
});
