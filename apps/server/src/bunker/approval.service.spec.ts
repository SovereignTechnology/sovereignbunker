import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { APPROVAL_CONSTANTS } from '@bunker46/config';
import {
  ApprovalService,
  previewRequest,
  previewSignEvent,
  type OpenApprovalInput,
} from './approval.service.js';
import type { EventsService } from '../events/events.service.js';

const TTL = 100_000;

describe('ApprovalService', () => {
  let publish: ReturnType<typeof vi.fn>;
  let service: ApprovalService;

  // `null` means no PUBLIC_BASE_URL (undefined would fall back to the default here).
  const make = (publicBaseUrl: string | null = 'https://signer.example.test:50217') =>
    new ApprovalService({ ttlMs: TTL, publicBaseUrl: publicBaseUrl ?? undefined }, {
      publishUserActivity: publish,
    } as unknown as EventsService);

  const input = (over: Partial<OpenApprovalInput> = {}): OpenApprovalInput => ({
    userId: 'user-1',
    connectionId: 'conn-1',
    connectionName: 'BIES',
    clientPubkey: 'c'.repeat(64),
    requestId: 'req-1',
    fingerprint: 'fp-1',
    permission: { method: 'sign_event', kind: 27235 },
    ...over,
  });

  beforeEach(() => {
    vi.useFakeTimers();
    publish = vi.fn().mockResolvedValue(undefined);
    service = make();
  });

  afterEach(() => {
    service.onModuleDestroy();
    vi.useRealTimers();
  });

  describe('tokens', () => {
    it('are at least 128 bits of randomness, URL-safe', () => {
      const hold = service.open(input())!;
      expect(hold.token).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(Buffer.from(hold.token, 'base64url').length).toBeGreaterThanOrEqual(16);
      expect(Buffer.from(hold.token, 'base64url').length).toBe(APPROVAL_CONSTANTS.TOKEN_BYTES);
    });

    it('never repeat across many holds', () => {
      const seen = new Set<string>();
      for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION; i++) {
        for (let c = 0; c < 20; c++) {
          const hold = service.open(input({ connectionId: `conn-${c}`, requestId: `r${i}` }));
          if (hold) seen.add(hold.token);
        }
      }
      expect(seen.size).toBe(service.size);
    });
  });

  describe('authUrl', () => {
    it('is <PUBLIC_BASE_URL>/approvals/<token>', () => {
      const { token } = service.open(input())!;
      expect(service.authUrl(token)).toBe(`https://signer.example.test:50217/approvals/${token}`);
    });

    it('is undefined without a PUBLIC_BASE_URL (the hold still works)', () => {
      const bare = make(null);
      const { token } = bare.open(input())!;
      expect(bare.authUrl(token)).toBeUndefined();
      bare.onModuleDestroy();
    });
  });

  describe('canAsk', () => {
    it('is true with a PUBLIC_BASE_URL and false without: nothing can be asked without a link to send', () => {
      expect(make().canAsk).toBe(true);
      expect(make(null).canAsk).toBe(false);
    });
  });

  describe('one hold per request id', () => {
    it('a second event carrying the same request id shares the first hold, and is told so', async () => {
      const first = service.open(input())!;
      const second = service.open(input())!;
      expect(second.token).toBe(first.token);
      expect(second.shared).toBe(true);
      expect(first.shared).toBeFalsy();
      expect(service.list('user-1')).toHaveLength(1);
      service.resolve(first.token, 'user-1', 'denied');
      await expect(second.decision).resolves.toBe('denied');
    });

    it('a shared hold takes no extra slot under any cap', () => {
      for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION - 1; i++) {
        service.open(input({ requestId: `r${i}` }));
      }
      expect(service.open(input({ requestId: 'last' }))).toBeDefined();
      // The connection is full, yet a retry of a request that is held still shares it.
      expect(service.open(input({ requestId: 'last' }))?.shared).toBe(true);
    });

    it('the same id on another connection is a different request', () => {
      const a = service.open(input())!;
      const b = service.open(input({ connectionId: 'conn-2' }))!;
      expect(b.token).not.toBe(a.token);
      expect(b.shared).toBeFalsy();
    });

    it('the same id for something else is refused, never merged: approving one must not sign the other', () => {
      service.open(input({ fingerprint: 'event-A' }));
      expect(service.open(input({ fingerprint: 'event-B' }))).toBeUndefined();
      expect(
        service.open(input({ permission: { method: 'sign_event', kind: 1 } })),
      ).toBeUndefined();
      expect(service.list('user-1')).toHaveLength(1);
    });

    it('once the first hold has ended, the same id is held afresh', () => {
      const first = service.open(input())!;
      service.resolve(first.token, 'user-1', 'denied');
      const again = service.open(input())!;
      expect(again.token).not.toBe(first.token);
      expect(again.shared).toBeFalsy();
    });
  });

  describe('listing and ownership', () => {
    it("lists only the user's own holds, oldest first", () => {
      service.open(input({ requestId: 'a' }));
      vi.advanceTimersByTime(1000);
      service.open(input({ requestId: 'b', permission: { method: 'sign_event', kind: 1 } }));
      service.open(input({ userId: 'user-2', connectionId: 'conn-9' }));

      const mine = service.list('user-1');
      expect(mine.map((a) => a.kind)).toEqual([27235, 1]);
      expect(service.list('user-2')).toHaveLength(1);
      expect(service.list('nobody')).toEqual([]);
      expect(service.pendingCount('user-1')).toBe(2);
    });

    it('describes a hold without exposing anything but what the operator needs', () => {
      const { token } = service.open(
        input({ preview: { kind: 27235, content: 'login', tags: [{ name: 'u', values: ['x'] }] } }),
      )!;
      const dto = service.get(token, 'user-1');
      expect(Object.keys(dto).sort()).toEqual(
        [
          'clientPubkey',
          'connectionId',
          'connectionName',
          'createdAt',
          'expiresAt',
          'kind',
          'method',
          'preview',
          'token',
        ].sort(),
      );
      expect(new Date(dto.expiresAt).getTime() - new Date(dto.createdAt).getTime()).toBe(TTL);
    });

    it("another user's token is exactly as unknown as one that never existed", () => {
      const { token } = service.open(input())!;
      const foreign = () => service.get(token, 'user-2');
      const unknown = () => service.get('x'.repeat(32), 'user-1');
      expect(foreign).toThrow(NotFoundException);
      expect(unknown).toThrow(NotFoundException);
      expect(() => service.resolve(token, 'user-2', 'approved_once')).toThrow(NotFoundException);
      // ...and the foreign attempt changed nothing.
      expect(service.list('user-1')).toHaveLength(1);
    });
  });

  describe('deciding', () => {
    it.each([
      ['approved_once', 'approved_once'],
      ['approved_always', 'approved_always'],
      ['denied', 'denied'],
    ] as const)('%s settles the held request with that outcome', async (given, expected) => {
      const hold = service.open(input())!;
      service.resolve(hold.token, 'user-1', given);
      await expect(hold.decision).resolves.toBe(expected);
      expect(service.size).toBe(0);
    });

    it('a hold can be decided once; the second attempt finds nothing', () => {
      const { token } = service.open(input())!;
      service.resolve(token, 'user-1', 'approved_once');
      expect(() => service.resolve(token, 'user-1', 'denied')).toThrow(NotFoundException);
    });

    it('always allow also settles the other holds for the same method and kind on the connection', async () => {
      const first = service.open(input({ requestId: 'r1' }))!;
      const retry = service.open(input({ requestId: 'r2' }))!;
      const otherKind = service.open(
        input({ requestId: 'r3', permission: { method: 'sign_event', kind: 1 } }),
      )!;
      const otherConn = service.open(input({ requestId: 'r4', connectionId: 'conn-2' }))!;

      service.resolve(first.token, 'user-1', 'approved_always');

      await expect(first.decision).resolves.toBe('approved_always');
      await expect(retry.decision).resolves.toBe('approved_always');
      expect(
        service
          .list('user-1')
          .map((a) => a.token)
          .sort(),
      ).toEqual([otherKind.token, otherConn.token].sort());
    });

    it('approve once settles only that request', () => {
      const first = service.open(input({ requestId: 'r1' }))!;
      const retry = service.open(input({ requestId: 'r2' }))!;
      service.resolve(first.token, 'user-1', 'approved_once');
      expect(service.list('user-1').map((a) => a.token)).toEqual([retry.token]);
    });
  });

  describe('time to live', () => {
    it('expires an undecided hold after the TTL, as expired', async () => {
      const hold = service.open(input())!;
      vi.advanceTimersByTime(TTL - 1);
      expect(service.size).toBe(1);
      vi.advanceTimersByTime(1);
      await expect(hold.decision).resolves.toBe('expired');
      expect(service.size).toBe(0);
    });

    it('a decision cancels the timer: nothing fires later', async () => {
      const hold = service.open(input())!;
      service.resolve(hold.token, 'user-1', 'denied');
      publish.mockClear();
      vi.advanceTimersByTime(TTL * 2);
      expect(publish).not.toHaveBeenCalled();
      await expect(hold.decision).resolves.toBe('denied');
    });

    it('an approval after the hold expired is refused', () => {
      const { token } = service.open(input())!;
      vi.advanceTimersByTime(TTL);
      expect(() => service.resolve(token, 'user-1', 'approved_once')).toThrow(NotFoundException);
    });
  });

  describe('caps', () => {
    it('refuses a hold beyond the per-connection cap, and other connections are unaffected', () => {
      for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION; i++) {
        expect(service.open(input({ requestId: `r${i}` }))).toBeDefined();
      }
      expect(service.open(input({ requestId: 'one-too-many' }))).toBeUndefined();
      expect(service.open(input({ connectionId: 'conn-2' }))).toBeDefined();
    });

    it('frees room as holds end', () => {
      const holds = [];
      for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION; i++) {
        holds.push(service.open(input({ requestId: `r${i}` }))!);
      }
      service.resolve(holds[0]!.token, 'user-1', 'denied');
      expect(service.open(input({ requestId: 'fits-now' }))).toBeDefined();
    });

    it('refuses a hold beyond the per-user cap of 50, below the global one; other users are unaffected', () => {
      // 5 connections x 10 holds = 50 for one user.
      for (let c = 0; c < 5; c++) {
        for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION; i++) {
          expect(
            service.open(input({ connectionId: `conn-${c}`, requestId: `r${c}-${i}` })),
          ).toBeDefined();
        }
      }
      expect(service.open(input({ connectionId: 'conn-9', requestId: 'over' }))).toBeUndefined();
      expect(
        service.open(input({ userId: 'user-2', connectionId: 'conn-x', requestId: 'o' })),
      ).toBeDefined();
      expect(APPROVAL_CONSTANTS.MAX_HOLDS_GLOBAL).toBeGreaterThan(50);
    });

    it('refuses a hold beyond the global cap', () => {
      for (let i = 0; i < APPROVAL_CONSTANTS.MAX_HOLDS_GLOBAL; i++) {
        expect(
          service.open(
            input({ userId: `user-${i}`, connectionId: `conn-${i}`, requestId: `r${i}` }),
          ),
        ).toBeDefined();
      }
      expect(
        service.open(input({ userId: 'user-next', connectionId: 'conn-next', requestId: 'n' })),
      ).toBeUndefined();
    });
  });

  describe('cancelling', () => {
    it('ends every hold of one connection, as cancelled, and leaves the others', async () => {
      const a = service.open(input({ requestId: 'a' }))!;
      const b = service.open(input({ requestId: 'b' }))!;
      const other = service.open(input({ connectionId: 'conn-2' }))!;

      expect(service.cancelForConnection('conn-1')).toBe(2);

      await expect(a.decision).resolves.toBe('cancelled');
      await expect(b.decision).resolves.toBe('cancelled');
      expect(service.list('user-1').map((x) => x.token)).toEqual([other.token]);
      expect(service.cancelForConnection('conn-1')).toBe(0);
    });

    it('shutdown cancels what is still held, so no wait is left dangling', async () => {
      const hold = service.open(input())!;
      service.onModuleDestroy();
      await expect(hold.decision).resolves.toBe('cancelled');
    });
  });

  describe('live updates', () => {
    it('tells the owner when a hold opens and when it ends', () => {
      const { token } = service.open(input())!;
      expect(publish).toHaveBeenCalledWith('user-1');
      publish.mockClear();
      service.resolve(token, 'user-1', 'approved_once');
      expect(publish).toHaveBeenCalledWith('user-1');
    });

    it('a failing notification never undoes a decision', async () => {
      publish.mockRejectedValue(new Error('redis down'));
      const hold = service.open(input())!;
      service.resolve(hold.token, 'user-1', 'denied');
      await expect(hold.decision).resolves.toBe('denied');
    });
  });
});

describe('previewSignEvent', () => {
  const event = (over: Record<string, unknown>) =>
    JSON.stringify({ kind: 1, content: '', ...over });
  const MAX = APPROVAL_CONSTANTS.PREVIEW_CONTENT_MAX;

  it('shows the kind, the content and, for every tag, its name and its first values', () => {
    const preview = previewSignEvent(
      event({
        kind: 1,
        content: 'hello',
        tags: [['e', 'abc', 'wss://relay.example', 'root', 'a fourth value'], ['p', 'def'], ['t']],
      }),
    );
    expect(preview).toEqual({
      kind: 1,
      content: 'hello',
      contentTruncated: false,
      contentLength: 5,
      tagCount: 3,
      tags: [
        { name: 'e', values: ['abc', 'wss://relay.example', 'root'] },
        { name: 'p', values: ['def'] },
        { name: 't', values: [] },
      ],
    });
  });

  it('keeps two tags of the same name apart: their values are the difference', () => {
    const preview = previewSignEvent(
      event({
        tags: [
          ['u', 'https://app.example/login'],
          ['u', 'https://app.example/account/delete'],
        ],
      }),
    )!;
    expect(preview.tags?.map((t) => t.values[0])).toEqual([
      'https://app.example/login',
      'https://app.example/account/delete',
    ]);
  });

  it('cuts every value to 100 characters, and a tag to 3 values', () => {
    const preview = previewSignEvent(event({ tags: [['x', 'v'.repeat(500), 'b', 'c', 'd']] }))!;
    expect(preview.tags![0]!.values).toHaveLength(3);
    expect(preview.tags![0]!.values[0]).toHaveLength(100);
  });

  it('cleans tag values like content: controls, bidi and invisible characters never reach the view', () => {
    const preview = previewSignEvent(
      event({ tags: [['u', 'https://good.example/\u202eevil\u0000\u200bx\u00ady']] }),
    )!;
    expect(preview.tags![0]!.values[0]).toBe('https://good.example/?evil??x?y');
  });

  it('cuts content, tag names and values by code point, never through a surrogate pair', () => {
    const preview = previewSignEvent(
      event({ content: '😀'.repeat(MAX + 5), tags: [['😀'.repeat(20), '😀'.repeat(150)]] }),
    )!;
    expect(preview.content).toBe('😀'.repeat(MAX));
    expect(preview.tags![0]!.name).toBe('😀'.repeat(16));
    expect(preview.tags![0]!.values[0]).toBe('😀'.repeat(100));
  });

  it('cuts long content and says how long the whole of it was', () => {
    const preview = previewSignEvent(event({ content: 'x'.repeat(MAX + 50) }))!;
    expect(preview.content).toHaveLength(MAX);
    expect(preview.contentTruncated).toBe(true);
    expect(preview.contentLength).toBe(MAX + 50);
  });

  it('removes control characters so the content cannot garble or spoof the view', () => {
    const preview = previewSignEvent(event({ content: 'a\u0000b\u001b[31mc\nd\u007fe' }))!;
    // eslint-disable-next-line no-control-regex
    expect(preview.content).not.toMatch(/[\u0000-\u001f\u007f]/);
    expect(preview.content).toBe('a b [31mc d e');
  });

  it('removes characters that reorder or hide text: bidi overrides, zero-width, C1 and line separators', () => {
    const evil = 'pay\u202eevil\u202c\u2066x\u2069\u200bz\u200f\u0085\u2028\u2029\u2060\ufeffend';
    const preview = previewSignEvent(event({ content: evil }))!;
    expect(preview.content).toBe('pay evil  x  z      end');
  });

  it('also removes the soft hyphen, Arabic letter mark, Hangul fillers, variation selectors and tag characters', () => {
    const evil = 'a\u00adb\u061cc\u115fd\u1160e\u3164f\uffa0g\ufe0fh\u{E0041}i';
    const preview = previewSignEvent(event({ content: evil }))!;
    expect(preview.content).toBe('a b c d e f g h i');
  });

  it('keeps ordinary non-ASCII text intact', () => {
    const preview = previewSignEvent(event({ content: 'café 日本語 🚀' }))!;
    expect(preview.content).toBe('café 日本語 🚀');
  });

  it('cleans tag names the same way', () => {
    const preview = previewSignEvent(event({ tags: [['p\u202eq', 'v']] }))!;
    expect(preview.tags![0]!.name).toBe('p?q');
  });

  it('bounds the tags, in count and length, and still says how many there were', () => {
    const tags = Array.from({ length: 100 }, (_, i) => [`tag-${i}-${'z'.repeat(40)}`, 'v']);
    const preview = previewSignEvent(event({ tags }))!;
    expect(preview.tags).toHaveLength(APPROVAL_CONSTANTS.PREVIEW_TAG_NAMES_MAX);
    expect(preview.tagCount).toBe(100);
    expect(Math.max(...preview.tags!.map((t) => t.name.length))).toBeLessThanOrEqual(16);
  });

  it('ignores malformed tags and a kind that is not a whole number from 0 to 65535', () => {
    const preview = previewSignEvent(
      JSON.stringify({ kind: -3, content: 5, tags: ['x', [], [7], ['ok']] }),
    )!;
    expect(preview.kind).toBeUndefined();
    expect(preview.content).toBeUndefined();
    expect(preview.tags).toEqual([{ name: 'ok', values: [] }]);
  });

  it.each([65536, 3_000_000_000, 1.5])('shows no kind for %s: it could never be signed', (kind) => {
    expect(previewSignEvent(event({ kind }))!.kind).toBeUndefined();
  });

  it('keeps kind 65535, the last one there is', () => {
    expect(previewSignEvent(event({ kind: 65535 }))!.kind).toBe(65535);
  });

  describe('kind 27235 (HTTP auth, also what confirms deleting an account)', () => {
    const PAYLOAD = 'ab'.repeat(32);
    const login = (u: string, extra: string[][] = []) =>
      previewSignEvent(
        event({
          kind: 27235,
          tags: [['u', u], ['method', 'DELETE'], ['payload', PAYLOAD], ...extra],
        }),
      )!;

    it('puts the host and path of u, the method and the payload where they cannot be missed', () => {
      expect(login('https://shop.example/api/account?confirm=1').httpAuth).toEqual({
        host: 'shop.example',
        path: '/api/account?confirm=1',
        method: 'DELETE',
        payload: PAYLOAD,
      });
    });

    it('shows the real host: user info before the @ does not pass for it', () => {
      expect(login('https://trusted.example@evil.example:8443/x').httpAuth?.host).toBe(
        'evil.example:8443',
      );
    });

    it('shows a look-alike host in its punycode form', () => {
      expect(login('https://\u0430pp.example/').httpAuth?.host).toMatch(/^xn--/);
    });

    it('a u that is not a URL is shown as it is, cleaned, and gives no host', () => {
      const auth = login('not a url\u202e')!.httpAuth!;
      expect(auth.host).toBeUndefined();
      expect(auth.url).toBe('not a url?');
    });

    it('only for kind 27235', () => {
      expect(
        previewSignEvent(event({ kind: 1, tags: [['u', 'https://x.example/']] }))!.httpAuth,
      ).toBeUndefined();
    });
  });

  it.each([undefined, '', 'not json', 'null', '42', '"str"'])(
    'gives no preview for %j (the hold does not depend on one)',
    (raw) => {
      expect(previewSignEvent(raw)).toBeUndefined();
    },
  );
});

describe('previewRequest', () => {
  const PEER = 'ab'.repeat(32);

  it('previews a sign_event request as its event', () => {
    expect(
      previewRequest('sign_event', [JSON.stringify({ kind: 1, content: 'hi' })]),
    ).toMatchObject({ kind: 1, content: 'hi' });
  });

  it.each(['nip04_encrypt', 'nip44_encrypt'])(
    '%s: the peer and the plaintext, cleaned and cut, with its length',
    (method) => {
      const preview = previewRequest(method, [PEER, 'secret\u202eplan']);
      expect(preview).toEqual({
        peer: PEER,
        content: 'secret plan',
        contentTruncated: false,
        contentLength: 11,
      });
    },
  );

  it.each(['nip04_decrypt', 'nip44_decrypt'])(
    '%s: the peer and the ciphertext length, never the ciphertext itself',
    (method) => {
      const ciphertext = 'x'.repeat(300) + '?iv=abc';
      const preview = previewRequest(method, [PEER, ciphertext]);
      expect(preview).toEqual({ peer: PEER, ciphertextLength: ciphertext.length });
      expect(JSON.stringify(preview)).not.toContain('xxxx');
    },
  );

  it('cleans and bounds a peer value that is not a pubkey', () => {
    const preview = previewRequest('nip44_decrypt', ['\u202e' + 'p'.repeat(200), 'c'])!;
    expect(preview.peer).toHaveLength(64);
    expect(preview.peer).not.toContain('\u202e');
  });

  it.each(['ping', 'connect', 'get_public_key', 'switch_relays'])('has none for %s', (method) => {
    expect(previewRequest(method, [])).toBeUndefined();
  });
});
