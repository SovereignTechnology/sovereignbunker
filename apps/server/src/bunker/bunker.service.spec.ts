import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { NOSTR_CONSTANTS } from '@bunker46/config';
import { BunkerService } from './bunker.service.js';
import type { PrismaService } from '../prisma/prisma.service.js';
import type { BunkerRpcHandler } from './bunker-rpc.handler.js';
import { ApprovalService } from './approval.service.js';
import type { EventsService } from '../events/events.service.js';
import type { Nip46Request } from '@bunker46/shared-types';
import type { EncryptionService } from '../common/crypto/encryption.service.js';

vi.mock('nostr-tools/pool', () => ({
  SimplePool: vi.fn().mockImplementation(function (this: unknown) {
    return {
      subscribe: vi.fn().mockReturnValue({ close: vi.fn() }),
      close: vi.fn(),
      publish: vi.fn().mockResolvedValue(undefined),
      listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
    };
  }),
  useWebSocketImplementation: vi.fn(),
}));

describe('BunkerService', () => {
  let service: BunkerService;
  let prisma: Partial<PrismaService>;
  let encryption: Partial<EncryptionService>;
  let rpcHandler: Partial<BunkerRpcHandler>;
  let approvals: Partial<ApprovalService>;

  beforeEach(async () => {
    vi.clearAllMocks();
    approvals = { authUrl: vi.fn().mockReturnValue(undefined) };
    prisma = {
      nsecKey: {
        findMany: vi.fn().mockResolvedValue([]),
        findUnique: vi.fn().mockResolvedValue(null),
      },
      relayConfig: { findMany: vi.fn().mockResolvedValue([]) },
    };
    encryption = { decrypt: vi.fn().mockReturnValue('decrypted-nsec-hex') };
    rpcHandler = { setPendingSecretLookup: vi.fn(), setBaseRelayLookup: vi.fn() };
    service = new BunkerService(
      rpcHandler as BunkerRpcHandler,
      prisma as PrismaService,
      encryption as EncryptionService,
      [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
      approvals as ApprovalService,
    );
    await service.onModuleInit();
  });

  afterEach(async () => {
    await service.onModuleDestroy();
  });

  describe('switch_relays relay lookup', () => {
    it("hands the RPC handler the owner's relay_configs, else the defaults", async () => {
      const lookup = vi.mocked(rpcHandler.setBaseRelayLookup!).mock.calls[0][0];
      vi.mocked(prisma.relayConfig!.findMany).mockResolvedValueOnce([
        { url: 'wss://a.example.com' },
        { url: 'wss://b.example.com' },
      ] as never);
      await expect(lookup('u1')).resolves.toEqual(['wss://a.example.com', 'wss://b.example.com']);
      await expect(lookup('u2')).resolves.toEqual([...NOSTR_CONSTANTS.DEFAULT_RELAYS]);
    });
  });

  describe('pending secrets', () => {
    it('should register and consume pending secret', () => {
      const pubkey = 'a'.repeat(64);
      const secret = 'secret123';
      const info = { userId: 'u1', nsecKeyId: 'k1', name: 'Test' };
      service.registerPendingSecret(pubkey, secret, info);
      expect(service.getPendingSecretCount()).toBe(1);
      const consumed = service.consumePendingSecret(pubkey, secret);
      expect(consumed).toEqual(info);
      expect(service.getPendingSecretCount()).toBe(0);
    });

    it('should return undefined when consuming unknown secret', () => {
      const result = service.consumePendingSecret('a'.repeat(64), 'unknown');
      expect(result).toBeUndefined();
    });

    it('preserves the operator-chosen permission seed through register/consume', () => {
      const pubkey = 'b'.repeat(64);
      const secret = 'secret-with-perms';
      const info = {
        userId: 'u1',
        nsecKeyId: 'k1',
        name: 'Test',
        permissions: [
          { method: 'sign_event' as const, kind: 30078 },
          { method: 'nip44_decrypt' as const },
        ],
      };
      service.registerPendingSecret(pubkey, secret, info);
      // The connect handler reads these back to seed the auto-created connection's granted permissions.
      expect(service.consumePendingSecret(pubkey, secret)).toEqual(info);
    });
  });

  describe('starting the listeners at boot', () => {
    it('keeps going when one key cannot be started', async () => {
      const poolModule = await import('nostr-tools/pool');
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe: vi.fn().mockReturnValue({ close: vi.fn() }),
          close: vi.fn(),
          publish: vi.fn().mockReturnValue([]),
          listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
        };
      });
      vi.mocked(prisma.nsecKey!.findMany).mockResolvedValueOnce([
        { userId: 'u1', publicKey: 'a'.repeat(64), encryptedNsec: 'unreadable', connections: [] },
        { userId: 'u1', publicKey: 'd'.repeat(64), encryptedNsec: 'readable', connections: [] },
      ] as never);
      vi.mocked(encryption.decrypt!).mockImplementation((value: string) => {
        if (value === 'unreadable') throw new Error('bad ciphertext');
        return 'e'.repeat(64);
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );

      await svc.onModuleInit();

      expect(svc.isListening('a'.repeat(64))).toBe(false);
      expect(svc.isListening('d'.repeat(64))).toBe(true);
      await svc.onModuleDestroy();
    });
  });

  describe('listeners', () => {
    it('should start listening and report active count', async () => {
      const poolModule = await import('nostr-tools/pool');
      const pubkey = 'b'.repeat(64);
      const nsec = 'c'.repeat(64);
      expect(service.isListening(pubkey)).toBe(false);
      expect(service.getActiveListenerCount()).toBe(0);
      service.startListeningForKey(pubkey, nsec, ['wss://relay.example.com']);
      expect(service.isListening(pubkey)).toBe(true);
      expect(service.getActiveListenerCount()).toBe(1);
      const poolInstance = vi.mocked(poolModule.SimplePool).mock.results.at(-1)?.value;
      expect(poolInstance?.subscribe).toHaveBeenCalledWith(
        ['wss://relay.example.com'],
        expect.any(Object),
        expect.any(Object),
      );
    });

    it('should stop listening when stopListeningForKey is called', async () => {
      const poolModule = await import('nostr-tools/pool');
      const closeFn = vi.fn();
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe: vi.fn().mockReturnValue({ close: closeFn }),
          close: vi.fn(),
          publish: vi.fn().mockResolvedValue(undefined),
        };
      });
      service = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await service.onModuleInit();
      const pubkey = 'd'.repeat(64);
      service.startListeningForKey(pubkey, 'e'.repeat(64), ['wss://r.example.com']);
      expect(service.isListening(pubkey)).toBe(true);
      service.stopListeningForKey(pubkey);
      expect(closeFn).toHaveBeenCalled();
      expect(service.isListening(pubkey)).toBe(false);
      await service.onModuleDestroy();
    });

    it('should use default relays when empty array passed', async () => {
      const poolModule = await import('nostr-tools/pool');
      service.startListeningForKey('f'.repeat(64), 'e'.repeat(64), []);
      const poolInstance = vi.mocked(poolModule.SimplePool).mock.results.at(-1)?.value;
      expect(poolInstance?.subscribe).toHaveBeenCalled();
      const [relays] = (poolInstance?.subscribe as ReturnType<typeof vi.fn>)?.mock.calls[0] ?? [];
      expect(Array.isArray(relays)).toBe(true);
      expect(relays.length).toBeGreaterThan(0);
    });
  });

  describe('connection watchdog', () => {
    // Build a service whose pool reports the given relay connection status, and
    // invoke the watchdog's check directly (avoids fragile fake-timer machinery).
    async function makeService(status: Map<string, boolean>) {
      const poolModule = await import('nostr-tools/pool');
      const subscribe = vi.fn().mockReturnValue({ close: vi.fn() });
      const listConnectionStatus = vi.fn().mockReturnValue(status);
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe,
          close: vi.fn(),
          publish: vi.fn().mockResolvedValue(undefined),
          listConnectionStatus,
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      const runWatchdog = () => (svc as unknown as { checkConnections(): void }).checkConnections();
      return { svc, subscribe, listConnectionStatus, runWatchdog };
    }

    it('schedules a periodic check on init', async () => {
      const spy = vi.spyOn(globalThis, 'setInterval');
      const { svc } = await makeService(new Map());
      expect(spy).toHaveBeenCalledWith(
        expect.any(Function),
        NOSTR_CONSTANTS.RELAY_WATCHDOG_INTERVAL_MS,
      );
      await svc.onModuleDestroy();
      spy.mockRestore();
    });

    it('re-subscribes a listener when its relay connection has dropped', async () => {
      // Empty status map => relay reported as not connected => watchdog must act.
      const { svc, subscribe, listConnectionStatus, runWatchdog } = await makeService(new Map());

      const pubkey = 'a'.repeat(64);
      svc.startListeningForKey(pubkey, 'b'.repeat(64), ['wss://relay.example.com']);
      expect(subscribe).toHaveBeenCalledTimes(1);

      runWatchdog();

      expect(listConnectionStatus).toHaveBeenCalled();
      expect(subscribe).toHaveBeenCalledTimes(2);
      expect(svc.isListening(pubkey)).toBe(true);

      await svc.onModuleDestroy();
    });

    it('leaves a listener untouched while its relays stay connected', async () => {
      // Note: status keys are normalized URLs (bare host gains a trailing slash).
      const { svc, subscribe, runWatchdog } = await makeService(
        new Map([['wss://relay.example.com/', true]]),
      );

      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example.com']);
      expect(subscribe).toHaveBeenCalledTimes(1);

      runWatchdog();

      expect(subscribe).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('one listener failing to re-open does not stop the others', async () => {
      const { svc, subscribe, runWatchdog } = await makeService(new Map()); // every relay dropped
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example.com']);
      svc.startListeningForKey('d'.repeat(64), 'e'.repeat(64), ['wss://other.example.com']);
      const listeners = (
        svc as unknown as { activeListeners: Map<string, { reopen: (url: string) => void }> }
      ).activeListeners;
      listeners.get('a'.repeat(64))!.reopen = () => {
        throw new Error('boom');
      };

      expect(() => runWatchdog()).not.toThrow();
      // Two opened at start, plus the second listener's re-open.
      expect(subscribe).toHaveBeenCalledTimes(3);

      await svc.onModuleDestroy();
    });
  });

  describe('replay guard', () => {
    type OnEvent = (event: {
      id: string;
      pubkey: string;
      content: string;
      created_at: number;
    }) => Promise<void>;

    afterEach(() => {
      vi.useRealTimers();
    });

    async function makeService() {
      const poolModule = await import('nostr-tools/pool');
      const subscribe = vi.fn().mockReturnValue({ close: vi.fn() });
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe,
          close: vi.fn(),
          publish: vi.fn().mockResolvedValue(undefined),
          // Empty status => every relay reads as dropped, so the watchdog re-subscribes.
          listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      // Count the requests that reach the decrypt-and-answer path without running it.
      // true: the event was a request that got answered (what the guard remembers).
      const internals = svc as unknown as { handleIncomingEvent: () => Promise<boolean> };
      const handle = vi.spyOn(internals, 'handleIncomingEvent');
      handle.mockResolvedValue(true);
      const onEventOfCall = (n: number) =>
        (subscribe.mock.calls[n]?.[2] as { onevent: OnEvent }).onevent;
      const handled = () =>
        (svc as unknown as { handledEventIds: Map<string, number> }).handledEventIds;
      return { svc, subscribe, handle, onEventOfCall, handled };
    }

    // `ageS` seconds old (negative: dated that far ahead).
    const request = (id: string, ageS = 0) => ({
      id,
      pubkey: 'c'.repeat(64),
      content: 'ciphertext',
      created_at: Math.floor(Date.now() / 1000) - ageS,
    });
    const LISTEN = ['wss://relay.example.com'];

    it('only asks relays for requests inside the since window', async () => {
      const { svc, subscribe } = await makeService();
      const before = Math.floor(Date.now() / 1000);
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example.com']);
      const after = Math.floor(Date.now() / 1000);

      const filter = subscribe.mock.calls[0]?.[1] as { since?: number };
      expect(filter.since).toBeGreaterThanOrEqual(before - NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S);
      expect(filter.since).toBeLessThanOrEqual(after - NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S);

      await svc.onModuleDestroy();
    });

    it('answers a request once when relays deliver it again', async () => {
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example.com']);
      const onevent = onEventOfCall(0);

      await onevent(request('1'.repeat(64)));
      await onevent(request('1'.repeat(64)));
      expect(handle).toHaveBeenCalledTimes(1);

      await onevent(request('2'.repeat(64)));
      expect(handle).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it('remembers handled requests across a watchdog re-subscribe', async () => {
      // 2026-10-30: a relay drop made the watchdog re-subscribe, relays handed back 15 requests
      // that had already been answered, and the bunker signed all 15 again.
      const { svc, subscribe, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), ['wss://relay.example.com']);
      await onEventOfCall(0)(request('3'.repeat(64)));

      (svc as unknown as { checkConnections(): void }).checkConnections();
      expect(subscribe).toHaveBeenCalledTimes(2);

      await onEventOfCall(1)(request('3'.repeat(64)));
      expect(handle).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('accepts a request dated exactly at the edges of the window and drops one second beyond', async () => {
      vi.useFakeTimers(); // the clock stands still, so the edges are exact
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      const W = NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S;
      const AHEAD = NOSTR_CONSTANTS.NIP46_FUTURE_SKEW_S;

      await onevent(request('5'.repeat(64), W + 1));
      await onevent(request('6'.repeat(64), -(AHEAD + 1)));
      expect(handle).not.toHaveBeenCalled();

      await onevent(request('7'.repeat(64), W));
      await onevent(request('8'.repeat(64), -AHEAD));
      expect(handle).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it('warns once a minute about requests dated outside the window, then goes quiet', async () => {
      vi.useFakeTimers();
      const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      try {
        const { svc, onEventOfCall } = await makeService();
        svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
        const onevent = onEventOfCall(0);
        const stale = NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S + 100;
        const skewWarnings = () =>
          warn.mock.calls.filter((c) => String(c[0]).includes("off this server's clock")).length;

        await onevent(request('f1'.padEnd(64, '0'), stale));
        await onevent(request('f2'.padEnd(64, '0'), stale));
        expect(skewWarnings()).toBe(1);

        await vi.advanceTimersByTimeAsync(60_000);
        await onevent(request('f3'.padEnd(64, '0'), stale));
        expect(skewWarnings()).toBe(2);

        await svc.onModuleDestroy();
      } finally {
        warn.mockRestore();
      }
    });

    it('keeps a handled id exactly as long as its event can still be accepted', async () => {
      // A subscription is long-lived, so the guard must not forget an id before the age gate would
      // drop its event: at created_at + window the event is still accepted, one second later not.
      vi.useFakeTimers();
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      const W = NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S;
      const event = request('9'.repeat(64));
      await onevent(event);

      vi.setSystemTime((event.created_at + W) * 1000); // the last second the gate accepts it
      await onevent(event);
      expect(handle).toHaveBeenCalledTimes(1);

      vi.setSystemTime((event.created_at + W + 1) * 1000); // now the gate drops it
      await onevent(event);
      expect(handle).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('forgets ids once their event could no longer be accepted', async () => {
      vi.useFakeTimers();
      const { svc, onEventOfCall, handled } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      const old = request('a1'.padEnd(64, '0'));
      await onevent(old);
      expect(handled().size).toBe(1);

      const later =
        (old.created_at +
          NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S +
          NOSTR_CONSTANTS.NIP46_HANDLED_MARGIN_S +
          31) *
        1000;
      vi.setSystemTime(later);
      await onevent(request('a2'.padEnd(64, '0')));
      expect(handled().size).toBe(1);

      await svc.onModuleDestroy();
    });

    it('remembers a request per signer: two signers can be sent the same event', async () => {
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      svc.startListeningForKey('d'.repeat(64), 'e'.repeat(64), LISTEN);
      const event = request('b1'.padEnd(64, '0'));

      await onEventOfCall(0)(event);
      await onEventOfCall(1)(event);
      expect(handle).toHaveBeenCalledTimes(2);

      await onEventOfCall(0)(event);
      await onEventOfCall(1)(event);
      expect(handle).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it('remembers neither an event that was not a request nor one whose handling failed', async () => {
      const { svc, handle, onEventOfCall, handled } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);

      handle.mockResolvedValueOnce(false); // undecryptable junk: no slot taken
      await onevent(request('c1'.padEnd(64, '0')));
      expect(handled().size).toBe(0);
      await onevent(request('c1'.padEnd(64, '0'))); // tried again, now answered
      expect(handle).toHaveBeenCalledTimes(2);
      expect(handled().size).toBe(1);

      handle.mockRejectedValueOnce(new Error('database unavailable')); // retried on redelivery
      await onevent(request('c2'.padEnd(64, '0')));
      await onevent(request('c2'.padEnd(64, '0')));
      expect(handle).toHaveBeenCalledTimes(4);
      await onevent(request('c2'.padEnd(64, '0')));
      expect(handle).toHaveBeenCalledTimes(4);

      await svc.onModuleDestroy();
    });

    it('handles a request once when two relays deliver it at the same moment', async () => {
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      let release = () => {};
      handle.mockImplementationOnce(
        () =>
          new Promise<boolean>((resolve) => {
            release = () => resolve(true);
          }),
      );
      const event = request('d1'.padEnd(64, '0'));

      const first = onevent(event);
      await onevent(event); // a second relay's copy, while the first is still being answered
      expect(handle).toHaveBeenCalledTimes(1);

      release();
      await first;
      await onevent(event);
      expect(handle).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('handles a request once when its listener is swapped while it is being answered', async () => {
      const { svc, handle, onEventOfCall } = await makeService();
      const key = ['a'.repeat(64), 'b'.repeat(64)] as const;
      svc.startListeningForKey(...key, LISTEN);
      let release = () => {};
      handle.mockImplementationOnce(
        () =>
          new Promise<boolean>((resolve) => {
            release = () => resolve(true);
          }),
      );
      const event = request('e1'.padEnd(64, '0'));
      const first = onEventOfCall(0)(event);

      // Another relay joins: the listener is rebuilt, and its relays hand the request back.
      svc.startListeningForKey(...key, [...LISTEN, 'wss://other.example.com']);
      await onEventOfCall(1)(event);
      expect(handle).toHaveBeenCalledTimes(1);

      release();
      await first;
      await onEventOfCall(1)(event);
      expect(handle).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('ignores events that reach a listener after it was stopped', async () => {
      const { svc, handle, onEventOfCall } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      svc.stopListeningForKey('a'.repeat(64));

      await onevent(request('e2'.padEnd(64, '0')));
      expect(handle).not.toHaveBeenCalled();

      await svc.onModuleDestroy();
    });

    it('drops a stale self-ping of an earlier listener without handling or remembering it', async () => {
      const { svc, handle, onEventOfCall, handled } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);

      await onEventOfCall(0)({ ...request('e3'.padEnd(64, '0')), content: 'self-ping 7' });
      expect(handle).not.toHaveBeenCalled();
      expect(handled().size).toBe(0);

      await svc.onModuleDestroy();
    });

    it('stays bounded: past the cap the oldest ids go first', async () => {
      const { svc, handle, onEventOfCall, handled } = await makeService();
      svc.startListeningForKey('a'.repeat(64), 'b'.repeat(64), LISTEN);
      const onevent = onEventOfCall(0);
      const MAX = NOSTR_CONSTANTS.NIP46_HANDLED_EVENT_IDS_MAX;
      const id = (n: number) => n.toString(16).padStart(64, '0');

      for (let n = 0; n <= MAX; n++) await onevent(request(id(n)));
      expect(handled().size).toBe(MAX);
      expect(handle).toHaveBeenCalledTimes(MAX + 1);

      await onevent(request(id(MAX))); // the newest is still remembered
      expect(handle).toHaveBeenCalledTimes(MAX + 1);
      await onevent(request(id(0))); // the oldest was forgotten
      expect(handle).toHaveBeenCalledTimes(MAX + 2);

      await svc.onModuleDestroy();
    });
  });

  describe('per-relay subscriptions', () => {
    type Params = {
      onclose: (reasons: { url: string; reason: string }[]) => void;
      oneose?: () => void;
    };
    const PK = 'a'.repeat(64);
    const NSEC = 'b'.repeat(64);
    const two = ['wss://r1.example.com', 'wss://r2.example.com'];

    async function makeService(status = new Map<string, boolean>()) {
      const poolModule = await import('nostr-tools/pool');
      const closers: ReturnType<typeof vi.fn>[] = [];
      const subscribe = vi.fn().mockImplementation(() => {
        const close = vi.fn();
        closers.push(close);
        return { close };
      });
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe,
          close: vi.fn(),
          publish: vi.fn().mockReturnValue([]),
          listConnectionStatus: vi.fn().mockReturnValue(status),
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      const relaysOf = (n: number) => subscribe.mock.calls[n]?.[0] as string[];
      const paramsOf = (n: number) => subscribe.mock.calls[n]?.[2] as Params;
      return { svc, subscribe, relaysOf, paramsOf, closers };
    }

    // Jitter off: Math.random() = 0.5 leaves every delay exactly as configured.
    let random: { mockReturnValue(v: number): unknown; mockRestore(): void };
    beforeEach(() => {
      random = vi.spyOn(Math, 'random').mockReturnValue(0.5);
    });
    afterEach(() => {
      random.mockRestore();
      vi.useRealTimers();
    });

    it('subscribes to each relay separately', async () => {
      const { svc, subscribe, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, two);

      expect(subscribe).toHaveBeenCalledTimes(2);
      expect(relaysOf(0)).toEqual(['wss://r1.example.com']);
      expect(relaysOf(1)).toEqual(['wss://r2.example.com']);

      await svc.onModuleDestroy();
    });

    it('re-subscribes a relay that closed the subscription, after a backoff', async () => {
      // 2026-10-30: relay.ditto.pub answers a 21st subscription on one connection with
      // CLOSED "error: too many subscriptions"; the bunker never noticed and stayed deaf there.
      vi.useFakeTimers();
      const { svc, subscribe, relaysOf, paramsOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, two);

      const closed = [{ url: 'wss://r1.example.com/', reason: 'error: too many subscriptions' }];
      paramsOf(0).onclose(closed);
      expect(subscribe).toHaveBeenCalledTimes(2);

      vi.advanceTimersByTime(5_000);
      expect(subscribe).toHaveBeenCalledTimes(3);
      expect(relaysOf(2)).toEqual(['wss://r1.example.com']);

      await svc.onModuleDestroy();
    });

    it('does not re-subscribe after closing the subscription itself', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, paramsOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, ['wss://r1.example.com']);
      svc.stopListeningForKey(PK);

      paramsOf(0).onclose([{ url: 'wss://r1.example.com/', reason: 'closed by caller' }]);
      vi.advanceTimersByTime(60_000);
      expect(subscribe).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('backs off 5, 15, 30, then 60 s although a closing subscription reports EOSE first', async () => {
      // nostr-tools settles the EOSE of a subscription its relay closed just before onclose, so a
      // reset on EOSE kept every retry at 5 s (and every listener retrying on the same tick).
      vi.useFakeTimers();
      const { svc, subscribe, paramsOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, ['wss://r1.example.com']);

      let call = 0;
      for (const wait of [5_000, 15_000, 30_000, 60_000, 60_000]) {
        paramsOf(call).oneose?.();
        paramsOf(call).onclose([
          { url: 'wss://r1.example.com/', reason: 'error: too many subscriptions' },
        ]);
        await vi.advanceTimersByTimeAsync(wait - 1);
        expect(subscribe).toHaveBeenCalledTimes(call + 1);
        await vi.advanceTimersByTimeAsync(1);
        expect(subscribe).toHaveBeenCalledTimes(call + 2);
        call += 1;
      }

      await svc.onModuleDestroy();
    });

    it('starts the backoff over once a subscription stayed open for a minute', async () => {
      vi.useFakeTimers();
      // The relay's socket is up, so the watchdog leaves the subscription alone while it stays open.
      const { svc, subscribe, paramsOf } = await makeService(
        new Map([['wss://r1.example.com/', true]]),
      );
      svc.startListeningForKey(PK, NSEC, ['wss://r1.example.com']);
      const closed = [{ url: 'wss://r1.example.com/', reason: 'error: shutting down' }];

      paramsOf(0).onclose(closed);
      await vi.advanceTimersByTimeAsync(5_000); // call 1 opens
      paramsOf(1).onclose(closed);
      await vi.advanceTimersByTimeAsync(15_000); // call 2 opens, after the second step
      expect(subscribe).toHaveBeenCalledTimes(3);

      await vi.advanceTimersByTimeAsync(60_000); // call 2 stays open
      paramsOf(2).onclose(closed);
      await vi.advanceTimersByTimeAsync(5_000);
      expect(subscribe).toHaveBeenCalledTimes(4);

      await svc.onModuleDestroy();
    });

    it('spreads retries by up to 20% either way', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, paramsOf, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, two);
      const closed = (url: string) => [{ url, reason: 'error: too many subscriptions' }];

      random.mockReturnValue(0);
      paramsOf(0).onclose(closed('wss://r1.example.com/'));
      random.mockReturnValue(1);
      paramsOf(1).onclose(closed('wss://r2.example.com/'));

      await vi.advanceTimersByTimeAsync(4_000);
      expect(subscribe).toHaveBeenCalledTimes(3);
      expect(relaysOf(2)).toEqual(['wss://r1.example.com']);
      await vi.advanceTimersByTimeAsync(2_000);
      expect(subscribe).toHaveBeenCalledTimes(4);
      expect(relaysOf(3)).toEqual(['wss://r2.example.com']);

      await svc.onModuleDestroy();
    });

    it('leaves a relay on its backoff when the watchdog finds its connection dropped', async () => {
      vi.useFakeTimers();
      // No connection status: every relay reads as dropped to the watchdog.
      const { svc, subscribe, paramsOf, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, two);
      paramsOf(0).onclose([
        { url: 'wss://r1.example.com/', reason: 'error: too many subscriptions' },
      ]);

      (svc as unknown as { checkConnections(): void }).checkConnections();
      expect(subscribe).toHaveBeenCalledTimes(3);
      expect(relaysOf(2)).toEqual(['wss://r2.example.com']);

      await vi.advanceTimersByTimeAsync(5_000);
      expect(subscribe).toHaveBeenCalledTimes(4);
      expect(relaysOf(3)).toEqual(['wss://r1.example.com']);

      await svc.onModuleDestroy();
    });

    it('closes the old subscription when the watchdog opens a new one', async () => {
      const status = new Map([['wss://r2.example.com/', true]]);
      const { svc, closers } = await makeService(status);
      svc.startListeningForKey(PK, NSEC, two);

      (svc as unknown as { checkConnections(): void }).checkConnections();

      expect(closers[0]).toHaveBeenCalledTimes(1); // r1's, replaced
      expect(closers[1]).not.toHaveBeenCalled(); // r2's stays
      expect(closers[2]).not.toHaveBeenCalled(); // the new one

      await svc.onModuleDestroy();
    });

    it('opens one subscription per socket however a relay is spelled', async () => {
      // nostr-tools treats wss://x, wss://x/ and a differently cased host as one connection; a
      // subscription per spelling doubles them on it, and relays cap subscriptions per connection.
      const { svc, subscribe, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [
        'wss://r1.example.com',
        'wss://r1.example.com/',
        'wss://R1.example.com',
        'wss://r2.example.com',
      ]);
      expect(subscribe).toHaveBeenCalledTimes(2);
      expect(relaysOf(0)).toEqual(['wss://r1.example.com']);
      expect(relaysOf(1)).toEqual(['wss://r2.example.com']);

      // Another spelling of a relay it already listens on is no new relay: nothing is rebuilt.
      svc.startListeningForKey(PK, NSEC, ['wss://r2.example.com/']);
      expect(subscribe).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it("keeps the filter's since at now minus the window whatever nostr-tools writes to it", async () => {
      // On its own reconnect nostr-tools sets since = (newest event seen) + 1 on the object it was
      // given, and our pings (server clock) or an event dated ahead would then blind the
      // subscription to requests from a client with a slower clock.
      vi.useFakeTimers();
      const { svc, subscribe } = await makeService();
      svc.startListeningForKey(PK, NSEC, ['wss://r1.example.com']);
      const filter = subscribe.mock.calls[0]?.[1] as { since: number };
      const W = NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S;
      const sent = () => JSON.parse(JSON.stringify(filter)) as { since: number; kinds: number[] };

      filter.since = 4_000_000_000; // what the library writes
      expect(sent().since).toBe(Math.floor(Date.now() / 1000) - W);
      expect(sent().kinds).toEqual([NOSTR_CONSTANTS.NIP46_KIND]);

      await vi.advanceTimersByTimeAsync(3_600_000);
      expect(sent().since).toBe(Math.floor(Date.now() / 1000) - W);

      await svc.onModuleDestroy();
    });

    it('does not close a subscription its relay already closed', async () => {
      // nostr-tools counts a close down on the shared socket again, and the socket then idles out
      // under the other signers' live subscriptions.
      const { svc, paramsOf, closers } = await makeService();
      svc.startListeningForKey(PK, NSEC, two);
      paramsOf(0).onclose([
        { url: 'wss://r1.example.com/', reason: 'error: too many subscriptions' },
      ]);

      svc.stopListeningForKey(PK);

      expect(closers[0]).not.toHaveBeenCalled(); // r1: the relay closed it
      expect(closers[1]).toHaveBeenCalledTimes(1); // r2: still ours to close

      await svc.onModuleDestroy();
    });

    it('re-opens only the relay whose connection dropped', async () => {
      const status = new Map([['wss://r2.example.com/', true]]);
      const { svc, subscribe, relaysOf } = await makeService(status);
      svc.startListeningForKey(PK, NSEC, two);

      (svc as unknown as { checkConnections(): void }).checkConnections();
      expect(subscribe).toHaveBeenCalledTimes(3);
      expect(relaysOf(2)).toEqual(['wss://r1.example.com']);

      await svc.onModuleDestroy();
    });
  });

  describe('self-ping liveness', () => {
    type Event = { id: string; pubkey: string; content: string; created_at: number };
    type OnEvent = (event: Event) => Promise<void> | void;
    const PK = 'a'.repeat(64);
    const NSEC = 'b'.repeat(64);
    const R1 = 'wss://r1.example.com';
    const R2 = 'wss://r2.example.com';
    const FIRST = NOSTR_CONSTANTS.NIP46_SELF_PING_FIRST_MS;
    const EVERY = NOSTR_CONSTANTS.NIP46_SELF_PING_INTERVAL_MS;
    const WAIT = NOSTR_CONSTANTS.NIP46_SELF_PING_TIMEOUT_MS;

    async function makeService(outcome: () => Promise<string> = () => Promise.resolve('ok')) {
      const poolModule = await import('nostr-tools/pool');
      const subscribe = vi.fn().mockImplementation(() => ({ close: vi.fn() }));
      const published: { relays: string[]; event: Event }[] = [];
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe,
          close: vi.fn(),
          publish: vi.fn((relays: string[], event: Event) => {
            published.push({ relays, event });
            return [outcome()];
          }),
          // Both sockets up, so the watchdog never re-opens anything here.
          listConnectionStatus: vi.fn().mockReturnValue(
            new Map([
              [`${R1}/`, true],
              [`${R2}/`, true],
            ]),
          ),
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      const internals = svc as unknown as { handleIncomingEvent: () => Promise<boolean> };
      const handle = vi.spyOn(internals, 'handleIncomingEvent').mockResolvedValue(true);
      const onEventOf = (n: number) =>
        (subscribe.mock.calls[n]?.[2] as { onevent: OnEvent }).onevent;
      const relaysOf = (n: number) => subscribe.mock.calls[n]?.[0] as string[];
      return { svc, subscribe, published, handle, onEventOf, relaysOf };
    }

    // Jitter off: Math.random() = 0.5 leaves every delay exactly as configured.
    let random: { mockRestore(): void };
    beforeEach(() => {
      random = vi.spyOn(Math, 'random').mockReturnValue(0.5);
    });
    afterEach(() => {
      random.mockRestore();
      vi.useRealTimers();
    });

    it('drops its own self-pings; only the relay a ping went to can echo it', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, published, handle, onEventOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1, R2]);

      await vi.advanceTimersByTimeAsync(FIRST);
      expect(published.map((p) => p.relays)).toEqual([[R1], [R2]]);
      const [toR1, toR2] = published.map((p) => p.event);
      await onEventOf(1)(toR1!); // r1's self-ping, copied over to r2 by the relays
      await onEventOf(0)(toR1!);
      await onEventOf(1)(toR2!);
      expect(handle).not.toHaveBeenCalled();

      await onEventOf(0)({
        id: '4'.repeat(64),
        pubkey: 'c'.repeat(64),
        content: 'ciphertext',
        created_at: Math.floor(Date.now() / 1000),
      });
      expect(handle).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(WAIT);
      expect(subscribe).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it('re-subscribes a relay that echoed before, once it misses twice in a row', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, published, onEventOf, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1]);

      await vi.advanceTimersByTimeAsync(FIRST);
      await onEventOf(0)(published[0]!.event);

      await vi.advanceTimersByTimeAsync(EVERY + WAIT + 1);
      expect(published).toHaveLength(2);
      expect(subscribe).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(EVERY);
      expect(subscribe).toHaveBeenCalledTimes(2);
      expect(relaysOf(1)).toEqual([R1]);

      await svc.onModuleDestroy();
    });

    it('never re-subscribes a relay that has not echoed once', async () => {
      // relay.damus.io on 2026-10-31: accepted fresh-key kind-24133 events and delivered them to
      // nobody. Silence from such a relay says nothing about the subscription.
      vi.useFakeTimers();
      const { svc, subscribe, published } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1]);

      await vi.advanceTimersByTimeAsync(FIRST + 4 * EVERY + WAIT + 1);
      expect(published).toHaveLength(5);
      expect(subscribe).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('does not count a self-ping the relay refused as a miss', async () => {
      vi.useFakeTimers();
      let refuse = false;
      const { svc, subscribe, published, onEventOf } = await makeService(() =>
        refuse ? Promise.reject(new Error('blocked: kind not allowed')) : Promise.resolve('ok'),
      );
      svc.startListeningForKey(PK, NSEC, [R1]);
      await vi.advanceTimersByTimeAsync(FIRST);
      await onEventOf(0)(published[0]!.event);

      refuse = true;
      await vi.advanceTimersByTimeAsync(3 * EVERY + WAIT + 1);
      expect(published).toHaveLength(4);
      expect(subscribe).toHaveBeenCalledTimes(1);

      await svc.onModuleDestroy();
    });

    it('does not ping a relay whose subscription is waiting for its retry', async () => {
      // The ping would go out while nothing listens; the retry then lands before the ping times
      // out, and the silence would count as a miss.
      vi.useFakeTimers();
      const { svc, subscribe, published } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1]);
      await vi.advanceTimersByTimeAsync(FIRST - 1_000);
      const params = subscribe.mock.calls[0]?.[2] as {
        onclose: (reasons: { url: string; reason: string }[]) => void;
      };
      params.onclose([{ url: `${R1}/`, reason: 'error: too many subscriptions' }]); // retry at +5 s

      await vi.advanceTimersByTimeAsync(1_000); // the round fires
      expect(published).toHaveLength(0);

      await svc.onModuleDestroy();
    });

    it('stops pinging once the listener is stopped, leaving no timer behind', async () => {
      vi.useFakeTimers();
      const { svc, published } = await makeService();
      const before = vi.getTimerCount(); // the watchdog's
      svc.startListeningForKey(PK, NSEC, [R1]);
      expect(vi.getTimerCount()).toBeGreaterThan(before);
      svc.stopListeningForKey(PK);
      expect(vi.getTimerCount()).toBe(before);

      await vi.advanceTimersByTimeAsync(FIRST + EVERY);
      expect(published).toHaveLength(0);

      await svc.onModuleDestroy();
    });

    it('signs its pings with a throwaway key: one distinct event per relay', async () => {
      // Same author, kind, tags and second would give every relay of a round the same id.
      vi.useFakeTimers();
      const { svc, published } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1, R2]);
      await vi.advanceTimersByTimeAsync(FIRST);

      const [a, b] = published.map((p) => p.event as unknown as Parameters<typeof verifyEvent>[0]);
      expect(a!.id).not.toBe(b!.id);
      expect(a!.pubkey).toBe(b!.pubkey);
      expect(a!.pubkey).not.toBe(PK);
      expect(a!.pubkey).not.toBe(getPublicKey(hexToBytes(NSEC)));
      expect(verifyEvent(a!)).toBe(true);
      expect(a!.tags).toEqual([['p', PK]]);

      await svc.onModuleDestroy();
    });

    it('recognises the echo of every relay of a round, not only the last one', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, published, onEventOf, relaysOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1, R2]);
      await vi.advanceTimersByTimeAsync(FIRST);
      await onEventOf(0)(published[0]!.event);
      await onEventOf(1)(published[1]!.event);
      await vi.advanceTimersByTimeAsync(WAIT);
      expect(subscribe).toHaveBeenCalledTimes(2);

      // Both relays have echoed, so one that then goes quiet is noticed; r2 keeps echoing.
      await vi.advanceTimersByTimeAsync(EVERY - WAIT); // round 2
      await onEventOf(1)(published[3]!.event);
      await vi.advanceTimersByTimeAsync(WAIT);
      await vi.advanceTimersByTimeAsync(EVERY - WAIT); // round 3
      await onEventOf(1)(published[5]!.event);
      await vi.advanceTimersByTimeAsync(WAIT);

      expect(subscribe).toHaveBeenCalledTimes(3);
      expect(relaysOf(2)).toEqual([R1]);

      await svc.onModuleDestroy();
    });

    it("does not take another relay's copy of a ping for an echo", async () => {
      vi.useFakeTimers();
      const { svc, subscribe, published, onEventOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1, R2]);
      await vi.advanceTimersByTimeAsync(FIRST);
      await onEventOf(1)(published[0]!.event); // r1's ping, copied to r2's subscription

      // r1 never echoed on its own subscription, so silence from it proves nothing.
      await vi.advanceTimersByTimeAsync(4 * EVERY + WAIT);
      expect(subscribe).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });

    it('needs two misses IN A ROW: an echo in between starts the count over', async () => {
      vi.useFakeTimers();
      const { svc, subscribe, published, onEventOf } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1]);
      await vi.advanceTimersByTimeAsync(FIRST);
      await onEventOf(0)(published[0]!.event);

      await vi.advanceTimersByTimeAsync(EVERY + WAIT + 1); // round 2 unanswered: 1 miss
      await vi.advanceTimersByTimeAsync(EVERY - WAIT - 1); // round 3 starts
      await onEventOf(0)(published[2]!.event); // answered: count back to 0
      await vi.advanceTimersByTimeAsync(EVERY + WAIT + 1); // round 4 unanswered: 1 miss
      expect(subscribe).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(EVERY); // round 5 unanswered: 2 in a row
      expect(subscribe).toHaveBeenCalledTimes(2);

      await svc.onModuleDestroy();
    });
  });

  describe('unsupported methods', () => {
    const signerSk = generateSecretKey();
    const signerPk = getPublicKey(signerSk);
    const clientSk = generateSecretKey();
    const clientPk = getPublicKey(clientSk);
    const relays = ['wss://r.example.com'];

    async function makeService() {
      const poolModule = await import('nostr-tools/pool');
      const publish = vi.fn().mockReturnValue([Promise.resolve('ok')]);
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe: vi.fn().mockReturnValue({ close: vi.fn() }),
          close: vi.fn(),
          publish,
          listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      return { svc, publish };
    }

    // Hand the service a request exactly as a relay would deliver it: encrypted by the client.
    // rpcHandler has no handleRequest here, so reaching the normal path would throw.
    async function deliver(svc: BunkerService, request: unknown) {
      const ck = nip44.v2.utils.getConversationKey(clientSk, signerPk);
      const event = { pubkey: clientPk, content: nip44.v2.encrypt(JSON.stringify(request), ck) };
      const internals = svc as unknown as {
        handleIncomingEvent(e: object, nsec: string, pk: string, r: string[]): Promise<void>;
      };
      await internals.handleIncomingEvent(event, bytesToHex(signerSk), signerPk, relays);
    }

    function readReply(publish: ReturnType<typeof vi.fn>) {
      const [to, event] = publish.mock.calls[0] as [
        string[],
        { content: string; tags: string[][] },
      ];
      const ck = nip44.v2.utils.getConversationKey(clientSk, signerPk);
      return { to, tags: event.tags, reply: JSON.parse(nip44.v2.decrypt(event.content, ck)) };
    }

    it('replies with an error to an unknown method such as logout', async () => {
      const { svc, publish } = await makeService();
      await deliver(svc, { id: 'req-1', method: 'logout', params: [] });

      expect(publish).toHaveBeenCalledTimes(1);
      const { to, tags, reply } = readReply(publish);
      expect(to).toEqual(relays);
      expect(tags).toEqual([['p', clientPk]]);
      expect(reply).toEqual({ id: 'req-1', error: 'unsupported method: logout' });

      await svc.onModuleDestroy();
    });

    it('neutralises characters outside [A-Za-z0-9_] in the echoed method', async () => {
      const { svc, publish } = await makeService();
      await deliver(svc, { id: 'req-2', method: 'log\nout<x>', params: [] });

      expect(readReply(publish).reply).toEqual({
        id: 'req-2',
        error: 'unsupported method: log?out?x?',
      });

      await svc.onModuleDestroy();
    });

    it('still drops a known method whose params are malformed', async () => {
      const { svc, publish } = await makeService();
      await deliver(svc, { id: 'req-3', method: 'sign_event', params: [42] });

      expect(publish).not.toHaveBeenCalled();

      await svc.onModuleDestroy();
    });
  });

  describe('reply publish outcome', () => {
    const signerSk = generateSecretKey();
    const clientPk = getPublicKey(generateSecretKey());
    const relays = ['wss://a.example.com', 'wss://b.example.com'];

    async function makeService(publish: ReturnType<typeof vi.fn>) {
      const poolModule = await import('nostr-tools/pool');
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe: vi.fn().mockReturnValue({ close: vi.fn() }),
          close: vi.fn(),
          publish,
          listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
        };
      });
      const svc = new BunkerService(
        rpcHandler as BunkerRpcHandler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        approvals as ApprovalService,
      );
      await svc.onModuleInit();
      const internals = svc as unknown as {
        logger: { warn(m: string): void; error(m: string): void };
        sendResponse(r: object, m: string, pk: string, sk: Uint8Array, to: string[]): Promise<void>;
      };
      const warn = vi.spyOn(internals.logger, 'warn');
      const error = vi.spyOn(internals.logger, 'error');
      const send = () =>
        internals.sendResponse({ id: 'r1', result: 'ack' }, 'ping', clientPk, signerSk, relays);
      return { svc, warn, error, send };
    }

    const publishWarnings = (warn: ReturnType<typeof vi.spyOn>) =>
      warn.mock.calls.map(([m]) => String(m)).filter((m) => m.includes('reply publish'));

    it('warns with every relay outcome when one refuses the reply', async () => {
      // Rejected lazily, so the promise never sits without a handler.
      const refuse = () => Promise.reject(new Error('rate-limited: slow\n'));
      const publish = vi.fn(() => [Promise.resolve('ok'), refuse()]);
      const { svc, warn, send } = await makeService(publish);
      await send();

      await vi.waitFor(() => expect(publishWarnings(warn)).toHaveLength(1));
      const [line] = publishWarnings(warn);
      expect(line).toMatch(/^NIP-46 ping reply publish: a\.example\.com ok \d+ms, /);
      expect(line).toContain('b.example.com failed (Error: rate-limited: slow?)');

      await svc.onModuleDestroy();
    });

    it('stays quiet when every relay accepts promptly', async () => {
      const publish = vi.fn().mockReturnValue([Promise.resolve('ok'), Promise.resolve('ok')]);
      const { svc, warn, send } = await makeService(publish);
      await send();
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(publishWarnings(warn)).toHaveLength(0);

      await svc.onModuleDestroy();
    });

    it('contains a pool result it cannot read instead of rejecting unhandled', async () => {
      const { svc, error, send } = await makeService(vi.fn().mockReturnValue(undefined));
      await send();
      await new Promise((resolve) => setTimeout(resolve, 0));

      expect(error).toHaveBeenCalledWith(
        expect.stringContaining('Failed to publish NIP-46 response'),
      );

      await svc.onModuleDestroy();
    });
  });
  describe('hold and ask', () => {
    type OnEvent = (event: {
      id: string;
      pubkey: string;
      content: string;
      created_at: number;
    }) => Promise<void>;

    const signerSk = generateSecretKey();
    const signerPk = getPublicKey(signerSk);
    const signerNsec = bytesToHex(signerSk);
    const clientSk = generateSecretKey();
    const clientPk = getPublicKey(clientSk);
    const relays = ['wss://r.example.com'];
    const BASE = 'https://signer.example.test:50217';
    const DENIED = 'Permission denied for sign_event kind:27235';
    const SIGNED = '{"signed":true}';

    /**
     * A real ApprovalService and real nip44 on the wire; only the RPC handler is stubbed. It holds
     * the first pass of a request and answers the second by the outcome it is handed, the way the
     * real handler does (its own spec covers the decisions themselves).
     */
    async function setup(
      opts: { publicBaseUrl?: string | undefined; recheckThrows?: boolean } = {},
    ) {
      const publicBaseUrl = 'publicBaseUrl' in opts ? opts.publicBaseUrl : BASE;
      const poolModule = await import('nostr-tools/pool');
      const subscribe = vi.fn().mockReturnValue({ close: vi.fn() });
      const publish = vi.fn().mockReturnValue([Promise.resolve('ok')]);
      vi.mocked(poolModule.SimplePool).mockImplementationOnce(function (this: unknown) {
        return {
          subscribe,
          close: vi.fn(),
          publish,
          listConnectionStatus: vi.fn().mockReturnValue(new Map<string, boolean>()),
        };
      });
      const real = new ApprovalService({ ttlMs: 100_000, publicBaseUrl }, {
        publishUserActivity: vi.fn().mockResolvedValue(undefined),
      } as unknown as EventsService);
      const passes: Array<{ id: string; resolution: unknown }> = [];
      const handleRequest = vi.fn(async (...args: unknown[]) => {
        const req = args[2] as Nip46Request;
        const resolution = args[9];
        const holdAllowed = args[10];
        passes.push({ id: req.id, resolution });
        // The real handler refuses at once when the caller says the request may not be held.
        if (resolution === undefined && holdAllowed === false) {
          return { id: req.id, error: DENIED };
        }
        if (resolution === undefined) {
          const hold = real.open({
            userId: 'user-1',
            connectionId: 'conn-1',
            connectionName: 'BIES',
            clientPubkey: clientPk,
            requestId: req.id,
            fingerprint: JSON.stringify(req.params),
            permission: { method: 'sign_event', kind: 27235 },
          })!;
          return { id: req.id, hold };
        }
        if (opts.recheckThrows) throw new Error('database is down');
        if (resolution === 'approved_once' || resolution === 'approved_always') {
          return { id: req.id, result: SIGNED };
        }
        return { id: req.id, error: DENIED };
      });
      const handler = {
        setPendingSecretLookup: vi.fn(),
        setBaseRelayLookup: vi.fn(),
        handleRequest,
      } as unknown as BunkerRpcHandler;
      const svc = new BunkerService(
        handler,
        prisma as PrismaService,
        encryption as EncryptionService,
        [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
        real,
      );
      await svc.onModuleInit();
      return { svc, real, publish, subscribe, handleRequest, passes };
    }

    const ck = () => nip44.v2.utils.getConversationKey(clientSk, signerPk);
    const wireEvent = (id: string, request: unknown) => ({
      id,
      pubkey: clientPk,
      content: nip44.v2.encrypt(JSON.stringify(request), ck()),
      created_at: Math.floor(Date.now() / 1000),
    });
    const loginRequest = (id = 'req-1') => ({
      id,
      method: 'sign_event',
      params: [JSON.stringify({ kind: 27235, content: '', tags: [] })],
    });
    const deliver = (svc: BunkerService, request: unknown) =>
      (
        svc as unknown as {
          handleIncomingEvent(e: object, nsec: string, pk: string, r: string[]): Promise<boolean>;
        }
      ).handleIncomingEvent(wireEvent('e'.repeat(64), request), signerNsec, signerPk, relays);
    const deliverEvent = (svc: BunkerService, event: object) =>
      (
        svc as unknown as {
          handleIncomingEvent(e: object, nsec: string, pk: string, r: string[]): Promise<boolean>;
        }
      ).handleIncomingEvent(event, signerNsec, signerPk, relays);
    const replies = (publish: ReturnType<typeof vi.fn>) =>
      publish.mock.calls.map(([, event]) => {
        const e = event as { content: string };
        return JSON.parse(nip44.v2.decrypt(e.content, ck())) as Record<string, unknown>;
      });
    // Let queued promise callbacks run (setImmediate is not faked below).
    const settle = () => new Promise<void>((resolve) => setImmediate(resolve));

    beforeEach(() => {
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('sends ONE interim auth_url, then the final reply under the same id (approve once)', async () => {
      const { svc, real, publish, passes } = await setup();
      const done = deliver(svc, loginRequest('req-42'));
      await settle();

      // While the operator decides: exactly the interim, nothing else.
      const held = real.list('user-1');
      expect(held).toHaveLength(1);
      expect(replies(publish)).toEqual([
        { id: 'req-42', result: 'auth_url', error: `${BASE}/approvals/${held[0]!.token}` },
      ]);

      real.resolve(held[0]!.token, 'user-1', 'approved_once');
      // true: the request was answered (twice), which is what lets the replay guard remember it.
      expect(await done).toBe(true);

      const all = replies(publish);
      expect(all).toHaveLength(2);
      expect(all[1]).toEqual({ id: 'req-42', result: SIGNED });
      expect(all.filter((r) => r['result'] === 'auth_url')).toHaveLength(1);
      // The request went through the handler again, told how the hold ended.
      expect(passes).toEqual([
        { id: 'req-42', resolution: undefined },
        { id: 'req-42', resolution: 'approved_once' },
      ]);
      await svc.onModuleDestroy();
    });

    it('always allow: the handler is told, and the client gets the signature', async () => {
      const { svc, real, publish, passes } = await setup();
      const done = deliver(svc, loginRequest());
      await settle();
      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'approved_always');
      await done;
      expect(passes[1]?.resolution).toBe('approved_always');
      expect(replies(publish)[1]).toEqual({ id: 'req-1', result: SIGNED });
      await svc.onModuleDestroy();
    });

    it('deny: the final reply is the unchanged permission text', async () => {
      const { svc, real, publish, passes } = await setup();
      const done = deliver(svc, loginRequest());
      await settle();
      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'denied');
      expect(await done).toBe(true);
      expect(passes[1]?.resolution).toBe('denied');
      expect(replies(publish)[1]).toEqual({ id: 'req-1', error: DENIED });
      await svc.onModuleDestroy();
    });

    it('timeout: answered as denied once the TTL passes, with no reply before that', async () => {
      const { svc, publish, passes } = await setup();
      const done = deliver(svc, loginRequest());
      await settle();

      vi.advanceTimersByTime(99_999);
      await settle();
      expect(replies(publish)).toHaveLength(1); // still just the interim

      vi.advanceTimersByTime(1);
      expect(await done).toBe(true);
      expect(passes[1]?.resolution).toBe('expired');
      expect(replies(publish)[1]).toEqual({ id: 'req-1', error: DENIED });
      await svc.onModuleDestroy();
    });

    it('revoked or deleted while held: the wait ends at once and is re-checked as cancelled', async () => {
      const { svc, real, publish, passes } = await setup();
      const done = deliver(svc, loginRequest());
      await settle();
      real.cancelForConnection('conn-1');
      await done;
      expect(passes[1]?.resolution).toBe('cancelled');
      expect(replies(publish)[1]).toEqual({ id: 'req-1', error: DENIED });
      await svc.onModuleDestroy();
    });

    it('a retry with a NEW event but the same request id shares the hold: one auth_url and ONE answer', async () => {
      const { svc, real, publish, passes } = await setup();
      const first = deliverEvent(svc, wireEvent('1'.repeat(64), loginRequest('req-7')));
      await settle();
      // The retry is acknowledged at once (so a redelivery of it is ignored): it adds no waiter of
      // its own to answer, sign or log when the hold ends.
      expect(await deliverEvent(svc, wireEvent('2'.repeat(64), loginRequest('req-7')))).toBe(true);

      // BIES treats a second auth_url for one id as a refusal: there must be exactly one.
      expect(real.list('user-1')).toHaveLength(1);
      expect(replies(publish).filter((r) => r['result'] === 'auth_url')).toHaveLength(1);

      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'denied');
      expect(await first).toBe(true);
      const finals = replies(publish).filter((r) => r['result'] !== 'auth_url');
      expect(finals).toEqual([{ id: 'req-7', error: DENIED }]);
      expect(passes.filter((p) => p.resolution !== undefined)).toHaveLength(1);
      await svc.onModuleDestroy();
    });

    it('a client parking events under one request id gets ONE answer, ONE signature and ONE audit pass', async () => {
      const { svc, real, publish, passes } = await setup();
      const first = deliverEvent(svc, wireEvent('1'.repeat(64), loginRequest('req-9')));
      await settle();
      // Same id, same params, a different event id each time.
      const others: boolean[] = [];
      for (let i = 2; i <= 30; i++) {
        others.push(
          await deliverEvent(
            svc,
            wireEvent(
              String(i % 10).repeat(60) + String(i).padStart(4, '0'),
              loginRequest('req-9'),
            ),
          ),
        );
      }
      // The retry is acknowledged; every one past it is dropped without being remembered, so a
      // flood of them cannot push real event ids out of the replay guard.
      expect(others[0]).toBe(true);
      expect(others.slice(1).every((handled) => handled === false)).toBe(true);
      expect(real.list('user-1')).toHaveLength(1);

      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'approved_once');
      // The first event still answers normally, whatever was parked beside it.
      expect(await first).toBe(true);
      const all = replies(publish);
      expect(all.filter((r) => r['result'] === 'auth_url')).toHaveLength(1);
      expect(all.filter((r) => r['result'] === SIGNED)).toEqual([{ id: 'req-9', result: SIGNED }]);
      expect(all).toHaveLength(2);
      expect(passes.filter((p) => p.resolution === 'approved_once')).toHaveLength(1);
      await svc.onModuleDestroy();
    });

    it('a request created before this process started is never held: relays redeliver it after a restart, and its client has long been answered', async () => {
      const { svc, real, publish } = await setup();
      const old = {
        ...wireEvent('3'.repeat(64), loginRequest('req-old')),
        created_at: Math.floor(Date.now() / 1000) - 120,
      };
      expect(await deliverEvent(svc, old)).toBe(true);
      expect(real.list('user-1')).toHaveLength(0);
      expect(replies(publish)).toEqual([{ id: 'req-old', error: DENIED }]);
      await svc.onModuleDestroy();
    });

    it('a hold without a link to give sends no interim (the handler never opens one then: this is the service alone)', async () => {
      const { svc, real, publish } = await setup({ publicBaseUrl: undefined });
      const done = deliver(svc, loginRequest());
      await settle();
      expect(publish).not.toHaveBeenCalled();
      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'approved_once');
      await done;
      expect(replies(publish)).toEqual([{ id: 'req-1', result: SIGNED }]);
      await svc.onModuleDestroy();
    });

    it('answers even when the re-check fails: the client is never left waiting in silence', async () => {
      const { svc, real, publish } = await setup({ recheckThrows: true });
      const done = deliver(svc, loginRequest());
      await settle();
      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'approved_once');
      // Answered with an error, but answered: a re-delivery must not be held and asked again.
      expect(await done).toBe(true);
      expect(replies(publish)[1]).toEqual({ id: 'req-1', error: 'Internal error' });
      await svc.onModuleDestroy();
    });

    it('never puts the hold, or its token, anywhere but the interim link', async () => {
      const { svc, real, publish } = await setup();
      const done = deliver(svc, loginRequest());
      await settle();
      const { token } = real.list('user-1')[0]!;
      real.resolve(token, 'user-1', 'approved_once');
      await done;

      const all = replies(publish);
      for (const reply of all) {
        expect(Object.keys(reply).every((k) => ['id', 'result', 'error'].includes(k))).toBe(true);
      }
      expect(JSON.stringify(all[1])).not.toContain(token);
      await svc.onModuleDestroy();
    });

    it('a request that is not held gets exactly one reply and no interim', async () => {
      const { svc, publish, handleRequest } = await setup();
      handleRequest.mockResolvedValueOnce({ id: 'p1', result: 'pong' } as never);
      await deliver(svc, { id: 'p1', method: 'ping', params: [] });
      expect(replies(publish)).toEqual([{ id: 'p1', result: 'pong' }]);
      await svc.onModuleDestroy();
    });

    it('a request re-delivered by a relay while it is held is not held a second time', async () => {
      const { svc, real, publish, subscribe, handleRequest } = await setup();
      svc.startListeningForKey(signerPk, signerNsec, relays);
      const onevent = (subscribe.mock.calls[0]?.[2] as { onevent: OnEvent }).onevent;
      const event = wireEvent('f'.repeat(64), loginRequest('req-9'));

      const first = onevent(event);
      await settle();
      await onevent(event); // the relay hands it back, e.g. after a re-subscribe
      await onevent(event);

      expect(handleRequest).toHaveBeenCalledTimes(1);
      expect(real.list('user-1')).toHaveLength(1);
      expect(replies(publish).filter((r) => r['result'] === 'auth_url')).toHaveLength(1);

      // Nothing is remembered while the request is waiting: the guard marks it only once answered.
      const remembered = () =>
        (svc as unknown as { handledEventIds: Map<string, number> }).handledEventIds.size;
      expect(remembered()).toBe(0);

      real.resolve(real.list('user-1')[0]!.token, 'user-1', 'approved_once');
      await first;
      expect(remembered()).toBe(1);

      // Answered, so a copy that arrives afterwards is dropped: it is neither held nor signed again.
      const passesBefore = handleRequest.mock.calls.length;
      await onevent(event);
      expect(handleRequest.mock.calls.length).toBe(passesBefore);
      expect(real.size).toBe(0);
      expect(replies(publish).filter((r) => r['result'] === SIGNED)).toHaveLength(1);
      await svc.onModuleDestroy();
    });
  });
});
