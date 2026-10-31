import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NOSTR_CONSTANTS } from '@bunker46/config';
import { BunkerService } from './bunker.service.js';
import type { PrismaService } from '../prisma/prisma.service.js';
import type { BunkerRpcHandler } from './bunker-rpc.handler.js';
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

  beforeEach(async () => {
    vi.clearAllMocks();
    prisma = {
      nsecKey: {
        findMany: vi.fn().mockResolvedValue([]),
        findUnique: vi.fn().mockResolvedValue(null),
      },
      relayConfig: { findMany: vi.fn().mockResolvedValue([]) },
    };
    encryption = { decrypt: vi.fn().mockReturnValue('decrypted-nsec-hex') };
    rpcHandler = { setPendingSecretLookup: vi.fn() };
    service = new BunkerService(
      rpcHandler as BunkerRpcHandler,
      prisma as PrismaService,
      encryption as EncryptionService,
      [...NOSTR_CONSTANTS.DEFAULT_RELAYS],
    );
    await service.onModuleInit();
  });

  afterEach(async () => {
    await service.onModuleDestroy();
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
      service.startListeningForKey('f'.repeat(64), 'g'.repeat(64), []);
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
  });

  describe('replay guard', () => {
    type OnEvent = (event: { id: string; pubkey: string; content: string }) => Promise<void>;

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
      );
      await svc.onModuleInit();
      // Count the requests that reach the decrypt-and-answer path without running it.
      const internals = svc as unknown as { handleIncomingEvent: () => Promise<void> };
      const handle = vi.spyOn(internals, 'handleIncomingEvent');
      handle.mockResolvedValue(undefined);
      const onEventOfCall = (n: number) =>
        (subscribe.mock.calls[n]?.[2] as { onevent: OnEvent }).onevent;
      return { svc, subscribe, handle, onEventOfCall };
    }

    const request = (id: string) => ({ id, pubkey: 'c'.repeat(64), content: 'ciphertext' });

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
  });

  describe('per-relay subscriptions', () => {
    type Params = {
      onclose: (reasons: { url: string; reason: string }[]) => void;
      oneose: () => void;
    };
    const PK = 'a'.repeat(64);
    const NSEC = 'b'.repeat(64);
    const two = ['wss://r1.example.com', 'wss://r2.example.com'];

    async function makeService(status = new Map<string, boolean>()) {
      const poolModule = await import('nostr-tools/pool');
      const subscribe = vi.fn().mockImplementation(() => ({ close: vi.fn() }));
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
      );
      await svc.onModuleInit();
      const relaysOf = (n: number) => subscribe.mock.calls[n]?.[0] as string[];
      const paramsOf = (n: number) => subscribe.mock.calls[n]?.[2] as Params;
      return { svc, subscribe, relaysOf, paramsOf };
    }

    afterEach(() => {
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
    type Event = { id: string; pubkey: string; content: string };
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
      );
      await svc.onModuleInit();
      const internals = svc as unknown as { handleIncomingEvent: () => Promise<void> };
      const handle = vi.spyOn(internals, 'handleIncomingEvent').mockResolvedValue(undefined);
      const onEventOf = (n: number) =>
        (subscribe.mock.calls[n]?.[2] as { onevent: OnEvent }).onevent;
      const relaysOf = (n: number) => subscribe.mock.calls[n]?.[0] as string[];
      return { svc, subscribe, published, handle, onEventOf, relaysOf };
    }

    afterEach(() => {
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

      await onEventOf(0)({ id: '4'.repeat(64), pubkey: 'c'.repeat(64), content: 'ciphertext' });
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

    it('stops pinging once the listener is stopped', async () => {
      vi.useFakeTimers();
      const { svc, published } = await makeService();
      svc.startListeningForKey(PK, NSEC, [R1]);
      svc.stopListeningForKey(PK);

      await vi.advanceTimersByTimeAsync(FIRST + EVERY);
      expect(published).toHaveLength(0);

      await svc.onModuleDestroy();
    });
  });
});
