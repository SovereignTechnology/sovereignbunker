import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { PendingApprovalDto } from '@bunker46/shared-types';

const apiGet = vi.fn();
vi.mock('@/lib/api', () => ({ api: { get: (...a: unknown[]) => apiGet(...a) } }));

type Handlers = { onActivity: () => void; onOpen?: () => void; onUnavailable?: () => void };
let streams: Array<{ handlers: Handlers; stop: ReturnType<typeof vi.fn> }> = [];
vi.mock('@/composables/useActivityStream', () => ({
  connectActivityStream: (handlers: Handlers) => {
    const stop = vi.fn();
    streams.push({ handlers, stop });
    return stop;
  },
}));

import {
  $approvals,
  $approvalsCanAsk,
  $approvalsError,
  $approvalsLoaded,
  $pendingApprovalCount,
  refreshApprovals,
  startApprovalWatch,
  stopApprovalWatch,
} from './approvals.js';

const item = (token: string): PendingApprovalDto => ({
  token,
  connectionId: 'c1',
  connectionName: 'BIES',
  clientPubkey: 'a'.repeat(64),
  method: 'sign_event',
  kind: 27235,
  createdAt: '2026-11-24T12:00:00.000Z',
  expiresAt: '2026-11-24T12:01:40.000Z',
});
const reply = (...tokens: string[]) => ({ approvals: tokens.map(item), canAsk: true });
const flush = () => vi.advanceTimersByTimeAsync(0);

describe('approvals store', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    apiGet.mockReset();
    streams = [];
    stopApprovalWatch();
  });
  afterEach(() => {
    stopApprovalWatch();
    vi.useRealTimers();
  });

  describe('refreshApprovals', () => {
    it('loads the list and counts it', async () => {
      apiGet.mockResolvedValue(reply('a', 'b'));
      await expect(refreshApprovals()).resolves.toBe(true);
      expect(apiGet).toHaveBeenCalledWith('/approvals');
      expect($approvals.get().map((a) => a.token)).toEqual(['a', 'b']);
      expect($pendingApprovalCount.get()).toBe(2);
      expect($approvalsLoaded.get()).toBe(true);
    });

    it('remembers whether the server can ask at all (it has no link to send without PUBLIC_BASE_URL)', async () => {
      expect($approvalsCanAsk.get()).toBe(true);
      apiGet.mockResolvedValueOnce({ approvals: [], canAsk: false });
      await refreshApprovals();
      expect($approvalsCanAsk.get()).toBe(false);
      apiGet.mockResolvedValueOnce({ approvals: [], canAsk: true });
      await refreshApprovals();
      expect($approvalsCanAsk.get()).toBe(true);
    });

    it('surfaces a failure instead of swallowing it, and clears it once a refresh works', async () => {
      apiGet.mockRejectedValueOnce(new Error('ThrottlerException: Too Many Requests'));
      await expect(refreshApprovals()).resolves.toBe(false);
      expect($approvalsError.get()).toContain('Too Many Requests');
      expect($approvalsLoaded.get()).toBe(false);
      apiGet.mockResolvedValueOnce(reply('a'));
      await refreshApprovals();
      expect($approvalsError.get()).toBe('');
      expect($approvalsLoaded.get()).toBe(true);
    });

    it('keeps the last list when a refresh fails', async () => {
      apiGet.mockResolvedValueOnce(reply('a'));
      await refreshApprovals();
      apiGet.mockRejectedValueOnce(new Error('offline'));
      await expect(refreshApprovals()).resolves.toBe(false);
      expect($approvals.get().map((a) => a.token)).toEqual(['a']);
    });
  });

  describe('overlapping refreshes', () => {
    const deferred = () => {
      let resolve!: (v: unknown) => void;
      const promise = new Promise((r) => (resolve = r));
      return { promise, resolve };
    };

    it('an older answer that lands last does not replace a newer one', async () => {
      const older = deferred();
      const newer = deferred();
      apiGet.mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise);
      const first = refreshApprovals();
      const second = refreshApprovals();
      newer.resolve(reply('new'));
      await second;
      older.resolve(reply('old', 'stale'));
      await expect(first).resolves.toBe(true);
      expect($approvals.get().map((a) => a.token)).toEqual(['new']);
    });

    it('an answer that started before the watch stopped is dropped', async () => {
      const slow = deferred();
      apiGet.mockReturnValueOnce(slow.promise);
      const pending = refreshApprovals();
      stopApprovalWatch();
      slow.resolve(reply('previous-session'));
      await expect(pending).resolves.toBe(false);
      expect($approvals.get()).toEqual([]);
      expect($approvalsLoaded.get()).toBe(false);
    });
  });

  describe('watching', () => {
    it('loads at once and opens one stream; starting twice changes nothing', async () => {
      apiGet.mockResolvedValue(reply('a'));
      startApprovalWatch();
      startApprovalWatch();
      await flush();
      expect(apiGet).toHaveBeenCalledTimes(1);
      expect(streams).toHaveLength(1);
      expect($pendingApprovalCount.get()).toBe(1);
    });

    it('reloads when the server pushes an activity event, a second after the last one', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockResolvedValue(reply('x', 'y', 'z'));
      streams[0]!.handlers.onActivity();
      await vi.advanceTimersByTimeAsync(999);
      expect($pendingApprovalCount.get()).toBe(0);
      await vi.advanceTimersByTimeAsync(1);
      expect($pendingApprovalCount.get()).toBe(3);
    });

    it('a steady stream of events still refreshes about once a second: it cannot starve the list (a throttle, not a debounce)', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockClear();
      // A busy client: an event every 500 ms for ten seconds. A timer that restarts on every event
      // would never fire until the events stopped, and the list would not move.
      for (let i = 0; i < 20; i++) {
        streams[0]!.handlers.onActivity();
        await vi.advanceTimersByTimeAsync(500);
      }
      expect(apiGet.mock.calls.length).toBeGreaterThanOrEqual(9);
      expect(apiGet.mock.calls.length).toBeLessThanOrEqual(11);
    });

    it('the first event of a run waits one second, and later ones in that second do not push it back', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockResolvedValue(reply('x'));
      streams[0]!.handlers.onActivity();
      await vi.advanceTimersByTimeAsync(900);
      streams[0]!.handlers.onActivity();
      await vi.advanceTimersByTimeAsync(99);
      expect($pendingApprovalCount.get()).toBe(0);
      await vi.advanceTimersByTimeAsync(1);
      // One second after the FIRST event, although another came 100 ms before.
      expect($pendingApprovalCount.get()).toBe(1);
    });

    it('a burst of activity events is a handful of reloads, never one per event: a client spamming ping cannot push the page past its rate limit', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockClear();
      for (let i = 0; i < 200; i++) {
        streams[0]!.handlers.onActivity();
        await vi.advanceTimersByTimeAsync(10);
      }
      await vi.advanceTimersByTimeAsync(1_000);
      // 200 events over two seconds: one reload per second.
      expect(apiGet.mock.calls.length).toBeGreaterThanOrEqual(2);
      expect(apiGet.mock.calls.length).toBeLessThanOrEqual(3);
    });

    it('a quiet stream costs nothing: no event, no reload', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      streams[0]!.handlers.onOpen?.();
      await flush();
      apiGet.mockClear();
      await vi.advanceTimersByTimeAsync(20_000);
      expect(apiGet).not.toHaveBeenCalled();
    });

    it('a pending reload does not outlive the watch', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockClear();
      streams[0]!.handlers.onActivity();
      stopApprovalWatch();
      await vi.advanceTimersByTimeAsync(5_000);
      expect(apiGet).not.toHaveBeenCalled();
    });

    it('after a watch is stopped and restarted, an event arms a fresh timer', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      streams[0]!.handlers.onActivity();
      stopApprovalWatch();
      startApprovalWatch();
      await flush();
      apiGet.mockClear();
      streams[1]!.handlers.onActivity();
      await vi.advanceTimersByTimeAsync(1_000);
      expect(apiGet).toHaveBeenCalledTimes(1);
    });

    it('polls only slowly while the stream is up', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      streams[0]!.handlers.onOpen?.();
      await flush();
      apiGet.mockClear();
      await vi.advanceTimersByTimeAsync(29_000);
      expect(apiGet).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1_000);
      expect(apiGet).toHaveBeenCalledTimes(1);
    });

    it('falls back to polling every 5 s when there is no stream (no Redis)', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      streams[0]!.handlers.onUnavailable?.();
      apiGet.mockClear();
      await vi.advanceTimersByTimeAsync(15_000);
      expect(apiGet).toHaveBeenCalledTimes(3);
    });

    it('tries the stream again later, and goes back to slow polling once it is up', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      streams[0]!.handlers.onUnavailable?.();
      expect(streams).toHaveLength(1);

      await vi.advanceTimersByTimeAsync(30_000);
      expect(streams).toHaveLength(2);
      expect(streams[0]!.stop).toHaveBeenCalled();

      streams[1]!.handlers.onOpen?.();
      await flush();
      apiGet.mockClear();
      await vi.advanceTimersByTimeAsync(10_000);
      expect(apiGet).not.toHaveBeenCalled();
    });

    it('stopping closes the stream, ends the polling and forgets the list', async () => {
      apiGet.mockResolvedValue(reply('a'));
      startApprovalWatch();
      await flush();
      stopApprovalWatch();

      expect(streams[0]!.stop).toHaveBeenCalled();
      expect($approvals.get()).toEqual([]);
      expect($approvalsLoaded.get()).toBe(false);
      apiGet.mockClear();
      await vi.advanceTimersByTimeAsync(120_000);
      expect(apiGet).not.toHaveBeenCalled();
      expect(streams).toHaveLength(1);
    });

    it('a watch can start again after stopping (log out, log in)', async () => {
      apiGet.mockResolvedValue(reply('a'));
      startApprovalWatch();
      await flush();
      stopApprovalWatch();
      startApprovalWatch();
      await flush();
      expect(streams).toHaveLength(2);
      expect($pendingApprovalCount.get()).toBe(1);
    });
  });
});
