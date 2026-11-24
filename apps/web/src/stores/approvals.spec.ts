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
const reply = (...tokens: string[]) => ({ approvals: tokens.map(item) });
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

    it('reloads when the server pushes an activity event', async () => {
      apiGet.mockResolvedValue(reply());
      startApprovalWatch();
      await flush();
      apiGet.mockResolvedValue(reply('x', 'y', 'z'));
      streams[0]!.handlers.onActivity();
      await flush();
      expect($pendingApprovalCount.get()).toBe(3);
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
