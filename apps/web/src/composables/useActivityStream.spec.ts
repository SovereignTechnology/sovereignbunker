import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

const mockAuth = vi.fn();
vi.mock('@/stores/auth', () => ({ useAuthStore: () => mockAuth() }));

import { connectActivityStream } from './useActivityStream.js';

/** A fetch body the test feeds by hand, like a server pushing server-sent events. */
function sseBody() {
  const encoder = new TextEncoder();
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      controller = c;
    },
  });
  return {
    body,
    push: (text: string) => controller.enqueue(encoder.encode(text)),
    end: () => controller.close(),
  };
}
const tick = () => new Promise<void>((r) => setTimeout(r, 0));

describe('connectActivityStream', () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockAuth.mockReturnValue({ accessToken: 'tok' });
    fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends the token in a header, never in the URL', async () => {
    const sse = sseBody();
    fetchMock.mockResolvedValue({ ok: true, body: sse.body });
    const stop = connectActivityStream({ onActivity: vi.fn() });
    await tick();
    const [url, init] = fetchMock.mock.calls[0] as [string, { headers: Record<string, string> }];
    expect(url).toBe('/api/events/stream');
    expect(url).not.toContain('tok');
    expect(init.headers['Authorization']).toBe('Bearer tok');
    stop();
  });

  it('reports open, then calls onActivity for each activity event only', async () => {
    const sse = sseBody();
    fetchMock.mockResolvedValue({ ok: true, body: sse.body });
    const handlers = { onActivity: vi.fn(), onOpen: vi.fn(), onUnavailable: vi.fn() };
    const stop = connectActivityStream(handlers);
    await tick();
    expect(handlers.onOpen).toHaveBeenCalledTimes(1);

    sse.push('data: activity\n\n');
    sse.push('data: something-else\n\n');
    sse.push('data: activity\n\n');
    await tick();
    expect(handlers.onActivity).toHaveBeenCalledTimes(2);
    expect(handlers.onUnavailable).not.toHaveBeenCalled();
    stop();
  });

  it('handles an event split across two chunks', async () => {
    const sse = sseBody();
    fetchMock.mockResolvedValue({ ok: true, body: sse.body });
    const onActivity = vi.fn();
    const stop = connectActivityStream({ onActivity });
    await tick();
    sse.push('data: acti');
    await tick();
    expect(onActivity).not.toHaveBeenCalled();
    sse.push('vity\n\n');
    await tick();
    expect(onActivity).toHaveBeenCalledTimes(1);
    stop();
  });

  it('is unavailable when the server has no stream (503: no Redis)', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 503, body: null });
    const onUnavailable = vi.fn();
    connectActivityStream({ onActivity: vi.fn(), onUnavailable });
    await tick();
    expect(onUnavailable).toHaveBeenCalledTimes(1);
  });

  it('is unavailable when the network fails', async () => {
    fetchMock.mockRejectedValue(new TypeError('network down'));
    const onUnavailable = vi.fn();
    connectActivityStream({ onActivity: vi.fn(), onUnavailable });
    await tick();
    expect(onUnavailable).toHaveBeenCalledTimes(1);
  });

  it('is unavailable when the server closes the stream', async () => {
    const sse = sseBody();
    fetchMock.mockResolvedValue({ ok: true, body: sse.body });
    const onUnavailable = vi.fn();
    connectActivityStream({ onActivity: vi.fn(), onUnavailable });
    await tick();
    sse.end();
    await tick();
    expect(onUnavailable).toHaveBeenCalledTimes(1);
  });

  it('says nothing after the caller stopped it', async () => {
    fetchMock.mockImplementation((_url: string, init: { signal: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
      }),
    );
    const onUnavailable = vi.fn();
    const stop = connectActivityStream({ onActivity: vi.fn(), onUnavailable });
    stop();
    await tick();
    expect(onUnavailable).not.toHaveBeenCalled();
  });

  it('without a session there is nothing to connect to', () => {
    mockAuth.mockReturnValue({ accessToken: null });
    const onUnavailable = vi.fn();
    connectActivityStream({ onActivity: vi.fn(), onUnavailable });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(onUnavailable).toHaveBeenCalledTimes(1);
  });
});
