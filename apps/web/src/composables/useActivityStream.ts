import { onMounted, onUnmounted } from 'vue';
import { useAuthStore } from '@/stores/auth';

export interface ActivityStreamHandlers {
  /** A server-sent `activity` event arrived: refetch what the page shows. */
  onActivity: () => void;
  /** The stream is up (the server answered 200). */
  onOpen?: () => void;
  /**
   * The stream is not available: the server has no Redis (503), refused it, the network dropped, or
   * the connection ended. The caller falls back to polling. Not called when the caller stopped it.
   */
  onUnavailable?: () => void;
}

/**
 * Open the activity stream and return a function that closes it. Uses fetch + ReadableStream so the
 * token is sent via the Authorization header (not in the URL). A plain function, so a store can
 * hold the stream for the whole session; `useActivityStream` is the per-component form.
 */
export function connectActivityStream(handlers: ActivityStreamHandlers): () => void {
  const token = useAuthStore().accessToken;
  if (!token) {
    handlers.onUnavailable?.();
    return () => undefined;
  }

  const abort = new AbortController();
  const unavailable = () => {
    if (!abort.signal.aborted) handlers.onUnavailable?.();
  };

  fetch('/api/events/stream', {
    signal: abort.signal,
    headers: { Authorization: `Bearer ${token}` },
  })
    .then(async (res) => {
      if (!res.ok || !res.body) {
        unavailable();
        return;
      }
      handlers.onOpen?.();
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? '';
          for (const line of lines) {
            if (line.startsWith('data: ') && line.slice(6).trim() === 'activity') {
              handlers.onActivity();
            }
          }
        }
      } finally {
        reader.releaseLock();
      }
      unavailable();
    })
    .catch(() => {
      // Aborted by the caller, or a network error: only the latter reaches the fallback.
      unavailable();
    });

  return () => abort.abort();
}

/**
 * Subscribe to server-sent activity events (e.g. connection used, new connection, request held for
 * approval) for the life of a component. When Redis is configured the server pushes an event so the
 * UI can refetch. Calls onActivity when an event is received.
 */
export function useActivityStream(onActivity: () => void) {
  let stop: (() => void) | null = null;

  onMounted(() => {
    stop = connectActivityStream({ onActivity });
  });

  onUnmounted(() => {
    stop?.();
    stop = null;
  });
}
