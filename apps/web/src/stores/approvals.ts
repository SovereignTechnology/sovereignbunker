import { atom, computed } from 'nanostores';
import type { PendingApprovalDto } from '@bunker46/shared-types';
import { api } from '@/lib/api';
import { connectActivityStream } from '@/composables/useActivityStream';

/** Requests the signer is holding for the operator right now. */
const $approvals = atom<PendingApprovalDto[]>([]);
/** True once the first load answered, so a page can tell "none waiting" from "not loaded yet". */
const $approvalsLoaded = atom(false);
const $pendingApprovalCount = computed($approvals, (list) => list.length);

/** Polling cadence: a slow safety net while the stream is up, quick when there is no stream. */
const SAFETY_POLL_MS = 30_000;
const FALLBACK_POLL_MS = 5_000;
const RECONNECT_MS = 30_000;

// A refresh applies only if no newer one has landed and the watch it started under is still the
// current one, so a slow old answer can neither restore a resolved approval nor leak into the next
// login in the same tab.
let startedSeq = 0;
let appliedSeq = 0;
let session = 0;

/** Reload the list. Keeps the last known list when the request fails (e.g. a brief outage). */
async function refreshApprovals(): Promise<boolean> {
  const seq = ++startedSeq;
  const startedIn = session;
  try {
    const res = await api.get<{ approvals: PendingApprovalDto[] }>('/approvals');
    if (startedIn !== session) return false;
    if (seq < appliedSeq) return true;
    appliedSeq = seq;
    $approvals.set(res.approvals);
    $approvalsLoaded.set(true);
    return true;
  } catch {
    return false;
  }
}

let stopStream: (() => void) | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let watching = false;

function setPolling(ms: number) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => void refreshApprovals(), ms);
}

function connect() {
  stopStream?.();
  stopStream = connectActivityStream({
    onActivity: () => void refreshApprovals(),
    onOpen: () => {
      // Back on pushes: refresh once (events were missed while down) and poll slowly again.
      void refreshApprovals();
      setPolling(SAFETY_POLL_MS);
    },
    onUnavailable: () => {
      // No stream (no Redis, a proxy that drops it, a network blip): poll quickly, and try again.
      setPolling(FALLBACK_POLL_MS);
      if (watching && !reconnectTimer) {
        reconnectTimer = setTimeout(() => {
          reconnectTimer = null;
          if (watching) connect();
        }, RECONNECT_MS);
      }
    },
  });
}

/**
 * Keep the list fresh for a logged-in session: push events when the server has them, polling when it
 * does not. Idempotent; pair every start with stopApprovalWatch (logout, unmount).
 */
function startApprovalWatch() {
  if (watching) return;
  watching = true;
  void refreshApprovals();
  setPolling(SAFETY_POLL_MS);
  connect();
}

function stopApprovalWatch() {
  watching = false;
  session += 1;
  stopStream?.();
  stopStream = null;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
  if (reconnectTimer) clearTimeout(reconnectTimer);
  reconnectTimer = null;
  $approvals.set([]);
  $approvalsLoaded.set(false);
}

export {
  $approvals,
  $approvalsLoaded,
  $pendingApprovalCount,
  refreshApprovals,
  startApprovalWatch,
  stopApprovalWatch,
};
