import { atom, computed } from 'nanostores';
import type { PendingApprovalDto, PendingApprovalsDto } from '@bunker46/shared-types';
import { api } from '@/lib/api';
import { connectActivityStream } from '@/composables/useActivityStream';

/** Requests the signer is holding for the operator right now. */
const $approvals = atom<PendingApprovalDto[]>([]);
/** True once the first load answered, so a page can tell "none waiting" from "not loaded yet". */
const $approvalsLoaded = atom(false);
const $pendingApprovalCount = computed($approvals, (list) => list.length);
/**
 * False when the server has no PUBLIC_BASE_URL: it has no link to send a client, so it refuses a
 * gated request at once, and the forms should not offer to ask. True until the server says otherwise.
 */
const $approvalsCanAsk = atom(true);
/** Why the last refresh failed ('' when it did not), so a page can say so instead of "Loading…". */
const $approvalsError = atom('');

/** Polling cadence: a slow safety net while the stream is up, quick when there is no stream. */
const SAFETY_POLL_MS = 30_000;
const FALLBACK_POLL_MS = 5_000;
const RECONNECT_MS = 30_000;
/**
 * Every signing request the server handles is an activity event, and every open tab refreshes on it:
 * a client sending `ping` in a loop must not become a request storm. A THROTTLE, not a debounce: the
 * first event starts a timer and the refresh happens when it fires, however many events came
 * meanwhile. A debounce restarts on every event, so a client sending a `ping` every half second
 * would postpone the refresh for ever and the list would only move on the slow safety poll.
 */
const ACTIVITY_THROTTLE_MS = 1_000;

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
    const res = await api.get<PendingApprovalsDto>('/approvals');
    if (startedIn !== session) return false;
    if (seq < appliedSeq) return true;
    appliedSeq = seq;
    $approvals.set(res.approvals);
    // An older server sends no flag: it could always ask.
    $approvalsCanAsk.set(res.canAsk !== false);
    $approvalsError.set('');
    $approvalsLoaded.set(true);
    return true;
  } catch (err) {
    // Said, not swallowed: a 429 or an outage otherwise leaves the page on "Loading…" while the
    // request it is about to show runs out. The list that was there is kept.
    if (startedIn === session) {
      $approvalsError.set(err instanceof Error ? err.message : 'Could not load the approvals');
    }
    return false;
  }
}

let stopStream: (() => void) | null = null;
let pollTimer: ReturnType<typeof setInterval> | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let activityTimer: ReturnType<typeof setTimeout> | null = null;
let watching = false;

function refreshSoon() {
  // A refresh is already due: this event is covered by it. Never push it back.
  if (activityTimer) return;
  activityTimer = setTimeout(() => {
    activityTimer = null;
    if (watching) void refreshApprovals();
  }, ACTIVITY_THROTTLE_MS);
}

function setPolling(ms: number) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => void refreshApprovals(), ms);
}

function connect() {
  stopStream?.();
  stopStream = connectActivityStream({
    onActivity: refreshSoon,
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
  if (activityTimer) clearTimeout(activityTimer);
  activityTimer = null;
  $approvals.set([]);
  $approvalsLoaded.set(false);
  $approvalsError.set('');
}

export {
  $approvals,
  $approvalsCanAsk,
  $approvalsError,
  $approvalsLoaded,
  $pendingApprovalCount,
  refreshApprovals,
  startApprovalWatch,
  stopApprovalWatch,
};
