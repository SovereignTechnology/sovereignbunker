<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import { useStore } from '@nanostores/vue';
import { BellRing, ShieldCheck } from '@lucide/vue';
import {
  LOGIN_EVENT_KIND,
  grantNeedsConfirmation,
  type PendingApprovalDto,
  type PermissionDescriptor,
} from '@bunker46/shared-types';
import { api } from '@/lib/api';
import {
  $approvals,
  $approvalsError,
  $approvalsLoaded,
  refreshApprovals,
} from '@/stores/approvals';
import Button from '@/components/ui/Button.vue';
import Card from '@/components/ui/Card.vue';
import Badge from '@/components/ui/Badge.vue';
import PubkeyDisplay from '@/components/PubkeyDisplay.vue';

const route = useRoute();
const approvals = useStore($approvals);
const loaded = useStore($approvalsLoaded);
const loadError = useStore($approvalsError);

/** The request the link in the client pointed at, if this page was opened from one. */
const focusToken = computed(() =>
  typeof route.params.token === 'string' ? route.params.token : '',
);

const busy = ref('');
const error = ref('');
/** The card whose button is waiting for its second, confirming click, and which one. */
const confirming = ref<{ token: string; action: 'once' | 'always' } | null>(null);
const isConfirming = (a: PendingApprovalDto, action: 'once' | 'always') =>
  confirming.value?.token === a.token && confirming.value.action === action;
/**
 * What the operator just did, by token. The card is replaced by a line saying so, of the same height,
 * until it is dismissed (or the page is opened again): a card that vanished would pull the next one
 * under the pointer, and a double click would answer a request the operator never read.
 */
const answered = ref<Record<string, string>>({});
const heights = ref<Record<string, number>>({});
const cardEls = new Map<string, HTMLElement>();
function bindCard(token: string, el: unknown) {
  const node =
    el !== null && typeof el === 'object' && '$el' in el ? (el as { $el: unknown }).$el : el;
  if (node instanceof HTMLElement) cardEls.set(token, node);
  else cardEls.delete(token);
}

// A second-resolution clock for the countdowns.
const now = ref(Date.now());
let tick: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  void refreshApprovals();
  tick = setInterval(() => (now.value = Date.now()), 1000);
});
onUnmounted(() => clearInterval(tick));

/**
 * The cards, in the order they first appeared. A request that leaves the server's list without the
 * operator having answered it (it timed out, or another tab answered it) STAYS here, greyed out and
 * disabled, until it is dismissed: a card that vanished would pull the next one up under the
 * pointer, and a client could time a short-lived request to have the operator's click land on a
 * different one.
 */
const seen = ref<PendingApprovalDto[]>([]);
/** Tokens that must not come back as cards: dismissed, or answered here. */
const finished = new Set<string>();

function syncSeen(live: PendingApprovalDto[]) {
  const byToken = new Map(live.map((a) => [a.token, a]));
  // Live ones refresh in place; the ones that left keep what they last showed.
  const next = seen.value.map((a) => byToken.get(a.token) ?? a);
  const have = new Set(next.map((a) => a.token));
  for (const a of live) {
    if (have.has(a.token) || finished.has(a.token)) continue;
    // The one that was linked to comes first.
    if (a.token === focusToken.value) next.unshift(a);
    else next.push(a);
  }
  seen.value = next;
}
// The store hands out deeply readonly data; the list is only read.
watch(approvals, (live) => syncSeen([...live] as PendingApprovalDto[]), { immediate: true });

const liveTokens = computed(() => new Set(approvals.value.map((a) => a.token)));
const isGone = (a: PendingApprovalDto) => !liveTokens.value.has(a.token);

function dismiss(a: PendingApprovalDto) {
  finished.add(a.token);
  seen.value = seen.value.filter((x) => x.token !== a.token);
  const rest = { ...answered.value };
  delete rest[a.token];
  answered.value = rest;
}

/** The link's request is gone: answered elsewhere, timed out, or the signer restarted. */
const focusGone = computed(
  () =>
    loaded.value &&
    !!focusToken.value &&
    !seen.value.some((a) => a.token === focusToken.value) &&
    !answered.value[focusToken.value],
);

const KIND_LABELS: Record<number, string> = {
  0: 'Update your profile',
  1: 'Publish a note',
  3: 'Update your follow list',
  4: 'Send an encrypted direct message',
  5: 'Ask relays to delete events',
  7: 'React to a note',
  22242: 'Authenticate to a relay',
  24133: 'Sign a remote-signer message',
  [LOGIN_EVENT_KIND]: 'Sign in to a website (HTTP auth)',
};
const METHOD_LABELS: Record<string, string> = {
  nip04_encrypt: 'Encrypt a message (NIP-04)',
  nip04_decrypt: 'Decrypt a message (NIP-04)',
  nip44_encrypt: 'Encrypt a message (NIP-44)',
  nip44_decrypt: 'Decrypt a message (NIP-44)',
};

const isLogin = (a: PendingApprovalDto) => a.method === 'sign_event' && a.kind === LOGIN_EVENT_KIND;
const asPermission = (a: PendingApprovalDto): PermissionDescriptor => ({
  method: a.method as PermissionDescriptor['method'],
  kind: a.kind,
});
/**
 * "Always allow" takes a second click, and is sent confirmed, for everything but an ordinary kind
 * (shared with the server, which refuses it otherwise): any encrypt or decrypt, a login, deleting
 * events, relay auth, a profile, a follow list, a seal, ...
 */
const alwaysNeedsConfirm = (a: PendingApprovalDto) => grantNeedsConfirmation(asPermission(a));
/** The login's URL is not shown in full: allowing it, even once, is a second click. */
const onceNeedsConfirm = (a: PendingApprovalDto) => a.preview?.httpAuth?.truncated === true;

/** What always allowing it would let the app do, for the confirming warning. */
function alwaysRisk(a: PendingApprovalDto): string {
  if (isLogin(a)) {
    return 'sign in to any website as you, including sites where signing in can delete an account';
  }
  if (a.method === 'sign_event') {
    if (a.kind === 5) return 'ask relays to delete any of your events';
    if (a.kind === 22242) return 'authenticate to any relay as you';
    if (a.kind === 24133) return 'sign remote-signer messages as you, for any signer';
    return `sign any event of kind ${a.kind ?? '?'} as you`;
  }
  if (a.method.endsWith('decrypt')) {
    return 'decrypt anything addressed to you, which is how your private messages are read';
  }
  return 'encrypt any message with your key, to anyone';
}

const what = (a: PendingApprovalDto) =>
  a.method === 'sign_event'
    ? (KIND_LABELS[a.kind ?? -1] ?? 'Sign an event')
    : (METHOD_LABELS[a.method] ?? a.method);
const permission = (a: PendingApprovalDto) => (a.kind != null ? `${a.method}:${a.kind}` : a.method);
const secondsLeft = (a: PendingApprovalDto) =>
  isGone(a) ? 0 : Math.max(0, Math.ceil((Date.parse(a.expiresAt) - now.value) / 1000));

const cardClass = (a: PendingApprovalDto) =>
  [
    a.token === focusToken.value ? 'border-amber-500 ring-1 ring-amber-500/40' : '',
    isGone(a) ? 'opacity-60' : '',
  ]
    .filter(Boolean)
    .join(' ');

const hasPreview = (a: PendingApprovalDto) => {
  const p = a.preview;
  return (
    !!p &&
    !!(
      p.content ||
      p.tags?.length ||
      p.httpAuth ||
      p.peer ||
      p.ciphertextLength != null ||
      p.eventTime ||
      p.eventTimeOff
    )
  );
};
/**
 * A key shortened to its first and last twelve characters, as an npub when the server gave one; the
 * whole of it is in the tooltip.
 */
const shortKey = (text: string) =>
  text.length > 26 ? `${text.slice(0, 12)}…${text.slice(-12)}` : text;
const peerShown = (p: NonNullable<PendingApprovalDto['preview']>) =>
  shortKey(p.peerNpub ?? p.peer ?? '');
const peerTitle = (p: NonNullable<PendingApprovalDto['preview']>) => p.peerNpub ?? p.peer ?? '';

type Action = 'once' | 'always' | 'deny';

async function decide(a: PendingApprovalDto, action: Action) {
  busy.value = a.token;
  error.value = '';
  // The card's height, before it is replaced by the line that says what was done.
  heights.value = { ...heights.value, [a.token]: cardEls.get(a.token)?.offsetHeight ?? 0 };
  try {
    if (action === 'deny') {
      await api.post(`/approvals/${a.token}/deny`);
      answered.value = { ...answered.value, [a.token]: `Denied: ${a.connectionName} was refused.` };
    } else {
      // The server refuses a permanent grant of anything but an ordinary kind without `confirm`.
      await api.post(
        `/approvals/${a.token}/approve`,
        action === 'always' && alwaysNeedsConfirm(a)
          ? { mode: action, confirm: true }
          : { mode: action },
      );
      answered.value = {
        ...answered.value,
        [a.token]:
          action === 'always'
            ? `Allowed: ${a.connectionName} may do this from now on.`
            : `Allowed once: ${a.connectionName} is being answered.`,
      };
    }
    // Answered here: the card gives way to a line saying so (same height), it is not "gone".
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Something went wrong.';
  } finally {
    busy.value = '';
    confirming.value = null;
    await refreshApprovals();
  }
}

function askAlways(a: PendingApprovalDto) {
  // A permanent grant of something this wide is worth a second look: it is not one request but every
  // later one. An ordinary kind is one click.
  if (alwaysNeedsConfirm(a) && !isConfirming(a, 'always')) {
    confirming.value = { token: a.token, action: 'always' };
    return;
  }
  void decide(a, 'always');
}

function askOnce(a: PendingApprovalDto) {
  if (onceNeedsConfirm(a) && !isConfirming(a, 'once')) {
    confirming.value = { token: a.token, action: 'once' };
    return;
  }
  void decide(a, 'once');
}
</script>

<template>
  <div class="max-w-3xl mx-auto">
    <div class="flex items-center gap-3 mb-2">
      <BellRing class="w-6 h-6 text-amber-500 shrink-0" />
      <h1 class="text-2xl font-bold">Approvals</h1>
    </div>
    <p class="text-sm text-muted-foreground mb-6">
      Apps connected with <strong>ask</strong> mode wait here when they need something they have no
      permission for. The app is waiting for your answer; a request that is not answered in time is
      refused.
    </p>

    <p v-if="error" class="text-sm text-destructive mb-4" role="alert">
      {{ error }}
    </p>

    <!-- The linked request is no longer waiting -->
    <div
      v-if="focusGone"
      class="mb-4 rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm"
      data-testid="approval-gone"
    >
      This request is not waiting any more: it was answered, or it timed out. The app can ask again.
    </div>

    <!-- The list could not be loaded: say why, instead of waiting in silence while holds run out. -->
    <div
      v-if="loadError"
      class="mb-4 rounded-lg border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm"
      role="alert"
      :data-testid="loaded ? 'approvals-stale' : 'approvals-error'"
    >
      <template v-if="loaded">
        The list could not be refreshed ({{ loadError }}). What is shown may be out of date; trying
        again.
      </template>
      <template v-else>
        Could not load what is waiting for you ({{ loadError }}). Trying again.
      </template>
    </div>

    <div v-if="!loaded && !loadError" class="text-muted-foreground">Loading…</div>

    <div
      v-else-if="loaded && seen.length === 0"
      class="text-center py-12"
      data-testid="approvals-empty"
    >
      <p class="text-muted-foreground mb-1">Nothing is waiting for you.</p>
      <p class="text-sm text-muted-foreground">
        Turn on <strong>ask</strong> for a connection to have its requests wait here.
      </p>
    </div>

    <div v-else-if="loaded" class="space-y-4">
      <template v-for="a in seen" :key="a.token">
        <!-- Answered here: a line of the card's height, not a gap the next card slides into. -->
        <div
          v-if="answered[a.token]"
          class="rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm flex items-center justify-between gap-3"
          data-testid="approval-tombstone"
          :style="heights[a.token] ? { minHeight: `${heights[a.token]}px` } : undefined"
        >
          <span class="flex items-center gap-2" data-testid="approval-answered">
            <ShieldCheck class="w-4 h-4 shrink-0 text-primary" />
            {{ answered[a.token] }}
          </span>
          <Button data-testid="approval-tombstone-dismiss" variant="ghost" @click="dismiss(a)">
            Dismiss
          </Button>
        </div>
        <Card
          v-else
          :ref="(el: unknown) => bindCard(a.token, el)"
          data-testid="approval-card"
          :data-state="isGone(a) ? 'expired' : 'waiting'"
          :class="cardClass(a)"
        >
          <div class="flex items-start justify-between gap-3 mb-3">
            <div class="min-w-0">
              <h2 class="font-semibold truncate">
                {{ a.connectionName }}
              </h2>
              <p class="text-xs text-muted-foreground flex items-center gap-1">
                <PubkeyDisplay :pubkey="a.clientPubkey" :truncate="true" />
              </p>
            </div>
            <Badge v-if="isGone(a)" variant="secondary" data-testid="approval-expired">
              No longer waiting
            </Badge>
            <Badge v-else :variant="secondsLeft(a) > 15 ? 'secondary' : 'destructive'">
              <span data-testid="approval-countdown">{{ secondsLeft(a) }}s left</span>
            </Badge>
          </div>

          <p class="font-medium">
            {{ what(a) }}
          </p>
          <p class="text-xs font-mono text-muted-foreground mb-3">
            {{ permission(a) }}
          </p>

          <!-- What it would do. Shown as text only, never as markup. -->
          <div
            v-if="hasPreview(a)"
            class="rounded-lg bg-muted/50 border border-border p-3 mb-3 text-sm"
            data-testid="approval-preview"
          >
            <!-- A login: what it is FOR. Kind 27235 is also what confirms deleting an account. -->
            <div
              v-if="a.preview?.httpAuth"
              class="rounded border border-amber-500/50 bg-amber-500/10 p-2 mb-2"
              data-testid="approval-httpauth"
            >
              <p class="text-xs text-muted-foreground">This signature is for</p>
              <p class="font-mono text-sm break-all">
                <strong v-if="a.preview.httpAuth.method">{{ a.preview.httpAuth.method }}</strong>
                {{ a.preview.httpAuth.host }}{{ a.preview.httpAuth.path
                }}{{ a.preview.httpAuth.url }}
              </p>
              <p v-if="a.preview.httpAuth.payload" class="text-xs text-muted-foreground break-all">
                payload
                <span class="font-mono">{{ a.preview.httpAuth.payload }}</span>
              </p>
              <p
                v-if="a.preview.httpAuth.truncated"
                class="mt-1 text-xs font-semibold text-destructive"
                role="alert"
                data-testid="approval-url-truncated"
              >
                URL longer than shown ({{ a.preview.httpAuth.urlLength }} chars): the end of it is
                not shown.
              </p>
            </div>

            <!-- When the event says it was made: a stale or far-future date is not "now". -->
            <p
              v-if="a.preview?.eventTime || a.preview?.eventTimeOff"
              :class="[
                'text-xs mb-2',
                a.preview.eventTimeOff ? 'font-semibold text-amber-600' : 'text-muted-foreground',
              ]"
              data-testid="approval-event-time"
            >
              <template v-if="a.preview.eventTime">
                Event dated {{ a.preview.eventTime }}
                <template v-if="a.preview.eventTimeOff"> (more than a day from now) </template>
              </template>
              <template v-else> Event date is not a valid time </template>
            </p>

            <!-- Encrypt and decrypt: with whom. -->
            <p v-if="a.preview?.peer" class="text-xs mb-2" data-testid="approval-peer">
              With
              <span class="font-mono" :title="peerTitle(a.preview)">{{
                peerShown(a.preview)
              }}</span>
            </p>
            <p
              v-if="a.preview?.ciphertextLength != null"
              class="text-xs text-muted-foreground mb-2"
              data-testid="approval-ciphertext"
            >
              Ciphertext of {{ a.preview.ciphertextLength }} characters (not shown)
            </p>

            <pre v-if="a.preview?.content" class="whitespace-pre-wrap break-words font-mono text-xs"
              >{{ a.preview.content }}{{ a.preview.contentTruncated ? ' …' : '' }}</pre>
            <p
              v-if="a.preview?.contentTruncated"
              class="text-xs text-muted-foreground mt-1"
              data-testid="approval-truncated"
            >
              Only the start is shown: the whole is {{ a.preview.contentLength }} characters.
            </p>

            <ul
              v-if="a.preview?.tags?.length"
              class="mt-2 space-y-0.5 text-xs"
              data-testid="approval-tags"
            >
              <li v-for="(tag, i) in a.preview.tags" :key="i" class="font-mono break-all">
                <span class="text-muted-foreground">{{ tag.name }}</span>
                <span v-for="(value, j) in tag.values" :key="j" class="ml-2">{{ value }}</span>
                <span v-if="tag.cut" class="ml-1 text-muted-foreground" title="Not shown in full"
                  >…</span
                >
                <span v-if="tag.nonText" class="ml-2 text-muted-foreground"
                  >(+{{ tag.nonText }} non-text tag values)</span
                >
              </li>
            </ul>
            <p
              v-if="
                a.preview?.tagCount && a.preview.tags && a.preview.tagCount > a.preview.tags.length
              "
              class="text-xs text-muted-foreground mt-1"
            >
              … and {{ a.preview.tagCount - a.preview.tags.length }} more tags.
            </p>
          </div>

          <div
            v-if="isConfirming(a, 'once')"
            class="rounded-lg border border-destructive/50 bg-destructive/10 p-3 mb-3 text-sm"
            data-testid="approval-once-warning"
          >
            The URL this signs for is longer than what is shown above. Allow it only if you trust
            <strong>{{ a.connectionName }}</strong> with the part you cannot see.
          </div>
          <div
            v-if="isConfirming(a, 'always')"
            class="rounded-lg border border-destructive/50 bg-destructive/10 p-3 mb-3 text-sm"
            data-testid="approval-always-warning"
          >
            Always allowing this lets <strong>{{ a.connectionName }}</strong>
            {{ alwaysRisk(a) }} without asking again. Choose <em>Allow once</em> to be asked each
            time.
          </div>

          <div class="flex flex-wrap gap-2">
            <Button
              data-testid="approve-once"
              :loading="busy === a.token"
              :disabled="secondsLeft(a) === 0"
              @click="askOnce(a)"
            >
              {{ isConfirming(a, 'once') ? 'Yes, allow once' : 'Allow once' }}
            </Button>
            <Button
              data-testid="approve-always"
              variant="outline"
              :disabled="busy === a.token || secondsLeft(a) === 0"
              @click="askAlways(a)"
            >
              {{ isConfirming(a, 'always') ? 'Yes, always allow' : 'Always allow' }}
            </Button>
            <Button
              data-testid="deny"
              variant="ghost"
              :disabled="busy === a.token || isGone(a)"
              @click="decide(a, 'deny')"
            >
              Deny
            </Button>
            <Button
              v-if="isGone(a)"
              data-testid="approval-dismiss"
              variant="outline"
              @click="dismiss(a)"
            >
              Dismiss
            </Button>
          </div>
        </Card>
      </template>
    </div>
  </div>
</template>
