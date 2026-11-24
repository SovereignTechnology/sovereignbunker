<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import { useStore } from '@nanostores/vue';
import { BellRing, ShieldCheck } from '@lucide/vue';
import { LOGIN_EVENT_KIND, type PendingApprovalDto } from '@bunker46/shared-types';
import { api } from '@/lib/api';
import { $approvals, $approvalsLoaded, refreshApprovals } from '@/stores/approvals';
import Button from '@/components/ui/Button.vue';
import Card from '@/components/ui/Card.vue';
import Badge from '@/components/ui/Badge.vue';
import PubkeyDisplay from '@/components/PubkeyDisplay.vue';

const route = useRoute();
const approvals = useStore($approvals);
const loaded = useStore($approvalsLoaded);

/** The request the link in the client pointed at, if this page was opened from one. */
const focusToken = computed(() =>
  typeof route.params.token === 'string' ? route.params.token : '',
);

const busy = ref('');
const error = ref('');
/** Token whose "always allow" is waiting for its second, confirming click. */
const confirmingAlways = ref('');
/** What the operator just did, by token, so the page can say so instead of "no longer waiting". */
const answered = ref<Record<string, string>>({});

// A second-resolution clock for the countdowns.
const now = ref(Date.now());
let tick: ReturnType<typeof setInterval> | undefined;
onMounted(() => {
  void refreshApprovals();
  tick = setInterval(() => (now.value = Date.now()), 1000);
});
onUnmounted(() => clearInterval(tick));

const list = computed<PendingApprovalDto[]>(() => {
  // The store hands out deeply readonly data; a copy is sorted, and the list is only read.
  const all = [...approvals.value] as PendingApprovalDto[];
  // The one that was linked to comes first.
  return all.sort(
    (a, b) => Number(b.token === focusToken.value) - Number(a.token === focusToken.value),
  );
});

/** The link's request is gone: answered elsewhere, timed out, or the signer restarted. */
const focusGone = computed(
  () =>
    loaded.value &&
    !!focusToken.value &&
    !approvals.value.some((a) => a.token === focusToken.value) &&
    !answered.value[focusToken.value],
);

const KIND_LABELS: Record<number, string> = {
  0: 'Update your profile',
  1: 'Publish a note',
  3: 'Update your follow list',
  4: 'Send an encrypted direct message',
  7: 'React to a note',
  [LOGIN_EVENT_KIND]: 'Sign in to a website (HTTP auth)',
};
const METHOD_LABELS: Record<string, string> = {
  nip04_encrypt: 'Encrypt a message (NIP-04)',
  nip04_decrypt: 'Decrypt a message (NIP-04)',
  nip44_encrypt: 'Encrypt a message (NIP-44)',
  nip44_decrypt: 'Decrypt a message (NIP-44)',
};

const isLogin = (a: PendingApprovalDto) => a.method === 'sign_event' && a.kind === LOGIN_EVENT_KIND;
const what = (a: PendingApprovalDto) =>
  a.method === 'sign_event'
    ? (KIND_LABELS[a.kind ?? -1] ?? 'Sign an event')
    : (METHOD_LABELS[a.method] ?? a.method);
const permission = (a: PendingApprovalDto) => (a.kind != null ? `${a.method}:${a.kind}` : a.method);
const secondsLeft = (a: PendingApprovalDto) =>
  Math.max(0, Math.ceil((Date.parse(a.expiresAt) - now.value) / 1000));

type Action = 'once' | 'always' | 'deny';

async function decide(a: PendingApprovalDto, action: Action) {
  busy.value = a.token;
  error.value = '';
  try {
    if (action === 'deny') {
      await api.post(`/approvals/${a.token}/deny`);
      answered.value = { ...answered.value, [a.token]: `Denied: ${a.connectionName} was refused.` };
    } else {
      await api.post(`/approvals/${a.token}/approve`, { mode: action });
      answered.value = {
        ...answered.value,
        [a.token]:
          action === 'always'
            ? `Allowed: ${a.connectionName} may do this from now on.`
            : `Allowed once: ${a.connectionName} is being answered.`,
      };
    }
  } catch (err) {
    error.value = err instanceof Error ? err.message : 'Something went wrong.';
  } finally {
    busy.value = '';
    confirmingAlways.value = '';
    await refreshApprovals();
  }
}

function askAlways(a: PendingApprovalDto) {
  // A login signature is the one worth a second look: always allowing it lets the app sign in to any
  // site as you. Everything else is one click.
  if (isLogin(a) && confirmingAlways.value !== a.token) {
    confirmingAlways.value = a.token;
    return;
  }
  void decide(a, 'always');
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

    <!-- What the operator just did -->
    <div
      v-for="(text, token) in answered"
      :key="token"
      class="mb-4 rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm flex items-center gap-2"
      data-testid="approval-answered"
    >
      <ShieldCheck class="w-4 h-4 shrink-0 text-primary" />
      {{ text }}
    </div>

    <!-- The linked request is no longer waiting -->
    <div
      v-if="focusGone"
      class="mb-4 rounded-lg border border-border bg-muted/40 px-4 py-3 text-sm"
      data-testid="approval-gone"
    >
      This request is not waiting any more: it was answered, or it timed out. The app can ask again.
    </div>

    <div v-if="!loaded" class="text-muted-foreground">Loading…</div>

    <div v-else-if="list.length === 0" class="text-center py-12" data-testid="approvals-empty">
      <p class="text-muted-foreground mb-1">Nothing is waiting for you.</p>
      <p class="text-sm text-muted-foreground">
        Turn on <strong>ask</strong> for a connection to have its requests wait here.
      </p>
    </div>

    <div v-else class="space-y-4">
      <Card
        v-for="a in list"
        :key="a.token"
        data-testid="approval-card"
        :class="a.token === focusToken ? 'border-amber-500 ring-1 ring-amber-500/40' : ''"
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
          <Badge :variant="secondsLeft(a) > 15 ? 'secondary' : 'destructive'">
            <span data-testid="approval-countdown">{{ secondsLeft(a) }}s left</span>
          </Badge>
        </div>

        <p class="font-medium">
          {{ what(a) }}
        </p>
        <p class="text-xs font-mono text-muted-foreground mb-3">
          {{ permission(a) }}
        </p>

        <!-- What it would sign. Shown as text only, never as markup. -->
        <div
          v-if="a.preview && (a.preview.content || a.preview.tagNames?.length)"
          class="rounded-lg bg-muted/50 border border-border p-3 mb-3 text-sm"
          data-testid="approval-preview"
        >
          <pre v-if="a.preview.content" class="whitespace-pre-wrap break-words font-mono text-xs"
            >{{ a.preview.content }}{{ a.preview.contentTruncated ? ' …' : '' }}</pre>
          <p v-if="a.preview.tagNames?.length" class="text-xs text-muted-foreground mt-2">
            Tags:
            <span v-for="name in a.preview.tagNames" :key="name" class="font-mono mr-1">{{
              name
            }}</span>
          </p>
        </div>

        <div
          v-if="confirmingAlways === a.token"
          class="rounded-lg border border-destructive/50 bg-destructive/10 p-3 mb-3 text-sm"
          data-testid="approval-always-warning"
        >
          Always allowing this lets <strong>{{ a.connectionName }}</strong> sign in to any website
          as you without asking again, including sites where signing in can delete an account.
          Choose <em>Allow once</em> to be asked each time.
        </div>

        <div class="flex flex-wrap gap-2">
          <Button
            data-testid="approve-once"
            :loading="busy === a.token"
            :disabled="secondsLeft(a) === 0"
            @click="decide(a, 'once')"
          >
            Allow once
          </Button>
          <Button
            data-testid="approve-always"
            variant="outline"
            :disabled="busy === a.token || secondsLeft(a) === 0"
            @click="askAlways(a)"
          >
            {{ confirmingAlways === a.token ? 'Yes, always allow' : 'Always allow' }}
          </Button>
          <Button
            data-testid="deny"
            variant="ghost"
            :disabled="busy === a.token"
            @click="decide(a, 'deny')"
          >
            Deny
          </Button>
        </div>
      </Card>
    </div>
  </div>
</template>
