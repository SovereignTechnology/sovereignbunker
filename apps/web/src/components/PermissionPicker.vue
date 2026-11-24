<script setup lang="ts">
import { computed, ref } from 'vue';
import {
  GATED_PERMISSION_METHODS,
  LOGIN_EVENT_KIND,
  type PermissionDescriptor,
} from '@bunker46/shared-types';
import Button from '@/components/ui/Button.vue';
import Input from '@/components/ui/Input.vue';

/**
 * What a connection is allowed to do, chosen by the operator before it is created (the bunker:// URI
 * being generated, or a nostrconnect:// URI being imported). The operator is authoritative: what is
 * picked here is GRANTED when the connection is made, and everything else is refused, or, with
 * "ask me" on, held for the operator to decide. connect, ping, get_public_key and switch_relays are
 * always available.
 */
const permissions = defineModel<PermissionDescriptor[]>('permissions', { required: true });
/** Hold a request the connection has no permission for, instead of refusing it (approvalMode ASK). */
const ask = defineModel<boolean>('ask', { default: false });

const newKind = ref('');

const label = (p: PermissionDescriptor) => (p.kind != null ? `${p.method}:${p.kind}` : p.method);
const isAllKinds = (method: string) =>
  permissions.value.some((p) => p.method === method && p.kind == null);
/** Whether the login event (kind 27235) is already covered by what is picked. */
const loginGranted = computed(() =>
  permissions.value.some(
    (p) => p.method === 'sign_event' && (p.kind == null || p.kind === LOGIN_EVENT_KIND),
  ),
);
/** A sign_event grant that covers every kind also covers login: the preset has nothing to choose. */
const loginCoveredByAllKinds = computed(() => isAllKinds('sign_event'));
const loginChoice = computed<'always' | 'ask' | 'refuse'>(() =>
  loginGranted.value ? 'always' : ask.value ? 'ask' : 'refuse',
);

function toggleMethod(method: string) {
  // Toggle a method-level (all-kinds) grant. Granting all kinds replaces any kind-scoped rows for it.
  permissions.value = isAllKinds(method)
    ? permissions.value.filter((p) => p.method !== method)
    : [
        ...permissions.value.filter((p) => p.method !== method),
        { method } as PermissionDescriptor,
      ];
}

function remove(p: PermissionDescriptor) {
  permissions.value = permissions.value.filter((x) => label(x) !== label(p));
}

const allGranted = computed(() => GATED_PERMISSION_METHODS.every((m) => isAllKinds(m)));
function grantAll() {
  permissions.value = GATED_PERMISSION_METHODS.map((method) => ({ method }));
}
function revokeAll() {
  permissions.value = [];
}

function addKind() {
  const kind = Number.parseInt(newKind.value, 10);
  if (!Number.isInteger(kind) || kind < 0) return;
  const exists = permissions.value.some(
    (p) => p.method === 'sign_event' && (p.kind == null || p.kind === kind),
  );
  if (!exists) permissions.value = [...permissions.value, { method: 'sign_event', kind }];
  newKind.value = '';
}

/** "Login (kind 27235)" preset: ask each time (recommended), or always allow. */
function chooseLogin(choice: 'ask' | 'always') {
  if (choice === 'always') {
    if (!loginGranted.value) {
      permissions.value = [...permissions.value, { method: 'sign_event', kind: LOGIN_EVENT_KIND }];
    }
    return;
  }
  permissions.value = permissions.value.filter(
    (p) => !(p.method === 'sign_event' && p.kind === LOGIN_EVENT_KIND),
  );
  // Asking each time needs the hold: without it the login would simply be refused.
  ask.value = true;
}
</script>

<template>
  <div class="space-y-4">
    <div>
      <label class="text-sm font-medium mb-1.5 block">Permissions</label>
      <p class="text-xs text-muted-foreground mb-2">
        Granted to this connection when it connects. connect, ping, get_public_key and switch_relays
        are always available.
      </p>

      <div v-if="permissions.length" class="flex flex-wrap gap-2 mb-3" data-testid="perm-chips">
        <span
          v-for="perm in permissions"
          :key="label(perm)"
          data-testid="perm-chip"
          class="inline-flex items-center gap-1 text-xs font-mono px-2 py-1 rounded bg-primary/10 text-primary"
        >
          {{ label(perm) }}
          <button
            type="button"
            class="hover:text-destructive cursor-pointer"
            title="Remove"
            @click="remove(perm)"
          >
            ×
          </button>
        </span>
      </div>
      <p v-else class="text-xs text-muted-foreground mb-3" data-testid="perm-none">
        No permissions selected — the connection starts able to do nothing until you grant some.
      </p>

      <div class="rounded-lg border border-border divide-y divide-border/50">
        <!-- Master toggle: grant every gated method (all kinds) at once, or clear all. -->
        <div class="flex items-center justify-between px-3 py-2 bg-muted/30">
          <span class="text-sm font-medium">All permissions</span>
          <button
            type="button"
            data-testid="perm-all-toggle"
            :class="[
              'w-12 h-6 rounded-full transition-colors cursor-pointer relative',
              allGranted ? 'bg-primary' : 'bg-muted',
            ]"
            :title="allGranted ? 'Clear all' : 'Grant all (all kinds)'"
            @click="allGranted ? revokeAll() : grantAll()"
          >
            <span
              :class="[
                'absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform',
                allGranted ? 'left-6' : 'left-0.5',
              ]"
            />
          </button>
        </div>
        <div
          v-for="method in GATED_PERMISSION_METHODS"
          :key="method"
          class="flex items-center justify-between px-3 py-2"
        >
          <span class="text-sm font-mono">
            {{ method }}
            <span v-if="method === 'sign_event'" class="text-xs text-muted-foreground ml-1"
              >all kinds</span
            >
          </span>
          <button
            type="button"
            :data-testid="`perm-toggle-${method}`"
            :class="[
              'w-12 h-6 rounded-full transition-colors cursor-pointer relative',
              isAllKinds(method) ? 'bg-primary' : 'bg-muted',
            ]"
            :title="isAllKinds(method) ? 'Remove (all kinds)' : 'Allow all kinds'"
            @click="toggleMethod(method)"
          >
            <span
              :class="[
                'absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform',
                isAllKinds(method) ? 'left-6' : 'left-0.5',
              ]"
            />
          </button>
        </div>
      </div>

      <div class="flex items-center gap-2 mt-3">
        <Input
          v-model="newKind"
          data-testid="perm-kind-input"
          type="number"
          min="0"
          placeholder="sign_event kind, e.g. 30078"
          class="flex-1 font-mono text-sm"
          @keyup.enter="addKind"
        />
        <Button
          type="button"
          variant="ghost"
          data-testid="perm-add-kind"
          :disabled="!newKind"
          @click="addKind"
        >
          Add kind
        </Button>
      </div>
    </div>

    <!-- Login (kind 27235): what a remote-signer login asks for, each time. -->
    <fieldset class="rounded-lg border border-border p-3" data-testid="login-preset">
      <legend class="px-1 text-sm font-medium">Login (kind {{ LOGIN_EVENT_KIND }})</legend>
      <p class="text-xs text-muted-foreground mb-2">
        Apps such as BIES ask you to sign a login event each time you sign in to a website.
      </p>

      <p
        v-if="loginCoveredByAllKinds"
        class="text-xs text-muted-foreground"
        data-testid="login-covered"
      >
        Already allowed, because sign_event is allowed for all kinds above.
      </p>
      <div v-else class="space-y-2">
        <label class="flex items-start gap-2 text-sm cursor-pointer">
          <input
            type="radio"
            name="login-choice"
            data-testid="login-ask"
            class="mt-1"
            :checked="loginChoice === 'ask'"
            @change="chooseLogin('ask')"
          />
          <span>
            <strong>Ask each time</strong> (recommended)
            <span class="block text-xs text-muted-foreground">
              Every login waits for your approval, so nothing signs in without you.
            </span>
          </span>
        </label>
        <label class="flex items-start gap-2 text-sm cursor-pointer">
          <input
            type="radio"
            name="login-choice"
            data-testid="login-always"
            class="mt-1"
            :checked="loginChoice === 'always'"
            @change="chooseLogin('always')"
          />
          <span>
            <strong>Always allow</strong>
            <span class="block text-xs text-muted-foreground">
              Grants <code class="font-mono">sign_event:{{ LOGIN_EVENT_KIND }}</code> permanently.
            </span>
          </span>
        </label>
        <p
          v-if="loginChoice === 'always'"
          class="rounded border border-destructive/50 bg-destructive/10 p-2 text-xs"
          data-testid="login-warning"
        >
          This connection could then sign in to <strong>any</strong> website as you without asking,
          including sites where signing in can <strong>delete your account</strong>.
        </p>
      </div>
    </fieldset>

    <!-- Ask mode: hold what the connection has no permission for. -->
    <label class="flex items-start gap-2 text-sm cursor-pointer">
      <input v-model="ask" type="checkbox" data-testid="ask-checkbox" class="mt-1" />
      <span>
        <strong>Ask me</strong> when this app needs something it has no permission for
        <span class="block text-xs text-muted-foreground">
          The app waits while you decide on the Approvals page. Only for apps that understand a
          wait (a NIP-46 <code class="font-mono">auth_url</code> reply, as BIES does). Off: such
          requests are refused at once.
        </span>
      </span>
    </label>
  </div>
</template>
