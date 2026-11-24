import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import type { PendingApprovalDto } from '@bunker46/shared-types';

const apiGet = vi.fn();
const apiPost = vi.fn();
vi.mock('@/lib/api', () => ({
  api: { get: (...a: unknown[]) => apiGet(...a), post: (...a: unknown[]) => apiPost(...a) },
}));

let routeParams: Record<string, string> = {};
vi.mock('vue-router', () => ({ useRoute: () => ({ params: routeParams }) }));

// The store would otherwise open a stream and timers of its own; the view only reads and refreshes.
vi.mock('@/composables/useActivityStream', () => ({
  connectActivityStream: () => () => undefined,
}));

import ApprovalsView from './ApprovalsView.vue';
import { $approvals, $approvalsLoaded } from '@/stores/approvals';

const NOW = Date.parse('2026-11-24T12:00:00.000Z');
const item = (over: Partial<PendingApprovalDto> = {}): PendingApprovalDto => ({
  token: 'tok-login',
  connectionId: 'conn-1',
  connectionName: 'BIES',
  clientPubkey: 'a'.repeat(64),
  method: 'sign_event',
  kind: 27235,
  preview: { kind: 27235, content: 'https://app.example/login', tagNames: ['u', 'method'] },
  createdAt: new Date(NOW).toISOString(),
  expiresAt: new Date(NOW + 100_000).toISOString(),
  ...over,
});

function mountView(list: PendingApprovalDto[], params: Record<string, string> = {}) {
  routeParams = params;
  $approvals.set(list);
  $approvalsLoaded.set(true);
  apiGet.mockResolvedValue({ approvals: list });
  return mount(ApprovalsView, { global: { stubs: { PubkeyDisplay: true } } });
}

describe('ApprovalsView', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    apiGet.mockReset();
    apiPost.mockReset().mockResolvedValue({ success: true });
    $approvals.set([]);
    $approvalsLoaded.set(false);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('says so when nothing is waiting', async () => {
    const w = mountView([]);
    await flushPromises();
    expect(w.find('[data-testid="approvals-empty"]').exists()).toBe(true);
    expect(w.findAll('[data-testid="approval-card"]')).toHaveLength(0);
  });

  it('shows who is asking, for what, and what it would sign', async () => {
    const w = mountView([item()]);
    await flushPromises();
    const card = w.get('[data-testid="approval-card"]');
    expect(card.text()).toContain('BIES');
    expect(card.text()).toContain('Sign in to a website');
    expect(card.text()).toContain('sign_event:27235');
    expect(w.get('[data-testid="approval-preview"]').text()).toContain('https://app.example/login');
    expect(w.get('[data-testid="approval-preview"]').text()).toContain('method');
  });

  it('renders what the client wants signed as text, never as markup', async () => {
    const hostile = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const w = mountView([item({ preview: { kind: 1, content: hostile } })]);
    await flushPromises();
    const preview = w.get('[data-testid="approval-preview"]');
    expect(preview.find('img').exists()).toBe(false);
    expect(preview.find('script').exists()).toBe(false);
    expect(preview.text()).toContain(hostile);
  });

  it('counts down the time left, and counts it live', async () => {
    const w = mountView([item()]);
    await flushPromises();
    expect(w.get('[data-testid="approval-countdown"]').text()).toBe('100s left');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(w.get('[data-testid="approval-countdown"]').text()).toBe('90s left');
  });

  it('disables the approving buttons once the time is up, and keeps Deny', async () => {
    const w = mountView([item({ expiresAt: new Date(NOW + 1000).toISOString() })]);
    await flushPromises();
    await vi.advanceTimersByTimeAsync(2000);
    expect(w.get('[data-testid="approve-once"]').attributes('disabled')).toBeDefined();
    expect(w.get('[data-testid="approve-always"]').attributes('disabled')).toBeDefined();
    expect(w.get('[data-testid="deny"]').attributes('disabled')).toBeUndefined();
  });

  it('puts the request the link pointed at first and marks it', async () => {
    const w = mountView(
      [
        item({ token: 'other', connectionName: 'Other' }),
        item({ token: 'wanted', connectionName: 'Wanted' }),
      ],
      { token: 'wanted' },
    );
    await flushPromises();
    const cards = w.findAll('[data-testid="approval-card"]');
    expect(cards[0]!.text()).toContain('Wanted');
    expect(cards[0]!.classes().join(' ')).toContain('border-amber-500');
    expect(cards[1]!.classes().join(' ')).not.toContain('border-amber-500');
  });

  it('says the request is not waiting any more when the linked one is gone', async () => {
    const w = mountView([], { token: 'long-gone' });
    await flushPromises();
    expect(w.find('[data-testid="approval-gone"]').exists()).toBe(true);
  });

  it('does not say that for a link whose request is still waiting', async () => {
    const w = mountView([item({ token: 'wanted' })], { token: 'wanted' });
    await flushPromises();
    expect(w.find('[data-testid="approval-gone"]').exists()).toBe(false);
  });

  describe('deciding', () => {
    it('Allow once posts mode "once" and reports it', async () => {
      const w = mountView([item()]);
      await flushPromises();
      apiGet.mockResolvedValue({ approvals: [] });
      await w.get('[data-testid="approve-once"]').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/approvals/tok-login/approve', { mode: 'once' });
      expect(w.get('[data-testid="approval-answered"]').text()).toContain('Allowed once');
      // Answered by us: not reported as "gone".
      expect(w.find('[data-testid="approval-gone"]').exists()).toBe(false);
    });

    it('Deny posts to the deny route', async () => {
      const w = mountView([item()]);
      await flushPromises();
      apiGet.mockResolvedValue({ approvals: [] });
      await w.get('[data-testid="deny"]').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/approvals/tok-login/deny');
      expect(w.get('[data-testid="approval-answered"]').text()).toContain('Denied');
    });

    it('Always allow on a LOGIN needs a second click, after a warning about deleting accounts', async () => {
      const w = mountView([item()]);
      await flushPromises();

      await w.get('[data-testid="approve-always"]').trigger('click');
      expect(apiPost).not.toHaveBeenCalled();
      const warning = w.get('[data-testid="approval-always-warning"]');
      expect(warning.text()).toContain('delete an account');
      expect(w.get('[data-testid="approve-always"]').text()).toBe('Yes, always allow');

      apiGet.mockResolvedValue({ approvals: [] });
      await w.get('[data-testid="approve-always"]').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/approvals/tok-login/approve', { mode: 'always' });
    });

    it('Always allow on something else is one click', async () => {
      const w = mountView([
        item({ kind: 1, preview: { kind: 1, content: 'hi' }, token: 'tok-note' }),
      ]);
      await flushPromises();
      apiGet.mockResolvedValue({ approvals: [] });
      await w.get('[data-testid="approve-always"]').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/approvals/tok-note/approve', { mode: 'always' });
    });

    it('shows the server error and keeps the request when the decision fails', async () => {
      const w = mountView([item()]);
      await flushPromises();
      apiPost.mockRejectedValue(new Error('Approval not found'));
      await w.get('[data-testid="approve-once"]').trigger('click');
      await flushPromises();
      expect(w.get('[role="alert"]').text()).toContain('Approval not found');
      expect(w.find('[data-testid="approval-answered"]').exists()).toBe(false);
    });
  });
});
