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
import { $approvals, $approvalsError, $approvalsLoaded } from '@/stores/approvals';

const NOW = Date.parse('2026-11-24T12:00:00.000Z');
const item = (over: Partial<PendingApprovalDto> = {}): PendingApprovalDto => ({
  token: 'tok-login',
  connectionId: 'conn-1',
  connectionName: 'BIES',
  clientPubkey: 'a'.repeat(64),
  method: 'sign_event',
  kind: 27235,
  preview: {
    kind: 27235,
    content: 'https://app.example/login',
    contentLength: 25,
    tagCount: 2,
    tags: [
      { name: 'u', values: ['https://app.example/login'] },
      { name: 'method', values: ['POST'] },
    ],
    httpAuth: { host: 'app.example', path: '/login', method: 'POST' },
  },
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
    $approvalsError.set('');
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

  it('shows the VALUES of the tags, not just their names', async () => {
    const w = mountView([
      item({
        kind: 1,
        preview: {
          kind: 1,
          tags: [
            { name: 'p', values: ['deadbeef01'] },
            { name: 'p', values: ['cafebabe02'] },
          ],
        },
      }),
    ]);
    await flushPromises();
    const text = w.get('[data-testid="approval-preview"]').text();
    expect(text).toContain('deadbeef01');
    expect(text).toContain('cafebabe02');
  });

  it('for a login, puts the host, path, method and payload of the request up front', async () => {
    const payload = 'ab'.repeat(32);
    const w = mountView([
      item({
        preview: {
          kind: 27235,
          content: '',
          tags: [{ name: 'u', values: ['https://shop.example/api/account/delete'] }],
          httpAuth: {
            host: 'shop.example',
            path: '/api/account/delete',
            method: 'DELETE',
            payload,
          },
        },
      }),
    ]);
    await flushPromises();
    const auth = w.get('[data-testid="approval-httpauth"]').text();
    expect(auth).toContain('shop.example');
    expect(auth).toContain('/api/account/delete');
    expect(auth).toContain('DELETE');
    expect(auth).toContain(payload);
  });

  it('says how long the whole content is when only part of it is shown', async () => {
    const w = mountView([
      item({
        kind: 1,
        preview: { kind: 1, content: 'x'.repeat(280), contentTruncated: true, contentLength: 5421 },
      }),
    ]);
    await flushPromises();
    expect(w.get('[data-testid="approval-preview"]').text()).toContain('5421');
  });

  it('for a decrypt shows who it is with and how big the ciphertext is', async () => {
    const peer = 'ab12cd34' + 'e'.repeat(48) + '56ef78ab';
    const w = mountView([
      item({
        method: 'nip44_decrypt',
        kind: undefined,
        preview: { peer, ciphertextLength: 312 },
      }),
    ]);
    await flushPromises();
    const text = w.get('[data-testid="approval-preview"]').text();
    expect(text).toContain('ab12cd34…56ef78ab');
    expect(text).toContain('312');
  });

  it('for an encrypt shows who it is with and what would be encrypted', async () => {
    const w = mountView([
      item({
        method: 'nip04_encrypt',
        kind: undefined,
        preview: { peer: 'f'.repeat(64), content: 'meet at noon', contentLength: 12 },
      }),
    ]);
    await flushPromises();
    expect(w.get('[data-testid="approval-preview"]').text()).toContain('meet at noon');
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

  describe('a request that goes away', () => {
    it('stays in place, greyed out and disabled, so the next card does not slide under the pointer', async () => {
      const first = item({ token: 'a', connectionName: 'First' });
      const second = item({ token: 'b', connectionName: 'Second' });
      const w = mountView([first, second]);
      await flushPromises();

      // The server let the first one go (it timed out, or another tab answered it).
      apiGet.mockResolvedValue({ approvals: [second] });
      $approvals.set([second]);
      await flushPromises();

      const cards = w.findAll('[data-testid="approval-card"]');
      expect(cards).toHaveLength(2);
      expect(cards[0]!.text()).toContain('First');
      expect(cards[0]!.attributes('data-state')).toBe('expired');
      for (const id of ['approve-once', 'approve-always', 'deny']) {
        expect(cards[0]!.get(`[data-testid="${id}"]`).attributes('disabled')).toBeDefined();
      }
      expect(cards[1]!.get('[data-testid="approve-once"]').attributes('disabled')).toBeUndefined();
    });

    it('goes only when it is dismissed', async () => {
      const first = item({ token: 'a', connectionName: 'First' });
      const second = item({ token: 'b', connectionName: 'Second' });
      const w = mountView([first, second]);
      await flushPromises();
      apiGet.mockResolvedValue({ approvals: [second] });
      $approvals.set([second]);
      await flushPromises();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(w.findAll('[data-testid="approval-card"]')).toHaveLength(2);

      await w.get('[data-testid="approval-dismiss"]').trigger('click');
      const cards = w.findAll('[data-testid="approval-card"]');
      expect(cards).toHaveLength(1);
      expect(cards[0]!.text()).toContain('Second');
    });

    it('a request the operator answered is not kept: it is answered, not gone', async () => {
      const w = mountView([item()]);
      await flushPromises();
      apiGet.mockResolvedValue({ approvals: [] });
      await w.get('[data-testid="approve-once"]').trigger('click');
      await flushPromises();
      expect(w.findAll('[data-testid="approval-card"]')).toHaveLength(0);
    });
  });

  describe('when the list cannot be loaded', () => {
    it('says why, instead of "Loading…" until the hold has expired', async () => {
      routeParams = {};
      apiGet.mockReset().mockRejectedValue(new Error('ThrottlerException: Too Many Requests'));
      const w = mount(ApprovalsView, { global: { stubs: { PubkeyDisplay: true } } });
      await flushPromises();
      const box = w.get('[data-testid="approvals-error"]');
      expect(box.text()).toContain('Too Many Requests');
    });
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

    it.each([
      ['nip04_encrypt', undefined],
      ['nip04_decrypt', undefined],
      ['nip44_encrypt', undefined],
      ['nip44_decrypt', undefined],
      ['sign_event', 5],
      ['sign_event', 22242],
      ['sign_event', 24133],
      ['sign_event', 27235],
    ])(
      'Always allow on %s %s needs a second click: it is a blanket grant',
      async (method, kind) => {
        const w = mountView([item({ method, kind, preview: undefined })]);
        await flushPromises();
        await w.get('[data-testid="approve-always"]').trigger('click');
        expect(apiPost).not.toHaveBeenCalled();
        expect(w.find('[data-testid="approval-always-warning"]').exists()).toBe(true);
        expect(w.get('[data-testid="approve-always"]').text()).toBe('Yes, always allow');
        apiGet.mockResolvedValue({ approvals: [] });
        await w.get('[data-testid="approve-always"]').trigger('click');
        await flushPromises();
        expect(apiPost).toHaveBeenCalledWith('/approvals/tok-login/approve', { mode: 'always' });
      },
    );

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
