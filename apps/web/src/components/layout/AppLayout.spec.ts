import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import type { PendingApprovalDto } from '@bunker46/shared-types';

const apiGet = vi.fn();
vi.mock('@/lib/api', () => ({ api: { get: (...a: unknown[]) => apiGet(...a) } }));

const stopStream = vi.fn();
const connectActivityStream = vi.fn((_handlers: unknown) => stopStream);
vi.mock('@/composables/useActivityStream', () => ({
  connectActivityStream: (h: unknown) => connectActivityStream(h),
}));

const routeState = { name: 'dashboard' as string, path: '/dashboard' };
vi.mock('vue-router', () => ({
  useRoute: () => routeState,
  useRouter: () => ({ push: vi.fn() }),
}));

import AppLayout from './AppLayout.vue';
import { $auth } from '@/stores/auth';
import { $approvals, $approvalsLoaded, stopApprovalWatch } from '@/stores/approvals';

const waiting = (n: number): PendingApprovalDto[] =>
  Array.from({ length: n }, (_, i) => ({
    token: `t${i}`.padEnd(32, 'x'),
    connectionId: `c${i}`,
    connectionName: 'BIES',
    clientPubkey: 'b'.repeat(64),
    method: 'sign_event',
    kind: 27235,
    createdAt: '2026-11-24T12:00:00.000Z',
    expiresAt: '2026-11-24T12:01:40.000Z',
  }));

const signedOut = () => $auth.set({ accessToken: null, user: null, requiresTotp: false });
const signedIn = () => $auth.set({ accessToken: 'access', user: null, requiresTotp: false });

function mountLayout() {
  return mount(AppLayout, {
    slots: { default: '<p>page</p>' },
    global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } },
  });
}

describe('AppLayout: approvals badge and watch', () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'] });
    apiGet.mockReset();
    stopStream.mockClear();
    connectActivityStream.mockClear();
    routeState.name = 'dashboard';
    routeState.path = '/dashboard';
    signedOut();
    apiGet.mockImplementation(async (path: string) =>
      path === '/approvals' ? { approvals: [] } : {},
    );
  });
  afterEach(() => {
    stopApprovalWatch();
    signedOut();
    vi.useRealTimers();
  });

  it('does not watch for approvals while nobody is signed in', async () => {
    const w = mountLayout();
    await flushPromises();
    expect(apiGet).not.toHaveBeenCalledWith('/approvals');
    expect(connectActivityStream).not.toHaveBeenCalled();
    w.unmount();
  });

  it('does not watch while the second factor is still pending', async () => {
    $auth.set({ accessToken: 'partial', user: null, requiresTotp: true });
    const w = mountLayout();
    await flushPromises();
    expect(apiGet).not.toHaveBeenCalledWith('/approvals');
    expect(connectActivityStream).not.toHaveBeenCalled();
    w.unmount();
  });

  it('starts watching when signed in, and shows nothing while none are waiting', async () => {
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(apiGet).toHaveBeenCalledWith('/approvals');
    expect(connectActivityStream).toHaveBeenCalledTimes(1);
    expect(w.find('[data-testid="approvals-badge"]').exists()).toBe(false);
    expect(w.find('[data-testid="approvals-pill"]').exists()).toBe(false);
    w.unmount();
  });

  it('shows the count on the nav badge and in the header pill (plural)', async () => {
    apiGet.mockResolvedValue({ approvals: waiting(3) });
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(w.get('[data-testid="approvals-badge"]').text()).toBe('3');
    expect(w.get('[data-testid="approvals-pill"]').text()).toContain(
      '3 requests are waiting for you',
    );
    w.unmount();
  });

  it('uses the singular for one request', async () => {
    apiGet.mockResolvedValue({ approvals: waiting(1) });
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(w.get('[data-testid="approvals-badge"]').text()).toBe('1');
    expect(w.get('[data-testid="approvals-pill"]').text()).toContain(
      '1 request is waiting for you',
    );
    w.unmount();
  });

  it('updates the badge when the list changes, and drops it at zero', async () => {
    apiGet.mockResolvedValue({ approvals: waiting(2) });
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(w.get('[data-testid="approvals-badge"]').text()).toBe('2');

    $approvals.set(waiting(1));
    await flushPromises();
    expect(w.get('[data-testid="approvals-badge"]').text()).toBe('1');

    $approvals.set([]);
    await flushPromises();
    expect(w.find('[data-testid="approvals-badge"]').exists()).toBe(false);
    expect(w.find('[data-testid="approvals-pill"]').exists()).toBe(false);
    w.unmount();
  });

  it('starts watching when a sign-in happens after the layout is up', async () => {
    const w = mountLayout();
    await flushPromises();
    expect(connectActivityStream).not.toHaveBeenCalled();

    apiGet.mockResolvedValue({ approvals: waiting(1) });
    signedIn();
    await flushPromises();
    expect(connectActivityStream).toHaveBeenCalledTimes(1);
    expect(w.get('[data-testid="approvals-badge"]').text()).toBe('1');
    w.unmount();
  });

  it('stops watching and clears the badge on sign-out, so the next user sees none of it', async () => {
    apiGet.mockResolvedValue({ approvals: waiting(2) });
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(w.find('[data-testid="approvals-badge"]').exists()).toBe(true);

    signedOut();
    await flushPromises();
    expect(stopStream).toHaveBeenCalled();
    expect($approvals.get()).toEqual([]);
    expect($approvalsLoaded.get()).toBe(false);
    expect(w.find('[data-testid="approvals-badge"]').exists()).toBe(false);

    // And nothing polls any more.
    apiGet.mockClear();
    await vi.advanceTimersByTimeAsync(120_000);
    expect(apiGet).not.toHaveBeenCalledWith('/approvals');
    w.unmount();
  });

  it('stops watching when the layout goes away', async () => {
    signedIn();
    const w = mountLayout();
    await flushPromises();
    w.unmount();
    expect(stopStream).toHaveBeenCalled();
  });

  it('has an Approvals entry in the navigation', async () => {
    signedIn();
    const w = mountLayout();
    await flushPromises();
    expect(w.text()).toContain('Approvals');
    w.unmount();
  });

  it('does not watch on the login screens, where there is no layout', async () => {
    routeState.name = 'login';
    routeState.path = '/login';
    const w = mountLayout();
    await flushPromises();
    expect(w.find('[data-testid="approvals-badge"]').exists()).toBe(false);
    expect(w.text()).toContain('page');
    w.unmount();
  });
});
