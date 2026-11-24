import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createRouter, createMemoryHistory } from 'vue-router';

const mockUseAuthStore = vi.fn();

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => mockUseAuthStore(),
}));

describe('Router guards', () => {
  let router: ReturnType<typeof createRouter>;

  beforeEach(async () => {
    mockUseAuthStore.mockReturnValue({ isAuthenticated: false });
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/login', name: 'login', component: { template: 'Login' }, meta: { guest: true } },
        {
          path: '/dashboard',
          name: 'dashboard',
          component: { template: 'Dash' },
          meta: { requiresAuth: true },
        },
      ],
    });
    router.beforeEach((to) => {
      const auth = mockUseAuthStore();
      if (to.meta.requiresAuth && !auth?.isAuthenticated) return { name: 'login' };
      if (to.meta.guest && auth?.isAuthenticated) return { name: 'dashboard' };
      return;
    });
    await router.push('/login');
  });

  it('should redirect to login when unauthenticated and visiting protected route', async () => {
    mockUseAuthStore.mockReturnValue({ isAuthenticated: false });
    await router.push('/dashboard');
    expect(router.currentRoute.value.name).toBe('login');
  });

  it('should allow access to protected route when authenticated', async () => {
    mockUseAuthStore.mockReturnValue({ isAuthenticated: true });
    await router.push('/dashboard');
    expect(router.currentRoute.value.name).toBe('dashboard');
  });

  it('should redirect to dashboard when authenticated and visiting guest route', async () => {
    mockUseAuthStore.mockReturnValue({ isAuthenticated: true });
    await router.push('/dashboard');
    expect(router.currentRoute.value.name).toBe('dashboard');
    await router.push('/login');
    expect(router.currentRoute.value.name).toBe('dashboard');
  });

  describe('the real guard', () => {
    const to = (fullPath: string, meta: Record<string, unknown>) =>
      ({ fullPath, meta }) as unknown as import('vue-router').RouteLocationNormalized;

    it('sends a signed-out visitor of an approval link to login, carrying the link', async () => {
      const { authGuard } = await import('./index.js');
      mockUseAuthStore.mockReturnValue({ isAuthenticated: false });
      expect(authGuard(to('/approvals/Zm9vYmFy', { requiresAuth: true }))).toEqual({
        name: 'login',
        query: { redirect: '/approvals/Zm9vYmFy' },
      });
    });

    it('carries the whole path with its query', async () => {
      const { authGuard } = await import('./index.js');
      mockUseAuthStore.mockReturnValue({ isAuthenticated: false });
      expect(authGuard(to('/connections/abc?tab=logs', { requiresAuth: true }))).toEqual({
        name: 'login',
        query: { redirect: '/connections/abc?tab=logs' },
      });
    });

    it('lets a signed-in user through', async () => {
      const { authGuard } = await import('./index.js');
      mockUseAuthStore.mockReturnValue({ isAuthenticated: true });
      expect(authGuard(to('/approvals/Zm9vYmFy', { requiresAuth: true }))).toBeUndefined();
    });

    it('keeps a signed-in user off the guest pages', async () => {
      const { authGuard } = await import('./index.js');
      mockUseAuthStore.mockReturnValue({ isAuthenticated: true });
      expect(authGuard(to('/login', { guest: true }))).toEqual({ name: 'dashboard' });
    });

    it('registers /approvals/:token? behind the login', async () => {
      const { router: real } = await import('./index.js');
      const route = real.getRoutes().find((r) => r.name === 'approvals');
      expect(route?.path).toBe('/approvals/:token?');
      expect(route?.meta.requiresAuth).toBe(true);
    });
  });
});
