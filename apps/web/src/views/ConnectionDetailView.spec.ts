import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils';

const apiGet = vi.fn();
const apiPost = vi.fn();
const apiPut = vi.fn();
const apiPatch = vi.fn();
const apiDelete = vi.fn();
vi.mock('@/lib/api', () => ({
  api: {
    get: (...a: unknown[]) => apiGet(...a),
    post: (...a: unknown[]) => apiPost(...a),
    put: (...a: unknown[]) => apiPut(...a),
    patch: (...a: unknown[]) => apiPatch(...a),
    delete: (...a: unknown[]) => apiDelete(...a),
  },
}));
vi.mock('vue-router', () => ({
  useRoute: () => ({ params: { id: 'conn-1' } }),
  useRouter: () => ({ push: vi.fn() }),
}));
vi.mock('@/composables/useActivityStream', () => ({
  useActivityStream: () => undefined,
  connectActivityStream: () => () => undefined,
}));

import ConnectionDetailView from './ConnectionDetailView.vue';

type Row = { method: string; kind: number | null; allowed: boolean };
const pending = (method: string, kind: number | null = null): Row => ({
  method,
  kind,
  allowed: false,
});
const granted = (method: string, kind: number | null = null): Row => ({
  method,
  kind,
  allowed: true,
});

const connection = (permissions: Row[]) => ({
  id: 'conn-1',
  name: 'BIES',
  status: 'ACTIVE',
  clientPubkey: 'b'.repeat(64),
  nsecKey: { label: 'Main', publicKey: 'a'.repeat(64) },
  relays: [],
  approvalMode: 'ASK',
  loggingEnabled: false,
  permissions,
});

async function mountView(permissions: Row[]) {
  const current = connection(permissions);
  apiGet.mockImplementation(async (path: string) =>
    path.includes('/logs') ? { data: [] } : current,
  );
  const w = mount(ConnectionDetailView, {
    global: {
      stubs: { PubkeyDisplay: true, RouterLink: true, 'router-link': true, AlertDialog: true },
    },
  });
  await flushPromises();
  return w;
}

const button = (w: VueWrapper, text: string) => w.findAll('button').find((b) => b.text() === text)!;
const approveButtons = (w: VueWrapper) => w.findAll('[data-testid="approve-perm"]');
const postsTo = (suffix: string) =>
  apiPost.mock.calls.filter(([path]) => String(path).endsWith(suffix));

describe('ConnectionDetailView: requests a client filed', () => {
  beforeEach(() => {
    for (const fn of [apiGet, apiPost, apiPut, apiPatch, apiDelete]) fn.mockReset();
    apiPost.mockResolvedValue({ success: true });
    apiPut.mockResolvedValue({ success: true });
  });

  describe('Approve all', () => {
    it('is its own call, with no list: it can never be an empty list that means "everything"', async () => {
      const w = await mountView([pending('sign_event', 1), pending('sign_event', 27235)]);
      apiPost.mockResolvedValue({ success: true, approved: 1, needConfirmation: 1 });
      await w.get('[data-testid="approve-all"]').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledTimes(1);
      expect(apiPost).toHaveBeenCalledWith('/connections/conn-1/permissions/approve-all');
      expect(postsTo('/permissions/approve')).toHaveLength(0);
    });

    it('says how many requests it left for a deliberate answer', async () => {
      const w = await mountView([pending('sign_event', 1), pending('nip44_decrypt')]);
      apiPost.mockResolvedValue({ success: true, approved: 1, needConfirmation: 1 });
      await w.get('[data-testid="approve-all"]').trigger('click');
      await flushPromises();
      const note = w.get('[data-testid="approve-all-note"]').text();
      expect(note).toContain('1 request');
      expect(note).toContain('not approved');
    });

    it('says nothing when everything was approved', async () => {
      const w = await mountView([pending('sign_event', 1)]);
      apiPost.mockResolvedValue({ success: true, approved: 1, needConfirmation: 0 });
      await w.get('[data-testid="approve-all"]').trigger('click');
      await flushPromises();
      expect(w.find('[data-testid="approve-all-note"]').exists()).toBe(false);
    });

    it('Deny all is its own call too', async () => {
      const w = await mountView([pending('sign_event', 1)]);
      await button(w, 'Deny all').trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/connections/conn-1/permissions/deny-all');
      expect(postsTo('/permissions/deny')).toHaveLength(0);
    });
  });

  describe('approving one request', () => {
    it.each([
      ['a login', pending('sign_event', 27235), { method: 'sign_event', kind: 27235 }],
      ['a profile', pending('sign_event', 0), { method: 'sign_event', kind: 0 }],
      ['a seal', pending('sign_event', 13), { method: 'sign_event', kind: 13 }],
      ['every kind', pending('sign_event'), { method: 'sign_event' }],
      ['a decrypt', pending('nip44_decrypt'), { method: 'nip44_decrypt' }],
      ['an encrypt', pending('nip04_encrypt'), { method: 'nip04_encrypt' }],
    ])('%s is a SECOND click, sent as confirmed', async (_name, row, wire) => {
      const w = await mountView([row]);
      expect(w.text()).toContain('needs your confirmation');

      await approveButtons(w)[0]!.trigger('click');
      expect(apiPost).not.toHaveBeenCalled();
      expect(w.get('[data-testid="approve-perm-warning"]').text()).toContain('permanent');
      expect(approveButtons(w)[0]!.text()).toBe('Yes, approve for good');

      await approveButtons(w)[0]!.trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledTimes(1);
      expect(apiPost).toHaveBeenCalledWith('/connections/conn-1/permissions/approve', {
        permissions: [wire],
        confirm: true,
      });
    });

    it.each([1, 6, 7, 16])(
      'the ordinary kind %i is one click, with no confirmation',
      async (kind) => {
        const w = await mountView([pending('sign_event', kind)]);
        expect(w.text()).not.toContain('needs your confirmation');
        await approveButtons(w)[0]!.trigger('click');
        await flushPromises();
        expect(apiPost).toHaveBeenCalledTimes(1);
        const [path, body] = apiPost.mock.calls[0] as [string, Record<string, unknown>];
        expect(path).toBe('/connections/conn-1/permissions/approve');
        expect(body).toEqual({ permissions: [{ method: 'sign_event', kind }] });
        expect(body).not.toHaveProperty('confirm');
      },
    );

    it('the confirming click belongs to one row: another row still needs its own two', async () => {
      const w = await mountView([pending('sign_event', 27235), pending('nip44_decrypt')]);
      await approveButtons(w)[0]!.trigger('click');
      await approveButtons(w)[1]!.trigger('click');
      expect(apiPost).not.toHaveBeenCalled();
      expect(approveButtons(w)[0]!.text()).toBe('Approve');
      expect(approveButtons(w)[1]!.text()).toBe('Yes, approve for good');
    });

    it('Deny on a row is one click and names only that row', async () => {
      const w = await mountView([pending('sign_event', 27235), pending('sign_event', 7)]);
      await w
        .findAll('button')
        .filter((b) => b.text() === 'Deny')[0]!
        .trigger('click');
      await flushPromises();
      expect(apiPost).toHaveBeenCalledWith('/connections/conn-1/permissions/deny', {
        permissions: [{ method: 'sign_event', kind: 27235 }],
      });
    });

    it("shows the server's refusal instead of swallowing it", async () => {
      const w = await mountView([pending('sign_event', 7)]);
      apiPost.mockRejectedValue(new Error('Connection not found'));
      await approveButtons(w)[0]!.trigger('click');
      await flushPromises();
      expect(w.get('[data-testid="perm-error"]').text()).toContain('Connection not found');
    });
  });

  describe('adding a kind by hand', () => {
    const kindInput = (w: VueWrapper) => w.get('input[type="number"]');

    it.each(['3000000000', '65536', '70000', '1.5', '-1', '1e21'])(
      'refuses %s before asking the server, and says what a kind is',
      async (text) => {
        const w = await mountView([]);
        await kindInput(w).setValue(text);
        await button(w, 'Add kind').trigger('click');
        await flushPromises();
        expect(apiPut).not.toHaveBeenCalled();
        expect(w.get('[data-testid="perm-error"]').text()).toContain('65535');
        // What was typed stays, so the operator can see what was refused.
        // (A number input may write "1e21" back as "1e+21": the same number.)
        expect(Number((kindInput(w).element as HTMLInputElement).value)).toBe(Number(text));
      },
    );

    it.each([
      ['30078', 30078],
      ['65535', 65535],
      ['0', 0],
    ])('adds the kind %s', async (text, kind) => {
      const w = await mountView([granted('sign_event', 1)]);
      await kindInput(w).setValue(text);
      await button(w, 'Add kind').trigger('click');
      await flushPromises();
      expect(apiPut).toHaveBeenCalledTimes(1);
      expect(apiPut).toHaveBeenCalledWith('/connections/conn-1/permissions', {
        permissions: [
          { method: 'sign_event', kind: 1 },
          { method: 'sign_event', kind },
        ],
      });
      expect(w.find('[data-testid="perm-error"]').exists()).toBe(false);
      expect((kindInput(w).element as HTMLInputElement).value).toBe('');
    });

    it('shows a 400 from the server, and keeps what was typed', async () => {
      const w = await mountView([]);
      apiPut.mockRejectedValue(new Error('Invalid permissions list'));
      await kindInput(w).setValue('30078');
      await button(w, 'Add kind').trigger('click');
      await flushPromises();
      expect(w.get('[data-testid="perm-error"]').text()).toContain('Invalid permissions list');
      expect((kindInput(w).element as HTMLInputElement).value).toBe('30078');
    });

    it('the error goes away with the next change that works', async () => {
      const w = await mountView([]);
      await kindInput(w).setValue('3000000000');
      await button(w, 'Add kind').trigger('click');
      await flushPromises();
      expect(w.find('[data-testid="perm-error"]').exists()).toBe(true);

      await kindInput(w).setValue('7');
      await button(w, 'Add kind').trigger('click');
      await flushPromises();
      expect(w.find('[data-testid="perm-error"]').exists()).toBe(false);
    });
  });

  it('a failed change to the granted list is shown, not an unhandled rejection', async () => {
    const w = await mountView([granted('sign_event', 1)]);
    apiPut.mockRejectedValue(new Error('Invalid permissions list'));
    await button(w, '×').trigger('click');
    await flushPromises();
    expect(w.get('[data-testid="perm-error"]').text()).toContain('Invalid permissions list');
  });
});
