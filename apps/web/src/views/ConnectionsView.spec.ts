import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils';
import { DEFAULT_CONNECTION_PERMISSIONS } from '@bunker46/shared-types';

const apiGet = vi.fn();
const apiPost = vi.fn();
vi.mock('@/lib/api', () => ({
  api: { get: (...a: unknown[]) => apiGet(...a), post: (...a: unknown[]) => apiPost(...a) },
}));
vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useRoute: () => ({ query: {}, path: '/connections' }),
}));
vi.mock('@/composables/useActivityStream', () => ({ useActivityStream: () => undefined }));
vi.mock('qrcode', () => ({ toDataURL: vi.fn().mockResolvedValue('data:image/png;base64,AAAA') }));

import ConnectionsView from './ConnectionsView.vue';

const CLIENT = 'b'.repeat(64);
const KEY = {
  id: 'key-1',
  publicKey: 'a'.repeat(64),
  label: 'Main',
  createdAt: '2026-11-01T00:00:00Z',
};
const uri = (perms?: string) =>
  `nostrconnect://${CLIENT}?relay=${encodeURIComponent('wss://relay.example.com')}&secret=s3cret&name=BIES` +
  (perms === undefined ? '' : `&perms=${encodeURIComponent(perms)}`);

async function mountView() {
  apiGet.mockImplementation(async (path: string) => (path === '/connections' ? [] : [KEY]));
  apiPost.mockImplementation(async (path: string) => {
    if (path === '/bunker/parse-uri') {
      return {
        type: 'nostrconnect',
        clientPubkey: CLIENT,
        relays: ['wss://relay.example.com'],
        secret: 's3cret',
        name: 'BIES',
      };
    }
    if (path === '/bunker/generate-bunker-uri') return { uri: 'bunker://x' };
    return {};
  });
  const w = mount(ConnectionsView, {
    global: { stubs: { PubkeyDisplay: true, RouterLink: true, 'router-link': true } },
  });
  await flushPromises();
  return w;
}
const button = (w: VueWrapper, text: string) =>
  w.findAll('button').find((b) => b.text().includes(text))!;
const chips = (w: VueWrapper) =>
  w.findAll('[data-testid="perm-chip"]').map((c) => c.text().replace('×', '').trim());
const connectionsPost = () => apiPost.mock.calls.find(([p]) => p === '/connections');

async function openImport(w: VueWrapper, perms?: string) {
  await button(w, 'Use Nostrconnect URI').trigger('click');
  await w.get('input[placeholder="nostrconnect://..."]').setValue(uri(perms));
  await w.get('select').setValue('key-1');
  await flushPromises();
}

describe('ConnectionsView: importing a nostrconnect:// URI', () => {
  beforeEach(() => {
    apiGet.mockReset();
    apiPost.mockReset();
  });

  it('pre-selects what the URI asked for, and shows it before anything is granted', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1,sign_event:27235,nip44_decrypt');
    expect(chips(w)).toEqual(['sign_event:1', 'sign_event:27235', 'nip44_decrypt']);
  });

  it('grants exactly what the operator left in the picker, after editing it', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1,sign_event:27235,nip44_decrypt');

    // The operator drops the decrypt permission the app asked for.
    const decrypt = w
      .findAll('[data-testid="perm-chip"]')
      .find((c) => c.text().includes('nip44_decrypt'))!;
    await decrypt.get('button').trigger('click');
    expect(chips(w)).toEqual(['sign_event:1', 'sign_event:27235']);

    await button(w, 'Create Connection').trigger('click');
    await flushPromises();

    const [, body] = connectionsPost()! as [string, Record<string, unknown>];
    expect(body['permissions']).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'sign_event', kind: 27235 },
    ]);
  });

  it('never sends the raw perms string from the URI', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1,nip04_decrypt');
    await button(w, 'Create Connection').trigger('click');
    await flushPromises();
    const [, body] = connectionsPost()! as [string, Record<string, unknown>];
    expect(body).not.toHaveProperty('perms');
  });

  it('starts in ask mode and sends it', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1');
    expect((w.get('[data-testid="ask-checkbox"]').element as HTMLInputElement).checked).toBe(true);
    await button(w, 'Create Connection').trigger('click');
    await flushPromises();
    expect((connectionsPost()![1] as Record<string, unknown>)['approvalMode']).toBe('ASK');
  });

  it('sends DENY when the operator turns asking off', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1');
    await w.get('[data-testid="ask-checkbox"]').setValue(false);
    await button(w, 'Create Connection').trigger('click');
    await flushPromises();
    expect((connectionsPost()![1] as Record<string, unknown>)['approvalMode']).toBe('DENY');
  });

  it('a URI that asks for nothing starts from the conservative defaults', async () => {
    const w = await mountView();
    await openImport(w);
    expect(chips(w)).toEqual(DEFAULT_CONNECTION_PERMISSIONS.map((p) => `${p.method}:${p.kind}`));
  });

  it('an operator who clears everything creates a connection that can do nothing', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1');
    await w.get('[data-testid="perm-chip"] button').trigger('click');
    expect(chips(w)).toEqual([]);
    await button(w, 'Create Connection').trigger('click');
    await flushPromises();
    expect((connectionsPost()![1] as Record<string, unknown>)['permissions']).toEqual([]);
  });

  it('choosing "Always allow" for the login preset grants kind 27235 in the request', async () => {
    const w = await mountView();
    await openImport(w, 'sign_event:1');
    await w.get('[data-testid="login-always"]').setValue(true);
    await button(w, 'Create Connection').trigger('click');
    await flushPromises();
    expect((connectionsPost()![1] as Record<string, unknown>)['permissions']).toEqual([
      { method: 'sign_event', kind: 1 },
      { method: 'sign_event', kind: 27235 },
    ]);
  });
});

describe('ConnectionsView: generating a bunker:// URI', () => {
  beforeEach(() => {
    apiGet.mockReset();
    apiPost.mockReset();
  });

  async function openGenerate(w: VueWrapper) {
    await button(w, 'Generate bunker:// URI').trigger('click');
    await w.get('select').setValue('key-1');
  }
  const generatePost = () => apiPost.mock.calls.find(([p]) => p === '/bunker/generate-bunker-uri');

  it('sends the picked permissions and DENY by default: a URI can go to any client', async () => {
    const w = await mountView();
    await openGenerate(w);
    expect((w.get('[data-testid="ask-checkbox"]').element as HTMLInputElement).checked).toBe(false);
    await button(w, 'Generate URI').trigger('click');
    await flushPromises();
    const [, body] = generatePost()! as [string, Record<string, unknown>];
    expect(body['permissions']).toEqual([...DEFAULT_CONNECTION_PERMISSIONS]);
    expect(body['approvalMode']).toBe('DENY');
  });

  it('sends ASK once the operator turns it on', async () => {
    const w = await mountView();
    await openGenerate(w);
    await w.get('[data-testid="ask-checkbox"]').setValue(true);
    await button(w, 'Generate URI').trigger('click');
    await flushPromises();
    expect((generatePost()![1] as Record<string, unknown>)['approvalMode']).toBe('ASK');
  });
});
