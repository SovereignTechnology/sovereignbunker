import { describe, it, expect } from 'vitest';
import { mount } from '@vue/test-utils';
import { defineComponent, ref, h } from 'vue';
import type { PermissionDescriptor } from '@bunker46/shared-types';
import PermissionPicker from './PermissionPicker.vue';

/** The picker with real v-model state around it, as a form uses it. */
function mountPicker(initial: PermissionDescriptor[], ask = false) {
  const permissions = ref<PermissionDescriptor[]>(initial);
  const askRef = ref(ask);
  const Host = defineComponent({
    setup: () => () =>
      h(PermissionPicker, {
        permissions: permissions.value,
        'onUpdate:permissions': (v: PermissionDescriptor[]) => (permissions.value = v),
        ask: askRef.value,
        'onUpdate:ask': (v: boolean) => (askRef.value = v),
      }),
  });
  const w = mount(Host);
  return { w, permissions, ask: askRef };
}
const labels = (w: ReturnType<typeof mount>) =>
  w.findAll('[data-testid="perm-chip"]').map((c) => c.text().replace('×', '').trim());

describe('PermissionPicker', () => {
  describe('permissions', () => {
    it('shows what will be granted', () => {
      const { w } = mountPicker([{ method: 'sign_event', kind: 1 }, { method: 'nip44_decrypt' }]);
      expect(labels(w)).toEqual(['sign_event:1', 'nip44_decrypt']);
    });

    it('says plainly that an empty selection starts able to do nothing', () => {
      const { w } = mountPicker([]);
      expect(w.get('[data-testid="perm-none"]').text()).toContain('able to do nothing');
    });

    it('removes a chip', async () => {
      const { w, permissions } = mountPicker([
        { method: 'sign_event', kind: 1 },
        { method: 'sign_event', kind: 7 },
      ]);
      await w.findAll('[data-testid="perm-chip"] button')[0]!.trigger('click');
      expect(permissions.value).toEqual([{ method: 'sign_event', kind: 7 }]);
    });

    it('allowing a method for all kinds replaces its kind-scoped grants', async () => {
      const { w, permissions } = mountPicker([
        { method: 'sign_event', kind: 1 },
        { method: 'sign_event', kind: 7 },
        { method: 'nip44_decrypt' },
      ]);
      await w.get('[data-testid="perm-toggle-sign_event"]').trigger('click');
      expect(permissions.value).toEqual([{ method: 'nip44_decrypt' }, { method: 'sign_event' }]);
    });

    it('toggling an all-kinds method off removes it', async () => {
      const { w, permissions } = mountPicker([{ method: 'nip44_decrypt' }]);
      await w.get('[data-testid="perm-toggle-nip44_decrypt"]').trigger('click');
      expect(permissions.value).toEqual([]);
    });

    it('the master toggle grants every gated method for all kinds, and clears again', async () => {
      const { w, permissions } = mountPicker([]);
      await w.get('[data-testid="perm-all-toggle"]').trigger('click');
      expect(permissions.value.map((p) => p.method).sort()).toEqual([
        'nip04_decrypt',
        'nip04_encrypt',
        'nip44_decrypt',
        'nip44_encrypt',
        'sign_event',
      ]);
      expect(permissions.value.every((p) => p.kind === undefined)).toBe(true);
      await w.get('[data-testid="perm-all-toggle"]').trigger('click');
      expect(permissions.value).toEqual([]);
    });

    it('adds a typed kind once, and ignores nonsense', async () => {
      const { w, permissions } = mountPicker([]);
      const input = w.get('[data-testid="perm-kind-input"]');
      await input.setValue('30078');
      await w.get('[data-testid="perm-add-kind"]').trigger('click');
      await input.setValue('30078');
      await w.get('[data-testid="perm-add-kind"]').trigger('click');
      await input.setValue('-5');
      await w.get('[data-testid="perm-add-kind"]').trigger('click');
      expect(permissions.value).toEqual([{ method: 'sign_event', kind: 30078 }]);
    });

    it('rejects a kind that is not plain digits instead of reading its prefix', async () => {
      const { w, permissions } = mountPicker([]);
      const input = w.get('[data-testid="perm-kind-input"]');
      for (const bad of ['1e3', '1.5', '12abc', '0x10', '99999999999']) {
        await input.setValue(bad);
        await w.get('[data-testid="perm-add-kind"]').trigger('click');
      }
      expect(permissions.value).toEqual([]);
    });

    it('stops adding kinds at the server limit of 64 entries', async () => {
      const full = Array.from({ length: 64 }, (_, i) => ({ method: 'sign_event', kind: i }));
      const { w, permissions } = mountPicker(full);
      await w.get('[data-testid="perm-kind-input"]').setValue('5000');
      await w.get('[data-testid="perm-add-kind"]').trigger('click');
      expect(permissions.value).toHaveLength(64);
    });
  });

  describe('Login (kind 27235) preset', () => {
    it('shows "Ask each time" as the choice when asking is on and login is not granted', () => {
      const { w } = mountPicker([{ method: 'sign_event', kind: 1 }], true);
      expect((w.get('[data-testid="login-ask"]').element as HTMLInputElement).checked).toBe(true);
      expect((w.get('[data-testid="login-always"]').element as HTMLInputElement).checked).toBe(
        false,
      );
      expect(w.find('[data-testid="login-warning"]').exists()).toBe(false);
    });

    it('Ask each time turns asking on and grants nothing for login', async () => {
      const { w, permissions, ask } = mountPicker([{ method: 'sign_event', kind: 1 }], false);
      await w.get('[data-testid="login-ask"]').setValue(true);
      expect(ask.value).toBe(true);
      expect(permissions.value).toEqual([{ method: 'sign_event', kind: 1 }]);
    });

    it('Always allow grants sign_event:27235 and warns about deleting accounts', async () => {
      const { w, permissions } = mountPicker([{ method: 'sign_event', kind: 1 }], true);
      await w.get('[data-testid="login-always"]').setValue(true);
      expect(permissions.value).toEqual([
        { method: 'sign_event', kind: 1 },
        { method: 'sign_event', kind: 27235 },
      ]);
      expect(w.get('[data-testid="login-warning"]').text()).toContain('delete your account');
    });

    it('going back to Ask each time takes the grant away again', async () => {
      const { w, permissions, ask } = mountPicker([{ method: 'sign_event', kind: 27235 }], false);
      await w.get('[data-testid="login-ask"]').setValue(true);
      expect(permissions.value).toEqual([]);
      expect(ask.value).toBe(true);
    });

    it('does not grant twice', async () => {
      const { w, permissions } = mountPicker([{ method: 'sign_event', kind: 27235 }]);
      await w.get('[data-testid="login-always"]').setValue(true);
      expect(permissions.value).toEqual([{ method: 'sign_event', kind: 27235 }]);
    });

    it('has nothing to choose when sign_event is already allowed for all kinds', () => {
      const { w } = mountPicker([{ method: 'sign_event' }]);
      expect(w.find('[data-testid="login-covered"]').exists()).toBe(true);
      expect(w.find('[data-testid="login-ask"]').exists()).toBe(false);
    });
  });

  describe('ask checkbox', () => {
    it('follows and sets the ask state', async () => {
      const { w, ask } = mountPicker([], false);
      const box = w.get('[data-testid="ask-checkbox"]');
      expect((box.element as HTMLInputElement).checked).toBe(false);
      await box.setValue(true);
      expect(ask.value).toBe(true);
    });
  });
});
