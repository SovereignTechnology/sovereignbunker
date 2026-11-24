import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import { ApprovalsController } from './approvals.controller.js';
import { ApprovalService, type HeldRequest } from './approval.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { TotpVerifiedGuard } from '../auth/guards/totp-verified.guard.js';
import type { ConnectionsService } from '../connections/connections.service.js';
import type { EventsService } from '../events/events.service.js';

// @nestjs/throttler stores a route's limit under this key plus the throttler's name.
const THROTTLER_LIMIT = 'THROTTLER:LIMIT';

type Req = Parameters<ApprovalsController['list']>[0];
const as = (userId: string) => ({ user: { sub: userId } }) as unknown as Req;

describe('ApprovalsController', () => {
  let approvals: ApprovalService;
  let connections: {
    grantPermissions: ReturnType<typeof vi.fn>;
    denyRequests: ReturnType<typeof vi.fn>;
  };
  let controller: ApprovalsController;
  let hold: HeldRequest;

  const open = (
    over: { userId?: string; kind?: number; requestId?: string; method?: string } = {},
  ) =>
    approvals.open({
      userId: over.userId ?? 'user-1',
      connectionId: 'conn-1',
      connectionName: 'BIES',
      clientPubkey: 'c'.repeat(64),
      requestId: over.requestId ?? 'req-1',
      fingerprint: 'fp',
      permission:
        over.method && over.method !== 'sign_event'
          ? ({ method: over.method } as never)
          : { method: 'sign_event', kind: over.kind ?? 27235 },
    })!;

  const settled = async (h: HeldRequest) =>
    Promise.race([h.decision, new Promise<'pending'>((r) => setImmediate(() => r('pending')))]);

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    approvals = new ApprovalService({ ttlMs: 100_000, publicBaseUrl: undefined }, {
      publishUserActivity: vi.fn().mockResolvedValue(undefined),
    } as unknown as EventsService);
    connections = {
      grantPermissions: vi.fn().mockResolvedValue(undefined),
      denyRequests: vi.fn().mockResolvedValue(undefined),
    };
    controller = new ApprovalsController(approvals, connections as unknown as ConnectionsService);
    hold = open();
  });

  afterEach(() => {
    approvals.onModuleDestroy();
    vi.useRealTimers();
  });

  describe('access', () => {
    it('sits behind the login and, when enabled, the TOTP check', () => {
      const guards = Reflect.getMetadata('__guards__', ApprovalsController) as unknown[];
      expect(guards).toEqual(expect.arrayContaining([JwtAuthGuard, TotpVerifiedGuard]));
    });

    it.each(['get', 'approve', 'deny'] as const)('rate-limits %s on both throttlers', (name) => {
      const handler = ApprovalsController.prototype[name];
      expect(Reflect.getMetadata(`${THROTTLER_LIMIT}default`, handler)).toBeGreaterThan(0);
      expect(Reflect.getMetadata(`${THROTTLER_LIMIT}auth`, handler)).toBeGreaterThan(0);
    });

    it.each(['default', 'auth'])(
      'does not rate-limit the list on the %s throttler: the page refreshes on every signing event, and a 429 would hide a hold while it expires',
      (name) => {
        expect(
          Reflect.getMetadata(`THROTTLER:SKIP${name}`, ApprovalsController.prototype.list),
        ).toBe(true);
      },
    );

    it('allows far fewer decisions than reads', () => {
      const limit = (name: 'get' | 'approve') =>
        Reflect.getMetadata(
          `${THROTTLER_LIMIT}auth`,
          ApprovalsController.prototype[name],
        ) as number;
      expect(limit('approve')).toBeLessThan(limit('get'));
    });
  });

  describe('list and get', () => {
    it("lists the logged-in user's holds only", () => {
      open({ userId: 'user-2', requestId: 'other' });
      const { approvals: mine } = controller.list(as('user-1'));
      expect(mine).toHaveLength(1);
      expect(mine[0]?.token).toBe(hold.token);
      expect(controller.list(as('user-3')).approvals).toEqual([]);
    });

    it('says whether anything can be asked at all: no PUBLIC_BASE_URL, no link to send', () => {
      expect(controller.list(as('user-1')).canAsk).toBe(false);
      const withUrl = new ApprovalsController(
        new ApprovalService({ ttlMs: 100_000, publicBaseUrl: 'https://signer.example.test' }, {
          publishUserActivity: vi.fn().mockResolvedValue(undefined),
        } as unknown as EventsService),
        connections as unknown as ConnectionsService,
      );
      expect(withUrl.list(as('user-1')).canAsk).toBe(true);
    });

    it("returns 404 for another user's token, the same as for one that does not exist", () => {
      expect(() => controller.get(as('user-2'), hold.token)).toThrow(NotFoundException);
      expect(() => controller.get(as('user-1'), 'a'.repeat(32))).toThrow(NotFoundException);
    });

    it('refuses a token of the wrong shape before looking anything up', () => {
      for (const bad of [
        '',
        'short',
        'has space in it xxxxxxxxxxxxxxxx',
        '../../etc/passwd',
        'x'.repeat(200),
      ]) {
        expect(() => controller.get(as('user-1'), bad)).toThrow(BadRequestException);
      }
    });
  });

  describe('approve', () => {
    it.each([
      ['no body', undefined],
      ['an empty body', {}],
      ['an unknown mode', { mode: 'forever' }],
      ['a non-string mode', { mode: 1 }],
      ['an extra field', { mode: 'once', also: 'this' }],
      ['a case-variant mode', { mode: 'ONCE' }],
      ['a confirm that is not a boolean', { mode: 'always', confirm: 'yes' }],
    ])('rejects %s with 400 and decides nothing', async (_name, body) => {
      await expect(controller.approve(as('user-1'), hold.token, body)).rejects.toThrow(
        BadRequestException,
      );
      expect(connections.grantPermissions).not.toHaveBeenCalled();
      expect(await settled(hold)).toBe('pending');
    });

    it('once: answers this request and grants nothing', async () => {
      await expect(controller.approve(as('user-1'), hold.token, { mode: 'once' })).resolves.toEqual(
        {
          success: true,
        },
      );
      expect(await hold.decision).toBe('approved_once');
      expect(connections.grantPermissions).not.toHaveBeenCalled();
    });

    it('once: removes the pending row the request filed, so "Approve all" cannot turn it into a permanent grant', async () => {
      await controller.approve(as('user-1'), hold.token, { mode: 'once' });
      expect(connections.denyRequests).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind: 27235 },
      ]);
    });

    it('always: grants the permission FIRST, then settles the hold', async () => {
      let heldWhenGranted = -1;
      connections.grantPermissions.mockImplementation(async () => {
        heldWhenGranted = approvals.size;
      });

      await controller.approve(as('user-1'), hold.token, { mode: 'always', confirm: true });

      expect(connections.grantPermissions).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind: 27235 },
      ]);
      // The re-check after the wait must find the grant, so it is stored before the hold ends.
      expect(heldWhenGranted).toBe(1);
      expect(await hold.decision).toBe('approved_always');
    });

    it('always: when the grant fails the request is NOT approved and stays held', async () => {
      connections.grantPermissions.mockRejectedValue(new NotFoundException('Connection not found'));
      await expect(
        controller.approve(as('user-1'), hold.token, { mode: 'always', confirm: true }),
      ).rejects.toThrow(NotFoundException);
      expect(await settled(hold)).toBe('pending');
    });

    it("another user's token: 404, nothing granted, the hold untouched", async () => {
      await expect(
        controller.approve(as('user-2'), hold.token, { mode: 'always', confirm: true }),
      ).rejects.toThrow(NotFoundException);
      expect(connections.grantPermissions).not.toHaveBeenCalled();
      expect(await settled(hold)).toBe('pending');
    });

    it('a hold that already ended cannot be approved afterwards', async () => {
      vi.advanceTimersByTime(100_000);
      await expect(controller.approve(as('user-1'), hold.token, { mode: 'once' })).rejects.toThrow(
        NotFoundException,
      );
    });

    it('always: the hold timing out while the grant is stored still reports success (the grant stands)', async () => {
      connections.grantPermissions.mockImplementation(async () => {
        vi.advanceTimersByTime(100_000);
      });
      await expect(
        controller.approve(as('user-1'), hold.token, { mode: 'always', confirm: true }),
      ).resolves.toEqual({ success: true });
      expect(connections.grantPermissions).toHaveBeenCalledTimes(1);
      expect(await hold.decision).toBe('expired');
    });

    it('always only covers the kind that was asked, not the whole method', async () => {
      const other = open({ kind: 1, requestId: 'r2' });
      await controller.approve(as('user-1'), hold.token, { mode: 'always', confirm: true });
      expect(connections.grantPermissions).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind: 27235 },
      ]);
      expect(await settled(other)).toBe('pending');
    });
  });

  describe("the confirmation is the SERVER's gate, not only the page's", () => {
    // Every one of these is a permanent grant of something wide.
    const wide: Array<[string, { method?: string; kind?: number }]> = [
      ['sign_event:0 (profile)', { kind: 0 }],
      ['sign_event:3 (follow list)', { kind: 3 }],
      ['sign_event:4 (direct message)', { kind: 4 }],
      ['sign_event:5 (deletion)', { kind: 5 }],
      ['sign_event:13 (seal)', { kind: 13 }],
      ['sign_event:9734 (zap request)', { kind: 9734 }],
      ['sign_event:10002 (relay list)', { kind: 10002 }],
      ['sign_event:22242 (relay auth)', { kind: 22242 }],
      ['sign_event:23194 (wallet connect)', { kind: 23194 }],
      ['sign_event:24133 (remote signer)', { kind: 24133 }],
      ['sign_event:24242 (Blossom)', { kind: 24242 }],
      ['sign_event:27235 (HTTP auth)', { kind: 27235 }],
      ['nip04_encrypt', { method: 'nip04_encrypt' }],
      ['nip04_decrypt', { method: 'nip04_decrypt' }],
      ['nip44_encrypt', { method: 'nip44_encrypt' }],
      ['nip44_decrypt', { method: 'nip44_decrypt' }],
    ];

    it.each(wide)(
      'always on %s without confirm is a 409: nothing is granted and the hold stays',
      async (_name, over) => {
        approvals.cancelForConnection('conn-1');
        const h = open({ ...over, requestId: 'wide' });
        await expect(controller.approve(as('user-1'), h.token, { mode: 'always' })).rejects.toThrow(
          ConflictException,
        );
        await expect(
          controller.approve(as('user-1'), h.token, { mode: 'always', confirm: false }),
        ).rejects.toThrow(ConflictException);
        expect(connections.grantPermissions).not.toHaveBeenCalled();
        expect(await settled(h)).toBe('pending');
      },
    );

    it('says what it refused and how to proceed', async () => {
      await expect(
        controller.approve(as('user-1'), hold.token, { mode: 'always' }),
      ).rejects.toThrow(/sign_event:27235.*confirm: true/);
    });

    it.each(wide)('always on %s WITH confirm is granted', async (_name, over) => {
      approvals.cancelForConnection('conn-1');
      const h = open({ ...over, requestId: 'wide' });
      await controller.approve(as('user-1'), h.token, { mode: 'always', confirm: true });
      expect(connections.grantPermissions).toHaveBeenCalledTimes(1);
      expect(await h.decision).toBe('approved_always');
    });

    it.each([1, 6, 7, 16])('always on the ordinary kind %i needs no confirm', async (kind) => {
      approvals.cancelForConnection('conn-1');
      const h = open({ kind, requestId: 'plain' });
      await controller.approve(as('user-1'), h.token, { mode: 'always' });
      expect(connections.grantPermissions).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind },
      ]);
      expect(await h.decision).toBe('approved_always');
    });

    it.each(wide)('once on %s never needs a confirm: it grants nothing', async (_name, over) => {
      approvals.cancelForConnection('conn-1');
      const h = open({ ...over, requestId: 'once' });
      await controller.approve(as('user-1'), h.token, { mode: 'once' });
      expect(connections.grantPermissions).not.toHaveBeenCalled();
      expect(await h.decision).toBe('approved_once');
    });
  });

  describe('deny', () => {
    it('refuses the request and removes the pending row it filed', async () => {
      await expect(controller.deny(as('user-1'), hold.token)).resolves.toEqual({ success: true });
      expect(connections.denyRequests).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind: 27235 },
      ]);
      expect(await hold.decision).toBe('denied');
    });

    it("another user's token: 404, nothing removed, the hold untouched", async () => {
      await expect(controller.deny(as('user-2'), hold.token)).rejects.toThrow(NotFoundException);
      expect(connections.denyRequests).not.toHaveBeenCalled();
      expect(await settled(hold)).toBe('pending');
    });

    it('refuses a malformed token with 400', async () => {
      await expect(controller.deny(as('user-1'), '../x')).rejects.toThrow(BadRequestException);
    });
  });
});
