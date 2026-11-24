import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BadRequestException, NotFoundException } from '@nestjs/common';
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

  const open = (over: { userId?: string; kind?: number; requestId?: string } = {}) =>
    approvals.open({
      userId: over.userId ?? 'user-1',
      connectionId: 'conn-1',
      connectionName: 'BIES',
      clientPubkey: 'c'.repeat(64),
      requestId: over.requestId ?? 'req-1',
      permission: { method: 'sign_event', kind: over.kind ?? 27235 },
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

    it.each(['list', 'get', 'approve', 'deny'] as const)(
      'rate-limits %s on both throttlers',
      (name) => {
        const handler = ApprovalsController.prototype[name];
        expect(Reflect.getMetadata(`${THROTTLER_LIMIT}default`, handler)).toBeGreaterThan(0);
        expect(Reflect.getMetadata(`${THROTTLER_LIMIT}auth`, handler)).toBeGreaterThan(0);
      },
    );

    it('allows far fewer decisions than reads', () => {
      const limit = (name: 'list' | 'approve') =>
        Reflect.getMetadata(
          `${THROTTLER_LIMIT}auth`,
          ApprovalsController.prototype[name],
        ) as number;
      expect(limit('approve')).toBeLessThan(limit('list'));
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

    it('always: grants the permission FIRST, then settles the hold', async () => {
      let heldWhenGranted = -1;
      connections.grantPermissions.mockImplementation(async () => {
        heldWhenGranted = approvals.size;
      });

      await controller.approve(as('user-1'), hold.token, { mode: 'always' });

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
        controller.approve(as('user-1'), hold.token, { mode: 'always' }),
      ).rejects.toThrow(NotFoundException);
      expect(await settled(hold)).toBe('pending');
    });

    it("another user's token: 404, nothing granted, the hold untouched", async () => {
      await expect(
        controller.approve(as('user-2'), hold.token, { mode: 'always' }),
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
        controller.approve(as('user-1'), hold.token, { mode: 'always' }),
      ).resolves.toEqual({ success: true });
      expect(connections.grantPermissions).toHaveBeenCalledTimes(1);
      expect(await hold.decision).toBe('expired');
    });

    it('always only covers the kind that was asked, not the whole method', async () => {
      const other = open({ kind: 1, requestId: 'r2' });
      await controller.approve(as('user-1'), hold.token, { mode: 'always' });
      expect(connections.grantPermissions).toHaveBeenCalledWith('conn-1', 'user-1', [
        { method: 'sign_event', kind: 27235 },
      ]);
      expect(await settled(other)).toBe('pending');
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
