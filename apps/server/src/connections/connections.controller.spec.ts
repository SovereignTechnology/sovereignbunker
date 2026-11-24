import { describe, it, expect, beforeEach, vi } from 'vitest';
import { BadRequestException, NotFoundException } from '@nestjs/common';
import { ConnectionsController } from './connections.controller.js';
import type { ConnectionsService } from './connections.service.js';
import type { BunkerService } from '../bunker/bunker.service.js';
import type { ApprovalService } from '../bunker/approval.service.js';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard.js';
import { TotpVerifiedGuard } from '../auth/guards/totp-verified.guard.js';

type Req = Parameters<ConnectionsController['list']>[0];
const req = { user: { sub: 'user-1' } } as unknown as Req;
const CLIENT = 'c'.repeat(64);

describe('ConnectionsController', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;
  let bunker: Record<string, ReturnType<typeof vi.fn>>;
  let approvals: { cancelForConnection: ReturnType<typeof vi.fn> };
  let controller: ConnectionsController;

  const create = (body: Record<string, unknown>) =>
    controller.create(req, { nsecKeyId: 'key-1', clientPubkey: CLIENT, ...body });

  beforeEach(() => {
    service = {
      createConnection: vi.fn().mockResolvedValue({ id: 'conn-1' }),
      getConnection: vi.fn().mockResolvedValue({ id: 'conn-1' }),
      setPermissions: vi.fn().mockResolvedValue(undefined),
      updateConnectionStatus: vi.fn().mockResolvedValue({ id: 'conn-1', status: 'REVOKED' }),
      setApprovalMode: vi.fn().mockResolvedValue({ id: 'conn-1', approvalMode: 'ASK' }),
      deleteConnection: vi.fn().mockResolvedValue(undefined),
    };
    bunker = {
      ensureListeningForConnection: vi.fn().mockResolvedValue(undefined),
      sendConnectResponse: vi.fn().mockResolvedValue(undefined),
    };
    approvals = { cancelForConnection: vi.fn().mockReturnValue(0) };
    controller = new ConnectionsController(
      service as unknown as ConnectionsService,
      bunker as unknown as BunkerService,
      approvals as unknown as ApprovalService,
    );
  });

  it('sits behind the login and the TOTP check', () => {
    const guards = Reflect.getMetadata('__guards__', ConnectionsController) as unknown[];
    expect(guards).toEqual(expect.arrayContaining([JwtAuthGuard, TotpVerifiedGuard]));
  });

  describe('create: permissions', () => {
    it('passes the operator-picked list to the service as the granted seed', async () => {
      const picked = [{ method: 'sign_event', kind: 30078 }, { method: 'nip44_decrypt' }];
      await create({ permissions: picked });
      expect(service['createConnection']).toHaveBeenCalledWith(
        'user-1',
        'key-1',
        CLIENT,
        expect.any(Object),
        picked,
      );
    });

    it('an edited list is honoured as sent, not widened or replaced', async () => {
      // The import form is prefilled from the URI's perms; the operator removes one before saving.
      await create({ permissions: [{ method: 'sign_event', kind: 1 }] });
      const seed = service['createConnection']!.mock.calls[0]![4];
      expect(seed).toEqual([{ method: 'sign_event', kind: 1 }]);
    });

    it('an empty list is passed through as empty: a connection that starts able to do nothing', async () => {
      await create({ permissions: [] });
      expect(service['createConnection']!.mock.calls[0]![4]).toEqual([]);
    });

    it('an absent list is passed as undefined, which the service reads as "use the defaults"', async () => {
      await create({});
      expect(service['createConnection']!.mock.calls[0]![4]).toBeUndefined();
    });

    it.each([
      ['a string instead of a list', 'sign_event:1,sign_event:7'],
      ['an unknown method', [{ method: 'delete_everything' }]],
      ['a negative kind', [{ method: 'sign_event', kind: -1 }]],
      ['a fractional kind', [{ method: 'sign_event', kind: 1.5 }]],
      ['a non-numeric kind', [{ method: 'sign_event', kind: '1' }]],
      ['a list that is not an array of objects', ['sign_event']],
      ['more entries than any picker offers', Array.from({ length: 65 }, (_, i) => ({ method: 'sign_event', kind: i }))],
      ['null', null],
    ])('rejects %s with 400 and creates nothing', async (_name, permissions) => {
      await expect(create({ permissions })).rejects.toThrow(BadRequestException);
      expect(service['createConnection']).not.toHaveBeenCalled();
      expect(bunker['ensureListeningForConnection']).not.toHaveBeenCalled();
    });

    it('refuses the old `perms` string loudly instead of ignoring it, and creates nothing', async () => {
      await expect(create({ perms: 'sign_event,nip44_decrypt' })).rejects.toThrow(
        BadRequestException,
      );
      expect(service['createConnection']).not.toHaveBeenCalled();
      expect(service['setPermissions']).not.toHaveBeenCalled();
      expect(bunker['ensureListeningForConnection']).not.toHaveBeenCalled();
    });
  });

  describe('create: approval mode', () => {
    it.each(['DENY', 'ASK'])('passes %s to the service', async (approvalMode) => {
      await create({ approvalMode });
      expect(service['createConnection']!.mock.calls[0]![3]).toEqual(
        expect.objectContaining({ approvalMode }),
      );
    });

    it('leaves the mode unset when none is sent (the service defaults it to DENY)', async () => {
      await create({});
      expect(service['createConnection']!.mock.calls[0]![3]).toEqual(
        expect.objectContaining({ approvalMode: undefined }),
      );
    });

    it.each(['ask', 'ALLOW', 1, null, {}])('rejects %j with 400 and creates nothing', async (approvalMode) => {
      await expect(create({ approvalMode })).rejects.toThrow(BadRequestException);
      expect(service['createConnection']).not.toHaveBeenCalled();
    });
  });

  describe('create: ownership', () => {
    it("binds to the caller's id, so another user's key is refused by the service", async () => {
      service['createConnection']!.mockRejectedValue(new NotFoundException('Key not found'));
      await expect(create({ nsecKeyId: 'victims-key' })).rejects.toThrow(NotFoundException);
      expect(service['createConnection']!.mock.calls[0]![0]).toBe('user-1');
      expect(bunker['ensureListeningForConnection']).not.toHaveBeenCalled();
    });
  });

  describe('PATCH :id/approval-mode', () => {
    it.each([undefined, {}, { mode: 'maybe' }, { mode: 'ask' }, { mode: 'ASK', extra: 1 }, 'ASK'])(
      'rejects the body %j with 400 and changes nothing',
      async (body) => {
        await expect(controller.setApprovalMode(req, 'conn-1', body)).rejects.toThrow(
          BadRequestException,
        );
        expect(service['setApprovalMode']).not.toHaveBeenCalled();
      },
    );

    it('switches to ASK for the owner and leaves the holds alone', async () => {
      await controller.setApprovalMode(req, 'conn-1', { mode: 'ASK' });
      expect(service['setApprovalMode']).toHaveBeenCalledWith('conn-1', 'user-1', 'ASK');
      expect(approvals.cancelForConnection).not.toHaveBeenCalled();
    });

    it('switching back to DENY answers whatever is being held, now', async () => {
      await controller.setApprovalMode(req, 'conn-1', { mode: 'DENY' });
      expect(approvals.cancelForConnection).toHaveBeenCalledWith('conn-1');
    });

    it("another user's connection: 404 from the service, and no hold is touched", async () => {
      service['setApprovalMode']!.mockRejectedValue(new NotFoundException('Connection not found'));
      await expect(controller.setApprovalMode(req, 'conn-1', { mode: 'DENY' })).rejects.toThrow(
        NotFoundException,
      );
      expect(approvals.cancelForConnection).not.toHaveBeenCalled();
    });
  });

  describe('holds end with the connection', () => {
    it('revoking cancels the holds, so the clients are answered now', async () => {
      await controller.updateStatus(req, 'conn-1', { status: 'REVOKED' });
      expect(approvals.cancelForConnection).toHaveBeenCalledWith('conn-1');
    });

    it('reactivating does not', async () => {
      await controller.updateStatus(req, 'conn-1', { status: 'ACTIVE' });
      expect(approvals.cancelForConnection).not.toHaveBeenCalled();
    });

    it("a foreign connection is not revoked and its holds are not cancelled", async () => {
      service['getConnection']!.mockRejectedValue(new NotFoundException('Connection not found'));
      await expect(controller.updateStatus(req, 'conn-1', { status: 'REVOKED' })).rejects.toThrow(
        NotFoundException,
      );
      expect(service['updateConnectionStatus']).not.toHaveBeenCalled();
      expect(approvals.cancelForConnection).not.toHaveBeenCalled();
    });

    it('deleting cancels the holds, after the ownership check passed', async () => {
      await controller.remove(req, 'conn-1');
      expect(service['deleteConnection']).toHaveBeenCalledWith('conn-1', 'user-1');
      expect(approvals.cancelForConnection).toHaveBeenCalledWith('conn-1');
    });

    it("deleting someone else's connection cancels nothing", async () => {
      service['deleteConnection']!.mockRejectedValue(new NotFoundException());
      await expect(controller.remove(req, 'conn-1')).rejects.toThrow(NotFoundException);
      expect(approvals.cancelForConnection).not.toHaveBeenCalled();
    });
  });
});
