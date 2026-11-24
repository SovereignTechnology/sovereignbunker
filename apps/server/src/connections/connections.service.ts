import {
  ConflictException,
  Injectable,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { APPROVAL_CONSTANTS } from '@bunker46/config';
import { PrismaService } from '../prisma/prisma.service.js';
import { EncryptionService } from '../common/crypto/encryption.service.js';
import { EventsService } from '../events/events.service.js';
import type { ConnectionStatus as PrismaConnectionStatus } from '@/generated/prisma/client.js';
import {
  checkPermission,
  DEFAULT_CONNECTION_PERMISSIONS,
  formatPermission,
  grantNeedsConfirmation,
  type ApprovalMode,
  type PermissionDescriptor,
} from '@bunker46/shared-types';

/** A permission row's identity, with the method-level (kind-less) row as kind "". */
const permKey = (p: { method: string; kind?: number | null }) => `${p.method}:${p.kind ?? ''}`;

@Injectable()
export class ConnectionsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly encryption: EncryptionService,
    private readonly eventsService: EventsService,
  ) {}

  async addNsecKey(userId: string, nsecHex: string, publicKey: string, label: string) {
    const encryptedNsec = this.encryption.encrypt(nsecHex);
    return this.prisma.nsecKey.create({
      data: { userId, publicKey, encryptedNsec, label },
    });
  }

  async getNsecKeys(userId: string) {
    return this.prisma.nsecKey.findMany({
      where: { userId },
      select: { id: true, publicKey: true, label: true, createdAt: true },
    });
  }

  async getDecryptedNsec(nsecKeyId: string, userId: string): Promise<string> {
    const key = await this.prisma.nsecKey.findUnique({ where: { id: nsecKeyId } });
    if (!key || key.userId !== userId) throw new ForbiddenException('Not your key');
    return this.encryption.decrypt(key.encryptedNsec);
  }

  async createConnection(
    userId: string,
    nsecKeyId: string,
    clientPubkey: string,
    data: {
      name?: string;
      logoUrl?: string;
      relays?: string[];
      secret?: string;
      remotePubkey?: string;
      /** What happens to a gated request the connection holds no permission for. Default DENY. */
      approvalMode?: ApprovalMode;
    },
    /**
     * Operator-chosen permission seed (granted). When the operator picks permissions (generating a
     * bunker:// URI, importing a nostrconnect:// URI) those are the authoritative grants, and an
     * empty list is a real choice: the connection starts able to do nothing, as the UI says.
     * Only an omitted list (undefined) falls back to DEFAULT_CONNECTION_PERMISSIONS, so a caller
     * that states no choice never gets a connection that is both fail-open and unconfigured.
     */
    seedPermissions?: PermissionDescriptor[],
  ) {
    // Authorization (C1): bind a connection only to an nsec key the caller actually owns. Without
    // this, an authenticated user could create a connection referencing another user's nsecKeyId and
    // have the bunker sign/decrypt with the victim's private key. Scope the lookup by userId so a
    // foreign or non-existent key is indistinguishable.
    const key = await this.prisma.nsecKey.findFirst({ where: { id: nsecKeyId, userId } });
    if (!key) throw new NotFoundException('Key not found');

    // Seed the connection's granted permissions under the default-deny RPC handler. The operator's
    // explicit list wins, even when empty. Permissions a client asks for in its `connect` request are
    // not part of this seed: they are recorded as PENDING requests for the operator to approve.
    const seed = seedPermissions ?? DEFAULT_CONNECTION_PERMISSIONS;
    // A list from a caller can repeat an entry; the unique index does not collapse kind-less rows.
    const unique = [...new Map(seed.map((p) => [permKey(p), p])).values()];

    // One transaction: a seed the database refuses must not leave a connection with no permissions
    // behind (an orphan the operator would have to find and delete).
    const conn = await this.prisma.$transaction(async (tx) => {
      const created = await tx.bunkerConnection.create({
        data: {
          userId,
          nsecKeyId,
          clientPubkey,
          name: data.name ?? 'Unnamed Connection',
          logoUrl: data.logoUrl,
          relays: data.relays ?? [],
          secret: data.secret,
          remotePubkey: data.remotePubkey,
          approvalMode: data.approvalMode ?? 'DENY',
          status: 'PENDING',
        },
      });
      if (unique.length > 0) {
        await tx.connectionPermission.createMany({
          data: unique.map((p) => ({
            connectionId: created.id,
            method: p.method,
            kind: p.kind ?? null,
            allowed: true,
          })),
        });
      }
      return created;
    });

    await this.eventsService.publishUserActivity(userId);

    return this.prisma.bunkerConnection.findUniqueOrThrow({
      where: { id: conn.id },
      include: { permissions: true },
    });
  }

  async listConnections(userId: string) {
    return this.prisma.bunkerConnection.findMany({
      where: { userId },
      include: {
        permissions: true,
        nsecKey: { select: { publicKey: true, label: true } },
        _count: { select: { logs: true } },
      },
      orderBy: { updatedAt: 'desc' },
    });
  }

  async getConnection(connectionId: string, userId: string) {
    const conn = await this.prisma.bunkerConnection.findUnique({
      where: { id: connectionId },
      include: {
        permissions: true,
        nsecKey: { select: { publicKey: true, label: true } },
        logs: { take: 20, orderBy: { createdAt: 'desc' } },
      },
    });
    if (!conn || conn.userId !== userId) throw new NotFoundException('Connection not found');
    return conn;
  }

  async updateConnectionStatus(connectionId: string, status: PrismaConnectionStatus) {
    return this.prisma.bunkerConnection.update({
      where: { id: connectionId },
      data: { status },
    });
  }

  /**
   * Replace the connection's GRANTED permission set (operator-authoritative). Granted rows
   * (`allowed = true`) are what the signer actually enforces, as a whitelist under the default-deny
   * RPC handler. Pending requests (`allowed = false`) are PRESERVED, so editing the whitelist never
   * silently discards a client's outstanding permission request.
   */
  async setPermissions(connectionId: string, permissions: PermissionDescriptor[]) {
    // Each permission once: a repeated entry would break the unique index halfway and, with the old
    // grants already deleted, leave the connection with none.
    const unique = [...new Map(permissions.map((p) => [permKey(p), p])).values()];
    // One transaction, so the grants are replaced whole or not at all.
    await this.prisma.$transaction(async (tx) => {
      await tx.connectionPermission.deleteMany({ where: { connectionId, allowed: true } });
      if (unique.length > 0) {
        // Drop any pending row that is now being granted, to satisfy the (connectionId, method,
        // kind) unique constraint before inserting the granted rows.
        await tx.connectionPermission.deleteMany({
          where: {
            connectionId,
            allowed: false,
            OR: unique.map((p) => ({ method: p.method, kind: p.kind ?? null })),
          },
        });
        await tx.connectionPermission.createMany({
          data: unique.map((p) => ({
            connectionId,
            method: p.method,
            kind: p.kind ?? null,
            allowed: true,
          })),
        });
      }
    });
  }

  /**
   * Record permissions a client asked for (on `connect`, or by trying a gated method) as PENDING
   * (`allowed = false`) for the operator to approve. Pending rows grant nothing (the handler enforces
   * only `allowed = true`), so a client can never self-escalate. A method/kind that already has a
   * row, or that a granted row already covers, is skipped: this never downgrades a grant, and a
   * client retrying the same request adds nothing. Skipped here rather than by the unique index,
   * which treats the kind-less rows (kind NULL) as all different.
   */
  async requestPermissions(connectionId: string, permissions: PermissionDescriptor[]) {
    if (permissions.length === 0) return;
    const existing = await this.prisma.connectionPermission.findMany({
      where: { connectionId },
      select: { id: true, method: true, kind: true, allowed: true },
    });
    const have = new Set(existing.map(permKey));
    const granted = existing
      .filter((e) => e.allowed)
      .map((e) => ({
        method: e.method as PermissionDescriptor['method'],
        kind: e.kind ?? undefined,
      }));
    const max = APPROVAL_CONSTANTS.MAX_PENDING_PERMISSIONS_PER_CONNECTION;
    const fresh = permissions
      .filter((p) => {
        const key = permKey(p);
        if (have.has(key) || checkPermission(granted, p)) return false;
        have.add(key);
        return true;
      })
      .slice(0, max);
    if (fresh.length === 0) return;
    // Every denied request files a row, one per kind a client tries, so the table is bounded: past
    // `max` the OLDEST pending rows make room (ids are cuids, which sort by creation time). Granted
    // rows are never touched.
    const pending = existing.filter((e) => !e.allowed).sort((a, b) => (a.id < b.id ? -1 : 1));
    const drop = pending.length + fresh.length - max;
    if (drop > 0) {
      await this.prisma.connectionPermission.deleteMany({
        where: { id: { in: pending.slice(0, drop).map((e) => e.id) } },
      });
    }
    await this.prisma.connectionPermission.createMany({
      data: fresh.map((p) => ({
        connectionId,
        method: p.method,
        kind: p.kind ?? null,
        allowed: false,
      })),
      skipDuplicates: true,
    });
  }

  /**
   * Grant permissions for good ("always allow" on an approval). Owner-checked. A pending row for the
   * same method/kind is replaced by the grant, and one that is already granted is left alone.
   */
  async grantPermissions(
    connectionId: string,
    userId: string,
    permissions: PermissionDescriptor[],
  ) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException('Connection not found');
    // A late "always allow" must not outlive the revoke (which also ended the holds).
    if (conn.status === 'REVOKED') throw new ConflictException('Connection is revoked');
    if (permissions.length === 0) return;

    const existing = await this.prisma.connectionPermission.findMany({
      where: { connectionId },
      select: { method: true, kind: true, allowed: true },
    });
    const grantedKeys = new Set(existing.filter((e) => e.allowed).map(permKey));
    const toGrant = [...new Map(permissions.map((p) => [permKey(p), p])).values()].filter(
      (p) => !grantedKeys.has(permKey(p)),
    );
    if (toGrant.length === 0) return;

    await this.prisma.connectionPermission.deleteMany({
      where: {
        connectionId,
        allowed: false,
        OR: toGrant.map((p) => ({ method: p.method, kind: p.kind ?? null })),
      },
    });
    await this.prisma.connectionPermission.createMany({
      data: toGrant.map((p) => ({
        connectionId,
        method: p.method,
        kind: p.kind ?? null,
        allowed: true,
      })),
      // A concurrent approval of the same request may have created the row first.
      skipDuplicates: true,
    });
    await this.eventsService.publishUserActivity(userId);
  }

  /** Switch what the signer does with a gated request the connection holds no permission for. */
  async setApprovalMode(connectionId: string, userId: string, mode: ApprovalMode) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException('Connection not found');
    const updated = await this.prisma.bunkerConnection.update({
      where: { id: connectionId },
      data: { approvalMode: mode },
      select: { id: true, approvalMode: true },
    });
    await this.eventsService.publishUserActivity(userId);
    return updated;
  }

  /**
   * Operator approves these pending permission requests, turning them into grants. Approving anything
   * but an ordinary kind (see grantNeedsConfirmation: a login, a profile, a seal, any encrypt or
   * decrypt, ...) needs `confirm`: the pending rows are filed by the client, so a hostile one can
   * file exactly the rows an unattended click would turn into blanket grants.
   */
  async approveRequests(
    connectionId: string,
    userId: string,
    permissions: PermissionDescriptor[],
    confirm = false,
  ) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException();
    // An empty list is nothing to approve, never "everything" (that is approveAllRequests).
    if (permissions.length === 0) return;
    const needing = permissions.filter(grantNeedsConfirmation);
    if (needing.length > 0 && !confirm) {
      throw new ConflictException(
        `Approving ${needing.map(formatPermission).join(', ')} is a permanent, wide grant: confirm it explicitly`,
      );
    }
    await this.prisma.connectionPermission.updateMany({
      where: {
        connectionId,
        allowed: false,
        OR: permissions.map((p) => ({ method: p.method, kind: p.kind ?? null })),
      },
      data: { allowed: true },
    });
    await this.eventsService.publishUserActivity(userId);
  }

  /**
   * "Approve all": every pending request that is an ordinary kind. The ones that need an explicit
   * confirmation (see approveRequests) stay pending and are counted, so one click on a list a client
   * filled cannot grant them.
   */
  async approveAllRequests(connectionId: string, userId: string) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException();
    const pending = await this.prisma.connectionPermission.findMany({
      where: { connectionId, allowed: false },
      select: { id: true, method: true, kind: true },
    });
    const ordinary = pending.filter(
      (p) =>
        !grantNeedsConfirmation({
          method: p.method as PermissionDescriptor['method'],
          kind: p.kind ?? undefined,
        }),
    );
    if (ordinary.length > 0) {
      await this.prisma.connectionPermission.updateMany({
        where: { id: { in: ordinary.map((p) => p.id) }, connectionId, allowed: false },
        data: { allowed: true },
      });
    }
    await this.eventsService.publishUserActivity(userId);
    return { approved: ordinary.length, needConfirmation: pending.length - ordinary.length };
  }

  /** Operator denies (deletes) pending permission requests (all, or a given subset). */
  async denyRequests(connectionId: string, userId: string, permissions?: PermissionDescriptor[]) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException();
    await this.prisma.connectionPermission.deleteMany({
      where: {
        connectionId,
        allowed: false,
        ...(permissions?.length
          ? { OR: permissions.map((p) => ({ method: p.method, kind: p.kind ?? null })) }
          : {}),
      },
    });
    await this.eventsService.publishUserActivity(userId);
  }

  async getPermissions(connectionId: string): Promise<PermissionDescriptor[]> {
    const perms = await this.prisma.connectionPermission.findMany({
      where: { connectionId, allowed: true },
    });
    return perms.map((p) => ({
      method: p.method as PermissionDescriptor['method'],
      kind: p.kind ?? undefined,
    }));
  }

  async toggleLogging(connectionId: string, userId: string, enabled: boolean) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException();
    return this.prisma.bunkerConnection.update({
      where: { id: connectionId },
      data: { loggingEnabled: enabled },
    });
  }

  async touchActivity(connectionId: string) {
    await this.prisma.bunkerConnection.update({
      where: { id: connectionId },
      data: { lastActivity: new Date() },
    });
  }

  async deleteConnection(connectionId: string, userId: string) {
    const conn = await this.prisma.bunkerConnection.findUnique({ where: { id: connectionId } });
    if (!conn || conn.userId !== userId) throw new NotFoundException();
    await this.prisma.bunkerConnection.delete({ where: { id: connectionId } });
  }

  async updateNsecKeyLabel(nsecKeyId: string, userId: string, label: string) {
    const key = await this.prisma.nsecKey.findUnique({ where: { id: nsecKeyId } });
    if (!key || key.userId !== userId) throw new NotFoundException('Key not found');
    return this.prisma.nsecKey.update({
      where: { id: nsecKeyId },
      data: { label },
      select: { id: true, publicKey: true, label: true, createdAt: true },
    });
  }

  async deleteNsecKey(nsecKeyId: string, userId: string) {
    const key = await this.prisma.nsecKey.findUnique({ where: { id: nsecKeyId } });
    if (!key || key.userId !== userId) throw new NotFoundException('Key not found');
    const connectionCount = await this.prisma.bunkerConnection.count({ where: { nsecKeyId } });
    if (connectionCount > 0) {
      throw new ForbiddenException(
        'Cannot delete key with active connections. Remove connections first.',
      );
    }
    await this.prisma.nsecKey.delete({ where: { id: nsecKeyId } });
  }

  /**
   * Resolve the connection for an incoming NIP-46 request by BOTH the client pubkey and the signer
   * key the request was addressed to (the relay #p tag / listener key). Binding on the signer key
   * (M1) prevents key-confusion: a client that holds connections to several of the user's keys
   * cannot have a request addressed to key A served by a connection bound to key B — which could
   * sign/decrypt with the wrong key under a different, possibly broader permission set.
   */
  async findByClientAndSigner(clientPubkey: string, signerPubkey: string) {
    return this.prisma.bunkerConnection.findFirst({
      where: {
        clientPubkey,
        status: { in: ['ACTIVE', 'PENDING'] },
        nsecKey: { publicKey: signerPubkey },
      },
      include: { permissions: true, nsecKey: true },
      orderBy: { createdAt: 'desc' },
    });
  }

  async getAllConnectionsForNsecKey(nsecKeyId: string) {
    return this.prisma.bunkerConnection.findMany({
      where: { nsecKeyId, status: { in: ['ACTIVE', 'PENDING'] } },
      select: { relays: true },
    });
  }
}
