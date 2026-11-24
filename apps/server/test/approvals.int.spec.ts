import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { ConnectionsService } from '../src/connections/connections.service.js';
import type { EncryptionService } from '../src/common/crypto/encryption.service.js';
import type { EventsService } from '../src/events/events.service.js';

/**
 * DB integration test for hold-and-ask: the `approval_mode` column and the permission-row cleanup,
 * against the schema the migrations actually build.
 *
 * Opt-in like the other integration specs: RUN_DB_TESTS=1 and a Postgres reachable via DATABASE_URL
 * with the migrations applied (`pnpm test:integration`). Proves what mocked unit tests cannot:
 *  - a connection row that never heard of the column (every row that existed before the migration)
 *    reads back as DENY, so no existing connection starts holding requests;
 *  - the database refuses a mode that is not DENY or ASK;
 *  - the dedupe migration collapses duplicate kind-less permission rows, never loses a grant, and a
 *    second run changes nothing;
 *  - the service no longer creates duplicates, which the unique index alone cannot stop (NULLs are
 *    distinct in it).
 */
const RUN = process.env['RUN_DB_TESTS'] === '1';

const migrationSql = (dir: string) =>
  readFileSync(
    fileURLToPath(new URL(`../prisma/migrations/${dir}/migration.sql`, import.meta.url)),
    'utf8',
  );

describe.skipIf(!RUN)('hold-and-ask schema (DB integration)', () => {
  let prisma: PrismaService;
  let service: ConnectionsService;

  beforeAll(async () => {
    prisma = new PrismaService();
    await prisma.onModuleInit();
    service = new ConnectionsService(
      prisma,
      { encrypt: (v: string) => v, decrypt: (v: string) => v } as unknown as EncryptionService,
      { publishUserActivity: async () => undefined } as unknown as EventsService,
    );
  });

  afterAll(async () => {
    if (prisma) await prisma.onModuleDestroy();
  });

  beforeEach(async () => {
    await prisma.signingLog.deleteMany();
    await prisma.bunkerConnection.deleteMany();
    await prisma.nsecKey.deleteMany();
    await prisma.user.deleteMany();
  });

  async function seedKey() {
    const user = await prisma.user.create({
      data: { username: `ask-${Date.now()}-${Math.random()}`, passwordHash: 'x' },
    });
    const nsecKey = await prisma.nsecKey.create({
      data: { userId: user.id, publicKey: `pk-${Math.random()}`, encryptedNsec: 'enc' },
    });
    return { user, nsecKey };
  }

  async function seedConnection() {
    const { user, nsecKey } = await seedKey();
    const conn = await prisma.bunkerConnection.create({
      data: {
        userId: user.id,
        nsecKeyId: nsecKey.id,
        clientPubkey: `client-${Math.random()}`,
        name: 'App',
      },
    });
    return { user, nsecKey, conn };
  }

  const insertRaw = (connectionId: string, id: string, method: string, allowed: boolean) =>
    prisma.$executeRaw`
      INSERT INTO "connection_permissions" ("id", "connection_id", "method", "kind", "allowed")
      VALUES (${id}, ${connectionId}, ${method}, NULL, ${allowed})`;

  const rows = (connectionId: string, method: string) =>
    prisma.connectionPermission.findMany({
      where: { connectionId, method, kind: null },
      orderBy: { id: 'asc' },
    });

  describe('approval_mode', () => {
    it('a connection inserted without the column (a pre-existing row) is DENY', async () => {
      const { user, nsecKey } = await seedKey();
      await prisma.$executeRaw`
        INSERT INTO "bunker_connections"
          ("id", "user_id", "nsec_key_id", "client_pubkey", "name", "status", "relays",
           "logging_enabled", "created_at", "updated_at")
        VALUES
          ('legacy-conn', ${user.id}, ${nsecKey.id}, 'legacy-client', 'Legacy',
           'ACTIVE'::"ConnectionStatus", ARRAY[]::TEXT[], false, now(), now())`;
      const conn = await prisma.bunkerConnection.findUniqueOrThrow({
        where: { id: 'legacy-conn' },
      });
      expect(conn.approvalMode).toBe('DENY');
    });

    it('a connection created through Prisma without a mode is DENY', async () => {
      const { conn } = await seedConnection();
      expect(conn.approvalMode).toBe('DENY');
    });

    it('stores ASK, and the service creates a connection in either mode', async () => {
      const { user, nsecKey } = await seedKey();
      const ask = await service.createConnection(user.id, nsecKey.id, 'client-ask', {
        name: 'Ask',
        approvalMode: 'ASK',
      });
      const deny = await service.createConnection(user.id, nsecKey.id, 'client-deny', {
        name: 'Deny',
      });
      expect(ask.approvalMode).toBe('ASK');
      expect(deny.approvalMode).toBe('DENY');
    });

    it('refuses a mode that is neither DENY nor ASK', async () => {
      const { conn } = await seedConnection();
      await expect(
        prisma.$executeRawUnsafe(
          `UPDATE "bunker_connections" SET "approval_mode" = 'MAYBE' WHERE "id" = '${conn.id}'`,
        ),
      ).rejects.toThrow();
    });

    it('only the owner can switch the mode', async () => {
      const { conn } = await seedConnection();
      const { user: stranger } = await seedKey();
      await expect(service.setApprovalMode(conn.id, stranger.id, 'ASK')).rejects.toThrow();
      const unchanged = await prisma.bunkerConnection.findUniqueOrThrow({ where: { id: conn.id } });
      expect(unchanged.approvalMode).toBe('DENY');
    });
  });

  describe('duplicate kind-less permission rows', () => {
    it('the unique index alone lets duplicates in (why the application and the migration handle them)', async () => {
      const { conn } = await seedConnection();
      await insertRaw(conn.id, 'dup-1', 'nip44_decrypt', false);
      await insertRaw(conn.id, 'dup-2', 'nip44_decrypt', false);
      expect(await rows(conn.id, 'nip44_decrypt')).toHaveLength(2);
    });

    it('the cleanup migration keeps one row, and a granted one over pending ones', async () => {
      const { conn } = await seedConnection();
      await insertRaw(conn.id, 'a-pending', 'nip44_decrypt', false);
      await insertRaw(conn.id, 'm-granted', 'nip44_decrypt', true);
      await insertRaw(conn.id, 'z-pending', 'nip44_decrypt', false);
      await prisma.connectionPermission.create({
        data: { connectionId: conn.id, method: 'sign_event', kind: 1, allowed: true },
      });
      await insertRaw(conn.id, 'other-method', 'nip04_decrypt', false);

      await prisma.$executeRawUnsafe(migrationSql('20261124000100_dedupe_null_kind_permissions'));

      const kept = await rows(conn.id, 'nip44_decrypt');
      expect(kept).toHaveLength(1);
      expect(kept[0]).toMatchObject({ id: 'm-granted', allowed: true });
      // Everything else is untouched.
      expect(await rows(conn.id, 'nip04_decrypt')).toHaveLength(1);
      expect(
        await prisma.connectionPermission.count({ where: { connectionId: conn.id, kind: 1 } }),
      ).toBe(1);
    });

    it('running the cleanup again changes nothing', async () => {
      const { conn } = await seedConnection();
      await insertRaw(conn.id, 'a', 'nip44_decrypt', false);
      await insertRaw(conn.id, 'b', 'nip44_decrypt', false);
      const sql = migrationSql('20261124000100_dedupe_null_kind_permissions');
      await prisma.$executeRawUnsafe(sql);
      const once = await prisma.connectionPermission.count({ where: { connectionId: conn.id } });
      await prisma.$executeRawUnsafe(sql);
      expect(await prisma.connectionPermission.count({ where: { connectionId: conn.id } })).toBe(
        once,
      );
      expect(once).toBe(1);
    });

    it('does not merge rows across connections', async () => {
      const first = await seedConnection();
      const second = await seedConnection();
      await insertRaw(first.conn.id, 'p-1', 'nip44_decrypt', false);
      await insertRaw(second.conn.id, 'p-2', 'nip44_decrypt', false);
      await prisma.$executeRawUnsafe(migrationSql('20261124000100_dedupe_null_kind_permissions'));
      expect(await rows(first.conn.id, 'nip44_decrypt')).toHaveLength(1);
      expect(await rows(second.conn.id, 'nip44_decrypt')).toHaveLength(1);
    });

    it('requesting the same method-level permission again adds no second row', async () => {
      const { conn } = await seedConnection();
      await service.requestPermissions(conn.id, [{ method: 'nip44_decrypt' }]);
      await service.requestPermissions(conn.id, [{ method: 'nip44_decrypt' }]);
      await service.requestPermissions(conn.id, [{ method: 'nip44_decrypt' }]);
      expect(await rows(conn.id, 'nip44_decrypt')).toHaveLength(1);
    });

    it('requesting the same kind again adds no second row', async () => {
      const { conn } = await seedConnection();
      await service.requestPermissions(conn.id, [{ method: 'sign_event', kind: 27235 }]);
      await service.requestPermissions(conn.id, [{ method: 'sign_event', kind: 27235 }]);
      expect(
        await prisma.connectionPermission.count({ where: { connectionId: conn.id, kind: 27235 } }),
      ).toBe(1);
    });
  });

  describe('granting an approval for good', () => {
    it('turns the pending row into one grant, and granting again adds nothing', async () => {
      const { user, conn } = await seedConnection();
      await service.requestPermissions(conn.id, [{ method: 'sign_event', kind: 27235 }]);

      await service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]);
      await service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]);

      const all = await prisma.connectionPermission.findMany({ where: { connectionId: conn.id } });
      expect(all).toHaveLength(1);
      expect(all[0]).toMatchObject({ method: 'sign_event', kind: 27235, allowed: true });
      expect(await service.getPermissions(conn.id)).toEqual([
        { method: 'sign_event', kind: 27235 },
      ]);
    });

    it('a method-level grant works the same way', async () => {
      const { user, conn } = await seedConnection();
      await service.requestPermissions(conn.id, [{ method: 'nip44_decrypt' }]);
      await service.grantPermissions(conn.id, user.id, [{ method: 'nip44_decrypt' }]);
      const kept = await rows(conn.id, 'nip44_decrypt');
      expect(kept).toHaveLength(1);
      expect(kept[0]!.allowed).toBe(true);
    });

    it('refuses to grant on a revoked connection, and stores nothing', async () => {
      const { user, conn } = await seedConnection();
      await prisma.bunkerConnection.update({ where: { id: conn.id }, data: { status: 'REVOKED' } });
      await expect(
        service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]),
      ).rejects.toThrow();
      expect(await prisma.connectionPermission.count({ where: { connectionId: conn.id } })).toBe(0);
    });

    it('a later grant for the same kind adds no second row even when two approvals race', async () => {
      const { user, conn } = await seedConnection();
      await Promise.allSettled([
        service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]),
        service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]),
      ]);
      expect(
        await prisma.connectionPermission.count({
          where: { connectionId: conn.id, method: 'sign_event', kind: 27235 },
        }),
      ).toBe(1);
    });

    it("never grants on someone else's connection", async () => {
      const { conn } = await seedConnection();
      const { user: stranger } = await seedKey();
      await expect(
        service.grantPermissions(conn.id, stranger.id, [{ method: 'sign_event', kind: 27235 }]),
      ).rejects.toThrow();
      expect(await prisma.connectionPermission.count({ where: { connectionId: conn.id } })).toBe(0);
    });
  });

  describe('replacing and approving permissions', () => {
    it('a list with a repeated entry stores it once and keeps every grant (it must not hit the unique index and wipe them)', async () => {
      const { conn } = await seedConnection();
      await service.setPermissions(conn.id, [{ method: 'sign_event', kind: 1 }]);

      await service.setPermissions(conn.id, [
        { method: 'sign_event', kind: 7 },
        { method: 'sign_event', kind: 7 },
        { method: 'nip44_decrypt' },
        { method: 'nip44_decrypt' },
      ]);

      expect(await service.getPermissions(conn.id)).toEqual(
        expect.arrayContaining([{ method: 'sign_event', kind: 7 }, { method: 'nip44_decrypt' }]),
      );
      expect(await prisma.connectionPermission.count({ where: { connectionId: conn.id } })).toBe(2);
    });

    it('"approve all" grants the ordinary kinds and leaves a login, a profile and a decrypt pending', async () => {
      const { user, conn } = await seedConnection();
      await service.requestPermissions(conn.id, [
        { method: 'sign_event', kind: 1 },
        { method: 'sign_event', kind: 7 },
        { method: 'sign_event', kind: 27235 },
        { method: 'sign_event', kind: 0 },
        { method: 'nip44_decrypt' },
      ]);

      const result = await service.approveAllRequests(conn.id, user.id);

      expect(result).toEqual({ approved: 2, needConfirmation: 3 });
      expect(await service.getPermissions(conn.id)).toEqual(
        expect.arrayContaining([
          { method: 'sign_event', kind: 1 },
          { method: 'sign_event', kind: 7 },
        ]),
      );
      expect(await service.getPermissions(conn.id)).toHaveLength(2);
      expect(
        await prisma.connectionPermission.count({
          where: { connectionId: conn.id, allowed: false },
        }),
      ).toBe(3);
    });

    it('"approve all" never touches someone else\'s connection', async () => {
      const { conn } = await seedConnection();
      const { user: stranger } = await seedKey();
      await service.requestPermissions(conn.id, [{ method: 'sign_event', kind: 1 }]);
      await expect(service.approveAllRequests(conn.id, stranger.id)).rejects.toThrow();
      expect(await service.getPermissions(conn.id)).toEqual([]);
    });

    it('approving a wide request needs the confirmation, and with it grants exactly that one', async () => {
      const { user, conn } = await seedConnection();
      await service.requestPermissions(conn.id, [
        { method: 'sign_event', kind: 27235 },
        { method: 'sign_event', kind: 1 },
      ]);
      await expect(
        service.approveRequests(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]),
      ).rejects.toThrow(/confirm/);
      expect(await service.getPermissions(conn.id)).toEqual([]);

      await service.approveRequests(
        conn.id,
        user.id,
        [{ method: 'sign_event', kind: 27235 }],
        true,
      );
      expect(await service.getPermissions(conn.id)).toEqual([
        { method: 'sign_event', kind: 27235 },
      ]);
    });
  });

  describe('pending permission requests', () => {
    it('keeps the newest 50 per connection: a client probing kinds cannot grow the table without end', async () => {
      const { conn } = await seedConnection();
      for (let kind = 1; kind <= 55; kind++) {
        await service.requestPermissions(conn.id, [{ method: 'sign_event', kind }]);
      }
      const pending = await prisma.connectionPermission.findMany({
        where: { connectionId: conn.id, allowed: false },
      });
      expect(pending).toHaveLength(50);
      const kinds = pending.map((p) => p.kind).sort((a, b) => a! - b!);
      // The five oldest are the ones dropped.
      expect(kinds[0]).toBe(6);
      expect(kinds[49]).toBe(55);
    });

    it('never drops a granted row to make room', async () => {
      const { user, conn } = await seedConnection();
      await service.grantPermissions(conn.id, user.id, [{ method: 'sign_event', kind: 27235 }]);
      for (let kind = 1; kind <= 55; kind++) {
        await service.requestPermissions(conn.id, [{ method: 'sign_event', kind }]);
      }
      expect(await service.getPermissions(conn.id)).toEqual([
        { method: 'sign_event', kind: 27235 },
      ]);
    });
  });

  describe('seeding', () => {
    it('an empty chosen list creates a connection that holds no permission at all', async () => {
      const { user, nsecKey } = await seedKey();
      const conn = await service.createConnection(
        user.id,
        nsecKey.id,
        'client-x',
        { name: 'X' },
        [],
      );
      expect(await prisma.connectionPermission.count({ where: { connectionId: conn.id } })).toBe(0);
    });

    it('no list at all gets the conservative defaults, each once', async () => {
      const { user, nsecKey } = await seedKey();
      const conn = await service.createConnection(user.id, nsecKey.id, 'client-y', { name: 'Y' });
      const granted = await service.getPermissions(conn.id);
      expect(granted.map((p) => p.kind).sort()).toEqual([0, 1, 3, 4, 7]);
    });

    it('a seed the database cannot store leaves no connection behind (one transaction)', async () => {
      const { user, nsecKey } = await seedKey();
      await expect(
        service.createConnection(user.id, nsecKey.id, 'client-orphan', { name: 'Orphan' }, [
          { method: 'sign_event', kind: 3_000_000_000 },
        ]),
      ).rejects.toThrow();
      expect(
        await prisma.bunkerConnection.count({ where: { clientPubkey: 'client-orphan' } }),
      ).toBe(0);
    });

    it('a repeated entry in the chosen list is stored once', async () => {
      const { user, nsecKey } = await seedKey();
      const conn = await service.createConnection(user.id, nsecKey.id, 'client-z', { name: 'Z' }, [
        { method: 'nip44_decrypt' },
        { method: 'nip44_decrypt' },
      ]);
      expect(await rows(conn.id, 'nip44_decrypt')).toHaveLength(1);
    });
  });
});
