import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest';
import { WebSocketServer, type WebSocket as ServerSocket } from 'ws';
import { generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure';
import { BunkerSigner } from 'nostr-tools/nip46';
import { SimplePool } from 'nostr-tools/pool';
import { bytesToHex } from '@noble/hashes/utils.js';
import { BunkerService } from '../src/bunker/bunker.service.js';
import { BunkerRpcHandler } from '../src/bunker/bunker-rpc.handler.js';
import { ApprovalService } from '../src/bunker/approval.service.js';
import { ApprovalsController } from '../src/bunker/approvals.controller.js';
import { ConnectionsController } from '../src/connections/connections.controller.js';
import type { ConnectionsService } from '../src/connections/connections.service.js';
import type { BunkerService as BunkerServiceType } from '../src/bunker/bunker.service.js';
import type { LoggingService } from '../src/logging/logging.service.js';
import type { EventsService } from '../src/events/events.service.js';
import type { EncryptionService } from '../src/common/crypto/encryption.service.js';
import type { PrismaService } from '../src/prisma/prisma.service.js';

// The one test seam. In production the signer only listens on wss:// relays that are not loopback or
// private (SafeRelayUrlSchema keeps it away from internal hosts), so the in-process relay below, which
// is ws://127.0.0.1, would be filtered out and the signer would fall back to the public default relays.
// Everything else in this spec is the real code.
vi.mock('@bunker46/shared-types', async (importOriginal) => {
  const { z } = await import('zod');
  return {
    ...(await importOriginal<typeof import('@bunker46/shared-types')>()),
    SafeRelayUrlSchema: z.string(),
  };
});

/**
 * Hold-and-ask end to end, over a real relay connection with a real NIP-46 client.
 *
 * What the unit tests cannot show is how an actual client treats the two replies: nostr-tools'
 * BunkerSigner calls `onauth` for an `auth_url` reply and then keeps waiting for the final one under
 * the same request id. Here the signer side is the real BunkerService, RPC handler, ApprovalService
 * and ApprovalsController (only the database is replaced by an in-memory fake) and the client is the
 * real BunkerSigner, talking through a small in-process relay over WebSockets.
 */

const BASE = 'https://signer.example.test:50217';
const USER = 'user-1';
const DENIED = 'Permission denied for sign_event kind:27235';

type Filter = { kinds?: number[]; since?: number; '#p'?: string[] };
type RelayEvent = { id: string; kind: number; created_at: number; tags: string[][] };

/** Just enough relay for NIP-46: stores events, serves REQ (with stored events), pushes new ones. */
async function startRelay() {
  const wss = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  // The port is only known once the server is listening.
  await new Promise<void>((resolve, reject) => {
    wss.once('listening', resolve);
    wss.once('error', reject);
  });
  const stored: RelayEvent[] = [];
  const subs = new Map<ServerSocket, Map<string, Filter[]>>();

  const matches = (f: Filter, e: RelayEvent) =>
    (!f.kinds || f.kinds.includes(e.kind)) &&
    (f.since === undefined || e.created_at >= f.since) &&
    (!f['#p'] || e.tags.some((t) => t[0] === 'p' && f['#p']!.includes(t[1] as string)));

  wss.on('connection', (socket) => {
    subs.set(socket, new Map());
    socket.on('close', () => subs.delete(socket));
    socket.on('message', (raw) => {
      const msg = JSON.parse(raw.toString()) as [string, ...unknown[]];
      if (msg[0] === 'EVENT') {
        const event = msg[1] as RelayEvent;
        stored.push(event);
        socket.send(JSON.stringify(['OK', event.id, true, '']));
        for (const [other, bySub] of subs) {
          for (const [subId, filters] of bySub) {
            if (filters.some((f) => matches(f, event))) {
              other.send(JSON.stringify(['EVENT', subId, event]));
            }
          }
        }
      } else if (msg[0] === 'REQ') {
        const subId = msg[1] as string;
        const filters = msg.slice(2) as Filter[];
        subs.get(socket)?.set(subId, filters);
        for (const e of stored) {
          if (filters.some((f) => matches(f, e))) socket.send(JSON.stringify(['EVENT', subId, e]));
        }
        socket.send(JSON.stringify(['EOSE', subId]));
      } else if (msg[0] === 'CLOSE') {
        subs.get(socket)?.delete(msg[1] as string);
      }
    });
  });

  return {
    url: () => `ws://127.0.0.1:${(wss.address() as { port: number }).port}`,
    close: () =>
      new Promise<void>((resolve) => {
        for (const socket of subs.keys()) socket.terminate();
        wss.close(() => resolve());
      }),
  };
}

const until = async (cond: () => boolean, what: string, ms = 5000) => {
  const deadline = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 15));
  }
};

describe('hold and ask: a real NIP-46 client against the real signer, over a relay', () => {
  let relay: Awaited<ReturnType<typeof startRelay>>;
  const cleanups: Array<() => Promise<void> | void> = [];

  beforeAll(async () => {
    relay = await startRelay();
  });
  afterAll(async () => {
    await relay.close();
  });
  afterEach(async () => {
    for (const fn of cleanups.splice(0).reverse()) await fn();
  });

  async function boot(opts: { approvalMode: 'ASK' | 'DENY'; ttlMs?: number; grant?: boolean }) {
    const signerSk = generateSecretKey();
    const signerPk = getPublicKey(signerSk);
    const signerNsec = bytesToHex(signerSk);
    const clientSk = generateSecretKey();
    const clientPk = getPublicKey(clientSk);

    // The database, replaced by one connection in memory.
    const conn = {
      id: 'conn-1',
      userId: USER,
      name: 'BIES',
      clientPubkey: clientPk,
      status: 'ACTIVE',
      relays: [] as string[],
      secret: undefined as string | undefined,
      approvalMode: opts.approvalMode,
      permissions: [] as Array<{ method: string; kind: number | null; allowed: boolean }>,
      nsecKey: { encryptedNsec: 'enc' },
    };
    if (opts.grant) conn.permissions.push({ method: 'sign_event', kind: 27235, allowed: true });
    const connections = {
      findByClientAndSigner: vi.fn(async () => conn),
      // What the real service does with a status change, so a revoke has to come from production code.
      updateConnectionStatus: vi.fn(async (_id: string, status: string) => {
        conn.status = status;
        return conn;
      }),
      getConnection: vi.fn(async () => conn),
      requestPermissions: vi.fn(async () => undefined),
      touchActivity: vi.fn(async () => undefined),
      denyRequests: vi.fn(async () => undefined),
      grantPermissions: vi.fn(
        async (_c: string, _u: string, perms: Array<{ method: string; kind?: number }>) => {
          for (const p of perms) {
            conn.permissions.push({ method: p.method, kind: p.kind ?? null, allowed: true });
          }
        },
      ),
    };
    const logSigningAction = vi.fn(async () => undefined);
    const approvals = new ApprovalService({ ttlMs: opts.ttlMs ?? 100_000, publicBaseUrl: BASE }, {
      publishUserActivity: vi.fn(async () => undefined),
    } as unknown as EventsService);
    const handler = new BunkerRpcHandler(
      connections as unknown as ConnectionsService,
      { logSigningAction } as unknown as LoggingService,
      { publishUserActivity: vi.fn(async () => undefined) } as unknown as EventsService,
      { decrypt: () => signerNsec } as unknown as EncryptionService,
      approvals,
    );
    const svc = new BunkerService(
      handler,
      {
        nsecKey: { findMany: async () => [] },
        relayConfig: { findMany: async () => [] },
      } as unknown as PrismaService,
      {} as unknown as EncryptionService,
      [],
      approvals,
    );
    await svc.onModuleInit();
    svc.startListeningForKey(signerPk, signerNsec, [relay.url()]);

    const controller = new ApprovalsController(
      approvals,
      connections as unknown as ConnectionsService,
    );
    const asOwner = { user: { sub: USER } } as unknown as Parameters<
      ApprovalsController['list']
    >[0];
    // The real revoke route: it sets the status and ends the holds, or the test below fails.
    const connectionsController = new ConnectionsController(
      connections as unknown as ConnectionsService,
      svc as unknown as BunkerServiceType,
      approvals,
    );

    // The client: nostr-tools' own NIP-46 signer, the one BIES uses.
    const authUrls: string[] = [];
    const clientPool = new SimplePool();
    const client = BunkerSigner.fromBunker(
      clientSk,
      { pubkey: signerPk, relays: [relay.url()], secret: null },
      { pool: clientPool, onauth: (url: string) => authUrls.push(url) },
    );
    cleanups.push(async () => {
      try {
        await client.close();
      } catch {
        // already closed
      }
      clientPool.close([relay.url()]);
      await svc.onModuleDestroy();
      approvals.onModuleDestroy();
    });
    // Let the signer's subscription reach the relay before the first request.
    await new Promise((r) => setTimeout(r, 150));
    await client.connect();

    const login = () =>
      client.signEvent({
        kind: 27235,
        created_at: Math.floor(Date.now() / 1000),
        tags: [
          ['u', 'https://app.example/login'],
          ['method', 'POST'],
        ],
        content: '',
      });
    const oneHold = () => approvals.list(USER)[0]!;

    return {
      signerPk,
      conn,
      connections,
      logSigningAction,
      approvals,
      controller,
      asOwner,
      authUrls,
      login,
      oneHold,
      revoke: () =>
        connectionsController.updateStatus(asOwner as never, conn.id, { status: 'REVOKED' }),
    };
  }

  it('approve once: the client is told once where to go, waits, then gets its signature', async () => {
    const t = await boot({ approvalMode: 'ASK' });
    const pending = t.login();
    const settled = vi.fn();
    void pending.then(settled, settled);

    await until(() => t.authUrls.length === 1, 'the auth_url interim');
    const hold = t.oneHold();
    expect(t.authUrls[0]).toBe(`${BASE}/approvals/${hold.token}`);
    // The client has been told to wait, and is still waiting: nothing has settled it.
    await new Promise((r) => setTimeout(r, 200));
    expect(settled).not.toHaveBeenCalled();
    // The URL the login is for is what tells it apart from a login that deletes an account.
    expect(hold.preview).toMatchObject({
      kind: 27235,
      tags: [
        { name: 'u', values: ['https://app.example/login'] },
        { name: 'method', values: ['POST'] },
      ],
      httpAuth: { host: 'app.example', path: '/login', method: 'POST' },
    });

    await t.controller.approve(t.asOwner, hold.token, { mode: 'once' });
    const signed = await pending;

    expect(signed.kind).toBe(27235);
    expect(signed.pubkey).toBe(t.signerPk);
    expect(verifyEvent(signed)).toBe(true);
    // Exactly one interim for the request, and the grant was NOT stored.
    expect(t.authUrls).toHaveLength(1);
    expect(t.connections.grantPermissions).not.toHaveBeenCalled();
    expect(t.logSigningAction).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'APPROVED', metadata: { approval: 'approved_once' } }),
    );
  });

  it('approve once covers that request only: the next login is held again', async () => {
    const t = await boot({ approvalMode: 'ASK' });
    const first = t.login();
    await until(() => t.approvals.list(USER).length === 1, 'the first hold');
    await t.controller.approve(t.asOwner, t.oneHold().token, { mode: 'once' });
    await first;

    const second = t.login();
    void second.catch(() => undefined);
    await until(() => t.authUrls.length === 2, 'a second interim for the second request');
    await t.controller.deny(t.asOwner, t.oneHold().token);
    await expect(second).rejects.toThrow(DENIED);
  });

  it('always allow: signs, stores the grant, and the next login needs no answer at all', async () => {
    const t = await boot({ approvalMode: 'ASK' });
    const first = t.login();
    await until(() => t.approvals.list(USER).length === 1, 'the hold');
    await t.controller.approve(t.asOwner, t.oneHold().token, { mode: 'always' });
    expect(verifyEvent(await first)).toBe(true);

    expect(t.connections.grantPermissions).toHaveBeenCalledWith(t.conn.id, USER, [
      { method: 'sign_event', kind: 27235 },
    ]);
    const urlsBefore = t.authUrls.length;
    const again = await t.login();
    expect(verifyEvent(again)).toBe(true);
    expect(t.authUrls).toHaveLength(urlsBefore); // no interim: nothing was held
    expect(t.approvals.size).toBe(0);
  });

  it('deny: the client gets the unchanged permission error, and the denial is logged', async () => {
    const t = await boot({ approvalMode: 'ASK' });
    const pending = t.login();
    void pending.catch(() => undefined);
    await until(() => t.approvals.list(USER).length === 1, 'the hold');
    await t.controller.deny(t.asOwner, t.oneHold().token);

    await expect(pending).rejects.toThrow(DENIED);
    expect(t.authUrls).toHaveLength(1);
    expect(t.connections.denyRequests).toHaveBeenCalledWith(t.conn.id, USER, [
      { method: 'sign_event', kind: 27235 },
    ]);
    expect(t.logSigningAction).toHaveBeenCalledWith(
      expect.objectContaining({
        result: 'DENIED',
        errorMessage: DENIED,
        metadata: { approval: 'denied' },
      }),
    );
  });

  it('nobody answers in time: the client gets the same error once the hold expires', async () => {
    const t = await boot({ approvalMode: 'ASK', ttlMs: 1500 });
    const pending = t.login();
    void pending.catch(() => undefined);
    await until(() => t.authUrls.length === 1, 'the interim');
    await expect(pending).rejects.toThrow(DENIED);
    expect(t.approvals.size).toBe(0);
    expect(t.logSigningAction).toHaveBeenCalledWith(
      expect.objectContaining({ result: 'DENIED', metadata: { approval: 'expired' } }),
    );
  });

  it('revoked while held: the client is answered at once and nothing is signed', async () => {
    const t = await boot({ approvalMode: 'ASK' });
    const pending = t.login();
    void pending.catch(() => undefined);
    await until(() => t.approvals.list(USER).length === 1, 'the hold');
    // Through the real route: the status is set by it, not by the test.
    expect(t.conn.status).toBe('ACTIVE');
    await t.revoke();
    expect(t.conn.status).toBe('REVOKED');
    await expect(pending).rejects.toThrow('Connection revoked');
    expect(t.approvals.size).toBe(0);
    // Nothing was signed, and what was logged is a refusal, never an approval.
    expect(t.logSigningAction).not.toHaveBeenCalledWith(
      expect.objectContaining({ result: 'APPROVED' }),
    );
  });

  it('a connection that is not in ask mode never holds: refused at once, no auth_url (what ngit and other clients see)', async () => {
    const t = await boot({ approvalMode: 'DENY' });
    await expect(t.login()).rejects.toThrow(DENIED);
    expect(t.authUrls).toEqual([]);
    expect(t.approvals.size).toBe(0);
  });

  it('a request the connection may already make is signed at once, even in ask mode', async () => {
    const t = await boot({ approvalMode: 'ASK', grant: true });
    expect(verifyEvent(await t.login())).toBe(true);
    expect(t.authUrls).toEqual([]);
  });
});
