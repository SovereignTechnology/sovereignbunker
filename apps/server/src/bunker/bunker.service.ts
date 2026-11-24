import {
  Inject,
  Injectable,
  Logger,
  type OnModuleInit,
  type OnModuleDestroy,
} from '@nestjs/common';
import { SimplePool } from 'nostr-tools/pool';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { hexToBytes } from '@noble/hashes/utils.js';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { BunkerRpcHandler, type RpcReply } from './bunker-rpc.handler.js';
import { ApprovalService, type HeldRequest } from './approval.service.js';
import {
  Nip46Method,
  Nip46RequestEnvelopeSchema,
  Nip46RequestSchema,
  SafeRelayUrlSchema,
  type ApprovalMode,
  type Nip46Request,
  type Nip46Response,
  type PermissionDescriptor,
} from '@bunker46/shared-types';
import { NOSTR_CONSTANTS, NOSTR_DEFAULT_RELAYS_INJECTION_TOKEN } from '@bunker46/config';
import { PrismaService } from '../prisma/prisma.service.js';
import { EncryptionService } from '../common/crypto/encryption.service.js';
import { useWebSocketImplementation } from 'nostr-tools/pool';
import { normalizeURL } from 'nostr-tools/utils';
import WebSocket from 'ws';

useWebSocketImplementation(WebSocket);

/** Delay before re-subscribing a relay that closed our subscription, by consecutive attempt. */
const RESUBSCRIBE_BACKOFF_MS = [5_000, 15_000, 30_000, 60_000];

/**
 * A subscription that stayed open at least this long counts as healthy: only then does the next
 * close start the backoff over. nostr-tools calls `oneose` just before `onclose` when a relay
 * refuses or drops a subscription (it settles the EOSE of a closing subscription first), so EOSE
 * proves nothing and a reset there kept every retry at the first step.
 */
const RESUBSCRIBE_STABLE_MS = 60_000;

/** `ms` spread by up to +/- `fraction`, so listeners do not hit a relay on the same tick. */
const jitter = (ms: number, fraction: number) =>
  Math.round(ms * (1 + (Math.random() * 2 - 1) * fraction));

/** What the listener needs of a relay event (nostr-tools verified its id and signature). */
type RelayEvent = { id: string; pubkey: string; content: string; created_at: number };

/** A relay that takes longer than this to accept a NIP-46 reply is reported as slow. */
const SLOW_PUBLISH_MS = 5_000;

/** Relay-supplied text for a log line: printable ASCII only, bounded. */
const printable = (value: unknown) =>
  String(value)
    .replace(/[^\x20-\x7e]/g, '?')
    .slice(0, 80);

interface ActiveListener {
  relays: string[];
  /** Decrypted signer nsec (hex), kept so the listener can be rebuilt with merged relays. */
  nsecHex: string;
  /** Re-open one relay's subscription only (the watchdog, after that relay's socket dropped). */
  reopen: (url: string) => void;
  close: () => void;
}

export interface PendingSecretInfo {
  userId: string;
  nsecKeyId: string;
  name: string;
  /** Operator-chosen granted permissions to seed the auto-created connection with (bunker:// flow). */
  permissions?: PermissionDescriptor[];
  /** Whether the auto-created connection holds an ungranted request for the operator (ASK) or refuses it (DENY). */
  approvalMode?: ApprovalMode;
}

@Injectable()
export class BunkerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BunkerService.name);
  private pool: SimplePool;
  private activeListeners = new Map<string, ActiveListener>();
  private pendingSecrets = new Map<string, PendingSecretInfo>();
  /** Replay guard: `<signer pubkey>:<event id>` -> when the guard may forget it (ms), oldest first. */
  private handledEventIds = new Map<string, number>();
  private lastHandledSweep = 0;
  private watchdogHandle?: ReturnType<typeof setInterval>;

  constructor(
    private readonly rpcHandler: BunkerRpcHandler,
    private readonly prisma: PrismaService,
    private readonly encryption: EncryptionService,
    @Inject(NOSTR_DEFAULT_RELAYS_INJECTION_TOKEN)
    private readonly defaultRelays: string[],
    private readonly approvals: ApprovalService,
  ) {
    this.pool = new SimplePool({ enablePing: true, enableReconnect: true });
  }

  async onModuleInit() {
    this.logger.log('Bunker service initializing – resuming relay listeners...');

    this.rpcHandler.setPendingSecretLookup((signerPubkey, secret) => {
      return this.consumePendingSecret(signerPubkey, secret);
    });
    this.rpcHandler.setBaseRelayLookup((userId) => this.getBaseRelayUrlsForUser(userId));

    await this.resumeAllListeners();
    this.startConnectionWatchdog();
  }

  async onModuleDestroy() {
    if (this.watchdogHandle) {
      clearInterval(this.watchdogHandle);
      this.watchdogHandle = undefined;
    }
    for (const [pubkey, listener] of this.activeListeners) {
      listener.close();
      this.logger.debug(`Stopped listener for ${pubkey.slice(0, 12)}...`);
    }
    this.activeListeners.clear();
    this.pool.close([...this.defaultRelays]);
  }

  /**
   * Periodically verify every active listener still has live relay connections
   * and re-subscribe the ones that dropped. nostr-tools' own `enableReconnect`
   * gives up when a socket dies with an `error` event (it sets `skipReconnection`
   * and removes the relay from the pool), so without this the listener stays dead
   * until the process restarts. This watchdog makes recovery automatic.
   */
  private startConnectionWatchdog() {
    if (this.watchdogHandle) return;
    this.watchdogHandle = setInterval(
      () => this.checkConnections(),
      NOSTR_CONSTANTS.RELAY_WATCHDOG_INTERVAL_MS,
    );
    // Don't let the watchdog keep the event loop alive on its own.
    this.watchdogHandle.unref?.();
    this.logger.log(
      `Relay connection watchdog started (every ${NOSTR_CONSTANTS.RELAY_WATCHDOG_INTERVAL_MS / 1000}s)`,
    );
  }

  private checkConnections() {
    if (this.activeListeners.size === 0) return;
    // Defensive: skip if the pool implementation lacks status introspection.
    if (typeof this.pool.listConnectionStatus !== 'function') return;

    const status = this.pool.listConnectionStatus();
    for (const [pubkey, listener] of this.activeListeners) {
      const dead = listener.relays.filter((url) => status.get(normalizeURL(url)) !== true);
      if (dead.length === 0) continue;

      this.logger.warn(
        `Relay(s) disconnected for ${pubkey.slice(0, 12)}...: ${dead.join(', ')} – re-subscribing`,
      );
      // Only the dropped relays. Rebuilding every relay's subscription on each drop churned the
      // healthy relays (one flapping relay re-subscribed all of them every few minutes).
      for (const url of dead) listener.reopen(url);
    }
  }

  registerPendingSecret(signerPubkey: string, secret: string, info: PendingSecretInfo) {
    const key = `${signerPubkey}:${secret}`;
    this.pendingSecrets.set(key, info);
    setTimeout(() => this.pendingSecrets.delete(key), 10 * 60 * 1000);
    this.logger.debug(`Registered pending secret for ${signerPubkey.slice(0, 12)}...`);
  }

  consumePendingSecret(signerPubkey: string, secret: string): PendingSecretInfo | undefined {
    const key = `${signerPubkey}:${secret}`;
    const info = this.pendingSecrets.get(key);
    if (info) this.pendingSecrets.delete(key);
    return info;
  }

  getPendingSecretCount(): number {
    return this.pendingSecrets.size;
  }

  private async getBaseRelayUrlsForUser(userId: string): Promise<string[]> {
    const configured = await this.prisma.relayConfig.findMany({
      where: { userId },
      select: { url: true },
      orderBy: { createdAt: 'asc' },
    });
    return configured.length > 0 ? configured.map((r) => r.url) : [...this.defaultRelays];
  }

  private async resumeAllListeners() {
    const nsecKeys = await this.prisma.nsecKey.findMany({
      include: {
        connections: {
          where: { status: { in: ['ACTIVE', 'PENDING'] } },
          select: { relays: true },
        },
      },
    });

    const allConfigs = await this.prisma.relayConfig.findMany({
      select: { userId: true, url: true },
      orderBy: { createdAt: 'asc' },
    });
    const relaysByUser = new Map<string, string[]>();
    for (const row of allConfigs) {
      const list = relaysByUser.get(row.userId);
      if (list) list.push(row.url);
      else relaysByUser.set(row.userId, [row.url]);
    }

    let started = 0;
    for (const key of nsecKeys) {
      // One unreadable key must not stop the others from listening (or the watchdog from starting).
      try {
        const nsecHex = this.encryption.decrypt(key.encryptedNsec);
        const userRelays = relaysByUser.get(key.userId);
        const baseRelays =
          userRelays && userRelays.length > 0 ? userRelays : [...this.defaultRelays];
        const allRelays = new Set<string>(baseRelays);
        for (const conn of key.connections) {
          for (const r of conn.relays) allRelays.add(r);
        }

        this.startListeningForKey(key.publicKey, nsecHex, [...allRelays]);
        started += 1;
      } catch (err) {
        this.logger.error(
          `Could not start the NIP-46 listener for ${key.publicKey.slice(0, 12)}...: ${printable(err)}`,
        );
      }
    }

    this.logger.log(
      `Resumed listeners for ${started} of ${nsecKeys.length} nsec key(s) (per-user relay defaults)`,
    );
  }

  startListeningForKey(signerPubkeyHex: string, signerNsecHex: string, relays: string[]): void {
    const rawRelays = relays.length > 0 ? relays : [...this.defaultRelays];
    const effectiveRelays = rawRelays.filter((url) => {
      const result = SafeRelayUrlSchema.safeParse(url);
      if (!result.success) {
        this.logger.warn(`Skipping unsafe relay URL (SSRF): ${url.slice(0, 50)}...`);
        return false;
      }
      return true;
    });
    if (effectiveRelays.length === 0) {
      this.logger.warn('No safe relay URLs left after filtering; using defaults');
      effectiveRelays.push(...this.defaultRelays);
    }

    const existing = this.activeListeners.get(signerPubkeyHex);
    if (existing) {
      const newRelays = effectiveRelays.filter((r) => !existing.relays.includes(r));
      if (newRelays.length === 0) {
        return;
      }
      existing.close();
      this.activeListeners.delete(signerPubkeyHex);
      const mergedRelays = [...new Set([...existing.relays, ...effectiveRelays])];
      return this.startListeningForKey(signerPubkeyHex, signerNsecHex, mergedRelays);
    }

    const label = signerPubkeyHex.slice(0, 12);
    // Requests being answered right now, so two relays delivering one request at the same moment
    // are not both handled (the guard below only remembers a request once it is answered).
    const inFlight = new Set<string>();
    const onevent = async (event: RelayEvent) => {
      // Only requests the replay guard still remembers. A subscription is long-lived and its
      // `since` was fixed when it opened, so it keeps accepting everything newer than that; this
      // holds every accepted event inside the span the guard keeps its id for (see markHandled).
      const nowS = Math.floor(Date.now() / 1000);
      if (
        typeof event.created_at !== 'number' ||
        event.created_at < nowS - NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S ||
        event.created_at > nowS + NOSTR_CONSTANTS.NIP46_FUTURE_SKEW_S
      ) {
        this.logger.debug(
          `Ignoring NIP-46 event ${event.id.slice(0, 8)} for ${label}...: created_at is outside the accepted window`,
        );
        return;
      }
      if (inFlight.has(event.id) || this.isHandled(signerPubkeyHex, event.id)) {
        this.logger.debug(
          `Ignoring re-delivered NIP-46 event ${event.id.slice(0, 8)} for ${label}...`,
        );
        return;
      }
      inFlight.add(event.id);
      try {
        // Remembered only once it parsed as a request and was answered: undecryptable junk never
        // takes a slot, and a request that failed (a database blip) is retried on redelivery.
        if (
          await this.handleIncomingEvent(event, signerNsecHex, signerPubkeyHex, effectiveRelays)
        ) {
          this.markHandled(signerPubkeyHex, event);
        }
      } catch (err) {
        this.logger.error(`Error handling NIP-46 event: ${err}`);
      } finally {
        inFlight.delete(event.id);
      }
    };

    // One subscription per relay. SimplePool reports onclose only once EVERY relay of a
    // subscription has closed, so with one subscription across all relays a relay that sent
    // CLOSED (e.g. "error: too many subscriptions") went unnoticed, and the watchdog, which checks
    // sockets only, never revived it: requests published only to that relay were lost.
    const subs = new Map<string, { close: () => void }>();
    const attempts = new Map<string, number>();
    let stopped = false;

    // Self-ping liveness. A relay can stop delivering to a subscription while its socket stays up
    // and without sending CLOSED, which neither onclose nor the socket watchdog sees. So every few
    // minutes the signer publishes a kind-24133 to itself on each relay alone and expects it back
    // on that relay's subscription. Only a relay that has echoed before counts misses: some accept
    // the event and deliver it to nobody (relay.damus.io did for fresh keys on 2026-10-31) or
    // refuse the kind (relay.nos.social), and for those silence proves nothing.
    //
    // The pings are signed by a throwaway key made for this listener (the filter matches their
    // `p` tag, not their author), so the user's identity never appears on a relay for them.
    const pingSecretKey = generateSecretKey();
    const pingPubkey = getPublicKey(pingSecretKey);
    let pingSeq = 0;
    const selfPings = new Map<string, string>(); // self-ping event id -> the relay it went to
    // Relays whose subscription is closed and waiting for its backoff retry.
    const retrying = new Set<string>();
    const liveness = new Map<string, { verified: boolean; misses: number }>();
    const livenessOf = (url: string) => {
      let state = liveness.get(url);
      if (!state) {
        state = { verified: false, misses: 0 };
        liveness.set(url, state);
      }
      return state;
    };
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const later = (fn: () => void, ms: number) => {
      const timer = setTimeout(() => {
        timers.delete(timer);
        if (!stopped) fn();
      }, ms);
      timer.unref?.();
      timers.add(timer);
    };
    const onRelayEvent = (url: string, event: RelayEvent) => {
      // This listener's self-pings (this round's, a late one, or one a relay copied from another
      // relay) are never requests; only the relay a ping was sent to counts as its echo.
      if (event.pubkey === pingPubkey) {
        if (selfPings.get(event.id) === url) {
          selfPings.delete(event.id);
          const state = livenessOf(url);
          if (!state.verified) {
            this.logger.debug(`${url} echoes the NIP-46 self-ping for ${label}...`);
          }
          state.verified = true;
          state.misses = 0;
        }
        return;
      }
      // Nothing the signer's own key authored is a request either.
      if (event.pubkey === signerPubkeyHex) return;
      return onevent(event);
    };

    const open = (url: string) => {
      retrying.delete(url);
      const openedAt = Date.now();
      let closedByUs = false;
      // Assigned after the callbacks below that compare against it, so it cannot be a const (reading it
      // from an onclose that fires before the assignment must see undefined, not a TDZ error).
      // eslint-disable-next-line prefer-const
      let handle: { close: () => void } | undefined;
      const sub = this.pool.subscribe(
        [url],
        {
          kinds: [NOSTR_CONSTANTS.NIP46_KIND],
          '#p': [signerPubkeyHex],
          since: Math.floor(Date.now() / 1000) - NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S,
        },
        {
          onevent: (event) => onRelayEvent(url, event),
          onclose: (reasons) => {
            if (closedByUs || stopped || subs.get(url) !== handle) return;
            if (Date.now() - openedAt >= RESUBSCRIBE_STABLE_MS) attempts.set(url, 0);
            const n = attempts.get(url) ?? 0;
            attempts.set(url, n + 1);
            const step = Math.min(n, RESUBSCRIBE_BACKOFF_MS.length - 1);
            const delay = jitter(RESUBSCRIBE_BACKOFF_MS[step] ?? 60_000, 0.2);
            const why = printable(reasons.map((r) => r.reason).join('; '));
            this.logger.warn(
              `${url} closed the NIP-46 subscription for ${label}...: ${why} – re-subscribing in ${delay / 1000}s`,
            );
            retrying.add(url);
            later(() => {
              retrying.delete(url);
              if (subs.get(url) === handle) open(url);
            }, delay);
          },
        },
      );
      handle = {
        close: () => {
          closedByUs = true;
          sub.close();
        },
      };
      subs.set(url, handle);
    };
    for (const url of effectiveRelays) open(url);

    const selfPing = (url: string) => {
      // The sequence number keeps every ping's id distinct: same author, kind, tags and second
      // would otherwise give every relay of one round the SAME id, and the echo map (id -> relay)
      // would then recognise only the last relay's.
      pingSeq += 1;
      const event = finalizeEvent(
        {
          kind: NOSTR_CONSTANTS.NIP46_KIND,
          content: `self-ping ${pingSeq}`,
          tags: [['p', signerPubkeyHex]],
          created_at: Math.floor(Date.now() / 1000),
        },
        pingSecretKey,
      );
      selfPings.set(event.id, url);
      let sent: Promise<string>[];
      try {
        sent = this.pool.publish([url], event);
      } catch {
        selfPings.delete(event.id);
        return;
      }
      const settled = ([outcome]: PromiseSettledResult<string>[]) => {
        // A relay that refused or never took the event says nothing about our subscription.
        if (outcome?.status !== 'fulfilled') {
          selfPings.delete(event.id);
          return;
        }
        later(() => {
          if (!selfPings.delete(event.id)) return; // it came back
          // A closed subscription cannot echo; its backoff retry is already on the way.
          if (retrying.has(url)) return;
          const state = livenessOf(url);
          if (!state.verified) return;
          state.misses += 1;
          if (state.misses < NOSTR_CONSTANTS.NIP46_SELF_PING_MISSES) return;
          this.logger.warn(
            `${url} missed ${state.misses} NIP-46 self-pings in a row for ${label}... – re-subscribing`,
          );
          state.misses = 0;
          subs.get(url)?.close();
          open(url);
        }, NOSTR_CONSTANTS.NIP46_SELF_PING_TIMEOUT_MS);
      };
      void Promise.allSettled(sent).then(settled, () => selfPings.delete(event.id));
    };
    const round = () => {
      for (const url of effectiveRelays) selfPing(url);
      later(round, jitter(NOSTR_CONSTANTS.NIP46_SELF_PING_INTERVAL_MS, 0.1));
    };
    later(round, jitter(NOSTR_CONSTANTS.NIP46_SELF_PING_FIRST_MS, 0.5));

    this.activeListeners.set(signerPubkeyHex, {
      relays: effectiveRelays,
      nsecHex: signerNsecHex,
      reopen: (url) => {
        // A relay waiting for its backoff retry stays on the backoff: the watchdog (every 30 s)
        // would otherwise bypass it and hammer a relay that keeps refusing.
        if (stopped || retrying.has(url)) return;
        subs.get(url)?.close();
        open(url);
      },
      close: () => {
        stopped = true;
        for (const timer of timers) clearTimeout(timer);
        timers.clear();
        for (const handle of subs.values()) handle.close();
        subs.clear();
      },
    });

    this.logger.log(
      `Listening for NIP-46 on ${effectiveRelays.join(', ')} for ${signerPubkeyHex.slice(0, 12)}...`,
    );
  }

  async ensureListeningForConnection(
    nsecKeyId: string,
    userId: string,
    connectionRelays: string[],
  ) {
    // Defense-in-depth (same class as the C1 fix): scope the key lookup to its owner so this method
    // can never start a listener that decrypts with another user's key, even if a future caller forgets
    // to validate ownership first.
    const key = await this.prisma.nsecKey.findFirst({ where: { id: nsecKeyId, userId } });
    if (!key) return;

    const nsecHex = this.encryption.decrypt(key.encryptedNsec);

    const baseRelays = await this.getBaseRelayUrlsForUser(key.userId);

    const relays = [...new Set([...connectionRelays, ...baseRelays])];
    this.startListeningForKey(key.publicKey, nsecHex, relays);
  }

  stopListeningForKey(signerPubkeyHex: string) {
    const listener = this.activeListeners.get(signerPubkeyHex);
    if (listener) {
      listener.close();
      this.activeListeners.delete(signerPubkeyHex);
      this.logger.log(`Stopped listener for ${signerPubkeyHex.slice(0, 12)}...`);
    }
  }

  /**
   * Replay guard. Relays hand back stored requests whenever a subscription is re-opened, so the
   * same request event can arrive many times; answering it again re-signs an old request.
   *
   * Ids are kept per signer, until `created_at` + the since window + a margin: onevent accepts
   * only events no older than the since window, so an id is never forgotten while its event can
   * still be accepted. Only the size cap can drop one earlier (a flood of requests that really
   * decrypt and parse), and the worst a replay then does is a second reply to a request the
   * client already made.
   */
  private isHandled(signerPubkey: string, eventId: string): boolean {
    const expires = this.handledEventIds.get(`${signerPubkey}:${eventId}`);
    return expires !== undefined && expires > Date.now();
  }

  private markHandled(signerPubkey: string, event: { id: string; created_at: number }) {
    const now = Date.now();
    const { NIP46_SINCE_WINDOW_S: windowS, NIP46_HANDLED_MARGIN_S: marginS } = NOSTR_CONSTANTS;
    const expiresMs = (event.created_at + windowS + marginS) * 1000;
    this.handledEventIds.set(`${signerPubkey}:${event.id}`, expiresMs);
    if (now - this.lastHandledSweep >= 30_000) {
      this.lastHandledSweep = now;
      for (const [key, expires] of this.handledEventIds) {
        if (expires <= now) this.handledEventIds.delete(key);
      }
    }
    while (this.handledEventIds.size > NOSTR_CONSTANTS.NIP46_HANDLED_EVENT_IDS_MAX) {
      const oldest = this.handledEventIds.keys().next().value;
      if (oldest === undefined) break;
      this.handledEventIds.delete(oldest);
    }
  }

  isListening(signerPubkeyHex: string): boolean {
    return this.activeListeners.has(signerPubkeyHex);
  }

  getActiveListenerCount(): number {
    return this.activeListeners.size;
  }

  private async handleIncomingEvent(
    event: { pubkey: string; content: string },
    signerNsecHex: string,
    signerPubkeyHex: string,
    relays: string[],
  ): Promise<boolean> {
    const signerSecretKey = hexToBytes(signerNsecHex);
    const clientPubkey = event.pubkey;

    let decryptedContent: string;
    try {
      const conversationKey = nip44.v2.utils.getConversationKey(signerSecretKey, clientPubkey);
      decryptedContent = nip44.v2.decrypt(event.content, conversationKey);
    } catch {
      try {
        decryptedContent = await nip04.decrypt(signerSecretKey, clientPubkey, event.content);
      } catch {
        this.logger.warn(`Failed to decrypt NIP-46 message from ${clientPubkey.slice(0, 12)}...`);
        return false;
      }
    }

    let raw: unknown;
    try {
      raw = JSON.parse(decryptedContent);
    } catch {
      this.logger.warn(`Failed to parse NIP-46 JSON from ${clientPubkey.slice(0, 12)}...`);
      return false;
    }

    const parsed = Nip46RequestSchema.safeParse(raw);
    if (!parsed.success) {
      // NIP-46: requests with unknown or unsupported methods MUST be replied with an error.
      // Without a reply the client waits for its own timeout (e.g. nostr-tools' `logout`).
      const envelope = Nip46RequestEnvelopeSchema.safeParse(raw);
      if (envelope.success && !Nip46Method.safeParse(envelope.data.method).success) {
        const method = envelope.data.method.replace(/[^A-Za-z0-9_]/g, '?');
        this.logger.warn(
          `Unsupported NIP-46 method ${method} from ${clientPubkey.slice(0, 12)}... – replying with an error`,
        );
        await this.sendResponse(
          { id: envelope.data.id, error: `unsupported method: ${method}` },
          method,
          clientPubkey,
          signerSecretKey,
          relays,
        );
        return true;
      }
      this.logger.warn(`Invalid NIP-46 request schema from ${clientPubkey.slice(0, 12)}...`);
      return false;
    }

    this.logger.log(
      `NIP-46 ${parsed.data.method} from ${clientPubkey.slice(0, 12)}... (id: ${parsed.data.id})`,
    );

    const reply = await this.runRpc(clientPubkey, signerPubkeyHex, parsed.data);

    if (reply.hold) {
      await this.answerHeldRequest(
        reply.hold,
        parsed.data,
        clientPubkey,
        signerPubkeyHex,
        signerSecretKey,
        relays,
      );
      // Answered (twice, in fact): the replay guard marks the event once this returns.
      return true;
    }

    await this.sendResponse(reply, parsed.data.method, clientPubkey, signerSecretKey, relays);
    return true;
  }

  /** Run one NIP-46 request through the RPC handler with this signer's crypto. */
  private runRpc(
    clientPubkey: string,
    signerPubkeyHex: string,
    request: Nip46Request,
    resolution?: Parameters<BunkerRpcHandler['handleRequest']>[9],
  ): Promise<RpcReply> {
    return this.rpcHandler.handleRequest(
      clientPubkey,
      signerPubkeyHex,
      request,
      async (eventJson, nsec) => {
        const template = JSON.parse(eventJson);
        const sk = hexToBytes(nsec);
        return JSON.stringify(finalizeEvent(template, sk));
      },
      async (plaintext, thirdParty, nsec) => nip04.encrypt(hexToBytes(nsec), thirdParty, plaintext),
      async (ciphertext, thirdParty, nsec) =>
        nip04.decrypt(hexToBytes(nsec), thirdParty, ciphertext),
      async (plaintext, thirdParty, nsec) => {
        const ck = nip44.v2.utils.getConversationKey(hexToBytes(nsec), thirdParty);
        return nip44.v2.encrypt(plaintext, ck);
      },
      async (ciphertext, thirdParty, nsec) => {
        const ck = nip44.v2.utils.getConversationKey(hexToBytes(nsec), thirdParty);
        return nip44.v2.decrypt(ciphertext, ck);
      },
      (nsec) => getPublicKey(hexToBytes(nsec)),
      resolution,
    );
  }

  /**
   * A gated request on an ASK connection is waiting for the operator. NIP-46 lets a signer answer a
   * request twice: first `{id, result: "auth_url", error: <url>}` ("go here, I need the user"), then
   * the real reply under the same id. Exactly one interim reply is sent per request, because a client
   * (nostr-tools) rejects the request if a second `auth_url` arrives for the same id.
   *
   * When the hold ends the request goes through the handler again with the outcome, so the final
   * reply reflects the state of the connection NOW (revoked while held, permissions edited) and not
   * what it was when the request arrived. A refusal or a timeout is the ordinary permission error,
   * byte for byte, which is what clients already know how to read.
   */
  private async answerHeldRequest(
    hold: HeldRequest,
    request: Nip46Request,
    clientPubkey: string,
    signerPubkeyHex: string,
    signerSecretKey: Uint8Array,
    relays: string[],
  ) {
    const url = this.approvals.authUrl(hold.token);
    if (url) {
      await this.sendResponse(
        { id: request.id, result: 'auth_url', error: url },
        request.method,
        clientPubkey,
        signerSecretKey,
        relays,
      );
    } else {
      this.logger.warn(
        'PUBLIC_BASE_URL is not set: holding the request without telling the client where to approve it',
      );
    }

    const outcome = await hold.decision;

    let final: Nip46Response;
    try {
      const reply = await this.runRpc(clientPubkey, signerPubkeyHex, request, outcome);
      final = { id: reply.id, result: reply.result, error: reply.error };
    } catch (err) {
      // The client is still waiting under this id: it must get an answer, not silence.
      this.logger.error(`Failed to answer held NIP-46 request: ${printable(err)}`);
      final = { id: request.id, error: 'Internal error' };
    }
    await this.sendResponse(final, request.method, clientPubkey, signerSecretKey, relays);
  }

  /** Encrypt a NIP-46 response to the client and publish it on the listener's relays. */
  private async sendResponse(
    response: Nip46Response,
    method: string,
    clientPubkey: string,
    signerSecretKey: Uint8Array,
    relays: string[],
  ) {
    // Explicit fields: whatever else a reply object carries (the handler's `hold`) never goes out.
    const responseJson = JSON.stringify({
      id: response.id,
      result: response.result,
      error: response.error,
    });
    const conversationKey = nip44.v2.utils.getConversationKey(signerSecretKey, clientPubkey);
    const encryptedResponse = nip44.v2.encrypt(responseJson, conversationKey);

    const responseEvent = finalizeEvent(
      {
        kind: NOSTR_CONSTANTS.NIP46_KIND,
        content: encryptedResponse,
        tags: [['p', clientPubkey]],
        created_at: Math.floor(Date.now() / 1000),
      },
      signerSecretKey,
    );

    try {
      const started = Date.now();
      const attempts = this.pool.publish(relays, responseEvent);
      // Fire-and-forget, but never as an unhandled rejection (process guards treat those as fatal).
      this.reportPublishOutcome(method, relays, attempts, started).catch((err: unknown) =>
        this.logger.debug(`Could not report NIP-46 publish outcome: ${printable(err)}`),
      );
      await Promise.any(attempts);
      this.logger.log(`NIP-46 response sent for ${method} to ${clientPubkey.slice(0, 12)}...`);
    } catch (err) {
      this.logger.error(`Failed to publish NIP-46 response: ${err}`);
    }
  }

  /**
   * Once every relay has settled, report the ones that refused a reply or sat on it. The reply is
   * already on its way (Promise.any resolves at the first acceptance), so this never delays it; it
   * makes visible what "response sent" hides: a client listening only on a relay that rejected or
   * delayed the reply is still waiting.
   */
  private async reportPublishOutcome(
    method: string,
    relays: string[],
    attempts: Promise<string>[],
    started: number,
  ) {
    const outcomes = await Promise.all(
      attempts.map((attempt, i) =>
        attempt.then(
          () => ({ relay: relays[i] ?? '?', ok: true, ms: Date.now() - started, why: '' }),
          (err: unknown) => ({
            relay: relays[i] ?? '?',
            ok: false,
            ms: Date.now() - started,
            why: printable(err),
          }),
        ),
      ),
    );
    const parts = outcomes.map(
      (o) => `${o.relay.replace('wss://', '')} ${o.ok ? 'ok' : `failed (${o.why})`} ${o.ms}ms`,
    );
    const summary = parts.join(', ');
    if (outcomes.some((o) => !o.ok || o.ms > SLOW_PUBLISH_MS)) {
      this.logger.warn(`NIP-46 ${method} reply publish: ${summary}`);
    } else {
      this.logger.debug(`NIP-46 ${method} reply publish: ${summary}`);
    }
  }

  async sendConnectResponse(
    nsecKeyId: string,
    userId: string,
    clientPubkey: string,
    secret: string,
    relays: string[],
  ) {
    // Defense-in-depth (same class as the C1 fix): scope the key lookup to its owner so this method can
    // never sign/publish a NIP-46 response with another user's key.
    const key = await this.prisma.nsecKey.findFirst({ where: { id: nsecKeyId, userId } });
    if (!key) {
      this.logger.error('sendConnectResponse: nsec key not found');
      return;
    }

    const nsecHex = this.encryption.decrypt(key.encryptedNsec);
    const signerSecretKey = hexToBytes(nsecHex);

    const baseRelays = await this.getBaseRelayUrlsForUser(key.userId);
    const effectiveRelays = [...new Set([...relays, ...baseRelays])];

    const responsePayload = JSON.stringify({
      id: crypto.randomUUID(),
      result: secret,
    });

    const conversationKey = nip44.v2.utils.getConversationKey(signerSecretKey, clientPubkey);
    const encryptedResponse = nip44.v2.encrypt(responsePayload, conversationKey);

    const responseEvent = finalizeEvent(
      {
        kind: NOSTR_CONSTANTS.NIP46_KIND,
        content: encryptedResponse,
        tags: [['p', clientPubkey]],
        created_at: Math.floor(Date.now() / 1000),
      },
      signerSecretKey,
    );

    try {
      await Promise.any(this.pool.publish(effectiveRelays, responseEvent));
      this.logger.log(
        `Sent nostrconnect response to ${clientPubkey.slice(0, 12)}... on ${effectiveRelays.join(', ')}`,
      );
    } catch (err) {
      this.logger.error(`Failed to publish nostrconnect response: ${err}`);
    }
  }

  getPool(): SimplePool {
    return this.pool;
  }
}
