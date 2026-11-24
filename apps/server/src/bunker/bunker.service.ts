import {
  Inject,
  Injectable,
  Logger,
  type OnModuleInit,
  type OnModuleDestroy,
} from '@nestjs/common';
import { SimplePool } from 'nostr-tools/pool';
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure';
import { hexToBytes } from '@noble/hashes/utils.js';
import * as nip44 from 'nostr-tools/nip44';
import * as nip04 from 'nostr-tools/nip04';
import { BunkerRpcHandler } from './bunker-rpc.handler.js';
import {
  Nip46RequestSchema,
  SafeRelayUrlSchema,
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

/** Relay-supplied text for a log line: printable ASCII only, bounded. */
const printable = (value: unknown) => String(value).replace(/[^\x20-\x7e]/g, '?').slice(0, 80);

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
}

@Injectable()
export class BunkerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(BunkerService.name);
  private pool: SimplePool;
  private activeListeners = new Map<string, ActiveListener>();
  private pendingSecrets = new Map<string, PendingSecretInfo>();
  /** Replay guard: request event id -> when it was handled (ms), oldest first. */
  private handledEventIds = new Map<string, number>();
  private watchdogHandle?: ReturnType<typeof setInterval>;

  constructor(
    private readonly rpcHandler: BunkerRpcHandler,
    private readonly prisma: PrismaService,
    private readonly encryption: EncryptionService,
    @Inject(NOSTR_DEFAULT_RELAYS_INJECTION_TOKEN)
    private readonly defaultRelays: string[],
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

    for (const key of nsecKeys) {
      const nsecHex = this.encryption.decrypt(key.encryptedNsec);
      const userRelays = relaysByUser.get(key.userId);
      const baseRelays = userRelays && userRelays.length > 0 ? userRelays : [...this.defaultRelays];
      const allRelays = new Set<string>(baseRelays);
      for (const conn of key.connections) {
        for (const r of conn.relays) allRelays.add(r);
      }

      this.startListeningForKey(key.publicKey, nsecHex, [...allRelays]);
    }

    this.logger.log(
      `Resumed listeners for ${nsecKeys.length} nsec key(s) (per-user relay defaults)`,
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
    const onevent = async (event: { id: string; pubkey: string; content: string }) => {
      if (!this.markHandled(event.id)) {
        this.logger.debug(
          `Ignoring re-delivered NIP-46 event ${event.id.slice(0, 8)} for ${label}...`,
        );
        return;
      }
      try {
        await this.handleIncomingEvent(event, signerNsecHex, signerPubkeyHex, effectiveRelays);
      } catch (err) {
        this.logger.error(`Error handling NIP-46 event: ${err}`);
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
    const selfPubkey = getPublicKey(hexToBytes(signerNsecHex));
    const selfPings = new Map<string, string>(); // self-ping event id -> the relay it went to
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
    const onRelayEvent = (url: string, event: { id: string; pubkey: string; content: string }) => {
      // The signer's own events are self-pings (this round's, a late one, or one a relay copied
      // from another relay), never requests; only the relay it was sent to counts as an echo.
      if (event.pubkey === selfPubkey) {
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
      return onevent(event);
    };

    const open = (url: string) => {
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
          oneose: () => attempts.set(url, 0),
          onclose: (reasons) => {
            if (closedByUs || stopped || subs.get(url) !== handle) return;
            const n = attempts.get(url) ?? 0;
            attempts.set(url, n + 1);
            const step = Math.min(n, RESUBSCRIBE_BACKOFF_MS.length - 1);
            const delay = RESUBSCRIBE_BACKOFF_MS[step] ?? 60_000;
            const why = printable(reasons.map((r) => r.reason).join('; '));
            this.logger.warn(
              `${url} closed the NIP-46 subscription for ${label}...: ${why} – re-subscribing in ${delay / 1000}s`,
            );
            const timer = setTimeout(() => {
              if (!stopped && subs.get(url) === handle) open(url);
            }, delay);
            timer.unref?.();
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
      const event = finalizeEvent(
        {
          kind: NOSTR_CONSTANTS.NIP46_KIND,
          content: 'self-ping',
          tags: [['p', signerPubkeyHex]],
          created_at: Math.floor(Date.now() / 1000),
        },
        hexToBytes(signerNsecHex),
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
      later(round, NOSTR_CONSTANTS.NIP46_SELF_PING_INTERVAL_MS);
    };
    later(round, NOSTR_CONSTANTS.NIP46_SELF_PING_FIRST_MS);

    this.activeListeners.set(signerPubkeyHex, {
      relays: effectiveRelays,
      nsecHex: signerNsecHex,
      reopen: (url) => {
        if (stopped) return;
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
   * Replay guard. Relays hand back stored requests whenever the watchdog re-subscribes, so the same
   * request event can arrive many times; answering it again re-signs an old request. Returns true
   * only the first time an event id is seen. Ids are forgotten once they are older than the `since`
   * window (relays no longer return them) or when the map exceeds its cap.
   */
  private markHandled(eventId: string): boolean {
    if (this.handledEventIds.has(eventId)) return false;
    const now = Date.now();
    this.handledEventIds.set(eventId, now);
    const cutoff = now - (NOSTR_CONSTANTS.NIP46_SINCE_WINDOW_S + 60) * 1000;
    for (const [id, handledAt] of this.handledEventIds) {
      const overCap = this.handledEventIds.size > NOSTR_CONSTANTS.NIP46_HANDLED_EVENT_IDS_MAX;
      if (handledAt >= cutoff && !overCap) break;
      this.handledEventIds.delete(id);
    }
    return true;
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
  ) {
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
        return;
      }
    }

    let parsed;
    try {
      parsed = Nip46RequestSchema.safeParse(JSON.parse(decryptedContent));
    } catch {
      this.logger.warn(`Failed to parse NIP-46 JSON from ${clientPubkey.slice(0, 12)}...`);
      return;
    }

    if (!parsed.success) {
      this.logger.warn(`Invalid NIP-46 request schema from ${clientPubkey.slice(0, 12)}...`);
      return;
    }

    this.logger.log(
      `NIP-46 ${parsed.data.method} from ${clientPubkey.slice(0, 12)}... (id: ${parsed.data.id})`,
    );

    const response = await this.rpcHandler.handleRequest(
      clientPubkey,
      signerPubkeyHex,
      parsed.data,
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
    );

    const responseJson = JSON.stringify(response);
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
      await Promise.any(this.pool.publish(relays, responseEvent));
      this.logger.log(
        `NIP-46 response sent for ${parsed.data.method} to ${clientPubkey.slice(0, 12)}...`,
      );
    } catch (err) {
      this.logger.error(`Failed to publish NIP-46 response: ${err}`);
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
