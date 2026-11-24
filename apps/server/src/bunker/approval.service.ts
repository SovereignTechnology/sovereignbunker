import {
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  type OnModuleDestroy,
} from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { nip19 } from 'nostr-tools';
import {
  APPROVAL_CONFIG_INJECTION_TOKEN,
  APPROVAL_CONSTANTS,
  type ApprovalConfig,
} from '@bunker46/config';
import {
  MAX_EVENT_KIND,
  LOGIN_EVENT_KIND,
  type ApprovalHttpAuthPreview,
  type ApprovalPreviewDto,
  type ApprovalTagPreview,
  type PendingApprovalDto,
  type PermissionDescriptor,
} from '@bunker46/shared-types';
import { EventsService } from '../events/events.service.js';

/**
 * How a held request ended.
 * - `approved_once`: the operator allowed this one request.
 * - `approved_always`: the operator allowed it and the permission was granted for good (the caller
 *   grants it before settling, so the re-check after the wait finds it in the database).
 * - `denied`: the operator refused.
 * - `expired`: nobody decided within the TTL.
 * - `cancelled`: the connection was revoked, deleted or switched back to DENY, or the signer stopped.
 */
export type ApprovalOutcome =
  'approved_once' | 'approved_always' | 'denied' | 'expired' | 'cancelled';

/** The part of a hold the RPC handler gives the signer: the link token and the eventual decision. */
export interface HeldRequest {
  token: string;
  /** Settles exactly once and never rejects. */
  decision: Promise<ApprovalOutcome>;
  /**
   * True when this is a retry of a request that is already held (the same request id on the same
   * connection): it shares that hold's decision, and its client must NOT be sent a second `auth_url`
   * (nostr-tools rejects the request when it gets one).
   */
  shared?: boolean;
  /**
   * True when the hold already has all the waiters it allows (the request and one retry): this event
   * is ignored altogether, so a client cannot park any number of events on one hold and have each
   * answered, signed and logged when it ends.
   */
  dropped?: boolean;
}

export interface OpenApprovalInput {
  userId: string;
  connectionId: string;
  connectionName: string;
  clientPubkey: string;
  /** The NIP-46 request id; the final reply carries the same one. */
  requestId: string;
  /**
   * Identifies WHAT is asked (method and parameters). A second event with the same request id shares
   * the hold only when this matches, so approving one request can never sign another.
   */
  fingerprint: string;
  permission: PermissionDescriptor;
  preview?: ApprovalPreviewDto;
}

interface Entry {
  token: string;
  userId: string;
  connectionId: string;
  connectionName: string;
  clientPubkey: string;
  requestId: string;
  fingerprint: string;
  permission: PermissionDescriptor;
  preview?: ApprovalPreviewDto;
  createdAt: number;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
  decision: Promise<ApprovalOutcome>;
  settle: (outcome: ApprovalOutcome) => void;
  /** Events waiting on this hold: the one that opened it, and at most one retry. */
  waiters: number;
}

/**
 * What would garble or spoof the operator's view of a text, and is not a visible character: C0 and C1
 * controls, every default-ignorable code point (zero-width characters and joiners, the soft hyphen,
 * bidi marks and overrides, the Hangul and half-width fillers, variation selectors, the tag
 * characters, ...), the line and paragraph separators, and the interlinear and object-replacement
 * marks. Astral ranges need the `u` flag.
 */
const INVISIBLE =
  // The explicit ranges stay although the properties cover them: a Unicode update must not reopen one.
  // The class holds variation selectors and tag characters on purpose: it removes them.
  // eslint-disable-next-line no-control-regex, no-misleading-character-class
  /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Zl}\p{Zp}\u0000-\u001f\u007f-\u009f\u00ad\u061c\u115f\u1160\u200b-\u200f\u2028-\u202e\u2060-\u2069\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffc\u{e0000}-\u{e007f}\u{e0100}-\u{e01ef}]/gu;

/**
 * Characters that are blank in another way than a plain space: the no-break space, the en and em
 * spaces, the ideographic space and every other space separator, and the braille blank. Shown as the
 * space they look like, so none can pass for text it is not.
 */
const BLANKS = /[\p{Zs}\u2800]/gu;

const clean = (text: string, replacement: string) =>
  text.replace(BLANKS, ' ').replace(INVISIBLE, replacement);

/** The first `max` characters, counted in code points: never half of a surrogate pair. */
function cut(text: string, max: number): string {
  if (text.length <= max) return text;
  // Every code point is at most two UTF-16 units, so 2 * max units hold at least `max` of them.
  return Array.from(text.slice(0, max * 2))
    .slice(0, max)
    .join('');
}

/** The length in code points, without building an array of a long text. */
function countCodePoints(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i++;
    }
    n++;
  }
  return n;
}

/** A text the operator reads (event content, a plaintext): cleaned, cut, and its full length. */
function previewText(
  text: string,
): Pick<ApprovalPreviewDto, 'content' | 'contentTruncated' | 'contentLength'> {
  const cleaned = clean(text, ' ');
  const shown = cut(cleaned, APPROVAL_CONSTANTS.PREVIEW_CONTENT_MAX);
  return {
    content: shown,
    contentTruncated: shown.length < cleaned.length,
    contentLength: countCodePoints(cleaned),
  };
}

/** A text from the client, cleaned and cut, with whether it was cut and how long it was. */
interface Shown {
  text: string;
  cut: boolean;
  /** In characters (code points), before the cut. */
  length: number;
}
function shorten(text: string, max: number): Shown {
  const cleaned = clean(text, '?');
  const shown = cut(cleaned, max);
  return { text: shown, cut: shown.length < cleaned.length, length: countCodePoints(cleaned) };
}

/** A short text from the client (a tag name, a method, a peer): cleaned and cut. */
const short = (text: string, max: number) => shorten(text, max).text;

/**
 * What kind 27235 (NIP-98 HTTP auth) signs for. The operator cannot tell one login from another by
 * the kind, and an account deletion is confirmed with the very same kind, so the URL it is for is
 * what matters. Read with a URL parser, so `https://trusted.example@evil.example/` shows evil.example
 * and a look-alike domain shows its punycode form.
 */
function previewHttpAuth(tags: unknown[]): ApprovalHttpAuthPreview | undefined {
  const first = (name: string): string | undefined => {
    for (const tag of tags) {
      if (Array.isArray(tag) && tag[0] === name && typeof tag[1] === 'string') return tag[1];
    }
    return undefined;
  };
  const out: ApprovalHttpAuthPreview = {};
  // Whatever is cut is said to be: a login URL whose tail was dropped (`...&confirm=delete`) must not
  // look like the whole of it.
  let truncated = false;
  const take = (text: string, max: number) => {
    const shown = shorten(text, max);
    if (shown.cut) truncated = true;
    return shown.text;
  };
  const u = first('u');
  if (u !== undefined) {
    out.urlLength = countCodePoints(u);
    try {
      const url = new URL(u);
      if (url.host) {
        out.host = take(url.host, APPROVAL_CONSTANTS.PREVIEW_URL_MAX);
        out.path = take(url.pathname + url.search, APPROVAL_CONSTANTS.PREVIEW_URL_MAX);
      } else {
        out.url = take(u, APPROVAL_CONSTANTS.PREVIEW_URL_MAX);
      }
    } catch {
      out.url = take(u, APPROVAL_CONSTANTS.PREVIEW_URL_MAX);
    }
  }
  const method = first('method');
  if (method !== undefined) out.method = take(method, APPROVAL_CONSTANTS.PREVIEW_TAG_NAME_MAX);
  const payload = first('payload');
  if (payload !== undefined) out.payload = take(payload, APPROVAL_CONSTANTS.PREVIEW_TAG_VALUE_MAX);
  if (truncated) out.truncated = true;
  return Object.keys(out).length > 0 ? out : undefined;
}

/**
 * The event's own `created_at` as a date, flagged when it is more than a day from now: an event
 * dated far in the past or the future is a replay or a pre-signed one, not what the client is
 * doing at this moment. A value that is not a usable time is flagged without a date.
 */
function previewEventTime(
  createdAt: unknown,
): Pick<ApprovalPreviewDto, 'eventTime' | 'eventTimeOff'> {
  const usable =
    typeof createdAt === 'number' &&
    Number.isSafeInteger(createdAt) &&
    Math.abs(createdAt * 1000) <= 8.64e15;
  if (!usable) return { eventTimeOff: true };
  const nowS = Math.floor(Date.now() / 1000);
  return {
    eventTime: new Date(createdAt * 1000).toISOString(),
    eventTimeOff: Math.abs(createdAt - nowS) > APPROVAL_CONSTANTS.PREVIEW_TIME_SKEW_S,
  };
}

/**
 * What the operator is shown about a `sign_event` request: the kind, the content (controls removed,
 * cut short, with its full length), and every tag with its name and first values. For kind 27235 also
 * what the login is for. Never the whole event, and never anything the client could use to inject
 * markup (the web view renders it as text). Returns undefined for an event that does not parse; the
 * hold itself does not depend on a preview.
 */
export function previewSignEvent(eventJson: string | undefined): ApprovalPreviewDto | undefined {
  if (!eventJson) return undefined;
  let event: unknown;
  try {
    event = JSON.parse(eventJson);
  } catch {
    return undefined;
  }
  if (typeof event !== 'object' || event === null) return undefined;
  const { kind, content, tags, created_at } = event as {
    kind?: unknown;
    content?: unknown;
    tags?: unknown;
    created_at?: unknown;
  };

  const preview: ApprovalPreviewDto = {};
  if (typeof kind === 'number' && Number.isInteger(kind) && kind >= 0 && kind <= MAX_EVENT_KIND) {
    preview.kind = kind;
  }
  if (typeof content === 'string') Object.assign(preview, previewText(content));
  if (created_at !== undefined) Object.assign(preview, previewEventTime(created_at));
  if (Array.isArray(tags)) {
    const shown: ApprovalTagPreview[] = [];
    let count = 0;
    for (const tag of tags) {
      if (!Array.isArray(tag) || typeof tag[0] !== 'string') continue;
      count++;
      if (shown.length >= APPROVAL_CONSTANTS.PREVIEW_TAG_NAMES_MAX) continue;
      const rest: unknown[] = tag.slice(1);
      const texts = rest.filter((v): v is string => typeof v === 'string');
      const values = texts
        .slice(0, APPROVAL_CONSTANTS.PREVIEW_TAG_VALUES_MAX)
        .map((v) => shorten(v, APPROVAL_CONSTANTS.PREVIEW_TAG_VALUE_MAX));
      const nonText = rest.length - texts.length;
      const isCut =
        values.some((v) => v.cut) || texts.length > APPROVAL_CONSTANTS.PREVIEW_TAG_VALUES_MAX;
      shown.push({
        name: short(tag[0], APPROVAL_CONSTANTS.PREVIEW_TAG_NAME_MAX),
        values: values.map((v) => v.text),
        // Said, not dropped: a value that is not text (a number, an object) is not shown either.
        ...(nonText > 0 ? { nonText } : {}),
        ...(isCut ? { cut: true } : {}),
      });
    }
    preview.tags = shown;
    preview.tagCount = count;
    if (preview.kind === LOGIN_EVENT_KIND) {
      const httpAuth = previewHttpAuth(tags);
      if (httpAuth) preview.httpAuth = httpAuth;
    }
  }
  return preview;
}

const HEX_PUBKEY = /^[0-9a-f]{64}$/i;

/**
 * What the operator is shown about an encrypt or decrypt request: who it is with, and for an encrypt
 * the plaintext, for a decrypt only how long the ciphertext is (it means nothing to read, and the
 * plaintext is what the client is after).
 */
function previewCrypto(
  method: 'encrypt' | 'decrypt',
  params: readonly string[],
): ApprovalPreviewDto | undefined {
  const [peer, payload] = params;
  if (typeof peer !== 'string') return undefined;
  const preview: ApprovalPreviewDto = { peer: short(peer, APPROVAL_CONSTANTS.PREVIEW_PEER_MAX) };
  if (HEX_PUBKEY.test(peer)) {
    try {
      preview.peerNpub = nip19.npubEncode(peer.toLowerCase());
    } catch {
      // Shown as hex only.
    }
  }
  if (typeof payload === 'string') {
    if (method === 'encrypt') Object.assign(preview, previewText(payload));
    else preview.ciphertextLength = payload.length;
  }
  return preview;
}

/** What to show for a held request of this method, or undefined when there is nothing to show. */
export function previewRequest(
  method: string,
  params: readonly string[],
): ApprovalPreviewDto | undefined {
  switch (method) {
    case 'sign_event':
      return previewSignEvent(params[0]);
    case 'nip04_encrypt':
    case 'nip44_encrypt':
      return previewCrypto('encrypt', params);
    case 'nip04_decrypt':
    case 'nip44_decrypt':
      return previewCrypto('decrypt', params);
    default:
      return undefined;
  }
}

/**
 * Why a request must NOT be held, or undefined when it may be. It is checked before a hold is
 * opened, so nothing the operator could not judge, and nothing that could not be answered, ever takes
 * a slot: an encrypt or decrypt whose peer is not a public key or whose payload is missing or huge,
 * and a login whose URL is longer than can be shown in full (the tail of a URL is where
 * `...&confirm=delete` hides). Such a request is answered with the ordinary refusal.
 */
export function holdBlocker(method: string, params: readonly string[]): string | undefined {
  switch (method) {
    case 'sign_event': {
      let event: { kind?: unknown; tags?: unknown };
      try {
        event = JSON.parse(params[0] ?? '') as { kind?: unknown; tags?: unknown };
      } catch {
        return undefined;
      }
      if (event?.kind !== LOGIN_EVENT_KIND || !Array.isArray(event.tags)) return undefined;
      for (const tag of event.tags as unknown[]) {
        if (!Array.isArray(tag) || tag[0] !== 'u' || typeof tag[1] !== 'string') continue;
        if (countCodePoints(tag[1]) > APPROVAL_CONSTANTS.PREVIEW_URL_MAX) {
          return 'the URL of this login is too long to be shown in full';
        }
      }
      return undefined;
    }
    case 'nip04_encrypt':
    case 'nip44_encrypt':
    case 'nip04_decrypt':
    case 'nip44_decrypt': {
      const [peer, payload] = params;
      if (typeof peer !== 'string' || !HEX_PUBKEY.test(peer)) return 'the peer is not a public key';
      if (typeof payload !== 'string' || payload.length === 0) return 'there is nothing to process';
      if (payload.length > APPROVAL_CONSTANTS.MAX_HOLD_PAYLOAD_CHARS)
        return 'the payload is too big';
      return undefined;
    }
    default:
      return undefined;
  }
}

/**
 * Requests held for the operator ("hold and ask"). In memory, like the pending bunker:// secrets: a
 * hold lasts at most the TTL (about 100 s), so surviving a restart would buy nothing; a restart ends
 * the wait and the client times out as it would have anyway.
 *
 * Tokens are 192-bit random identifiers, never credentials: every route that takes one also checks
 * that the logged-in user owns the connection behind it, and a foreign or unknown token is
 * indistinguishable (404).
 */
@Injectable()
export class ApprovalService implements OnModuleDestroy {
  private readonly logger = new Logger(ApprovalService.name);
  private readonly entries = new Map<string, Entry>();

  constructor(
    @Inject(APPROVAL_CONFIG_INJECTION_TOKEN) private readonly config: ApprovalConfig,
    private readonly events: EventsService,
  ) {}

  onModuleDestroy() {
    for (const entry of [...this.entries.values()]) entry.settle('cancelled');
  }

  /**
   * Whether anything can be asked at all. Without a PUBLIC_BASE_URL there is no link to send the
   * client, so it would wait in silence and then be refused: the signer refuses it at once instead.
   */
  get canAsk(): boolean {
    return Boolean(this.config.publicBaseUrl);
  }

  /**
   * Hold a request. Returns undefined when it must not be held: a cap is reached (per connection,
   * per user, then globally), so a connected client cannot make the signer remember an unbounded
   * number of waits, or the request id is already in use for something else. The caller answers
   * such a request as denied.
   *
   * A second event with the same request id on the same connection (a client retry, a relay
   * redelivery) for the SAME request shares the first hold: one decision, and its client is not sent
   * a second `auth_url`.
   */
  open(input: OpenApprovalInput): HeldRequest | undefined {
    for (const e of this.entries.values()) {
      if (e.connectionId !== input.connectionId || e.requestId !== input.requestId) continue;
      if (
        e.fingerprint === input.fingerprint &&
        e.permission.method === input.permission.method &&
        e.permission.kind === input.permission.kind
      ) {
        // One retry may wait on the hold (a resend, a relay redelivery). Anything past that is a
        // client parking events: they would each be answered, signed and logged when the hold ends.
        if (e.waiters >= APPROVAL_CONSTANTS.MAX_WAITERS_PER_HOLD) {
          this.logger.warn(
            `Request id ${input.requestId.slice(0, 8)} on connection ${input.connectionId} already has ${e.waiters} waiting events; ignoring another`,
          );
          return { token: e.token, decision: e.decision, shared: true, dropped: true };
        }
        e.waiters++;
        return { token: e.token, decision: e.decision, shared: true };
      }
      // The same id for another request: sharing would let approving one sign the other.
      this.logger.warn(
        `Request id ${input.requestId.slice(0, 8)} is held for another request on connection ${input.connectionId}; refusing to hold this one`,
      );
      return undefined;
    }
    if (this.entries.size >= APPROVAL_CONSTANTS.MAX_HOLDS_GLOBAL) {
      this.logger.warn('Too many held requests overall; refusing to hold another');
      return undefined;
    }
    let forConnection = 0;
    let forUser = 0;
    for (const e of this.entries.values()) {
      if (e.connectionId === input.connectionId) forConnection++;
      if (e.userId === input.userId) forUser++;
    }
    if (forUser >= APPROVAL_CONSTANTS.MAX_HOLDS_PER_USER) {
      this.logger.warn(`Too many held requests for user ${input.userId}; refusing to hold another`);
      return undefined;
    }
    if (forConnection >= APPROVAL_CONSTANTS.MAX_HOLDS_PER_CONNECTION) {
      this.logger.warn(
        `Too many held requests for connection ${input.connectionId}; refusing to hold another`,
      );
      return undefined;
    }

    let token = this.newToken();
    while (this.entries.has(token)) token = this.newToken();

    const now = Date.now();
    let settle!: (outcome: ApprovalOutcome) => void;
    const decision = new Promise<ApprovalOutcome>((resolve) => {
      settle = resolve;
    });

    const entry: Entry = {
      token,
      userId: input.userId,
      connectionId: input.connectionId,
      connectionName: input.connectionName,
      clientPubkey: input.clientPubkey,
      requestId: input.requestId,
      fingerprint: input.fingerprint,
      permission: input.permission,
      preview: input.preview,
      createdAt: now,
      expiresAt: now + this.config.ttlMs,
      timer: setTimeout(() => this.finish(token, 'expired'), this.config.ttlMs),
      decision,
      settle,
      waiters: 1,
    };
    // A pending hold must not keep the process alive on its own.
    entry.timer.unref?.();
    this.entries.set(token, entry);
    this.notify(input.userId);
    return { token, decision };
  }

  /** The link a held request's client is sent, or undefined when PUBLIC_BASE_URL is not set. */
  authUrl(token: string): string | undefined {
    return this.config.publicBaseUrl
      ? `${this.config.publicBaseUrl}/approvals/${token}`
      : undefined;
  }

  /** The user's open holds, oldest first. */
  list(userId: string): PendingApprovalDto[] {
    return [...this.entries.values()]
      .filter((e) => e.userId === userId)
      .sort((a, b) => a.createdAt - b.createdAt)
      .map((e) => this.toDto(e));
  }

  /** One hold, only for the user who owns its connection. */
  get(token: string, userId: string): PendingApprovalDto {
    return this.toDto(this.owned(token, userId));
  }

  /**
   * The operator's decision. `approved_always` also settles every other hold for the same method and
   * kind on the connection, since the permission now covers them. Throws NotFoundException for an
   * unknown, foreign or already-settled token.
   */
  resolve(
    token: string,
    userId: string,
    outcome: 'approved_once' | 'approved_always' | 'denied',
  ): PendingApprovalDto {
    const entry = this.owned(token, userId);
    const dto = this.toDto(entry);
    this.finish(token, outcome);
    if (outcome === 'approved_always') {
      for (const other of [...this.entries.values()]) {
        if (
          other.connectionId === entry.connectionId &&
          other.permission.method === entry.permission.method &&
          other.permission.kind === entry.permission.kind
        ) {
          this.finish(other.token, 'approved_always');
        }
      }
    }
    return dto;
  }

  /** End every hold of a connection (revoked, deleted, or switched to DENY). */
  cancelForConnection(connectionId: string): number {
    let cancelled = 0;
    for (const e of [...this.entries.values()]) {
      if (e.connectionId !== connectionId) continue;
      this.finish(e.token, 'cancelled');
      cancelled++;
    }
    return cancelled;
  }

  /** How many holds the user has open (the badge in the app header). */
  pendingCount(userId: string): number {
    let n = 0;
    for (const e of this.entries.values()) if (e.userId === userId) n++;
    return n;
  }

  get size(): number {
    return this.entries.size;
  }

  private owned(token: string, userId: string): Entry {
    const entry = this.entries.get(token);
    if (!entry || entry.userId !== userId) throw new NotFoundException('Approval not found');
    return entry;
  }

  /** The only place a hold ends: timer cleared, entry removed, decision settled, UI told. */
  private finish(token: string, outcome: ApprovalOutcome) {
    const entry = this.entries.get(token);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.entries.delete(token);
    entry.settle(outcome);
    this.logger.log(`Held request ${entry.requestId.slice(0, 8)} ended: ${outcome}`);
    this.notify(entry.userId);
  }

  private notify(userId: string) {
    // Fire and forget: a failed notification must never undo or delay a decision.
    Promise.resolve(this.events.publishUserActivity(userId)).catch(() => undefined);
  }

  private newToken(): string {
    return randomBytes(APPROVAL_CONSTANTS.TOKEN_BYTES).toString('base64url');
  }

  private toDto(e: Entry): PendingApprovalDto {
    return {
      token: e.token,
      connectionId: e.connectionId,
      connectionName: e.connectionName,
      clientPubkey: e.clientPubkey,
      method: e.permission.method,
      kind: e.permission.kind,
      preview: e.preview,
      createdAt: new Date(e.createdAt).toISOString(),
      expiresAt: new Date(e.expiresAt).toISOString(),
    };
  }
}
