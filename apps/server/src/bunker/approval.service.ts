import { Inject, Injectable, Logger, NotFoundException, type OnModuleDestroy } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import {
  APPROVAL_CONFIG_INJECTION_TOKEN,
  APPROVAL_CONSTANTS,
  type ApprovalConfig,
} from '@bunker46/config';
import type {
  ApprovalPreviewDto,
  PendingApprovalDto,
  PermissionDescriptor,
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
  | 'approved_once'
  | 'approved_always'
  | 'denied'
  | 'expired'
  | 'cancelled';

/** The part of a hold the RPC handler gives the signer: the link token and the eventual decision. */
export interface HeldRequest {
  token: string;
  /** Settles exactly once and never rejects. */
  decision: Promise<ApprovalOutcome>;
}

export interface OpenApprovalInput {
  userId: string;
  connectionId: string;
  connectionName: string;
  clientPubkey: string;
  /** The NIP-46 request id; the final reply carries the same one. */
  requestId: string;
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
  permission: PermissionDescriptor;
  preview?: ApprovalPreviewDto;
  createdAt: number;
  expiresAt: number;
  timer: ReturnType<typeof setTimeout>;
  settle: (outcome: ApprovalOutcome) => void;
}

/**
 * What would garble or spoof the operator's view of the content: C0 and C1 controls, DEL, zero-width
 * and bidi-direction characters (a right-to-left override can make one text read as another), the
 * line and paragraph separators, and the byte-order mark.
 */
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g;
const TAG_NAME_MAX = 16;

/**
 * What the operator is shown about a `sign_event` request: the kind, the content (controls removed,
 * cut short) and the tag names. Never the whole event, never tag values, and never anything the
 * client could use to inject markup (the web view renders it as text). Returns undefined for an
 * event that does not parse; the hold itself does not depend on a preview.
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
  const { kind, content, tags } = event as { kind?: unknown; content?: unknown; tags?: unknown };

  const preview: ApprovalPreviewDto = {};
  if (typeof kind === 'number' && Number.isInteger(kind) && kind >= 0) preview.kind = kind;
  if (typeof content === 'string') {
    const clean = content.replace(CONTROL_CHARS, ' ');
    preview.content = clean.slice(0, APPROVAL_CONSTANTS.PREVIEW_CONTENT_MAX);
    preview.contentTruncated = clean.length > APPROVAL_CONSTANTS.PREVIEW_CONTENT_MAX;
  }
  if (Array.isArray(tags)) {
    const names = new Set<string>();
    for (const tag of tags) {
      if (!Array.isArray(tag) || typeof tag[0] !== 'string') continue;
      names.add(tag[0].replace(CONTROL_CHARS, '?').slice(0, TAG_NAME_MAX));
      if (names.size >= APPROVAL_CONSTANTS.PREVIEW_TAG_NAMES_MAX) break;
    }
    preview.tagNames = [...names];
  }
  return preview;
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
   * Hold a request. Returns undefined when a cap is reached (per connection, then globally): the
   * caller answers such a request as denied, so a connected client cannot make the signer remember
   * an unbounded number of waits.
   */
  open(input: OpenApprovalInput): HeldRequest | undefined {
    if (this.entries.size >= APPROVAL_CONSTANTS.MAX_HOLDS_GLOBAL) {
      this.logger.warn('Too many held requests overall; refusing to hold another');
      return undefined;
    }
    let forConnection = 0;
    for (const e of this.entries.values()) {
      if (e.connectionId === input.connectionId) forConnection++;
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
      permission: input.permission,
      preview: input.preview,
      createdAt: now,
      expiresAt: now + this.config.ttlMs,
      timer: setTimeout(() => this.finish(token, 'expired'), this.config.ttlMs),
      settle,
    };
    // A pending hold must not keep the process alive on its own.
    entry.timer.unref?.();
    this.entries.set(token, entry);
    this.notify(input.userId);
    return { token, decision };
  }

  /** The link a held request's client is sent, or undefined when PUBLIC_BASE_URL is not set. */
  authUrl(token: string): string | undefined {
    return this.config.publicBaseUrl ? `${this.config.publicBaseUrl}/approvals/${token}` : undefined;
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
