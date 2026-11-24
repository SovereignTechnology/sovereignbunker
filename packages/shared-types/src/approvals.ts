import { z } from 'zod';
import { PermissionDescriptorSchema, MAX_PERMISSIONS_PER_REQUEST } from './permissions.js';

/**
 * What the signer does with a gated request a connection holds no permission for.
 * DENY: answer with a permission error at once (the default, and what every client that does not
 * understand NIP-46 `auth_url` needs). ASK: hold the request and let the operator decide.
 */
export const ApprovalModeSchema = z.enum(['DENY', 'ASK']);
export type ApprovalMode = z.infer<typeof ApprovalModeSchema>;

/**
 * POST /api/approvals/:token/approve. `once` signs this request only; `always` also grants it for
 * good, and for anything but an ordinary kind (see grantNeedsConfirmation) the server refuses that
 * unless `confirm` is true: the second click lives in the page, so it cannot be the only gate.
 */
export const ApproveApprovalBodySchema = z
  .object({ mode: z.enum(['once', 'always']), confirm: z.boolean().optional() })
  .strict();
export type ApproveApprovalBody = z.infer<typeof ApproveApprovalBodySchema>;

/** PATCH /api/connections/:id/approval-mode */
export const SetApprovalModeBodySchema = z.object({ mode: ApprovalModeSchema }).strict();
export type SetApprovalModeBody = z.infer<typeof SetApprovalModeBodySchema>;

/** A validated, bounded permission list as accepted by POST /connections and generate-bunker-uri. */
export const PermissionListSchema = z
  .array(PermissionDescriptorSchema)
  .max(MAX_PERMISSIONS_PER_REQUEST);

/**
 * POST /api/connections/:id/permissions/approve: exactly these pending requests, never "all" (that is
 * its own call, `approve-all`). `confirm` must be true when any of them needs it
 * (grantNeedsConfirmation).
 */
export const ApprovePermissionsBodySchema = z
  .object({ permissions: PermissionListSchema.min(1), confirm: z.boolean().optional() })
  .strict();
export type ApprovePermissionsBody = z.infer<typeof ApprovePermissionsBodySchema>;

/** POST /api/connections/:id/permissions/deny: exactly these pending requests (`deny-all` is its own call). */
export const DenyPermissionsBodySchema = z
  .object({ permissions: PermissionListSchema.min(1) })
  .strict();
export type DenyPermissionsBody = z.infer<typeof DenyPermissionsBodySchema>;

/** One tag of the event, as shown: its name and its first few values, each cleaned and cut. */
export interface ApprovalTagPreview {
  name: string;
  values: string[];
  /** How many of the tag's values are not text, and so not shown. */
  nonText?: number;
  /** True when a value shown is only the start of a longer one. */
  cut?: boolean;
}

/**
 * For a kind 27235 event (NIP-98 HTTP auth: what a website login signs, and also what confirms an
 * account deletion): what the signature is for, taken from its `u`, `method` and `payload` tags.
 */
export interface ApprovalHttpAuthPreview {
  /** Host (and port) of `u`, as a URL parser reads it: user info dropped, look-alikes in punycode. */
  host?: string;
  /** Path and query of `u`. */
  path?: string;
  /** `u` as sent, when it is not a URL at all. */
  url?: string;
  method?: string;
  payload?: string;
  /** True when anything above is only the start of what was sent: the rest was never shown. */
  truncated?: boolean;
  /** How long `u` was, in characters, so a cut is never mistaken for all of it. */
  urlLength?: number;
}

/**
 * What the operator is shown about a request the client wants answered. Bounded; never the whole
 * event. Every string has had controls, bidi and invisible characters removed.
 */
export interface ApprovalPreviewDto {
  kind?: number;
  /** Event content (sign_event) or the plaintext (encrypt), cut to a fixed length. */
  content?: string;
  contentTruncated?: boolean;
  /** How long the whole content was, in characters, so a cut is never mistaken for all of it. */
  contentLength?: number;
  /** The tags, in order, with their first values. */
  tags?: ApprovalTagPreview[];
  /** How many tags the event has in all (the list above is cut). */
  tagCount?: number;
  httpAuth?: ApprovalHttpAuthPreview;
  /** The event's own `created_at`, as a date (ISO 8601). */
  eventTime?: string;
  /** True when that date is more than a day from now: a stale or future-dated event. */
  eventTimeOff?: boolean;
  /** The other party of an encrypt or decrypt request, as hex. */
  peer?: string;
  /** The same key as an npub, for display. */
  peerNpub?: string;
  /** How long the ciphertext of a decrypt request is (the ciphertext itself is never shown). */
  ciphertextLength?: number;
}

/** GET /api/approvals. */
export interface PendingApprovalsDto {
  approvals: PendingApprovalDto[];
  /**
   * False when the server has no PUBLIC_BASE_URL: it has no link to send a client, so it refuses a
   * gated request at once instead of holding it, and the UI should not offer asking.
   */
  canAsk: boolean;
}

/** A held request waiting for the operator, as listed by GET /api/approvals. */
export interface PendingApprovalDto {
  token: string;
  connectionId: string;
  connectionName: string;
  clientPubkey: string;
  method: string;
  kind?: number;
  preview?: ApprovalPreviewDto;
  createdAt: string;
  expiresAt: string;
}
