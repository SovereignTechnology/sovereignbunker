import { z } from 'zod';
import { PermissionDescriptorSchema, MAX_PERMISSIONS_PER_REQUEST } from './permissions.js';

/**
 * What the signer does with a gated request a connection holds no permission for.
 * DENY: answer with a permission error at once (the default, and what every client that does not
 * understand NIP-46 `auth_url` needs). ASK: hold the request and let the operator decide.
 */
export const ApprovalModeSchema = z.enum(['DENY', 'ASK']);
export type ApprovalMode = z.infer<typeof ApprovalModeSchema>;

/** POST /api/approvals/:token/approve. `once` signs this request only; `always` also grants it. */
export const ApproveApprovalBodySchema = z
  .object({ mode: z.enum(['once', 'always']) })
  .strict();
export type ApproveApprovalBody = z.infer<typeof ApproveApprovalBodySchema>;

/** PATCH /api/connections/:id/approval-mode */
export const SetApprovalModeBodySchema = z.object({ mode: ApprovalModeSchema }).strict();
export type SetApprovalModeBody = z.infer<typeof SetApprovalModeBodySchema>;

/** A validated, bounded permission list as accepted by POST /connections and generate-bunker-uri. */
export const PermissionListSchema = z
  .array(PermissionDescriptorSchema)
  .max(MAX_PERMISSIONS_PER_REQUEST);

/** What the operator is shown about the event a client asked to sign. Bounded; never the whole event. */
export interface ApprovalPreviewDto {
  kind?: number;
  /** Event content, control characters removed, cut to a fixed length. */
  content?: string;
  contentTruncated?: boolean;
  /** Distinct tag names (`e`, `p`, `u`, ...), not their values. */
  tagNames?: string[];
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
