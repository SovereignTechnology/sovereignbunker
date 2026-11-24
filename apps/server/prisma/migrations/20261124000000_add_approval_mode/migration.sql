-- Per-connection approval mode for gated requests the connection holds no permission for.
--
-- DENY (the default) answers with a permission error at once: exactly what every connection did
-- before this migration. ASK holds the request, sends the client an NIP-46 `auth_url` pointing at
-- the operator's approvals page, and answers once the operator decides. Additive and
-- backwards-compatible: existing rows take the DEFAULT, so no existing connection changes behaviour.

-- CreateEnum
CREATE TYPE "ApprovalMode" AS ENUM ('DENY', 'ASK');

-- AlterTable
ALTER TABLE "bunker_connections" ADD COLUMN "approval_mode" "ApprovalMode" NOT NULL DEFAULT 'DENY';
