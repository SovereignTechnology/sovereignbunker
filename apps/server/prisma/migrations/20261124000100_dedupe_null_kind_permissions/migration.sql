-- Remove duplicate method-level (kind IS NULL) permission rows.
--
-- The unique index on (connection_id, method, kind) does not collapse rows whose kind is NULL
-- (NULLs are distinct in a PostgreSQL unique index), so a client retrying a denied method-level
-- request (e.g. nip44_decrypt) inserted another pending row each time. The application now skips a
-- method/kind that already has a row; this clears the duplicates that accumulated before that.
-- A granted row wins over a pending one, then the oldest id, so no grant is ever lost.
--
-- Idempotent: once each (connection_id, method) has a single kind-NULL row this deletes nothing.
DELETE FROM "connection_permissions" p
USING (
  SELECT "id",
         ROW_NUMBER() OVER (
           PARTITION BY "connection_id", "method"
           ORDER BY "allowed" DESC, "id"
         ) AS rn
  FROM "connection_permissions"
  WHERE "kind" IS NULL
) d
WHERE p."id" = d."id" AND d.rn > 1;
