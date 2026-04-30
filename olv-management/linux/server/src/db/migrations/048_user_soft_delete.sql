-- Soft-delete for users. Hard-delete is destructive: it nullifies admin_user_id
-- in admin_audit_log (lose attribution), drops enterprise ownership, breaks
-- "who approved this device" trails. Soft-delete keeps the users row with a
-- terminal status='deleted' + nullified PII while explicitly tearing down
-- live relationships (devices, sessions, peers, ACLs) so the user can no
-- longer connect.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS deleted_at         TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS deleted_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

-- Partial index — most queries care about the live set; the deleted-rows
-- audit view is rare and can scan.
CREATE INDEX IF NOT EXISTS idx_users_deleted_at
  ON users(deleted_at) WHERE deleted_at IS NOT NULL;

-- Allow 'deleted' as a valid status. Existing CHECK constraint (if any —
-- we use it defensively) is dropped and recreated. No data migration: no
-- existing rows have status='deleted' yet.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check
  CHECK (status IN ('pending', 'enabled', 'disabled', 'deleted'));
