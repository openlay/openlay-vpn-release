-- Per-action signed admin audit. Every protected admin operation (approve
-- enrollment, delete/disable device, disable user, profile CRUD, …) now
-- carries a fresh ECDSA-P256 signature from the admin's iOS-app Secure
-- Enclave key. We verify against `users.admin_signing_public_key` and append
-- a row to admin_audit_log on success — so a compromised management server
-- can't forge approvals (private key never leaves the admin's device) and
-- there's a non-repudiable trail back to who authorized what.

-- Per-user public key. ECDSA-P256 X9.62 uncompressed (65 bytes raw),
-- base64-encoded — same wire format as device.public_key.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS admin_signing_public_key TEXT,
  ADD COLUMN IF NOT EXISTS admin_signing_registered_at TIMESTAMPTZ;

-- Audit table: one row per signed admin action.
CREATE TABLE IF NOT EXISTS admin_audit_log (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  admin_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  enterprise_id   TEXT REFERENCES enterprises(id) ON DELETE SET NULL,
  action          TEXT NOT NULL,                  -- e.g. 'approve_enrollment'
  target_type     TEXT,                           -- 'enrollment' | 'device' | 'user' | 'device_profile'
  target_id       TEXT,
  payload         JSONB NOT NULL,                 -- canonical fields that were signed (replay-reconstructable)
  signature       TEXT NOT NULL,                  -- base64 DER ECDSA
  nonce           TEXT NOT NULL,                  -- random hex from client
  signed_at       TIMESTAMPTZ NOT NULL,           -- client-supplied timestamp (server checks skew)
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_admin ON admin_audit_log(admin_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_enterprise ON admin_audit_log(enterprise_id, created_at DESC);

-- Replay defence: every (admin, action, nonce) triple consumed exactly once.
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_audit_replay
  ON admin_audit_log(admin_user_id, action, nonce);
