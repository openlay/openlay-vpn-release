-- Per-admin DEK wrap for an ssh_keys row. Each (ssh_key_id, admin_user_id)
-- pair holds the DEK encrypted to that admin's SE encryption pubkey via
-- Apple's kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM (see
-- server/src/services/ecies.js).
--
-- An admin without a wrap row CANNOT decrypt that SSH key — they need
-- another admin to grant access via the M3 re-wrap flow.

CREATE TABLE IF NOT EXISTS ssh_key_dek_wraps (
  ssh_key_id      TEXT NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
  admin_user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wrapped_dek     BYTEA NOT NULL,    -- ECIES blob: eph_pub(65) || ct || tag(16)
  wrapped_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (ssh_key_id, admin_user_id)
);

-- "Which keys does this admin have access to?" query for the deploy
-- picker — one row per (admin, key) so this index makes per-admin lookups
-- index-only.
CREATE INDEX IF NOT EXISTS idx_ssh_key_wraps_admin ON ssh_key_dek_wraps(admin_user_id);

-- "Which admins can decrypt this key?" — used by the multi-admin re-wrap
-- detection (M3) to find missing wraps when a new admin enrols.
CREATE INDEX IF NOT EXISTS idx_ssh_key_wraps_key ON ssh_key_dek_wraps(ssh_key_id);
