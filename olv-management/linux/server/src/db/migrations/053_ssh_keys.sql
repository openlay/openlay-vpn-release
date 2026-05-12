-- SSH private key vault. Each row holds an encrypted private key — the
-- DEK that decrypts it is NOT stored here; it lives only in
-- ssh_key_dek_wraps (054), wrapped per-admin to their SE encryption pubkey.
-- Server cannot decrypt without an iOS admin online + Face ID.
--
-- See memory `se_wrapping_pattern.md` for the threat model.

CREATE TABLE IF NOT EXISTS ssh_keys (
  id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id       TEXT NOT NULL REFERENCES enterprises(id) ON DELETE CASCADE,
  name                TEXT NOT NULL,                          -- user-supplied label
  fingerprint         TEXT NOT NULL,                          -- 'SHA256:base64...' (OpenSSH wire format)
  public_key_openssh  TEXT NOT NULL,                          -- '<algo> <base64> [comment]' single line
  encrypted_blob      BYTEA NOT NULL,                         -- AES-256-GCM(privkey_pkcs8_pem) under DEK
  dek_iv              BYTEA NOT NULL,                         -- 12-byte IV for the AES-256-GCM seal
  dek_tag             BYTEA NOT NULL,                         -- 16-byte GCM tag
  algorithm           TEXT NOT NULL,                          -- 'rsa' | 'ed25519' | 'ecdsa' (sshpk normalised)
  bits                INTEGER,                                -- key size in bits; -1 for ed25519
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by          TEXT REFERENCES users(id) ON DELETE SET NULL,
  -- Same fingerprint imported twice in the same enterprise = wasted DEK
  -- + duplicate confusion. Block at the DB level.
  UNIQUE (enterprise_id, fingerprint)
);

-- Listing keys in a single enterprise sorted by recency is the dominant
-- access pattern (Settings > SSH Keys list view).
CREATE INDEX IF NOT EXISTS idx_ssh_keys_enterprise_created
  ON ssh_keys(enterprise_id, created_at DESC);
