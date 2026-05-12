-- Per-admin Secure Enclave encryption pubkey. Wraps DEKs (data encryption
-- keys) for high-value secrets like SSH private keys (see ssh_keys + ssh_key_dek_wraps
-- in 053/054). The matching private key never leaves the admin's iOS Secure
-- Enclave — server alone CANNOT decrypt anything.
--
-- Wire format mirrors admin_signing_public_key (047): base64-encoded X9.62
-- uncompressed P-256 (65 raw bytes). The same physical key material is NOT
-- reused for signing — the iOS app holds two distinct SE keys with distinct
-- application tags, one for ECDSA signing and one for ECIES wrapping.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS admin_encryption_public_key TEXT,
  ADD COLUMN IF NOT EXISTS admin_encryption_registered_at TIMESTAMPTZ;

-- Index used by SSH key import: when wrapping a fresh DEK we enumerate
-- every admin in this enterprise that has an encryption key registered.
-- Without an index this is full-scan over `users` per import.
CREATE INDEX IF NOT EXISTS idx_users_has_encryption_key
  ON users(id)
  WHERE admin_encryption_public_key IS NOT NULL;
