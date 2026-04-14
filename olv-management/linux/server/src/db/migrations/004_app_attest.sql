-- Store App Attest attestation data per device
CREATE TABLE IF NOT EXISTS device_attestations (
  id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id      VARCHAR(255) NOT NULL UNIQUE,
  public_key  TEXT NOT NULL,
  sign_count  INTEGER NOT NULL DEFAULT 0,
  receipt     BYTEA,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_attestations_device_id ON device_attestations(device_id);
CREATE INDEX IF NOT EXISTS idx_device_attestations_key_id ON device_attestations(key_id);

-- Short-lived challenges for attestation and assertion
CREATE TABLE IF NOT EXISTS attest_challenges (
  id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenge   VARCHAR(255) NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attest_challenges_challenge ON attest_challenges(challenge);
