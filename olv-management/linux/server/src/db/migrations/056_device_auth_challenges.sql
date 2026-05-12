-- Server-issued one-time challenges for /api/auth/device (SE-signature
-- login). Replaces the prior "client-chooses-its-own-challenge + reject
-- last value" replay defence which any captured (challenge, signature)
-- tuple could trivially bypass by varying the challenge.
CREATE TABLE IF NOT EXISTS device_auth_challenges (
  id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  challenge   VARCHAR(255) NOT NULL UNIQUE,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_auth_challenges_challenge ON device_auth_challenges(challenge);
CREATE INDEX IF NOT EXISTS idx_device_auth_challenges_device_id ON device_auth_challenges(device_id);
