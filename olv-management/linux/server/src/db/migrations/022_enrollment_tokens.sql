-- Enrollment tokens for agent registration (multi-use, TTL, rotatable)
CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id          TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  token       TEXT UNIQUE NOT NULL,
  name        TEXT,
  created_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  max_uses    INT NOT NULL DEFAULT 0,   -- 0 = unlimited
  use_count   INT NOT NULL DEFAULT 0,
  revoked     BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_token ON enrollment_tokens(token);
