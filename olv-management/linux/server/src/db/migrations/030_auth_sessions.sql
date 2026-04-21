-- Refresh/login tokens for session+login split. Each row represents one
-- long-lived refresh token issued to (user, device). Access tokens are
-- stateless JWTs and not tracked here.
CREATE TABLE IF NOT EXISTS auth_sessions (
  id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id           TEXT REFERENCES devices(id) ON DELETE CASCADE,
  refresh_token_hash  TEXT NOT NULL UNIQUE,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at          TIMESTAMPTZ NOT NULL,
  revoked_at          TIMESTAMPTZ,
  last_used_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_agent          TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_hash_alive
  ON auth_sessions(refresh_token_hash) WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_device
  ON auth_sessions(user_id, device_id);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires
  ON auth_sessions(expires_at) WHERE revoked_at IS NULL;
