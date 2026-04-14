-- Map users to enterprises with roles
CREATE TABLE IF NOT EXISTS user_enterprise_roles (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  enterprise_id   TEXT NOT NULL REFERENCES enterprises(id) ON DELETE CASCADE,
  role            TEXT NOT NULL DEFAULT 'admin'
                  CHECK (role IN ('super_admin', 'admin', 'member')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, enterprise_id)
);

CREATE INDEX IF NOT EXISTS idx_uer_user_id ON user_enterprise_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_uer_enterprise_id ON user_enterprise_roles(enterprise_id);
