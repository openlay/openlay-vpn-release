-- Enterprise / tenant organisations
CREATE TABLE IF NOT EXISTS enterprises (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id   TEXT UNIQUE NOT NULL,          -- random public-facing ID
  name            TEXT NOT NULL,
  country         TEXT,
  company_size    TEXT,
  industry        TEXT,
  owner_user_id   TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enterprises_enterprise_id ON enterprises(enterprise_id);
CREATE INDEX IF NOT EXISTS idx_enterprises_owner ON enterprises(owner_user_id);
