-- Per-enterprise settings (replaces global app_settings for enterprise-scoped config)
CREATE TABLE IF NOT EXISTS enterprise_settings (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id   TEXT NOT NULL REFERENCES enterprises(id) ON DELETE CASCADE,
  key             TEXT NOT NULL,
  value           TEXT NOT NULL DEFAULT 'false',
  description     TEXT,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(enterprise_id, key)
);

CREATE INDEX IF NOT EXISTS idx_ent_settings_enterprise ON enterprise_settings(enterprise_id);
