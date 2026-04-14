CREATE TABLE IF NOT EXISTS app_settings (
  key         VARCHAR(255) PRIMARY KEY,
  value       TEXT NOT NULL DEFAULT '',
  description TEXT DEFAULT '',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO app_settings (key, value, description)
VALUES ('require_device_approval', 'false', 'When enabled, new devices require admin approval before they can connect')
ON CONFLICT (key) DO NOTHING;
