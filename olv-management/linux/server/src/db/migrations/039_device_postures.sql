-- Device posture history: client submits a posture snapshot every interval
-- (when posture_submission_enabled setting is on). Full snapshot lives in
-- the JSONB column; common fields are extracted to columns for indexing
-- and quick filtering in the admin UI.

-- NOTE: devices.id and enterprises.id are TEXT (the rest of this codebase
-- treats them as opaque strings via gen_random_uuid()::text). FK columns
-- here must match — using UUID type fails with "foreign key constraint
-- cannot be implemented" on apply.
CREATE TABLE device_postures (
  id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  enterprise_id TEXT REFERENCES enterprises(id) ON DELETE SET NULL,
  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  posture JSONB NOT NULL,
  platform TEXT,
  os_version TEXT,
  app_version TEXT,
  is_jailbroken BOOLEAN,
  is_disk_encrypted BOOLEAN,
  is_passcode_set BOOLEAN
);

CREATE INDEX idx_device_postures_device_submitted
  ON device_postures (device_id, submitted_at DESC);

CREATE INDEX idx_device_postures_enterprise_submitted
  ON device_postures (enterprise_id, submitted_at DESC);

ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_posture_at TIMESTAMPTZ;
