-- Track device enrollment per enterprise
-- For password users: auto-enroll on first login, locked to 1 device
-- For Apple users: manual enroll via QR code by admin

ALTER TABLE devices ADD COLUMN IF NOT EXISTS enterprise_id TEXT REFERENCES enterprises(id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS enrollment_method TEXT DEFAULT 'manual'
  CHECK (enrollment_method IN ('auto', 'manual', 'qr'));

CREATE INDEX IF NOT EXISTS idx_devices_enterprise ON devices(enterprise_id);

-- Track which password user is locked to which device
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_device_id TEXT REFERENCES devices(id) ON DELETE SET NULL;
