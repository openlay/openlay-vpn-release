-- Allow multiple users on same physical device
-- Add hardware_id column, keep id as random UUID primary key

ALTER TABLE devices ADD COLUMN IF NOT EXISTS hardware_id TEXT;

-- Backfill: existing device id IS the hardware id
UPDATE devices SET hardware_id = id WHERE hardware_id IS NULL;

-- Add unique constraint: same hardware + same user = same device record
CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_hardware_user ON devices(hardware_id, user_id);
