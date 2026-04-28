-- Device profiles: a reusable bundle of tunnel-rules that an admin builds
-- once and assigns to many devices. Replaces the per-device-static-IP
-- `allowed_ips` workflow (still kept as override) and the enterprise-wide
-- singleton `disallowed_ips` / `disallowed_domains` rows in
-- `enterprise_settings` (legacy fallback when a device has no profile).
CREATE TABLE IF NOT EXISTS device_profiles (
  id                TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id     TEXT NOT NULL REFERENCES enterprises(id) ON DELETE CASCADE,
  name              TEXT NOT NULL,
  description       TEXT,
  allowed_ips       TEXT[] NOT NULL DEFAULT '{}',
  exclusion_ips     TEXT[] NOT NULL DEFAULT '{}',
  exclusion_domains TEXT[] NOT NULL DEFAULT '{}',
  require_posture   BOOLEAN NOT NULL DEFAULT false,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (enterprise_id, name)
);

CREATE INDEX IF NOT EXISTS idx_device_profiles_enterprise ON device_profiles(enterprise_id);

-- ON DELETE SET NULL so deleting a profile downgrades affected devices to
-- "no profile" rather than cascading the device row.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS profile_id TEXT
  REFERENCES device_profiles(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_devices_profile ON devices(profile_id);
