-- Round out the device_postures schema introduced in 039:
--   * Wide set of extracted columns for fast filtering / dashboards
--   * GIN index on the JSONB for ad-hoc queries the columns can't cover
--   * Partial indexes for the common "show me at-risk devices" filters
--   * Latest-snapshot view for per-device dashboards
--   * Retention setting + helper function (cleanup runs from the management
--     server's daily timer — see services/postureCleanup.js)
--
-- Existing rows survive untouched; new columns default to NULL until the
-- next submission populates them.

----------------------------------------------------------------
-- Extracted columns
----------------------------------------------------------------
ALTER TABLE device_postures
  -- App / OS identity
  ADD COLUMN IF NOT EXISTS app_build TEXT,
  ADD COLUMN IF NOT EXISTS os_build TEXT,
  ADD COLUMN IF NOT EXISTS kernel_release TEXT,
  ADD COLUMN IF NOT EXISTS device_model TEXT,
  ADD COLUMN IF NOT EXISTS device_name TEXT,
  ADD COLUMN IF NOT EXISTS hostname TEXT,
  ADD COLUMN IF NOT EXISTS hardware_model TEXT,
  ADD COLUMN IF NOT EXISTS hardware_serial TEXT,
  ADD COLUMN IF NOT EXISTS hardware_id TEXT,
  -- Build flavour signals — useful for filtering out dev/sim noise
  ADD COLUMN IF NOT EXISTS is_simulator BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_debug_build BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_developer_mode BOOLEAN,
  -- Identity / lock factors (cross-platform)
  ADD COLUMN IF NOT EXISTS is_biometry_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS biometry_type TEXT,
  ADD COLUMN IF NOT EXISTS is_root BOOLEAN,
  -- Power / runtime
  ADD COLUMN IF NOT EXISTS uptime_seconds BIGINT,
  ADD COLUMN IF NOT EXISTS thermal_state TEXT,
  ADD COLUMN IF NOT EXISTS is_low_power_mode BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_charging BOOLEAN,
  ADD COLUMN IF NOT EXISTS battery_level NUMERIC(4, 3), -- 0.000–1.000
  ADD COLUMN IF NOT EXISTS battery_state TEXT,
  -- Storage / memory snapshots
  ADD COLUMN IF NOT EXISTS free_disk_bytes BIGINT,
  ADD COLUMN IF NOT EXISTS total_disk_bytes BIGINT,
  ADD COLUMN IF NOT EXISTS physical_memory_bytes BIGINT,
  ADD COLUMN IF NOT EXISTS free_memory_bytes BIGINT,
  -- Locale
  ADD COLUMN IF NOT EXISTS locale TEXT,
  ADD COLUMN IF NOT EXISTS timezone TEXT,
  -- macOS-specific
  ADD COLUMN IF NOT EXISTS is_filevault_on BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_sip_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_gatekeeper_on BOOLEAN,
  ADD COLUMN IF NOT EXISTS mdm_enrolled BOOLEAN,
  -- Linux-specific
  ADD COLUMN IF NOT EXISTS selinux_status TEXT,
  ADD COLUMN IF NOT EXISTS apparmor_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS firewall_state TEXT,
  ADD COLUMN IF NOT EXISTS process_count INTEGER,
  -- Windows-specific (no client populates these yet — Windows posture is
  -- queued for a later session, but the columns are here so the schema
  -- doesn't have to change again when that lands).
  ADD COLUMN IF NOT EXISTS is_bitlocker_on BOOLEAN,
  ADD COLUMN IF NOT EXISTS defender_state TEXT,
  ADD COLUMN IF NOT EXISTS uac_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS domain_joined BOOLEAN,
  -- Cross-platform secure boot / TPM
  ADD COLUMN IF NOT EXISTS is_secure_boot_on BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_tpm_present BOOLEAN,
  -- Source-of-truth audit fields — server-stamped, not from client payload
  ADD COLUMN IF NOT EXISTS submitted_from_ip TEXT,
  ADD COLUMN IF NOT EXISTS user_agent TEXT;

----------------------------------------------------------------
-- Indexes
----------------------------------------------------------------

-- GIN over the JSONB so admins can query fields we didn't promote to
-- columns (`posture @> '{"network_type":"cellular"}'::jsonb`, etc.).
-- jsonb_path_ops is more compact and faster for containment but only
-- supports `@>` — that's the operator the admin UI will use, so prefer it.
CREATE INDEX IF NOT EXISTS idx_device_postures_posture_gin
  ON device_postures USING GIN (posture jsonb_path_ops);

-- Partial indexes for "show me at-risk devices" dashboards. Partial
-- because the at-risk subset is tiny relative to the full table —
-- bounded scans where it counts.
CREATE INDEX IF NOT EXISTS idx_device_postures_jailbroken
  ON device_postures (device_id, submitted_at DESC)
  WHERE is_jailbroken = true;

CREATE INDEX IF NOT EXISTS idx_device_postures_unencrypted
  ON device_postures (device_id, submitted_at DESC)
  WHERE is_disk_encrypted = false;

CREATE INDEX IF NOT EXISTS idx_device_postures_no_passcode
  ON device_postures (device_id, submitted_at DESC)
  WHERE is_passcode_set = false;

CREATE INDEX IF NOT EXISTS idx_device_postures_filevault_off
  ON device_postures (device_id, submitted_at DESC)
  WHERE is_filevault_on = false;

CREATE INDEX IF NOT EXISTS idx_device_postures_bitlocker_off
  ON device_postures (device_id, submitted_at DESC)
  WHERE is_bitlocker_on = false;

----------------------------------------------------------------
-- Latest-snapshot view
----------------------------------------------------------------
-- Used by the admin compliance dashboard to scan the current state of
-- every device without window-functioning the full history. A regular
-- view (not materialized) is fine: PG plans DISTINCT ON cheaply against
-- the (device_id, submitted_at DESC) index.
CREATE OR REPLACE VIEW device_postures_latest AS
SELECT DISTINCT ON (device_id) *
FROM device_postures
ORDER BY device_id, submitted_at DESC;

COMMENT ON VIEW device_postures_latest IS
  'Most recent posture snapshot per device. Backed by the (device_id, submitted_at DESC) index.';

----------------------------------------------------------------
-- Retention setting
----------------------------------------------------------------
-- Global default; per-enterprise override can be added later if needed.
INSERT INTO app_settings (key, value, description)
VALUES (
  'posture_retention_days',
  '90',
  'Days of device posture history to keep. Older rows are deleted by the management server cleanup job. 0 = keep forever.'
)
ON CONFLICT (key) DO NOTHING;

----------------------------------------------------------------
-- Retention helper
----------------------------------------------------------------
-- Lets the cleanup job stay simple (one CALL, no inline date math) and
-- gives operators an easy `SELECT prune_device_postures(30);` knob for
-- one-off shrinking.
CREATE OR REPLACE FUNCTION prune_device_postures(retain_days INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
  deleted INTEGER;
BEGIN
  IF retain_days IS NULL OR retain_days <= 0 THEN
    RETURN 0;
  END IF;
  DELETE FROM device_postures
   WHERE submitted_at < NOW() - (retain_days || ' days')::INTERVAL;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END;
$$;

COMMENT ON FUNCTION prune_device_postures(INTEGER) IS
  'Delete posture rows older than retain_days. Returns deleted row count. retain_days <= 0 is a no-op.';
