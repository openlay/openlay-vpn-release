-- Antivirus / endpoint-security signals on device_postures. Best-effort
-- across platforms — see the per-platform collectors for what each value
-- actually means:
--   * Windows (when wired up): WMI SecurityCenter2 — strongest signal.
--   * macOS:    bundle / extension detection + XProtect plist read.
--   * Linux:    systemd unit + binary heuristics.

ALTER TABLE device_postures
  ADD COLUMN IF NOT EXISTS antivirus_name TEXT,
  ADD COLUMN IF NOT EXISTS antivirus_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS antivirus_up_to_date BOOLEAN,
  ADD COLUMN IF NOT EXISTS is_xprotect_on BOOLEAN,
  ADD COLUMN IF NOT EXISTS xprotect_version TEXT;

-- "Devices with no AV detected at last submission" is the headline
-- compliance query — a partial index keeps it cheap as the table grows.
CREATE INDEX IF NOT EXISTS idx_device_postures_no_av
  ON device_postures (device_id, submitted_at DESC)
  WHERE antivirus_name IS NULL;
