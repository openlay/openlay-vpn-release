-- Adds the `Allow WAN Access` toggle to device profiles. When TRUE, the
-- management server auto-maintains a per-device ACCEPT firewall rule
-- (src=device peer IP -> dst=wan zone) on every server the device has a
-- peer on. See server/src/services/deviceWanAccessFirewall.js.
ALTER TABLE device_profiles
  ADD COLUMN IF NOT EXISTS allow_wan_access BOOLEAN NOT NULL DEFAULT FALSE;
