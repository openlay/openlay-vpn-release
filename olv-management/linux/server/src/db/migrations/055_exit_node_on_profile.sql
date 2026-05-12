-- Move the exit-node selection from per-device (devices.exit_node_device_id,
-- migration 051) up to per-profile (device_profiles.exit_node_device_id).
-- Matches the existing policy-bundle shape on device_profiles
-- (allow_wan_access, can_be_exit_node, allowed_ips, exclusion_ips,
-- require_posture). One profile flip → every device on the profile
-- inherits the same exit-node assignment.
--
-- Self-loop guard is application-level only — pg CHECK can't reference
-- another table, and a profile pointing at one of ITS OWN member devices
-- as the exit node would cause that member to route through itself. The
-- sync service in deviceExitNodeRouting.js short-circuits at runtime and
-- the admin POST/PUT validators reject the assignment up front.

ALTER TABLE device_profiles
  ADD COLUMN IF NOT EXISTS exit_node_device_id TEXT NULL
    REFERENCES devices(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_device_profiles_exit_node_device_id
  ON device_profiles(exit_node_device_id) WHERE exit_node_device_id IS NOT NULL;

-- Drop the per-device column. Only test data exists at this point
-- (the feature shipped earlier today and we expect the user to re-assign
-- via the new profile-level UI). For any future production rollout, copy
-- existing devices.exit_node_device_id rows over to their profile here
-- before the DROP — but that's not needed today.
ALTER TABLE devices DROP CONSTRAINT IF EXISTS chk_devices_exit_node_not_self;
DROP INDEX IF EXISTS idx_devices_exit_node_device_id;
ALTER TABLE devices DROP COLUMN IF EXISTS exit_node_device_id;
