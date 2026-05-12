-- Exit-Node feature: a "transit peer" can have other peers' WAN traffic
-- routed through it instead of through the agent's default WAN gateway
-- (Tailscale-style exit node).
--
-- Two columns, mirroring 050_device_profile_wan_access:
--   1. device_profiles.can_be_exit_node — capability gate (admin opt-in
--      per profile; only devices on such a profile may be picked).
--   2. devices.exit_node_device_id      — selection (per-device pointer
--      to the chosen exit node; NULL = use agent gateway as today).
--
-- Sync logic lives in server/src/services/deviceExitNodeRouting.js: when
-- set, management pushes a route_policy to the agent (src=consumer peer
-- IP → route-to wg iface, gw=exit peer IP) AND extends the exit peer's
-- AllowedIPs with 0.0.0.0/0 so WG cryptokey routing accepts the
-- diverted packets. Linux client picks up `role: exit_node` from
-- /api/connect and enables ip_forward + iptables MASQUERADE.

ALTER TABLE device_profiles
  ADD COLUMN IF NOT EXISTS can_be_exit_node BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS exit_node_device_id TEXT NULL
    REFERENCES devices(id) ON DELETE SET NULL;

-- Block self-reference at the DB level — sync code also validates but
-- belt-and-braces avoids accidental infinite-loop configs.
DO $$ BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_devices_exit_node_not_self'
  ) THEN
    ALTER TABLE devices
      ADD CONSTRAINT chk_devices_exit_node_not_self
      CHECK (exit_node_device_id IS NULL OR exit_node_device_id <> id);
  END IF;
END $$;

-- Partial index: lets the resync chain quickly find consumers when an
-- exit node connects/disconnects (small set in practice).
CREATE INDEX IF NOT EXISTS idx_devices_exit_node_device_id
  ON devices(exit_node_device_id) WHERE exit_node_device_id IS NOT NULL;
