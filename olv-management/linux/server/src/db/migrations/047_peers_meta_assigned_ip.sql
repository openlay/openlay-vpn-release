-- Cache the peer's allocated VPN IP in management DB so the new
-- typed-target / typed-ingress resolvers (app servers + route
-- policies) don't need a roundtrip to the agent every lookup.
--
-- Source of truth stays the agent — peers_meta.assigned_ip is just a
-- cache populated on /api/connect insert. Existing rows backfill via
-- next reconnect; until then resolver treats them as "offline".
ALTER TABLE peers_meta
  ADD COLUMN IF NOT EXISTS assigned_ip INET;

CREATE INDEX IF NOT EXISTS idx_peers_meta_user_iface
  ON peers_meta (user_id, interface_name)
  WHERE assigned_ip IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_peers_meta_device
  ON peers_meta (device_id)
  WHERE assigned_ip IS NOT NULL;
