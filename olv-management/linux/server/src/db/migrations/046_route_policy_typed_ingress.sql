-- Route Policy ingress (M2) becomes typed reference instead of free
-- text CIDR. Same logical-rule pattern firewall uses: admin picks a
-- user / group / device, management resolves to current peer IP set at
-- agent-push time, re-resolves on peer change.
--
-- ingress_type ∈ {custom, users, group, device}
--   - custom → existing (ingress_iface, src_cidr) free text
--   - users  → pivot route_policy_users (1+ user_ids). 1-user variant
--              and N-user variant share schema; UI renders single vs
--              multi picker based on a flag, but DB only knows "users".
--   - group  → ingress_group_id (FK user_groups)
--   - device → ingress_device_id (FK devices)
--
-- For non-custom types, ingress_iface is auto-derived from the resolved
-- peer's interface_name (peers_meta) at agent-push time, so admin
-- doesn't pick iface manually. src_cidr likewise computed.
ALTER TABLE route_policies
  ADD COLUMN ingress_type      TEXT NOT NULL DEFAULT 'custom'
    CHECK (ingress_type IN ('custom','users','group','device')),
  ADD COLUMN ingress_group_id  TEXT REFERENCES user_groups(id) ON DELETE CASCADE,
  ADD COLUMN ingress_device_id TEXT REFERENCES devices(id)     ON DELETE CASCADE,
  ADD CONSTRAINT policy_ingress_xor CHECK (
    (ingress_type='custom'  AND ingress_group_id IS NULL AND ingress_device_id IS NULL) OR
    (ingress_type='users'   AND ingress_group_id IS NULL AND ingress_device_id IS NULL) OR
    (ingress_type='group'   AND ingress_group_id  IS NOT NULL AND ingress_device_id IS NULL) OR
    (ingress_type='device'  AND ingress_device_id IS NOT NULL AND ingress_group_id  IS NULL)
  );

CREATE TABLE route_policy_users (
  policy_id INT  NOT NULL REFERENCES route_policies(id) ON DELETE CASCADE,
  user_id   TEXT NOT NULL REFERENCES users(id)          ON DELETE CASCADE,
  PRIMARY KEY (policy_id, user_id)
);
CREATE INDEX idx_route_policy_users_user ON route_policy_users (user_id);
