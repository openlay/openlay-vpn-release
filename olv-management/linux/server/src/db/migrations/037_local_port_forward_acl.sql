-- M6.1 — per-mapping ACL for client-side local port forwards.
--
-- Default visibility stays 'all' so mappings created under migration
-- 036 (pre-ACL) keep working without manual intervention.
ALTER TABLE server_local_port_forwards
  ADD COLUMN IF NOT EXISTS visibility TEXT
    NOT NULL DEFAULT 'all'
    CHECK (visibility IN ('all', 'users', 'groups'));

-- Per-user grants. Composite PK prevents dup rows for the same user.
CREATE TABLE IF NOT EXISTS server_local_port_forward_users (
  port_forward_id INT  NOT NULL REFERENCES server_local_port_forwards(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (port_forward_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_slpfu_user ON server_local_port_forward_users (user_id);

-- Per-group grants. Groups are enterprise-scoped (user_groups table).
CREATE TABLE IF NOT EXISTS server_local_port_forward_groups (
  port_forward_id INT  NOT NULL REFERENCES server_local_port_forwards(id) ON DELETE CASCADE,
  user_group_id   TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (port_forward_id, user_group_id)
);
CREATE INDEX IF NOT EXISTS idx_slpfg_group ON server_local_port_forward_groups (user_group_id);
