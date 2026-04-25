-- Replace the M6 localhost-bind approach (server_local_port_forwards from
-- 036/037) with a richer Application Server model. The localhost design
-- failed against iOS NECP — the kernel blocks NWConnection from a Packet
-- Tunnel Extension to its own VPN-routed IPs and prevents same-device
-- loopback into a PTE listener. The new model is just an admin registry
-- of (name, ip, port) that users have access to; client-side localhost
-- proxying is dropped entirely.

DROP TABLE IF EXISTS server_local_port_forward_groups;
DROP TABLE IF EXISTS server_local_port_forward_users;
DROP TABLE IF EXISTS server_local_port_forwards;

-- Application Server: enterprise-scoped registry of an IP:port that
-- some users/groups are entitled to access. NULL enterprise_id = root
-- can declare globally-shared apps.
CREATE TABLE IF NOT EXISTS application_servers (
  id            SERIAL PRIMARY KEY,
  enterprise_id TEXT REFERENCES enterprises(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  description   TEXT,
  ip            INET NOT NULL,
  port          INT  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  local_port    INT  NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Within an enterprise, name is the human handle (must be unique) and
  -- local_port is the suggested client-side bookmark port (also unique
  -- so two apps don't suggest the same loopback port).
  UNIQUE (enterprise_id, name),
  UNIQUE (enterprise_id, local_port)
);
CREATE INDEX IF NOT EXISTS idx_appsrv_enterprise ON application_servers (enterprise_id);

-- Default-deny ACL. A user sees an Application Server only when they're
-- listed explicitly OR they belong to a granted user_group.
CREATE TABLE IF NOT EXISTS application_server_users (
  app_id     INT  NOT NULL REFERENCES application_servers(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (app_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_appsrv_users_user ON application_server_users (user_id);

CREATE TABLE IF NOT EXISTS application_server_groups (
  app_id        INT  NOT NULL REFERENCES application_servers(id) ON DELETE CASCADE,
  user_group_id TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (app_id, user_group_id)
);
CREATE INDEX IF NOT EXISTS idx_appsrv_groups_group ON application_server_groups (user_group_id);
