-- Re-scope application_servers from per-enterprise → per-VPN-server.
-- Each Application Server's IP only makes sense within a specific VPN
-- server's subnet, so the natural parent is `servers` not `enterprises`.
-- Admin UI moves from a top-level "Apps" tab to a section under each
-- server's detail page (alongside Firewall / NAT / Port-forwards).
--
-- ACL pivot tables persist their schema; just re-create them so FKs
-- point to the rebuilt parent. No data preserved (staging only had
-- test rows that we already cleaned up).
DROP TABLE IF EXISTS application_server_groups;
DROP TABLE IF EXISTS application_server_users;
DROP TABLE IF EXISTS application_servers;

CREATE TABLE application_servers (
  id          SERIAL PRIMARY KEY,
  server_id   INT  NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT,
  ip          INET NOT NULL,
  port        INT  NOT NULL CHECK (port BETWEEN 1 AND 65535),
  local_port  INT  NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (server_id, name),
  UNIQUE (server_id, local_port)
);
CREATE INDEX idx_appsrv_server ON application_servers (server_id);

CREATE TABLE application_server_users (
  app_id     INT  NOT NULL REFERENCES application_servers(id) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (app_id, user_id)
);
CREATE INDEX idx_appsrv_users_user ON application_server_users (user_id);

CREATE TABLE application_server_groups (
  app_id        INT  NOT NULL REFERENCES application_servers(id) ON DELETE CASCADE,
  user_group_id TEXT NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (app_id, user_group_id)
);
CREATE INDEX idx_appsrv_groups_group ON application_server_groups (user_group_id);
