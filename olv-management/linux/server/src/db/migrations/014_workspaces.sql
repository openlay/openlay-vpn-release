-- Workspaces: groups within an enterprise
CREATE TABLE IF NOT EXISTS workspaces (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id   TEXT NOT NULL REFERENCES enterprises(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  description     TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_workspaces_enterprise ON workspaces(enterprise_id);

-- Many-to-many: workspace <-> server
CREATE TABLE IF NOT EXISTS workspace_servers (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  workspace_id    TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(workspace_id, server_id)
);

CREATE INDEX IF NOT EXISTS idx_ws_workspace ON workspace_servers(workspace_id);
CREATE INDEX IF NOT EXISTS idx_ws_server ON workspace_servers(server_id);

-- Workspace membership with role (admin or member)
CREATE TABLE IF NOT EXISTS workspace_members (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  workspace_id    TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role            TEXT NOT NULL DEFAULT 'member'
                  CHECK (role IN ('admin', 'member')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_wm_workspace ON workspace_members(workspace_id);
CREATE INDEX IF NOT EXISTS idx_wm_user ON workspace_members(user_id);
