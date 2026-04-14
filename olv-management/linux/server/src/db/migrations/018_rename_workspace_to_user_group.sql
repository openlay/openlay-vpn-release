-- Rename workspaces -> user_groups
ALTER TABLE IF EXISTS workspaces RENAME TO user_groups;
ALTER TABLE IF EXISTS workspace_servers RENAME TO user_group_servers;
ALTER TABLE IF EXISTS workspace_members RENAME TO user_group_members;

-- Rename columns (safe if already renamed)
DO $$ BEGIN
  ALTER TABLE user_group_servers RENAME COLUMN workspace_id TO user_group_id;
EXCEPTION WHEN undefined_column THEN NULL;
END $$;

DO $$ BEGIN
  ALTER TABLE user_group_members RENAME COLUMN workspace_id TO user_group_id;
EXCEPTION WHEN undefined_column THEN NULL;
END $$;

-- Rename indexes (ignore if not found)
ALTER INDEX IF EXISTS idx_workspaces_enterprise RENAME TO idx_user_groups_enterprise;
ALTER INDEX IF EXISTS idx_ws_workspace RENAME TO idx_ugs_user_group;
ALTER INDEX IF EXISTS idx_ws_server RENAME TO idx_ugs_server;
ALTER INDEX IF EXISTS idx_wm_workspace RENAME TO idx_ugm_user_group;
ALTER INDEX IF EXISTS idx_wm_user RENAME TO idx_ugm_user;
