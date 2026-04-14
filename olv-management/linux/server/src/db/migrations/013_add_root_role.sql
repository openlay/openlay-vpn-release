-- Expand role check to include 'root'
ALTER TABLE user_enterprise_roles DROP CONSTRAINT IF EXISTS user_enterprise_roles_role_check;
ALTER TABLE user_enterprise_roles ADD CONSTRAINT user_enterprise_roles_role_check
  CHECK (role IN ('root', 'super_admin', 'admin', 'member'));

-- System-wide root users (not tied to any enterprise)
CREATE TABLE IF NOT EXISTS root_users (
  user_id   TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
