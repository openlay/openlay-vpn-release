-- Application Server target now polymorphic.
--
-- Old shape: every app pinned to a literal `ip`. Sparse `local_port` was
-- a vestige of the dropped client-side localhost listener idea (NECP
-- killed it on iOS — see feedback_ios_pte_necp.md). Drop both.
--
-- New shape: `target_type` ∈ {ip, user, device}.
--   - ip     → `ip` column (existing behavior)
--   - user   → `target_user_id`. Resolved at /api/connect time to that
--              user's most-recently-connected device's peer IP (1 user
--              = 1 active device in this product).
--   - device → `target_device_id`. Direct device → peer IP lookup.
-- Resolution failure (offline) → entry surfaces with reachable=false.
--
-- Staging only had test rows; we're not preserving their target shape.
ALTER TABLE application_servers
  DROP CONSTRAINT IF EXISTS application_servers_server_id_local_port_key,
  DROP COLUMN IF EXISTS local_port,
  ALTER COLUMN ip DROP NOT NULL,
  ADD COLUMN target_type      TEXT NOT NULL DEFAULT 'ip'
    CHECK (target_type IN ('ip','user','device')),
  ADD COLUMN target_user_id   TEXT REFERENCES users(id)   ON DELETE CASCADE,
  ADD COLUMN target_device_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
  ADD CONSTRAINT app_target_xor CHECK (
    (target_type='ip'     AND ip IS NOT NULL) OR
    (target_type='user'   AND target_user_id   IS NOT NULL
                          AND ip IS NULL AND target_device_id IS NULL) OR
    (target_type='device' AND target_device_id IS NOT NULL
                          AND ip IS NULL AND target_user_id   IS NULL)
  );

CREATE INDEX IF NOT EXISTS idx_appsrv_target_user   ON application_servers (target_user_id);
CREATE INDEX IF NOT EXISTS idx_appsrv_target_device ON application_servers (target_device_id);
