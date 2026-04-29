-- Tighten app_target_xor: original constraint forgot to assert that
-- target_user_id and target_device_id are NULL when target_type='ip',
-- so an INSERT with target_type='ip' could simultaneously set
-- target_user_id (mixing intent silently). Replace with a fully
-- exclusive check.
DELETE FROM application_servers
  WHERE target_type='ip'
    AND (target_user_id IS NOT NULL OR target_device_id IS NOT NULL);

ALTER TABLE application_servers
  DROP CONSTRAINT IF EXISTS app_target_xor,
  ADD CONSTRAINT app_target_xor CHECK (
    (target_type='ip'     AND ip IS NOT NULL
                          AND target_user_id IS NULL AND target_device_id IS NULL) OR
    (target_type='user'   AND target_user_id   IS NOT NULL
                          AND ip IS NULL AND target_device_id IS NULL) OR
    (target_type='device' AND target_device_id IS NOT NULL
                          AND ip IS NULL AND target_user_id   IS NULL)
  );
