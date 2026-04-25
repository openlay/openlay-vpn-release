-- Migration: enrollment code per-enterprise instead of global.
--
-- Was: enrollment_code_value + enrollment_code_expires_at lived in
-- app_settings (server-wide singletons). One code shared across every
-- enterprise hosted on the management server.
--
-- Now: same two keys live in enterprise_settings keyed by (enterprise_id,
-- key) so each enterprise rotates its own code independently. UI in iOS
-- admin shows the code of whatever enterprise is currently active.
--
-- Cleanup: drop the leftover global rows so the new code path doesn't see
-- stale data. New rows are created lazily on first GET per enterprise.

DELETE FROM app_settings
 WHERE key IN ('enrollment_code_value', 'enrollment_code_expires_at');
