-- Extend enrollment_requests.os AND devices.os to allow 'linux' so the Linux
-- VPN client (olv-client/linux-client/) can enroll through POST /api/enroll
-- and survive the admin approve step (which INSERTs a devices row).
--
-- Applies on top of 036_device_enroll.sql which defined the original CHECK
-- constraints with (macos, ios, windows, android).

ALTER TABLE enrollment_requests DROP CONSTRAINT IF EXISTS enrollment_requests_os_check;
ALTER TABLE enrollment_requests ADD CONSTRAINT enrollment_requests_os_check
  CHECK (os IN ('macos', 'ios', 'windows', 'android', 'linux'));

ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_os_check;
ALTER TABLE devices ADD CONSTRAINT devices_os_check
  CHECK (os IN ('macos', 'ios', 'windows', 'android', 'linux'));
