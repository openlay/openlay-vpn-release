-- Device enroll flow: user enters a short numeric code on the client,
-- request lands in enrollment_requests, admin approves in admin app and
-- chooses an enterprise — server auto-creates a user + device in one
-- transaction. Subsequent logins use Secure Enclave signature.

-- Expand users.auth_type to allow 'enroll'
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_auth_type_check;
ALTER TABLE users ADD CONSTRAINT users_auth_type_check
  CHECK (auth_type IN ('apple', 'password', 'enroll'));

-- Expand devices.enrollment_method to allow 'enroll_code'
ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_enrollment_method_check;
ALTER TABLE devices ADD CONSTRAINT devices_enrollment_method_check
  CHECK (enrollment_method IN ('auto', 'manual', 'qr', 'enroll_code'));

-- Pending enroll requests, unassociated with any user/enterprise until admin
-- approves and picks an enterprise. enterprise_id stays NULL while pending;
-- gets filled on approve.
CREATE TABLE IF NOT EXISTS enrollment_requests (
  id                  TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  enterprise_id       TEXT REFERENCES enterprises(id) ON DELETE SET NULL,
  device_name         VARCHAR(255) NOT NULL,
  hardware_id         TEXT NOT NULL,
  os                  VARCHAR(20) NOT NULL
                      CHECK (os IN ('macos', 'ios', 'windows', 'android')),
  os_version          VARCHAR(50) NOT NULL DEFAULT '',
  public_key          TEXT NOT NULL,
  status              VARCHAR(20) NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending', 'approved', 'rejected')),
  approved_device_id  TEXT REFERENCES devices(id) ON DELETE SET NULL,
  approved_user_id    TEXT REFERENCES users(id)   ON DELETE SET NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enroll_req_status_created
  ON enrollment_requests(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_enroll_req_hwid
  ON enrollment_requests(hardware_id);

-- Global enroll code + expiry (rotated lazily on read). Seed empty/past so
-- the first GET triggers a fresh rotation.
INSERT INTO app_settings (key, value, description) VALUES
  ('enrollment_code_value', '',
   'Current global 10-digit enroll code. Rotates hourly on read.'),
  ('enrollment_code_expires_at', '1970-01-01T00:00:00Z',
   'ISO timestamp when enrollment_code_value expires.')
ON CONFLICT (key) DO NOTHING;

-- Replay protection for POST /api/auth/device
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_auth_challenge TEXT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_auth_at        TIMESTAMPTZ;
