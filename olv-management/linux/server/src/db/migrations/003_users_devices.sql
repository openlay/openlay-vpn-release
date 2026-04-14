-- Users registered via Apple ID
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  email         VARCHAR(255),
  name          VARCHAR(255),
  apple_id      VARCHAR(255) NOT NULL UNIQUE,
  status        VARCHAR(20) NOT NULL DEFAULT 'enabled'
                CHECK (status IN ('enabled', 'disabled')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_apple_id ON users(apple_id);

-- Devices identified by Secure Enclave / TPM public key
CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name          VARCHAR(255) NOT NULL DEFAULT '',
  os            VARCHAR(20) NOT NULL
                CHECK (os IN ('macos', 'ios', 'windows', 'android')),
  os_version    VARCHAR(50) NOT NULL DEFAULT '',
  public_key    TEXT NOT NULL,
  status        VARCHAR(20) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'enabled', 'disabled')),
  user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_public_key ON devices(public_key);

-- Assign specific servers to users (dashboard manages this)
CREATE TABLE IF NOT EXISTS user_server_assignments (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  interface_name  VARCHAR(50) NOT NULL,
  subnet_id       INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, server_id, interface_name)
);

CREATE INDEX IF NOT EXISTS idx_user_server_assignments_user_id ON user_server_assignments(user_id);

-- Link peers back to app users/devices
ALTER TABLE peers_meta ADD COLUMN IF NOT EXISTS device_id TEXT REFERENCES devices(id) ON DELETE SET NULL;
ALTER TABLE peers_meta ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(id) ON DELETE SET NULL;
