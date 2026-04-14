-- Allow users without Apple ID (password-based admin accounts)
ALTER TABLE users ALTER COLUMN apple_id DROP NOT NULL;

-- Add password hash column for admin accounts
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

-- Add auth_type to distinguish login methods
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_type VARCHAR(20) NOT NULL DEFAULT 'apple'
  CHECK (auth_type IN ('apple', 'password'));

-- Username for password-based login (unique, optional)
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE username IS NOT NULL;
