-- Track WHICH App Attest environment the attestation came from.
-- Apple's verifyAttestation result includes `environment: "production" | "development"`
-- (derived from the aaguid in authData). Storing it lets us reject debug-build
-- devices on prod even if APP_ATTEST_PRODUCTION was flipped after attest.
ALTER TABLE device_attestations
  ADD COLUMN IF NOT EXISTS environment TEXT,        -- 'production' | 'development' | NULL (legacy)
  ADD COLUMN IF NOT EXISTS bundle_id   TEXT;

-- Pending attestation captured at enrollment time. Copied into
-- device_attestations on admin approve. We can't write into device_attestations
-- directly because the device row doesn't exist yet.
ALTER TABLE enrollment_requests
  ADD COLUMN IF NOT EXISTS attest_key_id      TEXT,
  ADD COLUMN IF NOT EXISTS attest_public_key  BYTEA,
  ADD COLUMN IF NOT EXISTS attest_environment TEXT,
  ADD COLUMN IF NOT EXISTS attest_bundle_id   TEXT,
  ADD COLUMN IF NOT EXISTS attest_receipt     BYTEA;

-- /api/enroll/challenge and /api/auth/apple's pre-auth challenge endpoint
-- both need to persist a challenge BEFORE any user exists (the device is
-- mid-enroll, or the user is mid-Apple-Sign-In). Drop the NOT NULL on
-- user_id so we can store a NULL row keyed by challenge alone.
ALTER TABLE attest_challenges ALTER COLUMN user_id DROP NOT NULL;
