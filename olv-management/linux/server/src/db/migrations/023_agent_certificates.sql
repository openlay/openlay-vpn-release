-- Track issued agent certificates (for revocation + audit)
CREATE TABLE IF NOT EXISTS agent_certificates (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  server_id       INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  agent_id        TEXT NOT NULL,         -- e.g. aws-i-xxxxx
  serial_number   TEXT UNIQUE NOT NULL,
  fingerprint     TEXT UNIQUE NOT NULL,  -- SHA256 of DER cert
  issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked         BOOLEAN NOT NULL DEFAULT FALSE,
  revoked_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agent_certs_server ON agent_certificates(server_id);
CREATE INDEX IF NOT EXISTS idx_agent_certs_agent_id ON agent_certificates(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_certs_fingerprint ON agent_certificates(fingerprint);
