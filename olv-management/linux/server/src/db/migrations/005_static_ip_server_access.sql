-- Device static IP assignments per server/subnet
CREATE TABLE IF NOT EXISTS device_static_ips (
  id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  device_id       TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  subnet_id       INTEGER NOT NULL REFERENCES subnets(id) ON DELETE CASCADE,
  ip_address      VARCHAR(45) NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- One static IP per device per server+subnet
  UNIQUE (device_id, server_id, subnet_id),
  -- No two devices can have the same IP in the same subnet
  UNIQUE (server_id, subnet_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_device_static_ips_device ON device_static_ips(device_id);
CREATE INDEX IF NOT EXISTS idx_device_static_ips_subnet ON device_static_ips(server_id, subnet_id);

-- Server access mode: public (anyone) or private (assigned users only)
ALTER TABLE servers ADD COLUMN IF NOT EXISTS access_mode VARCHAR(20) NOT NULL DEFAULT 'public'
  CHECK (access_mode IN ('public', 'private'));
