CREATE TABLE IF NOT EXISTS firewall_zones (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  builtin BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(server_id, name)
);

CREATE TABLE IF NOT EXISTS firewall_zone_members (
  id SERIAL PRIMARY KEY,
  zone_id INT NOT NULL REFERENCES firewall_zones(id) ON DELETE CASCADE,
  member_type VARCHAR(20) NOT NULL CHECK (member_type IN ('ip', 'subnet', 'user', 'interface')),
  member_value TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fz_server ON firewall_zones(server_id);
CREATE INDEX IF NOT EXISTS idx_fzm_zone ON firewall_zone_members(zone_id);
