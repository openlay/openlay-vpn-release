CREATE TABLE IF NOT EXISTS firewall_aliases (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  addresses TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_fa_server ON firewall_aliases(server_id);
