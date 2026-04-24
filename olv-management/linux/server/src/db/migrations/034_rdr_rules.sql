-- M3: DNAT / port-forward rules. Each row produces a pf `rdr` line
-- plus (by default) a companion `pass in quick` in the same olv-rdr
-- anchor so the DNAT'd traffic isn't blocked by the default filter
-- policy. The companion rule is colocated — deleting the row removes
-- both.
CREATE TABLE IF NOT EXISTS rdr_rules (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  wan_iface VARCHAR(32) NOT NULL,
  external_ip INET,                          -- NULL = any on wan
  external_port_start INT NOT NULL,
  external_port_end INT,                     -- NULL = single port
  protocol VARCHAR(8) NOT NULL,              -- tcp | udp | both
  internal_ip INET NOT NULL,
  internal_port_start INT NOT NULL,
  internal_port_end INT,                     -- NULL = single port OR auto-map
  auto_open_firewall BOOLEAN NOT NULL DEFAULT TRUE,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_rdr_server ON rdr_rules(server_id);
CREATE INDEX IF NOT EXISTS idx_rdr_extport ON rdr_rules(server_id, wan_iface, external_port_start);
