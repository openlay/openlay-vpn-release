-- M2: policy-based routing rules. Each row becomes a pf `pass quick ...
-- route-to (...)` line in the olv-policy anchor. Priority controls
-- ordering (lower = earlier; first match wins in pf).
CREATE TABLE IF NOT EXISTS route_policies (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  priority INT NOT NULL DEFAULT 100,
  ingress_iface VARCHAR(32),                 -- nullable = any
  src_cidr CIDR,
  dst_cidr CIDR,
  protocol VARCHAR(8),                        -- tcp | udp | icmp | NULL
  dst_port_start INT,
  dst_port_end INT,
  fib INT NOT NULL DEFAULT 0,                 -- target routing table
  action VARCHAR(16) NOT NULL DEFAULT 'route-to', -- route-to | reply-to | dup-to
  gateway INET,
  gateway_iface VARCHAR(32) NOT NULL,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  -- Name is the user-facing handle; collisions within a server are
  -- confusing. Priority can repeat (tie-break by created_at in the
  -- renderer).
  UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_rp_server ON route_policies(server_id);
CREATE INDEX IF NOT EXISTS idx_rp_prio ON route_policies(server_id, priority);
