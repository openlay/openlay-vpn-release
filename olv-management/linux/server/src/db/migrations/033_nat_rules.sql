-- M3: SNAT rules. One row per rewrite: packets from src_cidr leaving
-- via wan_iface get their source translated. Per-server scope because
-- WAN iface names are host-specific.
CREATE TABLE IF NOT EXISTS nat_rules (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  wan_iface VARCHAR(32) NOT NULL,
  src_cidr CIDR NOT NULL,
  nat_to INET,                           -- NULL = dynamic (iface primary addr)
  protocol VARCHAR(8),                   -- tcp | udp | NULL (any)
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_nat_server ON nat_rules(server_id);

-- Server-level default WAN iface so M4 site-to-site orchestrator can
-- auto-pick the egress without the caller spelling it out every time.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS default_wan_iface VARCHAR(32);
