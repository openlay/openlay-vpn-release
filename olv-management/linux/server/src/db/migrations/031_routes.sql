-- M1: static routes CRUD. One row per managed route on one server+iface.
-- The fib column is reserved for M2 (policy-based routing via multi-FIB)
-- but stays at 0 in M1 — keeping the column now avoids a second ALTER
-- TABLE when the next milestone lands.
CREATE TABLE IF NOT EXISTS routes (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  iface VARCHAR(32) NOT NULL,
  destination CIDR NOT NULL,
  gateway INET,
  metric INT NOT NULL DEFAULT 0,
  fib INT NOT NULL DEFAULT 0,
  description TEXT,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  -- One destination can only have one active next-hop per (server, iface, fib).
  -- If you need split routing, use policy rules in M2 — not duplicate rows.
  UNIQUE(server_id, iface, destination, fib)
);

CREATE INDEX IF NOT EXISTS idx_routes_server ON routes(server_id);
CREATE INDEX IF NOT EXISTS idx_routes_server_iface ON routes(server_id, iface);
