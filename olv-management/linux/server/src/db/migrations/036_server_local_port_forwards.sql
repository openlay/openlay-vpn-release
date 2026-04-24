-- M6: client-side local port forwards, per-server scope.
--
-- Unlike rdr_rules (M3) which live on the FreeBSD agent and NAT public
-- WAN traffic, these mappings are consumed by VPN client devices. The
-- Packet Tunnel Extension reads them from /api/connect and binds
-- NWListener on 127.0.0.1:<local_port>, proxying to the VPN-internal
-- <remote_host>:<remote_port>.
--
-- No agent involvement. Management owns + pushes via app-api.
CREATE TABLE IF NOT EXISTS server_local_port_forwards (
  id            SERIAL PRIMARY KEY,
  server_id     INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name          TEXT NOT NULL,
  local_port    INT NOT NULL CHECK (local_port BETWEEN 1 AND 65535),
  remote_host   TEXT NOT NULL,
  remote_port   INT NOT NULL CHECK (remote_port BETWEEN 1 AND 65535),
  description   TEXT,
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- One client cannot double-bind the same loopback port — two
  -- mappings on the same server with the same local_port would
  -- collide on any device that connects to this server.
  UNIQUE (server_id, local_port)
);

-- Partial index: app-api hot path is "enabled mappings for this server".
CREATE INDEX IF NOT EXISTS idx_slpf_server_enabled
  ON server_local_port_forwards (server_id) WHERE enabled = TRUE;
