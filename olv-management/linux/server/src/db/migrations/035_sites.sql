-- M4: site-to-site gateway. A "site" is a higher-level object that
-- glues together the primitives from M1/M2/M3: a WireGuard peer's
-- AllowedIPs, a static route to the remote LAN, optional SNAT on the
-- local LAN, optional policy-based routing by FIB, and firewall pass
-- rules for the cross-LAN flow.
--
-- The orchestrator (services/siteOrchestrator.js) owns translation:
-- on CREATE it calls M1/M2/M3 agent APIs and records each artifact
-- here. On DELETE it walks artifacts backwards and undoes each one.
-- This keeps the site row the single pointer for an operator to
-- "tear it all down" even months later.
CREATE TABLE IF NOT EXISTS sites (
  id SERIAL PRIMARY KEY,
  server_id INT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  local_iface VARCHAR(32) NOT NULL,        -- WG iface the remote peer is on
  local_subnet CIDR,                       -- LAN behind THIS server (optional)
  remote_peer_pubkey TEXT,                 -- WireGuard pubkey of the remote peer; optional
  remote_subnet CIDR NOT NULL,             -- LAN behind the remote
  remote_gateway INET,                     -- usually the peer's VPN-side IP
  enable_nat BOOLEAN NOT NULL DEFAULT FALSE,
  policy_fib INT,                          -- optional FIB pin via M2 policy routing
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(server_id, name)
);

CREATE INDEX IF NOT EXISTS idx_sites_server ON sites(server_id);

-- Every agent-side artifact created by orchestrator.create() lands
-- here with its type + agent-side id. The site's DELETE reverses the
-- artifacts in reverse order. If the agent is offline at delete time
-- we still clean up the DB rows; RestoreAll / RestorePolicies on next
-- agent boot converge the kernel.
CREATE TABLE IF NOT EXISTS site_artifacts (
  id SERIAL PRIMARY KEY,
  site_id INT NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  artifact_type VARCHAR(32) NOT NULL,
    -- 'peer-allowed-ips-added'  — appended remote_subnet to peer's allowedIPs
    -- 'route'                   — static route (M1)
    -- 'nat'                     — SNAT rule (M3)
    -- 'policy'                  — policy-based routing rule (M2)
  artifact_ref TEXT NOT NULL,
    -- agent-side id (rt-..., nat-..., pol-...) or, for peer-allowed-ips-added,
    -- the CIDR that was appended (so we know what to remove on rollback).
  details JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sa_site ON site_artifacts(site_id);
