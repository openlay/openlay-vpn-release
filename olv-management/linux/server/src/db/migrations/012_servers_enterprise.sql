-- Link servers to enterprises for multi-tenant scoping
ALTER TABLE servers ADD COLUMN IF NOT EXISTS enterprise_id TEXT REFERENCES enterprises(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_servers_enterprise_id ON servers(enterprise_id);
