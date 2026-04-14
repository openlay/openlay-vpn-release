-- Stable identity for agents that may change public IP (e.g. cloud VMs with dynamic IP).
-- instance_id is populated from cloud metadata (AWS/GCP/Azure/DO) or machine fingerprint.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS instance_id VARCHAR(255) DEFAULT '';

-- Partial unique index: only enforce uniqueness when instance_id is non-empty.
CREATE UNIQUE INDEX IF NOT EXISTS servers_instance_id_uq
  ON servers (instance_id)
  WHERE instance_id != '';
