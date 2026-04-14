-- Expand access_mode to support 3 types
ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_access_mode_check;
ALTER TABLE servers ADD CONSTRAINT servers_access_mode_check
  CHECK (access_mode IN ('public', 'private', 'private_free'));

-- Servers without enterprise_id that are private → mark as private_free
UPDATE servers SET access_mode = 'private_free'
  WHERE access_mode = 'private' AND enterprise_id IS NULL;
