ALTER TABLE servers DROP CONSTRAINT IF EXISTS servers_access_mode_check;
ALTER TABLE servers ADD CONSTRAINT servers_access_mode_check
  CHECK (access_mode IN ('public', 'private', 'private_free', 'for_sale'));
