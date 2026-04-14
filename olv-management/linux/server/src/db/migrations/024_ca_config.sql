-- Internal CA configuration (keypair + serial counter)
CREATE TABLE IF NOT EXISTS ca_config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
