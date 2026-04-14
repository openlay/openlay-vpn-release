CREATE TABLE IF NOT EXISTS servers (
  id            SERIAL PRIMARY KEY,
  name          VARCHAR(255) NOT NULL,
  url           TEXT NOT NULL,
  api_token     TEXT NOT NULL,
  description   TEXT DEFAULT '',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS subnets (
  id              SERIAL PRIMARY KEY,
  server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  interface_name  VARCHAR(63) NOT NULL,
  cidr            VARCHAR(43) NOT NULL,
  name            VARCHAR(255) NOT NULL DEFAULT '',
  description     TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (server_id, cidr)
);

CREATE TABLE IF NOT EXISTS peers_meta (
  id              SERIAL PRIMARY KEY,
  server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  interface_name  VARCHAR(63) NOT NULL,
  public_key      TEXT NOT NULL,
  subnet_id       INTEGER REFERENCES subnets(id) ON DELETE SET NULL,
  alias           VARCHAR(255) DEFAULT '',
  notes           TEXT DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (server_id, interface_name, public_key)
);

CREATE INDEX IF NOT EXISTS idx_subnets_server ON subnets(server_id);
CREATE INDEX IF NOT EXISTS idx_peers_meta_server ON peers_meta(server_id);
CREATE INDEX IF NOT EXISTS idx_peers_meta_subnet ON peers_meta(subnet_id);
