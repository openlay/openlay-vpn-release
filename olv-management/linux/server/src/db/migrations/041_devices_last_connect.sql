-- Track the last successful /api/connect for each device so the admin UI
-- can show a "last seen" timestamp without joining peer state from agents.
-- Stamped from app-api after the peer row is upserted.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_connect_at TIMESTAMPTZ;
