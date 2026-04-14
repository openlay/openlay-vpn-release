-- Add pending status for servers (agent enrolls as pending, admin approves)
ALTER TABLE servers ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending'
  CHECK (status IN ('pending', 'active', 'disabled'));

-- Existing servers default to active
UPDATE servers SET status = 'active' WHERE status = 'pending';
