const { Router } = require('express');
const { pool } = require('../db/pool');
const config = require('../config');
const { syncSubnets } = require('../services/subnetSync');

const router = Router();

// Auth middleware for agent endpoints
function agentAuth(req, res, next) {
  const expectedToken = config.managementApiToken;
  if (!expectedToken) return next();

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.slice(7);
  if (token !== expectedToken) {
    return res.status(403).json({ error: 'Invalid token' });
  }

  next();
}

router.use(agentAuth);

// POST /api/agents/register
router.post('/register', async (req, res) => {
  try {
    const { agentId, name, publicUrl, apiToken, hostname, publicIp, platform, arch, uptime, interfaces } = req.body;

    if (!publicUrl || !apiToken) {
      return res.status(400).json({ error: 'publicUrl and apiToken are required' });
    }

    const serverName = name || hostname || publicIp || 'Unknown Agent';
    const description = [platform, arch, publicIp].filter(Boolean).join(' / ');

    // ------------------------------------------------------------------
    // Lookup order (stable across IP changes):
    //   1. instance_id  — cloud VM/machine fingerprint (survives IP change)
    //   2. url          — legacy fallback for agents without instanceId
    // ------------------------------------------------------------------
    let existing = null;

    if (agentId) {
      const { rows } = await pool.query(
        `SELECT id, url FROM servers WHERE instance_id = $1`,
        [agentId]
      );
      if (rows.length > 0) existing = rows[0];
    }

    if (!existing) {
      const { rows } = await pool.query(
        `SELECT id, url FROM servers WHERE url = $1`,
        [publicUrl]
      );
      if (rows.length > 0) existing = rows[0];
    }

    let server;
    if (existing) {
      const urlChanged = existing.url !== publicUrl;
      // Re-register: preserve admin-set name; update url if IP changed
      const { rows } = await pool.query(
        `UPDATE servers
         SET api_token = $1, description = $2, hostname = $3,
             url = $4, instance_id = COALESCE(NULLIF($5, ''), instance_id),
             public_ip = COALESCE(NULLIF($7, ''), public_ip),
             updated_at = NOW()
         WHERE id = $6
         RETURNING id, name, url, hostname, description, public_ip`,
        [apiToken, description, hostname || '', publicUrl, agentId || '', existing.id, publicIp || '']
      );
      server = rows[0];
      if (urlChanged) {
        console.log(`[agents] Re-registered "${server.name}" (id=${server.id}) — IP changed: ${existing.url} → ${publicUrl}`);
      } else {
        console.log(`[agents] Re-registered "${server.name}" (id=${server.id}, uptime=${uptime}s)`);
      }
    } else {
      const { rows } = await pool.query(
        `INSERT INTO servers (name, url, api_token, description, hostname, instance_id, public_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, name, url, hostname, description, public_ip`,
        [serverName, publicUrl, apiToken, description, hostname || '', agentId || '', publicIp || '']
      );
      server = rows[0];
      console.log(`[agents] New agent registered: "${serverName}" → ${publicUrl} (id=${server.id}, instanceId=${agentId || 'none'})`);
    }

    // Sync subnets from interfaces
    const createdSubnets = await syncSubnets(server.id, interfaces);
    if (createdSubnets.length > 0) {
      console.log(`[agents] Created ${createdSubnets.length} subnet(s): ${createdSubnets.map(s => `${s.cidr} (${s.interface})`).join(', ')}`);
    }

    // Build WebSocket URL for agent to connect
    const wsProtocol = req.protocol === 'https' ? 'wss' : 'ws';
    const wsUrl = `${wsProtocol}://${req.headers.host}/ws/agent`;

    res.status(201).json({
      id: server.id,
      message: `Agent "${server.name}" registered`,
      subnets: createdSubnets,
      wsUrl,
    });
  } catch (err) {
    console.error('[agents] Registration failed:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/agents/heartbeat
router.post('/heartbeat', async (req, res) => {
  try {
    const { agentId, publicUrl, publicIp, interfaces } = req.body;

    if (!publicUrl) {
      return res.status(400).json({ error: 'publicUrl is required' });
    }

    // Same lookup order as register: instance_id → url
    let found = null;

    if (agentId) {
      const { rows } = await pool.query(
        `SELECT id, name, url FROM servers WHERE instance_id = $1`,
        [agentId]
      );
      if (rows.length > 0) found = rows[0];
    }

    if (!found) {
      const { rows } = await pool.query(
        `SELECT id, name, url FROM servers WHERE url = $1`,
        [publicUrl]
      );
      if (rows.length > 0) found = rows[0];
    }

    if (!found) {
      return res.status(404).json({ error: 'Agent not registered' });
    }

    // Update url if IP changed, always bump updated_at
    if (found.url !== publicUrl) {
      console.log(`[agents] Heartbeat: IP changed for "${found.name}" — ${found.url} → ${publicUrl}`);
    }

    await pool.query(
      `UPDATE servers SET url = $1, instance_id = COALESCE(NULLIF($2, ''), instance_id),
       public_ip = COALESCE(NULLIF($4, ''), public_ip), updated_at = NOW() WHERE id = $3`,
      [publicUrl, agentId || '', found.id, publicIp || '']
    );

    // Sync subnets on heartbeat too (pick up new interfaces)
    const createdSubnets = await syncSubnets(found.id, interfaces);
    if (createdSubnets.length > 0) {
      console.log(`[agents] Heartbeat: created ${createdSubnets.length} new subnet(s) for "${found.name}"`);
    }

    res.json({ ok: true, id: found.id, newSubnets: createdSubnets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/agents/deregister
router.post('/deregister', async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }

    const { rows } = await pool.query(
      `SELECT id, name, url FROM servers WHERE name = $1 ORDER BY updated_at DESC LIMIT 1`,
      [name]
    );

    if (rows.length > 0) {
      console.log(`[agents] Agent "${name}" (id=${rows[0].id}) deregistered (shutdown)`);
    }

    res.json({ ok: true, message: `Agent "${name}" deregistered` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
