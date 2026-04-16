const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');
const jwtAuth = require('../middleware/jwtAuth');

const router = Router();

// --- Routes that only need JWT (no enterprise context) ---

// GET /api/servers/available — List private_free servers (global, just needs auth)
router.get('/available', jwtAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, name, hostname, description, access_mode, created_at
       FROM servers
       WHERE access_mode = 'private_free' AND enterprise_id IS NULL
       ORDER BY name`
    );
    res.json({ servers: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Routes that need enterprise context ---
router.use(enterpriseContext);

// GET /api/servers — root sees all (including pending), others see active only
router.get('/', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const { rows } = isRoot
      ? await pool.query(
          `SELECT s.id, s.name, s.url, s.hostname, s.description, s.access_mode, s.enterprise_id, s.status, s.created_at, s.updated_at,
                  e.name as enterprise_name
           FROM servers s
           LEFT JOIN enterprises e ON s.enterprise_id = e.id
           ORDER BY s.id`)
      : await pool.query(
          `SELECT s.id, s.name, s.url, s.hostname, s.description, s.access_mode, s.enterprise_id, s.status, s.created_at, s.updated_at,
                  e.name as enterprise_name
           FROM servers s
           LEFT JOIN enterprises e ON s.enterprise_id = e.id
           WHERE s.status = 'active' AND (s.enterprise_id = $1 OR s.access_mode = 'public')
           ORDER BY s.id`,
          [req.enterpriseId]
        );
    res.json({ servers: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/subscribe — Claim a private_free server for enterprise (limit 1 per enterprise)
router.post('/subscribe', async (req, res) => {
  try {
    if (!['root', 'super_admin'].includes(req.enterpriseRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }

    const serverId = req.body.serverId || req.body.server_id;
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });

    // Check enterprise limit: max 1 private server per enterprise (free tier)
    const existingCount = await pool.query(
      `SELECT COUNT(*) as count FROM servers WHERE enterprise_id = $1 AND access_mode = 'private'`,
      [req.enterpriseId]
    );
    if (parseInt(existingCount.rows[0].count) >= 1 && req.enterpriseRole !== 'root') {
      return res.status(400).json({ error: 'Free tier limit: 1 private server per enterprise. Contact us to upgrade.' });
    }

    // Verify server is available (private_free + no enterprise)
    const server = await pool.query(
      `SELECT id, name FROM servers WHERE id = $1 AND access_mode = 'private_free' AND enterprise_id IS NULL`,
      [serverId]
    );
    if (server.rows.length === 0) {
      return res.status(404).json({ error: 'Server not available or already claimed' });
    }

    // Claim: set enterprise_id + change mode to private
    await pool.query(
      `UPDATE servers SET enterprise_id = $1, access_mode = 'private', updated_at = NOW() WHERE id = $2`,
      [req.enterpriseId, serverId]
    );

    res.json({ ok: true, message: `Server "${server.rows[0].name}" is now assigned to your enterprise.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/assign — Root only: assign any server to any enterprise
router.post('/assign', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }

    const serverId = req.body.serverId || req.body.server_id;
    const targetEnterpriseId = req.body.enterpriseId || req.body.enterprise_id;
    const accessMode = req.body.accessMode || req.body.access_mode || 'private';
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });
    if (!targetEnterpriseId) return res.status(400).json({ error: 'enterpriseId is required' });

    // Verify server exists
    const server = await pool.query('SELECT id, name FROM servers WHERE id = $1', [serverId]);
    if (server.rows.length === 0) return res.status(404).json({ error: 'Server not found' });

    // Verify enterprise exists
    const ent = await pool.query('SELECT id, name FROM enterprises WHERE id = $1', [targetEnterpriseId]);
    if (ent.rows.length === 0) return res.status(404).json({ error: 'Enterprise not found' });

    await pool.query(
      `UPDATE servers SET enterprise_id = $1, access_mode = $2, updated_at = NOW() WHERE id = $3`,
      [targetEnterpriseId, accessMode, serverId]
    );

    res.json({
      ok: true,
      message: `Server "${server.rows[0].name}" assigned to "${ent.rows[0].name}" as ${accessMode}.`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/unassign — Root only: remove server from enterprise
router.post('/unassign', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }

    const serverId = req.body.serverId || req.body.server_id;
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });

    const server = await pool.query('SELECT id, name FROM servers WHERE id = $1', [serverId]);
    if (server.rows.length === 0) return res.status(404).json({ error: 'Server not found' });

    await pool.query(
      `UPDATE servers SET enterprise_id = NULL, access_mode = 'private_free', updated_at = NOW() WHERE id = $1`,
      [serverId]
    );

    res.json({ ok: true, message: `Server "${server.rows[0].name}" unassigned and set to For Sale.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/approve — Root only: approve pending server + set access mode
router.post('/approve', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }

    const serverId = req.body.serverId || req.body.server_id;
    const accessMode = req.body.accessMode || req.body.access_mode || 'private_free';
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });
    if (!['public', 'private', 'private_free'].includes(accessMode)) {
      return res.status(400).json({ error: 'accessMode must be public, private, or private_free' });
    }

    const server = await pool.query('SELECT id, name, status FROM servers WHERE id = $1', [serverId]);
    if (server.rows.length === 0) return res.status(404).json({ error: 'Server not found' });

    await pool.query(
      `UPDATE servers SET status = 'active', access_mode = $1, updated_at = NOW() WHERE id = $2`,
      [accessMode, serverId]
    );

    res.json({
      ok: true,
      message: `Server "${server.rows[0].name}" approved as ${accessMode}.`,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/reject — Root only: reject/disable pending server
router.post('/reject', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }

    const serverId = req.body.serverId || req.body.server_id;
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });

    const server = await pool.query('SELECT id, name FROM servers WHERE id = $1', [serverId]);
    if (server.rows.length === 0) return res.status(404).json({ error: 'Server not found' });

    await pool.query(
      `UPDATE servers SET status = 'disabled', updated_at = NOW() WHERE id = $1`,
      [serverId]
    );

    res.json({ ok: true, message: `Server "${server.rows[0].name}" rejected.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers — auto-assign to current enterprise
router.post('/', async (req, res) => {
  try {
    if (!['root', 'super_admin'].includes(req.enterpriseRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }
    const { name, url, api_token, description, access_mode } = req.body;
    if (!name || !url || !api_token) {
      return res.status(400).json({ error: 'name, url, and api_token are required' });
    }
    const mode = ['public', 'private', 'private_free', 'for_sale'].includes(access_mode) ? access_mode : 'public';
    const { rows } = await pool.query(
      'INSERT INTO servers (name, url, api_token, description, access_mode, enterprise_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, url, hostname, description, access_mode, created_at, updated_at',
      [name, url, api_token, description || '', mode, req.enterpriseId]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id — own enterprise + public servers (public: limited info for non-root)
router.get('/:id', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const { rows } = isRoot
      ? await pool.query('SELECT id, name, url, hostname, description, access_mode, enterprise_id, created_at, updated_at FROM servers WHERE id = $1', [req.params.id])
      : await pool.query(
          `SELECT id, name, url, hostname, description, access_mode, enterprise_id, created_at, updated_at FROM servers
           WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
          [req.params.id, req.enterpriseId]
        );
    if (rows.length === 0) return res.status(404).json({ error: 'Server not found' });

    const server = rows[0];
    // Public servers: non-root only gets limited info
    if (server.access_mode === 'public' && !isRoot) {
      return res.json({ id: server.id, name: server.name, access_mode: server.access_mode });
    }
    res.json(server);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/servers/:id
router.put('/:id', async (req, res) => {
  try {
    if (!['root', 'super_admin'].includes(req.enterpriseRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }
    const { name, url, api_token, description } = req.body;
    const fields = [];
    const values = [];
    let idx = 1;

    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (url !== undefined) { fields.push(`url = $${idx++}`); values.push(url); }
    if (api_token !== undefined && api_token !== '') { fields.push(`api_token = $${idx++}`); values.push(api_token); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (req.body.access_mode !== undefined) {
      if (!['public', 'private', 'private_free', 'for_sale'].includes(req.body.access_mode)) {
        return res.status(400).json({ error: 'access_mode must be public, private, private_free, or for_sale' });
      }
      fields.push(`access_mode = $${idx++}`);
      values.push(req.body.access_mode);
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    fields.push(`updated_at = NOW()`);
    values.push(req.params.id);

    let query;
    if (req.enterpriseRole === 'root') {
      query = `UPDATE servers SET ${fields.join(', ')} WHERE id = $${idx} RETURNING id, name, url, hostname, description, access_mode, created_at, updated_at`;
    } else {
      values.push(req.enterpriseId);
      query = `UPDATE servers SET ${fields.join(', ')} WHERE id = $${idx} AND enterprise_id = $${idx + 1} RETURNING id, name, url, hostname, description, access_mode, created_at, updated_at`;
    }

    const { rows } = await pool.query(query, values);
    if (rows.length === 0) return res.status(404).json({ error: 'Server not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:id
router.delete('/:id', async (req, res) => {
  try {
    if (!['root', 'super_admin'].includes(req.enterpriseRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }
    const { rowCount } = req.enterpriseRole === 'root'
      ? await pool.query('DELETE FROM servers WHERE id = $1', [req.params.id])
      : await pool.query('DELETE FROM servers WHERE id = $1 AND enterprise_id = $2', [req.params.id, req.enterpriseId]);
    if (rowCount === 0) return res.status(404).json({ error: 'Server not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/health
router.get('/:id/health', async (req, res) => {
  try {
    const { rows } = req.enterpriseRole === 'root'
      ? await pool.query('SELECT url, api_token FROM servers WHERE id = $1', [req.params.id])
      : await pool.query(
          `SELECT url, api_token FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
          [req.params.id, req.enterpriseId]
        );
    if (rows.length === 0) return res.status(404).json({ error: 'Server not found' });
    const client = new AgentClient(parseInt(req.params.id));
    const health = await client.health();
    res.json(health);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/agent-logs?limit=100&type=audit|firewall
router.get('/:id/agent-logs', async (req, res) => {
  if (req.enterpriseRole !== 'root') {
    return res.status(403).json({ error: 'Root access required' });
  }
  try {
    const client = new AgentClient(parseInt(req.params.id));
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const type = req.query.type || 'audit';

    if (type === 'firewall') {
      const result = await client.request('firewallGetLogs', { limit }, 10000);
      res.json({ type: 'firewall', logs: result.logs || [] });
    } else {
      const result = await client.request('getAuditLogs', { limit, offset: 0 }, 10000);
      res.json({ type: 'audit', logs: result.entries || [], total: result.total || 0 });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/system-stats
router.get('/:id/system-stats', async (req, res) => {
  try {
    const client = new AgentClient(parseInt(req.params.id));
    const stats = await client.request('systemStats', {}, 5000);
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/agent-version
router.get('/:id/agent-version', async (req, res) => {
  try {
    const client = new AgentClient(parseInt(req.params.id));
    const health = await client.health();
    res.json({ version: health.version || 'unknown' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/agent-update — root only
router.post('/:id/agent-update', async (req, res) => {
  if (req.enterpriseRole !== 'root') {
    return res.status(403).json({ error: 'Root access required' });
  }
  try {
    const client = new AgentClient(parseInt(req.params.id));
    const result = await client.request('update', {}, 15000);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:id/users — only users in this enterprise
router.get('/:id/users', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT usa.id as assignment_id, usa.interface_name, usa.subnet_id,
        u.id as user_id, u.name as user_name, u.email as user_email, u.status as user_status,
        uer.alias as enterprise_alias,
        sub.cidr as subnet_cidr, sub.name as subnet_name
      FROM user_server_assignments usa
      JOIN users u ON usa.user_id = u.id
      LEFT JOIN user_enterprise_roles uer ON uer.user_id = u.id AND uer.enterprise_id = $2
      LEFT JOIN subnets sub ON usa.subnet_id = sub.id
      WHERE usa.server_id = $1
        AND usa.server_id IN (SELECT id FROM servers WHERE enterprise_id = $2)
      ORDER BY COALESCE(NULLIF(uer.alias, ''), u.name, u.email)
    `, [req.params.id, req.enterpriseId]);
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:id/users — only assign users in same enterprise
router.post('/:id/users', async (req, res) => {
  try {
    const user_id = req.body.user_id || req.body.userId;
    const interface_name = req.body.interface_name || req.body.interfaceName;
    const subnet_id = req.body.subnet_id || req.body.subnetId;
    if (!user_id || !interface_name) {
      return res.status(400).json({ error: 'user_id and interface_name are required' });
    }
    // Verify server belongs to enterprise (root can access any server)
    const sCheck = req.enterpriseRole === 'root'
      ? await pool.query('SELECT 1 FROM servers WHERE id = $1', [req.params.id])
      : await pool.query('SELECT 1 FROM servers WHERE id = $1 AND enterprise_id = $2', [req.params.id, req.enterpriseId]);
    if (sCheck.rows.length === 0) return res.status(404).json({ error: 'Server not found' });
    // Verify user belongs to enterprise
    const uCheck = await pool.query('SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2', [user_id, req.enterpriseId]);
    if (uCheck.rows.length === 0) return res.status(400).json({ error: 'User does not belong to this enterprise' });

    const { rows } = await pool.query(
      `INSERT INTO user_server_assignments (user_id, server_id, interface_name, subnet_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, server_id, interface_name) DO UPDATE SET subnet_id = $4
       RETURNING *`,
      [user_id, req.params.id, interface_name, subnet_id || null]
    );
    res.status(201).json({ assignment: rows[0] });
  } catch (err) {
    if (err.code === '23503') return res.status(404).json({ error: 'User or server not found' });
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:id/users/:assignmentId
router.delete('/:id/users/:assignmentId', async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `DELETE FROM user_server_assignments WHERE id = $1 AND server_id = $2
       AND server_id IN (SELECT id FROM servers WHERE enterprise_id = $3)`,
      [req.params.assignmentId, req.params.id, req.enterpriseId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
