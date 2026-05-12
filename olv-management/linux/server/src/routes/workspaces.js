const express = require('express');
const { sendError } = require('../middleware/errorHandler');
const router = express.Router({ mergeParams: true });
const pool = require('../db/pool').pool;
const jwtAuth = require('../middleware/jwtAuth');

router.use(jwtAuth);

// ── helpers ──────────────────────────────────────────────────────────
async function requireEnterpriseRole(userId, enterpriseId, roles) {
  const r = await pool.query(
    `SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2`,
    [userId, enterpriseId]
  );
  if (r.rows.length === 0) return null;
  if (roles && !roles.includes(r.rows[0].role)) return null;
  return r.rows[0].role;
}

async function getWorkspaceEnterprise(workspaceId) {
  const r = await pool.query('SELECT enterprise_id FROM workspaces WHERE id = $1', [workspaceId]);
  return r.rows[0]?.enterprise_id || null;
}

// ── Enterprise-scoped: /api/enterprises/:entId/workspaces ────────────

// POST — Create workspace (super_admin only)
router.post('/enterprises/:entId/workspaces', async (req, res) => {
  try {
    const role = await requireEnterpriseRole(req.user.id, req.params.entId, ['super_admin']);
    if (!role) return res.status(403).json({ error: 'super_admin access required' });

    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const result = await pool.query(
      `INSERT INTO workspaces (enterprise_id, name, description) VALUES ($1, $2, $3) RETURNING *`,
      [req.params.entId, name, description || null]
    );
    res.status(201).json(formatWorkspace(result.rows[0]));
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET — List workspaces for enterprise
router.get('/enterprises/:entId/workspaces', async (req, res) => {
  try {
    const role = await requireEnterpriseRole(req.user.id, req.params.entId, null);
    if (!role) return res.status(403).json({ error: 'No access to this enterprise' });

    let result;
    if (['super_admin', 'root'].includes(role)) {
      // See all workspaces
      result = await pool.query(
        `SELECT w.*, (SELECT count(*) FROM workspace_servers ws WHERE ws.workspace_id = w.id) AS server_count,
                     (SELECT count(*) FROM workspace_members wm WHERE wm.workspace_id = w.id) AS member_count
         FROM workspaces w WHERE w.enterprise_id = $1 ORDER BY w.name`,
        [req.params.entId]
      );
    } else {
      // Only see workspaces user is member of
      result = await pool.query(
        `SELECT w.*, wm.role AS member_role,
                (SELECT count(*) FROM workspace_servers ws WHERE ws.workspace_id = w.id) AS server_count,
                (SELECT count(*) FROM workspace_members wmm WHERE wmm.workspace_id = w.id) AS member_count
         FROM workspaces w
         JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = $1
         WHERE w.enterprise_id = $2 ORDER BY w.name`,
        [req.user.id, req.params.entId]
      );
    }

    res.json({ workspaces: result.rows.map(formatWorkspace) });
  } catch (err) {
    sendError(res, err, req);
  }
});

// ── Workspace-scoped: /api/workspaces/:id ────────────────────────────

// GET — Workspace detail with servers
router.get('/workspaces/:id', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });

    const role = await requireEnterpriseRole(req.user.id, entId, null);
    if (!role) return res.status(403).json({ error: 'No access' });

    const ws = await pool.query('SELECT * FROM workspaces WHERE id = $1', [req.params.id]);
    const servers = await pool.query(
      `SELECT s.id, s.name, s.url, s.hostname, s.description, s.access_mode
       FROM servers s
       JOIN workspace_servers wss ON wss.server_id = s.id
       WHERE wss.workspace_id = $1 ORDER BY s.name`,
      [req.params.id]
    );
    const members = await pool.query(
      `SELECT wm.id, wm.user_id, wm.role, wm.created_at, u.name AS user_name, u.email AS user_email
       FROM workspace_members wm
       JOIN users u ON u.id = wm.user_id
       WHERE wm.workspace_id = $1 ORDER BY u.name`,
      [req.params.id]
    );

    res.json({
      ...formatWorkspace(ws.rows[0]),
      servers: servers.rows,
      members: members.rows.map(m => ({
        id: m.id,
        userId: m.user_id,
        userName: m.user_name,
        userEmail: m.user_email,
        role: m.role,
        createdAt: m.created_at,
      })),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// PUT — Update workspace (super_admin)
router.put('/workspaces/:id', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['super_admin']);
    if (!role) return res.status(403).json({ error: 'super_admin access required' });

    const { name, description } = req.body;
    const result = await pool.query(
      `UPDATE workspaces SET name = COALESCE($1, name), description = COALESCE($2, description), updated_at = NOW()
       WHERE id = $3 RETURNING *`,
      [name, description, req.params.id]
    );
    res.json(formatWorkspace(result.rows[0]));
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE — Delete workspace (super_admin)
router.delete('/workspaces/:id', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['super_admin']);
    if (!role) return res.status(403).json({ error: 'super_admin access required' });

    await pool.query('DELETE FROM workspaces WHERE id = $1', [req.params.id]);
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST — Add server to workspace (super_admin)
router.post('/workspaces/:id/servers', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['super_admin']);
    if (!role) return res.status(403).json({ error: 'super_admin access required' });

    const serverId = req.body.serverId || req.body.server_id;
    if (!serverId) return res.status(400).json({ error: 'serverId is required' });

    // Verify server belongs to this enterprise (private only, not public/for-sale)
    const sCheck = await pool.query(
      `SELECT 1 FROM servers WHERE id = $1 AND enterprise_id = $2 AND access_mode = 'private'`,
      [serverId, entId]
    );
    if (sCheck.rows.length === 0) {
      return res.status(403).json({ error: 'Server does not belong to this enterprise or is not a private server' });
    }

    await pool.query(
      `INSERT INTO workspace_servers (workspace_id, server_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.params.id, serverId]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE — Remove server from workspace
router.delete('/workspaces/:id/servers/:serverId', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['super_admin']);
    if (!role) return res.status(403).json({ error: 'super_admin access required' });

    await pool.query(
      'DELETE FROM workspace_servers WHERE workspace_id = $1 AND server_id = $2',
      [req.params.id, req.params.serverId]
    );
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST — Add member to workspace (super_admin or workspace admin)
router.post('/workspaces/:id/members', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });

    // super_admin can always add; workspace admin can add members
    const entRole = await requireEnterpriseRole(req.user.id, entId, null);
    if (!entRole) return res.status(403).json({ error: 'No access' });

    if (entRole !== 'super_admin') {
      const wm = await pool.query(
        'SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]
      );
      if (wm.rows.length === 0 || wm.rows[0].role !== 'admin') {
        return res.status(403).json({ error: 'Workspace admin access required' });
      }
    }

    const userId = req.body.userId || req.body.user_id;
    const role = req.body.role;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    const memberRole = role || 'member';

    await pool.query(
      `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, $3)
       ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = $3`,
      [req.params.id, userId, memberRole]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET — List workspace members
router.get('/workspaces/:id/members', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT wm.id, wm.user_id, wm.role, wm.created_at, u.name AS user_name, u.email AS user_email
       FROM workspace_members wm JOIN users u ON u.id = wm.user_id
       WHERE wm.workspace_id = $1 ORDER BY u.name`,
      [req.params.id]
    );
    res.json({
      members: result.rows.map(m => ({
        id: m.id, userId: m.user_id, userName: m.user_name,
        userEmail: m.user_email, role: m.role, createdAt: m.created_at,
      })),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE — Remove member from workspace
router.delete('/workspaces/:id/members/:userId', async (req, res) => {
  try {
    const entId = await getWorkspaceEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'Workspace not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['super_admin']);
    if (!role) {
      // Check if workspace admin
      const wm = await pool.query(
        'SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]
      );
      if (wm.rows.length === 0 || wm.rows[0].role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }

    await pool.query(
      'DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2',
      [req.params.id, req.params.userId]
    );
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// ── format helper ────────────────────────────────────────────────────
function formatWorkspace(row) {
  return {
    id: row.id,
    enterpriseId: row.enterprise_id,
    name: row.name,
    description: row.description,
    serverCount: parseInt(row.server_count) || 0,
    memberCount: parseInt(row.member_count) || 0,
    memberRole: row.member_role || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

module.exports = router;
