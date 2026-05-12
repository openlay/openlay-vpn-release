const express = require('express');
const { sendError } = require('../middleware/errorHandler');
const router = express.Router();
const crypto = require('crypto');
const pool = require('../db/pool').pool;
const jwtAuth = require('../middleware/jwtAuth');
const { ROLE_RANK, canManageRole } = require('../constants/roles');

// All enterprise routes require JWT
router.use(jwtAuth);

// POST /api/enterprises — Register new enterprise
router.post('/', async (req, res) => {
  try {
    const { name, country, industry } = req.body;
    const companySize = req.body.companySize || req.body.company_size;
    if (!name) {
      return res.status(400).json({ error: 'name is required' });
    }

    // Generate random enterprise ID (URL-safe, hard to scan)
    const enterpriseId = crypto.randomBytes(16).toString('base64url');

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Create enterprise
      const entResult = await client.query(
        `INSERT INTO enterprises (enterprise_id, name, country, company_size, industry, owner_user_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [enterpriseId, name, country || null, companySize || null, industry || null, req.user.id]
      );
      const enterprise = entResult.rows[0];

      // Assign creator as super_admin
      await client.query(
        `INSERT INTO user_enterprise_roles (user_id, enterprise_id, role)
         VALUES ($1, $2, 'super_admin')`,
        [req.user.id, enterprise.id]
      );

      await client.query('COMMIT');

      res.status(201).json({
        id: enterprise.id,
        enterpriseId: enterprise.enterprise_id,
        name: enterprise.name,
        country: enterprise.country,
        companySize: enterprise.company_size,
        industry: enterprise.industry,
        role: 'super_admin',
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[enterprises] Create error:', err.message);
    sendError(res, err, req);
  }
});

// GET /api/enterprises — List user's enterprises
router.get('/', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.*, uer.role
       FROM enterprises e
       JOIN user_enterprise_roles uer ON uer.enterprise_id = e.id
       WHERE uer.user_id = $1
       ORDER BY e.name`,
      [req.user.id]
    );

    res.json({
      enterprises: result.rows.map(e => ({
        id: e.id,
        enterpriseId: e.enterprise_id,
        name: e.name,
        country: e.country,
        companySize: e.company_size,
        industry: e.industry,
        role: e.role,
        createdAt: e.created_at,
      })),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/enterprises/:id — Get enterprise detail
router.get('/:id', async (req, res) => {
  try {
    // Verify user has access
    const access = await pool.query(
      `SELECT uer.role FROM user_enterprise_roles uer
       WHERE uer.user_id = $1 AND uer.enterprise_id = $2`,
      [req.user.id, req.params.id]
    );
    if (access.rows.length === 0) {
      return res.status(403).json({ error: 'No access to this enterprise' });
    }

    const result = await pool.query('SELECT * FROM enterprises WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Enterprise not found' });
    }

    const e = result.rows[0];
    res.json({
      id: e.id,
      enterpriseId: e.enterprise_id,
      name: e.name,
      country: e.country,
      companySize: e.company_size,
      industry: e.industry,
      ownerUserId: e.owner_user_id,
      createdAt: e.created_at,
      role: access.rows[0].role,
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// PUT /api/enterprises/:id — Update enterprise
router.put('/:id', async (req, res) => {
  try {
    // Verify user is admin
    const access = await pool.query(
      `SELECT role FROM user_enterprise_roles
       WHERE user_id = $1 AND enterprise_id = $2 AND role IN ('super_admin', 'admin')`,
      [req.user.id, req.params.id]
    );
    if (access.rows.length === 0) {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { name, country, industry } = req.body;
    const companySize = req.body.companySize || req.body.company_size;
    const result = await pool.query(
      `UPDATE enterprises SET
        name = COALESCE($1, name),
        country = COALESCE($2, country),
        company_size = COALESCE($3, company_size),
        industry = COALESCE($4, industry),
        updated_at = NOW()
       WHERE id = $5 RETURNING *`,
      [name, country, companySize, industry, req.params.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Enterprise not found' });
    }

    const e = result.rows[0];
    res.json({
      id: e.id,
      enterpriseId: e.enterprise_id,
      name: e.name,
      country: e.country,
      companySize: e.company_size,
      industry: e.industry,
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// Role hierarchy comes from constants/roles. Local alias kept so the
// rest of the file reads naturally.
const canManage = canManageRole;

async function getCallerRole(userId, enterpriseId) {
  // Check root first
  const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [userId]);
  if (rootCheck.rows.length > 0) return 'root';
  // Then enterprise role
  const r = await pool.query(
    'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
    [userId, enterpriseId]
  );
  return r.rows[0]?.role || null;
}

async function getTargetRole(userId, enterpriseId) {
  const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [userId]);
  if (rootCheck.rows.length > 0) return 'root';
  const r = await pool.query(
    'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
    [userId, enterpriseId]
  );
  return r.rows[0]?.role || null;
}

// GET /api/enterprises/:id/members — List enterprise members
// super_admin cannot see root users; admin cannot see root users
router.get('/:id/members', async (req, res) => {
  try {
    const callerRole = await getCallerRole(req.user.id, req.params.id);
    if (!callerRole) return res.status(403).json({ error: 'No access' });

    // Get all members
    const result = await pool.query(
      `SELECT uer.id, uer.user_id, uer.role, uer.created_at,
              u.name AS user_name, u.email AS user_email, u.username, u.auth_type, u.status AS user_status
       FROM user_enterprise_roles uer
       JOIN users u ON u.id = uer.user_id
       WHERE uer.enterprise_id = $1
       ORDER BY u.name`,
      [req.params.id]
    );

    // Filter: only show members with rank <= caller's rank
    // root sees everyone; super_admin sees super_admin/admin/member (not root); admin sees admin/member
    const callerRank = ROLE_RANK[callerRole] || 0;
    const rootUserIds = new Set();

    // Find root users among results
    for (const m of result.rows) {
      const rc = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [m.user_id]);
      if (rc.rows.length > 0) rootUserIds.add(m.user_id);
    }

    const filtered = result.rows.filter(m => {
      const effectiveRole = rootUserIds.has(m.user_id) ? 'root' : m.role;
      return (ROLE_RANK[effectiveRole] || 0) <= callerRank;
    });

    res.json({
      members: filtered.map(m => ({
        id: m.id,
        userId: m.user_id,
        userName: m.user_name,
        userEmail: m.user_email,
        username: m.username,
        authType: m.auth_type,
        userStatus: m.user_status,
        role: m.role,
        createdAt: m.created_at,
      })),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/enterprises/:id/members — Add user to enterprise (super_admin+ only)
router.post('/:id/members', async (req, res) => {
  try {
    const callerRole = await getCallerRole(req.user.id, req.params.id);
    if (!callerRole || !['root', 'super_admin'].includes(callerRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }

    const userId = req.body.userId || req.body.user_id;
    const role = req.body.role;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    const assignRole = role || 'admin';

    // Validate role is a known value
    if (!['super_admin', 'admin', 'member'].includes(assignRole)) {
      return res.status(400).json({ error: `Invalid role: ${assignRole}. Must be super_admin, admin, or member` });
    }

    // Cannot assign a role >= your own
    if (!canManage(callerRole, assignRole)) {
      return res.status(403).json({ error: `Cannot assign role '${assignRole}' — insufficient privileges` });
    }

    // Verify target user exists
    const userCheck = await pool.query('SELECT 1 FROM users WHERE id = $1', [userId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If user already a member, check we can manage their current role before overwriting
    const existingRole = await getTargetRole(userId, req.params.id);
    if (existingRole && !canManage(callerRole, existingRole)) {
      return res.status(403).json({ error: `Cannot modify a ${existingRole} — insufficient privileges` });
    }

    await pool.query(
      `INSERT INTO user_enterprise_roles (user_id, enterprise_id, role)
       VALUES ($1, $2, $3)
       ON CONFLICT (user_id, enterprise_id) DO UPDATE SET role = $3`,
      [userId, req.params.id, assignRole]
    );

    res.status(201).json({ ok: true });
  } catch (err) {
    if (err.code === '23503') return res.status(404).json({ error: 'User not found' });
    sendError(res, err, req);
  }
});

// PUT /api/enterprises/:id/members/:userId — Change member role
router.put('/:id/members/:userId', async (req, res) => {
  try {
    const callerRole = await getCallerRole(req.user.id, req.params.id);
    if (!callerRole || !['root', 'super_admin'].includes(callerRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }

    const { role } = req.body;
    if (!role) return res.status(400).json({ error: 'role is required' });
    if (!['super_admin', 'admin', 'member'].includes(role)) {
      return res.status(400).json({ error: `Invalid role: ${role}. Must be super_admin, admin, or member` });
    }

    // Check target's current role
    const targetRole = await getTargetRole(req.params.userId, req.params.id);
    if (!targetRole) return res.status(404).json({ error: 'Member not found' });

    // Cannot change someone with rank >= yours
    if (!canManage(callerRole, targetRole)) {
      return res.status(403).json({ error: `Cannot modify a ${targetRole} — insufficient privileges` });
    }
    // Cannot promote to a role >= your own
    if (!canManage(callerRole, role)) {
      return res.status(403).json({ error: `Cannot assign role '${role}' — insufficient privileges` });
    }

    const result = await pool.query(
      `UPDATE user_enterprise_roles SET role = $1
       WHERE user_id = $2 AND enterprise_id = $3 RETURNING *`,
      [role, req.params.userId, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Member not found' });

    res.json({ ok: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE /api/enterprises/:id/members/:userId — Remove user from enterprise
router.delete('/:id/members/:userId', async (req, res) => {
  try {
    const callerRole = await getCallerRole(req.user.id, req.params.id);
    if (!callerRole || !['root', 'super_admin'].includes(callerRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }

    // Prevent removing yourself
    if (req.params.userId === req.user.id) {
      return res.status(400).json({ error: 'Cannot remove yourself from enterprise' });
    }

    // Check target's role — cannot remove someone with rank >= yours
    const targetRole = await getTargetRole(req.params.userId, req.params.id);
    if (targetRole && !canManage(callerRole, targetRole)) {
      return res.status(403).json({ error: `Cannot remove a ${targetRole} — insufficient privileges` });
    }

    await pool.query(
      'DELETE FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
      [req.params.userId, req.params.id]
    );
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
