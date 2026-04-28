const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { verifyAdminSignature } = require('../../services/adminSigning');

const router = Router();
router.use(enterpriseContext);

const ENT_USERS_FILTER = `
  u.id IN (SELECT user_id FROM user_enterprise_roles WHERE enterprise_id = $1)
`;

// GET /api/admin/users — with optional filters: server_id, user_group_id, search
router.get('/', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const serverId = req.query.server_id;
    const userGroupId = req.query.user_group_id;
    const search = req.query.search;

    const conditions = [];
    const params = [];

    // Enterprise scope — always filter by enterprise when one is selected,
    // even for root users (prevents cross-enterprise assignment errors)
    if (req.enterpriseId) {
      params.push(req.enterpriseId);
      conditions.push(`u.id IN (SELECT user_id FROM user_enterprise_roles WHERE enterprise_id = $${params.length})`);
    }

    // Filter by server
    if (serverId) {
      params.push(serverId);
      conditions.push(`u.id IN (SELECT user_id FROM user_server_assignments WHERE server_id = $${params.length})`);
    }

    // Filter by user group
    if (userGroupId) {
      params.push(userGroupId);
      conditions.push(`u.id IN (SELECT user_id FROM user_group_members WHERE user_group_id = $${params.length})`);
    }

    // Search by name, email, username
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(u.name ILIKE $${params.length} OR u.email ILIKE $${params.length} OR u.username ILIKE $${params.length})`);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    // Join enterprise role to get alias for current enterprise context
    const aliasJoin = req.enterpriseId
      ? `LEFT JOIN user_enterprise_roles uer ON uer.user_id = u.id AND uer.enterprise_id = '${req.enterpriseId.replace(/'/g, "''")}'`
      : `LEFT JOIN (SELECT DISTINCT ON (user_id) user_id, alias FROM user_enterprise_roles ORDER BY user_id, created_at) uer ON uer.user_id = u.id`;
    const { rows } = await pool.query(`
      SELECT u.*,
        uer.alias as enterprise_alias,
        (SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id) AS device_count,
        (SELECT COUNT(*) FROM peers_meta pm WHERE pm.user_id = u.id) AS peer_count,
        (SELECT MAX(d.last_connect_at) FROM devices d WHERE d.user_id = u.id) AS last_connect_at
      FROM users u ${aliasJoin} ${where}
      ORDER BY u.created_at DESC`, params);
    res.json({ users: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/users/:id
router.get('/:id', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    if (!isRoot) {
      const check = await pool.query(
        'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found in this enterprise' });
    }

    const { rows: users } = await pool.query(
      `SELECT u.*,
              (SELECT MAX(d.last_connect_at) FROM devices d WHERE d.user_id = u.id) AS last_connect_at
         FROM users u WHERE u.id = $1`,
      [req.params.id]
    );
    if (users.length === 0) return res.status(404).json({ error: 'User not found' });

    const { rows: devices } = await pool.query(
      `SELECT d.*,
        da.key_id as attest_key_id, da.sign_count as attest_sign_count, da.created_at as attest_date
       FROM devices d
       LEFT JOIN device_attestations da ON da.device_id = d.id
       WHERE d.user_id = $1
       ORDER BY d.created_at DESC`,
      [req.params.id]
    );

    const { rows: peers } = isRoot
      ? await pool.query(`SELECT pm.*, s.name as server_name FROM peers_meta pm LEFT JOIN servers s ON pm.server_id = s.id WHERE pm.user_id = $1 ORDER BY pm.created_at DESC`, [req.params.id])
      : await pool.query(`SELECT pm.*, s.name as server_name FROM peers_meta pm LEFT JOIN servers s ON pm.server_id = s.id WHERE pm.user_id = $1 AND (s.enterprise_id = $2 OR s.enterprise_id IS NULL) ORDER BY pm.created_at DESC`, [req.params.id, req.enterpriseId]);

    const { rows: assignments } = isRoot
      ? await pool.query(`SELECT usa.*, s.name as server_name, sub.cidr as subnet_cidr, sub.name as subnet_name FROM user_server_assignments usa LEFT JOIN servers s ON usa.server_id = s.id LEFT JOIN subnets sub ON usa.subnet_id = sub.id WHERE usa.user_id = $1`, [req.params.id])
      : await pool.query(`SELECT usa.*, s.name as server_name, sub.cidr as subnet_cidr, sub.name as subnet_name FROM user_server_assignments usa LEFT JOIN servers s ON usa.server_id = s.id LEFT JOIN subnets sub ON usa.subnet_id = sub.id WHERE usa.user_id = $1 AND (s.enterprise_id = $2 OR s.enterprise_id IS NULL)`, [req.params.id, req.enterpriseId]);

    // Get alias for this enterprise
    let alias = '';
    if (req.enterpriseId) {
      const { rows: aliasRows } = await pool.query(
        'SELECT alias FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      alias = aliasRows[0]?.alias || '';
    }

    // All enterprises the user belongs to (id, name, role, alias)
    const { rows: enterprises } = await pool.query(
      `SELECT e.id, e.name, e.enterprise_id as public_id, uer.role, uer.alias
       FROM user_enterprise_roles uer
       JOIN enterprises e ON e.id = uer.enterprise_id
       WHERE uer.user_id = $1
       ORDER BY uer.created_at`,
      [req.params.id]
    );

    res.json({ user: { ...users[0], enterprise_alias: alias }, devices, peers, assignments, enterprises });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/users/:id
router.put('/:id', async (req, res) => {
  try {
    const { name, status, alias } = req.body;

    // Alias-only update bypasses role hierarchy — it's just a display name
    if (alias !== undefined && name === undefined && status === undefined) {
      let aliasEntId = req.enterpriseId;
      if (!aliasEntId) {
        const { rows: uerRows } = await pool.query(
          'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 ORDER BY created_at LIMIT 1',
          [req.params.id]
        );
        aliasEntId = uerRows[0]?.enterprise_id;
      }
      if (aliasEntId) {
        await pool.query(
          'UPDATE user_enterprise_roles SET alias = $1 WHERE user_id = $2 AND enterprise_id = $3',
          [alias, req.params.id, aliasEntId]
        );
      }
      const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
      if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
      return res.json({ user: { ...rows[0], enterprise_alias: alias } });
    }

    if (req.enterpriseRole !== 'root') {
      const check = await pool.query(
        'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found in this enterprise' });
    }

    // Role hierarchy: cannot modify user with higher/equal rank
    const ROLE_RANK = { root: 4, super_admin: 3, admin: 2, member: 1 };
    const callerRank = ROLE_RANK[req.enterpriseRole] || 0;

    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.params.id]);
    const targetEntRole = await pool.query(
      'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
      [req.params.id, req.enterpriseId]
    );
    const targetRole = rootCheck.rows.length > 0 ? 'root' : (targetEntRole.rows[0]?.role || 'member');
    const targetRank = ROLE_RANK[targetRole] || 0;

    if (targetRank >= callerRank) {
      return res.status(403).json({ error: `Cannot modify a ${targetRole} — insufficient privileges` });
    }

    // Sign status / name changes (skip for alias-only — already short-circuited above).
    let action = 'update_user';
    const sigFields = { target_type: 'user', target_id: req.params.id };
    if (status !== undefined && name === undefined) {
      action = status === 'disabled' ? 'disable_user' : 'enable_user';
      sigFields.status = status;
    }
    const sigCheck = await verifyAdminSignature(req, action, sigFields);
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    // Also update alias if provided alongside other fields
    if (alias !== undefined) {
      // Determine which enterprise to update alias for
      let aliasEntId = req.enterpriseId;
      if (!aliasEntId) {
        // Root without enterprise header — use target user's first enterprise
        const { rows: uerRows } = await pool.query(
          'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 ORDER BY created_at LIMIT 1',
          [req.params.id]
        );
        aliasEntId = uerRows[0]?.enterprise_id;
      }
      if (aliasEntId) {
        await pool.query(
          'UPDATE user_enterprise_roles SET alias = $1 WHERE user_id = $2 AND enterprise_id = $3',
          [alias, req.params.id, aliasEntId]
        );
      }
    }

    const fields = [];
    const values = [];
    let idx = 1;

    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (status !== undefined) {
      if (!['enabled', 'disabled'].includes(status)) {
        return res.status(400).json({ error: 'status must be enabled or disabled' });
      }
      fields.push(`status = $${idx++}`);
      values.push(status);
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    fields.push(`updated_at = NOW()`);
    values.push(req.params.id);

    const { rows } = await pool.query(
      `UPDATE users SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id
router.delete('/:id', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      const check = await pool.query(
        'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found in this enterprise' });
    }

    // Role hierarchy check
    const ROLE_RANK = { root: 4, super_admin: 3, admin: 2, member: 1 };
    const callerRank = ROLE_RANK[req.enterpriseRole] || 0;
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.params.id]);
    const targetEntRole = await pool.query(
      'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
      [req.params.id, req.enterpriseId]
    );
    const targetRole = rootCheck.rows.length > 0 ? 'root' : (targetEntRole.rows[0]?.role || 'member');
    if ((ROLE_RANK[targetRole] || 0) >= callerRank) {
      return res.status(403).json({ error: `Cannot delete a ${targetRole} — insufficient privileges` });
    }

    const sigCheck = await verifyAdminSignature(req, 'delete_user', {
      target_type: 'user',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/users/:id/server-access — only enterprise servers
router.post('/:id/server-access', async (req, res) => {
  try {
    const server_id = req.body.server_id || req.body.serverId;
    const interface_name = req.body.interface_name || req.body.interfaceName;
    const subnet_id = req.body.subnet_id || req.body.subnetId;
    if (!server_id || !interface_name) {
      return res.status(400).json({ error: 'server_id and interface_name are required' });
    }
    // Verify server in enterprise (root can access any server)
    if (req.enterpriseRole !== 'root') {
      const sCheck = await pool.query(
        `SELECT 1 FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [server_id, req.enterpriseId]
      );
      if (sCheck.rows.length === 0) return res.status(404).json({ error: 'Server not found in this enterprise' });

      // Verify target user belongs to this enterprise
      const uCheck = await pool.query(
        'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      if (uCheck.rows.length === 0) return res.status(404).json({ error: 'User not found in this enterprise' });
    }

    const { rows } = await pool.query(
      `INSERT INTO user_server_assignments (user_id, server_id, interface_name, subnet_id)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, server_id, interface_name) DO UPDATE SET subnet_id = $4
       RETURNING *`,
      [req.params.id, server_id, interface_name, subnet_id || null]
    );
    res.status(201).json({ assignment: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/users/:id/server-access/:assignId
router.delete('/:id/server-access/:assignId', async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      'DELETE FROM user_server_assignments WHERE id = $1 AND user_id = $2',
      [req.params.assignId, req.params.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Assignment not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
