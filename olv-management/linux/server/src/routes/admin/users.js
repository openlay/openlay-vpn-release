const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { verifyAdminSignature } = require('../../services/adminSigning');
const AgentClient = require('../../services/agentClient');
const { resyncRulesByUsers } = require('../../services/ruleOrchestrator');

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
    // #7 — Block self-delete. A logged-in admin should never be able to
    // erase their own row mid-session: it would invalidate the JWT they're
    // currently using, leak audit attribution, and (worst) allow them to
    // delete themselves to bypass an investigation.
    if (req.user.id === req.params.id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

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

    // #5 — Block deleting the last admin of any enterprise. Without this,
    // an enterprise can be left with only members → no one can manage it.
    // Per-enterprise check: for every enterprise where target user is
    // admin/super_admin, count OTHER admins. Reject if any has 0.
    const { rows: orphanCheck } = await pool.query(
      `SELECT e.name, e.id AS enterprise_id
         FROM user_enterprise_roles uer
         JOIN enterprises e ON e.id = uer.enterprise_id
        WHERE uer.user_id = $1
          AND uer.role IN ('admin', 'super_admin')
          AND NOT EXISTS (
            SELECT 1 FROM user_enterprise_roles other
             WHERE other.enterprise_id = uer.enterprise_id
               AND other.user_id <> uer.user_id
               AND other.role IN ('admin', 'super_admin')
          )`,
      [req.params.id]
    );
    if (orphanCheck.length > 0) {
      const names = orphanCheck.map(r => r.name).join(', ');
      return res.status(409).json({
        error: `Cannot delete: this is the last admin of ${names}. Promote another member first.`,
      });
    }

    const sigCheck = await verifyAdminSignature(req, 'delete_user', {
      target_type: 'user',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    // Gather every WG peer (server_id + interface + public_key) tied to this
    // user — both directly via pm.user_id and via the user's devices. We
    // grab this BEFORE the DELETE so the FK ON DELETE SET NULL on
    // peers_meta.user_id / .device_id doesn't erase the linkage.
    const { rows: peerRows } = await pool.query(
      `SELECT DISTINCT pm.server_id, pm.interface_name, pm.public_key
         FROM peers_meta pm
        WHERE pm.user_id = $1
           OR pm.device_id IN (SELECT id FROM devices WHERE user_id = $1)`,
      [req.params.id]
    );

    // #2 — Collect every server that has rules / ACLs referencing this
    // user, so we can resync agent firewall rules AFTER the DELETE.
    // Without this, srcUserId/dstUserId in stored rules dangle: agent
    // keeps applying iptables/pf rules that reference an IP set the
    // server now believes is empty (or worse, the next user to be
    // assigned the same IP inherits the previous tenant's permissions).
    const { rows: serverRows } = await pool.query(
      `SELECT DISTINCT s.id AS server_id FROM (
         SELECT server_id FROM peers_meta WHERE user_id = $1
           OR device_id IN (SELECT id FROM devices WHERE user_id = $1)
         UNION
         SELECT server_id FROM user_server_assignments WHERE user_id = $1
         UNION
         SELECT a.server_id
           FROM application_server_users asu
           JOIN application_servers a ON a.id = asu.app_id
          WHERE asu.user_id = $1
       ) AS s`,
      [req.params.id]
    );
    const affectedServerIds = serverRows.map(r => r.server_id);

    // #3 — Parallel agent.removePeer calls. Sequential loop with N peers
    // × ~3s/RPC easily exceeds Express's 120s timeout for an enterprise
    // with many devices. allSettled because failures of unrelated agents
    // shouldn't block the others.
    const removeResults = await Promise.allSettled(
      peerRows.map(p => {
        const client = new AgentClient(parseInt(p.server_id, 10));
        return client.removePeer(p.interface_name, p.public_key);
      })
    );
    removeResults.forEach((r, i) => {
      if (r.status === 'rejected') {
        const p = peerRows[i];
        console.warn(
          `[users/delete] agent removePeer failed for ${p.public_key} on server=${p.server_id} iface=${p.interface_name}: ${r.reason?.message || r.reason}`
        );
      }
    });

    // CASCADE on users.id removes:
    //   - devices (and via devices: device_static_ips, device_attestations,
    //     device_postures, auth_sessions all CASCADE)
    //   - user_server_assignments (CASCADE)
    //   - user_enterprise_roles (CASCADE)
    //   - application_server_users (CASCADE)
    //   - root_users (CASCADE), attest_challenges (CASCADE), user_group_members (CASCADE)
    // peers_meta keeps the row but flips user_id/device_id to NULL — clean
    // those up explicitly so the admin doesn't see orphan rows in the UI.
    const { rowCount } = await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    if (peerRows.length > 0) {
      await pool.query(
        `DELETE FROM peers_meta
          WHERE (server_id, interface_name, public_key) IN (
            SELECT * FROM UNNEST($1::int[], $2::text[], $3::text[])
          )`,
        [
          peerRows.map(p => p.server_id),
          peerRows.map(p => p.interface_name),
          peerRows.map(p => p.public_key),
        ]
      );
    }

    // #2 (continued) — resync rules per affected server. Best-effort: a
    // single failing server doesn't unwind the delete (user is gone from
    // DB by now, retry would 404). Errors are logged for ops follow-up.
    await Promise.allSettled(
      affectedServerIds.map(async sid => {
        try {
          await resyncRulesByUsers(sid, [req.params.id]);
        } catch (e) {
          console.warn(`[users/delete] resyncRulesByUsers failed for server=${sid}: ${e.message}`);
        }
      })
    );

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
