const express = require('express');
const router = express.Router({ mergeParams: true });
const pool = require('../db/pool').pool;
const jwtAuth = require('../middleware/jwtAuth');

router.use(jwtAuth);

// ── helpers ──────────────────────────────────────────────────────────
async function requireEnterpriseRole(userId, enterpriseId, roles) {
  // Root bypasses all enterprise role checks
  const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [userId]);
  if (rootCheck.rows.length > 0) return 'root';

  const r = await pool.query(
    `SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2`,
    [userId, enterpriseId]
  );
  if (r.rows.length === 0) return null;
  if (roles && !roles.includes(r.rows[0].role)) return null;
  return r.rows[0].role;
}

async function getUserGroupEnterprise(userGroupId) {
  const r = await pool.query('SELECT enterprise_id FROM user_groups WHERE id = $1', [userGroupId]);
  return r.rows[0]?.enterprise_id || null;
}

/**
 * Re-sync agent route_policies on every server that has a policy with
 * ingress_type='group' referencing this group, after the group's
 * membership changed. Queries by ingress_group_id directly (NOT by
 * user intersection) — the membership row may have been deleted
 * already, so user-intersection queries miss it.
 */
async function resyncPoliciesAfterGroupChange(groupId) {
  let resyncPoliciesByIds;
  try {
    ({ resyncPoliciesByIds } = require('../services/policyResync'));
  } catch (err) {
    console.error('[user-groups] policyResync require failed:', err.message);
    return;
  }
  const { rows } = await pool.query(
    `SELECT id, server_id FROM route_policies
       WHERE ingress_type = 'group' AND ingress_group_id = $1`,
    [groupId]
  );
  const byServer = new Map();
  for (const r of rows) {
    if (!byServer.has(r.server_id)) byServer.set(r.server_id, []);
    byServer.get(r.server_id).push(r.id);
  }
  for (const [serverId, ids] of byServer) {
    try {
      await resyncPoliciesByIds(serverId, ids);
    } catch (err) {
      console.error(`[user-groups] policy resync server=${serverId} failed:`, err.message);
    }
  }
}

// ── Enterprise-scoped: /api/enterprises/:entId/user-groups ──────────

// POST — Create user group (super_admin only)
router.post('/enterprises/:entId/user-groups', async (req, res) => {
  try {
    const role = await requireEnterpriseRole(req.user.id, req.params.entId, ['root', 'super_admin', 'admin']);
    if (!role) return res.status(403).json({ error: 'admin access or higher required' });

    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });

    const result = await pool.query(
      `INSERT INTO user_groups (enterprise_id, name, description) VALUES ($1, $2, $3) RETURNING *`,
      [req.params.entId, name, description || null]
    );
    res.status(201).json(formatUserGroup(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET — List user groups for enterprise
router.get('/enterprises/:entId/user-groups', async (req, res) => {
  try {
    const role = await requireEnterpriseRole(req.user.id, req.params.entId, null);
    if (!role) return res.status(403).json({ error: 'No access to this enterprise' });

    let result;
    if (['super_admin', 'root', 'admin'].includes(role)) {
      result = await pool.query(
        `SELECT g.*,
                (SELECT count(*) FROM user_group_members gm WHERE gm.user_group_id = g.id) AS member_count
         FROM user_groups g WHERE g.enterprise_id = $1 ORDER BY g.name`,
        [req.params.entId]
      );
    } else {
      result = await pool.query(
        `SELECT g.*, gm.role AS member_role,
                (SELECT count(*) FROM user_group_members gmm WHERE gmm.user_group_id = g.id) AS member_count
         FROM user_groups g
         JOIN user_group_members gm ON gm.user_group_id = g.id AND gm.user_id = $1
         WHERE g.enterprise_id = $2 ORDER BY g.name`,
        [req.user.id, req.params.entId]
      );
    }

    res.json({ userGroups: result.rows.map(formatUserGroup) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── User-group-scoped: /api/user-groups/:id ─────────────────────────

// GET — User group detail with members
router.get('/user-groups/:id', async (req, res) => {
  try {
    const entId = await getUserGroupEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'User group not found' });

    const role = await requireEnterpriseRole(req.user.id, entId, null);
    if (!role) return res.status(403).json({ error: 'No access' });

    const ug = await pool.query('SELECT * FROM user_groups WHERE id = $1', [req.params.id]);
    const members = await pool.query(
      `SELECT gm.id, gm.user_id, gm.role, gm.created_at, u.name AS user_name, u.email AS user_email
       FROM user_group_members gm
       JOIN users u ON u.id = gm.user_id
       WHERE gm.user_group_id = $1 ORDER BY u.name`,
      [req.params.id]
    );

    res.json({
      ...formatUserGroup(ug.rows[0]),
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
    res.status(500).json({ error: err.message });
  }
});

// PUT — Update user group (super_admin)
router.put('/user-groups/:id', async (req, res) => {
  try {
    const entId = await getUserGroupEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'User group not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['root', 'super_admin', 'admin']);
    if (!role) return res.status(403).json({ error: 'admin access or higher required' });

    const { name, description } = req.body;
    const result = await pool.query(
      `UPDATE user_groups SET name = COALESCE($1, name), description = COALESCE($2, description), updated_at = NOW()
       WHERE id = $3 RETURNING *`,
      [name, description, req.params.id]
    );
    res.json(formatUserGroup(result.rows[0]));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE — Delete user group (super_admin)
router.delete('/user-groups/:id', async (req, res) => {
  try {
    const entId = await getUserGroupEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'User group not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['root', 'super_admin', 'admin']);
    if (!role) return res.status(403).json({ error: 'admin access or higher required' });

    // Refuse delete when the group still has dependents. CASCADE would
    // silently wipe rules + ACLs on the agent (some without resync hooks
    // wired up), and admins typically don't realize a group is in use
    // until a service breaks. Force them to clear dependents first.
    const [members, policies, appAcls] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM user_group_members       WHERE user_group_id = $1', [req.params.id]),
      pool.query('SELECT COUNT(*)::int AS n FROM route_policies           WHERE ingress_group_id = $1', [req.params.id]),
      pool.query('SELECT COUNT(*)::int AS n FROM application_server_groups WHERE user_group_id = $1', [req.params.id]),
    ]);
    const deps = {
      members:           members.rows[0].n,
      route_policies:    policies.rows[0].n,
      application_acls:  appAcls.rows[0].n,
    };
    const blocking = Object.entries(deps).filter(([_, n]) => n > 0);
    if (blocking.length > 0) {
      const summary = blocking.map(([k, n]) => `${k}=${n}`).join(', ');
      return res.status(409).json({
        error: `Group has dependents and cannot be deleted: ${summary}. Remove members + detach from rules/ACLs first.`,
        dependents: deps,
      });
    }

    await pool.query('DELETE FROM user_groups WHERE id = $1', [req.params.id]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST — Add member to user group (super_admin or group admin)
router.post('/user-groups/:id/members', async (req, res) => {
  try {
    const entId = await getUserGroupEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'User group not found' });

    const entRole = await requireEnterpriseRole(req.user.id, entId, null);
    if (!entRole) return res.status(403).json({ error: 'No access' });

    if (entRole !== 'super_admin' && entRole !== 'root') {
      const gm = await pool.query(
        'SELECT role FROM user_group_members WHERE user_group_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]
      );
      if (gm.rows.length === 0 || gm.rows[0].role !== 'admin') {
        return res.status(403).json({ error: 'Group admin access required' });
      }
    }

    const userId = req.body.userId || req.body.user_id;
    const role = req.body.role;
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    const memberRole = role || 'member';

    // Verify user belongs to enterprise
    const uCheck = await pool.query(
      'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
      [userId, entId]
    );
    if (uCheck.rows.length === 0) {
      return res.status(400).json({ error: 'User does not belong to this enterprise' });
    }

    await pool.query(
      `INSERT INTO user_group_members (user_group_id, user_id, role) VALUES ($1, $2, $3)
       ON CONFLICT (user_group_id, user_id) DO UPDATE SET role = $3`,
      [req.params.id, userId, memberRole]
    );
    // Group composition changed → resync route_policies on every server
    // that has a policy with ingress_type='group' referencing this
    // group, so the agent's pf rule picks up the new member's IP (or
    // drops the removed member's IP). resyncPoliciesByUsers itself does
    // a diff-skip if nothing actually changed.
    await resyncPoliciesAfterGroupChange(req.params.id);
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET — List user group members
router.get('/user-groups/:id/members', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT gm.id, gm.user_id, gm.role, gm.created_at, u.name AS user_name, u.email AS user_email
       FROM user_group_members gm JOIN users u ON u.id = gm.user_id
       WHERE gm.user_group_id = $1 ORDER BY u.name`,
      [req.params.id]
    );
    res.json({
      members: result.rows.map(m => ({
        id: m.id, userId: m.user_id, userName: m.user_name,
        userEmail: m.user_email, role: m.role, createdAt: m.created_at,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE — Remove member from user group
router.delete('/user-groups/:id/members/:userId', async (req, res) => {
  try {
    const entId = await getUserGroupEnterprise(req.params.id);
    if (!entId) return res.status(404).json({ error: 'User group not found' });
    const role = await requireEnterpriseRole(req.user.id, entId, ['root', 'super_admin', 'admin']);
    if (!role) {
      const gm = await pool.query(
        'SELECT role FROM user_group_members WHERE user_group_id = $1 AND user_id = $2',
        [req.params.id, req.user.id]
      );
      if (gm.rows.length === 0 || gm.rows[0].role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }

    await pool.query(
      'DELETE FROM user_group_members WHERE user_group_id = $1 AND user_id = $2',
      [req.params.id, req.params.userId]
    );
    await resyncPoliciesAfterGroupChange(req.params.id);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── format helper ────────────────────────────────────────────────────
function formatUserGroup(row) {
  return {
    id: row.id,
    enterpriseId: row.enterprise_id,
    name: row.name,
    description: row.description,
    memberCount: parseInt(row.member_count) || 0,
    memberRole: row.member_role || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

module.exports = router;
