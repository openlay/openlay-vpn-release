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

    // Hide soft-deleted users from the default list. Audit views can opt-in
    // via ?include_deleted=true (currently unused; left as a future hook).
    if (req.query.include_deleted !== 'true') {
      conditions.push(`u.status <> 'deleted'`);
    }

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
    // Soft-deleted users behave like 404 for the default detail view —
    // their PII is gone, role memberships are stripped, no point rendering.
    if (users[0].status === 'deleted' && req.query.include_deleted !== 'true') {
      return res.status(404).json({ error: 'User not found' });
    }

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

// DELETE /api/admin/users/:id — SOFT delete.
// Keeps the users row with status='deleted' + nullified PII so historical
// references (admin_audit_log.admin_user_id, peers_meta.user_id once the
// peer rows themselves are nuked, enrollment_requests.approved_user_id,
// enterprise_settings.created_by, etc.) stay attributable. Live
// relationships (devices, sessions, peer rows, ACL memberships, group
// memberships, attest challenges, root flag) are hard-deleted so the user
// can't reconnect after this returns.
//
// Order matters:
//   1. Fast-path guards (cheap, no DB writes).
//   2. Admin signature verification (writes audit row — must succeed before
//      we touch state).
//   3. Out-of-band agent calls (removePeer) — done BEFORE the DB transaction
//      so a hung agent doesn't hold a lock.
//   4. Single transaction: snapshot PII → soft-delete user + cascade
//      relationship cleanup → revoke sessions → drop devices/peers/ACL/etc.
//   5. Best-effort agent rule resync after commit.
router.delete('/:id', async (req, res) => {
  try {
    // #7 — Block self-delete. A logged-in admin should never be able to
    // erase their own row mid-session: it would invalidate the JWT they're
    // currently using, leak audit attribution, and (worst) allow them to
    // delete themselves to bypass an investigation.
    if (req.user.id === req.params.id) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    // Look up target row up-front so subsequent checks can avoid duplicate
    // queries. Reject early if the row is already soft-deleted (idempotency).
    const { rows: targetRows } = await pool.query(
      'SELECT id, name, email, username, status FROM users WHERE id = $1',
      [req.params.id]
    );
    if (targetRows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (targetRows[0].status === 'deleted') {
      return res.status(404).json({ error: 'User not found' });
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

    // Block deleting the last admin of any enterprise. Without this,
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

    // Block deleting an enterprise owner. Hard-cleared `owner_user_id` would
    // leave the enterprise ownerless without a clear audit trail. Admin
    // must transfer ownership manually before the user can be deleted.
    const { rows: ownerCheck } = await pool.query(
      'SELECT id, name FROM enterprises WHERE owner_user_id = $1',
      [req.params.id]
    );
    if (ownerCheck.length > 0) {
      const names = ownerCheck.map(r => r.name).join(', ');
      return res.status(409).json({
        error: `Cannot delete: user is owner of ${names}. Transfer ownership first.`,
      });
    }

    const sigCheck = await verifyAdminSignature(req, 'delete_user', {
      target_type: 'user',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    // Gather every WG peer (server_id + interface + public_key) tied to this
    // user — both directly via pm.user_id and via the user's devices. We
    // grab this BEFORE the soft-delete so the FK SET NULL on
    // peers_meta.user_id (when we drop devices below) doesn't erase the
    // linkage we need for agent removePeer calls.
    const { rows: peerRows } = await pool.query(
      `SELECT DISTINCT pm.server_id, pm.interface_name, pm.public_key
         FROM peers_meta pm
        WHERE pm.user_id = $1
           OR pm.device_id IN (SELECT id FROM devices WHERE user_id = $1)`,
      [req.params.id]
    );

    // Collect every server that has rules / ACLs referencing this user, so
    // we can resync agent firewall rules AFTER the transaction commits.
    // Without this, srcUserId/dstUserId in stored rules dangle: agent keeps
    // applying iptables/pf rules that reference an IP set the server now
    // believes is empty.
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

    // Parallel agent.removePeer calls — done OUTSIDE the DB transaction so a
    // slow/unreachable agent doesn't hold a row lock. allSettled because
    // failures of unrelated agents shouldn't block the others.
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

    // ── Snapshot route_policies that reference this user ────────────────
    // Must be done BEFORE the cascade deletes (route_policy_users,
    // user_group_members, devices) wipe the membership rows, otherwise
    // resyncPoliciesByUsers's intersection query would miss them and the
    // agent's pf rules stay stale referencing the deleted user's IP.
    //
    // For type='users'/'group' the policy itself stays (just rebuild
    // without this user). For type='device' the policy ROW gets
    // CASCADE-deleted along with the device, so we capture (server,
    // policy_name) pairs to force-remove from agent.
    const { rows: policySnapshot } = await pool.query(
      `SELECT p.id, p.server_id, p.name, p.ingress_type
         FROM route_policies p
        WHERE
          (p.ingress_type = 'users' AND EXISTS (
             SELECT 1 FROM route_policy_users rpu
              WHERE rpu.policy_id = p.id AND rpu.user_id = $1
          ))
          OR (p.ingress_type = 'group' AND EXISTS (
             SELECT 1 FROM user_group_members ugm
              WHERE ugm.user_group_id = p.ingress_group_id AND ugm.user_id = $1
          ))
          OR (p.ingress_type = 'device' AND EXISTS (
             SELECT 1 FROM devices d
              WHERE d.id = p.ingress_device_id AND d.user_id = $1
          ))`,
      [req.params.id]
    );

    // ── Transaction ──────────────────────────────────────────────────────
    // Anything that mutates `users` or its dependents goes through this
    // single connection so a failure leaves the DB consistent (admin can
    // retry).
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Soft-delete the user row + nullify PII. The WHERE status<>'deleted'
      // makes this a no-op-safe re-issue (idempotency at the SQL layer too).
      const { rowCount: softCount } = await client.query(
        `UPDATE users
            SET status                   = 'deleted',
                email                    = NULL,
                name                     = NULL,
                username                 = NULL,
                public_key               = NULL,
                apple_id                 = NULL,
                admin_signing_public_key = NULL,
                locked_device_id         = NULL,
                deleted_at               = NOW(),
                deleted_by_user_id       = $2,
                updated_at               = NOW()
          WHERE id = $1 AND status <> 'deleted'`,
        [req.params.id, req.user.id]
      );
      if (softCount === 0) {
        await client.query('ROLLBACK');
        return res.status(404).json({ error: 'User not found' });
      }

      // Revoke active access sessions. We can't CASCADE-delete auth_sessions
      // (the user row is staying), so flip revoked_at instead — both
      // jwtAuth.loadSessionValidity and audit reads treat revoked sessions
      // as inactive.
      await client.query(
        `UPDATE auth_sessions SET revoked_at = NOW()
          WHERE user_id = $1 AND revoked_at IS NULL`,
        [req.params.id]
      );

      // Hard-delete devices. CASCADE chain takes care of:
      //   device_static_ips, device_attestations, device_postures
      // and via peers_meta.device_id ON DELETE SET NULL — that NULL gets
      // mopped up immediately below.
      await client.query('DELETE FROM devices WHERE user_id = $1', [req.params.id]);

      // Live relationships — gone now that the user is terminated. Each is
      // a small targeted DELETE to avoid relying on CASCADE chains we don't
      // own.
      await client.query('DELETE FROM user_server_assignments WHERE user_id = $1', [req.params.id]);
      await client.query('DELETE FROM user_enterprise_roles    WHERE user_id = $1', [req.params.id]);
      await client.query('DELETE FROM user_group_members       WHERE user_id = $1', [req.params.id]);
      await client.query('DELETE FROM application_server_users WHERE user_id = $1', [req.params.id]);
      await client.query('DELETE FROM root_users               WHERE user_id = $1', [req.params.id]);
      await client.query('DELETE FROM attest_challenges        WHERE user_id = $1', [req.params.id]);

      // peers_meta orphan cleanup — at this point any pm.user_id matching
      // the deleted user is NULL (FK SET NULL) and pm.device_id is also NULL
      // (devices CASCADE just fired). The composite (server_id,iface,pubkey)
      // we captured above is the safe identifier.
      if (peerRows.length > 0) {
        await client.query(
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

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // Resync rules per affected server — best-effort, post-commit. A single
    // failing server doesn't unwind the delete (user is already terminated;
    // retry would 404). Errors are logged for ops follow-up.
    //
    // resyncRulesByUsers internally chains policy resync via current
    // membership query — but route_policy_users / user_group_members
    // rows for this user are already gone by now, so it'd miss the
    // affected policies. We use the pre-cascade snapshot instead.
    const { resyncPoliciesByIds } = require('../../services/policyResync');
    const policiesByServer = new Map();        // serverId → [policyId,...]
    const removedNamesByServer = new Map();    // serverId → [policyName,...] for type='device' (CASCADE-deleted)
    for (const ps of policySnapshot) {
      if (ps.ingress_type === 'device') {
        if (!removedNamesByServer.has(ps.server_id)) removedNamesByServer.set(ps.server_id, []);
        removedNamesByServer.get(ps.server_id).push(ps.name);
      } else {
        if (!policiesByServer.has(ps.server_id)) policiesByServer.set(ps.server_id, []);
        policiesByServer.get(ps.server_id).push(ps.id);
      }
    }
    const allPolicyServers = new Set([...policiesByServer.keys(), ...removedNamesByServer.keys()]);
    await Promise.allSettled(
      affectedServerIds.map(async sid => {
        try {
          await resyncRulesByUsers(sid, [req.params.id]);
        } catch (e) {
          console.warn(`[users/delete] resyncRulesByUsers failed for server=${sid}: ${e.message}`);
        }
      })
    );
    await Promise.allSettled(
      [...allPolicyServers].map(async sid => {
        try {
          await resyncPoliciesByIds(
            sid,
            policiesByServer.get(sid) || [],
            removedNamesByServer.get(sid) || []
          );
        } catch (e) {
          console.warn(`[users/delete] resyncPoliciesByIds failed for server=${sid}: ${e.message}`);
        }
      })
    );

    res.json({ deleted: true, soft: true });
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
