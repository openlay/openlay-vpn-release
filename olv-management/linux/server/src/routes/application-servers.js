// Admin CRUD for enterprise-scoped Application Servers (post-M6 redesign).
//
// Replaces the localhost-bind approach (036/037, dropped in 038). Today this
// route is just a registry: admin declares (ip, port) + ACL, users query
// their list via app-api /api/connect (default deny). Future work may wire
// agent-side firewall enforcement on top of these grants.
//
// JSON convention: snake_case on the wire (per repo-wide rule). Backend
// reads + emits snake_case keys directly.
const { Router } = require('express');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

function requireAdmin(req, res) {
  if (!['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) {
    res.status(403).json({ error: 'Admin access required' });
    return false;
  }
  return true;
}

// Ensure caller can act on the given enterprise. Root has free reign;
// non-root must match req.enterpriseId from middleware.
function verifyEnterpriseScope(req, res, enterpriseId) {
  if (req.enterpriseRole === 'root') return true;
  if (!enterpriseId) {
    res.status(403).json({ error: 'Root required for global apps' });
    return false;
  }
  if (enterpriseId !== req.enterpriseId) {
    res.status(403).json({ error: 'Cross-tenant access denied' });
    return false;
  }
  return true;
}

async function loadAcl(appIds) {
  if (appIds.length === 0) return { users: {}, groups: {} };
  const { rows: u } = await pool.query(
    `SELECT app_id, user_id FROM application_server_users WHERE app_id = ANY($1::int[])`,
    [appIds]
  );
  const { rows: g } = await pool.query(
    `SELECT app_id, user_group_id FROM application_server_groups WHERE app_id = ANY($1::int[])`,
    [appIds]
  );
  const users = {};
  const groups = {};
  for (const r of u) (users[r.app_id] ||= []).push(r.user_id);
  for (const r of g) (groups[r.app_id] ||= []).push(r.user_group_id);
  return { users, groups };
}

async function writeAcl(dbClient, appId, userIds, groupIds) {
  await dbClient.query('DELETE FROM application_server_users WHERE app_id = $1', [appId]);
  await dbClient.query('DELETE FROM application_server_groups WHERE app_id = $1', [appId]);
  if (Array.isArray(userIds)) {
    for (const uid of userIds) {
      await dbClient.query(
        'INSERT INTO application_server_users (app_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [appId, uid]
      );
    }
  }
  if (Array.isArray(groupIds)) {
    for (const gid of groupIds) {
      await dbClient.query(
        'INSERT INTO application_server_groups (app_id, user_group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [appId, gid]
      );
    }
  }
}

// GET /api/enterprises/:enterpriseId/application-servers
router.get('/', async (req, res) => {
  try {
    if (!verifyEnterpriseScope(req, res, req.params.enterpriseId)) return;
    const { rows } = await pool.query(
      'SELECT * FROM application_servers WHERE enterprise_id = $1 ORDER BY name',
      [req.params.enterpriseId]
    );
    const acl = await loadAcl(rows.map(r => r.id));
    res.json({
      application_servers: rows.map(r => ({
        ...r,
        user_ids: acl.users[r.id] || [],
        group_ids: acl.groups[r.id] || [],
      })),
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    if (!verifyEnterpriseScope(req, res, req.params.enterpriseId)) return;
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    if (!b.ip) return res.status(400).json({ error: 'ip is required' });
    if (!b.port) return res.status(400).json({ error: 'port is required' });
    if (!b.local_port) return res.status(400).json({ error: 'local_port is required' });

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      const { rows } = await dbClient.query(
        `INSERT INTO application_servers
           (enterprise_id, name, description, ip, port, local_port, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [req.params.enterpriseId, b.name, b.description || null,
         b.ip, b.port, b.local_port,
         b.enabled === undefined ? true : !!b.enabled]
      );
      await writeAcl(dbClient, rows[0].id, b.user_ids, b.group_ids);
      await dbClient.query('COMMIT');
      res.status(201).json({
        ...rows[0],
        user_ids: b.user_ids || [],
        group_ids: b.group_ids || [],
      });
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') {
        // Disambiguate which UNIQUE failed for a clearer message.
        const isPort = String(dbErr.detail || '').includes('local_port');
        return res.status(409).json({
          error: isPort ? `local_port ${b.local_port} already used in this enterprise`
                        : `name "${b.name}" already exists in this enterprise`,
        });
      }
      if (dbErr.code === '22P02') return res.status(400).json({ error: 'ip is not a valid INET' });
      if (dbErr.code === '23514') return res.status(400).json({ error: 'port out of range (1-65535)' });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.put('/:id', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    if (!verifyEnterpriseScope(req, res, req.params.enterpriseId)) return;
    const { rows: existing } = await pool.query(
      'SELECT * FROM application_servers WHERE id = $1 AND enterprise_id = $2',
      [req.params.id, req.params.enterpriseId]
    );
    if (existing.length === 0) return res.status(404).json({ error: 'Application server not found' });

    const set = [];
    const vals = [];
    let idx = 1;
    const cols = ['name', 'description', 'ip', 'port', 'local_port', 'enabled'];
    for (const c of cols) {
      if (req.body[c] === undefined) continue;
      set.push(`${c} = $${idx++}`);
      vals.push(req.body[c]);
    }
    const aclTouched = req.body.user_ids !== undefined || req.body.group_ids !== undefined;
    if (set.length === 0 && !aclTouched) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      let row = existing[0];
      if (set.length > 0) {
        set.push('updated_at = NOW()');
        vals.push(req.params.id, req.params.enterpriseId);
        const { rows } = await dbClient.query(
          `UPDATE application_servers SET ${set.join(', ')}
           WHERE id = $${idx++} AND enterprise_id = $${idx} RETURNING *`,
          vals
        );
        row = rows[0];
      }
      if (aclTouched) {
        await writeAcl(dbClient, row.id, req.body.user_ids, req.body.group_ids);
      }
      await dbClient.query('COMMIT');
      const acl = await loadAcl([row.id]);
      res.json({ ...row, user_ids: acl.users[row.id] || [], group_ids: acl.groups[row.id] || [] });
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') return res.status(409).json({ error: 'name or local_port conflict' });
      if (dbErr.code === '22P02') return res.status(400).json({ error: 'ip is not a valid INET' });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

router.delete('/:id', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    if (!verifyEnterpriseScope(req, res, req.params.enterpriseId)) return;
    const { rowCount } = await pool.query(
      'DELETE FROM application_servers WHERE id = $1 AND enterprise_id = $2',
      [req.params.id, req.params.enterpriseId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Application server not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
