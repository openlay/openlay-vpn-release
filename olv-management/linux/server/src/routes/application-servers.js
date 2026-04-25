// Admin CRUD for Application Servers — per-VPN-server scope.
//
// An Application Server is a registry entry under one VPN server,
// describing an internal IP:port that some users/groups are entitled
// to access while VPN'd in. The parent server defines which subnet
// the IP lives in, so the (ip, port) is only meaningful in that
// context. ACL grants are scoped to the server's enterprise (or any
// user/group caller can name when they're root).
//
// JSON convention: snake_case on the wire (per repo-wide rule).
const { Router } = require('express');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode, enterprise_id FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        'SELECT id, access_mode, enterprise_id FROM servers WHERE id = $1 AND enterprise_id = $2',
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) throw Object.assign(new Error('Root required'), { status: 403 });
  return rows[0];
}

function requireAdmin(req, res) {
  if (!['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) {
    res.status(403).json({ error: 'Admin access required' });
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
  // Either array (incl. empty) means "replace this side". Undefined means leave alone.
  if (Array.isArray(userIds)) {
    await dbClient.query('DELETE FROM application_server_users WHERE app_id = $1', [appId]);
    for (const uid of userIds) {
      await dbClient.query(
        'INSERT INTO application_server_users (app_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [appId, uid]
      );
    }
  }
  if (Array.isArray(groupIds)) {
    await dbClient.query('DELETE FROM application_server_groups WHERE app_id = $1', [appId]);
    for (const gid of groupIds) {
      await dbClient.query(
        'INSERT INTO application_server_groups (app_id, user_group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [appId, gid]
      );
    }
  }
}

// GET /api/servers/:serverId/application-servers
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM application_servers WHERE server_id = $1 ORDER BY name',
      [req.params.serverId]
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
    await verifyAccess(req.params.serverId, req);
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
           (server_id, name, description, ip, port, local_port, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
        [req.params.serverId, b.name, b.description || null,
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
        const isPort = String(dbErr.detail || '').includes('local_port');
        return res.status(409).json({
          error: isPort ? `local_port ${b.local_port} already used on this server`
                        : `name "${b.name}" already exists on this server`,
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
    await verifyAccess(req.params.serverId, req);
    const { rows: existing } = await pool.query(
      'SELECT * FROM application_servers WHERE id = $1 AND server_id = $2',
      [req.params.id, req.params.serverId]
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
        vals.push(req.params.id, req.params.serverId);
        const { rows } = await dbClient.query(
          `UPDATE application_servers SET ${set.join(', ')}
           WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
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
    await verifyAccess(req.params.serverId, req);
    const { rowCount } = await pool.query(
      'DELETE FROM application_servers WHERE id = $1 AND server_id = $2',
      [req.params.id, req.params.serverId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Application server not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
