// Admin CRUD for server-scoped client local port forwards (M6).
//
// These mappings travel to VPN clients via app-api's /api/connect response.
// Unlike port-forwards (M3 rdr rules on the agent), there is NO agent call
// here — purely management state. The client's Packet Tunnel Extension
// consumes the list.
//
// M6.1 — per-mapping ACL. Each row has `visibility` in {'all','users','groups'}
// plus optional pivot rows in server_local_port_forward_users /
// server_local_port_forward_groups. The app-api /api/connect filter
// honours these so users only see mappings they're entitled to.
const { Router } = require('express');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode, enterprise_id FROM servers WHERE id = $1', [serverId])
    : await pool.query('SELECT id, access_mode, enterprise_id FROM servers WHERE id = $1 AND enterprise_id = $2', [serverId, req.enterpriseId]);
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

function normaliseVisibility(v) {
  if (v === undefined || v === null || v === '') return 'all';
  if (!['all', 'users', 'groups'].includes(v)) {
    throw Object.assign(new Error('visibility must be all/users/groups'), { status: 400 });
  }
  return v;
}

// Replace pivot rows for a mapping in one transaction. For visibility 'all'
// both pivots are cleared — keeps the DB tidy (no dangling grants).
async function writeMembers(dbClient, portForwardId, visibility, userIds, groupIds) {
  await dbClient.query('DELETE FROM server_local_port_forward_users WHERE port_forward_id = $1', [portForwardId]);
  await dbClient.query('DELETE FROM server_local_port_forward_groups WHERE port_forward_id = $1', [portForwardId]);
  if (visibility === 'users' && Array.isArray(userIds)) {
    for (const uid of userIds) {
      await dbClient.query(
        'INSERT INTO server_local_port_forward_users (port_forward_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [portForwardId, uid]
      );
    }
  }
  if (visibility === 'groups' && Array.isArray(groupIds)) {
    for (const gid of groupIds) {
      await dbClient.query(
        'INSERT INTO server_local_port_forward_groups (port_forward_id, user_group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
        [portForwardId, gid]
      );
    }
  }
}

async function loadMembers(portForwardIds) {
  if (portForwardIds.length === 0) return { usersByMapping: {}, groupsByMapping: {} };
  const { rows: uRows } = await pool.query(
    `SELECT port_forward_id, user_id FROM server_local_port_forward_users WHERE port_forward_id = ANY($1::int[])`,
    [portForwardIds]
  );
  const { rows: gRows } = await pool.query(
    `SELECT port_forward_id, user_group_id FROM server_local_port_forward_groups WHERE port_forward_id = ANY($1::int[])`,
    [portForwardIds]
  );
  const usersByMapping = {};
  const groupsByMapping = {};
  for (const r of uRows) {
    (usersByMapping[r.port_forward_id] ||= []).push(r.user_id);
  }
  for (const r of gRows) {
    (groupsByMapping[r.port_forward_id] ||= []).push(r.user_group_id);
  }
  return { usersByMapping, groupsByMapping };
}

router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM server_local_port_forwards WHERE server_id = $1 ORDER BY local_port',
      [req.params.serverId]
    );
    const { usersByMapping, groupsByMapping } = await loadMembers(rows.map(r => r.id));
    const enriched = rows.map(r => ({
      ...r,
      userIds: usersByMapping[r.id] || [],
      groupIds: groupsByMapping[r.id] || [],
    }));
    res.json({ mappings: enriched });
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
    if (!b.localPort) return res.status(400).json({ error: 'localPort is required' });
    if (!b.remoteHost) return res.status(400).json({ error: 'remoteHost is required' });
    if (!b.remotePort) return res.status(400).json({ error: 'remotePort is required' });
    const visibility = normaliseVisibility(b.visibility);

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      const { rows } = await dbClient.query(
        `INSERT INTO server_local_port_forwards
           (server_id, name, local_port, remote_host, remote_port, description, enabled, visibility)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
        [req.params.serverId, b.name, b.localPort, b.remoteHost, b.remotePort,
         b.description || null, b.enabled === undefined ? true : !!b.enabled, visibility]
      );
      await writeMembers(dbClient, rows[0].id, visibility, b.userIds, b.groupIds);
      await dbClient.query('COMMIT');
      res.status(201).json({
        ...rows[0],
        userIds: visibility === 'users' ? (b.userIds || []) : [],
        groupIds: visibility === 'groups' ? (b.groupIds || []) : [],
      });
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') return res.status(409).json({ error: `local_port ${b.localPort} already mapped on this server` });
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

    const { rows: existingRows } = await pool.query(
      'SELECT * FROM server_local_port_forwards WHERE id = $1 AND server_id = $2',
      [req.params.id, req.params.serverId]
    );
    if (existingRows.length === 0) return res.status(404).json({ error: 'Mapping not found' });

    const set = [];
    const vals = [];
    let idx = 1;
    const mapping = [
      ['name', 'name'],
      ['local_port', 'localPort'],
      ['remote_host', 'remoteHost'],
      ['remote_port', 'remotePort'],
      ['description', 'description'],
      ['enabled', 'enabled'],
    ];
    for (const [col, camel] of mapping) {
      if (req.body[camel] === undefined) continue;
      set.push(`${col} = $${idx++}`);
      vals.push(req.body[camel]);
    }

    // ACL fields — always rewrite pivots when caller sent any of them
    // so a visibility switch (e.g. users → all) clears leftover grants.
    const aclTouched = req.body.visibility !== undefined
      || req.body.userIds !== undefined
      || req.body.groupIds !== undefined;
    let newVisibility;
    if (req.body.visibility !== undefined) {
      newVisibility = normaliseVisibility(req.body.visibility);
      set.push(`visibility = $${idx++}`);
      vals.push(newVisibility);
    } else {
      newVisibility = existingRows[0].visibility;
    }

    if (set.length === 0 && !aclTouched) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      let updated = existingRows[0];
      if (set.length > 0) {
        set.push('updated_at = NOW()');
        vals.push(req.params.id, req.params.serverId);
        const { rows } = await dbClient.query(
          `UPDATE server_local_port_forwards SET ${set.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
          vals
        );
        updated = rows[0];
      }
      if (aclTouched) {
        await writeMembers(dbClient, updated.id, newVisibility, req.body.userIds, req.body.groupIds);
      }
      await dbClient.query('COMMIT');
      const { usersByMapping, groupsByMapping } = await loadMembers([updated.id]);
      res.json({
        ...updated,
        userIds: usersByMapping[updated.id] || [],
        groupIds: groupsByMapping[updated.id] || [],
      });
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') return res.status(409).json({ error: 'local_port conflict' });
      if (dbErr.code === '23514') return res.status(400).json({ error: 'port out of range (1-65535)' });
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
      'DELETE FROM server_local_port_forwards WHERE id = $1 AND server_id = $2',
      [req.params.id, req.params.serverId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Mapping not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
