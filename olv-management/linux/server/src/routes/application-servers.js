// Admin CRUD for Application Servers — per-VPN-server scope.
//
// An Application Server is a registry entry under one VPN server,
// describing an internal service (port + target) that some users/groups
// are entitled to access while VPN'd in. Three target shapes:
//   - ip      → static internal IP (e.g. 10.88.0.5)
//   - user    → resolves at /api/connect time to that user's most
//               recently connected device's peer IP on this server
//   - device  → direct device → peer IP lookup
//
// JSON convention: snake_case on the wire (per repo-wide rule).
const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');
const { syncAppServerFirewall, removeAppServerRules } = require('../services/appServerFirewall');
const { isAdmin } = require('../constants/roles');
const { requireAdmin } = require('../middleware/serverAccess');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

const TARGET_COLS = ['ip', 'target_user_id', 'target_device_id'];

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

/** Validate body for target_type + matching reference field. Returns
 *  { target_type, ip, target_user_id, target_device_id } with the
 *  unused fields nulled out, or throws status-tagged Error. */
function pickTarget(body) {
  const t = body.target_type || 'ip';
  if (!['ip', 'user', 'device'].includes(t)) {
    throw Object.assign(new Error("target_type must be one of: ip, user, device"), { status: 400 });
  }
  const out = { target_type: t, ip: null, target_user_id: null, target_device_id: null };
  if (t === 'ip') {
    if (!body.ip) throw Object.assign(new Error('ip is required when target_type=ip'), { status: 400 });
    out.ip = body.ip;
  } else if (t === 'user') {
    if (!body.target_user_id) throw Object.assign(new Error('target_user_id is required when target_type=user'), { status: 400 });
    out.target_user_id = body.target_user_id;
  } else if (t === 'device') {
    if (!body.target_device_id) throw Object.assign(new Error('target_device_id is required when target_type=device'), { status: 400 });
    out.target_device_id = body.target_device_id;
  }
  return out;
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

function shapeRow(r, acl) {
  // Stringify INET so iOS APIClient gets a string, not a Postgres-typed
  // marker.
  return {
    id: r.id,
    server_id: r.server_id,
    name: r.name,
    description: r.description,
    target_type: r.target_type,
    // Strip the /32 (or /128 for IPv6) mask that Postgres' INET text
    // representation appends — admin/iOS expect a bare host address.
    ip: r.ip ? String(r.ip).split('/')[0] : null,
    target_user_id: r.target_user_id,
    target_device_id: r.target_device_id,
    port: r.port,
    protocol: r.protocol,
    enabled: r.enabled,
    created_at: r.created_at,
    updated_at: r.updated_at,
    user_ids: acl?.users?.[r.id] || [],
    group_ids: acl?.groups?.[r.id] || [],
  };
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
      application_servers: rows.map(r => shapeRow(r, acl)),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    if (!b.port) return res.status(400).json({ error: 'port is required' });
    const target = pickTarget(b);
    const protocol = b.protocol || 'tcp';
    if (!['tcp', 'udp', 'tcp+udp'].includes(protocol)) {
      return res.status(400).json({ error: 'protocol must be one of: tcp, udp, tcp+udp' });
    }

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      const { rows } = await dbClient.query(
        `INSERT INTO application_servers
           (server_id, name, description, target_type, ip, target_user_id, target_device_id, port, protocol, enabled)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [req.params.serverId, b.name, b.description || null,
         target.target_type, target.ip, target.target_user_id, target.target_device_id,
         b.port, protocol, b.enabled === undefined ? true : !!b.enabled]
      );
      await writeAcl(dbClient, rows[0].id, b.user_ids, b.group_ids);
      await dbClient.query('COMMIT');
      // Push agent firewall rules opening this app's port for granted
      // users. Best-effort — failure is logged but the DB row stays
      // (admin can retry by toggling enabled).
      syncAppServerFirewall(rows[0].id).catch(err =>
        console.error(`[application-servers] firewall sync app=${rows[0].id} failed:`, err.message)
      );
      const acl = { users: { [rows[0].id]: b.user_ids || [] }, groups: { [rows[0].id]: b.group_ids || [] } };
      res.status(201).json(shapeRow(rows[0], acl));
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') {
        return res.status(409).json({ error: `name "${b.name}" already exists on this server` });
      }
      if (dbErr.code === '22P02') return res.status(400).json({ error: 'ip is not a valid INET' });
      if (dbErr.code === '23514') return res.status(400).json({ error: dbErr.message });
      if (dbErr.code === '23503') return res.status(400).json({ error: 'target user/device does not exist' });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    sendError(res, err, req);
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
    const cols = ['name', 'description', 'port', 'protocol', 'enabled'];
    for (const c of cols) {
      if (req.body[c] === undefined) continue;
      if (c === 'protocol' && !['tcp', 'udp', 'tcp+udp'].includes(req.body[c])) {
        return res.status(400).json({ error: 'protocol must be one of: tcp, udp, tcp+udp' });
      }
      set.push(`${c} = $${idx++}`);
      vals.push(req.body[c]);
    }
    // Target type change: if any of (target_type, ip, target_user_id, target_device_id)
    // is touched, reset all 4 atomically based on new shape.
    const targetTouched = req.body.target_type !== undefined
      || TARGET_COLS.some(c => req.body[c] !== undefined);
    if (targetTouched) {
      const merged = {
        target_type: req.body.target_type ?? existing[0].target_type,
        ip: req.body.ip ?? existing[0].ip,
        target_user_id: req.body.target_user_id ?? existing[0].target_user_id,
        target_device_id: req.body.target_device_id ?? existing[0].target_device_id,
      };
      const shaped = pickTarget(merged);
      set.push(`target_type = $${idx++}`);      vals.push(shaped.target_type);
      set.push(`ip = $${idx++}`);                vals.push(shaped.ip);
      set.push(`target_user_id = $${idx++}`);    vals.push(shaped.target_user_id);
      set.push(`target_device_id = $${idx++}`);  vals.push(shaped.target_device_id);
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
      // Re-sync agent firewall rules — covers target/port/enabled and
      // ACL changes (any of which alters the rule set).
      syncAppServerFirewall(row.id).catch(err =>
        console.error(`[application-servers] firewall sync app=${row.id} failed:`, err.message)
      );
      const acl = await loadAcl([row.id]);
      res.json(shapeRow(row, acl));
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23505') return res.status(409).json({ error: 'name conflict on this server' });
      if (dbErr.code === '22P02') return res.status(400).json({ error: 'ip is not a valid INET' });
      if (dbErr.code === '23514') return res.status(400).json({ error: dbErr.message });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    sendError(res, err, req);
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
    // Tear down agent firewall rules that were opened for this app.
    removeAppServerRules(parseInt(req.params.serverId), parseInt(req.params.id))
      .catch(err => console.error(`[application-servers] firewall cleanup app=${req.params.id} failed:`, err.message));
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
