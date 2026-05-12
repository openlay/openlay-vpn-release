// Route policy CRUD with typed ingress (M2 + 046 typed pickers).
//
// Ingress shape:
//   - custom → admin types `ingress_iface` + `src_cidr` (existing behavior)
//   - users  → 1+ user IDs in pivot table; resolved to peer IPs at push
//   - group  → user_groups membership → peer IPs
//   - device → single device → peer IP
//
// At POST/PUT, management resolves the typed ref into (srcCIDR, ingressIface)
// and feeds those to agent's `routerAddPolicy` — agent contract unchanged.
// On peer connect/disconnect, hook in resyncRulesByUsers triggers a
// re-resolve + agent update so live pf state stays current.
//
// Body accepts BOTH camelCase and snake_case keys (existing convention
// per /api/snake_case rule + nat.js precedent — iOS sends snake_case
// via APIClient's convertToSnakeCase encoder).
const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');
const { resolvePolicyIngress } = require('../services/targetResolvers');
const { isAdmin } = require('../constants/roles');
const { requireAdmin } = require('../middleware/serverAccess');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

// Pull a key out of body trying camelCase first then snake_case.
function get(b, camel, snake) { return b[camel] !== undefined ? b[camel] : b[snake]; }

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode FROM servers WHERE id = $1', [serverId])
    : await pool.query('SELECT id, access_mode FROM servers WHERE id = $1 AND enterprise_id = $2', [serverId, req.enterpriseId]);
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) throw Object.assign(new Error('Root required'), { status: 403 });
}

function pickIngress(b) {
  const t = get(b, 'ingressType', 'ingress_type') || 'custom';
  if (!['custom', 'users', 'group', 'device'].includes(t)) {
    throw Object.assign(new Error('ingress_type must be one of: custom, users, group, device'), { status: 400 });
  }
  const out = {
    ingress_type: t,
    ingress_iface: null,
    src_cidr: null,
    ingress_user_ids: null,
    ingress_group_id: null,
    ingress_device_id: null,
  };
  if (t === 'custom') {
    out.ingress_iface = get(b, 'ingressIface', 'ingress_iface') || null;
    out.src_cidr      = get(b, 'srcCIDR', 'src_cidr') || null;
  } else if (t === 'users') {
    const ids = get(b, 'ingressUserIds', 'ingress_user_ids');
    if (!Array.isArray(ids) || ids.length === 0) {
      throw Object.assign(new Error('ingress_user_ids must be a non-empty array when ingress_type=users'), { status: 400 });
    }
    out.ingress_user_ids = ids;
  } else if (t === 'group') {
    const gid = get(b, 'ingressGroupId', 'ingress_group_id');
    if (!gid) throw Object.assign(new Error('ingress_group_id is required when ingress_type=group'), { status: 400 });
    out.ingress_group_id = gid;
  } else if (t === 'device') {
    const did = get(b, 'ingressDeviceId', 'ingress_device_id');
    if (!did) throw Object.assign(new Error('ingress_device_id is required when ingress_type=device'), { status: 400 });
    out.ingress_device_id = did;
  }
  return out;
}

async function loadIngressUserIds(policyIds) {
  if (policyIds.length === 0) return {};
  const { rows } = await pool.query(
    'SELECT policy_id, user_id FROM route_policy_users WHERE policy_id = ANY($1::int[])',
    [policyIds]
  );
  const out = {};
  for (const r of rows) (out[r.policy_id] ||= []).push(r.user_id);
  return out;
}

async function writeIngressUserIds(dbClient, policyId, userIds) {
  if (!Array.isArray(userIds)) return;
  await dbClient.query('DELETE FROM route_policy_users WHERE policy_id = $1', [policyId]);
  for (const uid of userIds) {
    await dbClient.query(
      'INSERT INTO route_policy_users (policy_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [policyId, uid]
    );
  }
}

function shapeRow(r, ingressUserIds) {
  return {
    id: r.id,
    server_id: r.server_id,
    name: r.name,
    priority: r.priority,
    ingress_type: r.ingress_type,
    ingress_iface: r.ingress_iface,
    src_cidr: r.src_cidr,
    ingress_user_ids: ingressUserIds?.[r.id] || [],
    ingress_group_id: r.ingress_group_id,
    ingress_device_id: r.ingress_device_id,
    dst_cidr: r.dst_cidr,
    protocol: r.protocol,
    dst_port_start: r.dst_port_start,
    dst_port_end: r.dst_port_end,
    fib: r.fib,
    action: r.action,
    gateway: r.gateway,
    gateway_iface: r.gateway_iface,
    description: r.description,
    enabled: r.enabled,
    created_at: r.created_at,
    updated_at: r.updated_at,
  };
}

// GET /api/servers/:serverId/route-policies
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query(
      'SELECT * FROM route_policies WHERE server_id = $1 ORDER BY priority, id',
      [req.params.serverId]
    );
    const ingressMap = await loadIngressUserIds(rows.map(r => r.id));
    res.json({ policies: rows.map(r => shapeRow(r, ingressMap)) });
  } catch (err) {
    sendError(res, err, req);
  }
});

router.get('/fib', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const client = new AgentClient(parseInt(req.params.serverId));
    const info = await client.routerGetFibInfo();
    res.json(info);
  } catch (err) {
    sendError(res, err, req);
  }
});

router.get('/live', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const client = new AgentClient(parseInt(req.params.serverId));
    const out = await client.routerListLivePolicies();
    res.json(out);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/route-policies
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const b = req.body || {};
    if (!b.name) return res.status(400).json({ error: 'name is required' });
    const gatewayIface = get(b, 'gatewayIface', 'gateway_iface');
    if (!gatewayIface) return res.status(400).json({ error: 'gateway_iface is required' });
    const ingress = pickIngress(b);

    const dbClient = await pool.connect();
    let dbInserted = null;
    let agentPolicy = null;
    try {
      await dbClient.query('BEGIN');
      const { rows } = await dbClient.query(
        `INSERT INTO route_policies (
           server_id, name, priority, ingress_type, ingress_iface, src_cidr, dst_cidr,
           protocol, dst_port_start, dst_port_end, fib, action,
           gateway, gateway_iface, description, enabled,
           ingress_group_id, ingress_device_id
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
         RETURNING *`,
        [
          req.params.serverId, b.name, b.priority || 100,
          ingress.ingress_type, ingress.ingress_iface, ingress.src_cidr,
          get(b, 'dstCIDR', 'dst_cidr') || null,
          b.protocol || null,
          get(b, 'dstPortStart', 'dst_port_start') || null,
          get(b, 'dstPortEnd', 'dst_port_end') || null,
          b.fib || 0,
          b.action || 'route-to',
          b.gateway || null,
          gatewayIface,
          b.description || null,
          b.enabled === undefined ? true : !!b.enabled,
          ingress.ingress_group_id, ingress.ingress_device_id,
        ]
      );
      dbInserted = rows[0];
      await writeIngressUserIds(dbClient, dbInserted.id, ingress.ingress_user_ids);

      // Resolve typed ingress → concrete (srcCIDR, ingressIface) for agent.
      const policyForResolve = {
        ...dbInserted,
        // resolveUserIds reads fresh — we passed dbClient in for tx visibility.
      };
      const resolved = await resolvePolicyIngress(policyForResolve, parseInt(req.params.serverId), dbClient);
      // Skip agent push when typed ingress resolves to no IPs — pushing
      // srcCIDR='' would render as "from any" in pf and silently match
      // all traffic. Policy stays in DB; resync (peer connect hook) will
      // ADD the rule once a referenced user comes online.
      const hasMatch = resolved.resolvedIPs.length > 0 || dbInserted.ingress_type === 'custom';
      if (hasMatch) {
        agentPolicy = await new AgentClient(parseInt(req.params.serverId)).routerAddPolicy({
          name: dbInserted.name,
          priority: dbInserted.priority,
          ingressIface: resolved.ingressIface,
          srcCIDR: resolved.srcCIDR,
          dstCIDR: dbInserted.dst_cidr || '',
          protocol: dbInserted.protocol || '',
          dstPortStart: dbInserted.dst_port_start || 0,
          dstPortEnd: dbInserted.dst_port_end || 0,
          fib: dbInserted.fib,
          action: dbInserted.action,
          gatewayIface: dbInserted.gateway_iface,
          gateway: dbInserted.gateway || '',
          description: dbInserted.description || '',
          enabled: dbInserted.enabled,
        });
      }
      await dbClient.query('COMMIT');

      const ingressMap = ingress.ingress_user_ids
        ? { [dbInserted.id]: ingress.ingress_user_ids }
        : {};
      res.status(201).json({ ...shapeRow(dbInserted, ingressMap), agent_id: agentPolicy?.id });
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      // Compensate agent if DB write succeeded but something later threw.
      // (In practice agent push is the last step; rollback only matters
      // when COMMIT itself fails — rare but safe to handle.)
      if (agentPolicy?.id) {
        try { await new AgentClient(parseInt(req.params.serverId)).routerRemovePolicy(agentPolicy.id); } catch {}
      }
      if (dbErr.code === '23505') return res.status(409).json({ error: 'Policy name already exists on this server' });
      if (dbErr.code === '23514') return res.status(400).json({ error: dbErr.message });
      if (dbErr.code === '23503') return res.status(400).json({ error: 'Referenced user/group/device does not exist' });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    sendError(res, err, req);
  }
});

// PUT /api/servers/:serverId/route-policies/:policyId
router.put('/:policyId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows: existingRows } = await pool.query(
      'SELECT * FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]
    );
    if (existingRows.length === 0) return res.status(404).json({ error: 'Policy not found' });
    const existing = existingRows[0];

    const b = req.body || {};
    const setFields = [];
    const values = [];
    let idx = 1;
    const cols = [
      ['priority',       b.priority],
      ['dst_cidr',       get(b, 'dstCIDR', 'dst_cidr')],
      ['protocol',       b.protocol],
      ['dst_port_start', get(b, 'dstPortStart', 'dst_port_start')],
      ['dst_port_end',   get(b, 'dstPortEnd', 'dst_port_end')],
      ['fib',            b.fib],
      ['action',         b.action],
      ['gateway',        b.gateway],
      ['gateway_iface',  get(b, 'gatewayIface', 'gateway_iface')],
      ['description',    b.description],
      ['enabled',        b.enabled],
    ];
    for (const [col, val] of cols) {
      if (val === undefined) continue;
      setFields.push(`${col} = $${idx++}`);
      values.push(val);
    }

    // Ingress retype: if body touches any ingress_* field, recompute the
    // whole ingress block atomically with pickIngress() — same approach
    // as application-servers target_type retype.
    const ingressTouched = ['ingressType','ingress_type','ingressIface','ingress_iface',
                            'srcCIDR','src_cidr','ingressUserIds','ingress_user_ids',
                            'ingressGroupId','ingress_group_id','ingressDeviceId','ingress_device_id']
                           .some(k => b[k] !== undefined);
    let ingressShape = null;
    if (ingressTouched) {
      // Merge body onto existing then re-validate.
      ingressShape = pickIngress({
        ingress_type: get(b, 'ingressType', 'ingress_type') ?? existing.ingress_type,
        ingress_iface: get(b, 'ingressIface', 'ingress_iface') ?? existing.ingress_iface,
        src_cidr: get(b, 'srcCIDR', 'src_cidr') ?? existing.src_cidr,
        ingress_user_ids: get(b, 'ingressUserIds', 'ingress_user_ids'),
        ingress_group_id: get(b, 'ingressGroupId', 'ingress_group_id') ?? existing.ingress_group_id,
        ingress_device_id: get(b, 'ingressDeviceId', 'ingress_device_id') ?? existing.ingress_device_id,
      });
      setFields.push(`ingress_type = $${idx++}`);     values.push(ingressShape.ingress_type);
      setFields.push(`ingress_iface = $${idx++}`);    values.push(ingressShape.ingress_iface);
      setFields.push(`src_cidr = $${idx++}`);         values.push(ingressShape.src_cidr);
      setFields.push(`ingress_group_id = $${idx++}`); values.push(ingressShape.ingress_group_id);
      setFields.push(`ingress_device_id = $${idx++}`);values.push(ingressShape.ingress_device_id);
    }

    if (setFields.length === 0 && !ingressTouched) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      let row = existing;
      if (setFields.length > 0) {
        setFields.push('updated_at = NOW()');
        values.push(req.params.policyId, req.params.serverId);
        const { rows } = await dbClient.query(
          `UPDATE route_policies SET ${setFields.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
          values
        );
        row = rows[0];
      }
      if (ingressShape && ingressShape.ingress_type === 'users') {
        await writeIngressUserIds(dbClient, row.id, ingressShape.ingress_user_ids);
      } else if (ingressShape) {
        // Cleared back to non-users — drop pivot rows.
        await dbClient.query('DELETE FROM route_policy_users WHERE policy_id = $1', [row.id]);
      }
      await dbClient.query('COMMIT');

      // Re-sync agent via remove+add (same pattern as policyResync).
      // Update-in-place would push srcCIDR='' for offline typed refs,
      // and pf renderer turns that into "from any" — silently routing
      // every packet through this policy's gateway. Remove+add gives
      // clean state: no rule when nothing to match, fresh rule when
      // there is.
      try {
        const resolved = await resolvePolicyIngress(row, parseInt(req.params.serverId));
        const client = new AgentClient(parseInt(req.params.serverId));
        const list = await client.routerListPolicies();
        const onAgent = (list.policies || []).find(p => p.name === row.name);
        if (onAgent) await client.routerRemovePolicy(onAgent.id);
        const hasMatch = resolved.resolvedIPs.length > 0 || row.ingress_type === 'custom';
        if (hasMatch) {
          await client.routerAddPolicy({
            name: row.name,
            priority: row.priority,
            ingressIface: resolved.ingressIface,
            srcCIDR: resolved.srcCIDR,
            dstCIDR: row.dst_cidr || '',
            protocol: row.protocol || '',
            dstPortStart: row.dst_port_start || 0,
            dstPortEnd: row.dst_port_end || 0,
            fib: row.fib,
            action: row.action,
            gateway: row.gateway || '',
            gatewayIface: row.gateway_iface,
            description: row.description || '',
            enabled: row.enabled,
          });
        }
      } catch (syncErr) {
        console.error(`[route-policies] agent sync failed:`, syncErr.message);
      }
      const ingressMap = await loadIngressUserIds([row.id]);
      res.json(shapeRow(row, ingressMap));
    } catch (dbErr) {
      await dbClient.query('ROLLBACK').catch(() => {});
      if (dbErr.code === '23514') return res.status(400).json({ error: dbErr.message });
      if (dbErr.code === '23503') return res.status(400).json({ error: 'Referenced user/group/device does not exist' });
      throw dbErr;
    } finally {
      dbClient.release();
    }
  } catch (err) {
    sendError(res, err, req);
  }
});

router.delete('/:policyId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows: existing } = await pool.query(
      'SELECT * FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]
    );
    if (existing.length === 0) return res.status(404).json({ error: 'Policy not found' });
    const row = existing[0];

    const client = new AgentClient(parseInt(req.params.serverId));
    try {
      const list = await client.routerListPolicies();
      const match = (list.policies || []).find(p => p.name === row.name);
      if (match) await client.routerRemovePolicy(match.id);
    } catch (err) {
      console.error(`[route-policies] agent delete failed (keeping DB change):`, err.message);
    }
    await pool.query('DELETE FROM route_policies WHERE id = $1 AND server_id = $2',
      [req.params.policyId, req.params.serverId]);
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
