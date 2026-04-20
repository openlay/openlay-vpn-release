const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { resyncRulesByZone } = require('../services/ruleOrchestrator');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

// Built-in zone names (auto-created per server)
const BUILTIN_ZONES = ['any', 'vpn-peers', 'wan'];

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode FROM servers WHERE id = $1', [serverId])
    : await pool.query('SELECT id, access_mode FROM servers WHERE id = $1 AND enterprise_id = $2', [serverId, req.enterpriseId]);
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) throw Object.assign(new Error('Root required for public server'), { status: 403 });
  return rows[0];
}

function requireAdmin(req, res) {
  if (!['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) {
    res.status(403).json({ error: 'Admin access required' });
    return false;
  }
  return true;
}

// Ensure built-in zones exist for a server
async function ensureBuiltinZones(serverId) {
  for (const name of BUILTIN_ZONES) {
    await pool.query(
      `INSERT INTO firewall_zones (server_id, name, description, builtin)
       VALUES ($1, $2, $3, TRUE)
       ON CONFLICT (server_id, name) DO NOTHING`,
      [serverId, name, getBuiltinDescription(name)]
    );
  }
}

function getBuiltinDescription(name) {
  switch (name) {
    case 'any': return 'All traffic (0.0.0.0/0)';
    case 'vpn-peers': return 'All VPN peer IPs (dynamic)';
    case 'wan': return 'Internet / non-VPN traffic';
    default: return '';
  }
}

// ---------------------------------------------------------------------------
// Resolve zone to IP/CIDR list
// ---------------------------------------------------------------------------

async function resolveZone(serverId, zoneId) {
  const { rows: zones } = await pool.query('SELECT * FROM firewall_zones WHERE id = $1 AND server_id = $2', [zoneId, serverId]);
  if (zones.length === 0) throw new Error('Zone not found');
  const zone = zones[0];

  // Built-in zones
  if (zone.name === 'any') return ['0.0.0.0/0'];
  if (zone.name === 'wan') return ['0.0.0.0/0']; // WAN = everything, agent chain handles VPN vs WAN

  if (zone.name === 'vpn-peers') {
    // Resolve all peer IPs from all interfaces on this server
    const { rows: peers } = await pool.query(
      `SELECT DISTINCT pm.public_key, s.id as subnet_id
       FROM peers_meta pm
       JOIN subnets s ON pm.subnet_id = s.id
       WHERE pm.server_id = $1`, [serverId]
    );
    // Get peer IPs from agent
    try {
      const client = new AgentClient(serverId);
      const { interfaces } = await client.listInterfaces();
      const ips = [];
      for (const iface of (interfaces || [])) {
        const { peers } = await client.request('listPeers', { iface });
        for (const p of (peers || [])) {
          if (p.allowedIPs) ips.push(...p.allowedIPs.split(',').map(ip => ip.trim()));
        }
      }
      return ips.length > 0 ? ips : ['10.0.0.0/8']; // fallback
    } catch {
      return ['10.0.0.0/8']; // fallback if agent offline
    }
  }

  // Custom zone — resolve members
  const { rows: members } = await pool.query('SELECT * FROM firewall_zone_members WHERE zone_id = $1', [zoneId]);
  const ips = [];

  for (const m of members) {
    switch (m.member_type) {
      case 'ip':
        ips.push(m.member_value);
        break;
      case 'subnet': {
        const { rows: subs } = await pool.query('SELECT cidr FROM subnets WHERE id = $1', [m.member_value]);
        if (subs.length > 0) ips.push(subs[0].cidr);
        break;
      }
      case 'user': {
        // Resolve all peer IPs for this user
        const { rows: peerRows } = await pool.query(
          `SELECT pm.public_key, s.interface_name
           FROM peers_meta pm
           JOIN users u ON u.id = pm.user_id
           JOIN subnets s ON pm.subnet_id = s.id
           WHERE u.id = $1 AND pm.server_id = $2`, [m.member_value, serverId]
        );
        // Get actual IPs from agent
        try {
          const client = new AgentClient(serverId);
          for (const pr of peerRows) {
            const peer = await client.request('getPeer', { iface: pr.interface_name, pubkey: pr.public_key });
            if (peer && peer.allowedIPs) ips.push(...peer.allowedIPs.split(',').map(ip => ip.trim()));
          }
        } catch {}
        break;
      }
      case 'interface': {
        const { rows: subs } = await pool.query(
          'SELECT cidr FROM subnets WHERE server_id = $1 AND interface_name = $2', [serverId, m.member_value]
        );
        for (const s of subs) ips.push(s.cidr);
        break;
      }
    }
  }

  return ips;
}

// ---------------------------------------------------------------------------
// Sync zone rules to agent — called when zone members change
// ---------------------------------------------------------------------------

async function syncZoneRulesToAgent(serverId, zoneId) {
  // Re-expand every logical rule that references this zone so IP membership changes
  // propagate to iptables.
  await resyncRulesByZone(serverId, zoneId);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// GET /api/servers/:serverId/firewall/zones
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    await ensureBuiltinZones(req.params.serverId);
    const { rows } = await pool.query(
      `SELECT z.*,
        (SELECT json_agg(json_build_object('id', m.id, 'memberType', m.member_type, 'memberValue', m.member_value, 'createdAt', m.created_at))
         FROM firewall_zone_members m WHERE m.zone_id = z.id) as members
       FROM firewall_zones z WHERE z.server_id = $1 ORDER BY z.builtin DESC, z.name`,
      [req.params.serverId]
    );
    res.json({ zones: rows.map(z => ({ ...z, members: z.members || [] })) });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/firewall/zones
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'name is required' });
    if (BUILTIN_ZONES.includes(name.toLowerCase())) return res.status(400).json({ error: 'Cannot use built-in zone name' });
    const { rows } = await pool.query(
      'INSERT INTO firewall_zones (server_id, name, description) VALUES ($1, $2, $3) RETURNING *',
      [req.params.serverId, name, description || '']
    );
    res.status(201).json({ ...rows[0], members: [] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Zone name already exists' });
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/firewall/zones/:zoneId
router.put('/:zoneId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows: existing } = await pool.query('SELECT builtin FROM firewall_zones WHERE id = $1 AND server_id = $2', [req.params.zoneId, req.params.serverId]);
    if (existing.length === 0) return res.status(404).json({ error: 'Zone not found' });
    if (existing[0].builtin) return res.status(400).json({ error: 'Cannot edit built-in zone' });
    const { name, description } = req.body;
    const { rows } = await pool.query(
      'UPDATE firewall_zones SET name = COALESCE($1, name), description = COALESCE($2, description), updated_at = NOW() WHERE id = $3 RETURNING *',
      [name, description, req.params.zoneId]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/firewall/zones/:zoneId
router.delete('/:zoneId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows } = await pool.query('SELECT builtin FROM firewall_zones WHERE id = $1 AND server_id = $2', [req.params.zoneId, req.params.serverId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Zone not found' });
    if (rows[0].builtin) return res.status(400).json({ error: 'Cannot delete built-in zone' });

    // Drop agent rules referencing this zone before DB delete so we don't orphan
    // rules that can no longer be resolved.
    const zoneId = parseInt(req.params.zoneId);
    await removeRulesReferencingZone(parseInt(req.params.serverId), zoneId);

    await pool.query('DELETE FROM firewall_zones WHERE id = $1', [req.params.zoneId]);
    res.json({ deleted: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

async function removeRulesReferencingZone(serverId, zoneId) {
  const client = new AgentClient(serverId);
  const all = await client.firewallListAllRules();
  const seen = new Set();
  for (const [iface, rules] of Object.entries(all.interfaces || {})) {
    for (const rule of rules) {
      if (!rule.groupId) continue;
      if (rule.srcZoneId != zoneId && rule.dstZoneId != zoneId) continue;
      const key = `${iface}::${rule.groupId}`;
      if (seen.has(key)) continue;
      seen.add(key);
      try { await client.firewallRemoveGroup(iface, rule.groupId); } catch {}
    }
  }
}

// POST /api/servers/:serverId/firewall/zones/:zoneId/members
router.post('/:zoneId/members', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const dbClient = await pool.connect();
  try {
    await verifyAccess(req.params.serverId, req);
    const { rows: zones } = await dbClient.query('SELECT builtin FROM firewall_zones WHERE id = $1 AND server_id = $2', [req.params.zoneId, req.params.serverId]);
    if (zones.length === 0) return res.status(404).json({ error: 'Zone not found' });
    if (zones[0].builtin) return res.status(400).json({ error: 'Cannot add members to built-in zone' });

    const { memberType, memberValue, member_type, member_value } = req.body;
    const type = memberType || member_type;
    const value = memberValue || member_value;
    if (!type || !value) return res.status(400).json({ error: 'memberType and memberValue are required' });
    if (!['ip', 'subnet', 'user', 'interface'].includes(type)) return res.status(400).json({ error: 'Invalid memberType' });

    await dbClient.query('BEGIN');
    const { rows } = await dbClient.query(
      'INSERT INTO firewall_zone_members (zone_id, member_type, member_value) VALUES ($1, $2, $3) RETURNING *',
      [req.params.zoneId, type, value]
    );

    // Sync to agent
    try {
      await syncZoneRulesToAgent(parseInt(req.params.serverId), parseInt(req.params.zoneId));
    } catch (syncErr) {
      await dbClient.query('ROLLBACK');
      dbClient.release();
      return res.status(502).json({ error: `Agent sync failed: ${syncErr.message}` });
    }

    await dbClient.query('COMMIT');
    dbClient.release();
    res.status(201).json(rows[0]);
  } catch (err) {
    try { await dbClient.query('ROLLBACK'); } catch {}
    dbClient.release();
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/firewall/zones/:zoneId/members/:memberId
router.delete('/:zoneId/members/:memberId', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const dbClient = await pool.connect();
  try {
    await verifyAccess(req.params.serverId, req);

    await dbClient.query('BEGIN');
    const { rowCount } = await dbClient.query(
      'DELETE FROM firewall_zone_members WHERE id = $1 AND zone_id = $2',
      [req.params.memberId, req.params.zoneId]
    );
    if (rowCount === 0) {
      await dbClient.query('ROLLBACK');
      dbClient.release();
      return res.status(404).json({ error: 'Member not found' });
    }

    try {
      await syncZoneRulesToAgent(parseInt(req.params.serverId), parseInt(req.params.zoneId));
    } catch (syncErr) {
      await dbClient.query('ROLLBACK');
      dbClient.release();
      return res.status(502).json({ error: `Agent sync failed: ${syncErr.message}` });
    }

    await dbClient.query('COMMIT');
    dbClient.release();
    res.json({ deleted: true });
  } catch (err) {
    try { await dbClient.query('ROLLBACK'); } catch {}
    dbClient.release();
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/firewall/zones/:zoneId/resolve
router.get('/:zoneId/resolve', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const ips = await resolveZone(parseInt(req.params.serverId), parseInt(req.params.zoneId));
    res.json({ ips });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.resolveZone = resolveZone;
