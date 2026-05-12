const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

// Helper to get agent client — verifies server access (enterprise or public)
async function getClient(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT url, api_token, access_mode, enterprise_id FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT url, api_token, access_mode, enterprise_id FROM servers
         WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  return { client: new AgentClient(parseInt(serverId)), server: rows[0] };
}

// Only root can modify interfaces (create/delete/up/down/reload/save)
function requireRoot(req, res) {
  if (req.enterpriseRole !== 'root') {
    res.status(403).json({ error: 'Root access required for interface management' });
    return false;
  }
  return true;
}

// For public servers, non-root can only read (GET), not detail
function requireServerAccess(server, req, res) {
  if (server.access_mode === 'public' && req.enterpriseRole !== 'root') {
    res.status(403).json({ error: 'Public server: read-only access for non-root users' });
    return false;
  }
  return true;
}

// GET /api/servers/:serverId/interfaces
router.get('/', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.listInterfaces();
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/servers/:serverId/interfaces/all
// Returns every system interface (physical + WireGuard) with an isWireGuard
// flag. Physical interfaces render as read-only on the client.
router.get('/all', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.listAllInterfaces();
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/servers/:serverId/interfaces/:iface
router.get('/:iface', async (req, res) => {
  try {
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.getInterface(req.params.iface);

    // Override peer_count to match what the peers list endpoint shows.
    // The agent counts peers in its on-disk .conf only, but the peers list
    // also surfaces orphan peers_meta rows (peers tracked in DB but missing
    // from the agent — happens after agent reinstall/config wipe).
    // Without this override the Interfaces tab shows "0 peers" while
    // clicking through reveals many.
    const agentKeys = new Set(
      Array.isArray(data.peers)
        ? data.peers.map(p => p.public_key || p.publicKey).filter(Boolean)
        : []
    );
    const { rows: metaRows } = await pool.query(
      'SELECT public_key FROM peers_meta WHERE server_id = $1 AND interface_name = $2',
      [req.params.serverId, req.params.iface]
    );
    for (const row of metaRows) agentKeys.add(row.public_key);
    data.peer_count = agentKeys.size;
    delete data.peerCount;

    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/interfaces — root only
router.post('/', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;

    const { name, port, listenPort, address, addressV6, mtu, dns } = req.body;
    const actualPort = Number(listenPort || port);

    if (!name || typeof name !== 'string' || !/^[a-z0-9_-]+$/.test(name)) {
      return res.status(400).json({ error: 'name is required and must be lowercase alphanumeric (a-z, 0-9, _, -)' });
    }
    if (!address || typeof address !== 'string') {
      return res.status(400).json({ error: 'address (CIDR) is required' });
    }
    if (!Number.isInteger(actualPort) || actualPort < 51820 || actualPort > 51830) {
      return res.status(400).json({ error: 'port must be an integer between 51820 and 51830' });
    }
    if (mtu !== undefined && mtu !== null) {
      const mtuNum = Number(mtu);
      if (!Number.isInteger(mtuNum) || mtuNum < 576 || mtuNum > 65535) {
        return res.status(400).json({ error: 'mtu must be an integer between 576 and 65535' });
      }
    }

    const { client } = await getClient(req.params.serverId, req);
    const data = await client.createInterface({
      name, listenPort: actualPort, address, addressV6, mtu: mtu ? Number(mtu) : undefined, dns,
    });

    // Auto-create the matching subnet so the admin doesn't have to bounce
    // through the Subnets tab right after creating an interface. We derive
    // the network CIDR from the interface address (e.g. `10.0.0.1/24` → the
    // subnet `10.0.0.0/24`) and skip on parse failures so a malformed
    // address never blocks the interface itself.
    let networkCidr = null;
    try {
      const m = String(address).match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
      if (m) {
        const octets = [m[1], m[2], m[3], m[4]].map(Number);
        const prefixLen = parseInt(m[5], 10);
        if (octets.every(o => o <= 255) && prefixLen >= 0 && prefixLen <= 32) {
          // Compute network address from address & mask. Bit math on
          // 32-bit unsigned — JS `|` is signed so we use `>>> 0` to clamp.
          const addrInt = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
          const mask = prefixLen === 0 ? 0 : (0xFFFFFFFF << (32 - prefixLen)) >>> 0;
          const net = (addrInt & mask) >>> 0;
          networkCidr =
            `${(net >>> 24) & 0xFF}.${(net >>> 16) & 0xFF}.${(net >>> 8) & 0xFF}.${net & 0xFF}/${prefixLen}`;
          // INSERT ... ON CONFLICT DO NOTHING — safe re-run if the admin
          // already created the subnet manually before this call landed.
          await pool.query(
            `INSERT INTO subnets (server_id, interface_name, cidr, name)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING`,
            [req.params.serverId, name, networkCidr, `${name}-default`]
          );
        }
      }
    } catch (e) {
      console.warn(`[interfaces/create] auto-subnet insert failed for ${name}: ${e.message}`);
    }

    // Allow Access Internet — when admin ticked the box on iOS, create a
    // matching SRC-NAT (masquerade-style) rule so peers in this WG subnet
    // can reach the public internet through the agent's WAN interface.
    // We pick the WAN automatically: first physical interface returned by
    // the agent's listAllInterfaces that's up and not a loopback. Failure
    // here doesn't unwind the interface creation — the admin can still
    // build the NAT rule manually from the NAT tab.
    const allowInternet = req.body.allow_access_internet ?? req.body.allowAccessInternet;
    if (allowInternet === true && networkCidr) {
      try {
        const all = await client.listAllInterfaces();
        const candidates = (all?.interfaces || all || [])
          .filter(i => !i.isWireGuard && i.up !== false && i.name && i.name !== 'lo' && i.name !== 'lo0');
        const wanIface = candidates[0]?.name;
        if (!wanIface) {
          console.warn(`[interfaces/create] allow_access_internet=true but no WAN candidate found on server=${req.params.serverId}`);
        } else {
          const ruleName = `${name}-internet`;
          const rule = {
            name: ruleName,
            wanIface,
            srcCIDR: networkCidr,
            natTo: '',
            protocol: '',
            description: `Auto-created with interface ${name} (Allow Access Internet)`,
            enabled: true,
          };
          const agentRule = await client.natAddRule(rule);
          try {
            await pool.query(
              `INSERT INTO nat_rules (server_id, name, wan_iface, src_cidr, nat_to, protocol, description, enabled)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
               ON CONFLICT DO NOTHING`,
              [req.params.serverId, rule.name, rule.wanIface, rule.srcCIDR, null, null, rule.description, true]
            );
          } catch (dbErr) {
            // DB write failed — roll back the agent rule to avoid drift.
            try { await client.natRemoveRule(agentRule.id); } catch {}
            console.warn(`[interfaces/create] NAT db insert failed for ${ruleName}: ${dbErr.message}`);
          }
        }
      } catch (e) {
        console.warn(`[interfaces/create] auto-NAT for ${name} failed: ${e.message}`);
      }
    }

    res.status(201).json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE /api/servers/:serverId/interfaces/:iface — root only
router.delete('/:iface', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;

    // Refuse delete when ANY rule/peer/policy still references this iface.
    // CASCADE-deleting silently leaves orphan agent rules + breaks
    // assumptions in routes/policies/zones. Force admin to clear deps
    // explicitly. Same pattern as user_groups DELETE refusal.
    const sid = req.params.serverId;
    const ifname = req.params.iface;
    const [users, peers, subnets, routes_, policies, natRules, rdrRules, zoneMembers] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM user_server_assignments WHERE server_id=$1 AND interface_name=$2', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM peers_meta WHERE server_id=$1 AND interface_name=$2 AND COALESCE(is_expired,FALSE)=FALSE', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM subnets WHERE server_id=$1 AND interface_name=$2', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM routes WHERE server_id=$1 AND iface=$2', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM route_policies WHERE server_id=$1 AND (ingress_iface=$2 OR gateway_iface=$2)', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM nat_rules WHERE server_id=$1 AND wan_iface=$2', [sid, ifname]),
      pool.query('SELECT COUNT(*)::int AS n FROM rdr_rules WHERE server_id=$1 AND wan_iface=$2', [sid, ifname]),
      pool.query(
        `SELECT COUNT(*)::int AS n FROM firewall_zone_members
          WHERE member_type='interface' AND member_value=$2
            AND zone_id IN (SELECT id FROM firewall_zones WHERE server_id=$1)`,
        [sid, ifname]
      ),
    ]);
    const deps = {
      user_assignments: users.rows[0].n,
      active_peers:     peers.rows[0].n,
      subnets:          subnets.rows[0].n,
      routes:           routes_.rows[0].n,
      route_policies:   policies.rows[0].n,
      nat_rules:        natRules.rows[0].n,
      rdr_rules:        rdrRules.rows[0].n,
      zone_members:     zoneMembers.rows[0].n,
    };
    const blocking = Object.entries(deps).filter(([_, n]) => n > 0);
    if (blocking.length > 0) {
      const summary = blocking.map(([k, n]) => `${k}=${n}`).join(', ');
      return res.status(409).json({
        error: `Cannot delete interface "${ifname}": ${summary}. Detach all dependents first (assignments, peers, subnets, routes, policies, NAT/rdr rules, zone members).`,
        dependents: deps,
      });
    }

    const { client } = await getClient(req.params.serverId, req);
    const data = await client.deleteInterface(req.params.iface);

    // Cascade-clean DB rows that referenced this iface by string name. Without
    // this, orphan rows linger and surface as: migrate empty-check failures,
    // ghost entries in the admin UI, and (worst) silent re-activation if a
    // future interface is created with the same name. All tables below hold
    // `iface`/`wan_iface` as VARCHAR with no FK, so cascade lives in code.
    // (sid + ifname captured above in the dependents pre-check.)
    const cascade = await pool.connect();
    try {
      await cascade.query('BEGIN');
      await cascade.query('DELETE FROM subnets              WHERE server_id = $1 AND interface_name = $2', [sid, ifname]);
      await cascade.query('DELETE FROM peers_meta           WHERE server_id = $1 AND interface_name = $2', [sid, ifname]);
      await cascade.query('DELETE FROM nat_rules            WHERE server_id = $1 AND wan_iface      = $2', [sid, ifname]);
      await cascade.query('DELETE FROM rdr_rules            WHERE server_id = $1 AND wan_iface      = $2', [sid, ifname]);
      await cascade.query('DELETE FROM routes               WHERE server_id = $1 AND iface          = $2', [sid, ifname]);
      await cascade.query('DELETE FROM route_policies       WHERE server_id = $1 AND (ingress_iface = $2 OR gateway_iface = $2)', [sid, ifname]);
      // firewall_zone_members: interface-type members holding this iface name
      await cascade.query(
        `DELETE FROM firewall_zone_members
          WHERE member_type = 'interface'
            AND member_value = $2
            AND zone_id IN (SELECT id FROM firewall_zones WHERE server_id = $1)`,
        [sid, ifname]
      );
      await cascade.query('COMMIT');
    } catch (cascadeErr) {
      await cascade.query('ROLLBACK');
      console.error('[interfaces] cascade cleanup failed:', cascadeErr.message);
      // Don't fail the whole request — the WG interface is already gone on
      // the agent. Surface a warning alongside the success payload.
      return res.json({ ...data, warning: `cascade cleanup failed: ${cascadeErr.message}` });
    } finally {
      cascade.release();
    }

    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/interfaces/:iface/up — root only
router.post('/:iface/up', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.bringUp(req.params.iface);
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/interfaces/:iface/down — root only
router.post('/:iface/down', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.bringDown(req.params.iface);
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/interfaces/:iface/reload — root only
router.post('/:iface/reload', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.reloadInterface(req.params.iface);
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/servers/:serverId/interfaces/:iface/save — root only
router.post('/:iface/save', async (req, res) => {
  try {
    if (!requireRoot(req, res)) return;
    const { client } = await getClient(req.params.serverId, req);
    const data = await client.saveConfig(req.params.iface);
    res.json(data);
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
