const { Router } = require('express');
const { pool } = require('../db/pool');
const { isValidCidr, getNextAvailableIp } = require('../services/subnetUtils');
const enterpriseContext = require('../middleware/enterpriseContext');

const AgentClient = require('../services/agentClient');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

/**
 * After creating/updating/deleting a subnet, sync all subnet addresses
 * for that interface to the agent's config file.
 */
async function syncAddressesToAgent(serverId, interfaceName) {
  // Get all subnets for this interface, build gateway addresses
  const { rows: subnets } = await pool.query(
    'SELECT cidr FROM subnets WHERE server_id = $1 AND interface_name = $2 ORDER BY id',
    [serverId, interfaceName]
  );

  // Each subnet CIDR like "10.0.0.0/24" → gateway is first usable IP "10.0.0.1/24"
  const addresses = subnets.map(s => {
    const [network, prefix] = s.cidr.split('/');
    const parts = network.split('.').map(Number);
    parts[3] = 1; // .1 as gateway
    return `${parts.join('.')}/${prefix}`;
  });

  if (addresses.length > 0) {
    const client = new AgentClient(parseInt(serverId));
    await client.setInterfaceAddresses(interfaceName, addresses);
  }
}

// Admin gate: anyone in `root`/`super_admin`/`admin` for this enterprise.
// Members can read subnets (GET) but mutations (POST/PUT/DELETE) reshape
// the gateway's address plan + trigger agent setInterfaceAddresses —
// admin-only is the right scope.
function requireAdmin(req, res) {
  if (['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) return true;
  res.status(403).json({ error: 'Admin access required' });
  return false;
}

// Verify server is accessible to this user
async function verifyServerAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT 1 FROM servers WHERE id = $1', [serverId])
    : await pool.query(`SELECT 1 FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`, [serverId, req.enterpriseId]);
  return rows.length > 0;
}

// GET /api/servers/:serverId/subnets
router.get('/', async (req, res) => {
  try {
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });
    const { rows } = await pool.query(
      'SELECT * FROM subnets WHERE server_id = $1 ORDER BY id',
      [req.params.serverId]
    );
    res.json({ subnets: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/subnets
router.post('/', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });
    const { cidr, interface_name, name, description } = req.body;
    if (!cidr || !interface_name) {
      return res.status(400).json({ error: 'cidr and interface_name are required' });
    }
    if (!isValidCidr(cidr)) {
      return res.status(400).json({ error: 'Invalid CIDR format' });
    }

    const { rows } = await pool.query(
      `INSERT INTO subnets (server_id, interface_name, cidr, name, description)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.params.serverId, interface_name, cidr, name || '', description || '']
    );

    // Sync addresses to agent — DB change persists even if agent is offline
    let agentSyncError = null;
    try {
      await syncAddressesToAgent(req.params.serverId, interface_name);
    } catch (err) {
      agentSyncError = err.message;
      console.error(`[subnets] Agent sync failed: ${err.message}`);
    }

    const result = rows[0];
    if (agentSyncError) result.warning = `Saved to DB but agent sync failed: ${agentSyncError}`;
    res.status(201).json(result);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Subnet with this CIDR already exists' });
    if (err.code === '23503') return res.status(404).json({ error: 'Server not found' });
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/subnets/:subnetId
router.get('/:subnetId', async (req, res) => {
  try {
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });
    const { rows } = await pool.query(
      'SELECT * FROM subnets WHERE id = $1 AND server_id = $2',
      [req.params.subnetId, req.params.serverId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Subnet not found' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/servers/:serverId/subnets/:subnetId
router.put('/:subnetId', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });
    const { cidr, interface_name, name, description } = req.body;
    if (cidr && !isValidCidr(cidr)) {
      return res.status(400).json({ error: 'Invalid CIDR format' });
    }
    const fields = [];
    const values = [];
    let idx = 1;
    if (cidr !== undefined) { fields.push(`cidr = $${idx++}`); values.push(cidr); }
    if (interface_name !== undefined) { fields.push(`interface_name = $${idx++}`); values.push(interface_name); }
    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    // Get old interface_name before update (for syncing old interface if changed)
    const { rows: oldRows } = await pool.query(
      'SELECT interface_name FROM subnets WHERE id = $1 AND server_id = $2',
      [req.params.subnetId, req.params.serverId]
    );
    const oldIfaceName = oldRows.length > 0 ? oldRows[0].interface_name : null;

    values.push(req.params.subnetId, req.params.serverId);
    const { rows } = await pool.query(
      `UPDATE subnets SET ${fields.join(', ')} WHERE id = $${idx++} AND server_id = $${idx} RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Subnet not found' });

    // Sync addresses to new interface
    const newIfaceName = rows[0].interface_name;
    await syncAddressesToAgent(req.params.serverId, newIfaceName);

    // If interface changed, also sync old interface (remove address from it)
    if (oldIfaceName && oldIfaceName !== newIfaceName) {
      await syncAddressesToAgent(req.params.serverId, oldIfaceName);
    }

    // Subnet CIDR change → zones referencing this subnet's CIDR resolve
    // to a different IP set, so any firewall rule using zone source/dst
    // is now stale. Trigger a zone-by-zone resync; diff-skip cheap when
    // nothing changed.
    if (cidr !== undefined) {
      try {
        const { resyncRulesByZone } = require('../services/ruleOrchestrator');
        const { rows: zones } = await pool.query(
          'SELECT id FROM firewall_zones WHERE server_id = $1',
          [req.params.serverId]
        );
        for (const z of zones) {
          await resyncRulesByZone(parseInt(req.params.serverId), z.id).catch(err =>
            console.error(`[subnets/PUT] zone=${z.id} resync failed: ${err.message}`));
        }
      } catch (err) {
        console.error('[subnets/PUT] zone resync setup failed:', err.message);
      }
    }

    res.json(rows[0]);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Subnet CIDR conflict' });
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/subnets/:subnetId
router.delete('/:subnetId', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });

    // Get interface_name before deleting (for address sync)
    const { rows: toDelete } = await pool.query(
      'SELECT interface_name FROM subnets WHERE id = $1 AND server_id = $2',
      [req.params.subnetId, req.params.serverId]
    );
    if (toDelete.length === 0) return res.status(404).json({ error: 'Subnet not found' });
    const ifaceName = toDelete[0].interface_name;

    // Refuse delete when ANY rule/peer/assignment still references this
    // subnet (or its CIDR via routes/policies). CASCADE would silently
    // wipe agent rules. Caller must clear deps explicitly. Same pattern
    // as interface delete and group delete refusals.
    const cidrText = await pool.query('SELECT cidr::text AS c FROM subnets WHERE id=$1', [req.params.subnetId]);
    const subnetCidr = cidrText.rows[0]?.c;
    const [users, peers, routesAffecting, policiesAffecting] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS n FROM user_server_assignments WHERE subnet_id = $1', [req.params.subnetId]),
      pool.query('SELECT COUNT(*)::int AS n FROM peers_meta WHERE subnet_id = $1 AND COALESCE(is_expired,FALSE)=FALSE', [req.params.subnetId]),
      // Routes/policies referencing the CIDR text (string match — they store text not subnet_id).
      subnetCidr
        ? pool.query('SELECT COUNT(*)::int AS n FROM routes WHERE server_id=$1 AND (destination::text=$2)', [req.params.serverId, subnetCidr])
        : Promise.resolve({ rows: [{ n: 0 }] }),
      subnetCidr
        ? pool.query(
            `SELECT COUNT(*)::int AS n FROM route_policies
              WHERE server_id=$1 AND (src_cidr=$2 OR dst_cidr=$2)`,
            [req.params.serverId, subnetCidr]
          )
        : Promise.resolve({ rows: [{ n: 0 }] }),
    ]);
    const deps = {
      user_assignments: users.rows[0].n,
      active_peers:     peers.rows[0].n,
      routes:           routesAffecting.rows[0].n,
      route_policies:   policiesAffecting.rows[0].n,
    };
    const blocking = Object.entries(deps).filter(([_, n]) => n > 0);
    if (blocking.length > 0) {
      const summary = blocking.map(([k, n]) => `${k}=${n}`).join(', ');
      return res.status(409).json({
        error: `Cannot delete subnet "${subnetCidr}": ${summary}. Detach all dependents first (assignments, peers, routes, policies).`,
        dependents: deps,
      });
    }

    await pool.query(
      'DELETE FROM subnets WHERE id = $1 AND server_id = $2',
      [req.params.subnetId, req.params.serverId]
    );

    // Sync remaining addresses to agent
    await syncAddressesToAgent(req.params.serverId, ifaceName);

    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/servers/:serverId/subnets/:subnetId/next-ip
router.get('/:subnetId/next-ip', async (req, res) => {
  try {
    if (!(await verifyServerAccess(req.params.serverId, req)))
      return res.status(404).json({ error: 'Server not found' });
    const { rows: subnets } = await pool.query(
      'SELECT * FROM subnets WHERE id = $1 AND server_id = $2',
      [req.params.subnetId, req.params.serverId]
    );
    if (subnets.length === 0) return res.status(404).json({ error: 'Subnet not found' });
    const subnet = subnets[0];

    const AgentClient = require('../services/agentClient');
    const { rows: servers } = await pool.query('SELECT id, url, api_token FROM servers WHERE id = $1', [req.params.serverId]);
    let usedIps = [];

    try {
      const client = new AgentClient(servers[0].id);
      const ifaceData = await client.getInterface(subnet.interface_name);
      if (ifaceData.peers) {
        usedIps = ifaceData.peers
          .map(p => p.allowedIPs)
          .filter(Boolean)
          .flatMap(ips => ips.split(',').map(ip => ip.trim()));
      }
      if (ifaceData.address) {
        usedIps.push(...ifaceData.address.split(',').map(a => a.trim()));
      }
    } catch {}

    try {
      const { rows: staticRows } = await pool.query(
        'SELECT ip_address FROM device_static_ips WHERE server_id = $1 AND subnet_id = $2',
        [req.params.serverId, subnet.id]
      );
      usedIps.push(...staticRows.map(r => r.ip_address));
    } catch {}

    const nextIp = getNextAvailableIp(subnet.cidr, usedIps);
    if (!nextIp) return res.status(409).json({ error: 'No available IPs in this subnet' });
    res.json({ ip: nextIp, cidr: `${nextIp}/32` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
