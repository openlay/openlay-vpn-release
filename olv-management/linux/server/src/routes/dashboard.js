const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const registry = require('../services/wsAgentRegistry');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router();

// GET /api/dashboard — scoped to current enterprise
router.get('/', enterpriseContext, async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const { rows: servers } = isRoot
      ? await pool.query('SELECT id, name, url, api_token, hostname, description, access_mode FROM servers ORDER BY id')
      : await pool.query('SELECT id, name, url, api_token, hostname, description, access_mode FROM servers WHERE enterprise_id = $1 ORDER BY id', [req.enterpriseId]);

    const results = await Promise.all(servers.map(async (server) => {
      const client = new AgentClient(server.id);
      const isOnline = registry.isOnline(server.id);
      const result = {
        id: server.id,
        name: server.name,
        hostname: server.hostname || '',
        description: server.description,
        access_mode: server.access_mode,
        status: isOnline ? 'online' : 'offline',
        interfaceCount: 0,
        totalPeers: 0,
        connectedPeers: 0,
        interfaces: [],
      };

      try {
        if (!isOnline) throw new Error('offline');

        // Get interface data via WebSocket (no HTTP health check needed)
        const ifaceData = await client.listInterfacesFast().catch(() => ({ interfaces: [] }));

        const ifaceNames = ifaceData.interfaces || [];
        result.interfaceCount = ifaceNames.length;

        const ifaceResults = await Promise.all(ifaceNames.map(async (ifaceName) => {
          try {
            const [ifaceInfo, connData] = await Promise.all([
              client.getInterfaceFast(ifaceName),
              client.getConnectedFast(ifaceName).catch(() => ({ count: 0 })),
            ]);
            const peerCount = ifaceInfo.peerCount || 0;
            const connected = connData.count || 0;
            return { name: ifaceName, address: ifaceInfo.address, listenPort: ifaceInfo.listenPort, peerCount, connectedPeers: connected };
          } catch { return null; }
        }));

        for (const iface of ifaceResults) {
          if (!iface) continue;
          result.totalPeers += iface.peerCount;
          result.connectedPeers += iface.connectedPeers;
          result.interfaces.push(iface);
        }
      } catch {
        result.status = 'offline';
      }

      const { rows: subnetRows } = await pool.query(
        'SELECT COUNT(*) as count FROM subnets WHERE server_id = $1',
        [server.id]
      );
      result.subnetCount = parseInt(subnetRows[0].count, 10);

      return result;
    }));

    // Users & devices: root sees all, others scoped to enterprise
    const [userStats, deviceStats] = isRoot
      ? await Promise.all([
          pool.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = 'enabled') as active FROM users`),
          pool.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = 'enabled') as enabled, COUNT(*) FILTER (WHERE status = 'pending') as pending FROM devices`),
        ])
      : await Promise.all([
          pool.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE u.status = 'enabled') as active FROM users u JOIN user_enterprise_roles uer ON uer.user_id = u.id WHERE uer.enterprise_id = $1`, [req.enterpriseId]),
          pool.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE d.status = 'enabled') as enabled, COUNT(*) FILTER (WHERE d.status = 'pending') as pending FROM devices d JOIN users u ON u.id = d.user_id JOIN user_enterprise_roles uer ON uer.user_id = u.id WHERE uer.enterprise_id = $1`, [req.enterpriseId]),
        ]);

    res.json({
      servers: results,
      users: {
        total: parseInt(userStats.rows[0].total, 10),
        active: parseInt(userStats.rows[0].active, 10),
      },
      devices: {
        total: parseInt(deviceStats.rows[0].total, 10),
        enabled: parseInt(deviceStats.rows[0].enabled, 10),
        pending: parseInt(deviceStats.rows[0].pending, 10),
      },
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
