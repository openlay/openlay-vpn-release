const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const { pool } = require('../db/pool');

const router = Router();

// GET /api/servers — List servers available to this user
// - No enterprise: only public servers (top 5 least busy)
// - Has enterprise: assigned servers + public servers (top 5 least busy)
router.get('/', async (req, res) => {
  try {
    const userId = req.user.id;
    const seen = new Set();
    const assignedList = [];

    // Check if user belongs to any enterprise
    const { rows: enterprises } = await pool.query(
      'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1',
      [userId]
    );
    const hasEnterprise = enterprises.length > 0;

    if (hasEnterprise) {
      // Only servers directly assigned to this user
      const { rows: assignments } = await pool.query(
        `SELECT usa.server_id, usa.interface_name, usa.subnet_id,
                s.name as server_name, s.access_mode, s.status,
                sub.cidr as subnet_cidr, sub.name as subnet_name
         FROM user_server_assignments usa
         JOIN servers s ON usa.server_id = s.id
         LEFT JOIN subnets sub ON usa.subnet_id = sub.id
         WHERE usa.user_id = $1 AND s.status = 'active' AND s.access_mode != 'for_sale'
         ORDER BY s.name`,
        [userId]
      );

      for (const a of assignments) {
        seen.add(a.server_id);
        assignedList.push({
          serverId: a.server_id,
          serverName: a.server_name,
          interfaceName: a.interface_name,
          subnetId: a.subnet_id,
          subnetCidr: a.subnet_cidr,
          subnetName: a.subnet_name,
          accessMode: a.access_mode,
        });
      }

      // Enterprise public servers — all public servers belonging to user's enterprise(s)
      for (const ent of enterprises) {
        const { rows: entPublic } = await pool.query(
          `SELECT s.id, s.name, s.access_mode
           FROM servers s
           WHERE s.enterprise_id = $1 AND s.access_mode = 'public' AND s.status = 'active'
           ORDER BY s.name`,
          [ent.enterprise_id]
        );
        for (const srv of entPublic) {
          if (seen.has(srv.id)) continue;
          seen.add(srv.id);
          const { rows: subnets } = await pool.query(
            'SELECT * FROM subnets WHERE server_id = $1 ORDER BY created_at LIMIT 1',
            [srv.id]
          );
          assignedList.push({
            serverId: srv.id,
            serverName: srv.name,
            interfaceName: subnets[0]?.interface_name || null,
            subnetId: subnets[0]?.id || null,
            subnetCidr: subnets[0]?.cidr || null,
            subnetName: subnets[0]?.name || null,
            accessMode: 'public',
          });
        }
      }
    }

    // 3. Public servers — top 5 least busy (by peer count), exclude already listed
    const excludeIds = [...seen];
    const { rows: publicServers } = await pool.query(
      `SELECT s.id, s.name,
              COALESCE((SELECT COUNT(*) FROM peers_meta pm WHERE pm.server_id = s.id), 0) as peer_count
       FROM servers s
       WHERE s.access_mode = 'public' AND s.status = 'active'
         AND s.enterprise_id IS NULL
         ${excludeIds.length > 0 ? `AND s.id NOT IN (${excludeIds.join(',')})` : ''}
       ORDER BY peer_count ASC, s.name ASC
       LIMIT 5`
    );

    const publicList = [];
    for (const srv of publicServers) {
      const { rows: subnets } = await pool.query(
        'SELECT * FROM subnets WHERE server_id = $1 ORDER BY created_at LIMIT 1',
        [srv.id]
      );
      if (subnets.length > 0) {
        publicList.push({
          serverId: srv.id,
          serverName: srv.name,
          interfaceName: subnets[0].interface_name,
          subnetId: subnets[0].id,
          subnetCidr: subnets[0].cidr,
          subnetName: subnets[0].name,
          accessMode: 'public',
          peerCount: parseInt(srv.peer_count, 10),
        });
      }
    }

    res.json({
      public: publicList,
      private: assignedList,
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
