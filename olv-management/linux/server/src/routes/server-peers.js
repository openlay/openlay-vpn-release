// Flat per-server peer list, joined with users/devices, for admin
// dropdowns: app-server target picker, route-policy ingress picker,
// route-policy gateway-IP picker.
//
// Source: peers_meta (cache populated at /api/connect time). Includes
// only peers where assigned_ip is non-null and not expired — those
// are the ones admin can usefully target right now.
const { Router } = require('express');
const { pool } = require('../db/pool');
const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

async function verifyAccess(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT id, access_mode FROM servers WHERE id = $1', [serverId])
    : await pool.query('SELECT id, access_mode FROM servers WHERE id = $1 AND enterprise_id = $2',
                       [serverId, req.enterpriseId]);
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  if (rows[0].access_mode === 'public' && !isRoot) throw Object.assign(new Error('Root required'), { status: 403 });
}

// GET /api/servers/:serverId/server-peers
// Optional ?iface=wg0 to filter to one interface (for gateway-iface
// dropdown which is iface-scoped).
router.get('/', async (req, res) => {
  try {
    await verifyAccess(req.params.serverId, req);
    const params = [req.params.serverId];
    let where = 'pm.server_id = $1 AND pm.assigned_ip IS NOT NULL AND COALESCE(pm.is_expired, FALSE) = FALSE';
    if (req.query.iface) {
      params.push(req.query.iface);
      where += ` AND pm.interface_name = $${params.length}`;
    }
    const { rows } = await pool.query(
      `SELECT pm.public_key,
              pm.interface_name      AS iface,
              pm.assigned_ip::text   AS ip,
              pm.alias,
              pm.user_id,
              u.email                AS user_email,
              pm.device_id,
              d.name                 AS device_name,
              d.os                   AS device_os,
              d.last_connect_at
         FROM peers_meta pm
         LEFT JOIN users   u ON u.id = pm.user_id
         LEFT JOIN devices d ON d.id = pm.device_id
        WHERE ${where}
        ORDER BY COALESCE(d.last_connect_at, pm.created_at) DESC`,
      params
    );
    res.json({ peers: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
