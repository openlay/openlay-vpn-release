const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { resyncRulesByUsers } = require('../../services/ruleOrchestrator');

const router = Router();
router.use(enterpriseContext);

const ENT_DEVICE_JOIN = `
  JOIN users u ON d.user_id = u.id
  JOIN user_enterprise_roles uer ON uer.user_id = u.id AND uer.enterprise_id =
`;

// GET /api/admin/devices — root sees all, others see enterprise only
router.get('/', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const { status } = req.query;

    // Join enterprise alias for the user
    const aliasEntId = req.enterpriseId;
    let query = `
      SELECT d.*, u.name as user_name, u.email as user_email,
        da.key_id as attest_key_id, da.sign_count as attest_sign_count, da.created_at as attest_date
        ${aliasEntId ? `, uer.alias as user_alias` : `, (SELECT uer2.alias FROM user_enterprise_roles uer2 WHERE uer2.user_id = u.id AND uer2.alias != '' ORDER BY uer2.created_at LIMIT 1) as user_alias`}
      FROM devices d
      LEFT JOIN users u ON d.user_id = u.id
      LEFT JOIN device_attestations da ON da.device_id = d.id
      ${aliasEntId ? `LEFT JOIN user_enterprise_roles uer ON uer.user_id = u.id AND uer.enterprise_id = '${aliasEntId.replace(/'/g, "''")}'` : ''}
    `;
    const conditions = [];
    const params = [];

    if (!isRoot) {
      params.push(req.enterpriseId);
      conditions.push(`d.user_id IN (SELECT user_id FROM user_enterprise_roles WHERE enterprise_id = $${params.length})`);
    }
    if (status && ['pending', 'enabled', 'disabled'].includes(status)) {
      params.push(status);
      conditions.push(`d.status = $${params.length}`);
    }

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY d.created_at DESC';

    const { rows } = await pool.query(query, params);
    res.json({ devices: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/devices/pending-count
router.get('/pending-count', async (req, res) => {
  try {
    const isRoot = req.enterpriseRole === 'root';
    const { rows } = isRoot
      ? await pool.query(`SELECT COUNT(*) as count FROM devices WHERE status = 'pending'`)
      : await pool.query(
          `SELECT COUNT(*) as count FROM devices WHERE status = 'pending'
           AND user_id IN (SELECT user_id FROM user_enterprise_roles WHERE enterprise_id = $1)`,
          [req.enterpriseId]
        );
    res.json({ count: parseInt(rows[0].count, 10) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/devices/:id/users — List users on same physical device (enterprise-scoped)
router.get('/:id/users', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const { rows: device } = await pool.query('SELECT hardware_id, name FROM devices WHERE id = $1', [req.params.id]);
    if (device.length === 0) return res.status(404).json({ error: 'Device not found' });

    const hardwareId = device[0].hardware_id || req.params.id;
    const isRoot = req.enterpriseRole === 'root';

    // Root sees all users on device; others only see enterprise users
    const { rows } = isRoot
      ? await pool.query(
          `SELECT d.id as device_id, d.status as device_status, d.enrollment_method, d.created_at as enrolled_at,
                  u.id as user_id, u.name as user_name, u.email, u.username, u.auth_type, u.status as user_status
           FROM devices d JOIN users u ON u.id = d.user_id
           WHERE d.hardware_id = $1 ORDER BY d.created_at DESC`,
          [hardwareId]
        )
      : await pool.query(
          `SELECT d.id as device_id, d.status as device_status, d.enrollment_method, d.created_at as enrolled_at,
                  u.id as user_id, u.name as user_name, u.email, u.username, u.auth_type, u.status as user_status
           FROM devices d JOIN users u ON u.id = d.user_id
           JOIN user_enterprise_roles uer ON uer.user_id = u.id AND uer.enterprise_id = $2
           WHERE d.hardware_id = $1 ORDER BY d.created_at DESC`,
          [hardwareId, req.enterpriseId]
        );

    res.json({
      hardwareId,
      deviceName: device[0].name || null,
      users: rows.map(r => ({
        deviceId: r.device_id,
        deviceStatus: r.device_status,
        enrollmentMethod: r.enrollment_method,
        enrolledAt: r.enrolled_at,
        userId: r.user_id,
        userName: r.user_name,
        email: r.email,
        username: r.username,
        authType: r.auth_type,
        userStatus: r.user_status,
      })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: verify device belongs to enterprise (root always passes)
async function verifyDeviceAccess(deviceId, req) {
  if (req.enterpriseRole === 'root') return true;
  const { rows } = await pool.query(
    `SELECT 1 FROM devices d
     JOIN user_enterprise_roles uer ON uer.user_id = d.user_id AND uer.enterprise_id = $2
     WHERE d.id = $1`,
    [deviceId, req.enterpriseId]
  );
  return rows.length > 0;
}

// PUT /api/admin/devices/:id
router.put('/:id', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { name, status } = req.body;
    const fields = [];
    const values = [];
    let idx = 1;

    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (status !== undefined) {
      if (!['pending', 'enabled', 'disabled'].includes(status)) {
        return res.status(400).json({ error: 'status must be pending, enabled, or disabled' });
      }
      fields.push(`status = $${idx++}`);
      values.push(status);
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    fields.push(`updated_at = NOW()`);
    values.push(req.params.id);

    const { rows } = await pool.query(
      `UPDATE devices SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Device not found' });
    res.json({ device: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/devices/:id/approve
router.post('/:id/approve', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows } = await pool.query(
      `UPDATE devices SET status = 'enabled', updated_at = NOW() WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Device not found' });
    res.json({ device: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/devices/:id/reject
router.post('/:id/reject', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows } = await pool.query(
      `UPDATE devices SET status = 'disabled', updated_at = NOW() WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Device not found' });
    res.json({ device: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Validate IPv4 CIDR
function isValidIpCidr(cidr) {
  const match = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!match) return false;
  const octets = [match[1], match[2], match[3], match[4]].map(Number);
  const prefix = parseInt(match[5], 10);
  return octets.every(o => o <= 255) && prefix >= 0 && prefix <= 32;
}

function normalizeIpAddress(raw) {
  const val = raw.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(val)) {
    const withMask = `${val}/32`;
    return isValidIpCidr(withMask) ? { value: withMask, error: null } : { value: null, error: 'Invalid IP address' };
  }
  if (isValidIpCidr(val)) return { value: val, error: null };
  return { value: null, error: `Invalid IP/CIDR format: "${val}"` };
}

function validateAllowedIps(list) {
  if (!Array.isArray(list)) return 'allowed_ips must be an array';
  const invalid = list.filter(c => !isValidIpCidr(c.trim()));
  if (invalid.length > 0) return `Invalid CIDR(s): ${invalid.join(', ')}`;
  return null;
}

// GET /api/admin/devices/:id/static-ips
router.get('/:id/static-ips', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows } = await pool.query(`
      SELECT dsi.*, s.name as server_name, sub.cidr as subnet_cidr, sub.name as subnet_name, sub.interface_name
      FROM device_static_ips dsi
      LEFT JOIN servers s ON dsi.server_id = s.id
      LEFT JOIN subnets sub ON dsi.subnet_id = sub.id
      WHERE dsi.device_id = $1 AND (s.enterprise_id = $2 OR s.enterprise_id IS NULL)
      ORDER BY s.name, sub.cidr
    `, [req.params.id, req.enterpriseId]);
    res.json({ staticIps: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/devices/:id/static-ips
router.post('/:id/static-ips', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const server_id = req.body.server_id || req.body.serverId;
    const subnet_id = req.body.subnet_id || req.body.subnetId;
    const ip_address = req.body.ip_address || req.body.ipAddress;
    const allowed_ips = req.body.allowed_ips || req.body.allowedIps || [];
    if (!server_id || !subnet_id || !ip_address) {
      return res.status(400).json({ error: 'server_id, subnet_id, and ip_address are required' });
    }
    // Verify server in enterprise
    const sCheck = await pool.query('SELECT 1 FROM servers WHERE id = $1 AND enterprise_id = $2', [server_id, req.enterpriseId]);
    if (sCheck.rows.length === 0) return res.status(404).json({ error: 'Server not in this enterprise' });

    const { value: normalizedIp, error: ipErr } = normalizeIpAddress(ip_address);
    if (ipErr) return res.status(400).json({ error: ipErr });
    const cidrErr = validateAllowedIps(allowed_ips);
    if (cidrErr) return res.status(400).json({ error: cidrErr });

    const { rows } = await pool.query(
      `INSERT INTO device_static_ips (device_id, server_id, subnet_id, ip_address, allowed_ips) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.params.id, server_id, subnet_id, normalizedIp, allowed_ips.map(c => c.trim())]
    );
    await triggerStaticIpResync(server_id, req.params.id);
    res.status(201).json({ staticIp: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Static IP already assigned' });
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/devices/:id/static-ips/:sipId
router.put('/:id/static-ips/:sipId', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const ip_address = req.body.ip_address || req.body.ipAddress;
    const allowed_ips = req.body.allowed_ips || req.body.allowedIps || [];
    if (!ip_address) return res.status(400).json({ error: 'ip_address is required' });

    const { value: normalizedIp, error: ipErr } = normalizeIpAddress(ip_address);
    if (ipErr) return res.status(400).json({ error: ipErr });
    const cidrErr = validateAllowedIps(allowed_ips);
    if (cidrErr) return res.status(400).json({ error: cidrErr });

    const { rows } = await pool.query(
      `UPDATE device_static_ips SET ip_address = $1, allowed_ips = $2 WHERE id = $3 AND device_id = $4 RETURNING *`,
      [normalizedIp, allowed_ips.map(c => c.trim()), req.params.sipId, req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Static IP not found' });
    await triggerStaticIpResync(rows[0].server_id, req.params.id);
    res.json({ staticIp: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'IP address conflict' });
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/devices/:id/static-ips/:sipId
router.delete('/:id/static-ips/:sipId', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows: existing } = await pool.query(
      'SELECT server_id FROM device_static_ips WHERE id = $1 AND device_id = $2',
      [req.params.sipId, req.params.id]
    );
    const { rowCount } = await pool.query(
      'DELETE FROM device_static_ips WHERE id = $1 AND device_id = $2',
      [req.params.sipId, req.params.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Static IP not found' });
    if (existing[0]) await triggerStaticIpResync(existing[0].server_id, req.params.id);
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Look up which user owns the given device and ask ruleOrchestrator to refresh
// any firewall rules that reference them.
async function triggerStaticIpResync(serverId, deviceId) {
  try {
    const { rows } = await pool.query('SELECT user_id FROM devices WHERE id = $1', [deviceId]);
    const userId = rows[0]?.user_id;
    if (userId) await resyncRulesByUsers(parseInt(serverId), [userId]);
  } catch (err) {
    console.error(`[admin/devices] static-ip resync failed:`, err.message);
  }
}

// DELETE /api/admin/devices/:id
router.delete('/:id', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rowCount } = await pool.query('DELETE FROM devices WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Device not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
