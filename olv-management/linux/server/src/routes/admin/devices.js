const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { resyncRulesByUsers } = require('../../services/ruleOrchestrator');
const { verifyAdminSignature } = require('../../services/adminSigning');

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
        da.key_id as attest_key_id, da.sign_count as attest_sign_count, da.created_at as attest_date,
        (SELECT COUNT(*) FROM device_postures dp WHERE dp.device_id = d.id) AS posture_count,
        (SELECT COUNT(*) FROM peers_meta pm WHERE pm.device_id = d.id) AS peer_count,
        dp_prof.name as profile_name,
        approve_log.admin_user_id as approved_by_user_id,
        approver.name as approved_by_name,
        approver.email as approved_by_email,
        approve_log.created_at as approved_at
        ${aliasEntId ? `, uer.alias as user_alias` : `, (SELECT uer2.alias FROM user_enterprise_roles uer2 WHERE uer2.user_id = u.id AND uer2.alias != '' ORDER BY uer2.created_at LIMIT 1) as user_alias`}
      FROM devices d
      LEFT JOIN users u ON d.user_id = u.id
      LEFT JOIN device_attestations da ON da.device_id = d.id
      LEFT JOIN device_profiles dp_prof ON dp_prof.id = d.profile_id
      LEFT JOIN LATERAL (
        SELECT al.admin_user_id, al.created_at
          FROM admin_audit_log al
          JOIN enrollment_requests er
            ON er.id = al.target_id
           AND er.approved_device_id = d.id
         WHERE al.action = 'approve_enrollment'
         ORDER BY al.created_at DESC
         LIMIT 1
      ) approve_log ON TRUE
      LEFT JOIN users approver ON approver.id = approve_log.admin_user_id
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
    const profileIdRaw = req.body.profile_id !== undefined ? req.body.profile_id : req.body.profileId;

    // Determine which "kind" of update this is — same payload, different
    // canonical signed form so the audit log distinguishes a status flip
    // from a profile assignment.
    let action = 'update_device';
    const sigFields = { target_type: 'device', target_id: req.params.id };
    if (status !== undefined && name === undefined && profileIdRaw === undefined) {
      action = status === 'disabled' ? 'disable_device' : 'enable_device';
      sigFields.status = status;
    } else if (profileIdRaw !== undefined && status === undefined && name === undefined) {
      action = 'assign_device_profile';
      sigFields.profile_id = profileIdRaw;
    }
    const sigCheck = await verifyAdminSignature(req, action, sigFields);
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });
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
    if (profileIdRaw !== undefined) {
      // null clears the profile; non-null must reference a profile in this enterprise.
      if (profileIdRaw !== null) {
        const check = await pool.query(
          'SELECT 1 FROM device_profiles WHERE id = $1 AND enterprise_id = $2',
          [profileIdRaw, req.enterpriseId]
        );
        if (check.rows.length === 0) {
          return res.status(400).json({ error: 'profile_id does not exist in this enterprise' });
        }
      }
      fields.push(`profile_id = $${idx++}`);
      values.push(profileIdRaw);
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

// GET /api/admin/devices/:id/peers
// All peer rows tied to this device, enriched with server / interface /
// subnet info so the admin sees a single screen of "where this device
// lives on the VPN" without bouncing between tabs.
router.get('/:id/peers', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows } = await pool.query(
      `SELECT pm.id, pm.public_key, pm.alias, pm.interface_name, pm.expires_at,
              pm.is_expired, pm.allowed_source_ip, pm.created_at,
              s.id AS server_id, s.name AS server_name,
              sub.cidr AS subnet_cidr, sub.name AS subnet_name
         FROM peers_meta pm
         LEFT JOIN servers s ON s.id = pm.server_id
         LEFT JOIN subnets sub ON sub.id = pm.subnet_id
        WHERE pm.device_id = $1
        ORDER BY pm.created_at DESC`,
      [req.params.id]
    );
    res.json({ peers: rows });
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

// GET /api/admin/devices/:id/postures — paginated posture history
router.get('/:id/postures', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const limit = Math.min(parseInt(req.query.limit || '50', 10) || 50, 200);
    const before = req.query.before;
    const params = [req.params.id];
    let where = 'device_id = $1';
    if (before) {
      params.push(before);
      where += ` AND submitted_at < $${params.length}`;
    }
    params.push(limit);
    const { rows } = await pool.query(
      `SELECT id, device_id, submitted_at, posture, platform, os_version, app_version,
              is_jailbroken, is_disk_encrypted, is_passcode_set
       FROM device_postures WHERE ${where}
       ORDER BY submitted_at DESC LIMIT $${params.length}`,
      params
    );
    res.json({ postures: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/devices/:id/postures/latest — most recent snapshot
router.get('/:id/postures/latest', async (req, res) => {
  try {
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const { rows } = await pool.query(
      `SELECT id, device_id, submitted_at, posture, platform, os_version, app_version,
              is_jailbroken, is_disk_encrypted, is_passcode_set
       FROM device_postures WHERE device_id = $1
       ORDER BY submitted_at DESC LIMIT 1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'No posture for this device' });
    res.json({ posture: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/devices/:id — root only.
// Disable (PUT status='disabled') is the reversible op for enterprise admins;
// delete is destructive and reserved for root.
router.delete('/:id', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Only root can delete devices. Use disable instead.' });
    }
    if (!(await verifyDeviceAccess(req.params.id, req))) {
      return res.status(404).json({ error: 'Device not found' });
    }
    const sigCheck = await verifyAdminSignature(req, 'delete_device', {
      target_type: 'device',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    // Snapshot route_policies + application_servers pointing at this
    // device BEFORE the DELETE. CASCADE on the FK will wipe the rows
    // entirely, leaving the agent with orphan pf rules unless we
    // explicitly clean them up by id/name.
    const [{ rows: orphanPolicies }, { rows: orphanApps }] = await Promise.all([
      pool.query(
        `SELECT server_id, name FROM route_policies
          WHERE ingress_type = 'device' AND ingress_device_id = $1`,
        [req.params.id]
      ),
      pool.query(
        `SELECT id, server_id FROM application_servers
          WHERE target_device_id = $1`,
        [req.params.id]
      ),
    ]);

    const { rowCount } = await pool.query('DELETE FROM devices WHERE id = $1', [req.params.id]);
    if (rowCount === 0) return res.status(404).json({ error: 'Device not found' });

    // Force-remove orphan policy rules by name.
    if (orphanPolicies.length > 0) {
      const { resyncPoliciesByIds } = require('../../services/policyResync');
      const byServer = new Map();
      for (const p of orphanPolicies) {
        if (!byServer.has(p.server_id)) byServer.set(p.server_id, []);
        byServer.get(p.server_id).push(p.name);
      }
      await Promise.allSettled(
        [...byServer.entries()].map(async ([sid, names]) => {
          try { await resyncPoliciesByIds(sid, [], names); }
          catch (e) { console.warn(`[devices/delete] policy cleanup server=${sid}: ${e.message}`); }
        })
      );
    }

    // Force-remove orphan app-server firewall rules by groupId.
    if (orphanApps.length > 0) {
      const { removeAppServerRules } = require('../../services/appServerFirewall');
      await Promise.allSettled(orphanApps.map(async a => {
        try { await removeAppServerRules(a.server_id, a.id); }
        catch (e) { console.warn(`[devices/delete] app cleanup id=${a.id}: ${e.message}`); }
      }));
    }

    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
