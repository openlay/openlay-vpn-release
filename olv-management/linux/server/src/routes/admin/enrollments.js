const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { verifyAdminSignature } = require('../../services/adminSigning');

const router = Router();
router.use(enterpriseContext);

// GET /api/admin/enrollments?status=pending|approved|rejected|all
// Codes are per-enterprise → every enrollment_request is stamped with its
// enterprise_id at filing time. We scope the list to req.enterpriseId so an
// admin only sees their own enterprise's queue. Root sees everything when
// no enterprise header is set, or the chosen one when set.
router.get('/', async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const where = [];
    const params = [];
    if (status !== 'all') {
      if (!['pending', 'approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'status must be pending, approved, rejected, or all' });
      }
      params.push(status);
      where.push(`status = $${params.length}`);
    }
    // Scope: non-root callers only see their enterprise. Root with header
    // set scopes to that one; root without header sees the whole table.
    if (req.enterpriseRole !== 'root' || req.enterpriseId) {
      params.push(req.enterpriseId);
      where.push(`enterprise_id = $${params.length}`);
    }
    const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const { rows } = await pool.query(
      `SELECT id, enterprise_id AS "assignedEnterpriseId",
              device_name AS "deviceName", hardware_id AS "hardwareId",
              public_key AS "publicKey",
              os, os_version AS "osVersion", status,
              approved_device_id AS "approvedDeviceId",
              approved_user_id AS "approvedUserId",
              created_at AS "createdAt", updated_at AS "updatedAt"
       FROM enrollment_requests ${whereSql}
       ORDER BY created_at DESC`,
      params
    );
    res.json({ enrollments: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Slugify a device name into a candidate username. Keeps a-z0-9 and dashes,
// lowercases, caps at 50 chars. Empty result falls back to 'device'.
function slugifyUsername(name) {
  const base = (name || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 50) || 'device';
  return base;
}

// POST /api/admin/enrollments/:id/approve
// body: { enterprise_id?, server_id?, interface_name?, subnet_id? }
// enterprise_id is optional — when omitted we use the enterprise the
// enrollment was filed against (the code identifies the enterprise on
// /api/enroll, so it's pre-stamped). Admin can still override to re-route.
// server_id + interface_name (optional) creates a user_server_assignment
// in the same transaction so approve is one atomic step.
router.post('/:id/approve', async (req, res) => {
  const overrideEnterpriseId = req.body.enterprise_id || req.body.enterpriseId || null;
  const assignServerId = req.body.server_id || req.body.serverId || null;
  const assignInterfaceName = req.body.interface_name || req.body.interfaceName || null;
  const assignSubnetId = req.body.subnet_id || req.body.subnetId || null;

  // Pre-fetch the enrollment so the canonical signed payload includes the
  // device's hardware_id + public_key — this binds the admin's signature to
  // the specific device, not just the enrollment row id.
  const { rows: preview } = await pool.query(
    `SELECT hardware_id, public_key FROM enrollment_requests WHERE id = $1`,
    [req.params.id]
  );
  if (preview.length === 0) {
    return res.status(404).json({ error: 'Enrollment request not found' });
  }
  const sigCheck = await verifyAdminSignature(req, 'approve_enrollment', {
    target_type: 'enrollment',
    target_id: req.params.id,
    device_hardware_id: preview[0].hardware_id,
    device_public_key: preview[0].public_key,
  });
  if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { rows: reqRows } = await client.query(
      `SELECT * FROM enrollment_requests WHERE id = $1 FOR UPDATE`,
      [req.params.id]
    );
    if (reqRows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Enrollment request not found' });
    }
    const enrollment = reqRows[0];
    if (enrollment.status !== 'pending') {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `Enrollment is already ${enrollment.status}` });
    }

    // Use the override if admin passed one, else fall back to the request's
    // pre-stamped enterprise (set on /api/enroll based on the code).
    const enterpriseId = overrideEnterpriseId || enrollment.enterprise_id;
    if (!enterpriseId) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: 'enrollment has no enterprise — pass enterpriseId in body to assign one',
      });
    }

    // Admin must have a role in the target enterprise (root bypasses).
    if (req.enterpriseRole !== 'root') {
      const { rows: roleRows } = await client.query(
        'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.user.id, enterpriseId]
      );
      if (roleRows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'No access to this enterprise' });
      }
    }

    // Find a free username: slug, slug-2, slug-3, ... until unique.
    const baseSlug = slugifyUsername(enrollment.device_name);
    let username = baseSlug;
    let suffix = 2;
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const { rows: taken } = await client.query(
        'SELECT 1 FROM users WHERE username = $1',
        [username]
      );
      if (taken.length === 0) break;
      username = `${baseSlug}-${suffix++}`;
      if (username.length > 50) username = `${baseSlug.slice(0, 45)}-${suffix}`;
    }

    const { rows: userRows } = await client.query(
      `INSERT INTO users (name, username, auth_type, status)
       VALUES ($1, $2, 'enroll', 'enabled')
       RETURNING id`,
      [enrollment.device_name, username]
    );
    const userId = userRows[0].id;

    await client.query(
      `INSERT INTO user_enterprise_roles (user_id, enterprise_id, role)
       VALUES ($1, $2, 'member')`,
      [userId, enterpriseId]
    );

    const { rows: deviceRows } = await client.query(
      `INSERT INTO devices (name, os, os_version, public_key, status, user_id,
                            enterprise_id, enrollment_method, hardware_id)
       VALUES ($1, $2, $3, $4, 'enabled', $5, $6, 'enroll_code', $7)
       RETURNING id`,
      [
        enrollment.device_name,
        enrollment.os,
        enrollment.os_version,
        enrollment.public_key,
        userId,
        enterpriseId,
        enrollment.hardware_id,
      ]
    );
    const deviceId = deviceRows[0].id;

    await client.query(
      'UPDATE users SET locked_device_id = $1 WHERE id = $2',
      [deviceId, userId]
    );

    // Carry the App Attest record forward. /api/enroll captures it on iOS/macOS;
    // copying here makes /api/connect's appAttest middleware able to verify
    // assertions against the same keyId without forcing a re-attest after
    // approval.
    if (enrollment.attest_key_id && enrollment.attest_public_key) {
      // Match the pattern in /api/attest/verify: replace any prior row for
      // this device. The unique key in device_attestations is `key_id`, not
      // `device_id`, so we DELETE first to avoid keyId collisions if the
      // device was approved-and-rejected earlier.
      await client.query('DELETE FROM device_attestations WHERE device_id = $1', [deviceId]);
      await client.query(
        `INSERT INTO device_attestations
           (device_id, key_id, public_key, sign_count, receipt, environment, bundle_id)
         VALUES ($1, $2, $3, 0, $4, $5, $6)`,
        [
          deviceId,
          enrollment.attest_key_id,
          enrollment.attest_public_key,
          enrollment.attest_receipt || null,
          enrollment.attest_environment || null,
          enrollment.attest_bundle_id || null,
        ]
      );
    }

    await client.query(
      `UPDATE enrollment_requests
         SET status = 'approved', enterprise_id = $1,
             approved_device_id = $2, approved_user_id = $3, updated_at = NOW()
       WHERE id = $4`,
      [enterpriseId, deviceId, userId, enrollment.id]
    );

    // Optional: assign user to a server's interface in same transaction.
    let assignmentId = null;
    if (assignServerId && assignInterfaceName) {
      // Verify server belongs to this enterprise (or root override).
      const serverCheck = req.enterpriseRole === 'root'
        ? await client.query('SELECT 1 FROM servers WHERE id = $1', [assignServerId])
        : await client.query(
            'SELECT 1 FROM servers WHERE id = $1 AND enterprise_id = $2',
            [assignServerId, enterpriseId]
          );
      if (serverCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Server not found or not in this enterprise' });
      }
      const { rows: assignRows } = await client.query(
        `INSERT INTO user_server_assignments (user_id, server_id, interface_name, subnet_id)
         VALUES ($1, $2, $3, $4)
         RETURNING id`,
        [userId, assignServerId, assignInterfaceName, assignSubnetId]
      );
      assignmentId = assignRows[0].id;
    }

    await client.query('COMMIT');
    res.json({ deviceId, userId, enterpriseId, assignmentId });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: err.message });
  } finally {
    client.release();
  }
});

// POST /api/admin/enrollments/:id/reject
router.post('/:id/reject', async (req, res) => {
  try {
    const sigCheck = await verifyAdminSignature(req, 'reject_enrollment', {
      target_type: 'enrollment',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    const { rows } = await pool.query(
      `UPDATE enrollment_requests
         SET status = 'rejected', updated_at = NOW()
       WHERE id = $1 AND status = 'pending'
       RETURNING id, status`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Pending enrollment not found' });
    }
    res.json({ status: rows[0].status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
