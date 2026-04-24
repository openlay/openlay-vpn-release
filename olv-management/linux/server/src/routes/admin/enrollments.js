const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const router = Router();
router.use(enterpriseContext);

// GET /api/admin/enrollments?status=pending|approved|rejected|all
// All admins see every pending/approved/rejected row. Enterprise scoping is
// applied on approve (admin picks their enterprise from a UI list). Pending
// rows have enterprise_id = NULL; approved rows reveal the chosen one.
router.get('/', async (req, res) => {
  try {
    const status = req.query.status || 'pending';
    const params = [];
    let where = '';
    if (status !== 'all') {
      if (!['pending', 'approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'status must be pending, approved, rejected, or all' });
      }
      params.push(status);
      where = `WHERE status = $${params.length}`;
    }
    const { rows } = await pool.query(
      `SELECT id, enterprise_id AS "assignedEnterpriseId",
              device_name AS "deviceName", hardware_id AS "hardwareId",
              os, os_version AS "osVersion", status,
              approved_device_id AS "approvedDeviceId",
              approved_user_id AS "approvedUserId",
              created_at AS "createdAt", updated_at AS "updatedAt"
       FROM enrollment_requests ${where}
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

// POST /api/admin/enrollments/:id/approve   body: { enterpriseId }
router.post('/:id/approve', async (req, res) => {
  const enterpriseId = req.body.enterpriseId || req.body.enterprise_id;
  if (!enterpriseId) {
    return res.status(400).json({ error: 'enterpriseId is required' });
  }

  // Admin must have a role in the target enterprise (root bypasses).
  if (req.enterpriseRole !== 'root') {
    const { rows } = await pool.query(
      'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
      [req.user.id, enterpriseId]
    );
    if (rows.length === 0) {
      return res.status(403).json({ error: 'No access to this enterprise' });
    }
  }

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

    await client.query(
      `UPDATE enrollment_requests
         SET status = 'approved', enterprise_id = $1,
             approved_device_id = $2, approved_user_id = $3, updated_at = NOW()
       WHERE id = $4`,
      [enterpriseId, deviceId, userId, enrollment.id]
    );

    await client.query('COMMIT');
    res.json({ deviceId, userId, enterpriseId });
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
