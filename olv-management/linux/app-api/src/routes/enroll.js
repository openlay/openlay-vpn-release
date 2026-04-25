const { Router } = require('express');
const { pool } = require('../db/pool');

const CODE_VALUE_KEY = 'enrollment_code_value';
const CODE_EXPIRES_KEY = 'enrollment_code_expires_at';

const router = Router();

// POST /api/enroll
// Public (unauthenticated). The 10-digit code identifies WHICH enterprise
// the device is enrolling into (enterprise admins rotate per-enterprise).
// We look it up across enterprise_settings, validate expiry, then record
// a pending enrollment_request pre-stamped with that enterprise_id so the
// admin doesn't have to pick at approve time (they still can override).
router.post('/', async (req, res) => {
  try {
    const code = req.body?.code;
    const deviceName = req.body?.deviceName ?? req.body?.device_name;
    const hardwareId = req.body?.hardwareId ?? req.body?.hardware_id;
    const os = req.body?.os;
    const osVersion = req.body?.osVersion ?? req.body?.os_version;
    const publicKey = req.body?.publicKey ?? req.body?.public_key;

    if (!code || typeof code !== 'string' || !/^\d{10}$/.test(code)) {
      return res.status(400).json({ error: 'code must be a 10-digit string' });
    }
    if (!deviceName || !hardwareId || !os || !publicKey) {
      return res.status(400).json({
        error: 'deviceName, hardwareId, os, and publicKey are required',
      });
    }
    if (!['macos', 'ios', 'windows', 'android', 'linux'].includes(os)) {
      return res.status(400).json({ error: 'os must be macos, ios, windows, android, or linux' });
    }

    // Reverse-lookup: find the enterprise whose current code matches.
    const { rows: codeRows } = await pool.query(
      `SELECT v.enterprise_id AS "enterpriseId",
              e.value          AS "expiresAt"
         FROM enterprise_settings v
         JOIN enterprise_settings e
           ON e.enterprise_id = v.enterprise_id AND e.key = $1
        WHERE v.key = $2 AND v.value = $3`,
      [CODE_EXPIRES_KEY, CODE_VALUE_KEY, code]
    );
    if (codeRows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }
    const { enterpriseId, expiresAt } = codeRows[0];
    const expiresMs = expiresAt ? Date.parse(expiresAt) : 0;
    if (!expiresMs || expiresMs <= Date.now()) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }

    // Idempotency: reuse an outstanding pending request for the same device
    // (scoped to the same enterprise — different orgs should not collide).
    const { rows: existing } = await pool.query(
      `SELECT id FROM enrollment_requests
        WHERE status = 'pending'
          AND hardware_id = $1
          AND public_key = $2
          AND enterprise_id IS NOT DISTINCT FROM $3
        LIMIT 1`,
      [hardwareId, publicKey, enterpriseId]
    );
    if (existing.length > 0) {
      return res.status(201).json({
        enrollmentId: existing[0].id,
        status: 'pending',
        enterpriseId,
      });
    }

    const { rows } = await pool.query(
      `INSERT INTO enrollment_requests
         (device_name, hardware_id, os, os_version, public_key, status, enterprise_id)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6)
       RETURNING id`,
      [deviceName, hardwareId, os, osVersion || '', publicKey, enterpriseId]
    );

    res.status(201).json({
      enrollmentId: rows[0].id,
      status: 'pending',
      enterpriseId,
    });
  } catch (err) {
    console.error('[enroll] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/enroll/:id/status — public polling endpoint
router.get('/:id/status', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT status,
              approved_device_id AS "deviceId",
              approved_user_id   AS "userId",
              enterprise_id      AS "enterpriseId"
       FROM enrollment_requests WHERE id = $1`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Enrollment not found' });
    }
    const r = rows[0];
    if (r.status === 'approved') {
      return res.json({
        status: r.status,
        deviceId: r.deviceId,
        userId: r.userId,
        enterpriseId: r.enterpriseId,
      });
    }
    res.json({ status: r.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
