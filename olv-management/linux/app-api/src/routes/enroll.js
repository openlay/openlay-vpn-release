const { Router } = require('express');
const { pool } = require('../db/pool');

const CODE_VALUE_KEY = 'enrollment_code_value';
const CODE_EXPIRES_KEY = 'enrollment_code_expires_at';

const router = Router();

// POST /api/enroll
// Public (unauthenticated). Validates the current global enroll code, records
// a pending enrollment_request, returns an opaque enrollmentId the client
// polls until the admin approves.
router.post('/', async (req, res) => {
  try {
    const { code, deviceName, hardwareId, os, osVersion, publicKey } = req.body || {};

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

    const { rows: settings } = await pool.query(
      `SELECT key, value FROM app_settings WHERE key IN ($1, $2)`,
      [CODE_VALUE_KEY, CODE_EXPIRES_KEY]
    );
    const map = Object.fromEntries(settings.map(r => [r.key, r.value]));
    const storedCode = map[CODE_VALUE_KEY] || '';
    const expiresAt = map[CODE_EXPIRES_KEY] || '';
    const expiresMs = expiresAt ? Date.parse(expiresAt) : 0;

    if (!storedCode || storedCode !== code) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }
    if (!expiresMs || expiresMs <= Date.now()) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }

    // Idempotency: reuse an outstanding pending request for the same device.
    const { rows: existing } = await pool.query(
      `SELECT id FROM enrollment_requests
       WHERE status = 'pending' AND hardware_id = $1 AND public_key = $2
       LIMIT 1`,
      [hardwareId, publicKey]
    );
    if (existing.length > 0) {
      return res.status(201).json({ enrollmentId: existing[0].id, status: 'pending' });
    }

    const { rows } = await pool.query(
      `INSERT INTO enrollment_requests
         (device_name, hardware_id, os, os_version, public_key, status)
       VALUES ($1, $2, $3, $4, $5, 'pending')
       RETURNING id`,
      [deviceName, hardwareId, os, osVersion || '', publicKey]
    );

    res.status(201).json({ enrollmentId: rows[0].id, status: 'pending' });
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
