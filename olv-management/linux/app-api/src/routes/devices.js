const { Router } = require('express');
const { pool } = require('../db/pool');

const router = Router();

// POST /api/devices — Register a new device
router.post('/', async (req, res) => {
  try {
    const { name, os, osVersion, publicKey } = req.body;

    if (!os || !publicKey) {
      return res.status(400).json({ error: 'os and publicKey are required' });
    }

    const validOs = ['macos', 'ios', 'windows', 'android'];
    if (!validOs.includes(os)) {
      return res.status(400).json({ error: `os must be one of: ${validOs.join(', ')}` });
    }

    // Check if device with same public key already exists for this user
    const { rows: existing } = await pool.query(
      'SELECT * FROM devices WHERE public_key = $1 AND user_id = $2',
      [publicKey, req.user.id]
    );

    if (existing.length > 0) {
      return res.json({ device: existing[0] });
    }

    // Check require_device_approval setting (per-enterprise, fallback to global)
    const { rows: entRole } = await pool.query(
      'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 LIMIT 1',
      [req.user.id]
    );
    const userEnterpriseId = entRole[0]?.enterprise_id;

    let requireApproval = false;
    if (userEnterpriseId) {
      const { rows: entSetting } = await pool.query(
        `SELECT value FROM enterprise_settings WHERE enterprise_id = $1 AND key = 'require_device_approval'`,
        [userEnterpriseId]
      );
      if (entSetting.length > 0) {
        requireApproval = entSetting[0].value === 'true';
      }
    }
    if (!requireApproval) {
      // Fallback to global setting
      const { rows: globalSetting } = await pool.query(
        `SELECT value FROM app_settings WHERE key = 'require_device_approval'`
      );
      requireApproval = globalSetting.length > 0 && globalSetting[0].value === 'true';
    }
    // Apple ID login always auto-approve; password login respects setting
    const { rows: userRows } = await pool.query('SELECT auth_type FROM users WHERE id = $1', [req.user.id]);
    const isAppleAuth = userRows[0]?.auth_type === 'apple';
    const deviceStatus = (isAppleAuth || !requireApproval) ? 'enabled' : 'pending';

    const { rows } = await pool.query(
      `INSERT INTO devices (name, os, os_version, public_key, status, user_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [name || '', os, osVersion || '', publicKey, deviceStatus, req.user.id]
    );

    res.status(201).json({ device: rows[0] });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/devices — List my devices
router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ devices: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PUT /api/devices/:deviceId — Update device name
router.put('/:deviceId', async (req, res) => {
  try {
    const { name } = req.body;
    const { rows } = await pool.query(
      `UPDATE devices SET name = $1, updated_at = NOW()
       WHERE id = $2 AND user_id = $3
       RETURNING *`,
      [name || '', req.params.deviceId, req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json({ device: rows[0] });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
