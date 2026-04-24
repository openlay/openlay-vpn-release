const { Router } = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool } = require('../db/pool');
const config = require('../config');
const { verifyAppleIdentityToken } = require('../services/appleAuth');
const { verifySecureEnclaveSignature } = require('../services/signatureVerifier');

// Password verification (scrypt, matches management server)
async function verifyPassword(password, hash) {
  const [salt, key] = hash.split(':');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex') === key);
    });
  });
}

const router = Router();

// POST /api/auth/apple
router.post('/apple', async (req, res) => {
  try {
    const identityToken = req.body.identityToken || req.body.identity_token;
    const name = req.body.name;
    if (!identityToken) {
      return res.status(400).json({ error: 'identityToken is required' });
    }

    // Verify with Apple JWKS
    const applePayload = await verifyAppleIdentityToken(identityToken, config.appleClientIds);
    const appleId = applePayload.sub;
    const email = applePayload.email || null;

    // Upsert user — Apple only sends email/name on first authorization
    const { rows } = await pool.query(
      `INSERT INTO users (apple_id, email, name, status)
       VALUES ($1, $2, $3, 'enabled')
       ON CONFLICT (apple_id)
       DO UPDATE SET
         email = COALESCE(EXCLUDED.email, users.email),
         name = COALESCE(EXCLUDED.name, users.name),
         updated_at = NOW()
       RETURNING *`,
      [appleId, email, name || null]
    );

    const user = rows[0];

    if (user.status !== 'enabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    // Sign JWT
    const token = jwt.sign(
      { sub: user.id, email: user.email, status: user.status },
      config.jwtSecret,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        status: user.status,
        authType: user.auth_type || 'apple',
      },
    });
  } catch (err) {
    if (err.code === 'ERR_JWT_EXPIRED' || err.code === 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED') {
      return res.status(401).json({ error: 'Invalid Apple identity token' });
    }
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/auth/login — Username/password login with device auto-enrollment
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const result = await pool.query(
      `SELECT * FROM users WHERE username = $1 AND auth_type = 'password'`,
      [username]
    );
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = result.rows[0];
    if (!user.password_hash) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (user.status !== 'enabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    // Device auto-enrollment for password users
    const deviceId = req.body.deviceId || req.body.device_id;
    const deviceName = req.body.deviceName || req.body.device_name;
    const deviceOs = req.body.deviceOs || req.body.device_os;
    const deviceOsVersion = req.body.deviceOsVersion || req.body.device_os_version;
    const publicKey = req.body.publicKey || req.body.public_key || '';

    // Check device lock: locked_device_id is a DB record UUID, deviceId from client is hardware ID
    if (user.locked_device_id && deviceId) {
      const lockedDevice = await pool.query('SELECT hardware_id FROM devices WHERE id = $1', [user.locked_device_id]);
      const lockedHardwareId = lockedDevice.rows[0]?.hardware_id || user.locked_device_id;
      if (lockedHardwareId !== deviceId) {
        return res.status(403).json({
          error: 'This account is locked to another device. Contact your admin to reset.',
          code: 'DEVICE_LOCKED',
        });
      }
    }

    // Update SE public key on every login if provided
    if (deviceId && publicKey) {
      await pool.query(
        `UPDATE devices SET public_key = $1, updated_at = NOW()
         WHERE hardware_id = $2 AND user_id = $3 AND (public_key IS NULL OR public_key = '')`,
        [publicKey, deviceId, user.id]
      );
    }

    // Auto-enroll device on first login
    // 1 user = 1 device (locked_device_id), but 1 device can have multiple users
    if (deviceId && !user.locked_device_id) {
      const entRow = await pool.query(
        'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 LIMIT 1',
        [user.id]
      );
      const userEnterpriseId = entRow.rows[0]?.enterprise_id || null;

      // Check if this user already has a device record for this hardware
      const existing = await pool.query(
        'SELECT id FROM devices WHERE hardware_id = $1 AND user_id = $2',
        [deviceId, user.id]
      );

      let enrolledDeviceId;
      if (existing.rows.length > 0) {
        enrolledDeviceId = existing.rows[0].id;
        await pool.query(
          `UPDATE devices SET name = $1, public_key = CASE WHEN $2 != '' THEN $2 ELSE public_key END,
           enterprise_id = COALESCE($3, enterprise_id), updated_at = NOW() WHERE id = $4`,
          [deviceName || 'Unknown', publicKey, userEnterpriseId, enrolledDeviceId]
        );
      } else {
        const ins = await pool.query(
          `INSERT INTO devices (name, os, os_version, public_key, status, user_id, enterprise_id, enrollment_method, hardware_id)
           VALUES ($1, $2, $3, $4, 'enabled', $5, $6, 'auto', $7)
           RETURNING id`,
          [deviceName || 'Unknown', deviceOs || 'unknown', deviceOsVersion || '', publicKey, user.id, userEnterpriseId, deviceId]
        );
        enrolledDeviceId = ins.rows[0].id;
      }

      await pool.query('UPDATE users SET locked_device_id = $1 WHERE id = $2', [enrolledDeviceId, user.id]);
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email, status: user.status },
      config.jwtSecret,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        status: user.status,
        authType: user.auth_type,
        lockedDeviceId: user.locked_device_id,
      },
    });
  } catch (err) {
    console.error('[auth/login] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/device — SE signature login for enroll-type users
// body: { deviceId, challenge, signature }
router.post('/device', async (req, res) => {
  try {
    const { deviceId, challenge, signature } = req.body || {};
    if (!deviceId || !challenge || !signature) {
      return res.status(400).json({ error: 'deviceId, challenge, and signature are required' });
    }

    const { rows } = await pool.query(
      'SELECT * FROM devices WHERE id = $1 OR hardware_id = $1',
      [deviceId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Device not found' });
    const device = rows[0];

    if (device.status !== 'enabled') {
      return res.status(403).json({ error: 'Device is not enabled' });
    }
    if (device.last_auth_challenge && device.last_auth_challenge === challenge) {
      return res.status(401).json({ error: 'Replay detected' });
    }

    const ok = verifySecureEnclaveSignature(device.public_key, challenge, signature);
    if (!ok) return res.status(401).json({ error: 'Invalid signature' });

    await pool.query(
      'UPDATE devices SET last_auth_challenge = $1, last_auth_at = NOW() WHERE id = $2',
      [challenge, device.id]
    );

    const { rows: userRows } = await pool.query(
      'SELECT id, email, name, username, status, auth_type FROM users WHERE id = $1',
      [device.user_id]
    );
    if (userRows.length === 0 || userRows[0].status !== 'enabled') {
      return res.status(403).json({ error: 'Account not found or disabled' });
    }
    const user = userRows[0];

    const token = jwt.sign(
      { sub: user.id, email: user.email, status: user.status },
      config.jwtSecret,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        status: user.status,
        authType: user.auth_type,
      },
      device: {
        id: device.id,
        name: device.name,
        status: device.status,
      },
    });
  } catch (err) {
    console.error('[auth/device] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me — Check token validity + get current user
const jwtAuth = require('../middleware/jwtAuth');

router.get('/me', jwtAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, email, name, username, status, auth_type, locked_device_id, created_at FROM users WHERE id = $1',
      [req.user.id]
    );

    if (rows.length === 0 || rows[0].status !== 'enabled') {
      return res.status(401).json({ error: 'Account not found or disabled' });
    }

    const user = rows[0];
    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        status: user.status,
        authType: user.auth_type,
        lockedDeviceId: user.locked_device_id,
      },
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
