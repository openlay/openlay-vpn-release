const { Router } = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { verifyAttestation } = require('node-app-attest');
const { pool } = require('../db/pool');
const config = require('../config');
const { verifyAppleIdentityToken } = require('../services/appleAuth');
const { verifySecureEnclaveSignature } = require('../services/signatureVerifier');
const rl = require('../middleware/rateLimit');

// Same wording as /api/connect + /api/enroll so the user sees one
// consistent message no matter which hop refuses the request.
const APP_ATTEST_USER_ERROR = 'Only Apple App Store applications are allowed to connect.';

/**
 * Verify an App Attest attestation token bound to a server-issued challenge.
 * Returns the verified result on success, or null + sets res.status on failure.
 *
 * Used by /api/auth/apple. The same shape used by /api/enroll lives in its
 * own route handler — kept duplicated to avoid coupling the two flows.
 */
async function verifyClientAppAttest(req, res, { os }) {
  if (config.skipAppAttest) return { skipped: true };
  if (!config.appAttestProduction) return { skipped: true };
  if (!['ios', 'macos'].includes(os)) return { skipped: true };

  const attestKeyId = req.body?.attest_key_id ?? req.body?.attestKeyId;
  const attestation = req.body?.attestation;
  const attestChallenge = req.body?.attest_challenge ?? req.body?.attestChallenge;
  if (!attestKeyId || !attestation || !attestChallenge) {
    console.log('[auth/apple] App Attest headers missing for', os);
    res.status(403).json({ error: APP_ATTEST_USER_ERROR });
    return null;
  }

  // Validate challenge: unused + not expired. Issued via /api/enroll/challenge.
  // We reuse the same challenge minting endpoint for both flows since both are
  // pre-auth (no JWT yet) and we don't want to mint a separate one per surface.
  const { rows: challRows } = await pool.query(
    `SELECT id FROM attest_challenges
       WHERE challenge = $1 AND user_id IS NULL AND used = FALSE AND expires_at > NOW()
       LIMIT 1`,
    [attestChallenge]
  );
  if (challRows.length === 0) {
    console.log('[auth/apple] invalid/expired attest_challenge');
    res.status(403).json({ error: APP_ATTEST_USER_ERROR });
    return null;
  }

  const allowDev = !config.appAttestProduction;
  let result = null;
  let lastError = null;
  for (const bundleId of config.appleClientIds) {
    try {
      result = await verifyAttestation({
        attestation: Buffer.from(attestation, 'base64'),
        challenge: attestChallenge,
        keyId: attestKeyId,
        bundleIdentifier: bundleId,
        teamIdentifier: config.appleTeamId,
        allowDevelopmentEnvironment: allowDev,
      });
      result._bundleId = bundleId;
      break;
    } catch (err) {
      lastError = err;
    }
  }
  if (!result) {
    console.log('[auth/apple] App Attest failed:', lastError?.message);
    res.status(403).json({ error: APP_ATTEST_USER_ERROR });
    return null;
  }

  await pool.query('UPDATE attest_challenges SET used = TRUE WHERE id = $1', [challRows[0].id]);
  return { skipped: false, ...result, keyId: attestKeyId };
}

// Password verification (scrypt, matches management server).
// Constant-time compare — see notes in server/src/routes/auth.js.
async function verifyPassword(password, hash) {
  const [salt, key] = hash.split(':');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) return reject(err);
      const expected = Buffer.from(key, 'hex');
      if (expected.length !== derivedKey.length) return resolve(false);
      resolve(crypto.timingSafeEqual(derivedKey, expected));
    });
  });
}

const router = Router();

// POST /api/auth/apple
router.post('/apple', rl.apple, async (req, res) => {
  try {
    const identityToken = req.body.identityToken || req.body.identity_token;
    const name = req.body.name;
    const os = req.body.os; // optional: 'ios' | 'macos' — used to gate App Attest
    if (!identityToken) {
      return res.status(400).json({ error: 'identityToken is required' });
    }

    // Verify App Attest before doing any DB writes — when APP_ATTEST_PRODUCTION
    // is on, we refuse Apple sign-ins from non-genuine clients (curl, debug
    // builds, etc.). Skipped on staging (SKIP_APP_ATTEST), in non-prod
    // attestation mode, or when the OS isn't iOS/macOS.
    const attestCheck = await verifyClientAppAttest(req, res, { os });
    if (attestCheck === null) return; // verifier already wrote the response

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
      { expiresIn: '30d', algorithm: 'HS256' }
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
router.post('/login', rl.login, async (req, res) => {
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
      { expiresIn: '30d', algorithm: 'HS256' }
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

// POST /api/auth/device/challenge — issue a one-time challenge for the
// next /api/auth/device call. Caller posts { deviceId }; server returns
// { challenge, expiresAt }. Challenges live for DEVICE_AUTH_CHALLENGE_TTL_S
// seconds and are single-use — the matching /device call marks it used,
// after which any replay (including the legitimate caller retrying) fails.
//
// Why this exists: the previous flow let the client supply its own
// challenge with replay defence reduced to "reject EXACTLY the last value
// stored on the device row". Any other captured (challenge, signature)
// tuple replayed forever. Server-issued one-time challenges are the
// standard defence — same shape as attest_challenges and the Apple Sign
// In challenge flow.
const DEVICE_AUTH_CHALLENGE_TTL_S = 120;

router.post('/device/challenge', rl.deviceChallenge, async (req, res) => {
  try {
    const { deviceId } = req.body || {};
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

    const { rows } = await pool.query(
      'SELECT id, status FROM devices WHERE id = $1 OR hardware_id = $1',
      [deviceId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Device not found' });
    if (rows[0].status !== 'enabled') {
      return res.status(403).json({ error: 'Device is not enabled' });
    }

    const challenge = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + DEVICE_AUTH_CHALLENGE_TTL_S * 1000);
    await pool.query(
      `INSERT INTO device_auth_challenges (device_id, challenge, expires_at)
       VALUES ($1, $2, $3)`,
      [rows[0].id, challenge, expiresAt]
    );

    res.json({ challenge, expiresAt: expiresAt.toISOString() });
  } catch (err) {
    console.error('[auth/device/challenge] error:', err.message);
    res.status(500).json({ error: 'Failed to issue challenge' });
  }
});

// POST /api/auth/device — SE signature login for enroll-type users
// body: { deviceId, challenge, signature }
//
// Challenge MUST have been issued by /api/auth/device/challenge for this
// device. Single-use: marked used on first successful verify; replays
// (including legitimate retries with the same body) fail with 401.
router.post('/device', rl.device, async (req, res) => {
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

    // Validate challenge — two paths, both enforce single-use via the
    // device_auth_challenges UNIQUE(challenge) constraint:
    //
    //   1. Strict (preferred): challenge was issued by
    //      /api/auth/device/challenge, lives in DB with used=FALSE +
    //      not expired. Atomic UPDATE...RETURNING marks it used.
    //
    //   2. Transitional: legacy clients still pick their own challenge.
    //      We accept it IF it's long enough to be unguessable AND not
    //      previously seen for any device — INSERT with used=TRUE
    //      records it; UNIQUE collision = replay = 401. This keeps
    //      existing iOS/macOS/linux clients working through the
    //      rollout window while still closing the "replay-forever"
    //      hole the old logic had.
    //
    // Remove the transitional branch once all clients call
    // /api/auth/device/challenge first.
    const { rows: challRows } = await pool.query(
      `UPDATE device_auth_challenges
          SET used = TRUE
        WHERE challenge = $1 AND device_id = $2
          AND used = FALSE AND expires_at > NOW()
        RETURNING id`,
      [challenge, device.id]
    );
    if (challRows.length === 0) {
      // No server-issued challenge matched. Fall back to legacy
      // client-chosen challenge with single-use enforcement.
      if (typeof challenge !== 'string' || challenge.length < 32) {
        return res.status(401).json({ error: 'Invalid or expired challenge' });
      }
      try {
        await pool.query(
          `INSERT INTO device_auth_challenges (device_id, challenge, expires_at, used)
           VALUES ($1, $2, NOW() + INTERVAL '5 minutes', TRUE)`,
          [device.id, challenge]
        );
      } catch (err) {
        // PostgreSQL unique_violation: this challenge was already used.
        if (err.code === '23505') {
          return res.status(401).json({ error: 'Challenge already used (replay detected)' });
        }
        throw err;
      }
    }

    const ok = verifySecureEnclaveSignature(device.public_key, challenge, signature);
    if (!ok) return res.status(401).json({ error: 'Invalid signature' });

    await pool.query(
      'UPDATE devices SET last_auth_at = NOW() WHERE id = $1',
      [device.id]
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
      { expiresIn: '30d', algorithm: 'HS256' }
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
