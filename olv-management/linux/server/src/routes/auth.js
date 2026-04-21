const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const config = require('../config');
const pool = require('../db/pool').pool;
const jwtAuth = require('../middleware/jwtAuth');

// Simple password hashing using scrypt (no bcrypt dependency needed)
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      resolve(salt + ':' + key.toString('hex'));
    });
  });
}

async function verifyPassword(password, hash) {
  const [salt, key] = hash.split(':');
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, derivedKey) => {
      if (err) reject(err);
      resolve(derivedKey.toString('hex') === key);
    });
  });
}

// Apple JWKS endpoint
const APPLE_JWKS = createRemoteJWKSet(
  new URL('https://appleid.apple.com/auth/keys')
);

// --- Token pair helpers -----------------------------------------------------

// Issue an access JWT + a fresh refresh token persisted in auth_sessions.
// Caller supplies userId and (optionally) deviceId — deviceId is only set
// once the client has registered a Secure Enclave key. Returns the plain
// refresh token so the caller can deliver it to the client; the DB only
// stores its hash.
async function issueTokenPair(user, deviceId, opts = {}) {
  const sessionId = crypto.randomUUID();
  const refreshToken = crypto.randomBytes(32).toString('hex');
  const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');

  const now = Date.now();
  const accessExpires = new Date(now + config.sessionTtlHours * 3600 * 1000);
  const refreshExpires = new Date(now + config.loginTtlDays * 24 * 3600 * 1000);

  await pool.query(
    `INSERT INTO auth_sessions
       (id, user_id, device_id, refresh_token_hash, expires_at, user_agent)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [sessionId, user.id, deviceId || null, refreshHash, refreshExpires, opts.userAgent || null]
  );

  const accessToken = jwt.sign(
    { sub: user.id, email: user.email, status: user.status, typ: 'access', sid: sessionId },
    config.jwtSecret,
    { expiresIn: `${config.sessionTtlHours}h` }
  );

  return {
    accessToken,
    refreshToken,
    accessExpiresAt: accessExpires.toISOString(),
    refreshExpiresAt: refreshExpires.toISOString(),
    sessionId,
  };
}

// Re-issue an access token for an existing session (refresh flow). Does NOT
// rotate the refresh token — rotation can be added later when we need
// linkable session audit trails or want to cap refresh lifetime absolutely.
async function reissueAccessToken(sessionRow, user) {
  const accessExpires = new Date(Date.now() + config.sessionTtlHours * 3600 * 1000);
  const accessToken = jwt.sign(
    { sub: user.id, email: user.email, status: user.status, typ: 'access', sid: sessionRow.id },
    config.jwtSecret,
    { expiresIn: `${config.sessionTtlHours}h` }
  );
  await pool.query('UPDATE auth_sessions SET last_used_at = NOW() WHERE id = $1', [sessionRow.id]);
  return { accessToken, accessExpiresAt: accessExpires.toISOString() };
}

function hashRefresh(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Build the canonical challenge payload the client signs when refreshing.
// Keep it tiny + deterministic — JSON.stringify with sorted keys, UTF-8.
// The server reconstructs the same payload and runs SecKeyVerifySignature
// against the device's stored SE public key.
function canonicalChallenge({ refreshTokenHash, nonce, timestamp }) {
  return JSON.stringify({ nonce, refreshTokenHash, timestamp });
}

// Verify an ECDSA P-256 signature produced by the device's Secure Enclave
// against a base64-encoded SPKI/X.963 public key. iOS SE exports with
// `SecKeyCopyExternalRepresentation` which returns the X9.63-formatted
// uncompressed point (0x04 ∥ X ∥ Y, 65 bytes). Node's crypto wants SPKI;
// we convert by wrapping with the P-256 SubjectPublicKeyInfo prefix.
function verifyDeviceSignature(publicKeyBase64, challengeText, signatureBase64) {
  try {
    const raw = Buffer.from(publicKeyBase64, 'base64');
    if (raw.length !== 65 || raw[0] !== 0x04) return false; // not uncompressed P-256
    // P-256 SPKI prefix for 04||X||Y uncompressed key
    const spkiPrefix = Buffer.from(
      '3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'
    );
    const spki = Buffer.concat([spkiPrefix, raw]);
    const pubKey = crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    // SE produces DER-encoded ECDSA signature; Node verifies DER by default.
    return crypto.verify(
      'sha256',
      Buffer.from(challengeText, 'utf8'),
      pubKey,
      Buffer.from(signatureBase64, 'base64')
    );
  } catch (err) {
    console.warn('[auth/refresh] signature verify error:', err.message);
    return false;
  }
}

const CHALLENGE_TTL_SEC = 300; // 5 min — tight enough to thwart replay.

// POST /api/auth/apple — Verify Apple identity token, upsert user, return JWT
router.post('/apple', async (req, res) => {
  try {
    const identityToken = req.body.identityToken || req.body.identity_token;
    const name = req.body.name;
    if (!identityToken) {
      return res.status(400).json({ error: 'identityToken is required' });
    }

    // Verify Apple identity token
    const { payload } = await jwtVerify(identityToken, APPLE_JWKS, {
      issuer: 'https://appleid.apple.com',
      audience: config.appleClientIds,
    });

    const appleId = payload.sub;
    const email = payload.email || null;
    const displayName = name || email || null;

    // Upsert user
    const result = await pool.query(
      `INSERT INTO users (apple_id, email, name, status)
       VALUES ($1, $2, $3, 'enabled')
       ON CONFLICT (apple_id) DO UPDATE SET
         email = COALESCE(EXCLUDED.email, users.email),
         name = COALESCE(EXCLUDED.name, users.name),
         updated_at = NOW()
       RETURNING *`,
      [appleId, email, displayName]
    );

    const user = result.rows[0];
    if (user.status !== 'enabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    // Load enterprises for this user
    const entResult = await pool.query(
      `SELECT e.*, uer.role
       FROM enterprises e
       JOIN user_enterprise_roles uer ON uer.enterprise_id = e.id
       WHERE uer.user_id = $1
       ORDER BY e.name`,
      [user.id]
    );

    // Issue paired tokens — refresh token bound to this session, access token
    // for immediate API calls.
    const pair = await issueTokenPair(user, null, { userAgent: req.headers['user-agent'] });

    // Load workspaces per enterprise
    const enterprises = await loadEnterprisesWithUserGroups(user.id, entResult.rows);

    // Check if root user
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [user.id]);
    const isRoot = rootCheck.rows.length > 0;

    res.json({
      // Legacy field — older clients keep reading `token`. Remove once all
      // clients are updated to use accessToken/refreshToken explicitly.
      token: pair.accessToken,
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      accessExpiresAt: pair.accessExpiresAt,
      refreshExpiresAt: pair.refreshExpiresAt,
      sessionId: pair.sessionId,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        status: user.status,
        isRoot,
      },
      enterprises,
    });
  } catch (err) {
    console.error('[auth/apple] Error:', err.message);
    res.status(401).json({ error: 'Invalid identity token: ' + err.message });
  }
});

// POST /api/auth/refresh — Exchange a refresh token (+ SE signature proving
// possession of the device key) for a new access token. Body:
//   { refreshToken, challenge: { nonce, timestamp, refreshTokenHash }, signature }
// The challenge is signed client-side with the Secure Enclave private key;
// the server verifies against the device's stored SE public key.
router.post('/refresh', async (req, res) => {
  try {
    const refreshToken = req.body.refreshToken || req.body.refresh_token;
    const challenge = req.body.challenge || {};
    const signature = req.body.signature;
    if (!refreshToken || !signature || !challenge.nonce || !challenge.timestamp) {
      return res.status(400).json({ error: 'refreshToken, challenge (nonce+timestamp), and signature are required' });
    }

    // Clock-skew guard against replay.
    const tsMs = new Date(challenge.timestamp).getTime();
    if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > CHALLENGE_TTL_SEC * 1000) {
      return res.status(401).json({ error: 'Challenge timestamp out of range' });
    }

    const refreshHash = hashRefresh(refreshToken);
    if (challenge.refreshTokenHash && challenge.refreshTokenHash !== refreshHash) {
      return res.status(401).json({ error: 'Challenge/refresh token mismatch' });
    }

    const { rows } = await pool.query(
      `SELECT s.*, u.id AS uid, u.email, u.status, u.name, d.public_key AS device_public_key
       FROM auth_sessions s
       JOIN users u ON u.id = s.user_id
       LEFT JOIN devices d ON d.id = s.device_id
       WHERE s.refresh_token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
      [refreshHash]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Refresh token invalid or expired' });
    }
    const session = rows[0];
    if (session.status !== 'enabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }
    if (!session.device_public_key) {
      // No SE key registered for this device row — we can't verify PoP, so
      // reject. This also prevents a refresh token leaked via channel X from
      // being usable on a different device.
      return res.status(401).json({ error: 'Device not bound to this session' });
    }

    const challengeText = canonicalChallenge({
      refreshTokenHash: refreshHash,
      nonce: challenge.nonce,
      timestamp: challenge.timestamp,
    });
    if (!verifyDeviceSignature(session.device_public_key, challengeText, signature)) {
      return res.status(401).json({ error: 'Invalid device signature' });
    }

    const user = { id: session.uid, email: session.email, status: session.status };
    const pair = await reissueAccessToken(session, user);
    res.json(pair);
  } catch (err) {
    console.error('[auth/refresh] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/auth/session — Revoke the current session (logout). Accepts
// the access token via Authorization header; looks up the session via the
// `sid` claim and marks it revoked.
router.delete('/session', jwtAuth, async (req, res) => {
  try {
    if (req.user.sessionId) {
      await pool.query(
        'UPDATE auth_sessions SET revoked_at = NOW() WHERE id = $1 AND user_id = $2',
        [req.user.sessionId, req.user.id]
      );
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/login — Username/password login with auto device enrollment
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    // Device info sent from client for auto-enrollment
    const deviceId = req.body.deviceId || req.body.device_id;
    const deviceName = req.body.deviceName || req.body.device_name;
    const deviceOs = req.body.deviceOs || req.body.device_os;
    const deviceOsVersion = req.body.deviceOsVersion || req.body.device_os_version;
    const publicKey = req.body.publicKey || req.body.public_key || '';

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

    // Password user device lock: locked_device_id is DB record UUID, deviceId is hardware ID
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

    // Auto-enroll device for password users (first login locks device)
    // 1 user = 1 device, but 1 device can have multiple users
    let enrolledDeviceId = user.locked_device_id || null;
    if (deviceId && !user.locked_device_id) {
      const entRow = await pool.query(
        'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 LIMIT 1',
        [user.id]
      );
      const userEnterpriseId = entRow.rows[0]?.enterprise_id || null;

      const existing = await pool.query(
        'SELECT id FROM devices WHERE hardware_id = $1 AND user_id = $2',
        [deviceId, user.id]
      );

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

      // Lock user to this device record
      await pool.query('UPDATE users SET locked_device_id = $1 WHERE id = $2', [enrolledDeviceId, user.id]);
    }

    const entResult = await pool.query(
      `SELECT e.*, uer.role FROM enterprises e
       JOIN user_enterprise_roles uer ON uer.enterprise_id = e.id
       WHERE uer.user_id = $1 ORDER BY e.name`,
      [user.id]
    );

    const enterprises = await loadEnterprisesWithUserGroups(user.id, entResult.rows);
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [user.id]);

    const pair = await issueTokenPair(user, enrolledDeviceId, { userAgent: req.headers['user-agent'] });

    res.json({
      token: pair.accessToken, // legacy
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      accessExpiresAt: pair.accessExpiresAt,
      refreshExpiresAt: pair.refreshExpiresAt,
      sessionId: pair.sessionId,
      user: {
        id: user.id, email: user.email, name: user.name,
        username: user.username, status: user.status,
        authType: user.auth_type,
        lockedDeviceId: user.locked_device_id,
        isRoot: rootCheck.rows.length > 0,
      },
      enterprises,
    });
  } catch (err) {
    console.error('[auth/login] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/create-admin — Create admin user with password (requires JWT + super_admin/root)
router.post('/create-admin', jwtAuth, async (req, res) => {
  try {
    const { username, password, name, email, role } = req.body;
    // Enterprise from body or X-Enterprise-Id header (iOS sends header automatically)
    const enterpriseId = req.body.enterpriseId || req.body.enterprise_id || req.headers['x-enterprise-id'];
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check caller is admin+ of the enterprise or root
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
    const isRoot = rootCheck.rows.length > 0;

    // Non-root MUST provide enterpriseId — cannot create free-floating users
    if (!isRoot && !enterpriseId) {
      return res.status(400).json({ error: 'enterpriseId is required' });
    }

    if (!isRoot) {
      // Verify caller belongs to this enterprise with admin+ role
      const entRole = await pool.query(
        `SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2`,
        [req.user.id, enterpriseId]
      );
      if (entRole.rows.length === 0 || !['super_admin', 'admin'].includes(entRole.rows[0].role)) {
        return res.status(403).json({ error: 'admin access or higher required in this enterprise' });
      }

      // Verify enterprise exists
      const entCheck = await pool.query('SELECT 1 FROM enterprises WHERE id = $1', [enterpriseId]);
      if (entCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Enterprise not found' });
      }
    }

    // Check username uniqueness
    const existing = await pool.query('SELECT 1 FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const passwordHash = await hashPassword(password);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const userResult = await client.query(
        `INSERT INTO users (username, password_hash, name, email, auth_type, status)
         VALUES ($1, $2, $3, $4, 'password', 'enabled')
         RETURNING *`,
        [username, passwordHash, name || null, email || null]
      );
      const newUser = userResult.rows[0];

      // Assign to enterprise — enforce role hierarchy
      if (enterpriseId) {
        const ROLE_RANK = { root: 4, super_admin: 3, admin: 2, member: 1 };
        const callerEntRole = await pool.query(
          'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
          [req.user.id, enterpriseId]
        );
        const callerRole = isRoot ? 'root' : (callerEntRole.rows[0]?.role || 'member');
        const callerRank = ROLE_RANK[callerRole] || 0;
        let assignRole = role || 'member';

        // Only allow valid roles
        if (!['super_admin', 'admin', 'member'].includes(assignRole)) {
          await client.query('ROLLBACK');
          return res.status(400).json({ error: `Invalid role: ${assignRole}. Must be super_admin, admin, or member` });
        }
        // Cannot assign role >= own rank
        if ((ROLE_RANK[assignRole] || 0) >= callerRank) {
          await client.query('ROLLBACK');
          return res.status(403).json({ error: `Cannot assign role "${assignRole}" — you can only assign roles below your own` });
        }

        await client.query(
          `INSERT INTO user_enterprise_roles (user_id, enterprise_id, role)
           VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
          [newUser.id, enterpriseId, assignRole]
        );
      }

      await client.query('COMMIT');

      res.status(201).json({
        user: {
          id: newUser.id, username: newUser.username,
          name: newUser.name, email: newUser.email,
          status: newUser.status, authType: newUser.auth_type,
        },
      });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('[auth/create-admin] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/auth/reset-password — Reset password for a user (super_admin/root, or self)
router.put('/reset-password', jwtAuth, async (req, res) => {
  try {
    const targetUserId = req.body.userId || req.body.user_id;
    const newPassword = req.body.password || req.body.new_password;

    if (!newPassword) return res.status(400).json({ error: 'password is required' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    // Determine target: self or another user
    const userId = targetUserId || req.user.id;
    const isSelf = userId === req.user.id;

    if (!isSelf) {
      // Must be super_admin or root to reset other users
      const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
      const isRoot = rootCheck.rows.length > 0;

      if (!isRoot) {
        // Check if super_admin in any shared enterprise
        const shared = await pool.query(
          `SELECT 1 FROM user_enterprise_roles a
           JOIN user_enterprise_roles b ON a.enterprise_id = b.enterprise_id
           WHERE a.user_id = $1 AND a.role = 'super_admin' AND b.user_id = $2`,
          [req.user.id, userId]
        );
        if (shared.rows.length === 0) {
          return res.status(403).json({ error: 'super_admin or root access required' });
        }
      }
    }

    // Verify target is a password user
    const userCheck = await pool.query(
      `SELECT auth_type FROM users WHERE id = $1`,
      [userId]
    );
    if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (userCheck.rows[0].auth_type !== 'password') {
      return res.status(400).json({ error: 'Can only reset password for password-based accounts' });
    }

    const passwordHash = await hashPassword(newPassword);
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
      [passwordHash, userId]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('[auth/reset-password] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/auth/reset-device — Reset device lock for a password user (admin+)
router.put('/reset-device', jwtAuth, async (req, res) => {
  try {
    const targetUserId = req.body.userId || req.body.user_id;
    if (!targetUserId) return res.status(400).json({ error: 'userId is required' });

    // Verify caller has admin+ access to a shared enterprise
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
    const isRoot = rootCheck.rows.length > 0;

    if (!isRoot) {
      const shared = await pool.query(
        `SELECT 1 FROM user_enterprise_roles a
         JOIN user_enterprise_roles b ON a.enterprise_id = b.enterprise_id
         WHERE a.user_id = $1 AND a.role IN ('super_admin', 'admin') AND b.user_id = $2`,
        [req.user.id, targetUserId]
      );
      if (shared.rows.length === 0) {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }

    // Get current user
    const userCheck = await pool.query('SELECT auth_type, locked_device_id FROM users WHERE id = $1', [targetUserId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (userCheck.rows[0].auth_type !== 'password') {
      return res.status(400).json({ error: 'Only password-based accounts have device locks' });
    }

    // Clear device lock
    await pool.query('UPDATE users SET locked_device_id = NULL, updated_at = NOW() WHERE id = $1', [targetUserId]);

    // Optionally delete the old device record
    if (userCheck.rows[0].locked_device_id) {
      await pool.query('DELETE FROM devices WHERE id = $1 AND user_id = $2', [userCheck.rows[0].locked_device_id, targetUserId]);
    }

    res.json({ ok: true, message: 'Device lock reset. User can now login from a new device.' });
  } catch (err) {
    console.error('[auth/reset-device] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// POST /api/auth/enroll-device — Enroll Apple user's device via QR code data (admin scans QR)
router.post('/enroll-device', jwtAuth, async (req, res) => {
  try {
    const deviceId = req.body.deviceId || req.body.device_id;
    const userId = req.body.userId || req.body.user_id;
    const publicKey = req.body.publicKey || req.body.public_key;
    const deviceName = req.body.deviceName || req.body.device_name || 'Unknown';
    const deviceOs = req.body.deviceOs || req.body.device_os || 'unknown';
    const deviceOsVersion = req.body.deviceOsVersion || req.body.device_os_version || '';
    const enterpriseId = req.body.enterpriseId || req.body.enterprise_id || req.headers['x-enterprise-id'];

    if (!deviceId || !userId || !publicKey) {
      return res.status(400).json({ error: 'deviceId, userId, and publicKey are required' });
    }

    // Verify caller is admin+ in the enterprise
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
    const isRoot = rootCheck.rows.length > 0;

    if (!isRoot && enterpriseId) {
      const entRole = await pool.query(
        `SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2`,
        [req.user.id, enterpriseId]
      );
      if (entRole.rows.length === 0 || !['super_admin', 'admin'].includes(entRole.rows[0].role)) {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }

    // Verify target user exists and is Apple auth
    const userCheck = await pool.query('SELECT auth_type FROM users WHERE id = $1', [userId]);
    if (userCheck.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    if (userCheck.rows[0].auth_type !== 'apple') {
      return res.status(400).json({ error: 'QR enrollment is only for Apple ID users' });
    }

    // Upsert device
    await pool.query(
      `INSERT INTO devices (id, name, os, os_version, public_key, status, user_id, enterprise_id, enrollment_method)
       VALUES ($1, $2, $3, $4, $5, 'enabled', $6, $7, 'qr')
       ON CONFLICT (id) DO UPDATE SET
         enterprise_id = COALESCE(EXCLUDED.enterprise_id, devices.enterprise_id),
         enrollment_method = 'qr',
         status = 'enabled',
         updated_at = NOW()`,
      [deviceId, deviceName, deviceOs, deviceOsVersion, publicKey, userId, enterpriseId]
    );

    res.status(201).json({ ok: true, message: 'Device enrolled successfully' });
  } catch (err) {
    console.error('[auth/enroll-device] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/auth/me — Return current user + enterprises
router.get('/me', jwtAuth, async (req, res) => {
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    if (user.status !== 'enabled') {
      return res.status(403).json({ error: 'Account is disabled' });
    }

    const entResult = await pool.query(
      `SELECT e.*, uer.role
       FROM enterprises e
       JOIN user_enterprise_roles uer ON uer.enterprise_id = e.id
       WHERE uer.user_id = $1
       ORDER BY e.name`,
      [user.id]
    );

    const enterprises = await loadEnterprisesWithUserGroups(user.id, entResult.rows);
    const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [user.id]);
    const isRoot = rootCheck.rows.length > 0;

    res.json({
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        username: user.username,
        status: user.status,
        authType: user.auth_type,
        lockedDeviceId: user.locked_device_id,
        isRoot,
      },
      enterprises,
    });
  } catch (err) {
    console.error('[auth/me] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── helper ───────────────────────────────────────────────────────────
async function loadEnterprisesWithUserGroups(userId, entRows) {
  const enterprises = [];
  for (const e of entRows) {
    let groups;
    if (['super_admin', 'root'].includes(e.role)) {
      const r = await pool.query(
        `SELECT g.*,
                (SELECT count(*) FROM user_group_members gm WHERE gm.user_group_id = g.id) AS member_count
         FROM user_groups g WHERE g.enterprise_id = $1 ORDER BY g.name`,
        [e.id]
      );
      groups = r.rows;
    } else {
      const r = await pool.query(
        `SELECT g.*, gm.role AS member_role,
                (SELECT count(*) FROM user_group_members gmm WHERE gmm.user_group_id = g.id) AS member_count
         FROM user_groups g
         JOIN user_group_members gm ON gm.user_group_id = g.id AND gm.user_id = $1
         WHERE g.enterprise_id = $2 ORDER BY g.name`,
        [userId, e.id]
      );
      groups = r.rows;
    }

    enterprises.push({
      id: e.id,
      enterpriseId: e.enterprise_id,
      name: e.name,
      country: e.country,
      companySize: e.company_size,
      industry: e.industry,
      role: e.role,
      userGroups: groups.map(g => ({
        id: g.id,
        name: g.name,
        description: g.description,
        memberCount: parseInt(g.member_count) || 0,
        memberRole: g.member_role || null,
      })),
    });
  }
  return enterprises;
}

module.exports = router;
