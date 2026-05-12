// One-shot bootstrap for the very first root user. The console install
// generates ROOT_SETUP_TOKEN, prints a QR with {url, token, ...}; the iOS
// management app scans it, signs in with Apple, and POSTs here. Once any
// root_users row exists this whole router becomes inert (returns 410), so
// it can't be used to escalate later.

const express = require('express');
const crypto = require('crypto');
const { createRemoteJWKSet, jwtVerify } = require('jose');
const config = require('../config');
const { pool } = require('../db/pool');
const rl = require('../middleware/rateLimit');
const { sendError } = require('../middleware/errorHandler');
const jwt = require('jsonwebtoken');

const router = express.Router();

const APPLE_JWKS = createRemoteJWKSet(
  new URL('https://appleid.apple.com/auth/keys')
);

async function hasRoot() {
  const { rows } = await pool.query('SELECT 1 FROM root_users LIMIT 1');
  return rows.length > 0;
}

function setupTokenConfigured() {
  return !!(process.env.ROOT_SETUP_TOKEN && process.env.ROOT_SETUP_TOKEN.length >= 16);
}

// Constant-time compare — avoid timing leaks on the setup token.
function tokensEqual(a, b) {
  const ab = Buffer.from(a || '', 'utf8');
  const bb = Buffer.from(b || '', 'utf8');
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// GET /api/setup/status — public; tells console + app whether bootstrap is
// still pending. `setup_required` flips to false the moment a root exists.
router.get('/status', async (req, res) => {
  try {
    const rooted = await hasRoot();
    res.json({
      has_root: rooted,
      setup_required: !rooted,
      setup_token_configured: setupTokenConfigured(),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/setup/root-enroll — body: { setup_token, identity_token, name? }
// Verifies the setup token, then the Apple identity token. If both check out
// AND no root exists yet, upserts the user and adds them to root_users in a
// single transaction, then returns the same login payload as /api/auth/apple.
router.post('/root-enroll', rl.setup, async (req, res) => {
  try {
    if (!setupTokenConfigured()) {
      return res.status(410).json({ error: 'Setup not enabled on this server' });
    }
    if (await hasRoot()) {
      return res.status(410).json({ error: 'Root already enrolled' });
    }

    const setupToken = req.body.setup_token || req.body.setupToken;
    const identityToken = req.body.identity_token || req.body.identityToken;
    const name = req.body.name;

    if (!setupToken || !identityToken) {
      return res.status(400).json({ error: 'setup_token and identity_token are required' });
    }
    if (!tokensEqual(setupToken, process.env.ROOT_SETUP_TOKEN)) {
      return res.status(401).json({ error: 'Invalid setup token' });
    }

    let payload;
    try {
      ({ payload } = await jwtVerify(identityToken, APPLE_JWKS, {
        issuer: 'https://appleid.apple.com',
        audience: config.appleClientIds,
      }));
    } catch (err) {
      return res.status(401).json({ error: 'Invalid Apple identity token: ' + err.message });
    }

    const appleId = payload.sub;
    const email = payload.email || null;
    const displayName = name || email || null;

    const client = await pool.connect();
    let user, sessionId, refreshToken, accessExpiresAt, refreshExpiresAt;
    try {
      await client.query('BEGIN');

      // Re-check inside the transaction so two concurrent enrolls can't both win.
      const { rows: rootRows } = await client.query('SELECT 1 FROM root_users LIMIT 1');
      if (rootRows.length > 0) {
        await client.query('ROLLBACK');
        return res.status(410).json({ error: 'Root already enrolled' });
      }

      const { rows: userRows } = await client.query(
        `INSERT INTO users (apple_id, email, name, status, auth_type)
         VALUES ($1, $2, $3, 'enabled', 'apple')
         ON CONFLICT (apple_id) DO UPDATE SET
           email = COALESCE(EXCLUDED.email, users.email),
           name = COALESCE(EXCLUDED.name, users.name),
           updated_at = NOW()
         RETURNING *`,
        [appleId, email, displayName]
      );
      user = userRows[0];

      await client.query(
        'INSERT INTO root_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [user.id]
      );

      // Inline the issueTokenPair logic — auth.js exports nothing reusable
      // and we want everything in one transaction.
      sessionId = crypto.randomUUID();
      refreshToken = crypto.randomBytes(32).toString('hex');
      const refreshHash = crypto.createHash('sha256').update(refreshToken).digest('hex');
      const now = Date.now();
      accessExpiresAt = new Date(now + config.sessionTtlHours * 3600 * 1000).toISOString();
      refreshExpiresAt = new Date(now + config.loginTtlDays * 24 * 3600 * 1000).toISOString();

      await client.query(
        `INSERT INTO auth_sessions
           (id, user_id, device_id, refresh_token_hash, expires_at, user_agent)
         VALUES ($1, $2, NULL, $3, $4, $5)`,
        [sessionId, user.id, refreshHash, refreshExpiresAt, req.headers['user-agent'] || null]
      );

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    const accessToken = jwt.sign(
      { sub: user.id, email: user.email, status: user.status, typ: 'access', sid: sessionId },
      config.jwtSecret,
      { expiresIn: `${config.sessionTtlHours}h` }
    );

    console.log(`[setup] First root enrolled: id=${user.id} email=${user.email}`);

    res.status(201).json({
      token: accessToken,
      access_token: accessToken,
      refresh_token: refreshToken,
      access_expires_at: accessExpiresAt,
      refresh_expires_at: refreshExpiresAt,
      session_id: sessionId,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        status: user.status,
        is_root: true,
      },
      enterprises: [],
    });
  } catch (err) {
    console.error('[setup/root-enroll] Error:', err.message);
    sendError(res, err, req);
  }
});

module.exports = router;
