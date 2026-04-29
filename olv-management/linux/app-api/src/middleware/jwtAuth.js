const jwt = require('jsonwebtoken');
const config = require('../config');
const { pool } = require('../db/pool');

// On its own, jwt.verify() proves the token wasn't forged and isn't past
// its own exp claim. But it does NOT detect a user that's been deleted or
// disabled mid-token-lifetime — and our access tokens last 30 days. Without
// a server-side check, a deleted user keeps full API access for up to a
// month, which defeats the point of admin "delete user".
//
// So we also confirm `users.id` still exists and `status = 'enabled'` on
// every request. To keep the DB out of the hot path, we cache the result
// for ~30s. Cache key is the user_id; entries auto-evict when TTL expires.
//
// On the management server side this same job is done via auth_sessions
// (which CASCADE-delete with the user). app-api has no equivalent session
// row, so we go straight to the users table.
const userCache = new Map(); // userId -> { valid, checkedAt }
const CACHE_TTL_MS = 30_000;

async function loadUserValidity(userId) {
  const cached = userCache.get(userId);
  const now = Date.now();
  if (cached && now - cached.checkedAt < CACHE_TTL_MS) return cached;
  try {
    const { rows } = await pool.query(
      `SELECT status FROM users WHERE id = $1`,
      [userId]
    );
    const valid = rows.length > 0 && rows[0].status === 'enabled';
    const record = { valid, checkedAt: now };
    userCache.set(userId, record);
    return record;
  } catch (err) {
    // DB hiccup — fail closed (reject) without poisoning cache so the next
    // request retries instead of being stuck rejected for the full TTL.
    return { valid: false, checkedAt: now - CACHE_TTL_MS };
  }
}

// Lets the user-deletion / disable code path bust the cache so the kick
// happens within ms instead of waiting the full TTL window.
function invalidateUser(userId) {
  if (userId) userCache.delete(userId);
}

async function jwtAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = authHeader.slice(7);
  let payload;
  try {
    payload = jwt.verify(token, config.jwtSecret);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (!payload.sub) {
    return res.status(401).json({ error: 'Token missing sub claim' });
  }

  const record = await loadUserValidity(payload.sub);
  if (!record.valid) {
    return res.status(401).json({ error: 'Account no longer active' });
  }

  req.user = { id: payload.sub, email: payload.email, status: payload.status };
  next();
}

module.exports = jwtAuth;
module.exports.invalidateUser = invalidateUser;
