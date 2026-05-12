const jwt = require('jsonwebtoken');
const config = require('../config');
const { pool } = require('../db/pool');

// Default middleware — only accepts access (session) tokens. Refresh tokens
// are opaque bytes, never sent as Bearer JWTs, so this also rejects them
// implicitly. Legacy JWTs without a `typ` claim (issued before the split)
// are still accepted so existing sessions don't break on deploy.
//
// If the token carries a `sid` claim we also look up the auth_sessions row
// and reject when it's revoked or past expires_at. Without this a stolen or
// logged-out access token would stay live until the JWT's own exp (up to
// 24h), which defeats the point of having explicit logout/revoke.
//
// Small in-memory cache (sid → validity flag) keeps the DB hit off the hot
// path. Entries expire quickly so a revoke propagates within `CACHE_TTL_MS`.
const sessionCache = new Map(); // sid -> { valid, expiresAtMs, checkedAt }
const CACHE_TTL_MS = 30_000;

async function loadSessionValidity(sid) {
  const cached = sessionCache.get(sid);
  const now = Date.now();
  if (cached && now - cached.checkedAt < CACHE_TTL_MS) return cached;
  try {
    const { rows } = await pool.query(
      'SELECT revoked_at, expires_at FROM auth_sessions WHERE id = $1',
      [sid]
    );
    let valid = false;
    let expiresAtMs = 0;
    if (rows.length > 0) {
      const { revoked_at, expires_at } = rows[0];
      expiresAtMs = new Date(expires_at).getTime();
      valid = !revoked_at && expiresAtMs > now;
    }
    const record = { valid, expiresAtMs, checkedAt: now };
    sessionCache.set(sid, record);
    return record;
  } catch (err) {
    // DB hiccup — fail closed but don't poison the cache.
    return { valid: false, expiresAtMs: 0, checkedAt: now };
  }
}

// Allow explicit invalidation from /refresh or /session routes so a revoke
// doesn't wait the full CACHE_TTL_MS to take effect.
function invalidateSession(sid) {
  if (sid) sessionCache.delete(sid);
}

async function jwtAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = header.slice(7);
  let payload;
  try {
    // Pin algorithm. jsonwebtoken v9 defaults to a sane allow-list but
    // explicit is safer against algorithm-confusion / `alg: none` if the
    // library ever regresses.
    payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] });
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  if (payload.typ && payload.typ !== 'access') {
    return res.status(401).json({ error: 'Wrong token type — access token required' });
  }

  if (payload.sid) {
    const record = await loadSessionValidity(payload.sid);
    if (!record.valid) {
      return res.status(401).json({ error: 'Session revoked or expired' });
    }
  }

  req.user = {
    id: payload.sub,
    email: payload.email,
    status: payload.status,
    sessionId: payload.sid || null,
  };
  next();
}

module.exports = jwtAuth;
module.exports.invalidateSession = invalidateSession;
