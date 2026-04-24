const { Router } = require('express');
const crypto = require('crypto');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const CODE_TTL_MS = 60 * 60 * 1000; // 1h
const CODE_VALUE_KEY = 'enrollment_code_value';
const CODE_EXPIRES_KEY = 'enrollment_code_expires_at';

function generateCode() {
  return crypto.randomInt(0, 1e10).toString().padStart(10, '0');
}

/**
 * Read current code. If expired (or missing), rotate it in-place and return
 * the fresh one. Kept in a single advisory-locked transaction so concurrent
 * reads don't double-rotate.
 */
async function getOrRotateCode() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Advisory lock the settings row so parallel readers serialize during rotation
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [CODE_VALUE_KEY]);

    const { rows } = await client.query(
      `SELECT key, value FROM app_settings WHERE key IN ($1, $2)`,
      [CODE_VALUE_KEY, CODE_EXPIRES_KEY]
    );
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const nowMs = Date.now();
    const expiresMs = map[CODE_EXPIRES_KEY] ? Date.parse(map[CODE_EXPIRES_KEY]) : 0;

    let code = map[CODE_VALUE_KEY] || '';
    let expiresAtIso = map[CODE_EXPIRES_KEY] || null;

    if (!code || !expiresAtIso || isNaN(expiresMs) || expiresMs <= nowMs) {
      code = generateCode();
      expiresAtIso = new Date(nowMs + CODE_TTL_MS).toISOString();
      await client.query(
        `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [CODE_VALUE_KEY, code]
      );
      await client.query(
        `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
        [CODE_EXPIRES_KEY, expiresAtIso]
      );
    }

    await client.query('COMMIT');
    const expiresMsFinal = Date.parse(expiresAtIso);
    return {
      code,
      expiresAt: expiresAtIso,
      rotatesInSeconds: Math.max(0, Math.floor((expiresMsFinal - Date.now()) / 1000)),
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function forceRotate() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [CODE_VALUE_KEY]);
    const code = generateCode();
    const expiresAtIso = new Date(Date.now() + CODE_TTL_MS).toISOString();
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [CODE_VALUE_KEY, code]
    );
    await client.query(
      `INSERT INTO app_settings (key, value, updated_at) VALUES ($1, $2, NOW())
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
      [CODE_EXPIRES_KEY, expiresAtIso]
    );
    await client.query('COMMIT');
    return {
      code,
      expiresAt: expiresAtIso,
      rotatesInSeconds: Math.floor(CODE_TTL_MS / 1000),
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

function requireGlobalAdmin(req, res, next) {
  if (req.enterpriseRole === 'root' || req.enterpriseRole === 'super_admin') return next();
  return res.status(403).json({ error: 'Only root or super_admin can view/rotate the enrollment code' });
}

const router = Router();
router.use(enterpriseContext);

router.get('/', requireGlobalAdmin, async (req, res) => {
  try {
    const payload = await getOrRotateCode();
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/rotate', requireGlobalAdmin, async (req, res) => {
  try {
    const payload = await forceRotate();
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.getOrRotateCode = getOrRotateCode;
