const { Router } = require('express');
const crypto = require('crypto');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const CODE_TTL_MS = 60 * 60 * 1000; // 1h
const CODE_VALUE_KEY = 'enrollment_code_value';
const CODE_EXPIRES_KEY = 'enrollment_code_expires_at';

// 14 digits ≈ 46.5 bits of entropy. The previous 10-digit code (33 bits)
// could be brute-forced in ≤10⁶ requests if rate limiting ever
// regressed — by the time we noticed, an attacker could mint a
// signed-by-our-CA agent cert. Bumping the length costs nothing on the
// admin side (still a copy-paste) and pairs with the per-IP rate limit
// on /api/enroll to make brute force impractical even if the throttle
// is misconfigured. Generated via two randomInt calls because
// crypto.randomInt's range is bounded by Number.MAX_SAFE_INTEGER —
// 10¹⁴ is safe but we split for headroom + clarity.
const CODE_DIGITS = 14;

function generateCode() {
  const hi = crypto.randomInt(0, 1e7).toString().padStart(7, '0');
  const lo = crypto.randomInt(0, 1e7).toString().padStart(7, '0');
  return hi + lo;
}

/**
 * Read current code for the given enterprise. If expired (or missing),
 * rotate it in-place and return the fresh one. Kept in a single
 * advisory-locked transaction keyed on (enterprise_id, key) so concurrent
 * reads serialize during rotation per-enterprise (no global contention).
 */
async function getOrRotateCode(enterpriseId) {
  if (!enterpriseId) throw new Error('enterpriseId is required');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Per-enterprise advisory lock — separate enterprises rotate in parallel.
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1))',
      [`${enterpriseId}:${CODE_VALUE_KEY}`]
    );

    const { rows } = await client.query(
      `SELECT key, value FROM enterprise_settings
        WHERE enterprise_id = $1 AND key IN ($2, $3)`,
      [enterpriseId, CODE_VALUE_KEY, CODE_EXPIRES_KEY]
    );
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    const nowMs = Date.now();
    const expiresMs = map[CODE_EXPIRES_KEY] ? Date.parse(map[CODE_EXPIRES_KEY]) : 0;

    let code = map[CODE_VALUE_KEY] || '';
    let expiresAtIso = map[CODE_EXPIRES_KEY] || null;

    if (!code || !expiresAtIso || isNaN(expiresMs) || expiresMs <= nowMs) {
      code = generateCode();
      expiresAtIso = new Date(nowMs + CODE_TTL_MS).toISOString();
      await upsertSetting(client, enterpriseId, CODE_VALUE_KEY, code);
      await upsertSetting(client, enterpriseId, CODE_EXPIRES_KEY, expiresAtIso);
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

async function forceRotate(enterpriseId) {
  if (!enterpriseId) throw new Error('enterpriseId is required');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'SELECT pg_advisory_xact_lock(hashtext($1))',
      [`${enterpriseId}:${CODE_VALUE_KEY}`]
    );
    const code = generateCode();
    const expiresAtIso = new Date(Date.now() + CODE_TTL_MS).toISOString();
    await upsertSetting(client, enterpriseId, CODE_VALUE_KEY, code);
    await upsertSetting(client, enterpriseId, CODE_EXPIRES_KEY, expiresAtIso);
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

async function upsertSetting(client, enterpriseId, key, value) {
  await client.query(
    `INSERT INTO enterprise_settings (enterprise_id, key, value, updated_at)
       VALUES ($1, $2, $3, NOW())
     ON CONFLICT (enterprise_id, key)
       DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
    [enterpriseId, key, value]
  );
}

/**
 * Reverse lookup used by the public /api/enroll: given a code, find which
 * enterprise it belongs to (if any) and return that enterprise_id along
 * with whether the code is still valid. Returns null when no match.
 */
async function lookupEnterpriseByCode(code) {
  if (!code) return null;
  const { rows } = await pool.query(
    `SELECT v.enterprise_id, e.value AS expires_at
       FROM enterprise_settings v
       JOIN enterprise_settings e
         ON e.enterprise_id = v.enterprise_id AND e.key = $1
      WHERE v.key = $2 AND v.value = $3`,
    [CODE_EXPIRES_KEY, CODE_VALUE_KEY, code]
  );
  if (rows.length === 0) return null;
  const { enterprise_id: enterpriseId, expires_at: expiresAt } = rows[0];
  const expiresMs = Date.parse(expiresAt);
  if (!expiresMs || expiresMs <= Date.now()) {
    return { enterpriseId, expired: true };
  }
  return { enterpriseId, expired: false };
}

// Per-enterprise enrollment code is ops-level — anyone with admin powers in
// the active enterprise can view/rotate. Members can't.
function requireEnterpriseAdmin(req, res, next) {
  if (['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) return next();
  return res.status(403).json({ error: 'Only enterprise admins can view/rotate the enrollment code' });
}

const router = Router();
router.use(enterpriseContext);

router.get('/', requireEnterpriseAdmin, async (req, res) => {
  try {
    if (!req.enterpriseId) {
      return res.status(400).json({ error: 'X-Enterprise-Id header is required' });
    }
    const payload = await getOrRotateCode(req.enterpriseId);
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/rotate', requireEnterpriseAdmin, async (req, res) => {
  try {
    if (!req.enterpriseId) {
      return res.status(400).json({ error: 'X-Enterprise-Id header is required' });
    }
    const payload = await forceRotate(req.enterpriseId);
    res.json(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.getOrRotateCode = getOrRotateCode;
module.exports.lookupEnterpriseByCode = lookupEnterpriseByCode;
