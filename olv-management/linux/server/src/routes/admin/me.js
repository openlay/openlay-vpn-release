// Admin self-service endpoints. Currently just hosts the SE-key
// registration call the iOS-admin app makes once on first launch (or after
// a key rotation). Kept in its own file so the URL surface
// (`/api/admin/me/...`) doesn't collide with `users/:id`.
const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const router = Router();
router.use(enterpriseContext);

// POST /api/admin/me/signing-key
// body: { public_key: <base64 X9.62 uncompressed P-256, 65 raw bytes> }
//
// Idempotent — a re-register with the same key returns 200 unchanged. A
// re-register with a DIFFERENT key replaces the stored key and updates the
// timestamp. We deliberately do NOT require the new key to sign anything;
// the JWT bearer is enough authority. This lets a user who reinstalled the
// admin app recover without going through admin-of-admin reset.
router.post('/signing-key', async (req, res) => {
  try {
    const publicKey = req.body?.public_key || req.body?.publicKey;
    if (!publicKey || typeof publicKey !== 'string') {
      return res.status(400).json({ error: 'public_key (base64 P-256 uncompressed) is required' });
    }

    // Sanity-check shape: base64 of exactly 65 bytes, leading 0x04 (uncompressed).
    let raw;
    try {
      raw = Buffer.from(publicKey, 'base64');
    } catch {
      return res.status(400).json({ error: 'public_key must be valid base64' });
    }
    if (raw.length !== 65 || raw[0] !== 0x04) {
      return res.status(400).json({ error: 'public_key must be 65-byte X9.62 uncompressed P-256 (0x04||X||Y)' });
    }

    await pool.query(
      `UPDATE users
          SET admin_signing_public_key    = $1,
              admin_signing_registered_at = NOW(),
              updated_at                  = NOW()
        WHERE id = $2`,
      [publicKey, req.user.id]
    );
    res.json({ registered: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/me/signing-key — current registration status
router.get('/signing-key', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT admin_signing_public_key, admin_signing_registered_at
         FROM users WHERE id = $1`,
      [req.user.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({
      registered: !!rows[0].admin_signing_public_key,
      public_key: rows[0].admin_signing_public_key,
      registered_at: rows[0].admin_signing_registered_at,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/me/audit-log?limit=50
// Last N audit rows for THIS admin — quick "did I really do this?" view.
router.get('/audit-log', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 200);
    const { rows } = await pool.query(
      `SELECT id, action, target_type, target_id, payload,
              signed_at, created_at, enterprise_id
         FROM admin_audit_log
        WHERE admin_user_id = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [req.user.id, limit]
    );
    res.json({ entries: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
