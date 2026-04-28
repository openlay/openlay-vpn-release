// Admin per-action signing — verifies an ECDSA-P256 signature over a
// canonical payload (key=value newline form, keys sorted) using the admin
// user's registered SE public key. On success appends an audit row to
// `admin_audit_log`. The unique constraint on (admin_user_id, action, nonce)
// catches replay attempts (same nonce reused).
//
// Signature shape matches the rest of the project:
//   - Public key: X9.62 uncompressed P-256 (65 bytes raw), base64
//   - Signature : DER-encoded ECDSA, base64
//   - Hash      : SHA-256 (`signatureVerifier.verifySecureEnclaveSignature`)
const crypto = require('crypto');
const { pool } = require('../db/pool');

const SKEW_MS = 5 * 60 * 1000;

// Same SPKI prefix + verify routine as `app-api/src/services/signatureVerifier.js`.
// Duplicated rather than cross-imported because the server and app-api are
// independent npm packages — an import would couple their lifecycles.
const P256_SPKI_HEADER = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex'
);

function verifySecureEnclaveSignature(devicePublicKeyBase64, data, signatureBase64) {
  try {
    const rawKey = Buffer.from(devicePublicKeyBase64, 'base64');
    const spkiDer = Buffer.concat([P256_SPKI_HEADER, rawKey]);
    const publicKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    return crypto.verify(
      'SHA256',
      Buffer.from(data, 'utf8'),
      publicKey,
      Buffer.from(signatureBase64, 'base64')
    );
  } catch (err) {
    return false;
  }
}

/**
 * Build the canonical string the client must sign. Keys are sorted
 * alphabetically and joined with `=` then `\n` so client + server compute
 * the same bytes regardless of map ordering.
 *
 * Format:
 *   action=<action>
 *   admin_user_id=<uuid>
 *   nonce=<hex>
 *   signed_at=<iso8601>
 *   <field1>=<value>
 *   <field2>=<value>
 *
 * Client (Swift) MUST mirror this exactly — see AdminSigner.canonicalize().
 */
function canonicalize({ action, adminUserId, nonce, signedAt, fields }) {
  const all = {
    action,
    admin_user_id: adminUserId,
    nonce,
    signed_at: signedAt,
    ...fields,
  };
  const sortedKeys = Object.keys(all).sort();
  return sortedKeys.map(k => `${k}=${all[k] ?? ''}`).join('\n');
}

/**
 * Verify the admin-signed payload attached to a privileged request.
 *
 * Returns:
 *   { ok: true, audited: true }  — verification + audit insert succeeded
 *   { ok: true, audited: false } — admin has not yet registered a signing
 *                                  key (grace period before first iOS-app
 *                                  upgrade rolls out).
 *   { ok: false, status, error } — verification failed; caller should
 *                                  res.status(...).json({ error }).
 *
 * The `fields` object MUST contain the action-specific data the client
 * also fed into its canonical string. Examples:
 *   approve_enrollment → { target_type:'enrollment', target_id, device_hardware_id, device_public_key }
 *   delete_device      → { target_type:'device', target_id }
 *   disable_device     → { target_type:'device', target_id, status }
 *   profile_update     → { target_type:'device_profile', target_id, name }
 */
async function verifyAdminSignature(req, action, fields) {
  const sig       = req.body?.admin_signature;
  const nonce     = req.body?.admin_nonce;
  const signedAt  = req.body?.admin_signed_at;

  // Look up admin's registered SE public key.
  const { rows } = await pool.query(
    'SELECT admin_signing_public_key FROM users WHERE id = $1',
    [req.user.id]
  );
  const adminPubKey = rows[0]?.admin_signing_public_key;

  // Grace period: admin hasn't registered yet AND didn't send a signature.
  // Older iOS-admin builds fall here. Safe ONLY because new builds register
  // immediately on launch — once the column is set, the next branch fires.
  if (!adminPubKey && !sig) {
    return { ok: true, audited: false };
  }

  // Admin registered a key — must sign every protected action.
  if (!sig || !nonce || !signedAt) {
    return {
      ok: false,
      status: 403,
      error: 'admin_signature, admin_nonce, and admin_signed_at are required for this action',
    };
  }

  // Skew defence (replay protection layer 1).
  const ts = Date.parse(signedAt);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > SKEW_MS) {
    return { ok: false, status: 403, error: 'admin_signed_at out of acceptable range (±5 min)' };
  }

  if (!adminPubKey) {
    // Edge case: client sent a signature but key isn't registered. Reject —
    // we can't verify, and silently passing would defeat the purpose.
    return { ok: false, status: 403, error: 'Admin signing key not registered' };
  }

  const canonical = canonicalize({
    action,
    adminUserId: req.user.id,
    nonce,
    signedAt,
    fields,
  });
  const ok = verifySecureEnclaveSignature(adminPubKey, canonical, sig);
  if (!ok) {
    return { ok: false, status: 403, error: 'Admin signature verification failed' };
  }

  // Audit + replay defence layer 2 (unique on admin_user_id+action+nonce).
  try {
    await pool.query(
      `INSERT INTO admin_audit_log
         (admin_user_id, enterprise_id, action, target_type, target_id,
          payload, signature, nonce, signed_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        req.user.id,
        req.enterpriseId || null,
        action,
        fields.target_type || null,
        fields.target_id || null,
        JSON.stringify(fields),
        sig,
        nonce,
        new Date(ts),
      ]
    );
  } catch (e) {
    if (e.code === '23505') {
      return { ok: false, status: 409, error: 'Replay detected (admin_nonce reused)' };
    }
    throw e;
  }
  return { ok: true, audited: true };
}

module.exports = { verifyAdminSignature, canonicalize };
