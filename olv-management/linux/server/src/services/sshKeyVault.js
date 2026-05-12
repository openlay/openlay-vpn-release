// SSH key vault — admin uploads a private key, server encrypts it with a
// random DEK, then wraps the DEK to every enrolled admin's SE encryption
// pubkey. Server NEVER stores the DEK or plaintext private key.
//
// Decryption (used by future remote-deploy flow): server returns the wrap
// for the requesting admin → admin's iOS Face ID unwraps DEK → admin POSTs
// DEK back → server transiently uses DEK to decrypt the SSH key for one
// SSH session, then wipes.
//
// See se_wrapping_pattern.md memory for the architectural rationale.

const sshpk = require('sshpk');
const { pool } = require('../db/pool');
const secretBox = require('./secretBox');
const { eciesEncryptToPubkey } = require('./ecies');

/**
 * Parse a PEM private key and derive the public-side metadata WITHOUT
 * persisting anything. Used by the upload route to validate input + return
 * a preview for error feedback before we touch the DB.
 *
 * @param {string} pem  PEM-encoded private key (OpenSSH, RSA, PKCS#8, etc.)
 * @returns {{
 *   algorithm: string,         // 'rsa' | 'ed25519' | 'ecdsa-sha2-nistp256' | ...
 *   bits: number,              // key size; -1 for ed25519 (per sshpk convention)
 *   fingerprint: string,       // SHA-256 fingerprint, OpenSSH wire format ('SHA256:...')
 *   publicKeyOpenSSH: string   // single-line "<algo> <base64> <comment>"
 * }}
 */
function parseAndPreview(pem) {
  let priv;
  try {
    priv = sshpk.parsePrivateKey(pem, 'auto');
  } catch (err) {
    throw new VaultError('invalid_pem', `Could not parse private key: ${err.message}`);
  }
  const pub = priv.toPublic();
  return {
    algorithm: priv.type, // sshpk normalises to lowercase 'rsa' / 'ed25519' / 'ecdsa'
    bits: typeof priv.size === 'number' ? priv.size : -1,
    fingerprint: pub.fingerprint('sha256').toString(), // 'SHA256:abc...'
    publicKeyOpenSSH: pub.toString('ssh'),             // 'ssh-ed25519 AAAA... [comment]'
  };
}

/**
 * Import a private key into the vault. Atomic: encrypt + insert + wrap to
 * all admins runs in a single transaction so a failure mid-way leaves no
 * orphan rows.
 *
 * Refuses to import if either:
 *   - The importing admin themselves has no encryption pubkey registered
 *     yet (they'd be unable to decrypt their own import — pointless), OR
 *   - No admin in the enterprise has an encryption pubkey registered (the
 *     key would be unrecoverable forever).
 *
 * @param {{
 *   pem: string,
 *   name: string,
 *   enterpriseId: string,
 *   createdBy: string  // admin user id
 * }} opts
 * @returns {Promise<{
 *   id: string,
 *   name: string,
 *   algorithm: string,
 *   bits: number,
 *   fingerprint: string,
 *   publicKeyOpenSSH: string,
 *   wrapsCount: number
 * }>}
 */
async function importKey({ pem, name, enterpriseId, createdBy }) {
  if (!name || typeof name !== 'string' || name.length > 200) {
    throw new VaultError('invalid_name', 'name is required (≤200 chars)');
  }
  if (!enterpriseId) {
    throw new VaultError('no_enterprise', 'enterprise context required');
  }

  const meta = parseAndPreview(pem);
  const priv = sshpk.parsePrivateKey(pem, 'auto');
  // Re-serialise to a canonical OpenSSH-format PEM ("BEGIN OPENSSH PRIVATE
  // KEY"). This is the format the `ssh2` library reliably parses for ALL
  // key types — RSA, ECDSA, and importantly ED25519 (which it cannot read
  // in PKCS#8 form). AWS-downloaded `.pem` files arrive in various formats;
  // normalising at import gives us a single decrypt path at deploy time.
  const canonicalPem = priv.toString('ssh-private');

  // Generate DEK + encrypt private key
  const dek = secretBox.randomKey(); // 32 bytes, AES-256
  const sealed = secretBox.seal(Buffer.from(canonicalPem, 'utf8'), dek);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Verify the importing admin has an encryption pubkey registered.
    // If not, fail fast — they'd be unable to ever decrypt their own
    // import, which is a confusing dead end.
    const meRes = await client.query(
      `SELECT admin_encryption_public_key FROM users WHERE id = $1`,
      [createdBy]
    );
    const myPubB64 = meRes.rows[0]?.admin_encryption_public_key;
    if (!myPubB64) {
      throw new VaultError(
        'importer_no_encryption_key',
        'You must log into the iOS admin app at least once to register your encryption key before importing SSH keys'
      );
    }

    // Find every admin in this enterprise that has registered an encryption
    // pubkey. We wrap the DEK to all of them so any of them can decrypt
    // later for deploy operations.
    //
    // Membership = users with ANY role in this enterprise. We deliberately
    // include the importer (they need a wrap to use their own key).
    const adminRes = await client.query(
      `SELECT u.id, u.admin_encryption_public_key
         FROM users u
         JOIN user_enterprise_roles uer ON uer.user_id = u.id
        WHERE uer.enterprise_id = $1
          AND u.admin_encryption_public_key IS NOT NULL`,
      [enterpriseId]
    );
    if (adminRes.rows.length === 0) {
      // Defensive — should never happen because we just confirmed the
      // importer has a key. But if the importer isn't a member of this
      // enterprise (data inconsistency), this catches it.
      throw new VaultError(
        'no_admins_with_encryption',
        'No admins in this enterprise have registered encryption keys'
      );
    }

    // Insert key row
    const keyRes = await client.query(
      `INSERT INTO ssh_keys
         (enterprise_id, name, fingerprint, public_key_openssh,
          encrypted_blob, dek_iv, dek_tag, algorithm, bits, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING id`,
      [
        enterpriseId, name, meta.fingerprint, meta.publicKeyOpenSSH,
        sealed.ciphertext, sealed.iv, sealed.tag,
        meta.algorithm, meta.bits, createdBy,
      ]
    );
    const sshKeyId = keyRes.rows[0].id;

    // Wrap DEK to each admin and insert wrap rows
    for (const a of adminRes.rows) {
      const recipientPub = Buffer.from(a.admin_encryption_public_key, 'base64');
      const wrapped = eciesEncryptToPubkey(recipientPub, dek);
      await client.query(
        `INSERT INTO ssh_key_dek_wraps (ssh_key_id, admin_user_id, wrapped_dek)
         VALUES ($1, $2, $3)`,
        [sshKeyId, a.id, wrapped]
      );
    }

    await client.query('COMMIT');

    return {
      id: sshKeyId,
      name,
      algorithm: meta.algorithm,
      bits: meta.bits,
      fingerprint: meta.fingerprint,
      public_key_openssh: meta.publicKeyOpenSSH,
      // The importer always has a wrap (we just inserted theirs), so
      // has_my_wrap is implicitly true. Returning it explicitly keeps the
      // shape congruent with listKeys() output so the iOS client can use
      // a single SshKey struct.
      has_my_wrap: true,
      wraps_count: adminRes.rows.length,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    secretBox.wipe(dek);
    client.release();
  }
}

/**
 * List all SSH keys in this enterprise. Annotates each row with whether
 * the current admin has a wrap (and can therefore actually use it).
 */
async function listKeys({ enterpriseId, currentAdminId }) {
  const { rows } = await pool.query(
    `SELECT k.id, k.name, k.fingerprint, k.public_key_openssh,
            k.algorithm, k.bits, k.created_at,
            cu.email AS created_by_email,
            EXISTS(
              SELECT 1 FROM ssh_key_dek_wraps w
               WHERE w.ssh_key_id = k.id AND w.admin_user_id = $2
            ) AS has_my_wrap,
            (SELECT count(*) FROM ssh_key_dek_wraps w WHERE w.ssh_key_id = k.id) AS wraps_count
       FROM ssh_keys k
       LEFT JOIN users cu ON cu.id = k.created_by
      WHERE k.enterprise_id = $1
      ORDER BY k.created_at DESC`,
    [enterpriseId, currentAdminId]
  );
  // snake_case keys — matches the rest of /api/admin/* (the iOS client
  // converts via JSONDecoder.keyDecodingStrategy = .convertFromSnakeCase).
  return rows.map(r => ({
    id: r.id,
    name: r.name,
    fingerprint: r.fingerprint,
    public_key_openssh: r.public_key_openssh,
    algorithm: r.algorithm,
    bits: r.bits,
    created_at: r.created_at,
    created_by_email: r.created_by_email,
    has_my_wrap: r.has_my_wrap,
    wraps_count: parseInt(r.wraps_count, 10) || 0,
  }));
}

/**
 * Public-key-only fetch. Returns the OpenSSH single-line string suitable
 * for `~/.ssh/authorized_keys`. No auth gating beyond enterprise scope —
 * public keys are not secret.
 */
async function getPublicKey(id, enterpriseId) {
  const { rows } = await pool.query(
    `SELECT public_key_openssh FROM ssh_keys WHERE id = $1 AND enterprise_id = $2`,
    [id, enterpriseId]
  );
  return rows[0]?.public_key_openssh ?? null;
}

async function deleteKey(id, enterpriseId) {
  // Wraps are ON DELETE CASCADE; one statement is enough.
  const { rowCount } = await pool.query(
    `DELETE FROM ssh_keys WHERE id = $1 AND enterprise_id = $2`,
    [id, enterpriseId]
  );
  return rowCount > 0;
}

class VaultError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    this.name = 'VaultError';
  }
}

module.exports = {
  parseAndPreview,
  importKey,
  listKeys,
  getPublicKey,
  deleteKey,
  VaultError,
};
