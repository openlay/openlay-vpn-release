// AES-256-GCM helpers used by the SSH key vault (and any future feature
// that needs symmetric encryption with a per-secret data encryption key).
//
// Why a tiny wrapper:
//   - Force the caller to think in terms of (ciphertext, iv, tag, key)
//     rather than scattered Buffers — the table schemas store these as
//     separate BYTEA columns and the API mismatch causes silent corruption
//     bugs if you mix them up.
//   - Centralise the choice of IV size (12 bytes — the GCM standard) and
//     auth tag length (16 bytes), so we can change once if we ever need to.
//   - Wipe key material from caller-controlled buffers via `wipe()`.
//
// IMPORTANT: this is for SYMMETRIC encryption only (DEK ↔ ciphertext).
// For asymmetric wrapping of the DEK to an admin's SE pubkey, see ecies.js.

const crypto = require('crypto');

const KEY_BYTES = 32;       // AES-256
const IV_BYTES = 12;        // GCM recommended IV size
const TAG_BYTES = 16;       // GCM auth tag

function randomKey() {
  return crypto.randomBytes(KEY_BYTES);
}

/**
 * Seal `plaintext` under `key`. Returns a fresh IV + ciphertext + tag.
 * Caller is responsible for storing all three; losing any one means the
 * ciphertext is unrecoverable.
 *
 * @param {Buffer} plaintext
 * @param {Buffer} key  exactly 32 bytes
 * @returns {{ ciphertext: Buffer, iv: Buffer, tag: Buffer }}
 */
function seal(plaintext, key) {
  if (!Buffer.isBuffer(plaintext)) throw new Error('plaintext must be a Buffer');
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new Error(`key must be a ${KEY_BYTES}-byte Buffer`);
  }
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, iv, tag };
}

/**
 * Open a sealed envelope. Throws if the tag fails to verify (tampering or
 * wrong key).
 *
 * @param {{ ciphertext: Buffer, iv: Buffer, tag: Buffer, key: Buffer }} env
 * @returns {Buffer} plaintext
 */
function open({ ciphertext, iv, tag, key }) {
  if (!Buffer.isBuffer(ciphertext)) throw new Error('ciphertext must be a Buffer');
  if (!Buffer.isBuffer(iv) || iv.length !== IV_BYTES) {
    throw new Error(`iv must be a ${IV_BYTES}-byte Buffer`);
  }
  if (!Buffer.isBuffer(tag) || tag.length !== TAG_BYTES) {
    throw new Error(`tag must be a ${TAG_BYTES}-byte Buffer`);
  }
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new Error(`key must be a ${KEY_BYTES}-byte Buffer`);
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Best-effort overwrite of a Buffer's contents with zeros. JavaScript
 * doesn't guarantee the GC clears memory, but this at least prevents the
 * key sitting in V8's heap until the next GC cycle.
 */
function wipe(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}

module.exports = { randomKey, seal, open, wipe, KEY_BYTES, IV_BYTES, TAG_BYTES };
