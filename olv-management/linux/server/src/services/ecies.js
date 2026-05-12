// Apple-compatible ECIES encryption — server side.
//
// We use this to WRAP a per-secret DEK (data encryption key) to an admin's
// Secure Enclave encryption pubkey (registered via /api/admin/me/encryption-key).
// The admin's iOS app DECRYPTS the wrapped DEK using
//   SecKeyCreateDecryptedData(privateKey,
//     .eciesEncryptionStandardX963SHA256AESGCM, blob)
// so this implementation MUST byte-for-byte match what that algorithm
// expects on input. Any deviation = silent failure on iOS.
//
// Algorithm: kSecKeyAlgorithmECIESEncryptionStandardX963SHA256AESGCM
//
// Per Apple's documentation + verified community implementations
// (https://developer.apple.com/documentation/security/seckeyalgorithm/ecies):
//
//   1. Generate ephemeral P-256 key pair (eph_priv, eph_pub).
//   2. shared_secret = ECDH(eph_priv, recipient_pub).X  →  32 bytes
//   3. shared_info  = eph_pub in X9.63 uncompressed form (65 bytes:
//                     0x04 || X(32) || Y(32))
//   4. aes_key = X963_KDF(SHA-256, shared_secret, shared_info, 16 bytes)
//                                                            (AES-128 key)
//   5. IV = 16 zero bytes (algorithm name has no "VariableIV" — fixed-zero
//      IV variant; safe because the ephemeral key is fresh per encryption,
//      so the (key, IV) pair is unique)
//   6. ciphertext, tag = AES-128-GCM(aes_key, IV, plaintext, no AAD)
//   7. Output blob layout: eph_pub(65) || ciphertext(plaintext_len) || tag(16)
//
// Round-tripped against an actual iOS Secure Enclave key during M3
// (multi-admin re-wrap) — see test fixtures in olv-tests/script/management.

const crypto = require('crypto');

const PUBKEY_LEN = 65;       // X9.63 uncompressed P-256
const TAG_LEN    = 16;       // AES-GCM tag
const IV_LEN     = 16;       // Apple-spec zero IV (NOT 12 like default GCM)
const AES_KEY    = 16;       // AES-128 key (algo name says ...AESGCM, no 256)

/**
 * ANSI X9.63 / NIST SP 800-56A KDF using SHA-256.
 *
 * Concatenates SHA-256(Z || counter || sharedInfo) blocks until enough
 * bytes are produced. Counter is a 32-bit big-endian integer starting at 1.
 *
 * @param {Buffer} Z              shared secret (raw ECDH X coord)
 * @param {Buffer} sharedInfo     ephemeral pubkey in X9.63 form
 * @param {number} outLen         number of bytes wanted
 * @returns {Buffer}
 */
function x963KDF(Z, sharedInfo, outLen) {
  const blocks = [];
  let produced = 0;
  let counter = 1;
  while (produced < outLen) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32BE(counter, 0);
    const block = crypto
      .createHash('sha256')
      .update(Z)
      .update(counterBuf)
      .update(sharedInfo)
      .digest();
    blocks.push(block);
    produced += block.length;
    counter++;
  }
  return Buffer.concat(blocks).slice(0, outLen);
}

/**
 * Encrypt `plaintext` to a recipient's SE encryption pubkey using Apple's
 * ECIES algorithm. Output is opaque to the server — only the holder of
 * the matching SE private key (an enrolled iOS admin) can decrypt.
 *
 * @param {Buffer} recipientPubRaw  65-byte X9.62 uncompressed P-256
 *                                  (matches what iOS publishes via
 *                                  /api/admin/me/encryption-key)
 * @param {Buffer} plaintext        the secret to wrap (typically a 32-byte DEK)
 * @returns {Buffer} blob = eph_pub(65) || ciphertext || tag(16)
 */
function eciesEncryptToPubkey(recipientPubRaw, plaintext) {
  if (!Buffer.isBuffer(recipientPubRaw) || recipientPubRaw.length !== PUBKEY_LEN
      || recipientPubRaw[0] !== 0x04) {
    throw new Error('recipient pubkey must be 65-byte X9.62 uncompressed P-256 (0x04||X||Y)');
  }
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error('plaintext must be a Buffer');
  }

  // 1-2. Ephemeral key pair + ECDH
  const eph = crypto.createECDH('prime256v1');
  eph.generateKeys();
  const ephPubRaw = eph.getPublicKey(null, 'uncompressed'); // 65 bytes
  const sharedSecret = eph.computeSecret(recipientPubRaw);  // 32 bytes (X coord)

  // 3-4. Derive AES key via X9.63 KDF
  const aesKey = x963KDF(sharedSecret, ephPubRaw, AES_KEY);

  // 5-6. AES-128-GCM with constant zero IV (no AAD)
  const iv = Buffer.alloc(IV_LEN, 0);
  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv, { authTagLength: TAG_LEN });
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // 7. Output blob
  const blob = Buffer.concat([ephPubRaw, ct, tag]);

  // Best-effort wipe of derived key material
  aesKey.fill(0);
  sharedSecret.fill(0);

  return blob;
}

module.exports = { eciesEncryptToPubkey, x963KDF, PUBKEY_LEN, TAG_LEN, IV_LEN };
