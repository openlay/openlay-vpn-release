const crypto = require('crypto');

// Fixed SPKI header for uncompressed EC P-256 public keys (26 bytes)
const P256_SPKI_HEADER = Buffer.from(
  '3059301306072a8648ce3d020106082a8648ce3d030107034200',
  'hex'
);

/**
 * Verify an ECDSA P-256 (SHA-256) signature from Secure Enclave / TPM.
 *
 * Client must sign the UTF-8 bytes of the data string using:
 *   SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data, &err)
 *
 * @param {string} devicePublicKeyBase64 - Base64-encoded raw uncompressed EC point (65 bytes: 04||X||Y)
 * @param {string} data - The string that was signed (UTF-8 bytes)
 * @param {string} signatureBase64 - Base64-encoded DER signature
 * @returns {boolean}
 */
function verifySecureEnclaveSignature(devicePublicKeyBase64, data, signatureBase64) {
  const rawKey = Buffer.from(devicePublicKeyBase64, 'base64');
  const spkiDer = Buffer.concat([P256_SPKI_HEADER, rawKey]);

  const publicKey = crypto.createPublicKey({
    key: spkiDer,
    format: 'der',
    type: 'spki',
  });

  return crypto.verify(
    'SHA256',
    Buffer.from(data, 'utf8'),
    publicKey,
    Buffer.from(signatureBase64, 'base64')
  );
}

module.exports = { verifySecureEnclaveSignature };
