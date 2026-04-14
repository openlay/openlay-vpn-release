const crypto = require('crypto');

/**
 * Generate WireGuard key pair using Curve25519.
 * WireGuard private keys are clamped Curve25519 scalars,
 * public keys are the Curve25519 base point multiplied by the private key.
 */
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });

  // x25519 DER-encoded keys have fixed-length headers
  // Private key: 48 bytes total, last 32 bytes are the raw key
  // Public key: 44 bytes total, last 32 bytes are the raw key
  const rawPrivate = privateKey.subarray(privateKey.length - 32);
  const rawPublic = publicKey.subarray(publicKey.length - 32);

  return {
    privateKey: rawPrivate.toString('base64'),
    publicKey: rawPublic.toString('base64'),
  };
}

function generatePresharedKey() {
  return crypto.randomBytes(32).toString('base64');
}

module.exports = { generateKeyPair, generatePresharedKey };
