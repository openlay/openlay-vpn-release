const { createRemoteJWKSet, jwtVerify } = require('jose');

const APPLE_JWKS_URL = new URL('https://appleid.apple.com/auth/keys');
const jwks = createRemoteJWKSet(APPLE_JWKS_URL);

/**
 * Verify an Apple identity token (JWT from Sign in with Apple).
 * Returns the decoded payload: { sub, email, email_verified, ... }
 */
async function verifyAppleIdentityToken(identityToken, clientIds) {
  const { payload } = await jwtVerify(identityToken, jwks, {
    issuer: 'https://appleid.apple.com',
    audience: clientIds,
  });
  return payload;
}

module.exports = { verifyAppleIdentityToken };
