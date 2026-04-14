const crypto = require('crypto');
const { verifyAssertion } = require('node-app-attest');
const { pool } = require('../db/pool');
const config = require('../config');

/**
 * Middleware to verify App Attest assertion on sensitive requests.
 *
 * Client must send:
 *   Header: X-App-Attest-KeyId — the keyId from attestation
 *   Header: X-App-Attest-Assertion — base64 assertion from generateAssertion()
 *   Body: { ..., challenge: "<server-issued challenge>" }
 *
 * The assertion signs SHA256(JSON payload including challenge).
 */
async function appAttest(req, res, next) {
  // Skip App Attest for password-authenticated users (they use SE signature instead)
  const { deviceId } = req.body;
  if (deviceId) {
    const { rows } = await pool.query(
      `SELECT d.os, u.auth_type FROM devices d
       LEFT JOIN users u ON d.user_id = u.id
       WHERE d.id = $1 OR d.hardware_id = $1`,
      [deviceId]
    );
    if (rows.length > 0) {
      // Skip for non-iOS (macOS doesn't support App Attest)
      if (rows[0].os !== 'ios') return next();
      // Skip for password users (no App Attest, verified by SE signature)
      if (rows[0].auth_type === 'password') return next();
    }
  }

  const keyId = req.headers['x-app-attest-keyid'];
  const assertionB64 = req.headers['x-app-attest-assertion'];
  const { challenge } = req.body;

  if (!keyId || !assertionB64 || !challenge) {
    return res.status(403).json({ error: 'App Attest required: X-App-Attest-KeyId, X-App-Attest-Assertion headers and challenge in body' });
  }

  try {
    // Validate challenge
    const { rows: challenges } = await pool.query(
      'SELECT * FROM attest_challenges WHERE challenge = $1 AND user_id = $2 AND used = FALSE AND expires_at > NOW()',
      [challenge, req.user.id]
    );

    if (challenges.length === 0) {
      return res.status(403).json({ error: 'Invalid or expired challenge' });
    }

    // Mark challenge as used
    await pool.query('UPDATE attest_challenges SET used = TRUE WHERE id = $1', [challenges[0].id]);

    // Look up stored attestation
    const { rows: attestations } = await pool.query(
      'SELECT * FROM device_attestations WHERE key_id = $1',
      [keyId]
    );

    if (attestations.length === 0) {
      return res.status(403).json({ error: 'Device not attested. Call /api/attest/verify first.' });
    }

    const attest = attestations[0];
    const bundleIds = config.appleClientIds;
    const teamId = config.appleTeamId;

    // payload must be the raw challenge string (UTF-8 bytes), matching how
    // verifyAttestation hashes it: SHA256(challenge_utf8_string).
    // Client should hash: SHA256(challenge.data(using: .utf8)!)
    const clientData = Buffer.from(challenge, 'utf8');

    console.log('[App Attest] keyId:', keyId);
    console.log('[App Attest] challenge:', challenge);
    console.log('[App Attest] signCount in DB:', attest.sign_count);
    console.log('[App Attest] teamId:', teamId, 'bundleIds:', bundleIds);

    let result = null;
    let lastError = null;

    for (const bundleId of bundleIds) {
      try {
        result = await verifyAssertion({
          assertion: Buffer.from(assertionB64, 'base64'),
          payload: clientData,
          publicKey: attest.public_key,
          bundleIdentifier: bundleId,
          teamIdentifier: teamId,
          signCount: attest.sign_count,
        });
        break;
      } catch (err) {
        console.log(`[App Attest] Failed with bundleId=${bundleId}:`, err.message);
        lastError = err;
      }
    }

    if (!result) {
      console.log('[App Attest] Assertion failed:', lastError?.message);
      return res.status(403).json({ error: 'App Attest assertion failed' });
    }

    // Update sign count
    await pool.query(
      'UPDATE device_attestations SET sign_count = $1 WHERE key_id = $2',
      [result.signCount, keyId]
    );

    next();
  } catch (err) {
    console.error('[App Attest] Error:', err.message);
    res.status(500).json({ error: 'App Attest verification error' });
  }
}

module.exports = appAttest;
