const crypto = require('crypto');
const { verifyAssertion } = require('node-app-attest');
const { pool } = require('../db/pool');
const config = require('../config');

// User-facing message for ALL App-Attest reject paths. We never expose
// internal details (missing-headers vs verify-fail vs not-attested) to the
// user — they all reduce to "your build can't talk to this server". Real
// failure cause is logged server-side for debugging.
const APP_ATTEST_USER_ERROR = 'Only Apple App Store applications are allowed to connect.';

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
  // Staging-only escape hatch. Set SKIP_APP_ATTEST=true in the staging .env
  // so dev work on simulator + Apple sign-in works without iOS hardware.
  // PRODUCTION MUST NOT SET THIS — production enforces App Attest for
  // every Apple-related request.
  if (config.skipAppAttest) return next();

  // Look up device + attestation env so we can decide whether App Attest
  // applies to this request, and reject development-environment devices
  // when APP_ATTEST_PRODUCTION=true.
  const { deviceId } = req.body;
  let deviceRow = null;
  if (deviceId) {
    const { rows } = await pool.query(
      `SELECT d.os, u.auth_type, da.environment AS attest_env
         FROM devices d
         LEFT JOIN users u ON d.user_id = u.id
         LEFT JOIN device_attestations da ON da.device_id = d.id
        WHERE d.id = $1 OR d.hardware_id = $1`,
      [deviceId]
    );
    if (rows.length > 0) {
      deviceRow = rows[0];
      // Skip non-Apple OS — DCAppAttestService doesn't exist on
      // Linux/Windows/Android.
      if (!['ios', 'macos'].includes(deviceRow.os)) return next();
      // Password users authenticate via SE signature on /api/connect itself —
      // App Attest is redundant for them.
      if (deviceRow.auth_type === 'password') return next();
      // PER-DEVICE GATE: enforce App Attest only when this specific device
      // has an attestation record stored. Logic:
      //   - At enroll, client may or may not provide attest fields. If
      //     provided + verified → row in device_attestations. If not →
      //     no row.
      //   - Devices WITH attestation row → "trusted-attested": every
      //     connect must verify a fresh assertion against stored pubkey.
      //   - Devices WITHOUT attestation → SE signature on /api/connect
      //     body is the trust anchor (already enforced in handler).
      // This handles the macOS case where DCAppAttestService.isSupported
      // is unreliable: macOS users where it works get the strict path,
      // those where it doesn't fall back to SE-only without breaking.
      if (!deviceRow.attest_env) {
        return next();
      }
    }
  }

  // When APP_ATTEST_PRODUCTION=true, refuse devices whose original
  // attestation came from the development environment (debug builds with
  // dev-cert AAGUID = "appattestdevelop"). This catches the case where a
  // device was attested before the prod flag was flipped — the row stays
  // valid for verifyAssertion (key match still works), but we want it
  // rejected at the policy layer.
  if (
    config.appAttestProduction &&
    deviceRow &&
    deviceRow.attest_env === 'development'
  ) {
    console.log('[App Attest] rejecting development-environment device on production');
    return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
  }

  const keyId = req.headers['x-app-attest-keyid'];
  const assertionB64 = req.headers['x-app-attest-assertion'];
  const { challenge } = req.body;

  if (!keyId || !assertionB64 || !challenge) {
    console.log('[App Attest] missing X-App-Attest-KeyId / X-App-Attest-Assertion / challenge');
    return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
  }

  try {
    // Validate challenge
    const { rows: challenges } = await pool.query(
      'SELECT * FROM attest_challenges WHERE challenge = $1 AND user_id = $2 AND used = FALSE AND expires_at > NOW()',
      [challenge, req.user.id]
    );

    if (challenges.length === 0) {
      console.log('[App Attest] invalid/expired challenge for user', req.user?.id);
      return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
    }

    // Mark challenge as used
    await pool.query('UPDATE attest_challenges SET used = TRUE WHERE id = $1', [challenges[0].id]);

    // Look up stored attestation
    const { rows: attestations } = await pool.query(
      'SELECT * FROM device_attestations WHERE key_id = $1',
      [keyId]
    );

    if (attestations.length === 0) {
      console.log('[App Attest] device not attested, keyId=', keyId);
      return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
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
      return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
    }

    // Update sign count
    await pool.query(
      'UPDATE device_attestations SET sign_count = $1 WHERE key_id = $2',
      [result.signCount, keyId]
    );

    next();
  } catch (err) {
    console.error('[App Attest] Error:', err.message);
    res.status(500).json({ error: APP_ATTEST_USER_ERROR });
  }
}

module.exports = appAttest;
