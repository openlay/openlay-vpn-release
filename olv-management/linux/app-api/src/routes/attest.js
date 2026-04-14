const { Router } = require('express');
const crypto = require('crypto');
const { verifyAttestation } = require('node-app-attest');
const { pool } = require('../db/pool');
const config = require('../config');

const router = Router();

const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// GET /api/attest/challenge — Generate a one-time challenge
router.get('/challenge', async (req, res) => {
  try {
    const challenge = crypto.randomBytes(32).toString('base64');
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS).toISOString();

    await pool.query(
      'INSERT INTO attest_challenges (user_id, challenge, expires_at) VALUES ($1, $2, $3)',
      [req.user.id, challenge, expiresAt]
    );

    res.json({ challenge });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/attest/verify — Verify attestation and store public key
router.post('/verify', async (req, res) => {
  try {
    const { keyId, attestation, challenge, deviceId } = req.body;

    if (!keyId || !attestation || !challenge || !deviceId) {
      return res.status(400).json({ error: 'keyId, attestation, challenge, and deviceId are required' });
    }

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

    // Validate device belongs to user
    const { rows: devices } = await pool.query(
      'SELECT * FROM devices WHERE id = $1 AND user_id = $2',
      [deviceId, req.user.id]
    );

    if (devices.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    // Build bundle identifiers from config
    const bundleIds = config.appleClientIds;
    const teamId = config.appleTeamId;
    const allowDev = !config.appAttestProduction;

    // Try verification against each bundle ID
    let result = null;
    let lastError = null;

    for (const bundleId of bundleIds) {
      try {
        result = await verifyAttestation({
          attestation: Buffer.from(attestation, 'base64'),
          challenge,
          keyId,
          bundleIdentifier: bundleId,
          teamIdentifier: teamId,
          allowDevelopmentEnvironment: allowDev,
        });
        break;
      } catch (err) {
        console.log(`[App Attest] verifyAttestation failed for ${teamId}.${bundleId}:`, err.message);
        lastError = err;
      }
    }

    if (!result) {
      console.log('[App Attest] Verification failed:', lastError?.message);
      console.log('[App Attest] teamId used:', teamId);
      console.log('[App Attest] bundleIds used:', bundleIds);
      // Print the actual appId hash from authData for debugging
      try {
        const cbor = require('cbor');
        const crypto = require('crypto');
        const decoded = cbor.decodeAllSync(Buffer.from(attestation, 'base64'))[0];
        const authData = decoded.authData;
        const actualRpIdHash = authData.subarray(0, 32).toString('base64');
        console.log('[App Attest] RP ID hash in authData (base64):', actualRpIdHash);
        for (const bundleId of bundleIds) {
          const expected = crypto.createHash('sha256').update(`${teamId}.${bundleId}`).digest('base64');
          console.log(`[App Attest] Expected hash for ${teamId}.${bundleId}:`, expected);
        }
      } catch (e) { /* ignore */ }
      return res.status(403).json({ error: 'Attestation verification failed' });
    }

    // Store attestation — delete old one for this device if exists
    await pool.query('DELETE FROM device_attestations WHERE device_id = $1', [deviceId]);

    await pool.query(
      `INSERT INTO device_attestations (device_id, key_id, public_key, sign_count, receipt)
       VALUES ($1, $2, $3, 0, $4)`,
      [deviceId, keyId, result.publicKey, result.receipt || null]
    );

    res.json({ verified: true, keyId });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
