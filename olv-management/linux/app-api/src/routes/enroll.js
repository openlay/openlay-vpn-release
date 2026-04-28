const { Router } = require('express');
const crypto = require('crypto');
const { verifyAttestation } = require('node-app-attest');
const { pool } = require('../db/pool');
const config = require('../config');

const CODE_VALUE_KEY = 'enrollment_code_value';
const CODE_EXPIRES_KEY = 'enrollment_code_expires_at';

// Same end-user-facing message as /api/connect's appAttest middleware so
// the iOS / macOS app shows a single coherent line regardless of which
// hop rejected the call.
const APP_ATTEST_USER_ERROR = 'Only Apple App Store applications are allowed to connect.';

const router = Router();

// POST /api/enroll/challenge — Public endpoint to mint a one-time challenge
// the client must include in its App Attest attestation. We persist it in
// `attest_challenges` with a NULL user_id (since the device hasn't enrolled
// yet) and a short TTL. /api/enroll consumes the row and marks it used.
router.post('/challenge', async (req, res) => {
  try {
    const challenge = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
    await pool.query(
      `INSERT INTO attest_challenges (challenge, user_id, expires_at, used)
       VALUES ($1, NULL, $2, FALSE)`,
      [challenge, expiresAt]
    );
    res.json({ challenge, expires_at: expiresAt.toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/enroll
// Public (unauthenticated). The 10-digit code identifies WHICH enterprise
// the device is enrolling into (enterprise admins rotate per-enterprise).
// We look it up across enterprise_settings, validate expiry, then record
// a pending enrollment_request pre-stamped with that enterprise_id so the
// admin doesn't have to pick at approve time (they still can override).
router.post('/', async (req, res) => {
  try {
    const code = req.body?.code;
    const deviceName = req.body?.deviceName ?? req.body?.device_name;
    const hardwareId = req.body?.hardwareId ?? req.body?.hardware_id;
    const os = req.body?.os;
    const osVersion = req.body?.osVersion ?? req.body?.os_version;
    const publicKey = req.body?.publicKey ?? req.body?.public_key;

    if (!code || typeof code !== 'string' || !/^\d{10}$/.test(code)) {
      return res.status(400).json({ error: 'code must be a 10-digit string' });
    }
    if (!deviceName || !hardwareId || !os || !publicKey) {
      return res.status(400).json({
        error: 'deviceName, hardwareId, os, and publicKey are required',
      });
    }
    if (!['macos', 'ios', 'windows', 'android', 'linux'].includes(os)) {
      return res.status(400).json({ error: 'os must be macos, ios, windows, android, or linux' });
    }

    // App Attest. Two independent decisions:
    //   1) "Is the client providing attest fields?" → if yes, ALWAYS verify
    //      and store them, regardless of production flag. The whole point of
    //      enroll is to bind the client's claimed publicKey to a real Apple
    //      attestation; skipping that work in dev means the connect path
    //      then has nothing to verify against and rejects.
    //   2) "Are attest fields REQUIRED?" → only when production flag is on.
    //      Otherwise it's best-effort: missing attest is fine in dev,
    //      provided attest still gets persisted.
    // The previous version gated #1 behind the production flag too, which
    // meant dev enrolls always discarded attest fields → device_attestations
    // never created → middleware appAttest later 403'd on connect.
    // App Attest policy:
    //   - REQUIRE: only iOS in production mode. iOS devices reliably have
    //     DCAppAttestService working, so we strictly enforce.
    //   - VERIFY+STORE: any Apple OS that provides attest fields. macOS
    //     where isSupported happens to be true gets stored too — that
    //     promotes the device to "trusted" status, and the connect
    //     middleware will require assertion on every call.
    //   - SKIP: SKIP_APP_ATTEST=true (staging), or non-Apple OS.
    const skipEntirely = config.skipAppAttest || !['ios', 'macos'].includes(os);
    const requireAttest =
      !config.skipAppAttest && config.appAttestProduction && os === 'ios';

    let attestResult = null;
    const attestKeyIdProvided = req.body?.attest_key_id ?? req.body?.attestKeyId;
    const attestationProvided = req.body?.attestation;
    const attestChallengeProvided = req.body?.attest_challenge ?? req.body?.attestChallenge;
    const attestProvided = !!(attestKeyIdProvided && attestationProvided && attestChallengeProvided);

    if (!skipEntirely) {
      if (requireAttest && !attestProvided) {
        console.log('[enroll] App Attest required but missing for', os);
        return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
      }
      if (attestProvided) {
        // Validate challenge: must exist, be unused, and not expired.
        const { rows: challRows } = await pool.query(
          `SELECT id FROM attest_challenges
            WHERE challenge = $1 AND user_id IS NULL AND used = FALSE AND expires_at > NOW()
            LIMIT 1`,
          [attestChallengeProvided]
        );
        if (challRows.length === 0) {
          console.log('[enroll] invalid/expired attest_challenge');
          if (requireAttest) {
            return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
          }
          // Best-effort mode: continue without storing attest.
        } else {
          const allowDev = !config.appAttestProduction;
          let lastError = null;
          for (const bundleId of config.appleClientIds) {
            try {
              attestResult = await verifyAttestation({
                attestation: Buffer.from(attestationProvided, 'base64'),
                challenge: attestChallengeProvided,
                keyId: attestKeyIdProvided,
                bundleIdentifier: bundleId,
                teamIdentifier: config.appleTeamId,
                allowDevelopmentEnvironment: allowDev,
              });
              attestResult._bundleId = bundleId;
              break;
            } catch (err) {
              lastError = err;
            }
          }
          if (!attestResult) {
            console.log('[enroll] App Attest verification failed:', lastError?.message);
            if (requireAttest) {
              return res.status(403).json({ error: APP_ATTEST_USER_ERROR });
            }
            // Best-effort: continue without storing attest.
          } else {
            await pool.query('UPDATE attest_challenges SET used = TRUE WHERE id = $1', [challRows[0].id]);
          }
        }
      }
    }

    // Reverse-lookup: find the enterprise whose current code matches.
    const { rows: codeRows } = await pool.query(
      `SELECT v.enterprise_id AS "enterpriseId",
              e.value          AS "expiresAt"
         FROM enterprise_settings v
         JOIN enterprise_settings e
           ON e.enterprise_id = v.enterprise_id AND e.key = $1
        WHERE v.key = $2 AND v.value = $3`,
      [CODE_EXPIRES_KEY, CODE_VALUE_KEY, code]
    );
    if (codeRows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }
    const { enterpriseId, expiresAt } = codeRows[0];
    const expiresMs = expiresAt ? Date.parse(expiresAt) : 0;
    if (!expiresMs || expiresMs <= Date.now()) {
      return res.status(401).json({ error: 'Invalid or expired enrollment code' });
    }

    // Idempotency: reuse an outstanding pending request for the same device
    // (scoped to the same enterprise — different orgs should not collide).
    const { rows: existing } = await pool.query(
      `SELECT id FROM enrollment_requests
        WHERE status = 'pending'
          AND hardware_id = $1
          AND public_key = $2
          AND enterprise_id IS NOT DISTINCT FROM $3
        LIMIT 1`,
      [hardwareId, publicKey, enterpriseId]
    );
    if (existing.length > 0) {
      return res.status(201).json({
        enrollmentId: existing[0].id,
        status: 'pending',
        enterpriseId,
      });
    }

    const { rows } = await pool.query(
      `INSERT INTO enrollment_requests
         (device_name, hardware_id, os, os_version, public_key, status, enterprise_id,
          attest_key_id, attest_public_key, attest_environment, attest_bundle_id, attest_receipt)
       VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $8, $9, $10, $11)
       RETURNING id`,
      [
        deviceName, hardwareId, os, osVersion || '', publicKey, enterpriseId,
        attestResult ? attestKeyIdProvided : null,
        attestResult ? attestResult.publicKey : null,
        attestResult ? attestResult.environment : null,
        attestResult ? attestResult._bundleId : null,
        attestResult ? attestResult.receipt || null : null,
      ]
    );

    res.status(201).json({
      enrollmentId: rows[0].id,
      status: 'pending',
      enterpriseId,
    });
  } catch (err) {
    console.error('[enroll] error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/enroll/:id/status — public polling endpoint
router.get('/:id/status', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT status,
              approved_device_id AS "deviceId",
              approved_user_id   AS "userId",
              enterprise_id      AS "enterpriseId"
       FROM enrollment_requests WHERE id = $1`,
      [req.params.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'Enrollment not found' });
    }
    const r = rows[0];
    if (r.status === 'approved') {
      return res.json({
        status: r.status,
        deviceId: r.deviceId,
        userId: r.userId,
        enterpriseId: r.enterpriseId,
      });
    }
    res.json({ status: r.status });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
