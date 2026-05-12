// Remote-deploy routes. Two phases per operation (test or run):
//
//   Phase 1 (no `dek` in body): server returns the requesting admin's
//     ECIES-wrapped DEK for the chosen SSH key. iOS does Face ID, unwraps
//     in the Secure Enclave, and POSTs back the plaintext DEK.
//
//   Phase 2 (`dek` in body): server uses the DEK to AES-256-GCM-decrypt
//     the SSH private key, then runs the SSH operation.
//
// Why one endpoint per op (instead of /test + /test/proceed):
//   - Stateless. No server-side request_id cache to expire.
//   - Each phase is independently signed; the unique nonce on each admin
//     signature is enough replay protection.
//   - The body shape (`dek` field present or absent) makes the phase
//     unambiguous to both client and server.

const { Router } = require('express');
const { sendError } = require('../../middleware/errorHandler');
const crypto = require('crypto');
const fs = require('fs');
const { pool } = require('../../db/pool');
const { verifyAdminSignature } = require('../../services/adminSigning');
const enterpriseContext = require('../../middleware/enterpriseContext');
const secretBox = require('../../services/secretBox');
const agentBinarySource = require('../../services/agentBinarySource');
const remoteDeploy = require('../../services/remoteDeploy');
const deployJobs = require('../../services/deployJobs');

const router = Router();
router.use(enterpriseContext);

/**
 * Common: load the requesting admin's wrap for a given SSH key.
 * Returns { wrappedDek: Buffer } or null if no wrap exists for this admin
 * (= they need another admin to grant access via M3 re-wrap flow).
 */
async function getMyWrap(sshKeyId, adminUserId, enterpriseId) {
  const { rows } = await pool.query(
    `SELECT w.wrapped_dek
       FROM ssh_key_dek_wraps w
       JOIN ssh_keys k ON k.id = w.ssh_key_id AND k.enterprise_id = $3
      WHERE w.ssh_key_id = $1 AND w.admin_user_id = $2`,
    [sshKeyId, adminUserId, enterpriseId]
  );
  if (rows.length === 0) return null;
  return { wrappedDek: rows[0].wrapped_dek };
}

/**
 * Common: given a DEK from iOS, decrypt the stored private-key blob
 * back into plaintext PEM. Returns the PEM string.
 */
async function decryptPrivateKey(sshKeyId, dekBuf, enterpriseId) {
  const { rows } = await pool.query(
    `SELECT encrypted_blob, dek_iv, dek_tag
       FROM ssh_keys WHERE id = $1 AND enterprise_id = $2`,
    [sshKeyId, enterpriseId]
  );
  if (rows.length === 0) throw new Error('SSH key not found');
  const { encrypted_blob, dek_iv, dek_tag } = rows[0];
  const plain = secretBox.open({
    ciphertext: encrypted_blob, iv: dek_iv, tag: dek_tag, key: dekBuf,
  });
  return plain.toString('utf8');
}

/**
 * Common: create a one-shot enrollment token. The agent uses it during
 * its first /agents/enroll call after install.sh starts the service.
 * `max_uses=1` means the token auto-revokes on first successful use.
 */
async function createDeployEnrollmentToken(adminUserId, label) {
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + 24 * 3600 * 1000).toISOString(); // 24h grace
  await pool.query(
    `INSERT INTO enrollment_tokens (token, name, created_by, expires_at, max_uses)
     VALUES ($1, $2, $3, $4, 1)`,
    [token, label, adminUserId, expiresAt]
  );
  return token;
}

// POST /api/admin/servers/deploy/test
// body: { host, port?, username?, ssh_key_id, dek?, admin_signature, admin_nonce, admin_signed_at }
router.post('/test', async (req, res) => {
  try {
    const { host, port, ssh_key_id, dek } = req.body;
    const username = (req.body.username && String(req.body.username).trim()) || 'root';
    if (!host || !ssh_key_id) {
      return res.status(400).json({ error: 'host and ssh_key_id are required' });
    }

    // Sign the operation regardless of phase. Nonce binds host + user +
    // key, making audit log non-repudiable.
    const sigCheck = await verifyAdminSignature(req, 'deploy_test', {
      target_type: 'ssh_key', target_id: ssh_key_id, host, username,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    if (!dek) {
      // Phase 1: hand back the admin's wrapped DEK
      const wrap = await getMyWrap(ssh_key_id, req.user.id, req.enterpriseId);
      if (!wrap) {
        return res.status(403).json({
          error: 'You do not have a decryption wrap for this SSH key — ask another admin to grant access',
          code: 'no_wrap',
        });
      }
      return res.json({
        phase: 'unwrap_required',
        wrapped_dek: wrap.wrappedDek.toString('base64'),
      });
    }

    // Phase 2: use DEK to decrypt + run SSH probe
    const dekBuf = Buffer.from(dek, 'base64');
    let pem;
    try {
      pem = await decryptPrivateKey(ssh_key_id, dekBuf, req.enterpriseId);
    } finally {
      secretBox.wipe(dekBuf);
    }
    const result = await remoteDeploy.testConnection({
      host, port, username, privateKeyPem: pem,
    });
    return res.json({ phase: 'done', result });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/admin/servers/deploy/run
// body: { host, port?, ssh_key_id, dek?, admin_signature, admin_nonce, admin_signed_at }
//
// Phase 2 of this endpoint kicks off an async deploy job and returns the
// job_id immediately. iOS then polls GET /jobs/:id for live log + final
// status. We do NOT block the HTTP response on install.sh — it can take
// several minutes.
router.post('/run', async (req, res) => {
  try {
    const { host, port, ssh_key_id, dek } = req.body;
    const username = (req.body.username && String(req.body.username).trim()) || 'root';
    if (!host || !ssh_key_id) {
      return res.status(400).json({ error: 'host and ssh_key_id are required' });
    }

    const sigCheck = await verifyAdminSignature(req, 'deploy_run', {
      target_type: 'ssh_key', target_id: ssh_key_id, host, username,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    if (!dek) {
      const wrap = await getMyWrap(ssh_key_id, req.user.id, req.enterpriseId);
      if (!wrap) {
        return res.status(403).json({
          error: 'You do not have a decryption wrap for this SSH key',
          code: 'no_wrap',
        });
      }
      return res.json({
        phase: 'unwrap_required',
        wrapped_dek: wrap.wrappedDek.toString('base64'),
      });
    }

    // Phase 2: full deploy. Decrypt key + create enrollment token + build
    // tarball + spawn the SSH job, all upfront. The deploy itself runs in
    // background; we return the job id so iOS can start polling.
    const dekBuf = Buffer.from(dek, 'base64');
    let pem;
    try {
      pem = await decryptPrivateKey(ssh_key_id, dekBuf, req.enterpriseId);
    } finally {
      secretBox.wipe(dekBuf);
    }

    const enrollmentToken = await createDeployEnrollmentToken(
      req.user.id,
      `auto-deploy-${host}-${Date.now()}`
    );

    // Match the URL the iOS admin app's selected server is reachable at.
    // `req.protocol` + host gives us the canonical externally-visible URL
    // for this management instance.
    const managementApiUrl = `${req.protocol}://${req.get('host')}`;

    const tarballPath = await agentBinarySource.buildDeployTarball({
      enrollmentToken, managementApiUrl,
    });

    const job = deployJobs.create({
      host, ssh_key_id, admin_user_id: req.user.id,
    });
    deployJobs.appendLog(job.id, `[setup] preparing deploy to ${host}`);
    deployJobs.appendLog(job.id, `[setup] enrollment token created (1-use, 24h ttl)`);
    deployJobs.appendLog(job.id, `[setup] agent binary cached, building tarball`);

    // Optional su(8) password — only used when the SSH user isn't root
    // AND wheel doesn't grant passwordless su. Transient: never logged,
    // never persisted, lives only in this request's RAM during the SSH
    // session.
    const suPassword = req.body.su_password || req.body.suPassword || null;

    // Fire and forget — caller polls GET /jobs/:id for status.
    remoteDeploy.deploy({
      host, port, username, privateKeyPem: pem, tarballPath, suPassword,
      enrollmentToken, managementApiUrl,
      onLogLine: (line) => deployJobs.appendLog(job.id, line),
    }).then(result => {
      deployJobs.complete(job.id, result.ok ? null : result.error);
      try { fs.unlinkSync(tarballPath); } catch { /* best effort */ }
    }).catch(err => {
      deployJobs.complete(job.id, err.message);
      try { fs.unlinkSync(tarballPath); } catch { /* */ }
    });

    return res.status(202).json({ phase: 'started', job_id: job.id });
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/admin/servers/deploy/jobs/:id
// Polled by iOS every ~1.5s while the wizard's deploy step is on screen.
router.get('/jobs/:id', (req, res) => {
  const snap = deployJobs.snapshot(req.params.id);
  if (!snap) return res.status(404).json({ error: 'Job not found or expired' });
  // Ownership check: only the admin who started it can see the log.
  // (We don't enforce strict cross-admin isolation otherwise — once the
  //  agent is enrolled, the new server row is visible enterprise-wide.)
  if (snap.meta.admin_user_id && snap.meta.admin_user_id !== req.user.id) {
    return res.status(403).json({ error: 'Job belongs to another admin' });
  }
  res.json({ job: snap });
});

// GET /api/admin/servers/deploy/agent-version
// Returns the VERSION string of the upstream agent binary cache. iOS
// shows this in the deploy wizard's confirmation screen so the admin
// knows what version they're shipping.
router.get('/agent-version', async (req, res) => {
  try {
    const version = await agentBinarySource.getVersion();
    res.json({ version });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
