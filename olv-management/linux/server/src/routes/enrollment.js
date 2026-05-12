const { Router } = require('express');
const { sendError } = require('../middleware/errorHandler');
const crypto = require('crypto');
const { pool } = require('../db/pool');
const caManager = require('../services/caManager');
const jwtAuth = require('../middleware/jwtAuth');
const { syncSubnets } = require('../services/subnetSync');

const router = Router();

// ── Token Management (root only) ─────────────────────────────────────

async function requireRoot(req, res) {
  const { rows } = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
  if (rows.length === 0) {
    res.status(403).json({ error: 'Root access required' });
    return false;
  }
  return true;
}

// POST /api/enrollment/tokens — Create enrollment token
router.post('/tokens', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    const name = req.body.name || 'Enrollment Token';
    const ttlHours = parseInt(req.body.ttlHours || req.body.ttl_hours) || 24;
    const maxUses = parseInt(req.body.maxUses || req.body.max_uses) || 0;

    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000);

    const { rows } = await pool.query(
      `INSERT INTO enrollment_tokens (token, name, created_by, expires_at, max_uses)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [token, name, req.user.id, expiresAt.toISOString(), maxUses]
    );

    res.status(201).json({
      id: rows[0].id,
      token: rows[0].token,
      name: rows[0].name,
      expiresAt: rows[0].expires_at,
      maxUses: rows[0].max_uses,
      useCount: rows[0].use_count,
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// GET /api/enrollment/tokens — List tokens
router.get('/tokens', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    const { rows } = await pool.query(
      `SELECT id, token, name, expires_at, max_uses, use_count, revoked, created_at
       FROM enrollment_tokens ORDER BY created_at DESC`
    );
    res.json({
      tokens: rows.map(t => ({
        id: t.id,
        token: t.token,
        name: t.name,
        expiresAt: t.expires_at,
        maxUses: t.max_uses,
        useCount: t.use_count,
        revoked: t.revoked,
        createdAt: t.created_at,
        isExpired: new Date(t.expires_at) < new Date(),
        isValid: !t.revoked && new Date(t.expires_at) > new Date() && (t.max_uses === 0 || t.use_count < t.max_uses),
      })),
    });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/enrollment/tokens/:id/revoke — Revoke token
router.post('/tokens/:id/revoke', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    const { rowCount } = await pool.query(
      'UPDATE enrollment_tokens SET revoked = TRUE WHERE id = $1',
      [req.params.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Token not found' });
    res.json({ ok: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// DELETE /api/enrollment/tokens/:id — Delete token
router.delete('/tokens/:id', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    await pool.query('DELETE FROM enrollment_tokens WHERE id = $1', [req.params.id]);
    res.json({ deleted: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

// ── Agent Enrollment (uses enrollment token, not JWT) ────────────────

// POST /api/enrollment/enroll — Agent enrolls with token + CSR
router.post('/enroll', async (req, res) => {
  try {
    // Validate enrollment token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Enrollment token required' });
    }
    const token = authHeader.slice(7);

    // Atomic consume: increment use_count only when it's still < max_uses
    // (or max_uses=0 meaning unlimited). Combined with WHERE on
    // revoked/expires_at, this collapses the previous "SELECT → check →
    // sign cert → UPDATE" sequence into one CAS. If the UPDATE returns
    // zero rows, the token is exhausted/revoked/expired; reject before
    // doing any expensive cert work. The old order let a token mint
    // arbitrary certs if the post-sign UPDATE ever failed, and let two
    // concurrent enrollments race past the max_uses check.
    const { rows: tokens } = await pool.query(
      `UPDATE enrollment_tokens
          SET use_count = use_count + 1
        WHERE token = $1
          AND revoked = FALSE
          AND expires_at > NOW()
          AND (max_uses = 0 OR use_count < max_uses)
        RETURNING *`,
      [token]
    );
    if (tokens.length === 0) {
      return res.status(401).json({ error: 'Invalid, expired, or exhausted enrollment token' });
    }

    const enrollToken = tokens[0];

    // Parse enrollment payload
    const { agentId, hostname, publicUrl, publicIp, apiToken, csr, platform, arch, interfaces } = req.body;
    if (!agentId || !csr) {
      // Roll back the use_count we just claimed — the request never
      // turned into a cert.
      await pool.query(
        'UPDATE enrollment_tokens SET use_count = GREATEST(use_count - 1, 0) WHERE id = $1',
        [enrollToken.id]
      );
      return res.status(400).json({ error: 'agentId and csr are required' });
    }

    // Sign CSR
    let signed;
    try {
      signed = await caManager.signCSR(csr, agentId);
    } catch (err) {
      // Cert issuance failed — refund the use_count.
      await pool.query(
        'UPDATE enrollment_tokens SET use_count = GREATEST(use_count - 1, 0) WHERE id = $1',
        [enrollToken.id]
      );
      throw err;
    }

    // Upsert server record (same logic as agents.js register)
    const description = [platform, arch, publicUrl?.replace('https://', '').split(':')[0]].filter(Boolean).join(' / ');
    const serverName = hostname || agentId;

    let server;
    const { rows: existing } = await pool.query(
      'SELECT id, name FROM servers WHERE instance_id = $1',
      [agentId]
    );

    if (existing.length > 0) {
      // Re-enroll existing server
      await pool.query(
        `UPDATE servers SET url = COALESCE($1, url), api_token = COALESCE($2, api_token),
         hostname = COALESCE($3, hostname), public_ip = COALESCE($4, public_ip), description = $5, updated_at = NOW()
         WHERE id = $6`,
        [publicUrl, apiToken, hostname, publicIp || '', description, existing[0].id]
      );
      server = existing[0];
      console.log(`[enrollment] Re-enrolled existing agent: "${server.name}" (id=${server.id})`);
    } else {
      // New server
      const { rows: newServer } = await pool.query(
        `INSERT INTO servers (name, url, api_token, description, hostname, instance_id, public_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name`,
        [serverName, publicUrl || '', apiToken || '', description, hostname || '', agentId, publicIp || '']
      );
      server = newServer[0];
      console.log(`[enrollment] New agent enrolled: "${server.name}" (id=${server.id})`);
    }

    // Sync subnets
    await syncSubnets(server.id, interfaces || []);

    // Record certificate
    await pool.query(
      `INSERT INTO agent_certificates (server_id, agent_id, serial_number, fingerprint, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [server.id, agentId, signed.serial, signed.fingerprint, signed.expiresAt.toISOString()]
    );

    // use_count was already claimed atomically up-front; nothing to do here.

    // Build WebSocket URL
    const wsProtocol = req.protocol === 'https' ? 'wss' : 'ws';
    const wsUrl = `${wsProtocol}://${req.headers.host}/ws/agent`;

    res.status(201).json({
      serverId: server.id,
      agentCert: signed.cert,
      caCert: caManager.getCACert(),
      wsUrl,
      message: `Agent "${server.name}" enrolled successfully`,
    });

    console.log(`[enrollment] Cert issued: serial=${signed.serial} fingerprint=${signed.fingerprint.substring(0, 16)}...`);
  } catch (err) {
    console.error('[enrollment] Error:', err.message);
    sendError(res, err, req);
  }
});

// GET /api/enrollment/ca — Public CA certificate (agents need this)
router.get('/ca', (req, res) => {
  res.type('application/x-pem-file').send(caManager.getCACert());
});

// ── Certificate management ───────────────────────────────────────────

// GET /api/enrollment/certificates — List issued certificates
router.get('/certificates', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    const { rows } = await pool.query(
      `SELECT ac.*, s.name as server_name
       FROM agent_certificates ac
       LEFT JOIN servers s ON s.id = ac.server_id
       ORDER BY ac.issued_at DESC`
    );
    res.json({ certificates: rows });
  } catch (err) {
    sendError(res, err, req);
  }
});

// POST /api/enrollment/certificates/:id/revoke — Revoke agent cert
router.post('/certificates/:id/revoke', jwtAuth, async (req, res) => {
  if (!(await requireRoot(req, res))) return;
  try {
    const { rowCount } = await pool.query(
      'UPDATE agent_certificates SET revoked = TRUE, revoked_at = NOW() WHERE id = $1',
      [req.params.id]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Certificate not found' });
    res.json({ ok: true });
  } catch (err) {
    sendError(res, err, req);
  }
});

module.exports = router;
