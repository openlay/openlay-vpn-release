// SSH key vault routes. Mounted under /api/admin/ssh-keys via routes/admin/index.js.
//
// Auth model:
//   - All routes require the standard admin JWT + enterprise context (mounted
//     under the admin router which applies enterpriseContext middleware).
//   - WRITE routes (POST upload, DELETE) ALSO require an admin signature so
//     they show up in admin_audit_log with non-repudiable provenance.
//   - READ routes (GET list, GET public-key) skip the signature — they don't
//     change state and the JWT is sufficient.

const { Router } = require('express');
const sshKeyVault = require('../../services/sshKeyVault');
const { verifyAdminSignature } = require('../../services/adminSigning');
const enterpriseContext = require('../../middleware/enterpriseContext');

const router = Router();
// All SSH key routes require an authenticated admin in an enterprise
// context — same pattern as the other /api/admin/* sub-routers (me.js,
// devices.js, etc). This middleware sets req.user, req.enterpriseId, and
// req.enterpriseRole.
router.use(enterpriseContext);

// POST /api/admin/ssh-keys
// body: { name, pem, admin_signature, admin_nonce, admin_signed_at }
//
// Imports a private key into the vault. Server parses, derives metadata,
// generates DEK, encrypts the private key, and wraps the DEK to every
// admin in the enterprise that has registered an SE encryption pubkey.
router.post('/', async (req, res) => {
  try {
    const { name, pem } = req.body;
    if (!pem || typeof pem !== 'string') {
      return res.status(400).json({ error: 'pem (PEM-encoded private key) is required' });
    }
    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'name is required' });
    }

    // Sign with name only — fingerprint isn't known to iOS until the server
    // parses the PEM. Replay protection comes from the unique nonce.
    const sigCheck = await verifyAdminSignature(req, 'import_ssh_key', {
      target_type: 'ssh_key',
      name,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    const result = await sshKeyVault.importKey({
      pem,
      name,
      enterpriseId: req.enterpriseId,
      createdBy: req.user.id,
    });
    res.status(201).json({ key: result });
  } catch (err) {
    if (err && err.name === 'VaultError') {
      // 412 Precondition Failed for "you need to do X first" cases;
      // 400 for invalid input.
      const status = err.code === 'invalid_pem' || err.code === 'invalid_name' ? 400 : 412;
      return res.status(status).json({ error: err.message, code: err.code });
    }
    // Postgres unique violation on (enterprise_id, fingerprint)
    if (err && err.code === '23505') {
      return res.status(409).json({
        error: 'A key with this fingerprint already exists in this enterprise',
        code: 'duplicate_fingerprint',
      });
    }
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/ssh-keys
// Lists all keys in the current enterprise. Annotates each row with
// `has_my_wrap` so the iOS UI can show a "request access" badge for keys
// the current admin can't decrypt yet.
router.get('/', async (req, res) => {
  try {
    const keys = await sshKeyVault.listKeys({
      enterpriseId: req.enterpriseId,
      currentAdminId: req.user.id,
    });
    res.json({ keys });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/ssh-keys/:id/public-key
// Returns the OpenSSH single-line public key as JSON. The iOS app decodes
// this with the standard JSON request helper; if a CLI use case ever
// needs raw text, branch on Accept header.
router.get('/:id/public-key', async (req, res) => {
  try {
    const pub = await sshKeyVault.getPublicKey(req.params.id, req.enterpriseId);
    if (!pub) return res.status(404).json({ error: 'SSH key not found' });
    res.json({ public_key: pub });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/ssh-keys/:id
// Signed admin action. Cascades to ssh_key_dek_wraps via FK ON DELETE.
router.delete('/:id', async (req, res) => {
  try {
    const sigCheck = await verifyAdminSignature(req, 'delete_ssh_key', {
      target_type: 'ssh_key',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    const ok = await sshKeyVault.deleteKey(req.params.id, req.enterpriseId);
    if (!ok) return res.status(404).json({ error: 'SSH key not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
