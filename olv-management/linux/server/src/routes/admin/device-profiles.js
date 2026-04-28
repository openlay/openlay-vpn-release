const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const router = Router();
router.use(enterpriseContext);

// Validate IPv4 CIDR — same shape as the helper in admin/devices.js.
// Duplicated here to keep this route self-contained.
function isValidIpCidr(cidr) {
  const m = String(cidr).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return false;
  const octets = [m[1], m[2], m[3], m[4]].map(Number);
  const prefix = parseInt(m[5], 10);
  return octets.every(o => o <= 255) && prefix >= 0 && prefix <= 32;
}

function validateCidrList(list, fieldName) {
  if (!Array.isArray(list)) return `${fieldName} must be an array`;
  const bad = list.filter(c => !isValidIpCidr(c));
  if (bad.length) return `Invalid CIDR(s) in ${fieldName}: ${bad.join(', ')}`;
  return null;
}

// Domain: a-z, 0-9, dot, hyphen; allow leading "*." wildcard.
function isValidDomain(d) {
  return /^(\*\.)?([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i.test(String(d).trim());
}

function validateDomainList(list) {
  if (!Array.isArray(list)) return 'exclusion_domains must be an array';
  const bad = list.filter(d => !isValidDomain(d));
  if (bad.length) return `Invalid domain(s): ${bad.join(', ')}`;
  return null;
}

function requireEnterprise(req, res) {
  if (!req.enterpriseId) {
    res.status(400).json({ error: 'X-Enterprise-Id header is required' });
    return false;
  }
  return true;
}

// GET /api/admin/device-profiles — list profiles in the active enterprise.
router.get('/', async (req, res) => {
  try {
    if (!requireEnterprise(req, res)) return;
    const { rows } = await pool.query(
      `SELECT p.*,
              (SELECT COUNT(*) FROM devices d WHERE d.profile_id = p.id) AS device_count
         FROM device_profiles p
        WHERE p.enterprise_id = $1
        ORDER BY p.name`,
      [req.enterpriseId]
    );
    res.json({ profiles: rows });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/admin/device-profiles
router.post('/', async (req, res) => {
  try {
    if (!requireEnterprise(req, res)) return;
    const {
      name,
      description = null,
      allowed_ips = [],
      exclusion_ips = [],
      exclusion_domains = [],
      require_posture = false,
    } = req.body;

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'name is required' });
    }
    for (const [list, fld] of [[allowed_ips, 'allowed_ips'], [exclusion_ips, 'exclusion_ips']]) {
      const err = validateCidrList(list, fld);
      if (err) return res.status(400).json({ error: err });
    }
    const dErr = validateDomainList(exclusion_domains);
    if (dErr) return res.status(400).json({ error: dErr });

    const { rows } = await pool.query(
      `INSERT INTO device_profiles
         (enterprise_id, name, description, allowed_ips, exclusion_ips,
          exclusion_domains, require_posture)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [
        req.enterpriseId,
        name.trim(),
        description,
        allowed_ips.map(s => s.trim()),
        exclusion_ips.map(s => s.trim()),
        exclusion_domains.map(s => s.trim()),
        !!require_posture,
      ]
    );
    res.status(201).json({ profile: rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A profile with this name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// GET /api/admin/device-profiles/:id
router.get('/:id', async (req, res) => {
  try {
    if (!requireEnterprise(req, res)) return;
    const { rows } = await pool.query(
      `SELECT * FROM device_profiles WHERE id = $1 AND enterprise_id = $2`,
      [req.params.id, req.enterpriseId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    res.json({ profile: rows[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/device-profiles/:id
router.put('/:id', async (req, res) => {
  try {
    if (!requireEnterprise(req, res)) return;
    const fields = [];
    const values = [];
    let idx = 1;

    const setIf = (col, val) => { fields.push(`${col} = $${idx++}`); values.push(val); };

    if (req.body.name !== undefined) {
      if (!req.body.name || typeof req.body.name !== 'string') {
        return res.status(400).json({ error: 'name must be a non-empty string' });
      }
      setIf('name', req.body.name.trim());
    }
    if (req.body.description !== undefined) setIf('description', req.body.description || null);

    if (req.body.allowed_ips !== undefined) {
      const e = validateCidrList(req.body.allowed_ips, 'allowed_ips');
      if (e) return res.status(400).json({ error: e });
      setIf('allowed_ips', req.body.allowed_ips.map(s => s.trim()));
    }
    if (req.body.exclusion_ips !== undefined) {
      const e = validateCidrList(req.body.exclusion_ips, 'exclusion_ips');
      if (e) return res.status(400).json({ error: e });
      setIf('exclusion_ips', req.body.exclusion_ips.map(s => s.trim()));
    }
    if (req.body.exclusion_domains !== undefined) {
      const e = validateDomainList(req.body.exclusion_domains);
      if (e) return res.status(400).json({ error: e });
      setIf('exclusion_domains', req.body.exclusion_domains.map(s => s.trim()));
    }
    if (req.body.require_posture !== undefined) {
      setIf('require_posture', !!req.body.require_posture);
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    fields.push(`updated_at = NOW()`);
    values.push(req.params.id);
    values.push(req.enterpriseId);
    const { rows } = await pool.query(
      `UPDATE device_profiles SET ${fields.join(', ')}
        WHERE id = $${idx++} AND enterprise_id = $${idx}
        RETURNING *`,
      values
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Profile not found' });
    res.json({ profile: rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'A profile with this name already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/admin/device-profiles/:id
// Devices referencing the profile are detached (FK ON DELETE SET NULL).
router.delete('/:id', async (req, res) => {
  try {
    if (!requireEnterprise(req, res)) return;
    const { rowCount } = await pool.query(
      `DELETE FROM device_profiles WHERE id = $1 AND enterprise_id = $2`,
      [req.params.id, req.enterpriseId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Profile not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
