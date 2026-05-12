const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');
const { verifyAdminSignature } = require('../../services/adminSigning');

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

// Pull an exit_node_device_id field from a body, accepting both
// snake_case and camelCase. `undefined` means "not specified" (PUT skip
// behaviour). `null` means "explicitly clear".
function pickExitNode(body) {
  if ('exit_node_device_id' in body) return body.exit_node_device_id;
  if ('exitNodeDeviceId' in body) return body.exitNodeDeviceId;
  return undefined;
}

/**
 * Validate that `exitNodeDeviceId` (non-null) is acceptable for profile
 * `profileId`. Returns `{ status, error }` on failure or `null` when ok.
 *
 * Checks (mirrors devices.js's old per-device validation, plus the new
 * self-loop guard for profile-level assignment):
 *   - target device exists and (for non-root admins) is in the request
 *     enterprise
 *   - target device is enabled
 *   - target's profile has can_be_exit_node = TRUE
 *   - target runs Linux (only OS that implements PostUp MASQUERADE)
 *   - target is NOT itself on profile `profileId` — self-loop guard.
 *     A profile can't pick one of its OWN member devices as exit node:
 *     that device would route through itself.
 */
async function validateExitNodeAssignment(profileId, exitNodeDeviceId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const check = isRoot
    ? await pool.query(
        `SELECT d.id, d.status, d.os, d.profile_id, dp.can_be_exit_node
           FROM devices d LEFT JOIN device_profiles dp ON dp.id = d.profile_id
          WHERE d.id = $1`,
        [exitNodeDeviceId]
      )
    : await pool.query(
        `SELECT d.id, d.status, d.os, d.profile_id, dp.can_be_exit_node
           FROM devices d
           LEFT JOIN device_profiles dp ON dp.id = d.profile_id
           JOIN user_enterprise_roles uer ON uer.user_id = d.user_id AND uer.enterprise_id = $2
          WHERE d.id = $1`,
        [exitNodeDeviceId, req.enterpriseId]
      );
  if (check.rows.length === 0) {
    return { status: 404, error: 'exit_node_device_id does not reference a device' + (isRoot ? '' : ' in this enterprise') };
  }
  const t = check.rows[0];
  if (t.status !== 'enabled') return { status: 422, error: 'exit node device must be enabled' };
  if (!t.can_be_exit_node) return { status: 422, error: 'target device profile does not have can_be_exit_node=TRUE' };
  if (t.os !== 'linux') return { status: 422, error: 'exit node device must run Linux (only Linux client implements MASQUERADE forwarding)' };
  if (profileId && t.profile_id === profileId) {
    return { status: 422, error: 'exit_node_device_id cannot reference a device on this same profile (self-loop)' };
  }
  return null;
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
      allow_wan_access = false,
      can_be_exit_node = false,
    } = req.body;
    const exitNodeRaw = pickExitNode(req.body); // undefined | null | id

    if (!name || typeof name !== 'string') {
      return res.status(400).json({ error: 'name is required' });
    }
    for (const [list, fld] of [[allowed_ips, 'allowed_ips'], [exclusion_ips, 'exclusion_ips']]) {
      const err = validateCidrList(list, fld);
      if (err) return res.status(400).json({ error: err });
    }
    const dErr = validateDomainList(exclusion_domains);
    if (dErr) return res.status(400).json({ error: dErr });

    // Validate exit_node target up front (no profile id yet — pass null
    // so self-loop check is skipped; on POST the profile is brand new and
    // can't have any member devices anyway).
    if (exitNodeRaw !== undefined && exitNodeRaw !== null) {
      const v = await validateExitNodeAssignment(null, exitNodeRaw, req);
      if (v) return res.status(v.status).json({ error: v.error });
    }

    const sigCheck = await verifyAdminSignature(req, 'create_device_profile', {
      target_type: 'device_profile',
      target_id: '',
      name: name.trim(),
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    const { rows } = await pool.query(
      `INSERT INTO device_profiles
         (enterprise_id, name, description, allowed_ips, exclusion_ips,
          exclusion_domains, require_posture, allow_wan_access,
          can_be_exit_node, exit_node_device_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       RETURNING *`,
      [
        req.enterpriseId,
        name.trim(),
        description,
        allowed_ips.map(s => s.trim()),
        exclusion_ips.map(s => s.trim()),
        exclusion_domains.map(s => s.trim()),
        !!require_posture,
        !!allow_wan_access,
        !!can_be_exit_node,
        exitNodeRaw === undefined ? null : exitNodeRaw,
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
    const wanAccessTouched = req.body.allow_wan_access !== undefined;
    if (wanAccessTouched) {
      setIf('allow_wan_access', !!req.body.allow_wan_access);
    }
    const exitNodeTouched = req.body.can_be_exit_node !== undefined;
    if (exitNodeTouched) {
      setIf('can_be_exit_node', !!req.body.can_be_exit_node);
    }
    const exitNodeRaw = pickExitNode(req.body);
    const exitNodeAssignTouched = exitNodeRaw !== undefined;
    let priorExitNodeDeviceId = null;
    if (exitNodeAssignTouched) {
      // Snapshot the previous pointer so the sync service can also bring
      // the OLD exit node's AllowedIPs back to /32 once its consumer
      // count drops to 0.
      const { rows: prev } = await pool.query(
        'SELECT exit_node_device_id FROM device_profiles WHERE id = $1 AND enterprise_id = $2',
        [req.params.id, req.enterpriseId]
      );
      priorExitNodeDeviceId = prev[0]?.exit_node_device_id || null;

      if (exitNodeRaw !== null) {
        const v = await validateExitNodeAssignment(req.params.id, exitNodeRaw, req);
        if (v) return res.status(v.status).json({ error: v.error });
      }
      setIf('exit_node_device_id', exitNodeRaw); // null clears, id sets
    }

    if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });

    const sigCheck = await verifyAdminSignature(req, 'update_device_profile', {
      target_type: 'device_profile',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

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

    // Auto-managed firewall rules track allow_wan_access. When the toggle is
    // touched, fan out a sync across every device using this profile so
    // newly-allowed devices gain a rule and newly-revoked ones lose theirs.
    // Idempotent and tolerant — failures here must not 500 the API.
    if (wanAccessTouched) {
      try {
        const { syncProfileWanAccessAcrossServers } = require('../../services/deviceWanAccessFirewall');
        await syncProfileWanAccessAcrossServers(req.params.id);
      } catch (err) {
        console.error(`[device-profiles/PUT] wan-access sync failed for profile=${req.params.id}: ${err.message}`);
      }
    }

    // Sync exit-node side-effects whenever EITHER toggle flips:
    //   - can_be_exit_node — profile members gain/lose capability →
    //     consumers of THIS profile need re-eval (their PBR rules and
    //     this profile's exit-side AllowedIPs).
    //   - exit_node_device_id — profile members switch which exit they
    //     route through. Sync rebuilds PBR for each member and bumps the
    //     OLD + NEW exit nodes' AllowedIPs.
    if (exitNodeTouched || exitNodeAssignTouched) {
      try {
        const { syncProfileExitNodeAcrossServers } = require('../../services/deviceExitNodeRouting');
        await syncProfileExitNodeAcrossServers(req.params.id, priorExitNodeDeviceId);
      } catch (err) {
        console.error(`[device-profiles/PUT] exit-node sync failed for profile=${req.params.id}: ${err.message}`);
      }
    }

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
    const sigCheck = await verifyAdminSignature(req, 'delete_device_profile', {
      target_type: 'device_profile',
      target_id: req.params.id,
    });
    if (!sigCheck.ok) return res.status(sigCheck.status).json({ error: sigCheck.error });

    // Snapshot devices BEFORE the DELETE — the FK is ON DELETE SET NULL
    // so post-delete `profile_id` would be empty and we couldn't find them.
    const { rows: affectedDevices } = await pool.query(
      'SELECT id FROM devices WHERE profile_id = $1',
      [req.params.id]
    );

    const { rowCount } = await pool.query(
      `DELETE FROM device_profiles WHERE id = $1 AND enterprise_id = $2`,
      [req.params.id, req.enterpriseId]
    );
    if (rowCount === 0) return res.status(404).json({ error: 'Profile not found' });

    // Profile is gone -> profile_id is NULL on those devices -> sync will
    // see "no profile" and tear down any wan-access rule still on the agent.
    if (affectedDevices.length > 0) {
      try {
        const { syncDeviceWanAccessAcrossServers } = require('../../services/deviceWanAccessFirewall');
        await Promise.allSettled(
          affectedDevices.map(d => syncDeviceWanAccessAcrossServers(d.id))
        );
      } catch (err) {
        console.error(`[device-profiles/DELETE] wan-access cleanup failed: ${err.message}`);
      }
      try {
        // Same fan-out for exit-node: devices losing the profile may have
        // been someone's exit node; sync removes their consumers' PBR rules.
        const { syncDeviceExitNodeAcrossServers } = require('../../services/deviceExitNodeRouting');
        await Promise.allSettled(
          affectedDevices.map(d => syncDeviceExitNodeAcrossServers(d.id))
        );
      } catch (err) {
        console.error(`[device-profiles/DELETE] exit-node cleanup failed: ${err.message}`);
      }
    }

    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
