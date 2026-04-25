const { Router } = require('express');
const { pool } = require('../../db/pool');
const enterpriseContext = require('../../middleware/enterpriseContext');

const router = Router();
router.use(enterpriseContext);

// Default descriptions for known settings
const SETTING_DEFAULTS = {
  require_device_approval: {
    defaultValue: 'false',
    description: 'When enabled, new devices require admin approval before they can connect',
  },
  peer_ttl_hours: {
    // NODE_ENV=development → 15 minutes (0.25h) so dev keys rotate quickly;
    // otherwise 24 hours. Admin can override per enterprise.
    defaultValue: process.env.NODE_ENV === 'development' ? '0.25' : '24',
    description: 'Hours before a newly issued peer key expires (0 = never). Dev default 0.25h (15m), prod 24h.',
  },
  posture_submission_enabled: {
    defaultValue: 'false',
    description: 'When enabled, devices submit posture snapshots (OS, model, security state) on the configured interval',
  },
  posture_submission_interval_seconds: {
    defaultValue: '300',
    description: 'Interval in seconds between device posture submissions (minimum enforced client-side: 60)',
  },
};

// GET /api/admin/settings — per-enterprise settings
router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT key, value, description, updated_at FROM enterprise_settings WHERE enterprise_id = $1 ORDER BY key',
      [req.enterpriseId]
    );

    const settings = {};

    // Start with defaults
    for (const [key, def] of Object.entries(SETTING_DEFAULTS)) {
      settings[key] = {
        value: coerceSettingValue(def.defaultValue),
        description: def.description,
        updated_at: null,
      };
    }

    // Override with stored values
    for (const row of rows) {
      settings[row.key] = {
        value: coerceSettingValue(row.value),
        description: row.description || SETTING_DEFAULTS[row.key]?.description || null,
        updated_at: row.updated_at,
      };
    }

    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/admin/settings — per-enterprise settings
router.put('/', async (req, res) => {
  try {
    if (!['root', 'super_admin'].includes(req.enterpriseRole)) {
      return res.status(403).json({ error: 'super_admin access required' });
    }

    const updates = req.body;
    for (const [key, value] of Object.entries(updates)) {
      const desc = SETTING_DEFAULTS[key]?.description || null;
      await pool.query(
        `INSERT INTO enterprise_settings (enterprise_id, key, value, description, updated_at)
         VALUES ($1, $2, $3, $4, NOW())
         ON CONFLICT (enterprise_id, key) DO UPDATE SET value = $3, updated_at = NOW()`,
        [req.enterpriseId, key, String(value), desc]
      );
    }

    // Return updated settings
    const { rows } = await pool.query(
      'SELECT key, value, description, updated_at FROM enterprise_settings WHERE enterprise_id = $1 ORDER BY key',
      [req.enterpriseId]
    );
    const settings = {};
    for (const [k, def] of Object.entries(SETTING_DEFAULTS)) {
      settings[k] = { value: coerceSettingValue(def.defaultValue), description: def.description, updated_at: null };
    }
    for (const row of rows) {
      settings[row.key] = {
        value: coerceSettingValue(row.value),
        description: row.description || SETTING_DEFAULTS[row.key]?.description || null,
        updated_at: row.updated_at,
      };
    }
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Settings stored as TEXT — return typed value so iOS/client can bind directly.
// Booleans round-trip as 'true'/'false' strings; anything else is a number if
// parseable, otherwise raw string.
function coerceSettingValue(raw) {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  if (raw === null || raw === undefined || raw === '') return raw;
  const n = Number(raw);
  if (!Number.isNaN(n) && String(n) === String(raw)) return n;
  return raw;
}

// Exported so other routes (e.g. app-api /connect) can read settings with the
// same defaults/coercion. Keeps the "source of truth" for known keys in one file.
async function getSetting(enterpriseId, key) {
  const { rows } = await pool.query(
    'SELECT value FROM enterprise_settings WHERE enterprise_id = $1 AND key = $2',
    [enterpriseId, key]
  );
  const raw = rows[0]?.value ?? SETTING_DEFAULTS[key]?.defaultValue;
  return coerceSettingValue(raw);
}

module.exports = router;
module.exports.getSetting = getSetting;
module.exports.SETTING_DEFAULTS = SETTING_DEFAULTS;
