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
        value: def.defaultValue === 'true',
        description: def.description,
        updated_at: null,
      };
    }

    // Override with stored values
    for (const row of rows) {
      settings[row.key] = {
        value: row.value === 'true' ? true : row.value === 'false' ? false : row.value,
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
      settings[k] = { value: def.defaultValue === 'true', description: def.description, updated_at: null };
    }
    for (const row of rows) {
      settings[row.key] = {
        value: row.value === 'true' ? true : row.value === 'false' ? false : row.value,
        description: row.description || SETTING_DEFAULTS[row.key]?.description || null,
        updated_at: row.updated_at,
      };
    }
    res.json({ settings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
