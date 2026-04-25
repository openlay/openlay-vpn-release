const { Router } = require('express');
const { pool } = require('../db/pool');

const router = Router();

const POSTURE_DEFAULTS = {
  enabled: false,
  interval_seconds: 300,
};

router.get('/', async (req, res) => {
  try {
    const { rows: er } = await pool.query(
      'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 LIMIT 1',
      [req.user.id]
    );
    const enterpriseId = er[0]?.enterprise_id;

    let enabled = POSTURE_DEFAULTS.enabled;
    let intervalSeconds = POSTURE_DEFAULTS.interval_seconds;

    if (enterpriseId) {
      const { rows } = await pool.query(
        `SELECT key, value FROM enterprise_settings
         WHERE enterprise_id = $1 AND key IN ('posture_submission_enabled', 'posture_submission_interval_seconds')`,
        [enterpriseId]
      );
      for (const row of rows) {
        if (row.key === 'posture_submission_enabled') enabled = row.value === 'true';
        else if (row.key === 'posture_submission_interval_seconds') {
          const n = Number(row.value);
          if (Number.isFinite(n) && n >= 60) intervalSeconds = n;
        }
      }
    }

    res.json({
      posture: { enabled, interval_seconds: intervalSeconds },
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
