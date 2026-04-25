// Daily prune of device_postures rows older than the configured retention.
// Reads `posture_retention_days` from app_settings (default 90, 0 = keep
// forever) and calls the SQL helper `prune_device_postures()` defined in
// migration 043. Runs in-process on management because that's the long-
// lived service that owns DB maintenance — app-api is request-driven and
// would re-fire the timer on every fork/restart.

const { pool } = require('../db/pool');

const DAY_MS = 24 * 60 * 60 * 1000;

async function prune() {
  try {
    const { rows } = await pool.query(
      `SELECT value FROM app_settings WHERE key = 'posture_retention_days'`
    );
    const days = parseInt(rows[0]?.value ?? '90', 10);
    if (!Number.isFinite(days) || days <= 0) {
      console.log('[posture cleanup] retention disabled (days=0); skipping');
      return;
    }
    const { rows: out } = await pool.query(
      `SELECT prune_device_postures($1) AS deleted`,
      [days]
    );
    const deleted = out[0]?.deleted ?? 0;
    if (deleted > 0) {
      console.log(`[posture cleanup] deleted ${deleted} rows older than ${days} days`);
    }
  } catch (err) {
    console.error('[posture cleanup] error:', err.message);
  }
}

function start() {
  // Run shortly after boot so a freshly-deployed server cleans up without
  // waiting a full day, then daily afterwards.
  setTimeout(prune, 60 * 1000);
  setInterval(prune, DAY_MS);
}

module.exports = { start, prune };
