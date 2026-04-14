const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const config = require('../config');

const pool = new Pool({ connectionString: config.databaseUrl });

async function runMigrations() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS _migrations (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL UNIQUE,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const migrationsDir = path.join(__dirname, 'migrations');
    const files = fs.readdirSync(migrationsDir).filter(f => f.endsWith('.sql')).sort();

    const { rows: applied } = await client.query('SELECT filename FROM _migrations');
    const appliedSet = new Set(applied.map(r => r.filename));

    let count = 0;
    for (const file of files) {
      if (appliedSet.has(file)) continue;
      const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO _migrations (filename) VALUES ($1)', [file]);
        await client.query('COMMIT');
        console.log(`[migration] Applied: ${file}`);
        count++;
      } catch (err) {
        await client.query('ROLLBACK');
        console.error(`[migration] FAILED: ${file} — ${err.message}`);
        throw err;
      }
    }
    if (count === 0) {
      console.log(`[migration] Up to date (${files.length} files, none pending)`);
    } else {
      console.log(`[migration] Done — ${count} new migration(s) applied`);
    }
  } finally {
    client.release();
  }
}

module.exports = { pool, runMigrations };
