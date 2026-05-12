// Helper for PATCH/PUT routes that need to translate a partial body
// into a SQL UPDATE. The 9-route-duplicate pattern was:
//
//   const fields = [];
//   const values = [];
//   let idx = 1;
//   if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
//   if (...) { ... }
//   const sql = `UPDATE table SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`;
//
// Each repetition was a typo-bug surface (forgetting to bump idx,
// shadowing values, allowing a non-allowlisted column through). Build a
// single helper that takes the allowlist + the body and returns
// {clause, values, nextIdx} ready to splice into a parametrised query.
//
// Usage:
//   const { clause, values } = buildPatch(req.body, {
//     name: 'name', description: 'description',
//   });
//   if (!clause) return res.status(400).json({ error: 'No fields to update' });
//   values.push(req.params.id);
//   const { rows } = await pool.query(
//     `UPDATE table SET ${clause} WHERE id = $${values.length} RETURNING *`,
//     values
//   );

/**
 * Build a parameterised SET clause from a request body. Only keys in
 * `allowed` are mapped — body fields outside the allowlist are silently
 * dropped (defence against mass-assignment).
 *
 * @param {object} body — req.body or equivalent
 * @param {object} allowed — { bodyKey: 'sql_column_name' }. Same name
 *   for both? Just pass `{ name: 'name', description: 'description' }`.
 * @param {object} opts
 *   @param {number} opts.startIdx — first $N placeholder. Default 1.
 *     Pass > 1 if the calling query already has earlier parameters.
 *   @param {function} opts.transform — optional (column, value) => value
 *     for serialisation (e.g. JSON.stringify for jsonb columns).
 *
 * @returns {{ clause: string, values: any[], nextIdx: number }}
 *   `clause` is the `col=$1, col=$2, ...` text; empty string if no
 *   allowed keys were present. `nextIdx` is the next $-placeholder
 *   the caller should use for WHERE-clause params.
 */
function buildPatch(body, allowed, opts = {}) {
  const startIdx = opts.startIdx ?? 1;
  const transform = opts.transform ?? ((_, v) => v);
  const fields = [];
  const values = [];
  let idx = startIdx;
  for (const [bodyKey, col] of Object.entries(allowed)) {
    if (body == null) continue;
    if (Object.prototype.hasOwnProperty.call(body, bodyKey) && body[bodyKey] !== undefined) {
      fields.push(`${col} = $${idx++}`);
      values.push(transform(col, body[bodyKey]));
    }
  }
  return { clause: fields.join(', '), values, nextIdx: idx };
}

module.exports = { buildPatch };
