// Shared helpers for routes scoped to /api/servers/:serverId/...
//
// The previous codebase had `function requireAdmin(req, res)` copy-pasted
// across 13+ route files (firewall, nat, routes, peers, subnets,
// route-policies, port-forwards, firewall-aliases, firewall-zones,
// sites, application-servers, dns-filter) plus a similar
// `async function getClient(serverId, req)` shape in another 5 files.
// Drift was already visible: a few requireAdmin implementations rejected
// 'member' but accepted 'admin' while others (post-refactor) were
// stricter. Single source of truth here.
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { isAdmin } = require('../constants/roles');

/**
 * Verify the caller has admin role in the active enterprise. Sends a 403
 * response on failure. Returns true on success so the route can short-
 * circuit:
 *
 *   if (!requireAdmin(req, res)) return;
 *
 * Reads role from req.enterpriseRole (set by enterpriseContext
 * middleware). Internal-key callers ride in with enterpriseRole='root'.
 */
function requireAdmin(req, res) {
  if (isAdmin(req.enterpriseRole)) return true;
  res.status(403).json({ error: 'Admin access required' });
  return false;
}

/**
 * Verify the caller can access the requested server + return both the
 * server row and an AgentClient bound to it. Throws a 404-status Error
 * when the server doesn't exist or isn't reachable to this enterprise.
 * Root sees every server; non-root sees servers in their enterprise OR
 * any server marked access_mode='public'.
 *
 * Usage:
 *   const { server, client } = await requireServerAccess(req, req.params.serverId);
 */
async function requireServerAccess(req, serverId) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT * FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT * FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) {
    const e = new Error('Server not found');
    e.status = 404;
    throw e;
  }
  return { server: rows[0], client: new AgentClient(parseInt(serverId)) };
}

module.exports = { requireAdmin, requireServerAccess };
