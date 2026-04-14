const pool = require('../db/pool').pool;
const jwtAuth = require('./jwtAuth');
const config = require('../config');

/**
 * Middleware: JWT auth + enterprise context from X-Enterprise-Id header.
 * Sets req.enterpriseId and verifies user has access.
 * Also sets req.enterpriseRole ('root', 'super_admin', 'admin', 'member').
 *
 * Internal service-to-service calls (app-api → management) can bypass JWT
 * by sending X-Internal-Key header matching INTERNAL_API_KEY.
 */
function enterpriseContext(req, res, next) {
  // Internal service bypass (app-api → management, same host)
  const internalKey = req.headers['x-internal-key'];
  if (internalKey && config.internalApiKey && internalKey === config.internalApiKey) {
    req.enterpriseId = req.headers['x-enterprise-id'] || null;
    req.enterpriseRole = 'root'; // internal calls have full access
    req.user = { id: 'internal-service', email: 'internal' };
    return next();
  }

  // First run JWT auth
  jwtAuth(req, res, async (err) => {
    if (err) return; // jwtAuth already sent 401

    const enterpriseId = req.headers['x-enterprise-id'];

    try {
      // Check if root user (can access any enterprise, enterprise header optional)
      const rootCheck = await pool.query('SELECT 1 FROM root_users WHERE user_id = $1', [req.user.id]);
      if (rootCheck.rows.length > 0) {
        req.enterpriseId = enterpriseId || null;
        req.enterpriseRole = 'root';
        return next();
      }

      if (!enterpriseId) {
        return res.status(400).json({ error: 'X-Enterprise-Id header is required' });
      }

      // Check user role in this enterprise
      const roleCheck = await pool.query(
        'SELECT role FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
        [req.user.id, enterpriseId]
      );
      if (roleCheck.rows.length === 0) {
        return res.status(403).json({ error: 'No access to this enterprise' });
      }

      req.enterpriseId = enterpriseId;
      req.enterpriseRole = roleCheck.rows[0].role;
      next();
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}

module.exports = enterpriseContext;
