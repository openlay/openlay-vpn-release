require('dotenv').config();

module.exports = {
  // WireGuard config directory
  wgConfigDir: process.env.WG_CONFIG_DIR || '/etc/wireguard',

  // Audit logging
  auditLogFile: process.env.AUDIT_LOG_FILE || '',
  auditLogMax: parseInt(process.env.AUDIT_LOG_MAX, 10) || 1000,

  // Management server
  managementApiUrl: process.env.MANAGEMENT_API_URL || '',
  managementApiToken: process.env.MANAGEMENT_API_TOKEN || '',
  enrollmentToken: process.env.ENROLLMENT_TOKEN || process.env.MANAGEMENT_API_TOKEN || '',
  managementCaCert: process.env.MANAGEMENT_CA_CERT || '',
  heartbeatInterval: parseInt(process.env.HEARTBEAT_INTERVAL, 10) || 30,

  // Legacy (kept for backward compat with registration.js publicUrl)
  apiToken: process.env.API_TOKEN || '',
};
