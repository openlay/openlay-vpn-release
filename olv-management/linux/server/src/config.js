const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

module.exports = {
  port: parseInt(process.env.PORT, 10) || 3001,
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/wireguard_management',
  // Token agents must send to register (empty = no auth on agent endpoints)
  managementApiToken: process.env.MANAGEMENT_API_TOKEN || '',
  // TLS certificate directory (key.pem + cert.pem)
  tlsCertDir: path.resolve(
    __dirname, '../..',
    process.env.TLS_CERT_DIR || 'certs'
  ),
  // JWT for management app auth
  jwtSecret: process.env.JWT_SECRET || 'openlay-management-secret-change-me',
  // Internal service-to-service key (app-api → management)
  internalApiKey: process.env.INTERNAL_API_KEY || '',
  // Apple Sign In
  appleClientIds: (process.env.APPLE_CLIENT_IDS || 'com.openlay.vpnmanagement').split(',').map(s => s.trim()),
  appleTeamId: process.env.APPLE_TEAM_ID || '',
  // Auth token TTLs. Long-lived refresh token (login) for renew + short-lived
  // access token (session) used on every API call.
  loginTtlDays: parseInt(process.env.LOGIN_TTL_DAYS, 10) || (process.env.NODE_ENV === 'development' ? 7 : 90),
  sessionTtlHours: parseInt(process.env.SESSION_TTL_HOURS, 10) || (process.env.NODE_ENV === 'development' ? 1 : 24),
};
