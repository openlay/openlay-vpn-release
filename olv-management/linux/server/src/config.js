const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

const DEFAULT_JWT_SECRET = 'openlay-management-secret-change-me';
const isProd = process.env.NODE_ENV === 'production';

// Refuse to boot in production with unset or default-shipped secrets. In dev
// (NODE_ENV=development) we keep the defaults so a `npm run dev` clone works
// out-of-the-box. Any other environment (NODE_ENV unset, "staging", etc.) is
// treated as prod-adjacent and fails closed — historically staging shipped
// with the default JWT secret because of this exact gap.
function requireSecret(name, value, opts = {}) {
  const isDefault = opts.defaultMarker && value === opts.defaultMarker;
  if (value && !isDefault) return;
  const reason = !value ? 'unset' : 'using the shipped default';
  const msg = `[config] ${name} is ${reason} — set a real secret in .env`;
  if (process.env.NODE_ENV === 'development') {
    console.warn(`${msg} (NODE_ENV=development — continuing; this would refuse to boot anywhere else)`);
    return;
  }
  console.error(`${msg} (NODE_ENV=${process.env.NODE_ENV || '<unset>'} — refusing to boot)`);
  process.exit(1);
}

requireSecret('JWT_SECRET', process.env.JWT_SECRET, { defaultMarker: DEFAULT_JWT_SECRET });
requireSecret('MANAGEMENT_API_TOKEN', process.env.MANAGEMENT_API_TOKEN);
requireSecret('INTERNAL_API_KEY', process.env.INTERNAL_API_KEY);

module.exports = {
  port: parseInt(process.env.PORT, 10) || 3001,
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/wireguard_management',
  managementApiToken: process.env.MANAGEMENT_API_TOKEN || '',
  tlsCertDir: path.resolve(
    __dirname, '../..',
    process.env.TLS_CERT_DIR || 'certs'
  ),
  jwtSecret: process.env.JWT_SECRET || DEFAULT_JWT_SECRET,
  rateLimitDisabled: process.env.RATE_LIMIT_DISABLED === 'true',
  internalApiKey: process.env.INTERNAL_API_KEY || '',
  appleClientIds: (process.env.APPLE_CLIENT_IDS || 'com.openlay.vpnmanagement').split(',').map(s => s.trim()),
  appleTeamId: process.env.APPLE_TEAM_ID || '',
  // Auth token TTLs. Long-lived refresh token (login) for renew + short-lived
  // access token (session) used on every API call.
  loginTtlDays: parseInt(process.env.LOGIN_TTL_DAYS, 10) || (process.env.NODE_ENV === 'development' ? 7 : 90),
  sessionTtlHours: parseInt(process.env.SESSION_TTL_HOURS, 10) || (process.env.NODE_ENV === 'development' ? 1 : 24),
  isProd,
};
