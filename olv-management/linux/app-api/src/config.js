require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

module.exports = {
  port: parseInt(process.env.PORT, 10) || 443,
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/wireguard_management',
  jwtSecret: process.env.JWT_SECRET || 'change-me-to-a-secure-random-secret',
  appleClientIds: (process.env.APPLE_CLIENT_IDS || '').split(',').map(s => s.trim()).filter(Boolean),
  appleTeamId: process.env.APPLE_TEAM_ID || '',
  appAttestProduction: process.env.APP_ATTEST_PRODUCTION === 'true',
  // Management server URL (agent operations proxied through it)
  managementUrl: process.env.MANAGEMENT_URL || 'https://localhost:3084',
  // Internal service-to-service key (must match management server's INTERNAL_API_KEY)
  internalApiKey: process.env.INTERNAL_API_KEY || '',
};
