require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });

const DEFAULT_JWT_SECRET = 'change-me-to-a-secure-random-secret';

// Refuse to boot in production-ish environments (anything other than
// NODE_ENV=development) with unset secrets or the SKIP_APP_ATTEST escape
// hatch left enabled. Historical gap: staging shipped with default secrets
// because the previous code silently fell back to a hardcoded constant.
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
requireSecret('INTERNAL_API_KEY', process.env.INTERNAL_API_KEY);

// SKIP_APP_ATTEST bypasses every App Attest check. It exists for the
// staging tier where iOS dev builds can't produce real attestations. In
// production it MUST be off; the env var being explicitly set to 'true'
// while NODE_ENV=production is treated as a deploy mistake, not a feature.
if (process.env.SKIP_APP_ATTEST === 'true' && process.env.NODE_ENV === 'production') {
  console.error('[config] SKIP_APP_ATTEST=true with NODE_ENV=production — refusing to boot (this would disable App Attest on prod)');
  process.exit(1);
}

module.exports = {
  port: parseInt(process.env.PORT, 10) || 443,
  databaseUrl: process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/wireguard_management',
  jwtSecret: process.env.JWT_SECRET || DEFAULT_JWT_SECRET,
  appleClientIds: (process.env.APPLE_CLIENT_IDS || '').split(',').map(s => s.trim()).filter(Boolean),
  appleTeamId: process.env.APPLE_TEAM_ID || '',
  appAttestProduction: process.env.APP_ATTEST_PRODUCTION === 'true',
  skipAppAttest: process.env.SKIP_APP_ATTEST === 'true',
  managementUrl: process.env.MANAGEMENT_URL || 'https://localhost:3084',
  internalApiKey: process.env.INTERNAL_API_KEY || '',
};
