const https = require('https');
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const config = require('./config');

const authRouter = require('./routes/auth');
const enrollRouter = require('./routes/enroll');
const devicesRouter = require('./routes/devices');
const serversRouter = require('./routes/servers');
const connectRouter = require('./routes/connect');
const attestRouter = require('./routes/attest');
const configRouter = require('./routes/config');
const jwtAuth = require('./middleware/jwtAuth');
const appAttest = require('./middleware/appAttest');

const app = express();

// CORS: closed by default. iOS client traffic is native HTTP (no
// preflight). Set CORS_ALLOWED_ORIGINS=https://foo in .env to opt in
// any browser caller explicitly. Dev mode falls back to the previous
// permissive default.
const corsAllow = (process.env.CORS_ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
if (corsAllow.length > 0) {
  app.use(cors({ origin: corsAllow, credentials: true }));
} else if (process.env.NODE_ENV === 'development') {
  app.use(cors());
  console.warn('[cors] NODE_ENV=development — Access-Control-Allow-Origin: *');
}
// Tight body-size cap on the public-facing app-api. iOS clients send
// small JSON; anything beyond 1mb is either accidental (corrupt body)
// or hostile. enroll attestation blobs top out around 7kb.
app.use(express.json({ limit: '1mb' }));

// Request/Response logger with bodies — redacted. The unredacted version
// would dump JWTs issued by /api/auth/apple, Apple identity tokens
// received from clients, SE signatures, App Attest assertions, WG
// pre-shared keys, etc. into stdout (and from there into journalctl,
// log-shipping, syslog, etc.). Anyone with read access to those logs
// would inherit full session tokens for every active user. The redaction
// keys list mirrors every secret-shaped field in our request/response
// schemas; add new ones as routes grow.
const REDACT_KEYS = new Set([
  'token', 'access_token', 'refresh_token', 'jwt', 'authorization',
  'identityToken', 'identity_token', 'authorizationCode', 'authorization_code',
  'signature', 'assertion', 'attestation',
  'publicKey', 'public_key', 'privateKey', 'private_key',
  'presharedKey', 'preshared_key', 'psk',
  'password', 'pwd',
  'apiToken', 'api_token', 'managementApiToken',
]);

function redact(value, depth = 0) {
  if (depth > 6 || value == null) return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  if (typeof value !== 'object') return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (REDACT_KEYS.has(k)) {
      out[k] = typeof v === 'string' && v.length > 0 ? `<redacted ${v.length}ch>` : '<redacted>';
    } else {
      out[k] = redact(v, depth + 1);
    }
  }
  return out;
}

app.use((req, res, next) => {
  const start = Date.now();
  const { method, url } = req;
  const ip = req.ip || req.socket.remoteAddress;

  console.log(`\n→ ${method} ${url} [${ip}]`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('  req body:', JSON.stringify(redact(req.body), null, 2));
  }

  // Capture response body
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    const ms = Date.now() - start;
    console.log(`← ${method} ${url} ${res.statusCode} ${ms}ms`);
    console.log('  res body:', JSON.stringify(redact(body), null, 2));
    return originalJson(body);
  };

  next();
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'app-api' });
});

// Public routes
app.use('/api/auth', authRouter);
app.use('/api/enroll', enrollRouter);

// JWT-protected routes
app.use('/api/devices', jwtAuth, devicesRouter);
app.use('/api/servers', jwtAuth, serversRouter);
app.use('/api/attest', jwtAuth, attestRouter);
app.use('/api/config', jwtAuth, configRouter);
// /api/connect/refresh is mounted FIRST so Express routes it before falling
// through to the broader /api/connect handler. Refresh skips appAttest because
// DCAppAttestService can't run in a Network Extension; the (jwtAuth + SE
// signature + currentPeerId continuity) trio is the equivalent assurance.
app.use('/api/connect/refresh', jwtAuth, connectRouter.refreshRouter);
app.use('/api/connect', jwtAuth, appAttest, connectRouter);

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// Load TLS certs
const certsDir = path.resolve(__dirname, '../certs');
const tlsOptions = {
  key: fs.readFileSync(path.join(certsDir, 'key.pem')),
  cert: fs.readFileSync(path.join(certsDir, 'cert.pem')),
};

https.createServer(tlsOptions, app).listen(config.port, () => {
  console.log(`App API running on https://0.0.0.0:${config.port}`);
});
