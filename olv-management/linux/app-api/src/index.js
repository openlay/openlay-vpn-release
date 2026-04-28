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

app.use(cors());
app.use(express.json());

// Request/Response logger with body
app.use((req, res, next) => {
  const start = Date.now();
  const { method, url } = req;
  const ip = req.ip || req.socket.remoteAddress;

  console.log(`\n→ ${method} ${url} [${ip}]`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('  req body:', JSON.stringify(req.body, null, 2));
  }

  // Capture response body
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    const ms = Date.now() - start;
    console.log(`← ${method} ${url} ${res.statusCode} ${ms}ms`);
    console.log('  res body:', JSON.stringify(body, null, 2));
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
