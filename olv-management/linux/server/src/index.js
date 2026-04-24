const express = require('express');
const https = require('https');
const fs = require('fs');
const cors = require('cors');
const path = require('path');
const config = require('./config');
const { runMigrations, pool } = require('./db/pool');
const enterpriseContext = require('./middleware/enterpriseContext');
const errorHandler = require('./middleware/errorHandler');

const serversRouter = require('./routes/servers');
const interfacesRouter = require('./routes/interfaces');
const peersRouter = require('./routes/peers');
const subnetsRouter = require('./routes/subnets');
const statusRouter = require('./routes/status');
const dashboardRouter = require('./routes/dashboard');
const adminRouter = require('./routes/admin');
const agentsRouter = require('./routes/agents');
const authRouter = require('./routes/auth');
const enterprisesRouter = require('./routes/enterprises');
const userGroupsRouter = require('./routes/user-groups');
const enrollmentRouter = require('./routes/enrollment');
const firewallRouter = require('./routes/firewall');
const firewallZonesRouter = require('./routes/firewall-zones');
const firewallAliasesRouter = require('./routes/firewall-aliases');
const dnsFilterRouter = require('./routes/dns-filter');
const routesRouter = require('./routes/routes');
const routePoliciesRouter = require('./routes/route-policies');
const natRouter = require('./routes/nat');
const portForwardsRouter = require('./routes/port-forwards');
const sitesRouter = require('./routes/sites');
const localPortForwardsRouter = require('./routes/local-port-forwards');
const migrateRouter = require('./routes/migrate');
const caManager = require('./services/caManager');
const { startExpiryChecker } = require('./services/expiryChecker');

const app = express();

app.use(cors());
app.use(express.json());

// API routes
app.use('/api/servers', serversRouter);
app.use('/api/servers/:serverId/interfaces', interfacesRouter);
app.use('/api/servers/:serverId/interfaces/:iface/peers', peersRouter);
app.use('/api/servers/:serverId/subnets', subnetsRouter);
app.use('/api/servers/:serverId/status', statusRouter);
app.use('/api/servers/:serverId/firewall', firewallRouter);
app.use('/api/servers/:serverId/firewall/zones', firewallZonesRouter);
app.use('/api/servers/:serverId/firewall/aliases', firewallAliasesRouter);
app.use('/api/servers/:serverId/dns', dnsFilterRouter);
app.use('/api/servers/:serverId/routes', routesRouter);
app.use('/api/servers/:serverId/route-policies', routePoliciesRouter);
app.use('/api/servers/:serverId/nat', natRouter);
app.use('/api/servers/:serverId/port-forwards', portForwardsRouter);
app.use('/api/servers/:serverId/sites', sitesRouter);
app.use('/api/servers/:serverId/local-port-forwards', localPortForwardsRouter);
// POST /api/servers/:destId/migrate-from/:sourceId — root-only server clone.
app.use('/api/servers/:destId/migrate-from', migrateRouter);
app.use('/api/dashboard', dashboardRouter);
app.use('/api/admin', adminRouter);
app.use('/api/agents', agentsRouter);
app.use('/api/auth', authRouter);
app.use('/api/enterprises', enterprisesRouter);
app.use('/api/enrollment', enrollmentRouter);
app.use('/api', userGroupsRouter);

// Test results (root only)
app.post('/api/test-results', enterpriseContext, async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') return res.status(403).json({ error: 'Root only' });
    const { serverId, summary, rawLog } = req.body;
    const userId = req.userId || req.user?.id || 'unknown';
    await pool.query(
      'INSERT INTO test_results (server_id, user_id, summary, raw_log) VALUES ($1, $2, $3, $4)',
      [serverId, userId, JSON.stringify(summary), rawLog]
    );
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve frontend in production
const clientDist = path.join(__dirname, '../../client/dist');
app.use(express.static(clientDist));
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(clientDist, 'index.html'));
});

app.use(errorHandler);

async function start() {
  try {
    await runMigrations();
  } catch (err) {
    console.error('[migration] Fatal:', err.message);
    process.exit(1);
  }

  // Initialize internal CA (generate keypair if first run)
  try {
    await caManager.init();
  } catch (err) {
    console.error('[CA] Failed to initialize:', err.message);
    process.exit(1);
  }

  // Start peer expiry checker (every 60 seconds)
  startExpiryChecker(60000);

  // Load TLS certs for HTTPS
  const certDir = config.tlsCertDir;
  const keyPath = path.resolve(certDir, 'key.pem');
  const certPath = path.resolve(certDir, 'cert.pem');

  console.log(`[TLS] Cert dir: ${certDir}`);
  console.log(`[TLS] Key: ${keyPath} (exists: ${fs.existsSync(keyPath)})`);
  console.log(`[TLS] Cert: ${certPath} (exists: ${fs.existsSync(certPath)})`);

  if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    const sslOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };

    startServer(sslOptions);
  } else {
    console.warn(`[TLS] Cert files not found at ${certDir} — generating self-signed cert...`);
    const { execSync } = require('child_process');
    fs.mkdirSync(certDir, { recursive: true });
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout "${keyPath}" -out "${certPath}" -days 3650 -nodes -subj "/CN=wireguard-management"`,
      { stdio: 'pipe' }
    );
    console.log(`[TLS] Self-signed cert generated at ${certDir}`);

    const sslOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };

    startServer(sslOptions);
  }
}

function startServer(sslOptions) {
  // Request client cert (optional — for mutual TLS with agents)
  // requestCert=true asks clients to present cert, rejectUnauthorized=false allows without
  sslOptions.requestCert = true;
  sslOptions.rejectUnauthorized = false;
  // Add CA cert so server can verify agent certs
  const caCert = caManager.getCACert();
  if (caCert) {
    sslOptions.ca = [caCert];
  }

  const httpsServer = https.createServer(sslOptions, app);

  // Attach WebSocket server for agent connections
  const { attachWebSocketServer } = require('./services/wsServer');
  attachWebSocketServer(httpsServer);

  httpsServer.listen(config.port, () => {
    console.log(`OpenLayVPN Management API running on https://0.0.0.0:${config.port}`);
    console.log(`WebSocket agent endpoint: wss://0.0.0.0:${config.port}/ws/agent`);
  });
}

start();
