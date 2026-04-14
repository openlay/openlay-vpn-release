const config = require('./config');
const registration = require('./services/registration');
const wsClient = require('./services/wsClient');
const certManager = require('./services/certManager');
const firewall = require('./services/firewall');
const dnsFilter = require('./services/dnsFilter');

// ---------------------------------------------------------------------------
// Boot — enroll → connect WebSocket (no HTTPS server, no listening port)
// ---------------------------------------------------------------------------

async function boot() {
  console.log('OpenLay VPN Agent starting...');

  // Resolve agent identity
  await registration.resolveAgentId();
  const currentAgentId = registration.getAgentId();
  console.log(`[boot] Agent ID: ${currentAgentId}`);

  // Check if we have a valid enrolled certificate
  const certStatus = certManager.check(currentAgentId);

  if (certStatus.certMismatch) {
    console.log('[boot] EC2 clone detected — clearing old certs for re-enrollment');
    certManager.clearCerts();
  }

  let wsUrl = null;

  if (certStatus.enrolled) {
    console.log('[boot] Agent cert valid — skipping enrollment');
    const result = await registration.boot();
    wsUrl = result?.wsUrl;
  } else {
    console.log('[boot] No valid cert — attempting enrollment...');
    const enrollResult = await registration.enroll(certManager);

    if (enrollResult?.agentCert) {
      wsUrl = enrollResult.wsUrl;
      console.log('[boot] Enrollment successful — cert received');
    } else {
      console.log('[boot] Enrollment failed — falling back to legacy registration');
      const result = await registration.boot();
      wsUrl = result?.wsUrl;
    }
  }

  // Derive wsUrl if not received from server
  if (!wsUrl && config.managementApiUrl) {
    wsUrl = config.managementApiUrl
      .replace(/\/api$/, '')
      .replace(/^https:/, 'wss:')
      .replace(/^http:/, 'ws:')
      + '/ws/agent';
  }

  // Restore firewall rules + policy for all interfaces
  await firewall.restoreAll();

  // Initialize DNS filter (load persisted blocklists)
  await dnsFilter.init();

  // Connect WebSocket to management server
  if (wsUrl) {
    if (certManager.hasCert()) {
      wsClient.setClientCert(certManager.getCertPaths());
      console.log('[ws] Using client certificate for WebSocket auth');
    }
    wsClient.connect(wsUrl, config.managementApiToken, currentAgentId);
    console.log(`[ws] Connecting to management WebSocket: ${wsUrl}`);
  } else {
    console.error('[boot] No management URL configured — agent idle');
  }
}

boot().catch(err => {
  console.error('[boot] Fatal:', err.message);
  process.exit(1);
});

// Graceful shutdown
async function gracefulShutdown(signal) {
  console.log(`\n[shutdown] ${signal} received — shutting down...`);
  wsClient.close();
  await registration.shutdown();
  process.exit(0);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
