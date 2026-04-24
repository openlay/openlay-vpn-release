const os = require('os');
const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const config = require('../config');
const audit = require('./audit');
const wgService = require('./wireguard');

let heartbeatTimer = null;
let registered = false;
let lastRegisterResponse = null;
let cachedPublicIp = null;
let cachedPublicIpAt = 0;
const PUBLIC_IP_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
let agentId = null;

// ---------------------------------------------------------------------------
// Load management server CA cert (for TLS cert pinning, chống MITM)
// ---------------------------------------------------------------------------

let managementCa = null;

function loadManagementCa() {
  if (managementCa !== null) return managementCa; // already loaded (or empty)

  if (config.managementCaCert) {
    try {
      managementCa = fs.readFileSync(config.managementCaCert);
      console.log(`[tls] Management CA cert loaded: ${config.managementCaCert}`);
    } catch (err) {
      console.error(`[tls] FATAL: Cannot read MANAGEMENT_CA_CERT at "${config.managementCaCert}": ${err.message}`);
      console.error('[tls] Agent will REFUSE to connect to management server without valid CA cert.');
      managementCa = false; // mark as failed
    }
  } else {
    managementCa = false; // not configured
  }
  return managementCa;
}

// ---------------------------------------------------------------------------
// HTTP client — 2 modes:
//   - metadata calls (cloud internal, HTTP, no TLS verification)
//   - management calls (strict TLS, pinned CA cert)
// ---------------------------------------------------------------------------

function httpRequest(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const timeout = opts.timeout || 3000;

    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: opts.method || 'GET',
      headers: opts.headers || {},
      timeout,
    };

    if (isHttps) {
      if (opts.ca) {
        // Strict mode: only trust the pinned CA cert
        reqOpts.ca = opts.ca;
        reqOpts.rejectUnauthorized = true;
        reqOpts.checkServerIdentity = () => undefined;
      } else if (opts.rejectUnauthorized === false) {
        // Caller explicitly accepts self-signed (e.g. management server)
        reqOpts.rejectUnauthorized = false;
      } else {
        // Default: use system CA bundle (e.g. metadata services, external APIs)
        reqOpts.rejectUnauthorized = true;
      }
    }

    const req = lib.request(reqOpts, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8').trim();
        resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, body });
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${url}`)); });
    req.on('error', reject);

    if (opts.body) req.write(opts.body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Cloud metadata helpers — multi-cloud support
// Thứ tự: AWS → GCP → Azure → DigitalOcean → fallback
// ---------------------------------------------------------------------------

async function metaGet(url, headers = {}, timeout = 2000) {
  try {
    const res = await httpRequest(url, { headers, timeout });
    if (!res.ok) return null;
    try { return JSON.parse(res.body); } catch { return res.body; }
  } catch {
    return null;
  }
}

let awsImdsToken = null;

async function getAwsImdsToken() {
  if (awsImdsToken) return awsImdsToken;
  try {
    const res = await httpRequest('http://169.254.169.254/latest/api/token', {
      method: 'PUT',
      headers: { 'X-aws-ec2-metadata-token-ttl-seconds': '300' },
      timeout: 2000,
    });
    if (res.ok) awsImdsToken = res.body;
  } catch {}
  return awsImdsToken;
}

async function awsMeta(path) {
  const token = await getAwsImdsToken();
  if (!token) return null;
  return metaGet(`http://169.254.169.254/latest/meta-data/${path}`, {
    'X-aws-ec2-metadata-token': token,
  });
}

async function gcpMeta(path) {
  return metaGet(`http://metadata.google.internal/computeMetadata/v1/${path}`, {
    'Metadata-Flavor': 'Google',
  });
}

async function azureMeta() {
  return metaGet('http://169.254.169.254/metadata/instance?api-version=2021-02-01', {
    'Metadata': 'true',
  });
}

async function doMeta(path) {
  return metaGet(`http://169.254.169.254/metadata/v1/${path}`);
}

// ---------------------------------------------------------------------------
// Agent ID — cloud instance ID (unique per instance, stable qua reboot)
// ---------------------------------------------------------------------------

async function resolveAgentId() {
  if (agentId) return agentId;

  // 1) AWS EC2
  try {
    const id = await awsMeta('instance-id');
    if (id) { agentId = `aws-${id}`; console.log(`[registration] Agent ID from AWS EC2: ${agentId}`); return agentId; }
  } catch {}

  // 2) Google Cloud
  try {
    const id = await gcpMeta('instance/id');
    if (id) { agentId = `gcp-${id}`; console.log(`[registration] Agent ID from GCP: ${agentId}`); return agentId; }
  } catch {}

  // 3) Azure
  try {
    const meta = await azureMeta();
    if (meta && meta.compute && meta.compute.vmId) { agentId = `azure-${meta.compute.vmId}`; console.log(`[registration] Agent ID from Azure: ${agentId}`); return agentId; }
  } catch {}

  // 4) DigitalOcean
  try {
    const id = await doMeta('id');
    if (id) { agentId = `do-${id}`; console.log(`[registration] Agent ID from DigitalOcean: ${agentId}`); return agentId; }
  } catch {}

  // 5) Fallback: deterministic hash from hostname + MAC addresses
  const nets = os.networkInterfaces();
  const macs = [];
  for (const ifaces of Object.values(nets)) {
    for (const iface of ifaces) {
      if (iface.mac && iface.mac !== '00:00:00:00:00:00') macs.push(iface.mac);
    }
  }
  macs.sort();
  const fingerprint = `${os.hostname()}:${macs.join(',')}`;
  const hash = crypto.createHash('sha256').update(fingerprint).digest('hex');
  agentId = `local-${hash.slice(0, 16)}`;
  console.log(`[registration] Agent ID from machine fingerprint: ${agentId}`);
  return agentId;
}

// ---------------------------------------------------------------------------
// Auto-detect public IP — multi-cloud metadata → external API fallback
// ---------------------------------------------------------------------------

async function fetchPublicIp() {
  if (cachedPublicIp && (Date.now() - cachedPublicIpAt) < PUBLIC_IP_CACHE_TTL) return cachedPublicIp;

  // 1) AWS EC2
  try {
    const ip = await awsMeta('public-ipv4');
    if (ip) { cachedPublicIp = ip; cachedPublicIpAt = Date.now(); console.log(`[registration] Public IP from AWS metadata: ${cachedPublicIp}`); return cachedPublicIp; }
  } catch {}

  // 2) GCP
  try {
    const ip = await gcpMeta('instance/network-interfaces/0/access-configs/0/external-ip');
    if (ip) { cachedPublicIp = ip; cachedPublicIpAt = Date.now(); console.log(`[registration] Public IP from GCP metadata: ${cachedPublicIp}`); return cachedPublicIp; }
  } catch {}

  // 3) Azure
  try {
    const meta = await azureMeta();
    const ip = meta && meta.network && meta.network.interface && meta.network.interface[0] &&
      meta.network.interface[0].ipv4 && meta.network.interface[0].ipv4.ipAddress &&
      meta.network.interface[0].ipv4.ipAddress[0] && meta.network.interface[0].ipv4.ipAddress[0].publicIpAddress;
    if (ip) { cachedPublicIp = ip; cachedPublicIpAt = Date.now(); console.log(`[registration] Public IP from Azure metadata: ${cachedPublicIp}`); return cachedPublicIp; }
  } catch {}

  // 4) DigitalOcean
  try {
    const ip = await doMeta('interfaces/public/0/ipv4/address');
    if (ip) { cachedPublicIp = ip; cachedPublicIpAt = Date.now(); console.log(`[registration] Public IP from DigitalOcean metadata: ${cachedPublicIp}`); return cachedPublicIp; }
  } catch {}

  // 5) Fallback: external services
  const services = [
    'https://api.ipify.org',
    'https://ifconfig.me/ip',
    'https://icanhazip.com',
  ];
  for (const url of services) {
    try {
      const res = await httpRequest(url, { timeout: 3000 });
      if (res.ok && res.body) {
        cachedPublicIp = res.body; cachedPublicIpAt = Date.now();
        console.log(`[registration] Public IP from ${url}: ${cachedPublicIp}`);
        return cachedPublicIp;
      }
    } catch { continue; }
  }

  console.warn('[registration] Could not detect public IP, using local IP');
  const nets = os.networkInterfaces();
  for (const ifaces of Object.values(nets)) {
    for (const iface of ifaces) {
      if (!iface.internal && iface.family === 'IPv4') return iface.address;
    }
  }
  return '127.0.0.1';
}

// ---------------------------------------------------------------------------
// Build payload
// ---------------------------------------------------------------------------

async function buildAgentPayload() {
  const publicIp = await fetchPublicIp();
  const id = await resolveAgentId();

  // Đọc tất cả WireGuard interfaces có sẵn trên server
  let interfaces = [];
  try {
    interfaces = await wgService.getInterfaceSummaries();
  } catch { /* WG chưa có config nào */ }

  return {
    agentId: id,
    name: os.hostname(),
    publicUrl: `https://${publicIp}`,
    apiToken: config.apiToken,
    hostname: os.hostname(),
    publicIp,
    platform: os.platform(),
    arch: os.arch(),
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
    // Danh sách interfaces + subnet đang có trên server
    interfaces,
  };
}

// ---------------------------------------------------------------------------
// Management API request helper
// ---------------------------------------------------------------------------

async function request(apiPath, method = 'POST', body = null, overrideToken = null) {
  const url = `${config.managementApiUrl.replace(/\/+$/, '')}${apiPath}`;
  const isHttps = url.startsWith('https://');

  // Load CA cert if available (optional — for pinning management server cert)
  const ca = loadManagementCa();
  // No longer required — management uses self-signed cert, agent accepts it

  const bearerToken = overrideToken || config.managementApiToken;
  const headers = { 'Content-Type': 'application/json' };
  if (bearerToken) {
    headers['Authorization'] = `Bearer ${bearerToken}`;
  }

  const res = await httpRequest(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    timeout: 10000,
    ca: isHttps && ca ? ca : undefined,
    rejectUnauthorized: !!(isHttps && ca),  // Accept self-signed if no CA cert pinned
  });

  let data;
  try { data = JSON.parse(res.body); } catch { data = res.body; }

  if (!res.ok) {
    const err = new Error(`Management API ${method} ${apiPath} → ${res.status}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

// ---------------------------------------------------------------------------
// Register — management server should upsert by agentId
// ---------------------------------------------------------------------------

async function register() {
  if (!config.managementApiUrl) return;

  const payload = await buildAgentPayload();
  console.log(`[registration] Registering agent="${payload.agentId}" name="${payload.name}" (${payload.publicUrl})`);

  try {
    const res = await request('/agents/register', 'POST', payload);
    registered = true;
    lastRegisterResponse = res;
    console.log('[registration] Registered successfully:', res.message || res.id || 'ok');
    if (res.wsUrl) {
      console.log(`[registration] WebSocket URL: ${res.wsUrl}`);
    }
    audit.log('management.register', {
      agentId: payload.agentId,
      url: config.managementApiUrl,
      name: payload.name,
      status: 'success',
    });
  } catch (err) {
    registered = false;
    console.error(`[registration] Failed to register: ${err.message}`);
    audit.log('management.register', { url: config.managementApiUrl, status: 'failed', error: err.message });
    scheduleRetry();
  }
}

/**
 * Enroll with CSR — get signed cert from management.
 * Uses enrollment token (not management API token).
 */
async function enroll(certManager) {
  if (!config.managementApiUrl) return null;

  const payload = await buildAgentPayload();
  const { csr } = certManager.generateCSR(agentId);

  console.log(`[enrollment] Enrolling agent="${agentId}" with CSR...`);

  try {
    // Use enrollment token (API_TOKEN from .env) for enrollment
    const enrollPayload = {
      agentId: payload.agentId,
      hostname: payload.hostname,
      publicUrl: payload.publicUrl,
      apiToken: config.apiToken,
      platform: payload.platform,
      arch: payload.arch,
      csr,
      interfaces: payload.interfaces,
    };

    const res = await request('/enrollment/enroll', 'POST', enrollPayload, config.enrollmentToken);

    if (res.agentCert && res.caCert) {
      certManager.storeCert(res.agentCert, res.caCert);
      registered = true;
      lastRegisterResponse = res;
      console.log(`[enrollment] Enrolled successfully. Cert received.`);
      if (res.wsUrl) {
        console.log(`[enrollment] WebSocket URL: ${res.wsUrl}`);
      }
      return res;
    } else {
      console.error('[enrollment] No cert in response');
      return null;
    }
  } catch (err) {
    console.error(`[enrollment] Failed: ${err.message}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

async function sendHeartbeat() {
  if (!config.managementApiUrl) return;

  const payload = await buildAgentPayload();

  try {
    await request('/agents/heartbeat', 'POST', payload);
    if (!registered) {
      registered = true;
      console.log('[heartbeat] Re-registered via heartbeat');
    }
  } catch (err) {
    console.error(`[heartbeat] Failed: ${err.message}`);
    if (err.status === 404 || err.status === 401) {
      registered = false;
      console.log('[heartbeat] Agent not recognized, re-registering...');
      await register();
    }
  }
}

function startHeartbeat() {
  if (!config.managementApiUrl || config.heartbeatInterval <= 0) return;

  stopHeartbeat();
  const ms = config.heartbeatInterval * 1000;
  heartbeatTimer = setInterval(sendHeartbeat, ms);
  heartbeatTimer.unref();
  console.log(`[heartbeat] Started — every ${config.heartbeatInterval}s`);
}

function stopHeartbeat() {
  if (heartbeatTimer) {
    clearInterval(heartbeatTimer);
    heartbeatTimer = null;
  }
}

// ---------------------------------------------------------------------------
// Deregister (graceful shutdown)
// ---------------------------------------------------------------------------

async function deregister() {
  if (!config.managementApiUrl || !registered) return;

  const id = await resolveAgentId();
  console.log('[registration] Deregistering from management server...');

  try {
    await request('/agents/deregister', 'POST', { agentId: id, name: os.hostname() });
    console.log('[registration] Deregistered successfully');
    audit.log('management.deregister', { agentId: id, status: 'success' });
  } catch (err) {
    console.error(`[registration] Failed to deregister: ${err.message}`);
  }
  registered = false;
}

// ---------------------------------------------------------------------------
// Retry
// ---------------------------------------------------------------------------

function scheduleRetry() {
  const delay = Math.min((config.heartbeatInterval || 30) * 1000, 60000);
  setTimeout(async () => {
    if (!registered) {
      console.log('[registration] Retrying registration...');
      await register();
      if (registered) startHeartbeat();
    }
  }, delay).unref();
}

// ---------------------------------------------------------------------------
// Boot / Shutdown
// ---------------------------------------------------------------------------

async function boot() {
  if (!config.managementApiUrl) {
    console.log('[registration] MANAGEMENT_API_URL not set — skipping registration');
    return;
  }

  // Load CA cert if available (optional for server verification)
  loadManagementCa();

  await resolveAgentId();
  await register();
  if (registered) startHeartbeat();

  return {
    agentId,
    wsUrl: lastRegisterResponse?.wsUrl || null,
  };
}

async function shutdown() {
  stopHeartbeat();
  await deregister();
}

module.exports = {
  boot,
  enroll,
  shutdown,
  resolveAgentId,
  fetchPublicIp,
  isRegistered: () => registered,
  getAgentId: () => agentId,
};
