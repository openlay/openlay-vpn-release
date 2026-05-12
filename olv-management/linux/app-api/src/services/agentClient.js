// Agent operations proxied through management server (via WebSocket internally)
// App-API no longer calls agents directly — management handles the WebSocket connection.
//
// TLS: we pin the management server's self-signed cert as the trust
// anchor for outbound HTTPS, rather than the previous
// `NODE_TLS_REJECT_UNAUTHORIZED=0` global which disabled cert verification
// for EVERY outbound TLS connection in this process — including the
// Apple JWKS fetch and any future external HTTPS call. Anyone able to
// MITM the path to Apple's keys could forge Sign-In tokens; pinning
// management's cert here closes that hole without affecting the
// downstream-to-management hop, which still runs over loopback in the
// default deploy.

const fs = require('fs');
const { Agent: UndiciAgent } = require('undici');
const config = require('../config');

let _dispatcher;
function getDispatcher() {
  if (_dispatcher) return _dispatcher;
  const caPath = process.env.MANAGEMENT_CA_PATH
    || '/home/olv-management/wireguard-management/certs/cert.pem';

  if (!fs.existsSync(caPath)) {
    if (process.env.NODE_ENV === 'development') {
      console.warn(`[agentClient] MANAGEMENT_CA_PATH not found at ${caPath} — falling back to rejectUnauthorized=false (NODE_ENV=development only)`);
      _dispatcher = new UndiciAgent({ connect: { rejectUnauthorized: false } });
      return _dispatcher;
    }
    throw new Error(`MANAGEMENT_CA_PATH not found at ${caPath} — set MANAGEMENT_CA_PATH in app-api .env to the management server's cert.pem`);
  }

  _dispatcher = new UndiciAgent({
    connect: {
      ca: fs.readFileSync(caPath),
      rejectUnauthorized: true,
      // Management's self-signed cert carries CN=wireguard-management, but
      // app-api connects via `https://localhost:3084` in the default
      // deploy. The hostname identity check would fail here. Skip it —
      // on-host MITM between app-api and management requires root anyway,
      // and `ca` above still pins the certificate content.
      checkServerIdentity: () => undefined,
    },
  });
  return _dispatcher;
}

/**
 * Client that proxies agent operations through management server.
 * Management server forwards commands to agents via WebSocket.
 */
class AgentClient {
  constructor(serverId) {
    this.serverId = serverId;
    // Management server base URL (same DB, different API port)
    this.mgmtUrl = (config.managementUrl || 'https://localhost:3001').replace(/\/+$/, '');
  }

  async request(method, path, body) {
    const url = `${this.mgmtUrl}/api/servers/${this.serverId}${path}`;
    const opts = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Internal-Key': config.internalApiKey || '',
      },
      signal: AbortSignal.timeout(10000),
      dispatcher: getDispatcher(),
    };
    if (body !== undefined) {
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(url, opts);
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!res.ok) {
      const err = new Error(data.error || `Management responded with ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  getInterface(name) { return this.request('GET', `/interfaces/${encodeURIComponent(name)}`); }
  addPeer(iface, data) { return this.request('POST', `/interfaces/${encodeURIComponent(iface)}/peers`, data); }
  removePeer(iface, pubkey) {
    return this.request('DELETE', `/interfaces/${encodeURIComponent(iface)}/peers/${encodeURIComponent(pubkey)}`);
  }
  getStatus(iface) { return this.request('GET', `/status/${encodeURIComponent(iface)}`); }
  getHandshakes(iface) { return this.request('GET', `/status/${encodeURIComponent(iface)}/handshakes`); }
  // Ask management to re-expand firewall rules whose src/dst reference these users,
  // because their peer IP set just changed.
  resyncUserFirewallRules(userIds) {
    return this.request('POST', `/firewall/resync-users`, { userIds });
  }
}

module.exports = AgentClient;
