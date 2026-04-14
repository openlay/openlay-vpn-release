// Agent operations proxied through management server (via WebSocket internally)
// App-API no longer calls agents directly — management handles the WebSocket connection.

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const config = require('../config');

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
}

module.exports = AgentClient;
