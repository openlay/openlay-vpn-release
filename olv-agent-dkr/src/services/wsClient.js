const WebSocket = require('ws');
const fs = require('fs');
const os = require('os');
const config = require('../config');
const { execute } = require('./commandHandler');
const wgService = require('./wireguard');
const { fetchPublicIp } = require('./registration');

const HEARTBEAT_INTERVAL = (config.heartbeatInterval || 30) * 1000;
const RECONNECT_BASE = 1000;
const RECONNECT_MAX = 30000;

class WsClient {
  constructor() {
    this.ws = null;
    this.agentId = null;
    this.wsUrl = null;
    this.token = null;
    this.reconnectDelay = RECONNECT_BASE;
    this.reconnectTimer = null;
    this.heartbeatTimer = null;
    this.closing = false;
  }

  /**
   * Connect to management WebSocket.
   * @param {string} wsUrl — wss://host:port/ws/agent
   * @param {string} token — management API token
   * @param {string} agentId — agent instance ID
   */
  connect(wsUrl, token, agentId) {
    this.wsUrl = wsUrl;
    this.token = token;
    this.agentId = agentId;
    this.closing = false;
    this._connect();
  }

  /**
   * Set client certificate for mutual TLS.
   * @param {{ cert: string, key: string, ca: string }} certPaths
   */
  setClientCert(certPaths) {
    this.certPaths = certPaths;
  }

  _connect() {
    if (this.closing) return;

    // Build URL — use cert auth if available, fallback to token
    let url;
    if (this.certPaths) {
      url = this.wsUrl; // No token needed — cert auth
    } else {
      url = `${this.wsUrl}?token=${encodeURIComponent(this.token)}`;
    }

    // TLS options
    const wsOptions = {};

    // Client certificate (mutual TLS) — for agent identity
    if (this.certPaths) {
      try {
        wsOptions.cert = fs.readFileSync(this.certPaths.cert);
        wsOptions.key = fs.readFileSync(this.certPaths.key);
        console.log('[wsClient] Using client certificate for auth');
      } catch (err) {
        console.warn(`[wsClient] Failed to load client cert: ${err.message}`);
      }
    }

    // Server TLS verification
    // Management server uses self-signed TLS cert — always accept
    // Agent cert (mTLS) is verified by management, not the other way around
    wsOptions.rejectUnauthorized = false;

    console.log(`[wsClient] Connecting to ${this.wsUrl}...`);
    this.ws = new WebSocket(url, { ...wsOptions });

    this.ws.on('open', async () => {
      console.log(`[wsClient] Connected to management server`);
      this.reconnectDelay = RECONNECT_BASE;

      // Send hello with public IP
      let publicIp = '';
      try { publicIp = await fetchPublicIp(); } catch { /* ignore */ }
      this._send({
        type: 'hello',
        id: null,
        payload: {
          agentId: this.agentId,
          hostname: os.hostname(),
          publicIp,
        },
      });

      // Start heartbeat
      this._startHeartbeat();
    });

    this.ws.on('message', async (rawData) => {
      let msg;
      try {
        msg = JSON.parse(rawData.toString());
      } catch {
        console.warn('[wsClient] Received invalid JSON');
        return;
      }

      const { type, id, payload } = msg;

      // Welcome from server
      if (type === 'welcome') {
        console.log(`[wsClient] Server acknowledged: serverId=${payload?.serverId}`);
        return;
      }

      // Error from server (no correlation)
      if (type === 'error' && !id) {
        console.error(`[wsClient] Server error: ${payload?.error}`);
        return;
      }

      // Command from management — execute and respond
      if (type && id) {
        try {
          const result = await execute(type, payload || {});
          this._send({ type: 'response', id, payload: result });
        } catch (err) {
          this._send({
            type: 'error',
            id,
            payload: { error: err.message, status: err.status || 500 },
          });
        }
      }
    });

    this.ws.on('close', (code, reason) => {
      console.log(`[wsClient] Connection closed: code=${code}`);
      this._stopHeartbeat();
      this._scheduleReconnect();
    });

    this.ws.on('error', (err) => {
      console.error(`[wsClient] Error: ${err.message}`);
      // close event will fire after this
    });

    this.ws.on('ping', () => {
      // Auto-pong is handled by ws library
    });
  }

  _send(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  _startHeartbeat() {
    this._stopHeartbeat();
    this.heartbeatTimer = setInterval(async () => {
      try {
        const interfaces = await wgService.listInterfaces();
        const ifaceDetails = [];
        for (const name of interfaces) {
          try {
            const info = await wgService.getInterface(name);
            ifaceDetails.push({ name, address: info.address });
          } catch {}
        }

        let publicIp = '';
        try { publicIp = await fetchPublicIp(); } catch { /* ignore */ }
        this._send({
          type: 'heartbeat',
          id: null,
          payload: {
            agentId: this.agentId,
            hostname: os.hostname(),
            publicIp,
            uptime: process.uptime(),
            platform: process.platform,
            arch: process.arch,
            timestamp: new Date().toISOString(),
            interfaces: ifaceDetails,
          },
        });
      } catch (err) {
        console.warn(`[wsClient] Heartbeat error: ${err.message}`);
      }
    }, HEARTBEAT_INTERVAL);
  }

  _stopHeartbeat() {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  _scheduleReconnect() {
    if (this.closing) return;
    if (this.reconnectTimer) return;

    console.log(`[wsClient] Reconnecting in ${this.reconnectDelay / 1000}s...`);
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this._connect();
    }, this.reconnectDelay);

    // Exponential backoff
    this.reconnectDelay = Math.min(this.reconnectDelay * 2, RECONNECT_MAX);
  }

  /**
   * Graceful close.
   */
  close() {
    this.closing = true;
    this._stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this._send({ type: 'goodbye', id: null, payload: { agentId: this.agentId } });
      this.ws.close();
      this.ws = null;
    }
    console.log('[wsClient] Closed');
  }
}

module.exports = new WsClient();
