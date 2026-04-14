const crypto = require('crypto');

/**
 * In-memory registry of connected WebSocket agents.
 * Maps serverId → WebSocket connection, handles request/response correlation.
 */
class WsAgentRegistry {
  constructor() {
    // serverId (int) → { ws, agentId, hostname, connectedAt, lastHeartbeat, heartbeatData }
    this.connections = new Map();
    // messageId (string) → { resolve, reject, timer, serverId }
    this.pending = new Map();
  }

  register(serverId, ws, meta = {}) {
    // Clean up old connection if exists
    this.unregister(serverId);
    this.connections.set(serverId, {
      ws,
      agentId: meta.agentId || null,
      hostname: meta.hostname || null,
      connectedAt: new Date(),
      lastHeartbeat: new Date(),
      heartbeatData: null,
    });
    console.log(`[wsRegistry] Agent registered: serverId=${serverId} agentId=${meta.agentId}`);
  }

  unregister(serverId) {
    const conn = this.connections.get(serverId);
    if (!conn) return;

    // Reject all pending commands for this server
    for (const [msgId, entry] of this.pending) {
      if (entry.serverId === serverId) {
        clearTimeout(entry.timer);
        entry.reject(new Error('Agent disconnected'));
        this.pending.delete(msgId);
      }
    }

    try { conn.ws.close(); } catch {}
    this.connections.delete(serverId);
    console.log(`[wsRegistry] Agent unregistered: serverId=${serverId}`);
  }

  isOnline(serverId) {
    const conn = this.connections.get(serverId);
    return conn != null && conn.ws.readyState === 1; // WebSocket.OPEN
  }

  getConnection(serverId) {
    return this.connections.get(serverId) || null;
  }

  getLastHeartbeat(serverId) {
    return this.connections.get(serverId)?.heartbeatData || null;
  }

  getAllOnlineServerIds() {
    const ids = [];
    for (const [id, conn] of this.connections) {
      if (conn.ws.readyState === 1) ids.push(id);
    }
    return ids;
  }

  /**
   * Send command to agent and wait for response.
   * @param {number} serverId
   * @param {string} type - Command type (e.g. 'listInterfaces')
   * @param {object} payload
   * @param {number} timeoutMs - Default 10000
   * @returns {Promise<object>} Response payload
   */
  sendCommand(serverId, type, payload = {}, timeoutMs = 10000) {
    return new Promise((resolve, reject) => {
      const conn = this.connections.get(serverId);
      if (!conn || conn.ws.readyState !== 1) {
        const err = new Error('Agent not connected');
        err.status = 503;
        return reject(err);
      }

      const id = crypto.randomUUID();
      const timer = setTimeout(() => {
        this.pending.delete(id);
        const err = new Error(`Command '${type}' timed out after ${timeoutMs}ms`);
        err.status = 504;
        reject(err);
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer, serverId });

      try {
        conn.ws.send(JSON.stringify({ type, id, payload }));
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err);
      }
    });
  }

  /**
   * Handle incoming message from agent.
   */
  handleMessage(serverId, rawData) {
    let msg;
    try {
      msg = JSON.parse(rawData);
    } catch {
      console.warn(`[wsRegistry] Invalid JSON from serverId=${serverId}`);
      return;
    }

    const { type, id, payload } = msg;

    // Response to a pending command
    if (type === 'response' && id && this.pending.has(id)) {
      const entry = this.pending.get(id);
      clearTimeout(entry.timer);
      this.pending.delete(id);
      entry.resolve(payload || {});
      return;
    }

    // Error response
    if (type === 'error' && id && this.pending.has(id)) {
      const entry = this.pending.get(id);
      clearTimeout(entry.timer);
      this.pending.delete(id);
      const err = new Error(payload?.error || 'Agent error');
      err.status = payload?.status || 500;
      entry.reject(err);
      return;
    }

    // Heartbeat from agent
    if (type === 'heartbeat') {
      const conn = this.connections.get(serverId);
      if (conn) {
        conn.lastHeartbeat = new Date();
        conn.heartbeatData = payload;
      }
      // Emit event for external handlers (subnet sync etc.)
      if (this.onHeartbeat) {
        this.onHeartbeat(serverId, payload);
      }
      return;
    }

    // Unknown message type with id — ignore silently
    if (id && this.pending.has(id)) {
      // Treat any message with matching id as response
      const entry = this.pending.get(id);
      clearTimeout(entry.timer);
      this.pending.delete(id);
      entry.resolve(payload || {});
    }
  }

  // Optional callback
  onHeartbeat = null;
}

// Singleton
const registry = new WsAgentRegistry();
module.exports = registry;
