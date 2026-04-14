const WebSocket = require('ws');
const url = require('url');
const { pool } = require('../db/pool');
const config = require('../config');
const registry = require('./wsAgentRegistry');
const { syncSubnets } = require('./subnetSync');
const caManager = require('./caManager');

const PING_INTERVAL = 30000; // 30s
const PONG_TIMEOUT = 10000;  // 10s

/**
 * Attach WebSocket server to existing HTTPS server.
 * Agents connect via:
 *   1. Client certificate (mutual TLS) — preferred, no query params needed
 *   2. Token query param — legacy/fallback: wss://host/ws/agent?token=xxx
 */
function attachWebSocketServer(httpsServer) {
  const wss = new WebSocket.Server({
    server: httpsServer,
    path: '/ws/agent',
    verifyClient: (info, cb) => {
      const parsed = url.parse(info.req.url, true);

      // Method 1: Client certificate (mutual TLS)
      const peerCert = info.req.socket.getPeerCertificate?.(true);
      if (peerCert && peerCert.raw) {
        // Client presented a cert — verify it was signed by our CA
        const certPem = '-----BEGIN CERTIFICATE-----\n' +
          peerCert.raw.toString('base64').match(/.{1,64}/g).join('\n') +
          '\n-----END CERTIFICATE-----';
        const result = caManager.verifyCert(certPem);
        if (result.valid) {
          // Store verified info on request for later use
          info.req._agentCertAuth = {
            agentId: result.agentId,
            fingerprint: result.fingerprint,
          };
          console.log(`[wsServer] Client cert auth: agentId=${result.agentId}`);
          cb(true);
          return;
        }
        console.log('[wsServer] Client cert invalid — trying token fallback');
      }

      // Method 2: Token query param (legacy)
      const token = parsed.query.token;
      const expectedToken = config.managementApiToken;

      if (expectedToken && token === expectedToken) {
        cb(true);
        return;
      }

      console.log('[wsServer] Rejected connection: no valid cert or token');
      cb(false, 401, 'Unauthorized');
    },
  });

  wss.on('connection', async (ws, req) => {
    const ip = req.socket.remoteAddress;
    console.log(`[wsServer] New WebSocket connection from ${ip}`);

    let serverId = null;
    let pingTimer = null;
    let pongReceived = true;

    // If client cert auth succeeded, auto-identify without hello
    if (req._agentCertAuth) {
      const { agentId, fingerprint } = req._agentCertAuth;

      // Check cert not revoked
      const revoked = await caManager.isRevoked(fingerprint);
      if (revoked) {
        console.log(`[wsServer] Cert revoked for agentId=${agentId}`);
        ws.close(4001, 'Certificate revoked');
        return;
      }

      try {
        const { rows } = await pool.query(
          'SELECT id FROM servers WHERE instance_id = $1', [agentId]
        );
        if (rows.length > 0) {
          serverId = rows[0].id;
          registry.register(serverId, ws, { agentId, hostname: '' });
          // Update public_ip from WebSocket remote address (strip IPv6 prefix)
          const remoteIp = (ip || '').replace(/^::ffff:/, '');
          await pool.query(
            'UPDATE servers SET updated_at = NOW(), public_ip = COALESCE(NULLIF($2, \'\'), public_ip) WHERE id = $1',
            [serverId, remoteIp]
          );
          ws.send(JSON.stringify({ type: 'welcome', id: null, payload: { serverId, auth: 'cert' } }));
          console.log(`[wsServer] Agent identified via cert: serverId=${serverId} agentId=${agentId} remoteIp=${remoteIp}`);

          // Start keepalive
          pingTimer = setInterval(() => {
            if (!pongReceived) { ws.terminate(); return; }
            pongReceived = false;
            ws.ping();
          }, PING_INTERVAL);
        } else {
          console.log(`[wsServer] Cert valid but agent not in DB: ${agentId}`);
          ws.close(4002, 'Agent not registered');
          return;
        }
      } catch (err) {
        console.error('[wsServer] DB error during cert auth:', err.message);
        ws.close();
        return;
      }
    }

    // Wait for hello message (token-based auth fallback)
    const helloTimeout = !serverId ? setTimeout(() => {
      if (!serverId) {
        console.log('[wsServer] No hello received within 10s, closing');
        ws.close();
      }
    }, 10000) : null;

    ws.on('message', async (rawData) => {
      // First message must be hello (only for token-based auth)
      if (!serverId) {
        let msg;
        try { msg = JSON.parse(rawData); } catch { ws.close(); return; }

        if (msg.type !== 'hello' || !msg.payload?.agentId) {
          console.log('[wsServer] First message must be hello with agentId');
          ws.close();
          return;
        }

        if (helloTimeout) clearTimeout(helloTimeout);
        const agentId = msg.payload.agentId;
        const hostname = msg.payload.hostname || '';

        // Lookup server by instance_id (agentId)
        try {
          const { rows } = await pool.query(
            'SELECT id FROM servers WHERE instance_id = $1',
            [agentId]
          );
          if (rows.length === 0) {
            console.log(`[wsServer] Unknown agent: ${agentId} — must register via HTTPS first`);
            ws.send(JSON.stringify({ type: 'error', id: null, payload: { error: 'Not registered. POST /api/agents/register first.' } }));
            ws.close();
            return;
          }

          serverId = rows[0].id;
          const remoteIp = req.socket.remoteAddress || '';
          registry.register(serverId, ws, { agentId, hostname });

          // Update server status + public IP from hello
          const publicIp = msg.payload.publicIp || '';
          console.log(`[wsServer] Agent hello: serverId=${serverId} remoteIp=${remoteIp} publicIp=${publicIp || '(not sent)'}`);
          if (publicIp) {
            await pool.query('UPDATE servers SET public_ip = $1, updated_at = NOW() WHERE id = $2', [publicIp, serverId]);
          } else {
            await pool.query('UPDATE servers SET updated_at = NOW() WHERE id = $1', [serverId]);
          }

          // Start ping/pong keepalive
          pingTimer = setInterval(() => {
            if (!pongReceived) {
              console.log(`[wsServer] No pong from serverId=${serverId}, closing`);
              ws.terminate();
              return;
            }
            pongReceived = false;
            ws.ping();
          }, PING_INTERVAL);

          ws.send(JSON.stringify({ type: 'welcome', id: null, payload: { serverId } }));
          console.log(`[wsServer] Agent identified: serverId=${serverId} agentId=${agentId}`);
        } catch (err) {
          console.error('[wsServer] DB error during hello:', err.message);
          ws.close();
        }
        return;
      }

      // Subsequent messages — route through registry
      registry.handleMessage(serverId, rawData.toString());
    });

    ws.on('pong', () => {
      pongReceived = true;
    });

    ws.on('close', () => {
      if (helloTimeout) clearTimeout(helloTimeout);
      if (pingTimer) clearInterval(pingTimer);
      if (serverId) {
        registry.unregister(serverId);
        console.log(`[wsServer] Connection closed: serverId=${serverId}`);
      }
    });

    ws.on('error', (err) => {
      console.error(`[wsServer] Error serverId=${serverId}:`, err.message);
    });
  });

  // Handle heartbeat events — sync subnets
  registry.onHeartbeat = async (serverId, payload) => {
    try {
      if (payload?.interfaces) {
        await syncSubnets(serverId, payload.interfaces);
      }
      const publicIp = payload?.publicIp || '';
      if (publicIp) {
        await pool.query('UPDATE servers SET public_ip = $1, updated_at = NOW() WHERE id = $2', [publicIp, serverId]);
      } else {
        await pool.query('UPDATE servers SET updated_at = NOW() WHERE id = $1', [serverId]);
      }
    } catch (err) {
      console.error(`[wsServer] Heartbeat processing error serverId=${serverId}:`, err.message);
    }
  };

  console.log('[wsServer] WebSocket server attached at /ws/agent');
  return wss;
}

module.exports = { attachWebSocketServer };
