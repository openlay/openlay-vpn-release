const { pool } = require('../db/pool');
const AgentClient = require('./agentClient');

/**
 * Check for expired peers and disable them on the agent.
 * Runs periodically from the server index.
 */
async function checkExpiredPeers() {
  try {
    // Find expired peers that haven't been marked yet
    const { rows: expiredPeers } = await pool.query(
      `SELECT pm.*, s.url, s.api_token
       FROM peers_meta pm
       JOIN servers s ON pm.server_id = s.id
       WHERE pm.expires_at IS NOT NULL
         AND pm.expires_at <= NOW()
         AND pm.is_expired = FALSE`
    );

    // Common case: no peers expire this tick → return fast, zero agent calls.
    if (expiredPeers.length === 0) return;

    // Track which (server_id → user_id) pairs need a downstream resync.
    // We batch by server so multiple expiring peers on the same server
    // collapse into a single resyncRulesByUsers call (which itself
    // chains to policy + app-server resync, all with diff-skip).
    const usersToResyncByServer = new Map();

    for (const peer of expiredPeers) {
      try {
        const client = new AgentClient(peer.server_id);
        // Disable peer on agent (remove from running config but keep in .conf)
        await client.disablePeer(peer.interface_name, peer.public_key);
        console.log(`[EXPIRY] Disabled expired peer ${peer.alias || peer.public_key.substring(0, 12)} on ${peer.interface_name}`);
      } catch (err) {
        console.error(`[EXPIRY] Failed to disable peer ${peer.public_key.substring(0, 12)}: ${err.message}`);
      }

      // Mark as expired in local DB regardless (so we don't retry endlessly)
      await pool.query(
        'UPDATE peers_meta SET is_expired = TRUE WHERE id = $1',
        [peer.id]
      );

      if (peer.user_id) {
        if (!usersToResyncByServer.has(peer.server_id)) {
          usersToResyncByServer.set(peer.server_id, new Set());
        }
        usersToResyncByServer.get(peer.server_id).add(peer.user_id);
      }
    }

    console.log(`[EXPIRY] Processed ${expiredPeers.length} expired peer(s), resyncing ${usersToResyncByServer.size} server(s)`);

    // Fan out resync per server. Each call chains: firewall →
    // policies → app-server rules. Diff-skip cheap when nothing
    // resolves differently (rare here — expiry just dropped peers).
    // Lazy-require to avoid a load-time cycle through ruleOrchestrator.
    const { resyncRulesByUsers } = require('./ruleOrchestrator');
    for (const [serverId, userSet] of usersToResyncByServer) {
      try {
        await resyncRulesByUsers(serverId, [...userSet]);
      } catch (err) {
        console.error(`[EXPIRY] resync server=${serverId} failed: ${err.message}`);
      }
    }
  } catch (err) {
    console.error('[EXPIRY] Check failed:', err.message);
  }
}

/**
 * Start the periodic expiry checker.
 * @param {number} intervalMs - Check interval in milliseconds (default: 60s)
 */
function startExpiryChecker(intervalMs = 60000) {
  console.log(`[EXPIRY] Checker started (interval: ${intervalMs / 1000}s)`);
  // Run immediately once, then on interval
  checkExpiredPeers();
  return setInterval(checkExpiredPeers, intervalMs);
}

module.exports = { checkExpiredPeers, startExpiryChecker };
