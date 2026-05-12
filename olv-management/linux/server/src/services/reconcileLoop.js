// Periodic reconciliation of agent state against management's source of
// truth. Belt-and-suspenders: the read-modify-write paths in
// ruleOrchestrator + appServerFirewall + deviceWanAccessFirewall are
// already serialized (serverLock) and atomic (firewallReplaceGroup), so
// in steady state nothing should drift. This loop catches three classes
// of drift those mechanisms can't:
//
//   1. Manual edits to the agent's on-disk JSON (operator inspecting a
//      bug, partial recovery from a backup, etc.).
//   2. Agent restarts where pf state didn't replay cleanly.
//   3. Bugs we haven't found yet — periodic forced convergence beats
//      "discover drift in production days later".
//
// Per server: re-run zone + alias resync (covers user-managed firewall
// rules whose IPs come from zone/alias membership) and app-server
// firewall sync (covers app-managed ACL rules). Wan-access + exit-node
// rules are re-converged via the chain inside resyncRulesByUsers — but
// we don't trigger that here because the user-IP set hasn't changed;
// the on-reconnect path in wsServer already covers those.

const { pool } = require('../db/pool');
const registry = require('./wsAgentRegistry');

// Default 30 min. Set RECONCILE_INTERVAL_MS=0 to disable entirely.
const DEFAULT_INTERVAL_MS = 30 * 60 * 1000;

async function reconcileServer(serverId) {
  // Lazy-require to avoid a load-order cycle: reconcileLoop is started
  // from index.js before all services are wired.
  const { resyncRulesByZone, resyncRulesByAlias } = require('./ruleOrchestrator');
  const { syncAppServerFirewall } = require('./appServerFirewall');

  const stats = { zones: 0, aliases: 0, apps: 0, errors: 0 };

  try {
    const { rows } = await pool.query(
      'SELECT id FROM firewall_zones WHERE server_id = $1',
      [serverId]
    );
    for (const z of rows) {
      try { await resyncRulesByZone(serverId, z.id); stats.zones++; }
      catch (err) {
        stats.errors++;
        console.error(`[reconcileLoop] zone=${z.id} server=${serverId}: ${err.message}`);
      }
    }
  } catch (err) {
    stats.errors++;
    console.error(`[reconcileLoop] list zones server=${serverId}: ${err.message}`);
  }

  try {
    const { rows } = await pool.query(
      'SELECT id FROM firewall_aliases WHERE server_id = $1',
      [serverId]
    );
    for (const a of rows) {
      try { await resyncRulesByAlias(serverId, a.id); stats.aliases++; }
      catch (err) {
        stats.errors++;
        console.error(`[reconcileLoop] alias=${a.id} server=${serverId}: ${err.message}`);
      }
    }
  } catch (err) {
    stats.errors++;
    console.error(`[reconcileLoop] list aliases server=${serverId}: ${err.message}`);
  }

  try {
    const { rows } = await pool.query(
      'SELECT id FROM application_servers WHERE server_id = $1 AND enabled = TRUE',
      [serverId]
    );
    for (const app of rows) {
      try { await syncAppServerFirewall(app.id); stats.apps++; }
      catch (err) {
        stats.errors++;
        console.error(`[reconcileLoop] app=${app.id} server=${serverId}: ${err.message}`);
      }
    }
  } catch (err) {
    stats.errors++;
    console.error(`[reconcileLoop] list apps server=${serverId}: ${err.message}`);
  }

  return stats;
}

async function reconcileAll() {
  const onlineIds = registry.getAllOnlineServerIds();
  if (onlineIds.length === 0) return;
  for (const serverId of onlineIds) {
    try {
      const stats = await reconcileServer(serverId);
      // Only log when something happened or something failed — quiet
      // success keeps prod logs readable.
      if (stats.errors > 0) {
        console.warn(`[reconcileLoop] server=${serverId} zones=${stats.zones} aliases=${stats.aliases} apps=${stats.apps} errors=${stats.errors}`);
      }
    } catch (err) {
      console.error(`[reconcileLoop] server=${serverId} fatal: ${err.message}`);
    }
  }
}

function start(intervalMs) {
  const ms = intervalMs ?? (process.env.RECONCILE_INTERVAL_MS != null
    ? parseInt(process.env.RECONCILE_INTERVAL_MS, 10)
    : DEFAULT_INTERVAL_MS);
  if (!Number.isFinite(ms) || ms <= 0) {
    console.log('[reconcileLoop] disabled (RECONCILE_INTERVAL_MS=0)');
    return null;
  }
  console.log(`[reconcileLoop] enabled — every ${Math.round(ms / 60000)} min`);
  // Run after a short delay so we don't fight the on-reconnect reconcile
  // that wsServer fires right when an agent connects.
  return setInterval(reconcileAll, ms);
}

module.exports = { start, reconcileServer, reconcileAll };
