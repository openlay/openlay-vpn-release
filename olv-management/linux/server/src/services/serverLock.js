// Per-serverId async mutex. Serialises read-modify-write sequences against
// an agent's state (firewall rules, route policies) so concurrent triggers
// don't both `read state → mutate state` and lose each other's writes.
//
// The motivating bug (observed prod 2026-05-12): ruleOrchestrator.
// resyncRulesWhere does `firewallRemoveGroup(G) → firewallAddRule × N`
// per logical rule. Two concurrent resync triggers (e.g. two peers
// connecting in the same tick, each calling resyncRulesByUsers) both
// snapshot the agent state including group G, both queue the remove, the
// second remove finds the first rebuild's NEW groupId so it doesn't touch
// it, and both append their fresh rebuild on top. After enough churn the
// rule set accumulates dozens of identical groups (we saw 21 groupIds for
// one "Peer->wan" logical rule, 85 physical rules where 8 were expected).
//
// Re-entrancy: chained syncs from within an already-locked section
// (resyncRulesByUsers calls syncAppServersForUsers, syncWanAccessForUsers,
// syncExitNodeForUsers, resyncPoliciesByUsers — and each may want its own
// withServerLock guard so it's also safe when called directly) must NOT
// deadlock. AsyncLocalStorage tracks which serverIds the current async
// context already holds; a recursive acquire becomes a pass-through.
const { AsyncLocalStorage } = require('node:async_hooks');

const tails = new Map(); // serverId(string) → tail Promise
const held = new AsyncLocalStorage(); // Set<string> of serverIds held in current async ctx

async function withServerLock(serverId, fn) {
  const key = String(serverId);
  const current = held.getStore();
  if (current && current.has(key)) {
    // Already holding this server's lock further up the call chain;
    // re-entering is safe — the outer holder ordered the work.
    return fn();
  }

  const prev = tails.get(key) || Promise.resolve();
  let release;
  const tail = new Promise(r => { release = r; });
  tails.set(key, tail);

  try {
    // Wait for the prior holder. Swallow its rejection — caller already
    // saw it; we only need ordering, not error propagation.
    await prev.catch(() => {});
    const next = new Set(current || []);
    next.add(key);
    return await held.run(next, fn);
  } finally {
    release();
    // Best-effort GC: drop the entry only if no later caller queued
    // behind us. Keeps the map bounded under high-server-count load.
    if (tails.get(key) === tail) tails.delete(key);
  }
}

module.exports = { withServerLock };
