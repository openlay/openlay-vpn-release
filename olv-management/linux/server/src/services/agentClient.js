const registry = require('./wsAgentRegistry');

/**
 * Client to communicate with wireguard-agent-api instances via WebSocket.
 * No HTTPS fallback — agents connect to management via WebSocket only.
 */
class AgentClient {
  constructor(serverId) {
    this.serverId = serverId;
  }

  async request(type, payload = {}, timeoutMs = 10000) {
    return registry.sendCommand(this.serverId, type, payload, timeoutMs);
  }

  /**
   * Like request() but retries on transport-level failures (WS not
   * connected / command timed out). Only safe for commands the agent
   * handles idempotently — handler must either (a) be naturally
   * idempotent (read, remove-by-id, replaceGroup) or (b) dedup repeats
   * (addRule with content-equal guard). Do NOT use for addPeer /
   * createInterface — repeating those creates ghost state.
   *
   * Backoff: 500ms → 2s → 5s. Caps at `attempts` total tries. After the
   * final timeout the original error propagates.
   *
   * Why this exists: ena0 Tx stalls on EC2 (and the equivalent on any
   * cloud NIC) cause WS commands to time out at 10s even though the
   * agent processed the request and the response is in flight. Without
   * retry, callers like ruleOrchestrator silently abandon the rebuild
   * half-way and rules disappear (observed prod 2026-05-12).
   */
  async requestIdempotent(type, payload = {}, timeoutMs = 10000, attempts = 3) {
    const backoffs = [500, 2000, 5000];
    let lastErr;
    for (let i = 0; i < attempts; i++) {
      try {
        return await registry.sendCommand(this.serverId, type, payload, timeoutMs);
      } catch (err) {
        lastErr = err;
        // Only retry transport failures. Business errors (validation,
        // not-found, etc.) have no status or a 4xx status — those are
        // deterministic and re-sending won't help.
        if (err.status !== 503 && err.status !== 504) throw err;
        if (i === attempts - 1) break;
        const wait = backoffs[Math.min(i, backoffs.length - 1)];
        console.warn(`[AgentClient] ${type} on server=${this.serverId} ${err.status === 503 ? 'not connected' : 'timed out'} — retry ${i + 1}/${attempts - 1} in ${wait}ms`);
        await new Promise(r => setTimeout(r, wait));
      }
    }
    throw lastErr;
  }

  // Health
  health() { return this.request('health', {}, 5000); }
  healthFast() { return this.request('health', {}, 3000); }

  // Interfaces
  listInterfaces() { return this.request('listInterfaces'); }
  listInterfacesFast() { return this.request('listInterfaces', {}, 4000); }
  listAllInterfaces() { return this.request('listAllInterfaces', {}, 5000); }
  getInterface(name) { return this.request('getInterface', { name }); }
  getInterfaceFast(name) { return this.request('getInterface', { name }, 4000); }
  createInterface(data) { return this.request('createInterface', data); }
  deleteInterface(name) { return this.request('deleteInterface', { name }); }
  bringUp(name) { return this.request('bringUp', { name }); }
  bringDown(name) { return this.request('bringDown', { name }); }
  reloadInterface(name) { return this.request('reloadInterface', { name }); }
  setInterfaceAddresses(name, addresses) { return this.request('setInterfaceAddresses', { name, addresses }); }
  saveConfig(name) { return this.request('saveConfig', { name }); }

  // Peers
  listPeers(iface) { return this.request('listPeers', { iface }); }
  // Internal-only — returns PSK as plaintext. Used by migrate; never
  // surface via user-facing route.
  listPeersWithSecrets(iface) { return this.request('listPeersWithSecrets', { iface }); }
  addPeer(iface, data) { return this.request('addPeer', { iface, ...data }); }
  getPeer(iface, pubkey) { return this.request('getPeer', { iface, pubkey }); }
  updatePeer(iface, pubkey, data) { return this.request('updatePeer', { iface, pubkey, ...data }); }
  removePeer(iface, pubkey) { return this.request('removePeer', { iface, pubkey }); }
  enablePeer(iface, pubkey) { return this.request('enablePeer', { iface, pubkey }); }
  disablePeer(iface, pubkey) { return this.request('disablePeer', { iface, pubkey }); }
  renamePeerAlias(iface, pubkey, alias) { return this.request('renamePeerAlias', { iface, pubkey, alias }); }
  rotatePeerKeys(iface, pubkey) { return this.request('rotatePeerKeys', { iface, pubkey }); }
  setPeerEndpoint(iface, pubkey, endpoint) { return this.request('setPeerEndpoint', { iface, pubkey, endpoint }); }
  setPeerAllowedIPs(iface, pubkey, allowedIPs) { return this.request('setPeerAllowedIPs', { iface, pubkey, allowedIPs }); }
  setPeerKeepalive(iface, pubkey, seconds) { return this.request('setPeerKeepalive', { iface, pubkey, seconds }); }

  // Status
  getStatus(iface) { return this.request('getStatus', { iface }); }
  getConnected(iface, activeWithinSeconds) { return this.request('getConnected', { iface, activeWithinSeconds }); }
  getConnectedFast(iface) { return this.request('getConnected', { iface }, 4000); }
  getTransfer(iface) { return this.request('getTransfer', { iface }); }
  getHandshakes(iface) { return this.request('getHandshakes', { iface }); }
  getPeerStatus(iface, pubkey) { return this.request('getPeerStatus', { iface, pubkey }); }
  getPeerTransfer(iface, pubkey) { return this.request('getPeerTransfer', { iface, pubkey }); }
  getAuditLogs(limit, offset) { return this.request('getAuditLogs', { limit, offset }); }

  // Firewall — Layer 3/4
  //
  // All firewall RPCs go through requestIdempotent: reads are pure;
  // mutations are idempotent at the agent (addRule has content-dedup,
  // removeRule/removeGroup are no-op when target is gone, replaceGroup
  // is a whole-group swap with deterministic output, flushRules
  // converges to empty).
  firewallGetPolicy() { return this.requestIdempotent('firewallGetPolicy'); }
  firewallSetPolicy(defaultPolicy) { return this.requestIdempotent('firewallSetPolicy', { defaultPolicy }); }
  firewallGetRules(iface) { return this.requestIdempotent('firewallGetRules', { iface }); }
  firewallGetAllRules() { return this.requestIdempotent('firewallGetAllRules'); }
  firewallListLive(iface) { return this.requestIdempotent('firewallListLive', { iface }); }
  firewallGetLogs(filter) { return this.requestIdempotent('firewallGetLogs', filter || {}, 15000); }
  firewallAddRule(iface, rule) { return this.requestIdempotent('firewallAddRule', { iface, rule }); }
  firewallRemoveRule(iface, ruleId) { return this.requestIdempotent('firewallRemoveRule', { iface, ruleId }); }
  firewallRemoveGroup(iface, groupId) { return this.requestIdempotent('firewallRemoveGroup', { iface, groupId }); }
  // Atomically swap every rule in `groupId` for the provided list. Single
  // RPC — agent holds Store.mu across load+filter+save+rebuild, so a WS
  // timeout either commits the whole change or leaves the prior state
  // untouched. Use this instead of removeGroup+addRule×N for any rebuild
  // (resync, app-server sync, wan-access sync) where partial commit
  // would lose rules.
  firewallReplaceGroup(iface, groupId, rules) {
    return this.requestIdempotent('firewallReplaceGroup', { iface, groupId, rules });
  }
  firewallListAllRules() { return this.requestIdempotent('firewallGetAllRules'); }
  firewallFlushRules(iface) { return this.requestIdempotent('firewallFlushRules', { iface }); }
  // Convenience wrappers — block/allow IP/port/peer are server-side
  // sugar over addRule on the agent (same dedup), so retrying is safe.
  firewallBlockIP(iface, ip, direction) { return this.requestIdempotent('firewallBlockIP', { iface, ip, direction }); }
  firewallAllowIP(iface, ip, direction) { return this.requestIdempotent('firewallAllowIP', { iface, ip, direction }); }
  firewallBlockPort(iface, port, protocol) { return this.requestIdempotent('firewallBlockPort', { iface, port, protocol }); }
  firewallAllowPort(iface, port, protocol) { return this.requestIdempotent('firewallAllowPort', { iface, port, protocol }); }
  firewallBlockPeer(iface, peerIP) { return this.requestIdempotent('firewallBlockPeer', { iface, peerIP }); }
  firewallRateLimitPeer(iface, peerIP, rateKbps) { return this.requestIdempotent('firewallRateLimitPeer', { iface, peerIP, rateKbps }); }

  // Router — static routes (M1). Reads + set-shaped mutations are all
  // idempotent at the agent.
  routerListRoutes(iface) { return this.requestIdempotent('routerListRoutes', { iface }); }
  routerGetAllRoutes() { return this.requestIdempotent('routerGetAllRoutes'); }
  routerAddRoute(iface, route) { return this.requestIdempotent('routerAddRoute', { iface, route }); }
  routerUpdateRoute(iface, id, patch) { return this.requestIdempotent('routerUpdateRoute', { iface, id, patch }); }
  routerRemoveRoute(iface, id) { return this.requestIdempotent('routerRemoveRoute', { iface, id }); }
  routerEnableRoute(iface, id) { return this.requestIdempotent('routerEnableRoute', { iface, id }); }
  routerDisableRoute(iface, id) { return this.requestIdempotent('routerDisableRoute', { iface, id }); }
  routerFlushRoutes(iface) { return this.requestIdempotent('routerFlushRoutes', { iface }); }
  routerListLive(fib) { return this.requestIdempotent('routerListLive', { fib: fib || 0 }); }

  // Router — policy-based routing (M2)
  routerListPolicies() { return this.requestIdempotent('routerListPolicies'); }
  routerAddPolicy(policy) { return this.requestIdempotent('routerAddPolicy', { policy }); }
  routerUpdatePolicy(id, patch) { return this.requestIdempotent('routerUpdatePolicy', { id, patch }); }
  routerRemovePolicy(id) { return this.requestIdempotent('routerRemovePolicy', { id }); }
  routerEnablePolicy(id) { return this.requestIdempotent('routerEnablePolicy', { id }); }
  routerDisablePolicy(id) { return this.requestIdempotent('routerDisablePolicy', { id }); }
  routerGetFibInfo() { return this.requestIdempotent('routerGetFibInfo'); }
  routerListLivePolicies() { return this.requestIdempotent('routerListLivePolicies'); }

  // NAT — SNAT (M3)
  natListRules() { return this.request('natListRules'); }
  natAddRule(rule) { return this.request('natAddRule', { rule }); }
  natUpdateRule(id, patch) { return this.request('natUpdateRule', { id, patch }); }
  natRemoveRule(id) { return this.request('natRemoveRule', { id }); }
  natEnableRule(id) { return this.request('natEnableRule', { id }); }
  natDisableRule(id) { return this.request('natDisableRule', { id }); }
  natListLive(wanIface) { return this.request('natListLive', { wanIface }); }
  natRebuild() { return this.request('natRebuild'); }

  // NAT — DNAT / port-forward (M3)
  rdrListRules() { return this.request('rdrListRules'); }
  rdrAddRule(rule) { return this.request('rdrAddRule', { rule }); }
  rdrUpdateRule(id, patch) { return this.request('rdrUpdateRule', { id, patch }); }
  rdrRemoveRule(id) { return this.request('rdrRemoveRule', { id }); }
  rdrEnableRule(id) { return this.request('rdrEnableRule', { id }); }
  rdrDisableRule(id) { return this.request('rdrDisableRule', { id }); }

  // DNS Filtering — Layer 7
  dnsEnable(iface) { return this.request('dnsEnable', { iface }); }
  dnsDisable(iface) { return this.request('dnsDisable', { iface }); }
  dnsBlockDomain(iface, domain) { return this.request('dnsBlockDomain', { iface, domain }); }
  dnsUnblockDomain(iface, domain) { return this.request('dnsUnblockDomain', { iface, domain }); }
  dnsListBlocked(iface) { return this.request('dnsListBlocked', { iface }); }
  dnsEnableCategory(iface, category) { return this.request('dnsEnableCategory', { iface, category }); }
  dnsDisableCategory(iface, category) { return this.request('dnsDisableCategory', { iface, category }); }
  dnsListCategories() { return this.request('dnsListCategories'); }
  dnsGetStats() { return this.request('dnsGetStats'); }
}

module.exports = AgentClient;
