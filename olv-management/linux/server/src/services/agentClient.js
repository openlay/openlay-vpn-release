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
  firewallGetPolicy() { return this.request('firewallGetPolicy'); }
  firewallSetPolicy(defaultPolicy) { return this.request('firewallSetPolicy', { defaultPolicy }); }
  firewallGetRules(iface) { return this.request('firewallGetRules', { iface }); }
  firewallGetAllRules() { return this.request('firewallGetAllRules'); }
  firewallListLive(iface) { return this.request('firewallListLive', { iface }); }
  firewallGetLogs(filter) { return this.request('firewallGetLogs', filter || {}, 15000); }
  firewallAddRule(iface, rule) { return this.request('firewallAddRule', { iface, rule }); }
  firewallRemoveRule(iface, ruleId) { return this.request('firewallRemoveRule', { iface, ruleId }); }
  firewallRemoveGroup(iface, groupId) { return this.request('firewallRemoveGroup', { iface, groupId }); }
  firewallListAllRules() { return this.request('firewallGetAllRules'); }
  firewallFlushRules(iface) { return this.request('firewallFlushRules', { iface }); }
  firewallBlockIP(iface, ip, direction) { return this.request('firewallBlockIP', { iface, ip, direction }); }
  firewallAllowIP(iface, ip, direction) { return this.request('firewallAllowIP', { iface, ip, direction }); }
  firewallBlockPort(iface, port, protocol) { return this.request('firewallBlockPort', { iface, port, protocol }); }
  firewallAllowPort(iface, port, protocol) { return this.request('firewallAllowPort', { iface, port, protocol }); }
  firewallBlockPeer(iface, peerIP) { return this.request('firewallBlockPeer', { iface, peerIP }); }
  firewallRateLimitPeer(iface, peerIP, rateKbps) { return this.request('firewallRateLimitPeer', { iface, peerIP, rateKbps }); }

  // Router — static routes (M1)
  routerListRoutes(iface) { return this.request('routerListRoutes', { iface }); }
  routerGetAllRoutes() { return this.request('routerGetAllRoutes'); }
  routerAddRoute(iface, route) { return this.request('routerAddRoute', { iface, route }); }
  routerUpdateRoute(iface, id, patch) { return this.request('routerUpdateRoute', { iface, id, patch }); }
  routerRemoveRoute(iface, id) { return this.request('routerRemoveRoute', { iface, id }); }
  routerEnableRoute(iface, id) { return this.request('routerEnableRoute', { iface, id }); }
  routerDisableRoute(iface, id) { return this.request('routerDisableRoute', { iface, id }); }
  routerFlushRoutes(iface) { return this.request('routerFlushRoutes', { iface }); }
  routerListLive(fib) { return this.request('routerListLive', { fib: fib || 0 }); }

  // Router — policy-based routing (M2)
  routerListPolicies() { return this.request('routerListPolicies'); }
  routerAddPolicy(policy) { return this.request('routerAddPolicy', { policy }); }
  routerUpdatePolicy(id, patch) { return this.request('routerUpdatePolicy', { id, patch }); }
  routerRemovePolicy(id) { return this.request('routerRemovePolicy', { id }); }
  routerEnablePolicy(id) { return this.request('routerEnablePolicy', { id }); }
  routerDisablePolicy(id) { return this.request('routerDisablePolicy', { id }); }
  routerGetFibInfo() { return this.request('routerGetFibInfo'); }
  routerListLivePolicies() { return this.request('routerListLivePolicies'); }

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
