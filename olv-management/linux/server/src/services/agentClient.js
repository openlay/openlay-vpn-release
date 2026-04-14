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
  firewallFlushRules(iface) { return this.request('firewallFlushRules', { iface }); }
  firewallBlockIP(iface, ip, direction) { return this.request('firewallBlockIP', { iface, ip, direction }); }
  firewallAllowIP(iface, ip, direction) { return this.request('firewallAllowIP', { iface, ip, direction }); }
  firewallBlockPort(iface, port, protocol) { return this.request('firewallBlockPort', { iface, port, protocol }); }
  firewallAllowPort(iface, port, protocol) { return this.request('firewallAllowPort', { iface, port, protocol }); }
  firewallBlockPeer(iface, peerIP) { return this.request('firewallBlockPeer', { iface, peerIP }); }
  firewallRateLimitPeer(iface, peerIP, rateKbps) { return this.request('firewallRateLimitPeer', { iface, peerIP, rateKbps }); }

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
