const wgService = require('./wireguard');
const firewall = require('./firewall');
const dnsFilter = require('./dnsFilter');
const audit = require('./audit');
const os = require('os');
const { spawn } = require('child_process');
const pkg = require('../../package.json');

/**
 * Dispatch WebSocket commands to existing WireGuard service functions.
 * Each handler receives payload object and returns result object.
 */
const handlers = {
  // Health
  async health() {
    return {
      status: 'ok',
      version: pkg.version,
      hostname: os.hostname(),
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    };
  },

  // System stats: CPU, RAM, Network
  async systemStats() {
    const cpus = os.cpus();
    const cpuCount = cpus.length;
    const cpuModel = cpus[0]?.model || 'Unknown';

    // CPU usage (compute over a 200ms window)
    const cpuUsage = await measureCpuUsage();

    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const usedMem = totalMem - freeMem;

    const loadavg = os.loadavg();

    // Network interfaces — sum bytes from /proc/net/dev (Linux only)
    const network = await readNetworkStats();

    return {
      cpu: {
        count: cpuCount,
        model: cpuModel,
        usagePercent: cpuUsage,
        loadavg: { one: loadavg[0], five: loadavg[1], fifteen: loadavg[2] },
      },
      memory: {
        total: totalMem,
        used: usedMem,
        free: freeMem,
        usagePercent: Math.round((usedMem / totalMem) * 100),
      },
      network,
      uptime: os.uptime(),
      timestamp: new Date().toISOString(),
    };
  },

  // Self-update: pull latest release and rebuild Docker container
  async update() {
    const child = spawn('bash', ['-c',
      'cd /opt/openlay-vpn-release && git pull && cd olv-agent-dkr && bash update.sh'
    ], { detached: true, stdio: 'ignore' });
    child.unref();
    audit.log('update', { pid: child.pid });
    return { ok: true, message: 'Agent update started. Container will restart shortly.' };
  },

  // Interfaces
  async listInterfaces() {
    return { interfaces: await wgService.listInterfaces() };
  },

  async getInterface({ name }) {
    return await wgService.getInterface(name);
  },

  async createInterface({ name, listenPort, port, address, addressV6, mtu, dns }) {
    const result = await wgService.createInterface(name, listenPort || port, address, {
      addressV6, mtu, dns,
    });
    audit.log('createInterface', { name });
    return result;
  },

  async deleteInterface({ name }) {
    await wgService.deleteInterface(name);
    audit.log('deleteInterface', { name });
    return { ok: true };
  },

  async bringUp({ name }) {
    await wgService.bringUpInterface(name);
    audit.log('bringUp', { name });
    return { ok: true };
  },

  async bringDown({ name }) {
    await wgService.bringDownInterface(name);
    audit.log('bringDown', { name });
    return { ok: true };
  },

  async reloadInterface({ name }) {
    await wgService.reloadInterface(name);
    audit.log('reloadInterface', { name });
    return { ok: true };
  },

  async setInterfaceAddresses({ name, addresses }) {
    const result = await wgService.setInterfaceAddresses(name, addresses);
    audit.log('setInterfaceAddresses', { name, addresses });
    return result;
  },

  async saveConfig({ name }) {
    await wgService.saveRunningConfig(name);
    audit.log('saveConfig', { name });
    return { ok: true };
  },

  // Peers
  async listPeers({ iface }) {
    return { peers: await wgService.listPeers(iface) };
  },

  async addPeer({ iface, publicKey, allowedIPs, presharedKey, endpoint, persistentKeepalive, alias }) {
    const result = await wgService.addPeer(iface, publicKey, allowedIPs, {
      presharedKey, endpoint, persistentKeepalive, alias,
    });
    audit.log('addPeer', { iface, publicKey });
    return result;
  },

  async getPeer({ iface, pubkey }) {
    return await wgService.getPeer(iface, pubkey);
  },

  async updatePeer({ iface, pubkey, ...data }) {
    const result = await wgService.updatePeer(iface, pubkey, data);
    audit.log('updatePeer', { iface, pubkey });
    return result;
  },

  async removePeer({ iface, pubkey }) {
    await wgService.removePeer(iface, pubkey);
    audit.log('removePeer', { iface, pubkey });
    return { ok: true };
  },

  async enablePeer({ iface, pubkey }) {
    await wgService.enablePeer(iface, pubkey);
    audit.log('enablePeer', { iface, pubkey });
    return { ok: true };
  },

  async disablePeer({ iface, pubkey }) {
    await wgService.disablePeer(iface, pubkey);
    audit.log('disablePeer', { iface, pubkey });
    return { ok: true };
  },

  async renamePeerAlias({ iface, pubkey, alias }) {
    await wgService.renamePeerAlias(iface, pubkey, alias);
    audit.log('renamePeerAlias', { iface, pubkey, alias });
    return { ok: true };
  },

  async rotatePeerKeys({ iface, pubkey }) {
    const result = await wgService.rotatePeerKeys(iface, pubkey);
    audit.log('rotatePeerKeys', { iface, pubkey });
    return result;
  },

  async setPeerEndpoint({ iface, pubkey, endpoint }) {
    await wgService.setPeerEndpoint(iface, pubkey, endpoint);
    audit.log('setPeerEndpoint', { iface, pubkey, endpoint });
    return { ok: true };
  },

  async setPeerAllowedIPs({ iface, pubkey, allowedIPs }) {
    await wgService.setPeerAllowedIPs(iface, pubkey, allowedIPs);
    audit.log('setPeerAllowedIPs', { iface, pubkey, allowedIPs });
    return { ok: true };
  },

  async setPeerKeepalive({ iface, pubkey, seconds }) {
    await wgService.setPeerKeepalive(iface, pubkey, seconds);
    audit.log('setPeerKeepalive', { iface, pubkey, seconds });
    return { ok: true };
  },

  // Status
  async getStatus({ iface }) {
    return await wgService.getServerStatus(iface);
  },

  async getConnected({ iface, activeWithinSeconds }) {
    return await wgService.getConnectedPeers(iface, activeWithinSeconds);
  },

  async getTransfer({ iface }) {
    return await wgService.getTransferStats(iface);
  },

  async getHandshakes({ iface }) {
    return await wgService.getHandshakeStatus(iface);
  },

  async getPeerStatus({ iface, pubkey }) {
    return await wgService.getPeerStatus(iface, pubkey);
  },

  async getPeerTransfer({ iface, pubkey }) {
    return await wgService.getPeerTransferStats(iface, pubkey);
  },

  // Audit
  async getAuditLogs({ limit, offset }) {
    return audit.getEntries(limit, offset);
  },

  // Firewall — Layer 3/4
  async firewallGetPolicy() {
    return await firewall.getPolicy();
  },

  async firewallSetPolicy({ defaultPolicy }) {
    const result = await firewall.setPolicy(defaultPolicy);
    audit.log('firewallSetPolicy', { defaultPolicy });
    return result;
  },

  async firewallGetRules({ iface }) {
    return await firewall.getRules(iface);
  },

  async firewallGetAllRules() {
    return await firewall.getAllRules();
  },

  async firewallListLive({ iface }) {
    return await firewall.listLiveRules(iface);
  },

  async firewallGetLogs({ ruleId, ip, iface }) {
    return { logs: await firewall.getLogs({ ruleId, ip, iface }) };
  },

  async firewallAddRule({ iface, rule }) {
    const result = await firewall.addRule(iface, rule);
    audit.log('firewallAddRule', { iface, rule: result });
    return result;
  },

  async firewallRemoveRule({ iface, ruleId }) {
    const result = await firewall.removeRule(iface, ruleId);
    audit.log('firewallRemoveRule', { iface, ruleId });
    return result;
  },

  async firewallFlushRules({ iface }) {
    const result = await firewall.flushRules(iface);
    audit.log('firewallFlushRules', { iface });
    return result;
  },

  async firewallBlockIP({ iface, ip, direction }) {
    const result = await firewall.blockIP(iface, ip, direction);
    audit.log('firewallBlockIP', { iface, ip, direction });
    return result;
  },

  async firewallAllowIP({ iface, ip, direction }) {
    const result = await firewall.allowIP(iface, ip, direction);
    audit.log('firewallAllowIP', { iface, ip, direction });
    return result;
  },

  async firewallBlockPort({ iface, port, protocol }) {
    const result = await firewall.blockPort(iface, port, protocol);
    audit.log('firewallBlockPort', { iface, port, protocol });
    return result;
  },

  async firewallAllowPort({ iface, port, protocol }) {
    const result = await firewall.allowPort(iface, port, protocol);
    audit.log('firewallAllowPort', { iface, port, protocol });
    return result;
  },

  async firewallBlockPeer({ iface, peerIP }) {
    const result = await firewall.blockPeer(iface, peerIP);
    audit.log('firewallBlockPeer', { iface, peerIP });
    return result;
  },

  async firewallRateLimitPeer({ iface, peerIP, rateKbps }) {
    const result = await firewall.rateLimitPeer(iface, peerIP, rateKbps);
    audit.log('firewallRateLimitPeer', { iface, peerIP, rateKbps });
    return result;
  },

  // DNS Filtering — Layer 7
  async dnsEnable({ iface }) {
    const result = await dnsFilter.enable(iface);
    audit.log('dnsEnable', { iface });
    return result;
  },

  async dnsDisable({ iface }) {
    const result = await dnsFilter.disable(iface);
    audit.log('dnsDisable', { iface });
    return result;
  },

  async dnsBlockDomain({ iface, domain }) {
    const result = await dnsFilter.blockDomain(iface, domain);
    audit.log('dnsBlockDomain', { iface, domain });
    return result;
  },

  async dnsUnblockDomain({ iface, domain }) {
    const result = await dnsFilter.unblockDomain(iface, domain);
    audit.log('dnsUnblockDomain', { iface, domain });
    return result;
  },

  async dnsListBlocked({ iface }) {
    return await dnsFilter.listBlocked(iface);
  },

  async dnsEnableCategory({ iface, category }) {
    const result = await dnsFilter.enableCategory(iface, category);
    audit.log('dnsEnableCategory', { iface, category });
    return result;
  },

  async dnsDisableCategory({ iface, category }) {
    const result = await dnsFilter.disableCategory(iface, category);
    audit.log('dnsDisableCategory', { iface, category });
    return result;
  },

  async dnsListCategories() {
    return dnsFilter.listCategories();
  },

  async dnsGetStats() {
    return dnsFilter.getStats();
  },
};

/**
 * Execute a command by type.
 * @param {string} type
 * @param {object} payload
 * @returns {Promise<object>}
 */
async function execute(type, payload = {}) {
  console.log(`[command] ${type}`, JSON.stringify(payload).substring(0, 200));
  const handler = handlers[type];
  if (!handler) {
    const err = new Error(`Unknown command: ${type}`);
    err.status = 400;
    throw err;
  }
  try {
    const result = await handler(payload);
    console.log(`[command] ${type} OK`);
    return result;
  } catch (err) {
    console.error(`[command] ${type} FAILED:`, err.message);
    throw err;
  }
}

// ----- system stats helpers -----

function cpuTotal(cpu) {
  return Object.values(cpu.times).reduce((a, b) => a + b, 0);
}

async function measureCpuUsage() {
  const start = os.cpus();
  await new Promise(r => setTimeout(r, 200));
  const end = os.cpus();
  let totalDiff = 0, idleDiff = 0;
  for (let i = 0; i < start.length; i++) {
    totalDiff += cpuTotal(end[i]) - cpuTotal(start[i]);
    idleDiff += end[i].times.idle - start[i].times.idle;
  }
  if (totalDiff === 0) return 0;
  return Math.round(((totalDiff - idleDiff) / totalDiff) * 100);
}

async function readNetworkStats() {
  // Try Linux /proc/net/dev first
  try {
    const fs = require('fs');
    const content = fs.readFileSync('/proc/net/dev', 'utf8');
    const lines = content.split('\n').slice(2);
    const interfaces = [];
    let totalRx = 0, totalTx = 0;
    for (const line of lines) {
      const m = line.trim().match(/^(\S+):\s+(\d+)(?:\s+\d+){7}\s+(\d+)/);
      if (!m) continue;
      const name = m[1].replace(':', '');
      if (name === 'lo') continue;
      const rx = parseInt(m[2], 10);
      const tx = parseInt(m[3], 10);
      interfaces.push({ name, rxBytes: rx, txBytes: tx });
      totalRx += rx;
      totalTx += tx;
    }
    return { totalRx, totalTx, interfaces };
  } catch {
    return { totalRx: 0, totalTx: 0, interfaces: [] };
  }
}

module.exports = { execute };
