const fs = require('fs/promises');
const fsSync = require('fs');
const path = require('path');
const config = require('../config');
const { exec } = require('../utils/exec');

const confDir = config.wgConfigDir;
const CHAIN_PREFIX = 'OLV-FW';
const POLICY_FILE = path.join(confDir, 'firewall-policy.json');
const LOG_PREFIX = 'olv-fw:';
const MAX_LOG_LINES = 500;

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

function rulesPath(iface) {
  return path.join(confDir, `${iface}-firewall.json`);
}

async function loadRules(iface) {
  try {
    const rules = JSON.parse(await fs.readFile(rulesPath(iface), 'utf8'));
    return rules.map(toCanonicalRule);
  } catch { return []; }
}

// Drop any snake_case aliases and keep a single camelCase field per attribute,
// so clients consuming this JSON get a predictable shape.
function toCanonicalRule(rule) {
  const { src_ip, dst_ip, src_port, dst_port, srcIp, dstIp, proto, ...rest } = rule;
  const canonical = { ...rest };
  const assignIfDefined = (key, value) => { if (value !== undefined && value !== null) canonical[key] = value; };
  assignIfDefined('srcIP', rule.srcIP ?? src_ip ?? srcIp);
  assignIfDefined('dstIP', rule.dstIP ?? dst_ip ?? dstIp);
  assignIfDefined('srcPort', rule.srcPort ?? src_port);
  assignIfDefined('dstPort', rule.dstPort ?? dst_port);
  assignIfDefined('protocol', rule.protocol ?? proto);
  return canonical;
}

async function saveRules(iface, rules) {
  await fs.writeFile(rulesPath(iface), JSON.stringify(rules, null, 2));
}

async function loadPolicy() {
  try {
    return JSON.parse(await fs.readFile(POLICY_FILE, 'utf8'));
  } catch { return { defaultPolicy: 'block_wan' }; }
}

async function savePolicy(policy) {
  await fs.writeFile(POLICY_FILE, JSON.stringify(policy, null, 2));
}

// ---------------------------------------------------------------------------
// Chain management
// ---------------------------------------------------------------------------

function chainName(iface) { return `${CHAIN_PREFIX}-${iface}`; }

async function ensureChain(iface) {
  const chain = chainName(iface);
  try { await exec('iptables', ['-N', chain]); } catch {}
  try { await exec('iptables', ['-C', 'FORWARD', '-i', iface, '-j', chain]); } catch {
    await exec('iptables', ['-I', 'FORWARD', '1', '-i', iface, '-j', chain]);
  }
  try { await exec('iptables', ['-C', 'FORWARD', '-o', iface, '-j', chain]); } catch {
    await exec('iptables', ['-I', 'FORWARD', '2', '-o', iface, '-j', chain]);
  }
}

async function flushChain(iface) {
  try { await exec('iptables', ['-F', chainName(iface)]); } catch {}
}

// ---------------------------------------------------------------------------
// System rules (non-deletable) — applied first in chain
// ---------------------------------------------------------------------------

function getSystemRules(managementIP) {
  return [
    { id: 'sys-vpn-in', system: true, protocol: 'udp', dstPort: '51820:51830', target: 'ACCEPT', label: 'Allow VPN input (51820-51830/udp)' },
    { id: 'sys-dns', system: true, protocol: 'udp', dstPort: '53', target: 'ACCEPT', label: 'Allow DNS (53/udp)' },
    { id: 'sys-dns-tcp', system: true, protocol: 'tcp', dstPort: '53', target: 'ACCEPT', label: 'Allow DNS (53/tcp)' },
    ...(managementIP ? [
      { id: 'sys-mgmt', system: true, dstIP: managementIP, protocol: 'tcp', dstPort: '3084', target: 'ACCEPT', label: `Allow management (${managementIP}:3084)` },
    ] : []),
  ];
}

// ---------------------------------------------------------------------------
// Normalize rule keys (iOS sends snake_case via APIClient encoder)
// ---------------------------------------------------------------------------

function normalizeRule(rule) {
  return {
    ...rule,
    srcIP: rule.srcIP || rule.src_ip || rule.srcIp,
    dstIP: rule.dstIP || rule.dst_ip || rule.dstIp,
    srcPort: rule.srcPort || rule.src_port,
    dstPort: rule.dstPort || rule.dst_port,
    protocol: rule.protocol || rule.proto,
  };
}

// ---------------------------------------------------------------------------
// Build iptables args
// ---------------------------------------------------------------------------

function buildArgs(iface, rule) {
  rule = normalizeRule(rule);
  const chain = chainName(iface);
  const args = ['-t', rule.table || 'filter'];

  if (rule.position) args.push('-I', chain, String(rule.position));
  else args.push('-A', chain);

  if (rule.protocol) args.push('-p', rule.protocol);
  if (rule.srcIP) args.push('-s', rule.srcIP);
  if (rule.dstIP) args.push('-d', rule.dstIP);
  if (rule.dstPort) args.push('--dport', String(rule.dstPort));
  if (rule.srcPort) args.push('--sport', String(rule.srcPort));

  // LOG target: log then continue (no ACCEPT/DROP)
  if (rule.log) {
    // Insert LOG rule before the actual rule
    const logArgs = [...args];
    logArgs.push('-j', 'LOG', '--log-prefix', `${LOG_PREFIX}${rule.id || 'match'}:`, '--log-level', '4');
    if (rule.id) logArgs.push('-m', 'comment', '--comment', `olv-fw-log:${rule.id}`);
    return { logArgs, ruleArgs: buildMainArgs(args, rule) };
  }

  return { logArgs: null, ruleArgs: buildMainArgs(args, rule) };
}

function buildMainArgs(args, rule) {
  args.push('-j', rule.target || 'DROP');
  if (rule.id) args.push('-m', 'comment', '--comment', `olv-fw:${rule.id}`);
  return args;
}

function buildDeleteArgs(iface, rule) {
  rule = normalizeRule(rule);
  const chain = chainName(iface);
  const args = ['-t', rule.table || 'filter', '-D', chain];
  if (rule.protocol) args.push('-p', rule.protocol);
  if (rule.srcIP) args.push('-s', rule.srcIP);
  if (rule.dstIP) args.push('-d', rule.dstIP);
  if (rule.dstPort) args.push('--dport', String(rule.dstPort));
  if (rule.srcPort) args.push('--sport', String(rule.srcPort));
  args.push('-j', rule.target || 'DROP');
  if (rule.id) args.push('-m', 'comment', '--comment', `olv-fw:${rule.id}`);
  return args;
}

// ---------------------------------------------------------------------------
// Policy management
// ---------------------------------------------------------------------------

async function getPolicy() {
  return await loadPolicy();
}

async function setPolicy(defaultPolicy) {
  // 'block_all' = DROP all forwarded traffic by default
  // 'block_wan' = DROP forwarded traffic to WAN, allow peer-to-peer (default)
  // 'allow_all' = ACCEPT all (no filtering)
  if (!['block_all', 'block_wan', 'allow_all'].includes(defaultPolicy)) {
    throw new Error(`Invalid policy: ${defaultPolicy}. Use: block_all, block_wan, allow_all`);
  }
  const policy = { defaultPolicy };
  await savePolicy(policy);
  // Rebuild all chains to apply new policy
  await rebuildAllChains();
  // Flush conntrack to kill established connections (otherwise old sessions bypass new policy)
  try { await exec('conntrack', ['-F']); } catch {}
  return policy;
}

// ---------------------------------------------------------------------------
// Rebuild chains with system rules + user rules + policy
// ---------------------------------------------------------------------------

function getManagementIP() {
  try {
    const url = config.managementApiUrl || '';
    const match = url.match(/https?:\/\/([^:/]+)/);
    return match ? match[1] : null;
  } catch { return null; }
}

async function rebuildChain(iface) {
  await ensureChain(iface);
  await flushChain(iface);

  const chain = chainName(iface);
  const policy = await loadPolicy();
  const mgmtIP = getManagementIP();
  const sysRules = getSystemRules(mgmtIP);

  // 1. System rules (ACCEPT critical traffic)
  for (const rule of sysRules) {
    const { ruleArgs } = buildArgs(iface, { ...rule, position: undefined });
    try { await exec('iptables', ruleArgs); } catch {}
  }

  // 2. User rules
  const userRules = await loadRules(iface);
  for (const rule of userRules) {
    if (rule.type === 'rate-limit') continue;
    try {
      const { logArgs, ruleArgs } = buildArgs(iface, rule);
      if (logArgs) await exec('iptables', logArgs);
      await exec('iptables', ruleArgs);
    } catch (err) {
      console.error(`[firewall] Failed to apply rule ${rule.id}:`, err.message);
    }
  }

  // 3. Default policy at end of chain
  if (policy.defaultPolicy === 'block_all') {
    await exec('iptables', ['-A', chain, '-j', 'DROP']);
  } else if (policy.defaultPolicy === 'block_wan') {
    // Allow peer-to-peer traffic within VPN subnets
    try {
      const confFile = await fs.readFile(path.join(confDir, `${iface}.conf`), 'utf8');
      const addrMatch = confFile.match(/Address\s*=\s*(.+)/);
      if (addrMatch) {
        const addresses = addrMatch[1].split(',').map(a => a.trim());
        for (const addr of addresses) {
          const subnet = addr.replace(/\.\d+\//, '.0/');
          await exec('iptables', ['-A', chain, '-s', subnet, '-d', subnet, '-j', 'ACCEPT']);
        }
      }
    } catch {}
    // Allow established/related (for replies to allowed outbound)
    try {
      await exec('iptables', ['-A', chain, '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']);
    } catch {}
    // Drop everything else (WAN traffic)
    await exec('iptables', ['-A', chain, '-j', 'DROP']);
  }
  // allow_all = no default DROP, everything passes
}

async function rebuildAllChains() {
  try {
    const files = fsSync.readdirSync(confDir).filter(f => f.endsWith('.conf'));
    for (const f of files) {
      const iface = f.replace('.conf', '');
      await rebuildChain(iface);
    }
  } catch {}
}

// ---------------------------------------------------------------------------
// Rule CRUD
// ---------------------------------------------------------------------------

let ruleCounter = Date.now();
function generateId() { return `r${++ruleCounter}`; }

async function getRules(iface) {
  const mgmtIP = getManagementIP();
  const sysRules = getSystemRules(mgmtIP);
  const userRules = await loadRules(iface);
  return { system: sysRules, user: userRules };
}

async function getAllRules() {
  const mgmtIP = getManagementIP();
  const sysRules = getSystemRules(mgmtIP);
  const result = {};
  try {
    const files = fsSync.readdirSync(confDir).filter(f => f.endsWith('-firewall.json'));
    for (const f of files) {
      const iface = f.replace('-firewall.json', '');
      result[iface] = await loadRules(iface);
    }
  } catch {}
  return { system: sysRules, interfaces: result, policy: await loadPolicy() };
}

async function addRule(iface, rule) {
  await ensureChain(iface);
  rule = toCanonicalRule(rule);
  rule.id = rule.id || generateId();
  rule.iface = iface;
  rule.createdAt = new Date().toISOString();

  const { logArgs, ruleArgs } = buildArgs(iface, rule);
  if (logArgs) await exec('iptables', logArgs);
  await exec('iptables', ruleArgs);

  const rules = await loadRules(iface);
  rules.push(rule);
  await saveRules(iface, rules);
  return rule;
}

async function removeRule(iface, ruleId) {
  const rules = await loadRules(iface);
  const idx = rules.findIndex(r => r.id === ruleId);
  if (idx === -1) throw new Error(`Rule not found: ${ruleId}`);
  const rule = rules[idx];

  try { await exec('iptables', buildDeleteArgs(iface, rule)); } catch {}
  // Also remove log rule if it had logging
  if (rule.log) {
    try {
      const chain = chainName(iface);
      await exec('iptables', ['-t', 'filter', '-D', chain, '-j', 'LOG',
        '--log-prefix', `${LOG_PREFIX}${rule.id}:`, '--log-level', '4',
        '-m', 'comment', '--comment', `olv-fw-log:${rule.id}`]);
    } catch {}
  }

  rules.splice(idx, 1);
  await saveRules(iface, rules);
  return { ok: true };
}

async function flushRules(iface) {
  await flushChain(iface);
  await saveRules(iface, []);
  // Re-apply system rules + policy
  await rebuildChain(iface);
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

async function blockIP(iface, ip, direction = 'both') {
  const rules = [];
  if (direction === 'out' || direction === 'both')
    rules.push(await addRule(iface, { dstIP: ip, target: 'DROP', label: `Block to ${ip}` }));
  if (direction === 'in' || direction === 'both')
    rules.push(await addRule(iface, { srcIP: ip, target: 'DROP', label: `Block from ${ip}` }));
  return { rules };
}

async function allowIP(iface, ip, direction = 'both') {
  const rules = [];
  if (direction === 'out' || direction === 'both')
    rules.push(await addRule(iface, { dstIP: ip, target: 'ACCEPT', position: 1, label: `Allow to ${ip}` }));
  if (direction === 'in' || direction === 'both')
    rules.push(await addRule(iface, { srcIP: ip, target: 'ACCEPT', position: 1, label: `Allow from ${ip}` }));
  return { rules };
}

async function blockPort(iface, port, protocol = 'tcp') {
  return { rule: await addRule(iface, { dstPort: port, protocol, target: 'DROP', label: `Block ${protocol}/${port}` }) };
}

async function allowPort(iface, port, protocol = 'tcp') {
  return { rule: await addRule(iface, { dstPort: port, protocol, target: 'ACCEPT', position: 1, label: `Allow ${protocol}/${port}` }) };
}

async function blockPeer(iface, peerIP) {
  const rules = [];
  rules.push(await addRule(iface, { srcIP: peerIP, target: 'DROP', label: `Block peer ${peerIP}` }));
  rules.push(await addRule(iface, { dstIP: peerIP, target: 'DROP', label: `Block peer ${peerIP}` }));
  return { rules };
}

async function rateLimitPeer(iface, peerIP, rateKbps) {
  const mark = ipToMark(peerIP);
  const markHex = `0x${mark.toString(16)}`;
  try { await exec('iptables', ['-t', 'mangle', '-A', 'FORWARD', '-s', peerIP, '-o', iface, '-j', 'MARK', '--set-mark', markHex]); } catch {}
  try {
    await exec('tc', ['qdisc', 'add', 'dev', iface, 'root', 'handle', '1:', 'htb', 'default', '999']);
    await exec('tc', ['class', 'add', 'dev', iface, 'parent', '1:', 'classid', '1:999', 'htb', 'rate', '1000mbit']);
  } catch {}
  const classId = `1:${mark}`;
  try { await exec('tc', ['class', 'add', 'dev', iface, 'parent', '1:', 'classid', classId, 'htb', 'rate', `${rateKbps}kbit`]); }
  catch { await exec('tc', ['class', 'change', 'dev', iface, 'parent', '1:', 'classid', classId, 'htb', 'rate', `${rateKbps}kbit`]); }
  try { await exec('tc', ['filter', 'add', 'dev', iface, 'parent', '1:', 'protocol', 'ip', 'handle', markHex, 'fw', 'classid', classId]); } catch {}
  const rules = await loadRules(iface);
  rules.push({ id: generateId(), type: 'rate-limit', iface, peerIP, rateKbps, mark: markHex, createdAt: new Date().toISOString(), label: `Rate limit ${peerIP} @ ${rateKbps}kbps` });
  await saveRules(iface, rules);
  return { ok: true, peerIP, rateKbps };
}

function ipToMark(ip) {
  const parts = ip.replace('/32', '').split('.');
  return (parseInt(parts[2]) << 8) + parseInt(parts[3]);
}

// ---------------------------------------------------------------------------
// Firewall logs — read from kernel log
// ---------------------------------------------------------------------------

async function getLogs(filter = {}) {
  try {
    // Read from dmesg or /var/log/kern.log
    const { stdout } = await exec('dmesg', ['--time-format', 'iso', '-l', 'warn'], { timeout: 5000 });
    let lines = stdout.split('\n').filter(l => l.includes(LOG_PREFIX));

    // Parse and filter
    const logs = lines.slice(-MAX_LOG_LINES).map(parseFwLog).filter(Boolean);

    if (filter.ruleId) return logs.filter(l => l.ruleId === filter.ruleId);
    if (filter.ip) return logs.filter(l => l.src === filter.ip || l.dst === filter.ip);
    if (filter.iface) return logs.filter(l => l.inIface === filter.iface || l.outIface === filter.iface);

    return logs;
  } catch {
    return [];
  }
}

function parseFwLog(line) {
  try {
    const ruleMatch = line.match(/olv-fw:([^:]+):/);
    const srcMatch = line.match(/SRC=(\S+)/);
    const dstMatch = line.match(/DST=(\S+)/);
    const protoMatch = line.match(/PROTO=(\S+)/);
    const sptMatch = line.match(/SPT=(\d+)/);
    const dptMatch = line.match(/DPT=(\d+)/);
    const inMatch = line.match(/IN=(\S*)/);
    const outMatch = line.match(/OUT=(\S*)/);
    const timeMatch = line.match(/^(\S+)/);

    return {
      time: timeMatch?.[1] || '',
      ruleId: ruleMatch?.[1] || '',
      src: srcMatch?.[1] || '',
      dst: dstMatch?.[1] || '',
      protocol: protoMatch?.[1] || '',
      srcPort: sptMatch?.[1] || '',
      dstPort: dptMatch?.[1] || '',
      inIface: inMatch?.[1] || '',
      outIface: outMatch?.[1] || '',
      raw: line,
    };
  } catch { return null; }
}

async function listLiveRules(iface) {
  const chain = chainName(iface);
  try {
    const { stdout } = await exec('iptables', ['-L', chain, '-n', '-v', '--line-numbers']);
    return { chain, rules: stdout };
  } catch {
    return { chain, rules: '' };
  }
}

// ---------------------------------------------------------------------------
// Restore on startup
// ---------------------------------------------------------------------------

async function restoreAll() {
  try {
    const files = fsSync.readdirSync(confDir).filter(f => f.endsWith('.conf'));
    for (const f of files) {
      const iface = f.replace('.conf', '');
      await rebuildChain(iface);
    }
    const policy = await loadPolicy();
    console.log(`[firewall] Restored. Policy: ${policy.defaultPolicy}`);
  } catch (err) {
    console.error(`[firewall] Restore error:`, err.message);
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  getPolicy, setPolicy,
  getRules, getAllRules,
  addRule, removeRule, flushRules,
  blockIP, allowIP, blockPort, allowPort, blockPeer,
  rateLimitPeer,
  listLiveRules, getLogs,
  restoreAll,
};
