const fs = require('fs/promises');
const fsSync = require('fs');
const path = require('path');
const config = require('../config');
const { wg, wgQuick, exec } = require('../utils/exec');

const isDocker = fsSync.existsSync('/.dockerenv');

const confDir = config.wgConfigDir;

// ---------------------------------------------------------------------------
// Config file parser / writer
// ---------------------------------------------------------------------------

function parseWgConf(text) {
  const sections = [];
  let current = null;

  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) {
      if (current) current._comments = (current._comments || []).concat(raw);
      continue;
    }
    if (line.startsWith('[')) {
      const type = line.replace(/[[\]]/g, '').trim();
      current = { _type: type };
      sections.push(current);
      continue;
    }
    const eq = line.indexOf('=');
    if (eq !== -1 && current) {
      const key = line.slice(0, eq).trim();
      const val = line.slice(eq + 1).trim();
      if (current[key] !== undefined) {
        if (!Array.isArray(current[key])) current[key] = [current[key]];
        current[key].push(val);
      } else {
        current[key] = val;
      }
    }
  }
  return sections;
}

function serializeWgConf(sections) {
  const lines = [];
  for (const sec of sections) {
    lines.push(`[${sec._type}]`);
    for (const [k, v] of Object.entries(sec)) {
      if (k.startsWith('_')) continue;
      if (Array.isArray(v)) {
        for (const item of v) lines.push(`${k} = ${item}`);
      } else {
        lines.push(`${k} = ${v}`);
      }
    }
    lines.push('');
  }
  return lines.join('\n');
}

function confPath(name) {
  const safe = name.replace(/[^a-zA-Z0-9_-]/g, '');
  return path.join(confDir, `${safe}.conf`);
}

async function readConf(name) {
  const text = await fs.readFile(confPath(name), 'utf8');
  return parseWgConf(text);
}

async function writeConf(name, sections) {
  await fs.writeFile(confPath(name), serializeWgConf(sections), 'utf8');
}

// ---------------------------------------------------------------------------
// Alias store (peer public key -> alias, stored as JSON sidecar)
// ---------------------------------------------------------------------------

function aliasPath(name) {
  return path.join(confDir, `.${name}-aliases.json`);
}

async function readAliases(name) {
  try {
    return JSON.parse(await fs.readFile(aliasPath(name), 'utf8'));
  } catch {
    return {};
  }
}

async function writeAliases(name, aliases) {
  await fs.writeFile(aliasPath(name), JSON.stringify(aliases, null, 2), 'utf8');
}

// ---------------------------------------------------------------------------
// Interface functions
// ---------------------------------------------------------------------------

async function createInterface(name, listenPort, addressV4, opts = {}) {
  // Prevent overwriting existing interface
  const confFile = confPath(name);
  try {
    await fs.access(confFile);
    throw Object.assign(new Error(`Interface "${name}" already exists`), { status: 409 });
  } catch (err) {
    if (err.status === 409) throw err;
    // File doesn't exist — OK to create
  }

  // Detect default outbound interface for NAT
  let defaultIface = 'eth0';
  try {
    const { stdout: routeOut } = await exec('bash', ['-c', "ip -4 route show default | awk '{print $5}' | head -1"]);
    if (routeOut.trim()) defaultIface = routeOut.trim();
  } catch { /* fallback eth0 */ }

  // Extract subnet from address for NAT rule (e.g. 10.0.0.1/24 → 10.0.0.0/24)
  const subnet = addressV4.replace(/\.\d+\//, '.0/');

  const iface = {
    _type: 'Interface',
    Address: [addressV4, opts.addressV6].filter(Boolean).join(', '),
    ListenPort: String(listenPort),
  };

  // Generate keys
  const { stdout: privateKey } = await wg('genkey');
  iface.PrivateKey = privateKey;

  if (opts.mtu) iface.MTU = String(opts.mtu);
  // NOTE: DNS is NOT set in server-side WG config — it causes wg-quick to
  // invoke resolvconf which fails inside Docker containers. DNS is only
  // relevant for client-side configs and is sent via the connect API response.

  // NAT + forwarding rules (auto-applied on interface up/down)
  iface.PostUp = `sysctl -w net.ipv4.ip_forward=1 || true; iptables -t nat -A POSTROUTING -s ${subnet} -o ${defaultIface} -j MASQUERADE; iptables -A FORWARD -i ${name} -j ACCEPT; iptables -A FORWARD -o ${name} -m state --state RELATED,ESTABLISHED -j ACCEPT`;
  iface.PostDown = `iptables -t nat -D POSTROUTING -s ${subnet} -o ${defaultIface} -j MASQUERADE; iptables -D FORWARD -i ${name} -j ACCEPT; iptables -D FORWARD -o ${name} -m state --state RELATED,ESTABLISHED -j ACCEPT`;

  const sections = [iface];
  await writeConf(name, sections);

  // Bring up the interface + enable auto-start on boot
  try {
    await wgQuick('up', name);
  } catch (err) {
    console.error(`[wireguard] wg-quick up ${name} failed:`, err.stderr || err.message);
  }
  if (!isDocker) {
    try {
      await exec('systemctl', ['enable', `wg-quick@${name}`]);
    } catch { /* may not have systemd */ }
  }

  // Derive public key
  const { stdout: publicKey } = await exec('bash', ['-c', `echo "${privateKey}" | wg pubkey`]);

  return { name, publicKey, privateKey, listenPort, address: iface.Address };
}

async function deleteInterface(name) {
  try { await wgQuick('down', name); } catch { /* may already be down */ }
  await fs.unlink(confPath(name));
  try { await fs.unlink(aliasPath(name)); } catch { /* optional */ }
}

async function getInterface(name) {
  const sections = await readConf(name);
  const iface = sections.find(s => s._type === 'Interface') || {};
  const aliases = await readAliases(name);
  const peers = sections.filter(s => s._type === 'Peer').map(p => ({
    publicKey: p.PublicKey,
    allowedIPs: p.AllowedIPs,
    endpoint: p.Endpoint || null,
    persistentKeepalive: p.PersistentKeepalive || null,
    presharedKey: p.PresharedKey ? '(hidden)' : null,
    alias: aliases[p.PublicKey] || null,
  }));

  return {
    name,
    address: iface.Address || null,
    listenPort: iface.ListenPort || null,
    mtu: iface.MTU || null,
    dns: iface.DNS || null,
    privateKey: '(hidden)',
    peerCount: peers.length,
    peers,
  };
}

async function listInterfaces() {
  const files = await fs.readdir(confDir);
  return files
    .filter(f => f.endsWith('.conf'))
    .map(f => f.replace('.conf', ''));
}

async function getInterfaceSummaries() {
  const names = await listInterfaces();
  const results = [];
  for (const name of names) {
    try {
      const sections = await readConf(name);
      const iface = sections.find(s => s._type === 'Interface') || {};
      const peerCount = sections.filter(s => s._type === 'Peer').length;
      results.push({
        name,
        address: iface.Address || null,
        listenPort: iface.ListenPort || null,
        peerCount,
      });
    } catch { /* skip unreadable configs */ }
  }
  return results;
}

async function bringUpInterface(name) {
  await wgQuick('up', name);
}

async function bringDownInterface(name) {
  await wgQuick('down', name);
}

async function reloadInterface(name) {
  await exec('bash', ['-c', `wg syncconf ${name} <(wg-quick strip ${name})`]);
}

async function setInterfaceAddresses(name, addresses) {
  // Update Address field in config file, then restart interface to apply
  const sections = await readConf(name);
  const iface = sections.find(s => s._type === 'Interface');
  if (!iface) throw new Error(`Interface "${name}" not found in config`);

  const addrList = Array.isArray(addresses) ? addresses : [addresses];
  iface.Address = addrList.join(', ');

  // Update PostUp/PostDown NAT rules for all subnets
  let defaultIface = 'eth0';
  try {
    const { stdout: routeOut } = await exec('bash', ['-c', "ip -4 route show default | awk '{print $5}' | head -1"]);
    if (routeOut.trim()) defaultIface = routeOut.trim();
  } catch { /* fallback */ }

  const subnets = addrList.map(a => a.replace(/\.\d+\//, '.0/'));
  const postUpParts = [`sysctl -w net.ipv4.ip_forward=1 || true`];
  subnets.forEach(s => postUpParts.push(`iptables -t nat -A POSTROUTING -s ${s} -o ${defaultIface} -j MASQUERADE`));
  postUpParts.push(`iptables -A FORWARD -i ${name} -j ACCEPT`);
  postUpParts.push(`iptables -A FORWARD -o ${name} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

  const postDownParts = subnets.map(s => `iptables -t nat -D POSTROUTING -s ${s} -o ${defaultIface} -j MASQUERADE`);
  postDownParts.push(`iptables -D FORWARD -i ${name} -j ACCEPT`);
  postDownParts.push(`iptables -D FORWARD -o ${name} -m state --state RELATED,ESTABLISHED -j ACCEPT`);

  iface.PostUp = postUpParts.join('; ');
  iface.PostDown = postDownParts.join('; ');

  await writeConf(name, sections);

  // Restart interface to apply new addresses + NAT rules
  try { await wgQuick('down', name); } catch { /* may already be down */ }
  try { await wgQuick('up', name); } catch { /* log but don't fail */ }

  return { name, address: iface.Address };
}

async function saveRunningConfig(name) {
  // `wg showconf` only outputs [Interface] PrivateKey/ListenPort and [Peer]
  // blocks — it does NOT include wg-quick directives (Address, DNS, MTU,
  // PostUp, PostDown, etc.). We must preserve those from the existing config.
  const existingSections = await readConf(name);
  const ifaceSection = existingSections.find(s => s._type === 'Interface') || {};

  // Get runtime config (peers + interface keys/port)
  const { stdout } = await wg('showconf', name);
  const runtimeSections = parseWgConf(stdout);
  const runtimeIface = runtimeSections.find(s => s._type === 'Interface') || {};
  const runtimePeers = runtimeSections.filter(s => s._type === 'Peer');

  // Merge: keep wg-quick directives from existing, update wg-native fields from runtime
  const merged = { ...ifaceSection };
  if (runtimeIface.PrivateKey) merged.PrivateKey = runtimeIface.PrivateKey;
  if (runtimeIface.ListenPort) merged.ListenPort = runtimeIface.ListenPort;

  await writeConf(name, [merged, ...runtimePeers]);
}

// ---------------------------------------------------------------------------
// Runtime peer helper — uses `wg set` to apply a single peer without
// disrupting other peers or resetting the network interface.
// ---------------------------------------------------------------------------

async function applyPeerToRuntime(iface, peer) {
  const args = ['set', iface, 'peer', peer.PublicKey];

  if (peer.AllowedIPs) {
    args.push('allowed-ips', peer.AllowedIPs);
  }
  if (peer.Endpoint) {
    args.push('endpoint', peer.Endpoint);
  }
  if (peer.PersistentKeepalive) {
    args.push('persistent-keepalive', peer.PersistentKeepalive);
  }
  if (peer.PresharedKey) {
    // wg set reads preshared-key from a file; use process substitution
    await exec('bash', [
      '-c',
      `echo "${peer.PresharedKey}" | wg set ${iface} peer ${peer.PublicKey} preshared-key /dev/stdin` +
        (peer.AllowedIPs ? ` allowed-ips ${peer.AllowedIPs}` : '') +
        (peer.Endpoint ? ` endpoint ${peer.Endpoint}` : '') +
        (peer.PersistentKeepalive ? ` persistent-keepalive ${peer.PersistentKeepalive}` : ''),
    ]);
    return;
  }

  await wg(...args);
}

// ---------------------------------------------------------------------------
// Peer functions
// ---------------------------------------------------------------------------

async function listPeers(iface) {
  const sections = await readConf(iface);
  const aliases = await readAliases(iface);
  return sections.filter(s => s._type === 'Peer').map(p => ({
    publicKey: p.PublicKey,
    allowedIPs: p.AllowedIPs,
    endpoint: p.Endpoint || null,
    persistentKeepalive: p.PersistentKeepalive || null,
    presharedKey: p.PresharedKey ? true : false,
    alias: aliases[p.PublicKey] || null,
  }));
}

// listPeersWithSecrets is identical to listPeers but returns the actual
// PSK string instead of a boolean. Intended for internal migrate flow
// over the mTLS-authed management WS — never wire this into a user-facing
// route or the iOS admin UI would leak PSKs.
async function listPeersWithSecrets(iface) {
  const sections = await readConf(iface);
  const aliases = await readAliases(iface);
  return sections.filter(s => s._type === 'Peer').map(p => ({
    publicKey: p.PublicKey,
    allowedIPs: p.AllowedIPs,
    endpoint: p.Endpoint || null,
    persistentKeepalive: p.PersistentKeepalive || null,
    presharedKey: p.PresharedKey || '',
    alias: aliases[p.PublicKey] || null,
  }));
}

async function getPeer(iface, publicKey) {
  const sections = await readConf(iface);
  const aliases = await readAliases(iface);
  const peer = sections.find(s => s._type === 'Peer' && s.PublicKey === publicKey);
  if (!peer) return null;
  return {
    publicKey: peer.PublicKey,
    allowedIPs: peer.AllowedIPs,
    endpoint: peer.Endpoint || null,
    persistentKeepalive: peer.PersistentKeepalive || null,
    presharedKey: peer.PresharedKey ? true : false,
    alias: aliases[peer.PublicKey] || null,
  };
}

async function addPeer(iface, publicKey, allowedIPs, opts = {}) {
  const sections = await readConf(iface);
  const peer = { _type: 'Peer', PublicKey: publicKey, AllowedIPs: allowedIPs };
  if (opts.presharedKey) peer.PresharedKey = opts.presharedKey;
  if (opts.endpoint) peer.Endpoint = opts.endpoint;
  if (opts.persistentKeepalive) peer.PersistentKeepalive = String(opts.persistentKeepalive);
  sections.push(peer);
  await writeConf(iface, sections);

  if (opts.alias) {
    const aliases = await readAliases(iface);
    aliases[publicKey] = opts.alias;
    await writeAliases(iface, aliases);
  }

  // Apply to runtime via wg set (no network reset for other peers)
  try {
    await applyPeerToRuntime(iface, peer);
  } catch { /* interface may be down */ }
  return peer;
}

async function updatePeer(iface, publicKey, updates = {}) {
  const sections = await readConf(iface);
  const peer = sections.find(s => s._type === 'Peer' && s.PublicKey === publicKey);
  if (!peer) throw new Error('Peer not found');

  if (updates.allowedIPs !== undefined) peer.AllowedIPs = updates.allowedIPs;
  if (updates.endpoint !== undefined) peer.Endpoint = updates.endpoint;
  if (updates.persistentKeepalive !== undefined) peer.PersistentKeepalive = String(updates.persistentKeepalive);
  if (updates.presharedKey !== undefined) peer.PresharedKey = updates.presharedKey;

  await writeConf(iface, sections);

  // Apply only this peer to runtime (no network reset)
  try {
    await applyPeerToRuntime(iface, peer);
  } catch {}
  return { publicKey, updated: true };
}

async function removePeer(iface, publicKey) {
  const sections = await readConf(iface);
  const filtered = sections.filter(s => !(s._type === 'Peer' && s.PublicKey === publicKey));
  if (filtered.length === sections.length) throw new Error('Peer not found');
  await writeConf(iface, filtered);

  const aliases = await readAliases(iface);
  delete aliases[publicKey];
  await writeAliases(iface, aliases);

  // Remove only this peer from runtime (other peers unaffected)
  try {
    await wg('set', iface, 'peer', publicKey, 'remove');
  } catch {}
}

async function enablePeer(iface, publicKey) {
  // Re-add peer via wg set (peer may have been removed at runtime)
  const sections = await readConf(iface);
  const peer = sections.find(s => s._type === 'Peer' && s.PublicKey === publicKey);
  if (!peer) throw new Error('Peer not found');

  await applyPeerToRuntime(iface, peer);
}

async function disablePeer(iface, publicKey) {
  await wg('set', iface, 'peer', publicKey, 'remove');
}

async function renamePeerAlias(iface, publicKey, alias) {
  const aliases = await readAliases(iface);
  aliases[publicKey] = alias;
  await writeAliases(iface, aliases);
}

async function rotatePeerKeys(iface, publicKey) {
  const { stdout: newPrivateKey } = await wg('genkey');
  const { stdout: newPublicKey } = await exec('bash', ['-c', `echo "${newPrivateKey}" | wg pubkey`]);
  const { stdout: newPsk } = await wg('genpsk');

  const sections = await readConf(iface);
  const peer = sections.find(s => s._type === 'Peer' && s.PublicKey === publicKey);
  if (!peer) throw new Error('Peer not found');

  const oldPublicKey = peer.PublicKey;
  peer.PublicKey = newPublicKey;
  peer.PresharedKey = newPsk;

  await writeConf(iface, sections);

  // Update aliases
  const aliases = await readAliases(iface);
  if (aliases[oldPublicKey]) {
    aliases[newPublicKey] = aliases[oldPublicKey];
    delete aliases[oldPublicKey];
    await writeAliases(iface, aliases);
  }

  // Remove old peer, add new peer to runtime (other peers unaffected)
  try {
    await wg('set', iface, 'peer', oldPublicKey, 'remove');
    await applyPeerToRuntime(iface, peer);
  } catch {}

  return {
    oldPublicKey,
    newPublicKey,
    newPrivateKey,
    newPresharedKey: newPsk,
  };
}

async function setPeerEndpoint(iface, publicKey, endpoint) {
  return updatePeer(iface, publicKey, { endpoint });
}

async function setPeerAllowedIPs(iface, publicKey, allowedIPs) {
  return updatePeer(iface, publicKey, { allowedIPs });
}

async function setPeerKeepalive(iface, publicKey, seconds) {
  return updatePeer(iface, publicKey, { persistentKeepalive: seconds });
}

// ---------------------------------------------------------------------------
// Status / observability
// ---------------------------------------------------------------------------

function parseWgShow(output) {
  const peers = [];
  let current = null;

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (line.startsWith('peer:')) {
      if (current) peers.push(current);
      current = { publicKey: trimmed.split(':')[1]?.trim() };
    } else if (current && trimmed.includes(':')) {
      const [key, ...rest] = trimmed.split(':');
      const k = key.trim().replace(/\s+/g, '_');
      current[k] = rest.join(':').trim();
    }
  }
  if (current) peers.push(current);
  return peers;
}

async function getServerStatus(iface) {
  const { stdout } = await wg('show', iface);
  const lines = stdout.split('\n');
  const info = {};
  for (const line of lines) {
    if (line.startsWith('peer:')) break;
    const match = line.match(/^\s*(.+?):\s+(.+)$/);
    if (match) info[match[1].trim().replace(/\s+/g, '_')] = match[2].trim();
  }
  const peers = parseWgShow(stdout);
  return { interface: iface, ...info, peerCount: peers.length };
}

async function getPeerStatus(iface, publicKey) {
  const { stdout } = await wg('show', iface);
  const peers = parseWgShow(stdout);
  const peer = peers.find(p => p.publicKey === publicKey);
  if (!peer) throw new Error('Peer not found or not active');
  return peer;
}

async function getHandshakeStatus(iface) {
  const { stdout } = await wg('show', iface, 'latest-handshakes');
  const result = [];
  for (const line of stdout.split('\n')) {
    const [pubkey, timestamp] = line.split('\t');
    if (pubkey && timestamp) {
      const ts = parseInt(timestamp, 10);
      result.push({
        publicKey: pubkey.trim(),
        latestHandshake: ts === 0 ? null : new Date(ts * 1000).toISOString(),
        secondsAgo: ts === 0 ? null : Math.floor(Date.now() / 1000) - ts,
      });
    }
  }
  return result;
}

async function getTransferStats(iface) {
  const { stdout } = await wg('show', iface, 'transfer');
  const result = [];
  for (const line of stdout.split('\n')) {
    const [pubkey, rx, tx] = line.split('\t');
    if (pubkey && rx && tx) {
      result.push({
        publicKey: pubkey.trim(),
        receivedBytes: parseInt(rx, 10),
        sentBytes: parseInt(tx, 10),
      });
    }
  }
  return result;
}

async function getPeerTransferStats(iface, publicKey) {
  const all = await getTransferStats(iface);
  const peer = all.find(p => p.publicKey === publicKey);
  if (!peer) throw new Error('Peer not found');
  return peer;
}

async function getConnectedPeers(iface, activeWithinSeconds = 180) {
  const handshakes = await getHandshakeStatus(iface);
  const now = Math.floor(Date.now() / 1000);
  return handshakes.filter(h => h.secondsAgo !== null && h.secondsAgo <= activeWithinSeconds);
}

module.exports = {
  createInterface,
  deleteInterface,
  getInterface,
  listInterfaces,
  getInterfaceSummaries,
  bringUpInterface,
  bringDownInterface,
  reloadInterface,
  setInterfaceAddresses,
  saveRunningConfig,
  listPeers,
  listPeersWithSecrets,
  getPeer,
  addPeer,
  updatePeer,
  removePeer,
  enablePeer,
  disablePeer,
  renamePeerAlias,
  rotatePeerKeys,
  setPeerEndpoint,
  setPeerAllowedIPs,
  setPeerKeepalive,
  getServerStatus,
  getPeerStatus,
  getHandshakeStatus,
  getTransferStats,
  getPeerTransferStats,
  getConnectedPeers,
};
