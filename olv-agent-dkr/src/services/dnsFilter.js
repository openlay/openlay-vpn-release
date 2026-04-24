const dgram = require('dgram');
const fs = require('fs/promises');
const path = require('path');
const config = require('../config');

const confDir = config.wgConfigDir;
const LISTEN_PORT = 5353;
const UPSTREAM_DNS = ['1.1.1.1', '8.8.8.8'];
const DNS_TIMEOUT = 3000;

// ---------------------------------------------------------------------------
// Domain blocklist — per interface
// ---------------------------------------------------------------------------

function blocklistPath(iface) {
  return path.join(confDir, `${iface}-dns-blocklist.json`);
}

async function loadBlocklist(iface) {
  try {
    const data = await fs.readFile(blocklistPath(iface), 'utf8');
    return JSON.parse(data);
  } catch {
    return { domains: [], categories: {} };
  }
}

async function saveBlocklist(iface, blocklist) {
  await fs.writeFile(blocklistPath(iface), JSON.stringify(blocklist, null, 2));
}

// In-memory blocklists keyed by interface
const blocklists = new Map();

async function getBlocklist(iface) {
  if (!blocklists.has(iface)) {
    blocklists.set(iface, await loadBlocklist(iface));
  }
  return blocklists.get(iface);
}

async function persistBlocklist(iface) {
  const bl = blocklists.get(iface);
  if (bl) await saveBlocklist(iface, bl);
}

// ---------------------------------------------------------------------------
// Pre-built domain categories
// ---------------------------------------------------------------------------

const CATEGORIES = {
  social: [
    '*.facebook.com', '*.fbcdn.net', '*.instagram.com', '*.twitter.com',
    '*.x.com', '*.tiktok.com', '*.tiktokv.com', '*.snapchat.com',
    '*.reddit.com', '*.linkedin.com', '*.pinterest.com', '*.tumblr.com',
    '*.threads.net',
  ],
  streaming: [
    '*.netflix.com', '*.nflxvideo.net', '*.disneyplus.com', '*.hulu.com',
    '*.hbomax.com', '*.max.com', '*.primevideo.com', '*.crunchyroll.com',
    '*.twitch.tv', '*.ttvnw.net',
  ],
  gaming: [
    '*.steampowered.com', '*.steamcommunity.com', '*.epicgames.com',
    '*.riotgames.com', '*.blizzard.com', '*.battle.net', '*.ea.com',
    '*.origin.com', '*.xbox.com', '*.playstation.com',
  ],
  gambling: [
    '*.bet365.com', '*.betfair.com', '*.pokerstars.com', '*.888casino.com',
    '*.draftkings.com', '*.fanduel.com', '*.williamhill.com',
  ],
  adult: [
    '*.pornhub.com', '*.xvideos.com', '*.xhamster.com', '*.xnxx.com',
    '*.redtube.com', '*.youporn.com', '*.onlyfans.com',
  ],
  ads: [
    '*.doubleclick.net', '*.googlesyndication.com', '*.googleadservices.com',
    '*.adnxs.com', '*.adsrvr.org', '*.moatads.com', '*.facebook.com/tr',
    '*.analytics.google.com',
  ],
};

// ---------------------------------------------------------------------------
// DNS packet parsing (minimal, RFC 1035)
// ---------------------------------------------------------------------------

function parseDnsQuery(buf) {
  if (buf.length < 12) return null;
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qdcount = buf.readUInt16BE(4);
  if (qdcount === 0) return null;

  // Parse first question
  let offset = 12;
  const labels = [];
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) { offset++; break; }
    if (len > 63) return null; // compression not expected in queries
    offset++;
    labels.push(buf.toString('ascii', offset, offset + len));
    offset += len;
  }

  const qtype = buf.readUInt16BE(offset);
  const qclass = buf.readUInt16BE(offset + 2);

  return {
    id,
    flags,
    domain: labels.join('.').toLowerCase(),
    qtype,
    qclass,
    raw: buf,
  };
}

function buildBlockedResponse(query) {
  // Return 0.0.0.0 for A queries, empty NXDOMAIN for others
  const buf = Buffer.from(query.raw);

  // Set response flags: QR=1, AA=1, RCODE=0 (NOERROR)
  buf.writeUInt16BE(0x8180, 2); // QR=1, RD=1, RA=1

  if (query.qtype === 1) {
    // A record → return 0.0.0.0
    buf.writeUInt16BE(1, 6); // ANCOUNT = 1

    // Answer section: pointer to question name + A record with 0.0.0.0
    const answer = Buffer.alloc(16);
    answer.writeUInt16BE(0xC00C, 0); // name pointer to offset 12
    answer.writeUInt16BE(1, 2);      // TYPE A
    answer.writeUInt16BE(1, 4);      // CLASS IN
    answer.writeUInt32BE(60, 6);     // TTL 60s
    answer.writeUInt16BE(4, 10);     // RDLENGTH 4
    answer.writeUInt32BE(0, 12);     // 0.0.0.0

    return Buffer.concat([buf, answer]);
  }

  // For non-A queries, return NXDOMAIN
  buf.writeUInt16BE(0x8183, 2); // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
  buf.writeUInt16BE(0, 6); // ANCOUNT = 0
  return buf;
}

// ---------------------------------------------------------------------------
// Domain matching (supports wildcards)
// ---------------------------------------------------------------------------

function isDomainBlocked(domain, iface) {
  const bl = blocklists.get(iface);
  if (!bl) return false;

  // Collect all blocked patterns
  const patterns = [...bl.domains];
  for (const [cat, enabled] of Object.entries(bl.categories)) {
    if (enabled && CATEGORIES[cat]) {
      patterns.push(...CATEGORIES[cat]);
    }
  }

  for (const pattern of patterns) {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // .facebook.com
      if (domain === pattern.slice(2) || domain.endsWith(suffix)) return true;
    } else if (domain === pattern) {
      return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// DNS proxy server
// ---------------------------------------------------------------------------

let server = null;
let stats = { queries: 0, blocked: 0, forwarded: 0 };

function start() {
  if (server) return;

  server = dgram.createSocket('udp4');

  server.on('message', (msg, rinfo) => {
    stats.queries++;
    const query = parseDnsQuery(msg);
    if (!query) return;

    // Check all interfaces' blocklists
    let blocked = false;
    for (const iface of blocklists.keys()) {
      if (isDomainBlocked(query.domain, iface)) {
        blocked = true;
        break;
      }
    }

    if (blocked) {
      stats.blocked++;
      console.log(`[dns] BLOCKED: ${query.domain} from ${rinfo.address}`);
      const response = buildBlockedResponse(query);
      server.send(response, rinfo.port, rinfo.address);
      return;
    }

    // Forward to upstream DNS
    stats.forwarded++;
    forwardQuery(msg, rinfo);
  });

  server.on('error', (err) => {
    console.error('[dns] Server error:', err.message);
  });

  server.bind(LISTEN_PORT, '0.0.0.0', () => {
    console.log(`[dns] DNS filter proxy listening on :${LISTEN_PORT}`);
  });
}

function forwardQuery(msg, clientInfo) {
  const upstream = dgram.createSocket('udp4');
  const upstreamAddr = UPSTREAM_DNS[Math.floor(Math.random() * UPSTREAM_DNS.length)];

  const timer = setTimeout(() => {
    upstream.close();
  }, DNS_TIMEOUT);

  upstream.on('message', (response) => {
    clearTimeout(timer);
    server.send(response, clientInfo.port, clientInfo.address);
    upstream.close();
  });

  upstream.on('error', () => {
    clearTimeout(timer);
    upstream.close();
  });

  upstream.send(msg, 53, upstreamAddr);
}

function stop() {
  if (server) {
    server.close();
    server = null;
  }
}

// ---------------------------------------------------------------------------
// iptables: redirect DNS traffic from WireGuard peers to our proxy
// ---------------------------------------------------------------------------

const { exec } = require('../utils/exec');

async function enableDnsRedirect(iface) {
  try {
    await exec('iptables', [
      '-t', 'nat', '-C', 'PREROUTING',
      '-i', iface, '-p', 'udp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  } catch {
    await exec('iptables', [
      '-t', 'nat', '-A', 'PREROUTING',
      '-i', iface, '-p', 'udp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  }
  // Also redirect TCP DNS
  try {
    await exec('iptables', [
      '-t', 'nat', '-C', 'PREROUTING',
      '-i', iface, '-p', 'tcp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  } catch {
    await exec('iptables', [
      '-t', 'nat', '-A', 'PREROUTING',
      '-i', iface, '-p', 'tcp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  }
}

async function disableDnsRedirect(iface) {
  try {
    await exec('iptables', [
      '-t', 'nat', '-D', 'PREROUTING',
      '-i', iface, '-p', 'udp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  } catch { /* not present */ }
  try {
    await exec('iptables', [
      '-t', 'nat', '-D', 'PREROUTING',
      '-i', iface, '-p', 'tcp', '--dport', '53',
      '-j', 'REDIRECT', '--to-port', String(LISTEN_PORT),
    ]);
  } catch { /* not present */ }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

async function blockDomain(iface, domain) {
  const bl = await getBlocklist(iface);
  domain = domain.toLowerCase();
  if (!bl.domains.includes(domain)) {
    bl.domains.push(domain);
    await persistBlocklist(iface);
  }
  return { ok: true, domain };
}

async function unblockDomain(iface, domain) {
  const bl = await getBlocklist(iface);
  domain = domain.toLowerCase();
  bl.domains = bl.domains.filter(d => d !== domain);
  await persistBlocklist(iface);
  return { ok: true, domain };
}

async function listBlocked(iface) {
  const bl = await getBlocklist(iface);
  return {
    domains: bl.domains,
    categories: bl.categories,
  };
}

async function enableCategory(iface, category) {
  if (!CATEGORIES[category]) throw new Error(`Unknown category: ${category}`);
  const bl = await getBlocklist(iface);
  bl.categories[category] = true;
  await persistBlocklist(iface);
  return { ok: true, category, domains: CATEGORIES[category].length };
}

async function disableCategory(iface, category) {
  const bl = await getBlocklist(iface);
  delete bl.categories[category];
  await persistBlocklist(iface);
  return { ok: true, category };
}

function listCategories() {
  const result = {};
  for (const [name, domains] of Object.entries(CATEGORIES)) {
    result[name] = { count: domains.length, domains };
  }
  return { categories: result };
}

async function enable(iface) {
  await getBlocklist(iface); // ensure loaded
  start(); // start DNS proxy if not running
  await enableDnsRedirect(iface);
  return { ok: true, iface };
}

async function disable(iface) {
  await disableDnsRedirect(iface);
  return { ok: true, iface };
}

function getStats() {
  return { ...stats };
}

async function init() {
  // Load all existing blocklists into memory
  const fsSync = require('fs');
  try {
    const files = fsSync.readdirSync(confDir).filter(f => f.endsWith('-dns-blocklist.json'));
    for (const file of files) {
      const iface = file.replace('-dns-blocklist.json', '');
      await getBlocklist(iface);
    }
    if (files.length > 0) {
      start();
      console.log(`[dns] Loaded blocklists for ${files.length} interface(s)`);
    }
  } catch { /* no blocklists yet */ }
}

module.exports = {
  blockDomain,
  unblockDomain,
  listBlocked,
  enableCategory,
  disableCategory,
  listCategories,
  enable,
  disable,
  getStats,
  init,
};
