function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function longToIp(long) {
  return [
    (long >>> 24) & 255,
    (long >>> 16) & 255,
    (long >>> 8) & 255,
    long & 255,
  ].join('.');
}

function parseCidr(cidr) {
  const [ip, prefixStr] = cidr.split('/');
  const prefix = parseInt(prefixStr, 10);
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const network = ipToLong(ip) & mask;
  const broadcast = (network | ~mask) >>> 0;
  return { network, broadcast, prefix, mask };
}

/**
 * Get the next available IP in a subnet given a set of used IPs.
 * Skips network address (.0), gateway (.1), and broadcast address.
 */
function getNextAvailableIp(cidr, usedIps) {
  const { network, broadcast, prefix } = parseCidr(cidr);
  if (prefix >= 31) return null;

  const usedSet = new Set(usedIps.map(ip => ipToLong(ip.split('/')[0])));

  for (let addr = network + 2; addr < broadcast; addr++) {
    if (!usedSet.has(addr)) {
      return longToIp(addr);
    }
  }
  return null;
}

module.exports = { getNextAvailableIp };
