/**
 * CIDR utility functions for IPv4 subnet management.
 */

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

  if (prefix >= 31) {
    // /31 or /32 - no usable IPs for allocation
    return null;
  }

  const usedSet = new Set(usedIps.map(ip => {
    // Handle both "10.0.0.2" and "10.0.0.2/32" formats
    return ipToLong(ip.split('/')[0]);
  }));

  // Start from .2 (skip network .0 and gateway .1)
  for (let addr = network + 2; addr < broadcast; addr++) {
    if (!usedSet.has(addr)) {
      return longToIp(addr);
    }
  }

  return null; // Subnet is full
}

/**
 * Validate if an IP belongs to a CIDR range.
 */
function isIpInCidr(ip, cidr) {
  const { network, mask } = parseCidr(cidr);
  const ipLong = ipToLong(ip.split('/')[0]);
  return (ipLong & mask) === network;
}

/**
 * Validate CIDR format.
 */
function isValidCidr(cidr) {
  const match = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!match) return false;
  const octets = [match[1], match[2], match[3], match[4]].map(Number);
  const prefix = parseInt(match[5], 10);
  return octets.every(o => o >= 0 && o <= 255) && prefix >= 0 && prefix <= 32;
}

module.exports = { parseCidr, getNextAvailableIp, isIpInCidr, isValidCidr, ipToLong, longToIp };
