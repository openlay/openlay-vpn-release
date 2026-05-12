const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { verifySecureEnclaveSignature } = require('../services/signatureVerifier');
const { getNextAvailableIp } = require('../services/subnetUtils');

const router = Router();

// Peer key TTL in hours. Reads enterprise-level setting (peer_ttl_hours), falls
// back to NODE_ENV-aware default (15m dev, 24h prod). 0 or negative = never.
async function resolvePeerTtlHours(enterpriseId) {
  const fallback = process.env.NODE_ENV === 'development' ? 0.25 : 24;
  if (!enterpriseId) return fallback;
  try {
    const { rows } = await pool.query(
      'SELECT value FROM enterprise_settings WHERE enterprise_id = $1 AND key = $2',
      [enterpriseId, 'peer_ttl_hours']
    );
    if (rows.length === 0) return fallback;
    const n = Number(rows[0].value);
    return Number.isFinite(n) ? n : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Resolve which server/interface/subnet to use.
 * If serverId is provided, validate user has access.
 * Otherwise auto-select the server with fewest peers.
 */
async function resolveServer(userId, serverId, requestedInterface) {
  if (serverId) {
    // Check if user is assigned to this server
    const { rows: assignments } = await pool.query(
      `SELECT usa.*, s.url, s.hostname, s.public_ip, s.api_token, s.name as server_name, s.access_mode, s.status as server_status
       FROM user_server_assignments usa
       JOIN servers s ON usa.server_id = s.id
       WHERE usa.user_id = $1 AND usa.server_id = $2`,
      [userId, serverId]
    );

    if (assignments.length > 0) {
      // If client requested specific interface, find that assignment
      let a = requestedInterface
        ? assignments.find(x => x.interface_name === requestedInterface) || assignments[0]
        : assignments[0];

      if (a.access_mode === 'for_sale') {
        const err = new Error('This server is for sale and not available for connections');
        err.status = 403;
        throw err;
      }
      if (a.server_status === 'pending' || a.server_status === 'disabled') {
        const err = new Error('Server is not active');
        err.status = 403;
        throw err;
      }
      let subnetId = a.subnet_id;

      // Fallback: if assignment has no subnet_id, pick first subnet for this interface
      if (!subnetId) {
        const { rows: subnets } = await pool.query(
          'SELECT id FROM subnets WHERE server_id = $1 AND interface_name = $2 ORDER BY created_at LIMIT 1',
          [a.server_id, a.interface_name]
        );
        if (subnets.length === 0) {
          // Try any subnet on this server
          const { rows: anySub } = await pool.query(
            'SELECT id FROM subnets WHERE server_id = $1 ORDER BY created_at LIMIT 1',
            [a.server_id]
          );
          if (anySub.length === 0) {
            const err = new Error('No subnet configured on this server');
            err.status = 409;
            throw err;
          }
          subnetId = anySub[0].id;
        } else {
          subnetId = subnets[0].id;
        }
      }

      return {
        server: { id: a.server_id, name: a.server_name, url: a.url, hostname: a.hostname, public_ip: a.public_ip, api_token: a.api_token },
        interfaceName: a.interface_name,
        subnetId,
      };
    }

    // No direct assignment — check enterprise membership or public access
    const { rows: servers } = await pool.query('SELECT * FROM servers WHERE id = $1', [serverId]);
    if (servers.length === 0) {
      const err = new Error('Server not found');
      err.status = 404;
      throw err;
    }

    const server = servers[0];
    if (server.status === 'pending' || server.status === 'disabled') {
      const err = new Error('Server is not active');
      err.status = 403;
      throw err;
    }
    if (server.access_mode === 'for_sale') {
      const err = new Error('This server is for sale and not available for connections');
      err.status = 403;
      throw err;
    }

    // Allow public servers (global or enterprise public for members)
    if (server.access_mode === 'public') {
      if (server.enterprise_id) {
        // Enterprise public server — check user is member
        const { rows: membership } = await pool.query(
          'SELECT 1 FROM user_enterprise_roles WHERE user_id = $1 AND enterprise_id = $2',
          [userId, server.enterprise_id]
        );
        if (membership.length === 0) {
          const err = new Error('You do not have access to this server');
          err.status = 403;
          throw err;
        }
      }
      // Global public or enterprise member — allow
    } else {
      const err = new Error('You do not have access to this server. Ask your admin to assign it.');
      err.status = 403;
      throw err;
    }
    const { rows: subnets } = await pool.query(
      'SELECT * FROM subnets WHERE server_id = $1 ORDER BY created_at LIMIT 1',
      [server.id]
    );
    if (subnets.length === 0) {
      const err = new Error('No subnet configured on this server');
      err.status = 409;
      throw err;
    }

    return {
      server,
      interfaceName: subnets[0].interface_name,
      subnetId: subnets[0].id,
    };
  }

  // Auto-select: find server with fewest peers
  const { rows: assignments } = await pool.query(
    `SELECT usa.*, s.url, s.hostname, s.public_ip, s.api_token, s.name as server_name,
            s.enterprise_id
     FROM user_server_assignments usa
     JOIN servers s ON usa.server_id = s.id
     WHERE usa.user_id = $1`,
    [userId]
  );

  if (assignments.length > 0) {
    let best = null;
    let bestCount = Infinity;

    for (const a of assignments) {
      const { rows } = await pool.query(
        'SELECT COUNT(*) as cnt FROM peers_meta WHERE server_id = $1 AND interface_name = $2',
        [a.server_id, a.interface_name]
      );
      const count = parseInt(rows[0].cnt, 10);
      if (count < bestCount) {
        bestCount = count;
        best = a;
      }
    }

    // Propagate ALL host-resolving fields — endpoint builder below needs
    // public_ip / url / hostname (any one is enough) and enterprise_id for
    // TTL resolution. Missing any here is what caused the 409 "no public IP"
    // when a server had only public_ip set.
    return {
      server: {
        id: best.server_id,
        name: best.server_name,
        url: best.url,
        hostname: best.hostname,
        public_ip: best.public_ip,
        api_token: best.api_token,
        enterprise_id: best.enterprise_id,
      },
      interfaceName: best.interface_name,
      subnetId: best.subnet_id,
    };
  }

  // No explicit assignments. Mirror the priority /api/servers advertises:
  //   a) Public servers owned by the user's own enterprise(s) — "enterprise
  //      public". Preferred because they're on infra the user's org controls.
  //   b) Fall back to globally public servers (enterprise_id IS NULL) if no
  //      enterprise-public candidate exists.
  // Within each tier we pick fewest peers (least-busy).
  const { rows: entRows } = await pool.query(
    'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1',
    [userId]
  );
  const entIds = entRows.map(r => r.enterprise_id).filter(Boolean);

  let candidates = [];
  if (entIds.length > 0) {
    const { rows } = await pool.query(
      `SELECT * FROM servers
       WHERE access_mode = 'public' AND status = 'active'
         AND enterprise_id = ANY($1::text[])`,
      [entIds]
    );
    candidates = rows;
  }
  if (candidates.length === 0) {
    const { rows } = await pool.query(
      "SELECT * FROM servers WHERE access_mode = 'public' AND status = 'active' AND enterprise_id IS NULL"
    );
    candidates = rows;
  }
  if (candidates.length === 0) {
    const err = new Error('No servers available');
    err.status = 503;
    throw err;
  }

  let best = null;
  let bestCount = Infinity;

  for (const srv of candidates) {
    const { rows: subnets } = await pool.query(
      'SELECT * FROM subnets WHERE server_id = $1 ORDER BY created_at LIMIT 1',
      [srv.id]
    );
    if (subnets.length === 0) continue;

    const { rows } = await pool.query(
      'SELECT COUNT(*) as cnt FROM peers_meta WHERE server_id = $1 AND interface_name = $2',
      [srv.id, subnets[0].interface_name]
    );
    const count = parseInt(rows[0].cnt, 10);
    if (count < bestCount) {
      bestCount = count;
      best = { server: srv, interfaceName: subnets[0].interface_name, subnetId: subnets[0].id };
    }
  }

  if (!best) {
    const err = new Error('No servers with subnets available');
    err.status = 503;
    throw err;
  }

  return best;
}

/**
 * Get used IPs from agent for a given interface.
 */
async function getUsedIps(client, iface) {
  let usedIps = [];
  try {
    const ifaceData = await client.getInterface(iface);
    if (ifaceData.peers) {
      usedIps = ifaceData.peers
        .map(p => p.allowedIPs)
        .filter(Boolean)
        .flatMap(ips => ips.split(',').map(ip => ip.trim()));
    }
    if (ifaceData.address) {
      usedIps.push(...ifaceData.address.split(',').map(a => a.trim()));
    }
  } catch { /* ignore */ }
  return usedIps;
}

// POST /api/connect — Create WG peer for a device
router.post('/', async (req, res) => {
  try {
    const { deviceId, wgPublicKey, signature, presharedKey, serverId } = req.body;
    const requestedInterface = req.body.interfaceName || req.body.interface_name;

    if (!deviceId || !wgPublicKey || !signature) {
      return res.status(400).json({ error: 'deviceId, wgPublicKey, and signature are required' });
    }

    // Validate device ownership and status (search by id or hardware_id)
    const { rows: devices } = await pool.query(
      'SELECT * FROM devices WHERE (id = $1 OR hardware_id = $1) AND user_id = $2',
      [deviceId, req.user.id]
    );

    if (devices.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    const device = devices[0];
    if (device.status !== 'enabled') {
      return res.status(403).json({ error: 'Device is not enabled' });
    }

    // Verify Secure Enclave signature (all users, both Apple and password)
    const isValid = verifySecureEnclaveSignature(
      device.public_key,
      wgPublicKey,
      signature
    );

    if (!isValid) {
      console.log('[DEBUG] signature verify failed');
      console.log('  DB public_key:', device.public_key);
      console.log('  Ask client to log their current SE public key and compare');
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // Delete existing peer for this device (1 device = 1 peer)
    const { rows: existingPeers } = await pool.query(
      `SELECT pm.*, s.url, s.api_token
       FROM peers_meta pm
       JOIN servers s ON pm.server_id = s.id
       WHERE pm.device_id = $1`,
      [device.id]
    );

    // Collect servers where the user lost peers here — we'll resync rules AFTER
    // the new peer is added so the re-expansion sees the current IP set, not
    // the transient gap between remove and add.
    const resyncTargetsByServer = new Map();
    for (const oldPeer of existingPeers) {
      try {
        const oldClient = new AgentClient(oldPeer.server_id);
        await oldClient.removePeer(oldPeer.interface_name, oldPeer.public_key);
      } catch { /* agent may be unreachable, continue anyway */ }
      await pool.query('DELETE FROM peers_meta WHERE id = $1', [oldPeer.id]);
      if (oldPeer.user_id) {
        if (!resyncTargetsByServer.has(oldPeer.server_id)) resyncTargetsByServer.set(oldPeer.server_id, new Set());
        resyncTargetsByServer.get(oldPeer.server_id).add(oldPeer.user_id);
      }
    }

    // Resolve server/interface/subnet
    const resolved = await resolveServer(req.user.id, serverId, requestedInterface);
    const { server, interfaceName, subnetId } = resolved;

    const client = new AgentClient(server.id);

    // Get subnet CIDR
    const { rows: subnets } = await pool.query('SELECT * FROM subnets WHERE id = $1', [subnetId]);
    if (subnets.length === 0) {
      return res.status(409).json({ error: 'Subnet not found' });
    }
    const subnet = subnets[0];

    // Check for static IP + allowed_ips assigned to this device on this server/subnet
    const { rows: staticIpRows } = await pool.query(
      'SELECT ip_address, allowed_ips FROM device_static_ips WHERE device_id = $1 AND server_id = $2 AND subnet_id = $3 LIMIT 1',
      [device.id, server.id, subnetId]
    );

    // Device profile (if assigned) drives the tunnel rules. Profile-level
    // allowed_ips wins over per-static-IP allowed_ips so the admin can
    // change tunnel scope across many devices in one place. The static-IP
    // allowed_ips remains as a per-(device,server) override only when no
    // profile is assigned (legacy path).
    let profile = null;
    if (device.profile_id) {
      const { rows: profileRows } = await pool.query(
        'SELECT allowed_ips, exclusion_ips, exclusion_domains, require_posture, can_be_exit_node FROM device_profiles WHERE id = $1',
        [device.profile_id]
      );
      profile = profileRows[0] || null;
    }

    let nextIp;
    // Resolve effective device-level allowed_ips:
    //   1. Profile.allowed_ips (if profile assigned and non-empty)
    //   2. Static-IP allowed_ips (legacy per-(device,server) override)
    //   3. null → route all traffic (default 0.0.0.0/0, ::/0)
    const profileAllowed = profile?.allowed_ips && profile.allowed_ips.length > 0
      ? profile.allowed_ips
      : null;
    const staticAllowed = staticIpRows.length > 0 && staticIpRows[0].allowed_ips && staticIpRows[0].allowed_ips.length > 0
      ? staticIpRows[0].allowed_ips
      : null;
    const deviceAllowedIps = profileAllowed || staticAllowed;

    if (staticIpRows.length > 0) {
      nextIp = staticIpRows[0].ip_address;
    } else {
      const usedIps = await getUsedIps(client, interfaceName);
      nextIp = getNextAvailableIp(subnet.cidr, usedIps);
      if (!nextIp) {
        return res.status(409).json({ error: 'No available IPs in subnet' });
      }
    }

    // Always use /32 for server-side AllowedIPs (route only this specific host)
    const allowedIPs = `${nextIp.split('/')[0]}/32`;
    const alias = `${req.user.email || 'user'}/${device.name || device.os}`;

    // Create peer on agent
    try {
      console.log(`[connect] addPeer to server=${server.id} iface=${interfaceName}`);
      await client.addPeer(interfaceName, {
        publicKey: wgPublicKey,
        allowedIPs,
        presharedKey: presharedKey || undefined,
        persistentKeepalive: 25,
        alias,
      });
      console.log(`[connect] addPeer success`);
    } catch (peerErr) {
      console.error(`[connect] addPeer FAILED:`, peerErr.message);
    }

    // Get server connection info
    let serverPublicKey = '';
    let listenPort = '';
    let dns = '';
    try {
      const ifaceInfo = await client.getInterface(interfaceName);
      listenPort = ifaceInfo.listenPort;
      dns = ifaceInfo.dns || '';
      const statusInfo = await client.getStatus(interfaceName);
      console.log(`[connect] statusInfo keys:`, Object.keys(statusInfo));
      console.log(`[connect] statusInfo:`, JSON.stringify(statusInfo).substring(0, 500));
      serverPublicKey = statusInfo.public_key || '';
      console.log(`[connect] serverPublicKey=${serverPublicKey}, listenPort=${listenPort}`);
    } catch (infoErr) {
      console.error(`[connect] getInterface/getStatus FAILED:`, infoErr.message);
    }

    // Determine server host for WireGuard endpoint
    // Prefer public_ip (direct IP from agent), fallback to url parsing, then hostname
    let serverHost = server.public_ip || '';
    if (!serverHost && server.url) {
      try { serverHost = new URL(server.url).hostname; } catch { /* ignore */ }
    }
    if (!serverHost) serverHost = server.hostname || '';
    if (!serverHost) {
      return res.status(409).json({ error: 'Server has no public IP or hostname configured' });
    }
    const endpoint = `${serverHost}:${listenPort}`;

    // Resolve peer TTL from enterprise setting (dev default 0.25h = 15m, prod 24h).
    // A value of 0 (or non-positive) means "never expire".
    const ttlHours = await resolvePeerTtlHours(server.enterprise_id);
    const expiresAt = ttlHours > 0 ? new Date(Date.now() + ttlHours * 3600 * 1000).toISOString() : null;

    // Save peer metadata. assigned_ip is cached here so app-server target
    // resolvers and route-policy ingress resolvers (typed pickers, M6)
    // don't have to roundtrip the agent on every read.
    const peerIpOnly = nextIp.split('/')[0];
    const { rows: peerMeta } = await pool.query(
      `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, device_id, user_id, expires_at, is_expired, assigned_ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE, $9)
       ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
       SET subnet_id = $4, alias = $5, device_id = $6, user_id = $7, expires_at = $8, is_expired = FALSE, assigned_ip = $9
       RETURNING id`,
      [server.id, interfaceName, wgPublicKey, subnetId, alias, device.id, req.user.id, expiresAt, peerIpOnly]
    );

    // Stamp last successful connect on the device so the admin UI can show
    // a "last seen" relative time without joining live agent state.
    await pool.query(`UPDATE devices SET last_connect_at = NOW() WHERE id = $1`, [device.id]);

    // New peer IP joined this user — ask management to refresh firewall rules referencing them.
    // Also cover any servers where they lost peers above (maybe a different server).
    const resyncByServer = resyncTargetsByServer;
    if (!resyncByServer.has(server.id)) resyncByServer.set(server.id, new Set());
    resyncByServer.get(server.id).add(req.user.id);
    for (const [srvId, userSet] of resyncByServer) {
      try {
        const resyncClient = new AgentClient(srvId);
        await resyncClient.resyncUserFirewallRules([...userSet]);
      } catch (syncErr) {
        console.error(`[connect] resync failed for server ${srvId}:`, syncErr.message);
      }
    }

    // Application Servers the user is entitled to ON THIS server they're
    // connecting to. Default-deny: user must be explicitly granted via
    // app_users or be a member of a granted user_group. Reachability is
    // implicit — apps live in this server's subnet, so VPN routing
    // already brings the user to them.
    //
    // target_type ∈ {ip, user, device}:
    //   - ip      → use a.ip directly (always reachable)
    //   - user    → join peers_meta on target_user_id, latest device's
    //               assigned_ip; reachable=false when offline
    //   - device  → join peers_meta on target_device_id directly
    //
    // We do the resolution server-side and emit { ip, reachable } so
    // client renders entries even when target peer is currently offline
    // (with an "unreachable" badge).
    let application_servers = [];
    try {
      const { rows } = await pool.query(
        `SELECT a.id, a.name, a.description, a.target_type,
                host(a.ip)          AS ip,
                a.target_user_id, a.target_device_id,
                a.port, a.protocol, a.server_id
         FROM application_servers a
         WHERE a.server_id = $1 AND a.enabled = TRUE
         AND (
           EXISTS (
             SELECT 1 FROM application_server_users u
             WHERE u.app_id = a.id AND u.user_id = $2
           )
           OR EXISTS (
             SELECT 1 FROM application_server_groups g
             JOIN user_group_members m ON m.user_group_id = g.user_group_id
             WHERE g.app_id = a.id AND m.user_id = $2
           )
         )
         ORDER BY a.name`,
        [server.id, req.user.id]
      );
      // Resolve typed targets to concrete IPs by joining peers_meta.
      // Doing it as N small queries instead of one big LATERAL join
      // because there's only a handful of apps per user.
      for (const a of rows) {
        let resolvedIp = null;
        let reachable = false;
        if (a.target_type === 'ip') {
          resolvedIp = a.ip;
          reachable = true;
        } else if (a.target_type === 'user' && a.target_user_id) {
          const { rows: pm } = await pool.query(
            `SELECT host(pm.assigned_ip) AS ip
               FROM peers_meta pm
               LEFT JOIN devices d ON d.id = pm.device_id
              WHERE pm.server_id = $1 AND pm.user_id = $2
                AND pm.assigned_ip IS NOT NULL
                AND COALESCE(pm.is_expired, FALSE) = FALSE
              ORDER BY COALESCE(d.last_connect_at, pm.created_at) DESC
              LIMIT 1`,
            [server.id, a.target_user_id]
          );
          if (pm[0]) { resolvedIp = pm[0].ip; reachable = true; }
        } else if (a.target_type === 'device' && a.target_device_id) {
          const { rows: pm } = await pool.query(
            `SELECT host(assigned_ip) AS ip
               FROM peers_meta
              WHERE server_id = $1 AND device_id = $2
                AND assigned_ip IS NOT NULL
                AND COALESCE(is_expired, FALSE) = FALSE
              ORDER BY created_at DESC
              LIMIT 1`,
            [server.id, a.target_device_id]
          );
          if (pm[0]) { resolvedIp = pm[0].ip; reachable = true; }
        }
        application_servers.push({
          id: a.id,
          name: a.name,
          description: a.description,
          server_id: a.server_id,
          target_type: a.target_type,
          port: a.port,
          protocol: a.protocol,
          ip: resolvedIp,
          reachable,
        });
      }
    } catch (asErr) {
      console.error('[connect] load application_servers failed:', asErr.message);
    }

    // disallowedIPs / disallowedDomains: CIDRs and hostnames the client must
    // NEVER route through the tunnel. Source of truth precedence:
    //   1. Device profile (per-device, multi-device reusable)
    //   2. Enterprise settings (legacy enterprise-wide singletons)
    // Client subtracts these from AllowedIPs (plus the management host's
    // resolved IP) before writing WG config.
    let disallowedIPs = [];
    let disallowedDomains = [];
    if (profile) {
      disallowedIPs = profile.exclusion_ips || [];
      disallowedDomains = profile.exclusion_domains || [];
    } else if (server.enterprise_id) {
      const { rows } = await pool.query(
        `SELECT key, value FROM enterprise_settings
         WHERE enterprise_id = $1 AND key IN ($2, $3)`,
        [server.enterprise_id, 'disallowed_ips', 'disallowed_domains']
      );
      for (const r of rows) {
        const list = (r.value || '').split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
        if (r.key === 'disallowed_ips') disallowedIPs = list;
        else disallowedDomains = list;
      }
    }

    // Exit-node mode signal: when this device's profile has
    // can_be_exit_node=TRUE AND the device runs Linux, signal exit-node
    // mode. Only the Linux client implements PostUp/PostDown to enable
    // IP forwarding + iptables MASQUERADE — iOS/macOS NetworkExtension
    // sandbox can't forward host traffic, Windows isn't wired yet, and
    // Android is a placeholder. Silently downgrade non-Linux devices to
    // role="client" even if their profile is marked exit-capable, so we
    // don't blackhole consumers' WAN traffic.
    //
    // We also surface the VPN subnet (e.g. "10.10.0.0/24") so the Linux
    // client's PostUp can `ip route add <subnet> dev %i` — required so
    // reply traffic to consumer peers (DNAT'd back to 10.x.x.x by
    // conntrack) routes back into wg0. Without this route, replies fall
    // through to eth0 default and get dropped because 10.x.x.x isn't
    // reachable on the public iface. Comes from the same `subnet` row
    // already loaded above for assignedIp allocation.
    const isExitNode = !!profile?.can_be_exit_node && device.os === 'linux';
    const exitNodePayload = isExitNode
      ? { wanIface: 'auto', vpnSubnet: subnet?.cidr || null }
      : null;

    res.status(201).json({
      peerId: peerMeta[0].id,
      assignedIp: allowedIPs,
      expiresAt,
      serverPublicKey,
      serverEndpoint: endpoint,
      allowedIPs: deviceAllowedIps ? deviceAllowedIps.join(', ') : '0.0.0.0/0, ::/0',
      disallowedIPs,
      disallowedDomains,
      dns: dns || '1.1.1.1',
      persistentKeepalive: 25,
      serverName: server.name,
      application_servers,
      role: isExitNode ? 'exit_node' : 'client',
      exitNode: exitNodePayload,
    });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/connect/refresh — Rotate WG peer key for an existing device session.
// Mounted as a sibling route (jwtAuth only, no appAttest) so the iOS Network
// Extension can call it on its own — DCAppAttestService is host-app-only.
//
// Security model:
//   1. jwtAuth → user identity (Bearer JWT, 30d TTL).
//   2. SE signature over wgPublicKey → device hardware (same check as /connect).
//   3. currentPeerId must be an active peers_meta row for this device → continuity.
//      Prevents replay: a captured signature cannot be reused once the peer it
//      replaced has been rotated.
//
// No App Attest because (jwtAuth + SE sig + continuity) is equivalent assurance
// for *replacing* an existing peer that was originally provisioned through the
// full /api/connect path.
const refreshRouter = Router();
refreshRouter.post('/', async (req, res) => {
  try {
    const { deviceId, currentPeerId, wgPublicKey, signature, presharedKey } = req.body;
    if (!deviceId || !currentPeerId || !wgPublicKey || !signature) {
      return res.status(400).json({ error: 'deviceId, currentPeerId, wgPublicKey, and signature are required' });
    }

    // Validate device + ownership
    const { rows: devices } = await pool.query(
      'SELECT * FROM devices WHERE (id = $1 OR hardware_id = $1) AND user_id = $2',
      [deviceId, req.user.id]
    );
    if (devices.length === 0) return res.status(404).json({ error: 'Device not found' });
    const device = devices[0];
    if (device.status !== 'enabled') return res.status(403).json({ error: 'Device is not enabled' });

    // Verify SE signature over the new wgPublicKey
    const isValid = verifySecureEnclaveSignature(device.public_key, wgPublicKey, signature);
    if (!isValid) {
      return res.status(403).json({ error: 'Invalid signature' });
    }

    // Continuity check: currentPeerId must belong to this device and not be expired
    const { rows: existing } = await pool.query(
      `SELECT pm.*, s.name AS server_name, s.url, s.public_ip, s.hostname, s.api_token, s.enterprise_id
       FROM peers_meta pm
       JOIN servers s ON pm.server_id = s.id
       WHERE pm.id = $1 AND pm.device_id = $2 AND pm.is_expired = FALSE`,
      [currentPeerId, device.id]
    );
    if (existing.length === 0) {
      return res.status(403).json({ error: 'currentPeerId mismatch or peer expired (continuity check failed)' });
    }
    const old = existing[0];

    // Resolve subnet
    const { rows: subnets } = await pool.query('SELECT * FROM subnets WHERE id = $1', [old.subnet_id]);
    if (subnets.length === 0) return res.status(409).json({ error: 'Subnet not found' });
    const subnet = subnets[0];

    const client = new AgentClient(old.server_id);

    // Profile + static-IP resolution mirrors /api/connect so refresh respects
    // the same admin-managed routing rules.
    const { rows: staticIpRows } = await pool.query(
      'SELECT ip_address, allowed_ips FROM device_static_ips WHERE device_id = $1 AND server_id = $2 AND subnet_id = $3 LIMIT 1',
      [device.id, old.server_id, old.subnet_id]
    );

    let profile = null;
    if (device.profile_id) {
      const { rows: profileRows } = await pool.query(
        'SELECT allowed_ips, exclusion_ips, exclusion_domains, require_posture, can_be_exit_node FROM device_profiles WHERE id = $1',
        [device.profile_id]
      );
      profile = profileRows[0] || null;
    }
    const profileAllowed = profile?.allowed_ips && profile.allowed_ips.length > 0
      ? profile.allowed_ips : null;
    const staticAllowed = staticIpRows.length > 0 && staticIpRows[0].allowed_ips && staticIpRows[0].allowed_ips.length > 0
      ? staticIpRows[0].allowed_ips : null;
    const deviceAllowedIps = profileAllowed || staticAllowed;

    // Free the old peer first so a dynamic-IP refresh can keep the same address.
    try {
      await client.removePeer(old.interface_name, old.public_key);
    } catch { /* agent unreachable, continue */ }

    let nextIp;
    if (staticIpRows.length > 0) {
      nextIp = staticIpRows[0].ip_address;
    } else {
      const usedIps = await getUsedIps(client, old.interface_name);
      nextIp = getNextAvailableIp(subnet.cidr, usedIps);
      if (!nextIp) {
        return res.status(409).json({ error: 'No available IPs in subnet' });
      }
    }

    const allowedIPs = `${nextIp.split('/')[0]}/32`;
    const alias = `${req.user.email || 'user'}/${device.name || device.os}`;

    // Add new peer on agent
    try {
      await client.addPeer(old.interface_name, {
        publicKey: wgPublicKey,
        allowedIPs,
        presharedKey: presharedKey || undefined,
        persistentKeepalive: 25,
        alias,
      });
    } catch (peerErr) {
      console.error('[refresh] addPeer FAILED:', peerErr.message);
      return res.status(502).json({ error: 'Agent failure' });
    }

    // Atomic DB swap (single transaction so a partial failure doesn't leave a
    // ghost peer entry that the next refresh would mistake for current).
    let newPeerId;
    let dbExpiresAt;
    const dbClient = await pool.connect();
    try {
      await dbClient.query('BEGIN');
      await dbClient.query('DELETE FROM peers_meta WHERE id = $1', [old.id]);
      const ttlHours = await resolvePeerTtlHours(old.enterprise_id);
      const computedExpiresAt = ttlHours > 0 ? new Date(Date.now() + ttlHours * 3600 * 1000).toISOString() : null;
      const { rows: peerMeta } = await dbClient.query(
        `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, device_id, user_id, expires_at, is_expired)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, FALSE)
         ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
         SET subnet_id = $4, alias = $5, device_id = $6, user_id = $7, expires_at = $8, is_expired = FALSE
         RETURNING id, expires_at`,
        [old.server_id, old.interface_name, wgPublicKey, old.subnet_id, alias, device.id, req.user.id, computedExpiresAt]
      );
      newPeerId = peerMeta[0].id;
      dbExpiresAt = peerMeta[0].expires_at;
      await dbClient.query('UPDATE devices SET last_connect_at = NOW() WHERE id = $1', [device.id]);
      await dbClient.query('COMMIT');
    } catch (dbErr) {
      await dbClient.query('ROLLBACK');
      console.error('[refresh] DB swap failed:', dbErr.message);
      // Best-effort cleanup: undo the agent-side add since DB didn't accept it
      try { await client.removePeer(old.interface_name, wgPublicKey); } catch { /* ignore */ }
      return res.status(500).json({ error: 'Database update failed' });
    } finally {
      dbClient.release();
    }

    // Resync firewall rules so any policy referencing this user picks up the new IP
    try {
      await client.resyncUserFirewallRules([req.user.id]);
    } catch (syncErr) {
      console.error('[refresh] resync failed:', syncErr.message);
    }

    // Server connection info
    let serverPublicKey = '';
    let listenPort = '';
    let dns = '';
    try {
      const ifaceInfo = await client.getInterface(old.interface_name);
      listenPort = ifaceInfo.listenPort;
      dns = ifaceInfo.dns || '';
      const statusInfo = await client.getStatus(old.interface_name);
      serverPublicKey = statusInfo.public_key || '';
    } catch (infoErr) {
      console.error('[refresh] getInterface/getStatus FAILED:', infoErr.message);
    }

    let serverHost = old.public_ip || '';
    if (!serverHost && old.url) {
      try { serverHost = new URL(old.url).hostname; } catch { /* */ }
    }
    if (!serverHost) serverHost = old.hostname || '';
    if (!serverHost) {
      return res.status(409).json({ error: 'Server has no public IP or hostname configured' });
    }
    const endpoint = `${serverHost}:${listenPort}`;

    // Application servers
    let application_servers = [];
    try {
      const { rows } = await pool.query(
        `SELECT a.id, a.name, a.description, a.ip::text AS ip,
                a.port, a.local_port, a.server_id
         FROM application_servers a
         WHERE a.server_id = $1 AND a.enabled = TRUE
         AND (
           EXISTS (
             SELECT 1 FROM application_server_users u
             WHERE u.app_id = a.id AND u.user_id = $2
           )
           OR EXISTS (
             SELECT 1 FROM application_server_groups g
             JOIN user_group_members m ON m.user_group_id = g.user_group_id
             WHERE g.app_id = a.id AND m.user_id = $2
           )
         )
         ORDER BY a.local_port`,
        [old.server_id, req.user.id]
      );
      application_servers = rows;
    } catch (asErr) {
      console.error('[refresh] load application_servers failed:', asErr.message);
    }

    // disallowedIPs / disallowedDomains (same precedence as /api/connect)
    let disallowedIPs = [];
    let disallowedDomains = [];
    if (profile) {
      disallowedIPs = profile.exclusion_ips || [];
      disallowedDomains = profile.exclusion_domains || [];
    } else if (old.enterprise_id) {
      const { rows } = await pool.query(
        `SELECT key, value FROM enterprise_settings
         WHERE enterprise_id = $1 AND key IN ($2, $3)`,
        [old.enterprise_id, 'disallowed_ips', 'disallowed_domains']
      );
      for (const r of rows) {
        const list = (r.value || '').split(/[,\s]+/).map(s => s.trim()).filter(Boolean);
        if (r.key === 'disallowed_ips') disallowedIPs = list;
        else disallowedDomains = list;
      }
    }

    // See /api/connect for the OS gate rationale + vpnSubnet usage.
    const isExitNode = !!profile?.can_be_exit_node && device.os === 'linux';
    const exitNodePayload = isExitNode
      ? { wanIface: 'auto', vpnSubnet: subnet?.cidr || null }
      : null;
    res.status(200).json({
      peerId: newPeerId,
      assignedIp: allowedIPs,
      expiresAt: dbExpiresAt,
      serverPublicKey,
      serverEndpoint: endpoint,
      allowedIPs: deviceAllowedIps ? deviceAllowedIps.join(', ') : '0.0.0.0/0, ::/0',
      disallowedIPs,
      disallowedDomains,
      dns: dns || '1.1.1.1',
      persistentKeepalive: 25,
      serverName: old.server_name,
      application_servers,
      role: isExitNode ? 'exit_node' : 'client',
      exitNode: exitNodePayload,
    });
  } catch (err) {
    console.error('[refresh] unhandled error:', err);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/connect/status — My active connections
router.get('/status', async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT pm.*, s.name as server_name, s.url as server_url, s.api_token,
              d.name as device_name, d.os as device_os
       FROM peers_meta pm
       JOIN servers s ON pm.server_id = s.id
       LEFT JOIN devices d ON pm.device_id = d.id
       WHERE pm.user_id = $1
       ORDER BY pm.created_at DESC`,
      [req.user.id]
    );

    // Enrich with live status from agents
    const connections = [];
    for (const peer of rows) {
      let status = { connected: false };
      try {
        const client = new AgentClient(peer.server_id);
        const handshakes = await client.getHandshakes(peer.interface_name);
        const peerHandshake = handshakes.peers?.find(p => p.publicKey === peer.public_key);
        if (peerHandshake && peerHandshake.latestHandshake) {
          const handshakeAge = Date.now() / 1000 - peerHandshake.latestHandshake;
          status.connected = handshakeAge < 180;
          status.latestHandshake = peerHandshake.latestHandshake;
        }
      } catch { /* agent unreachable */ }

      connections.push({
        peerId: peer.id,
        serverName: peer.server_name,
        interfaceName: peer.interface_name,
        publicKey: peer.public_key,
        deviceName: peer.device_name,
        deviceOs: peer.device_os,
        alias: peer.alias,
        createdAt: peer.created_at,
        isExpired: peer.is_expired,
        ...status,
      });
    }

    res.json({ connections });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
module.exports.refreshRouter = refreshRouter;
