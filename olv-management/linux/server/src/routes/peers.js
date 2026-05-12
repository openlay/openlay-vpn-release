const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { generateKeyPair, generatePresharedKey } = require('../services/keygen');
const { buildClientConfig } = require('../services/configBuilder');
const { resyncRulesByUsers } = require('../services/ruleOrchestrator');

const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

// Admin gate for mutation paths. Reading the peer list is fine for
// members; creating / deleting / renaming a peer reshapes who has
// access to the network and must be admin-only.
function requireAdmin(req, res) {
  if (['root', 'super_admin', 'admin'].includes(req.enterpriseRole)) return true;
  res.status(403).json({ error: 'Admin access required' });
  return false;
}

async function getClientAndServer(serverId, req) {
  const isRoot = req.enterpriseRole === 'root';
  const { rows } = isRoot
    ? await pool.query('SELECT * FROM servers WHERE id = $1', [serverId])
    : await pool.query(
        `SELECT * FROM servers WHERE id = $1 AND (enterprise_id = $2 OR access_mode = 'public')`,
        [serverId, req.enterpriseId]
      );
  if (rows.length === 0) throw Object.assign(new Error('Server not found'), { status: 404 });
  return { client: new AgentClient(parseInt(serverId)), server: rows[0] };
}

// GET /api/servers/:serverId/interfaces/:iface/peers
router.get('/', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const agentData = await client.listPeers(req.params.iface);
    // Live runtime info per peer (handshake, transfer). Best-effort —
    // interface down or older agent → empty map, peers render as offline.
    let runtimeMap = new Map();
    try {
      const handshakes = await client.getHandshakes(req.params.iface);
      for (const r of (handshakes.peers || [])) {
        runtimeMap.set(r.public_key || r.publicKey, r);
      }
    } catch (_) { /* ignore — fall back to no runtime data */ }

    // Enrich with local metadata + user enterprise alias + device os (client type)
    const entId = req.enterpriseId;
    const params = [req.params.serverId, req.params.iface];
    let entIdSelect = '';
    let entIdJoin = '';
    if (entId) {
      params.push(entId);
      entIdSelect = `, uer.alias as user_alias`;
      // Parametrised — entId comes from req.enterpriseId (header-driven) so
      // it must NEVER reach SQL as a string literal. The previous
      // `'${entId.replace(/'/g, "''")}'` interpolation was a textbook
      // SQL injection footgun even though backslash payloads are blunted
      // by standard_conforming_strings.
      entIdJoin = `LEFT JOIN user_enterprise_roles uer ON uer.user_id = pm.user_id AND uer.enterprise_id = $${params.length}`;
    }
    const { rows: metaRows } = await pool.query(
      `SELECT pm.*, s.cidr as subnet_cidr, s.name as subnet_name,
              u.name as user_name, u.email as user_email,
              d.id as device_id, d.name as device_name, d.os as device_os
              ${entIdSelect}
       FROM peers_meta pm
       LEFT JOIN subnets s ON pm.subnet_id = s.id
       LEFT JOIN users u ON pm.user_id = u.id
       LEFT JOIN devices d ON pm.device_id = d.id
       ${entIdJoin}
       WHERE pm.server_id = $1 AND pm.interface_name = $2`,
      params
    );

    const metaMap = new Map(metaRows.map(m => [m.public_key, m]));
    const agentKeys = new Set((agentData.peers || []).map(p => p.publicKey || p.public_key));

    // Fallback: when peers_meta has no device_id (e.g. older imports),
    // try matching the peer's public_key against devices.public_key. Some
    // OS clients register their key directly with the device row.
    const unmatchedKeys = [...agentKeys].filter(k => {
      const m = metaMap.get(k);
      return !m?.device_id;
    });
    let deviceByKey = new Map();
    if (unmatchedKeys.length > 0) {
      const { rows: devRows } = await pool.query(
        `SELECT id, name, os, public_key FROM devices WHERE public_key = ANY($1::text[])`,
        [unmatchedKeys]
      );
      deviceByKey = new Map(devRows.map(d => [d.public_key, d]));
    }

    const enrichedPeers = (agentData.peers || []).map(peer => {
      const pubkey = peer.publicKey || peer.public_key;
      const meta = metaMap.get(pubkey);
      const rt = runtimeMap.get(pubkey);
      const fallbackDev = deviceByKey.get(pubkey);
      const deviceOs = meta?.device_os || fallbackDev?.os || null;
      return {
        ...peer,
        managed: !!meta,
        orphan: false,
        subnet_cidr: meta?.subnet_cidr || null,
        subnet_name: meta?.subnet_name || null,
        notes: meta?.notes || '',
        meta_alias: meta?.alias || '',
        user_id: meta?.user_id || null,
        user_name: meta?.user_name || null,
        user_email: meta?.user_email || null,
        user_alias: meta?.user_alias || null,
        device_id: meta?.device_id || fallbackDev?.id || null,
        device_name: meta?.device_name || fallbackDev?.name || null,
        client_type: clientTypeFor(deviceOs, !!meta || !!fallbackDev),
        expires_at: meta?.expires_at || null,
        is_expired: meta?.is_expired || false,
        allowed_source_ip: meta?.allowed_source_ip || null,
        latest_handshake: rt?.latest_handshake ?? null,
        transfer_rx: rt?.transfer_rx ?? 0,
        transfer_tx: rt?.transfer_tx ?? 0,
      };
    });

    // Surface orphaned peers_meta rows (agent has no matching WG peer — happens
    // after agent reinstall / config wipe). They render in the list so the
    // admin can remove them; delete just drops the DB row.
    for (const meta of metaRows) {
      if (agentKeys.has(meta.public_key)) continue;
      enrichedPeers.push({
        publicKey: meta.public_key,
        allowedIPs: '',
        endpoint: '',
        persistentKeepalive: 0,
        latest_handshake: null,
        transfer_rx: 0,
        transfer_tx: 0,
        managed: true,
        orphan: true,
        subnet_cidr: meta.subnet_cidr || null,
        subnet_name: meta.subnet_name || null,
        notes: meta.notes || '',
        meta_alias: meta.alias || '',
        user_id: meta.user_id || null,
        user_name: meta.user_name || null,
        user_email: meta.user_email || null,
        user_alias: meta.user_alias || null,
        device_id: meta.device_id || null,
        device_name: meta.device_name || null,
        client_type: clientTypeFor(meta.device_os, true),
        expires_at: meta.expires_at || null,
        is_expired: meta.is_expired || false,
        allowed_source_ip: meta.allowed_source_ip || null,
      });
    }

    res.json({ peers: enrichedPeers });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// Map a device os to one of our supported client labels. Returns 'manual'
// when there's no linked device — i.e. the peer was imported via raw key.
function clientTypeFor(os, isManaged) {
  if (!os) return isManaged ? 'manual' : 'manual';
  switch (String(os).toLowerCase()) {
    case 'macos': return 'macos';
    case 'ios': return 'ios';
    case 'windows': return 'windows';
    case 'linux': return 'linux';
    case 'android': return 'android';
    default: return 'manual';
  }
}

// POST /api/servers/:serverId/interfaces/:iface/peers
// Supports two modes: "auto" (generate keys) and "import" (provide public key)
//
// Transaction model: each POST holds a per-(server, iface) advisory lock
// so concurrent IP allocations can't both claim the same address. INSERT
// `peers_meta` is staged in the transaction BEFORE the agent addPeer
// push; if agent fails the transaction rolls back and the DB never sees
// a row for a peer that doesn't exist on the wire. If agent succeeds but
// COMMIT fails (rare — DB hiccup), we compensate by calling removePeer
// so we never leak a ghost peer in the agent that DB doesn't know about.
router.post('/', async (req, res) => {
  if (!requireAdmin(req, res)) return;
  const iface = req.params.iface;
  let tx = null;
  let agentAdded = null; // { iface, publicKey } if we already pushed and may need to compensate

  try {
    const { client, server } = await getClientAndServer(req.params.serverId, req);
    const { mode, subnetId: _sid, subnet_id: _sid2, alias, notes, persistentKeepalive, ttlHours, allowedSourceIp, requestedIp } = req.body;
    const subnetId = _sid || _sid2;
    const expiresAt = ttlHours ? new Date(Date.now() + ttlHours * 3600 * 1000).toISOString() : null;

    tx = await pool.connect();
    await tx.query('BEGIN');
    // Serialise IP allocation across concurrent POSTs on the same iface.
    // Releases automatically on COMMIT/ROLLBACK. Keyed by (server, iface)
    // so different ifaces (or different servers) don't block each other.
    await tx.query(
      'SELECT pg_advisory_xact_lock(hashtext($1))',
      [`peers:${req.params.serverId}:${iface}`]
    );

    let publicKey, privateKey, presharedKey, allowedIPs, clientConfig;

    if (mode === 'auto') {
      if (!subnetId) {
        await tx.query('ROLLBACK');
        return res.status(400).json({ error: 'subnetId is required for auto mode' });
      }
      const { rows: subnets } = await tx.query(
        'SELECT * FROM subnets WHERE id = $1 AND server_id = $2',
        [subnetId, req.params.serverId]
      );
      if (subnets.length === 0) {
        await tx.query('ROLLBACK');
        return res.status(404).json({ error: 'Subnet not found' });
      }
      const subnet = subnets[0];

      // Used IPs come from two places: live agent state + uncommitted
      // peers_meta rows. The advisory lock keeps OTHER mgmt processes
      // out, but our own in-flight transaction inserts also need to be
      // considered if we ever batch-add — currently single POST per
      // request, so DB query suffices.
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

      const { getNextAvailableIp, isIpInCidr } = require('../services/subnetUtils');
      let nextIp;
      if (requestedIp) {
        const cleanIp = requestedIp.replace(/\/\d+$/, '');
        if (!isIpInCidr(cleanIp, subnet.cidr)) {
          await tx.query('ROLLBACK');
          return res.status(400).json({ error: `IP ${cleanIp} is not in subnet ${subnet.cidr}` });
        }
        const usedClean = usedIps.map(ip => ip.replace(/\/\d+$/, ''));
        if (usedClean.includes(cleanIp)) {
          await tx.query('ROLLBACK');
          return res.status(409).json({ error: `IP ${cleanIp} is already in use` });
        }
        nextIp = cleanIp;
      } else {
        nextIp = getNextAvailableIp(subnet.cidr, usedIps);
      }
      if (!nextIp) {
        await tx.query('ROLLBACK');
        return res.status(409).json({ error: 'No available IPs in this subnet' });
      }

      const keys = generateKeyPair();
      publicKey = keys.publicKey;
      privateKey = keys.privateKey;
      presharedKey = generatePresharedKey();
      allowedIPs = `${nextIp}/32`;

      // 1. INSERT DB first (claim the IP authoritatively under the lock).
      await tx.query(
        `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, notes, expires_at, allowed_source_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
         SET subnet_id = $4, alias = $5, notes = $6, expires_at = $7, allowed_source_ip = $8`,
        [req.params.serverId, iface, publicKey, subnetId, alias || '', notes || '', expiresAt, allowedSourceIp || null]
      );

      // 2. Push to agent. If this throws, ROLLBACK below removes the row.
      await client.addPeer(iface, {
        publicKey,
        allowedIPs,
        presharedKey,
        persistentKeepalive: persistentKeepalive || 25,
        alias: alias || '',
      });
      agentAdded = { iface, publicKey };

      // 3. Build the client config (cheap reads, no state mutation).
      let serverPublicKey = '';
      let listenPort = '';
      let dns = '';
      try {
        const ifaceInfo = await client.getInterface(iface);
        listenPort = ifaceInfo.listenPort;
        dns = ifaceInfo.dns || '';
        const statusInfo = await client.getStatus(iface);
        serverPublicKey = statusInfo.public_key || '';
      } catch { /* ignore */ }

      let serverHost = '';
      try { if (server.url) serverHost = new URL(server.url).hostname; } catch {}
      if (!serverHost) serverHost = server.public_ip || server.hostname || '';
      const endpoint = `${serverHost}:${listenPort}`;

      const subnetPrefix = subnet.cidr.split('/')[1];
      clientConfig = buildClientConfig({
        privateKey,
        address: `${nextIp}/${subnetPrefix}`,
        dns,
        serverPublicKey,
        serverEndpoint: endpoint,
        allowedIPs: '0.0.0.0/0, ::/0',
        presharedKey,
        persistentKeepalive: persistentKeepalive || 25,
      });

      // 4. COMMIT. If this throws, the catch block runs removePeer below.
      await tx.query('COMMIT');
      agentAdded = null; // committed — no compensation needed

      res.status(201).json({
        publicKey,
        privateKey,
        presharedKey,
        allowedIPs,
        clientConfig,
        expiresAt,
        allowedSourceIp: allowedSourceIp || null,
      });
    } else {
      // Import mode — caller supplies public key.
      const { publicKey: importedKey, presharedKey: importedPsk, allowedIPs: importedAllowedIPs, endpoint } = req.body;
      if (!importedKey) {
        await tx.query('ROLLBACK');
        return res.status(400).json({ error: 'publicKey is required for import mode' });
      }

      let finalAllowedIPs = importedAllowedIPs;

      if (subnetId && !finalAllowedIPs) {
        const { rows: subnets } = await tx.query(
          'SELECT * FROM subnets WHERE id = $1 AND server_id = $2',
          [subnetId, req.params.serverId]
        );
        if (subnets.length > 0) {
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
          const { getNextAvailableIp } = require('../services/subnetUtils');
          const nextIp = getNextAvailableIp(subnets[0].cidr, usedIps);
          if (nextIp) finalAllowedIPs = `${nextIp}/32`;
        }
      }

      if (!finalAllowedIPs) {
        await tx.query('ROLLBACK');
        return res.status(400).json({ error: 'allowedIPs is required (or provide subnetId to auto-assign)' });
      }

      // 1. INSERT DB first.
      await tx.query(
        `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, notes, expires_at, allowed_source_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
         SET subnet_id = $4, alias = $5, notes = $6, expires_at = $7, allowed_source_ip = $8`,
        [req.params.serverId, iface, importedKey, subnetId || null, alias || '', notes || '', expiresAt, allowedSourceIp || null]
      );

      // 2. Push to agent.
      await client.addPeer(iface, {
        publicKey: importedKey,
        allowedIPs: finalAllowedIPs,
        presharedKey: importedPsk || undefined,
        endpoint: endpoint || undefined,
        persistentKeepalive: persistentKeepalive || 25,
        alias: alias || '',
      });
      agentAdded = { iface, publicKey: importedKey };

      // 3. COMMIT.
      await tx.query('COMMIT');
      agentAdded = null;

      res.status(201).json({
        publicKey: importedKey,
        allowedIPs: finalAllowedIPs,
        expiresAt,
        allowedSourceIp: allowedSourceIp || null,
      });
    }
  } catch (err) {
    if (tx) {
      try { await tx.query('ROLLBACK'); } catch { /* ignore */ }
    }
    // Compensate if we pushed to agent but couldn't commit / threw after.
    // Best-effort — log on failure but don't override the original error.
    if (agentAdded) {
      const { client } = await getClientAndServer(req.params.serverId, req).catch(() => ({ client: null }));
      if (client) {
        try { await client.removePeer(agentAdded.iface, agentAdded.publicKey); }
        catch (rmErr) { console.error('[peers POST] compensation removePeer failed:', rmErr.message); }
      }
    }
    res.status(err.status || 500).json({ error: err.message });
  } finally {
    if (tx) tx.release();
  }
});

// DELETE /api/servers/:serverId/interfaces/:iface/peers/:pubkey
router.delete('/:pubkey', async (req, res) => {
  try {
    if (!requireAdmin(req, res)) return;
    const { client } = await getClientAndServer(req.params.serverId, req);
    const pubkey = decodeURIComponent(req.params.pubkey);

    // Capture user_id BEFORE deletion so we can resync their firewall rules.
    const { rows: ownerRows } = await pool.query(
      'SELECT user_id FROM peers_meta WHERE server_id = $1 AND interface_name = $2 AND public_key = $3',
      [req.params.serverId, req.params.iface, pubkey]
    );
    const affectedUserId = ownerRows[0]?.user_id || null;

    // Agent may not have the peer (orphaned peers_meta rows after agent
    // reinstall / config wipe). Log and continue so the DB row still gets
    // cleaned — otherwise admin is stuck with phantom entries.
    try {
      await client.removePeer(req.params.iface, pubkey);
    } catch (agentErr) {
      console.warn(`[peers] agent removePeer failed for ${pubkey}:`, agentErr.message);
    }

    // Clean up local metadata
    await pool.query(
      'DELETE FROM peers_meta WHERE server_id = $1 AND interface_name = $2 AND public_key = $3',
      [req.params.serverId, req.params.iface, pubkey]
    );

    if (affectedUserId) {
      try { await resyncRulesByUsers(parseInt(req.params.serverId), [affectedUserId]); }
      catch (syncErr) { console.error(`[peers] resync failed:`, syncErr.message); }
    }

    res.json({ removed: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/peers/:pubkey/enable
router.post('/:pubkey/enable', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const data = await client.enablePeer(req.params.iface, decodeURIComponent(req.params.pubkey));
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/peers/:pubkey/disable
router.post('/:pubkey/disable', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const data = await client.disablePeer(req.params.iface, decodeURIComponent(req.params.pubkey));
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PATCH /api/servers/:serverId/interfaces/:iface/peers/:pubkey/alias
router.patch('/:pubkey/alias', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const pubkey = decodeURIComponent(req.params.pubkey);
    const { alias } = req.body;

    await client.renamePeerAlias(req.params.iface, pubkey, alias);

    // Update local metadata
    await pool.query(
      `UPDATE peers_meta SET alias = $1 WHERE server_id = $2 AND interface_name = $3 AND public_key = $4`,
      [alias, req.params.serverId, req.params.iface, pubkey]
    );

    res.json({ alias });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/peers/:pubkey/rotate-keys
router.post('/:pubkey/rotate-keys', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const data = await client.rotatePeerKeys(req.params.iface, decodeURIComponent(req.params.pubkey));
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PATCH /api/servers/:serverId/interfaces/:iface/peers/:pubkey/endpoint
router.patch('/:pubkey/endpoint', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const { endpoint } = req.body;
    const data = await client.setPeerEndpoint(req.params.iface, decodeURIComponent(req.params.pubkey), endpoint);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PATCH /api/servers/:serverId/interfaces/:iface/peers/:pubkey/allowed-ips
router.patch('/:pubkey/allowed-ips', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const { allowedIPs } = req.body;
    const data = await client.setPeerAllowedIPs(req.params.iface, decodeURIComponent(req.params.pubkey), allowedIPs);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// PATCH /api/servers/:serverId/interfaces/:iface/peers/:pubkey/keepalive
router.patch('/:pubkey/keepalive', async (req, res) => {
  try {
    const { client } = await getClientAndServer(req.params.serverId, req);
    const { seconds } = req.body;
    const data = await client.setPeerKeepalive(req.params.iface, decodeURIComponent(req.params.pubkey), seconds);
    res.json(data);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
