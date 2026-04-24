const { Router } = require('express');
const { pool } = require('../db/pool');
const AgentClient = require('../services/agentClient');
const { generateKeyPair, generatePresharedKey } = require('../services/keygen');
const { buildClientConfig } = require('../services/configBuilder');
const { resyncRulesByUsers } = require('../services/ruleOrchestrator');

const enterpriseContext = require('../middleware/enterpriseContext');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

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

    // Enrich with local metadata + user enterprise alias
    const entId = req.enterpriseId;
    const { rows: metaRows } = await pool.query(
      `SELECT pm.*, s.cidr as subnet_cidr, s.name as subnet_name,
              u.name as user_name, u.email as user_email
              ${entId ? `, uer.alias as user_alias` : ''}
       FROM peers_meta pm
       LEFT JOIN subnets s ON pm.subnet_id = s.id
       LEFT JOIN users u ON pm.user_id = u.id
       ${entId ? `LEFT JOIN user_enterprise_roles uer ON uer.user_id = pm.user_id AND uer.enterprise_id = '${entId.replace(/'/g, "''")}'` : ''}
       WHERE pm.server_id = $1 AND pm.interface_name = $2`,
      [req.params.serverId, req.params.iface]
    );

    const metaMap = new Map(metaRows.map(m => [m.public_key, m]));
    const agentKeys = new Set((agentData.peers || []).map(p => p.publicKey));

    const enrichedPeers = (agentData.peers || []).map(peer => {
      const meta = metaMap.get(peer.publicKey);
      return {
        ...peer,
        managed: !!meta,
        orphan: false,
        subnetCidr: meta?.subnet_cidr || null,
        subnetName: meta?.subnet_name || null,
        notes: meta?.notes || '',
        metaAlias: meta?.alias || '',
        userName: meta?.user_name || null,
        userEmail: meta?.user_email || null,
        userAlias: meta?.user_alias || null,
        expiresAt: meta?.expires_at || null,
        isExpired: meta?.is_expired || false,
        allowedSourceIp: meta?.allowed_source_ip || null,
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
        latestHandshake: null,
        transferRx: 0,
        transferTx: 0,
        managed: true,
        orphan: true,
        subnetCidr: meta.subnet_cidr || null,
        subnetName: meta.subnet_name || null,
        notes: meta.notes || '',
        metaAlias: meta.alias || '',
        userName: meta.user_name || null,
        userEmail: meta.user_email || null,
        userAlias: meta.user_alias || null,
        expiresAt: meta.expires_at || null,
        isExpired: meta.is_expired || false,
        allowedSourceIp: meta.allowed_source_ip || null,
      });
    }

    res.json({ peers: enrichedPeers });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/servers/:serverId/interfaces/:iface/peers
// Supports two modes: "auto" (generate keys) and "import" (provide public key)
router.post('/', async (req, res) => {
  try {
    const { client, server } = await getClientAndServer(req.params.serverId, req);
    const { mode, subnetId: _sid, subnet_id: _sid2, alias, notes, persistentKeepalive, ttlHours, allowedSourceIp, requestedIp } = req.body;
    const subnetId = _sid || _sid2;
    const iface = req.params.iface;

    // Calculate expiry time
    const expiresAt = ttlHours ? new Date(Date.now() + ttlHours * 3600 * 1000).toISOString() : null;

    let publicKey, privateKey, presharedKey, allowedIPs, clientConfig;

    if (mode === 'auto') {
      // Auto-generate keys
      if (!subnetId) {
        return res.status(400).json({ error: 'subnetId is required for auto mode' });
      }

      // Get subnet and next IP
      const { rows: subnets } = await pool.query(
        'SELECT * FROM subnets WHERE id = $1 AND server_id = $2',
        [subnetId, req.params.serverId]
      );
      if (subnets.length === 0) return res.status(404).json({ error: 'Subnet not found' });
      const subnet = subnets[0];

      // Get used IPs
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
        // Validate requested IP is in subnet and not already used
        const cleanIp = requestedIp.replace(/\/\d+$/, ''); // strip /32 if present
        if (!isIpInCidr(cleanIp, subnet.cidr)) {
          return res.status(400).json({ error: `IP ${cleanIp} is not in subnet ${subnet.cidr}` });
        }
        const usedClean = usedIps.map(ip => ip.replace(/\/\d+$/, ''));
        if (usedClean.includes(cleanIp)) {
          return res.status(409).json({ error: `IP ${cleanIp} is already in use` });
        }
        nextIp = cleanIp;
      } else {
        nextIp = getNextAvailableIp(subnet.cidr, usedIps);
      }
      if (!nextIp) {
        return res.status(409).json({ error: 'No available IPs in this subnet' });
      }

      // Generate keys
      const keys = generateKeyPair();
      publicKey = keys.publicKey;
      privateKey = keys.privateKey;
      presharedKey = generatePresharedKey();
      allowedIPs = `${nextIp}/32`;

      // Add peer to agent
      await client.addPeer(iface, {
        publicKey,
        allowedIPs,
        presharedKey,
        persistentKeepalive: persistentKeepalive || 25,
        alias: alias || '',
      });

      // Get server info for client config
      let serverPublicKey = '';
      let listenPort = '';
      let dns = '';
      try {
        const ifaceInfo = await client.getInterface(iface);
        listenPort = ifaceInfo.listenPort;
        dns = ifaceInfo.dns || '';
        // Get public key from status
        const statusInfo = await client.getStatus(iface);
        serverPublicKey = statusInfo.public_key || '';
      } catch { /* ignore */ }

      // Build endpoint from server URL, fallback to public_ip
      let serverHost = '';
      try { if (server.url) serverHost = new URL(server.url).hostname; } catch {}
      if (!serverHost) serverHost = server.public_ip || server.hostname || '';
      const endpoint = `${serverHost}:${listenPort}`;

      // Client Interface Address uses the subnet prefix (e.g. 10.0.0.100/24) so the
      // client can see the whole subnet and reach other peers.
      // Server-side AllowedIPs stays /32 (only this specific host).
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

      // Save metadata
      await pool.query(
        `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, notes, expires_at, allowed_source_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
         SET subnet_id = $4, alias = $5, notes = $6, expires_at = $7, allowed_source_ip = $8`,
        [req.params.serverId, iface, publicKey, subnetId, alias || '', notes || '', expiresAt, allowedSourceIp || null]
      );

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
      // Import mode - user provides public key
      const { publicKey: importedKey, presharedKey: importedPsk, allowedIPs: importedAllowedIPs, endpoint } = req.body;
      if (!importedKey) {
        return res.status(400).json({ error: 'publicKey is required for import mode' });
      }

      let finalAllowedIPs = importedAllowedIPs;

      // If subnetId provided, get next IP
      if (subnetId && !finalAllowedIPs) {
        const { rows: subnets } = await pool.query(
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
        return res.status(400).json({ error: 'allowedIPs is required (or provide subnetId to auto-assign)' });
      }

      // Add peer to agent
      await client.addPeer(iface, {
        publicKey: importedKey,
        allowedIPs: finalAllowedIPs,
        presharedKey: importedPsk || undefined,
        endpoint: endpoint || undefined,
        persistentKeepalive: persistentKeepalive || 25,
        alias: alias || '',
      });

      // Save metadata
      await pool.query(
        `INSERT INTO peers_meta (server_id, interface_name, public_key, subnet_id, alias, notes, expires_at, allowed_source_ip)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (server_id, interface_name, public_key) DO UPDATE
         SET subnet_id = $4, alias = $5, notes = $6, expires_at = $7, allowed_source_ip = $8`,
        [req.params.serverId, iface, importedKey, subnetId || null, alias || '', notes || '', expiresAt, allowedSourceIp || null]
      );

      res.status(201).json({
        publicKey: importedKey,
        allowedIPs: finalAllowedIPs,
        expiresAt,
        allowedSourceIp: allowedSourceIp || null,
      });
    }
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// DELETE /api/servers/:serverId/interfaces/:iface/peers/:pubkey
router.delete('/:pubkey', async (req, res) => {
  try {
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
