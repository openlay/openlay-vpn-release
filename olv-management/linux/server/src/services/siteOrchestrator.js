// Site-to-site orchestrator. Wraps M1/M2/M3 agent primitives into one
// "site" object. Create walks steps in order, recording artifacts;
// any mid-way failure compensates by undoing the recorded artifacts
// in reverse (best-effort — errors during rollback log but don't
// prevent the original failure surfacing to the caller).
//
// State shape: the `sites` row is the operator-facing handle; the
// `site_artifacts` rows are the bookkeeping that tells delete what to
// tear down.
const AgentClient = require('./agentClient');
const { pool } = require('../db/pool');

const ARTIFACT = {
  PEER: 'peer-allowed-ips-added',
  ROUTE: 'route',
  NAT: 'nat',
  POLICY: 'policy',
};

// Types considered reversible by deleteSite. Order matters: we undo
// in the reverse order of creation so dependent pieces clear first.
const ROLLBACK_ORDER = [ARTIFACT.POLICY, ARTIFACT.NAT, ARTIFACT.ROUTE, ARTIFACT.PEER];

// createSite persists the site row + composes agent primitives. The
// row is committed inside a DB transaction together with its
// artifacts, so a partial failure leaves no zombie DB state. Agent
// calls happen inside the transaction window — if any agent call
// fails we (a) roll back the DB transaction and (b) compensate each
// already-applied agent artifact.
async function createSite(serverId, input) {
  validateInput(input);
  const client = new AgentClient(serverId);
  const appliedArtifacts = []; // for compensation on failure

  // Pre-flight: make sure the peer exists (if the caller named one).
  // Skipping this check would surface as a cryptic
  // "peer not found" from setPeerAllowedIPs later.
  if (input.remotePeerPubkey) {
    const peers = await client.listPeers(input.localIface);
    const found = (peers.peers || peers || []).find(
      (p) => p.publicKey === input.remotePeerPubkey
    );
    if (!found) {
      throw Object.assign(
        new Error(`peer ${input.remotePeerPubkey} not found on ${input.localIface}`),
        { status: 400 }
      );
    }
    // Extend AllowedIPs with the remote subnet. We record the CIDR
    // we appended (not the full set) so rollback knows exactly what
    // to strip.
    const existingAllowed = commaSplit(found.allowedIPs || '');
    if (!existingAllowed.includes(input.remoteSubnet)) {
      const updated = [...existingAllowed, input.remoteSubnet].join(', ');
      await client.setPeerAllowedIPs(input.localIface, input.remotePeerPubkey, updated);
      appliedArtifacts.push({ type: ARTIFACT.PEER, ref: input.remoteSubnet });
    }
  }

  // Static route for the remote LAN.
  try {
    const rt = await client.routerAddRoute(input.localIface, {
      destination: input.remoteSubnet,
      gateway: input.remoteGateway || '',
      description: `site:${input.name}`,
      enabled: true,
    });
    appliedArtifacts.push({ type: ARTIFACT.ROUTE, ref: rt.id, iface: input.localIface });
  } catch (err) {
    await compensate(client, appliedArtifacts, input);
    throw err;
  }

  // Optional SNAT for traffic from local_subnet → remote_subnet.
  // Needs the server's default_wan_iface; orchestrator refuses
  // enable_nat when that isn't configured rather than guessing.
  if (input.enableNat) {
    const { rows: srvRows } = await pool.query(
      'SELECT default_wan_iface FROM servers WHERE id = $1',
      [serverId]
    );
    const wan = srvRows[0]?.default_wan_iface;
    if (!wan) {
      await compensate(client, appliedArtifacts, input);
      throw Object.assign(
        new Error('enable_nat requires servers.default_wan_iface to be set'),
        { status: 400 }
      );
    }
    if (!input.localSubnet) {
      await compensate(client, appliedArtifacts, input);
      throw Object.assign(
        new Error('enable_nat requires local_subnet'),
        { status: 400 }
      );
    }
    try {
      const nat = await client.natAddRule({
        name: `site-${input.name}-nat`,
        wanIface: wan,
        srcCIDR: input.localSubnet,
        description: `site:${input.name}`,
        enabled: true,
      });
      appliedArtifacts.push({ type: ARTIFACT.NAT, ref: nat.id });
    } catch (err) {
      await compensate(client, appliedArtifacts, input);
      throw err;
    }
  }

  // Optional policy route pinning the site's flow to a specific FIB.
  if (typeof input.policyFib === 'number') {
    try {
      const policy = await client.routerAddPolicy({
        name: `site-${input.name}-pol`,
        priority: 100,
        ingressIface: input.localIface,
        srcCIDR: input.localSubnet || '',
        dstCIDR: input.remoteSubnet,
        fib: input.policyFib,
        action: 'route-to',
        gatewayIface: input.localIface,
        gateway: input.remoteGateway || '',
        description: `site:${input.name}`,
        enabled: true,
      });
      appliedArtifacts.push({ type: ARTIFACT.POLICY, ref: policy.id });
    } catch (err) {
      await compensate(client, appliedArtifacts, input);
      throw err;
    }
  }

  // Persist site + artifacts in one DB transaction so a crash between
  // the INSERT rows and the artifact rows can't desync them.
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const { rows } = await dbClient.query(
      `INSERT INTO sites (
         server_id, name, description, local_iface, local_subnet,
         remote_peer_pubkey, remote_subnet, remote_gateway,
         enable_nat, policy_fib, enabled
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING *`,
      [
        serverId, input.name, input.description || null,
        input.localIface, input.localSubnet || null,
        input.remotePeerPubkey || null, input.remoteSubnet,
        input.remoteGateway || null,
        !!input.enableNat,
        input.policyFib !== undefined ? input.policyFib : null,
        input.enabled === undefined ? true : !!input.enabled,
      ]
    );
    const site = rows[0];
    for (const a of appliedArtifacts) {
      await dbClient.query(
        `INSERT INTO site_artifacts (site_id, artifact_type, artifact_ref, details)
         VALUES ($1,$2,$3,$4)`,
        [site.id, a.type, a.ref, JSON.stringify({ iface: a.iface || null })]
      );
    }
    await dbClient.query('COMMIT');
    return { ...site, artifacts: appliedArtifacts };
  } catch (dbErr) {
    await dbClient.query('ROLLBACK').catch(() => {});
    await compensate(client, appliedArtifacts, input);
    throw dbErr;
  } finally {
    dbClient.release();
  }
}

// deleteSite reverses the artifacts. Runs best-effort per-artifact;
// any per-artifact failure logs but doesn't block DB removal — a
// ghost agent rule gets cleaned up on next boot's Restore.
async function deleteSite(serverId, siteId) {
  const { rows } = await pool.query(
    'SELECT * FROM sites WHERE id = $1 AND server_id = $2',
    [siteId, serverId]
  );
  if (rows.length === 0) {
    throw Object.assign(new Error('Site not found'), { status: 404 });
  }
  const site = rows[0];

  const { rows: artifacts } = await pool.query(
    'SELECT * FROM site_artifacts WHERE site_id = $1',
    [siteId]
  );

  // Reverse into the canonical rollback order so e.g. NAT comes off
  // before the route it depends on.
  const ordered = orderForRollback(artifacts);
  const client = new AgentClient(serverId);
  for (const a of ordered) {
    try {
      await undoArtifact(client, site, a);
    } catch (err) {
      console.error(`[siteOrchestrator] undo ${a.artifact_type}/${a.artifact_ref}:`, err.message);
    }
  }

  // Cascade delete in DB — site_artifacts has ON DELETE CASCADE.
  await pool.query('DELETE FROM sites WHERE id = $1 AND server_id = $2',
    [siteId, serverId]);
  return { deleted: true };
}

// ---- helpers ----

function validateInput(input) {
  if (!input.name) throw Object.assign(new Error('name is required'), { status: 400 });
  if (!input.localIface) throw Object.assign(new Error('localIface is required'), { status: 400 });
  if (!input.remoteSubnet) throw Object.assign(new Error('remoteSubnet is required'), { status: 400 });
  if (input.enableNat && !input.localSubnet) {
    throw Object.assign(new Error('enable_nat requires local_subnet'), { status: 400 });
  }
}

function commaSplit(s) {
  return (s || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

async function compensate(client, applied, input) {
  // Compensate in reverse order — later artifacts may depend on earlier ones.
  for (const a of [...applied].reverse()) {
    try {
      await undoArtifact(client, { name: input.name, local_iface: input.localIface,
        remote_peer_pubkey: input.remotePeerPubkey, remote_subnet: input.remoteSubnet }, {
        artifact_type: a.type, artifact_ref: a.ref, details: { iface: a.iface || null },
      });
    } catch (err) {
      console.error(`[siteOrchestrator] compensation ${a.type}/${a.ref}:`, err.message);
    }
  }
}

// undoArtifact walks a single artifact back. Paired with the factory
// calls in createSite — every artifact type added there needs an
// entry here.
async function undoArtifact(client, site, artifact) {
  switch (artifact.artifact_type) {
    case ARTIFACT.PEER: {
      // Strip remote_subnet from the peer's AllowedIPs.
      if (!site.remote_peer_pubkey) return;
      const peers = await client.listPeers(site.local_iface);
      const found = (peers.peers || peers || []).find(
        (p) => p.publicKey === site.remote_peer_pubkey
      );
      if (!found) return;
      const kept = commaSplit(found.allowedIPs || '').filter(
        (c) => c !== artifact.artifact_ref
      );
      await client.setPeerAllowedIPs(
        site.local_iface,
        site.remote_peer_pubkey,
        kept.join(', ')
      );
      return;
    }
    case ARTIFACT.ROUTE: {
      const iface = artifact.details?.iface || site.local_iface;
      await client.routerRemoveRoute(iface, artifact.artifact_ref);
      return;
    }
    case ARTIFACT.NAT:
      await client.natRemoveRule(artifact.artifact_ref);
      return;
    case ARTIFACT.POLICY:
      await client.routerRemovePolicy(artifact.artifact_ref);
      return;
    default:
      // Unknown artifact type — log and move on. Happens if schema
      // evolved and an old row predates the new artifact class.
      console.warn(`[siteOrchestrator] unknown artifact type ${artifact.artifact_type}`);
  }
}

function orderForRollback(artifacts) {
  const bucketed = Object.fromEntries(ROLLBACK_ORDER.map((t) => [t, []]));
  for (const a of artifacts) {
    if (bucketed[a.artifact_type]) bucketed[a.artifact_type].push(a);
  }
  const out = [];
  for (const t of ROLLBACK_ORDER) out.push(...bucketed[t]);
  return out;
}

module.exports = { createSite, deleteSite, ARTIFACT };
