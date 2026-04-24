// Migrate an entire server's state (interfaces, peers, subnets, firewall,
// DNS, assignments, static IPs, advanced routing) from one agent to another.
//
// Invariants the caller relies on:
//   * Destination must be EMPTY (interfaces/peers/subnets/custom zones/aliases
//     all zero). Any resource found on dest aborts with 409 before we touch
//     anything.
//   * On any failure mid-flight we roll back every resource we created in
//     reverse order. Rollback is best-effort — its errors are logged but
//     don't mask the original failure.
//   * Source is untouched. We only READ from it.
//
// The orchestrator is a short-lived instance per migration run; do not
// reuse across requests.
const AgentClient = require('./agentClient');
const registry = require('./wsAgentRegistry');
const { pool } = require('../db/pool');
const { createLogicalRule } = require('./ruleOrchestrator');

const IFACE_NAME_RE = /^[A-Za-z0-9_-]{1,15}$/;

class Migrator {
  /**
   * @param {object} opts
   * @param {number} opts.sourceId
   * @param {number} opts.destId
   * @param {Object<string,string>} [opts.renameInterfacesFrom] map of source-iface → dest-iface
   * @param {boolean} [opts.dryRun] if true, validate and return the planned steps without applying
   */
  constructor({ sourceId, destId, renameInterfacesFrom = {}, dryRun = false }) {
    this.sourceId = sourceId;
    this.destId = destId;
    this.rename = renameInterfacesFrom || {};
    this.dryRun = !!dryRun;

    this.src = new AgentClient(sourceId);
    this.dst = new AgentClient(destId);

    // Steps reported back to the caller (success, skipped, or failed).
    this.steps = [];
    // Resources created on dest — popped in reverse on rollback.
    this.undoLog = [];
    // Remaps built during the run. Written only on non-dryRun.
    this.ifaceNameMap = {};   // sourceIface -> destIface
    this.subnetIdMap = {};    // sourceSubnetId -> destSubnetId
    this.zoneIdMap = {};      // sourceZoneId -> destZoneId
    this.aliasIdMap = {};     // sourceAliasId -> destAliasId

    this.rollbackErrors = [];
  }

  // -------------------------------------------------------------------------
  // Public entry
  // -------------------------------------------------------------------------

  async run() {
    await this.checkPreconditions();

    try {
      // Order is load-bearing:
      //   Interfaces first so wg is listening.
      //   Subnets before Peers so peers_meta.subnet_id can remap.
      //   Zones before Rules so rule.srcZoneId/dstZoneId remap resolves.
      await this.stepInterfaces();
      await this.stepSubnets();
      await this.stepPeers();
      await this.stepZones();
      await this.stepAliases();
      await this.stepFirewallPolicy();
      await this.stepFirewallRules();
      await this.stepDNS();
      await this.stepAssignments();
      await this.stepStaticIPs();
      await this.stepAdvancedRouting();
    } catch (err) {
      // Log BEFORE rollback — rollback can produce its own errors and blur
      // which step actually triggered the abort. Gives journalctl a clear
      // pre-rollback stack trace even when the response is later read only
      // in the iOS UI (where it may be truncated).
      console.error(`[migrate] step failed, rolling back — source=${this.sourceId} dest=${this.destId}`);
      console.error(`[migrate] error: ${err.message}`);
      if (err.stack) console.error(err.stack);
      console.error(`[migrate] completed steps so far:`, JSON.stringify(this.steps, null, 2));

      // Abort + rollback. Don't mask the original error.
      if (!this.dryRun) await this.rollback();

      if (this.rollbackErrors.length > 0) {
        console.error(`[migrate] rollback errors:`, JSON.stringify(this.rollbackErrors, null, 2));
      }

      return {
        dryRun: this.dryRun,
        steps: this.steps,
        rollback: true,
        errors: [{ message: err.message, stack: err.stack, rollbackErrors: this.rollbackErrors }],
      };
    }

    return {
      dryRun: this.dryRun,
      steps: this.steps,
      rollback: false,
      errors: [],
      summary: this.summarize(),
    };
  }

  // -------------------------------------------------------------------------
  // Preconditions
  // -------------------------------------------------------------------------

  async checkPreconditions() {
    if (this.sourceId === this.destId) {
      throw mk409('Source and destination are the same server');
    }

    const { rows: srcRows } = await pool.query(
      'SELECT id, name, status, enterprise_id FROM servers WHERE id = $1', [this.sourceId]
    );
    if (srcRows.length === 0) throw mk404('Source server not found');
    const source = srcRows[0];
    if (source.status !== 'active') throw mk409(`Source server status is "${source.status}", must be active`);

    const { rows: dstRows } = await pool.query(
      'SELECT id, name, status, enterprise_id FROM servers WHERE id = $1', [this.destId]
    );
    if (dstRows.length === 0) throw mk404('Destination server not found');
    const dest = dstRows[0];
    if (dest.status !== 'active') throw mk409(`Destination server status is "${dest.status}", must be active`);

    // Enterprise: route-level guard already restricts to root, who can
    // legitimately move a server across enterprises. Users are global
    // (users.id has no enterprise FK), so user_server_assignments still
    // copies cleanly regardless of source/dest enterprise.

    const online = new Set(registry.getAllOnlineServerIds());
    if (!online.has(this.sourceId)) throw mk409('Source agent is offline');
    if (!online.has(this.destId)) throw mk409('Destination agent is offline');

    // Dest empty — check both agent-side (live interfaces) and DB (subnets,
    // peers_meta, custom zones, aliases). The agent check catches cases
    // where an interface exists on disk without a DB subnet row.
    const destIfaces = await this.dst.listInterfaces();
    const destIfaceCount = (destIfaces?.interfaces || []).length;
    const { rows: counts } = await pool.query(
      `SELECT
         (SELECT count(*) FROM subnets WHERE server_id = $1) AS subnets,
         (SELECT count(*) FROM peers_meta WHERE server_id = $1) AS peers,
         (SELECT count(*) FROM firewall_zones WHERE server_id = $1 AND builtin = false) AS zones,
         (SELECT count(*) FROM firewall_aliases WHERE server_id = $1) AS aliases,
         (SELECT count(*) FROM user_server_assignments WHERE server_id = $1) AS assignments`,
      [this.destId]
    );
    const c = counts[0];
    const dirty = [];
    if (destIfaceCount > 0) dirty.push(`${destIfaceCount} interface(s)`);
    if (parseInt(c.subnets, 10) > 0) dirty.push(`${c.subnets} subnet(s)`);
    if (parseInt(c.peers, 10) > 0) dirty.push(`${c.peers} peer(s)`);
    if (parseInt(c.zones, 10) > 0) dirty.push(`${c.zones} custom zone(s)`);
    if (parseInt(c.aliases, 10) > 0) dirty.push(`${c.aliases} alias(es)`);
    if (parseInt(c.assignments, 10) > 0) dirty.push(`${c.assignments} user assignment(s)`);
    if (dirty.length > 0) {
      throw mk409(`Destination is not empty: ${dirty.join(', ')}`);
    }
  }

  // -------------------------------------------------------------------------
  // Step 1: Interfaces — keep private key generation to dest agent
  // -------------------------------------------------------------------------

  async stepInterfaces() {
    const list = await this.src.listInterfaces();
    const ifaces = list?.interfaces || [];

    for (const name of ifaces) {
      const destName = this.resolveDestIfaceName(name);
      this.ifaceNameMap[name] = destName;
      if (this.dryRun) {
        this.steps.push({ resource: 'interface', name, destRef: destName, status: 'planned' });
        continue;
      }
      const info = await this.src.getInterface(name);
      // createInterface payload mirrors the POST /interfaces body the iOS
      // admin sends, but strips anything we don't want to carry across (DNS
      // uses gateway IP on dest anyway; private key is generated dest-side).
      // Coerce numeric fields — source may return them as strings (wg-quick
      // parses from .conf as text). The FreeBSD agent has strict Go typing
      // and rejects string-typed mtu/port with "cannot unmarshal string".
      const mtuNum = info.mtu != null && info.mtu !== '' ? Number(info.mtu) : undefined;
      const payload = {
        name: destName,
        listenPort: info.listenPort ? Number(info.listenPort) : undefined,
        address: firstCIDR(info.address),
        mtu: Number.isFinite(mtuNum) && mtuNum > 0 ? mtuNum : undefined,
      };
      await this.dst.createInterface(payload);
      this.pushUndo(async () => {
        try { await this.dst.deleteInterface(destName); } catch {}
      });
      this.steps.push({ resource: 'interface', name, destRef: destName, status: 'created' });
    }
  }

  // Pick a dest name: explicit rename map wins; otherwise keep source name if
  // FreeBSD-safe; otherwise auto-derive.
  resolveDestIfaceName(source) {
    if (this.rename[source]) return this.rename[source];
    if (IFACE_NAME_RE.test(source)) return source;
    const stripped = source.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 15);
    return stripped || 'iface0';
  }

  // -------------------------------------------------------------------------
  // Step 3: Peers — WG config + peers_meta (covers both "manual" admin-added
  // peers and "auto" peers created by app-api when a client connects)
  // -------------------------------------------------------------------------
  //
  // Two classes of peers live in peers_meta:
  //   * manual: device_id = NULL (admin pasted a pubkey via iOS admin)
  //   * auto:   device_id = <uuid> (app-api created when a client did
  //             POST /api/connect). These have user_id set too.
  // We copy both indiscriminately — the distinction is preserved by
  // whatever columns we carry over (device_id, user_id, expires_at, ...).
  //
  // PSK caveat: Node agent's listPeers returns `presharedKey: true|false`
  // instead of the actual key (security hardening). Cross-agent copy
  // cannot preserve the PSK — the peer reconnects without PSK until the
  // admin rotates. Same-agent upgrades (Go→Go) preserve it.

  async stepPeers() {
    for (const [srcIface, destIface] of Object.entries(this.ifaceNameMap)) {
      const resp = this.dryRun
        ? await this.src.listPeers(srcIface).catch(() => ({ peers: [] }))
        : await this.src.listPeers(srcIface);
      const peers = resp?.peers || [];

      // Preload peers_meta rows for this source iface so we can copy
      // device_id/user_id/expires_at/alias/notes. Key by public_key.
      const metaByKey = {};
      if (!this.dryRun) {
        const { rows: metas } = await pool.query(
          `SELECT public_key, subnet_id, alias, notes, device_id, user_id,
                  expires_at, allowed_source_ip, is_expired
             FROM peers_meta
            WHERE server_id = $1 AND interface_name = $2`,
          [this.sourceId, srcIface]
        );
        for (const m of metas) metaByKey[m.public_key] = m;
      }

      for (const p of peers) {
        const pub = p.publicKey || p.pubkey;
        if (!pub) continue;

        if (this.dryRun) {
          this.steps.push({ resource: 'peer', iface: destIface, publicKey: pub, status: 'planned' });
          continue;
        }

        // Agent side — wg-quick config. Coerce numeric fields: Node source
        // agents return them as strings (parsed from wg-quick conf text),
        // Go (BSD) dest rejects string with "cannot unmarshal".
        const kaRaw = p.persistentKeepalive ?? p.persistent_keepalive;
        const kaNum = kaRaw != null && kaRaw !== '' ? Number(kaRaw) : undefined;
        await this.dst.addPeer(destIface, {
          publicKey: pub,
          allowedIPs: p.allowedIPs || p.allowed_ips || '',
          // PSK: pass through only if source returned a real string. Node's
          // listPeers returns a bool here so we skip it — not copyable.
          presharedKey: typeof p.presharedKey === 'string' ? p.presharedKey : undefined,
          endpoint: p.endpoint || undefined,
          persistentKeepalive: Number.isFinite(kaNum) && kaNum > 0 ? kaNum : undefined,
          alias: p.alias || undefined,
        });
        this.pushUndo(async () => {
          try { await this.dst.removePeer(destIface, pub); } catch {}
        });
        // Alias is included in addPeer above, but older agents might not
        // honor it — double-write via renamePeerAlias to be safe.
        if (p.alias) {
          try { await this.dst.renamePeerAlias(destIface, pub, p.alias); } catch {}
        }

        // DB side — peers_meta row
        const meta = metaByKey[pub] || {};
        const destSubnetId = meta.subnet_id ? this.subnetIdMap[meta.subnet_id] : null;
        const { rows: ins } = await pool.query(
          `INSERT INTO peers_meta
             (server_id, interface_name, public_key, subnet_id, alias, notes,
              device_id, user_id, expires_at, allowed_source_ip, is_expired)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id`,
          [
            this.destId, destIface, pub, destSubnetId,
            meta.alias || '', meta.notes || '',
            meta.device_id || null, meta.user_id || null,
            meta.expires_at || null, meta.allowed_source_ip || null,
            meta.is_expired || false,
          ]
        );
        const newMetaId = ins[0].id;
        this.pushUndo(async () => {
          try { await pool.query('DELETE FROM peers_meta WHERE id = $1', [newMetaId]); } catch {}
        });

        this.steps.push({
          resource: 'peer',
          iface: destIface,
          publicKey: pub,
          kind: meta.device_id ? 'auto' : 'manual',
          status: 'created',
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 2: Subnets — DB rows + push gateway IPs to dest agent
  // -------------------------------------------------------------------------

  async stepSubnets() {
    const { rows } = await pool.query(
      'SELECT id, interface_name, cidr, name, description FROM subnets WHERE server_id = $1 ORDER BY id',
      [this.sourceId]
    );
    const touchedIfaces = new Set();
    for (const s of rows) {
      // Skip orphan subnets whose source interface no longer exists on the
      // agent (stepInterfaces only maps interfaces it actually created on
      // dest — anything in DB but not on source agent is dead weight).
      if (!this.ifaceNameMap[s.interface_name]) {
        this.steps.push({
          resource: 'subnet', cidr: s.cidr, iface: s.interface_name,
          status: 'skipped', reason: 'source interface missing on agent',
        });
        continue;
      }
      const destIface = this.ifaceNameMap[s.interface_name];
      if (this.dryRun) {
        this.steps.push({ resource: 'subnet', cidr: s.cidr, iface: destIface, status: 'planned' });
        continue;
      }
      const { rows: ins } = await pool.query(
        `INSERT INTO subnets (server_id, interface_name, cidr, name, description)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [this.destId, destIface, s.cidr, s.name || '', s.description || '']
      );
      this.subnetIdMap[s.id] = ins[0].id;
      this.pushUndo(async () => {
        try { await pool.query('DELETE FROM subnets WHERE id = $1', [ins[0].id]); } catch {}
      });
      this.steps.push({ resource: 'subnet', cidr: s.cidr, iface: destIface, destId: ins[0].id, status: 'created' });
      touchedIfaces.add(destIface);
    }
    // Once all subnets are in the DB for a given iface, push the full address
    // list to the dest agent. The Linux code path for a fresh subnet insert
    // does this via routes/subnets.js:syncAddressesToAgent; we inline the
    // same logic to avoid a circular import.
    if (!this.dryRun) {
      for (const iface of touchedIfaces) {
        await this.pushGatewayAddressesToAgent(iface);
      }
    }
  }

  async pushGatewayAddressesToAgent(destIface) {
    const { rows } = await pool.query(
      'SELECT cidr FROM subnets WHERE server_id = $1 AND interface_name = $2 ORDER BY id',
      [this.destId, destIface]
    );
    const addresses = rows.map(r => gatewayFromCIDR(r.cidr)).filter(Boolean);
    if (addresses.length > 0) {
      await this.dst.setInterfaceAddresses(destIface, addresses);
    }
  }

  // -------------------------------------------------------------------------
  // Step 4: Custom firewall zones + members
  // -------------------------------------------------------------------------

  async stepZones() {
    const { rows: zones } = await pool.query(
      'SELECT id, name, description FROM firewall_zones WHERE server_id = $1 AND builtin = false ORDER BY id',
      [this.sourceId]
    );
    for (const z of zones) {
      if (this.dryRun) {
        this.steps.push({ resource: 'zone', name: z.name, status: 'planned' });
        continue;
      }
      const { rows: ins } = await pool.query(
        `INSERT INTO firewall_zones (server_id, name, description, builtin)
         VALUES ($1, $2, $3, false) RETURNING id`,
        [this.destId, z.name, z.description || '']
      );
      const newZoneId = ins[0].id;
      this.zoneIdMap[z.id] = newZoneId;
      this.pushUndo(async () => {
        try { await pool.query('DELETE FROM firewall_zones WHERE id = $1', [newZoneId]); } catch {}
      });
      // Copy members with member_value translated when it's an interface name.
      const { rows: members } = await pool.query(
        'SELECT member_type, member_value FROM firewall_zone_members WHERE zone_id = $1',
        [z.id]
      );
      for (const m of members) {
        let value = m.member_value;
        if (m.member_type === 'interface' && this.ifaceNameMap[value]) {
          value = this.ifaceNameMap[value];
        }
        await pool.query(
          `INSERT INTO firewall_zone_members (zone_id, member_type, member_value)
           VALUES ($1, $2, $3)`,
          [newZoneId, m.member_type, value]
        );
      }
      this.steps.push({ resource: 'zone', name: z.name, destId: newZoneId, memberCount: members.length, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Step 5: Firewall aliases
  // -------------------------------------------------------------------------

  async stepAliases() {
    const { rows: aliases } = await pool.query(
      'SELECT id, name, description, addresses FROM firewall_aliases WHERE server_id = $1 ORDER BY id',
      [this.sourceId]
    );
    for (const a of aliases) {
      if (this.dryRun) {
        this.steps.push({ resource: 'alias', name: a.name, status: 'planned' });
        continue;
      }
      const { rows: ins } = await pool.query(
        `INSERT INTO firewall_aliases (server_id, name, description, addresses)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [this.destId, a.name, a.description || '', a.addresses || []]
      );
      this.aliasIdMap[a.id] = ins[0].id;
      this.pushUndo(async () => {
        try { await pool.query('DELETE FROM firewall_aliases WHERE id = $1', [ins[0].id]); } catch {}
      });
      this.steps.push({ resource: 'alias', name: a.name, destId: ins[0].id, addressCount: (a.addresses || []).length, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Step 6: Firewall default policy
  // -------------------------------------------------------------------------

  async stepFirewallPolicy() {
    const policy = await this.src.firewallGetPolicy();
    const def = policy?.defaultPolicy || 'block_wan';
    if (this.dryRun) {
      this.steps.push({ resource: 'firewall-policy', defaultPolicy: def, status: 'planned' });
      return;
    }
    // Record the dest's prior policy so we can revert on rollback. Dest
    // starts empty → usually 'block_wan' default. Capture it to be safe.
    const prior = await this.dst.firewallGetPolicy().catch(() => ({ defaultPolicy: 'block_wan' }));
    await this.dst.firewallSetPolicy(def);
    this.pushUndo(async () => {
      try { await this.dst.firewallSetPolicy(prior.defaultPolicy || 'block_wan'); } catch {}
    });
    this.steps.push({ resource: 'firewall-policy', defaultPolicy: def, status: 'created' });
  }

  // -------------------------------------------------------------------------
  // Step 7: Firewall user rules — rebuild via createLogicalRule with id remap
  // -------------------------------------------------------------------------

  async stepFirewallRules() {
    const all = await this.src.firewallGetAllRules();
    const byIface = all?.interfaces || {};
    for (const [srcIface, rules] of Object.entries(byIface)) {
      const destIface = this.ifaceNameMap[srcIface] || srcIface;
      for (const r of rules) {
        if (this.dryRun) {
          this.steps.push({ resource: 'rule', iface: destIface, label: r.label, status: 'planned' });
          continue;
        }
        // Remap any zone/alias IDs baked into the rule body. User IDs stay
        // identical (users are shared across servers).
        const body = {
          ...r,
          srcZoneId: mapId(r.srcZoneId, this.zoneIdMap),
          dstZoneId: mapId(r.dstZoneId, this.zoneIdMap),
          srcAliasId: mapId(r.srcAliasId, this.aliasIdMap),
          dstAliasId: mapId(r.dstAliasId, this.aliasIdMap),
        };
        // Clear id/groupId from the source-side rule object so the dest
        // orchestrator generates a fresh groupId.
        delete body.id;
        delete body.groupId;
        const created = await createLogicalRule(this.destId, destIface, body);
        const newGroupId = created.groupId || created.id;
        this.pushUndo(async () => {
          try { await this.dst.firewallRemoveGroup(destIface, newGroupId); } catch {}
        });
        this.steps.push({ resource: 'rule', iface: destIface, label: r.label, destGroupId: newGroupId, status: 'created' });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Step 8: DNS filter per iface
  // -------------------------------------------------------------------------

  async stepDNS() {
    for (const [srcIface, destIface] of Object.entries(this.ifaceNameMap)) {
      let bl;
      try { bl = await this.src.dnsListBlocked(srcIface); }
      catch { bl = { domains: [], categories: {} }; }
      const domains = bl?.domains || [];
      const categories = bl?.categories || {};
      const hasAny = domains.length > 0 || Object.values(categories).some(Boolean);
      if (!hasAny) continue;

      if (this.dryRun) {
        this.steps.push({ resource: 'dns', iface: destIface, domainCount: domains.length, categoryCount: Object.keys(categories).filter(k => categories[k]).length, status: 'planned' });
        continue;
      }

      await this.dst.dnsEnable(destIface);
      this.pushUndo(async () => {
        try { await this.dst.dnsDisable(destIface); } catch {}
      });
      for (const domain of domains) {
        await this.dst.dnsBlockDomain(destIface, domain);
      }
      for (const [cat, on] of Object.entries(categories)) {
        if (on) await this.dst.dnsEnableCategory(destIface, cat);
      }
      // No per-domain/-category undo — the dnsDisable undo above wipes the
      // interface's matcher state on rollback, and the JSON file gets orphaned
      // but is harmless (next migration would overwrite). Skipping per-item
      // undo keeps the undo log a manageable size on servers with 10k+ blocked
      // domains.
      this.steps.push({ resource: 'dns', iface: destIface, domainCount: domains.length, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Step 9: user_server_assignments — users are global, just add dest rows
  // -------------------------------------------------------------------------

  async stepAssignments() {
    const { rows } = await pool.query(
      'SELECT user_id, interface_name, subnet_id FROM user_server_assignments WHERE server_id = $1',
      [this.sourceId]
    );
    for (const a of rows) {
      const destIface = this.ifaceNameMap[a.interface_name] || a.interface_name;
      const destSubnet = a.subnet_id ? this.subnetIdMap[a.subnet_id] : null;
      if (this.dryRun) {
        this.steps.push({ resource: 'assignment', userId: a.user_id, iface: destIface, status: 'planned' });
        continue;
      }
      // Unique constraint (user_id, server_id, interface_name) guarantees
      // idempotency via ON CONFLICT DO NOTHING. If somebody already ran
      // migrate partially we silently skip dupes rather than fail.
      const { rows: ins } = await pool.query(
        `INSERT INTO user_server_assignments (user_id, server_id, interface_name, subnet_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (user_id, server_id, interface_name) DO NOTHING
         RETURNING id`,
        [a.user_id, this.destId, destIface, destSubnet]
      );
      if (ins.length > 0) {
        const newId = ins[0].id;
        this.pushUndo(async () => {
          try { await pool.query('DELETE FROM user_server_assignments WHERE id = $1', [newId]); } catch {}
        });
      }
      this.steps.push({ resource: 'assignment', userId: a.user_id, iface: destIface, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Step 10: device_static_ips — remap subnet_id
  // -------------------------------------------------------------------------

  async stepStaticIPs() {
    const { rows } = await pool.query(
      'SELECT device_id, subnet_id, ip_address, allowed_ips FROM device_static_ips WHERE server_id = $1',
      [this.sourceId]
    );
    for (const sip of rows) {
      const destSubnet = this.subnetIdMap[sip.subnet_id];
      if (!destSubnet) continue; // source subnet didn't copy — nothing to pin to
      if (this.dryRun) {
        this.steps.push({ resource: 'static-ip', deviceId: sip.device_id, ip: sip.ip_address, status: 'planned' });
        continue;
      }
      const { rows: ins } = await pool.query(
        `INSERT INTO device_static_ips (device_id, server_id, subnet_id, ip_address, allowed_ips)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (device_id, server_id, subnet_id) DO NOTHING
         RETURNING id`,
        [sip.device_id, this.destId, destSubnet, sip.ip_address, sip.allowed_ips || []]
      );
      if (ins.length > 0) {
        const newId = ins[0].id;
        this.pushUndo(async () => {
          try { await pool.query('DELETE FROM device_static_ips WHERE id = $1', [newId]); } catch {}
        });
      }
      this.steps.push({ resource: 'static-ip', deviceId: sip.device_id, ip: sip.ip_address, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Step 11: Advanced routing — routes, nat_rules, sites, local port forwards
  // -------------------------------------------------------------------------

  async stepAdvancedRouting() {
    await this.copyTable('routes',
      ['iface', 'destination', 'gateway', 'metric', 'fib', 'description', 'enabled'],
      (row) => ({ ...row, iface: this.ifaceNameMap[row.iface] || row.iface }));

    await this.copyTable('nat_rules',
      ['name', 'wan_iface', 'src_cidr', 'nat_to', 'protocol', 'description', 'enabled'],
      (row) => row);

    await this.copyTable('sites',
      ['name', 'description', 'local_iface', 'local_subnet', 'remote_peer_pubkey',
       'remote_subnet', 'remote_gateway', 'enable_nat', 'policy_fib', 'enabled'],
      (row) => ({ ...row, local_iface: this.ifaceNameMap[row.local_iface] || row.local_iface }));

    await this.copyTable('server_local_port_forwards',
      ['name', 'local_port', 'remote_host', 'remote_port', 'description', 'enabled', 'visibility'],
      (row) => row);
  }

  async copyTable(table, columns, transform) {
    const { rows } = await pool.query(
      `SELECT ${columns.join(', ')} FROM ${table} WHERE server_id = $1 ORDER BY id`,
      [this.sourceId]
    );
    for (const row of rows) {
      const transformed = transform ? transform(row) : row;
      if (this.dryRun) {
        this.steps.push({ resource: table.replace(/_/g, '-'), status: 'planned' });
        continue;
      }
      const placeholders = columns.map((_, i) => `$${i + 2}`).join(', ');
      const values = columns.map(c => transformed[c]);
      const { rows: ins } = await pool.query(
        `INSERT INTO ${table} (server_id, ${columns.join(', ')})
         VALUES ($1, ${placeholders}) RETURNING id`,
        [this.destId, ...values]
      );
      const newId = ins[0].id;
      this.pushUndo(async () => {
        try { await pool.query(`DELETE FROM ${table} WHERE id = $1`, [newId]); } catch {}
      });
      this.steps.push({ resource: table.replace(/_/g, '-'), destId: newId, status: 'created' });
    }
  }

  // -------------------------------------------------------------------------
  // Rollback
  // -------------------------------------------------------------------------

  pushUndo(fn) { this.undoLog.push(fn); }

  async rollback() {
    // Reverse order so children are undone before parents (e.g. rules before
    // zones, members before zone owners).
    for (let i = this.undoLog.length - 1; i >= 0; i--) {
      try { await this.undoLog[i](); }
      catch (err) { this.rollbackErrors.push(err.message); }
    }
    // Mark previously-"created" steps as rolled back so the UI renders them
    // differently.
    for (const s of this.steps) {
      if (s.status === 'created') s.status = 'rolled-back';
    }
  }

  // -------------------------------------------------------------------------
  // Summary for the response
  // -------------------------------------------------------------------------

  summarize() {
    const by = {};
    for (const s of this.steps) {
      by[s.resource] = (by[s.resource] || 0) + 1;
    }
    return by;
  }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

function mk404(msg) { return Object.assign(new Error(msg), { status: 404 }); }
function mk409(msg) { return Object.assign(new Error(msg), { status: 409 }); }

// Pick the first CIDR from a comma-separated "10.0.0.1/24, fd00::/64" string.
// createInterface wants a single address; the full list is carried by
// subnets + setInterfaceAddresses which runs under the hood in step 3.
function firstCIDR(addr) {
  if (!addr) return '';
  const parts = String(addr).split(',').map(s => s.trim()).filter(Boolean);
  return parts[0] || '';
}

function mapId(value, map) {
  if (value == null) return value;
  return map[value] != null ? map[value] : value;
}

// Convert a network CIDR like "10.88.0.0/24" into the gateway form the agent
// expects as an Address line: "10.88.0.1/24". Mirrors routes/subnets.js.
function gatewayFromCIDR(cidr) {
  if (!cidr) return '';
  const [network, prefix] = String(cidr).split('/');
  if (!network || !prefix) return '';
  const parts = network.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return '';
  parts[3] = 1;
  return `${parts.join('.')}/${prefix}`;
}

/** Convenience: run one migration. */
async function migrateServer(opts) {
  const m = new Migrator(opts);
  return await m.run();
}

module.exports = { migrateServer, Migrator };
