const { Router } = require('express');
const { pool } = require('../db/pool');

const router = Router();

// POST /api/devices — Register a new device
router.post('/', async (req, res) => {
  try {
    const { name, os, osVersion, publicKey } = req.body;

    if (!os || !publicKey) {
      return res.status(400).json({ error: 'os and publicKey are required' });
    }

    const validOs = ['macos', 'ios', 'windows', 'android'];
    if (!validOs.includes(os)) {
      return res.status(400).json({ error: `os must be one of: ${validOs.join(', ')}` });
    }

    // Check if device with same public key already exists for this user
    const { rows: existing } = await pool.query(
      'SELECT * FROM devices WHERE public_key = $1 AND user_id = $2',
      [publicKey, req.user.id]
    );

    if (existing.length > 0) {
      return res.json({ device: existing[0] });
    }

    // Check require_device_approval setting (per-enterprise, fallback to global)
    const { rows: entRole } = await pool.query(
      'SELECT enterprise_id FROM user_enterprise_roles WHERE user_id = $1 LIMIT 1',
      [req.user.id]
    );
    const userEnterpriseId = entRole[0]?.enterprise_id;

    let requireApproval = false;
    if (userEnterpriseId) {
      const { rows: entSetting } = await pool.query(
        `SELECT value FROM enterprise_settings WHERE enterprise_id = $1 AND key = 'require_device_approval'`,
        [userEnterpriseId]
      );
      if (entSetting.length > 0) {
        requireApproval = entSetting[0].value === 'true';
      }
    }
    if (!requireApproval) {
      // Fallback to global setting
      const { rows: globalSetting } = await pool.query(
        `SELECT value FROM app_settings WHERE key = 'require_device_approval'`
      );
      requireApproval = globalSetting.length > 0 && globalSetting[0].value === 'true';
    }
    // Apple ID login always auto-approve; password login respects setting
    const { rows: userRows } = await pool.query('SELECT auth_type FROM users WHERE id = $1', [req.user.id]);
    const isAppleAuth = userRows[0]?.auth_type === 'apple';
    const deviceStatus = (isAppleAuth || !requireApproval) ? 'enabled' : 'pending';

    const { rows } = await pool.query(
      `INSERT INTO devices (name, os, os_version, public_key, status, user_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [name || '', os, osVersion || '', publicKey, deviceStatus, req.user.id]
    );

    res.status(201).json({ device: rows[0] });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// GET /api/devices — List my devices
router.get('/', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM devices WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ devices: rows });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// POST /api/devices/:deviceId/posture — Submit device posture snapshot
router.post('/:deviceId/posture', async (req, res) => {
  try {
    const deviceId = req.params.deviceId;

    const { rows: dev } = await pool.query(
      `SELECT d.id, uer.enterprise_id
       FROM devices d
       LEFT JOIN user_enterprise_roles uer ON uer.user_id = d.user_id
       WHERE d.id = $1 AND d.user_id = $2 LIMIT 1`,
      [deviceId, req.user.id]
    );
    if (dev.length === 0) return res.status(404).json({ error: 'Device not found' });
    const enterpriseId = dev[0].enterprise_id;

    let enabled = false;
    if (enterpriseId) {
      const { rows: setting } = await pool.query(
        `SELECT value FROM enterprise_settings WHERE enterprise_id = $1 AND key = 'posture_submission_enabled'`,
        [enterpriseId]
      );
      enabled = setting[0]?.value === 'true';
    }
    if (!enabled) return res.status(403).json({ error: 'Posture submission disabled' });

    const posture = (req.body && typeof req.body === 'object') ? req.body : {};
    const cols = extractPostureColumns(posture);
    const ip = (req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket?.remoteAddress || '').toString().split(',')[0].trim() || null;
    const ua = (req.headers['user-agent'] || '').toString().slice(0, 512) || null;

    await pool.query(
      `INSERT INTO device_postures (
         device_id, enterprise_id, posture,
         platform, os_version, os_build, app_version, app_build,
         kernel_release, device_model, device_name, hostname,
         hardware_model, hardware_serial, hardware_id,
         is_simulator, is_debug_build, is_developer_mode,
         is_biometry_enabled, biometry_type, is_root,
         uptime_seconds, thermal_state, is_low_power_mode, is_charging,
         battery_level, battery_state,
         free_disk_bytes, total_disk_bytes,
         physical_memory_bytes, free_memory_bytes,
         locale, timezone,
         is_jailbroken, is_disk_encrypted, is_passcode_set,
         is_filevault_on, is_sip_enabled, is_gatekeeper_on, mdm_enrolled,
         selinux_status, apparmor_enabled, firewall_state, process_count,
         is_bitlocker_on, defender_state, uac_enabled, domain_joined,
         is_secure_boot_on, is_tpm_present,
         submitted_from_ip, user_agent
       ) VALUES (
         $1, $2, $3,
         $4, $5, $6, $7, $8,
         $9, $10, $11, $12,
         $13, $14, $15,
         $16, $17, $18,
         $19, $20, $21,
         $22, $23, $24, $25,
         $26, $27,
         $28, $29,
         $30, $31,
         $32, $33,
         $34, $35, $36,
         $37, $38, $39, $40,
         $41, $42, $43, $44,
         $45, $46, $47, $48,
         $49, $50,
         $51, $52
       )`,
      [
        deviceId, enterpriseId, posture,
        cols.platform, cols.os_version, cols.os_build, cols.app_version, cols.app_build,
        cols.kernel_release, cols.device_model, cols.device_name, cols.hostname,
        cols.hardware_model, cols.hardware_serial, cols.hardware_id,
        cols.is_simulator, cols.is_debug_build, cols.is_developer_mode,
        cols.is_biometry_enabled, cols.biometry_type, cols.is_root,
        cols.uptime_seconds, cols.thermal_state, cols.is_low_power_mode, cols.is_charging,
        cols.battery_level, cols.battery_state,
        cols.free_disk_bytes, cols.total_disk_bytes,
        cols.physical_memory_bytes, cols.free_memory_bytes,
        cols.locale, cols.timezone,
        cols.is_jailbroken, cols.is_disk_encrypted, cols.is_passcode_set,
        cols.is_filevault_on, cols.is_sip_enabled, cols.is_gatekeeper_on, cols.mdm_enrolled,
        cols.selinux_status, cols.apparmor_enabled, cols.firewall_state, cols.process_count,
        cols.is_bitlocker_on, cols.defender_state, cols.uac_enabled, cols.domain_joined,
        cols.is_secure_boot_on, cols.is_tpm_present,
        ip, ua,
      ]
    );
    await pool.query(`UPDATE devices SET last_posture_at = NOW() WHERE id = $1`, [deviceId]);
    res.status(201).json({ ok: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

// Pull the well-known fields out of a posture payload into typed values
// for the extracted columns. Anything missing or wrong-typed becomes null
// so we never insert junk into the typed columns; the full untyped
// payload is still preserved in the JSONB column for forensic queries.
function extractPostureColumns(p) {
  const str = (v) => (typeof v === 'string' && v.length > 0 ? v.slice(0, 1024) : null);
  const bool = (v) => (typeof v === 'boolean' ? v : null);
  const int = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null);
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
  const big = (v) => {
    if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
    if (typeof v === 'string' && /^\d+$/.test(v)) return v;
    return null;
  };
  return {
    platform: str(p.platform),
    os_version: str(p.os_version),
    os_build: str(p.os_build),
    app_version: str(p.app_version),
    app_build: str(p.app_build),
    kernel_release: str(p.kernel_release),
    device_model: str(p.device_model),
    device_name: str(p.device_name),
    hostname: str(p.hostname),
    hardware_model: str(p.hardware_model),
    hardware_serial: str(p.hardware_serial),
    hardware_id: str(p.hardware_id),
    is_simulator: bool(p.is_simulator),
    is_debug_build: bool(p.is_debug_build),
    is_developer_mode: bool(p.is_developer_mode),
    is_biometry_enabled: bool(p.is_biometry_enabled),
    biometry_type: str(p.biometry_type),
    is_root: bool(p.is_root),
    uptime_seconds: big(p.uptime_seconds),
    thermal_state: str(p.thermal_state),
    is_low_power_mode: bool(p.is_low_power_mode),
    is_charging: bool(p.is_charging),
    battery_level: num(p.battery_level),
    battery_state: str(p.battery_state),
    free_disk_bytes: big(p.free_disk_bytes),
    total_disk_bytes: big(p.total_disk_bytes),
    physical_memory_bytes: big(p.physical_memory_bytes),
    free_memory_bytes: big(p.free_memory_bytes),
    locale: str(p.locale),
    timezone: str(p.timezone),
    is_jailbroken: bool(p.is_jailbroken),
    is_disk_encrypted: bool(p.is_disk_encrypted),
    is_passcode_set: bool(p.is_passcode_set),
    is_filevault_on: bool(p.is_filevault_on),
    is_sip_enabled: bool(p.is_sip_enabled),
    is_gatekeeper_on: bool(p.is_gatekeeper_on),
    mdm_enrolled: bool(p.mdm_enrolled),
    selinux_status: str(p.selinux_status),
    apparmor_enabled: bool(p.apparmor_enabled),
    firewall_state: str(p.firewall_state),
    process_count: int(p.process_count),
    is_bitlocker_on: bool(p.is_bitlocker_on),
    defender_state: str(p.defender_state),
    uac_enabled: bool(p.uac_enabled),
    domain_joined: bool(p.domain_joined),
    is_secure_boot_on: bool(p.is_secure_boot_on),
    is_tpm_present: bool(p.is_tpm_present),
  };
}

// PUT /api/devices/:deviceId — Update device name
router.put('/:deviceId', async (req, res) => {
  try {
    const { name } = req.body;
    const { rows } = await pool.query(
      `UPDATE devices SET name = $1, updated_at = NOW()
       WHERE id = $2 AND user_id = $3
       RETURNING *`,
      [name || '', req.params.deviceId, req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Device not found' });
    }

    res.json({ device: rows[0] });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
