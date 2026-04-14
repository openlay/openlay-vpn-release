const crypto = require('crypto');
const { X509Certificate } = require('crypto');
const { pool } = require('../db/pool');

const CA_VALIDITY_YEARS = 10;
const AGENT_CERT_VALIDITY_DAYS = 365;

/**
 * Internal CA for signing agent certificates.
 * CA keypair stored in ca_config DB table.
 */
class CAManager {
  constructor() {
    this.caKey = null;    // crypto.KeyObject (private)
    this.caCert = null;   // PEM string
    this.serial = 0;
  }

  /**
   * Initialize CA — load from DB or generate new.
   */
  async init() {
    const { rows } = await pool.query('SELECT key, value FROM ca_config');
    const config = {};
    for (const row of rows) config[row.key] = row.value;

    if (config.ca_private_key && config.ca_certificate) {
      // Load existing CA
      this.caKey = crypto.createPrivateKey(config.ca_private_key);
      this.caCert = config.ca_certificate;
      this.serial = parseInt(config.ca_serial_counter || '1', 10);
      console.log('[CA] Loaded existing CA certificate');
    } else {
      // Generate new CA
      await this._generateCA();
      console.log('[CA] Generated new CA certificate (valid 10 years)');
    }
  }

  async _generateCA() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    // Self-signed CA cert using native Node.js X509 (Node 20+)
    // Node.js doesn't have native cert generation — use openssl via child_process
    const { execSync } = require('child_process');
    const fs = require('fs');
    const os = require('os');
    const path = require('path');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ca-'));
    const keyPath = path.join(tmpDir, 'ca.key');
    const certPath = path.join(tmpDir, 'ca.crt');

    // Write private key
    const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.writeFileSync(keyPath, keyPem, { mode: 0o600 });

    // Generate self-signed CA cert
    execSync(`openssl req -new -x509 -key "${keyPath}" -out "${certPath}" \
      -days ${CA_VALIDITY_YEARS * 365} -subj "/CN=OpenLayVPN Internal CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"`, { stdio: 'pipe' });

    this.caCert = fs.readFileSync(certPath, 'utf8');
    this.caKey = privateKey;
    this.serial = 1;

    // Clean up temp files
    fs.rmSync(tmpDir, { recursive: true });

    // Store in DB
    await this._saveConfig('ca_private_key', keyPem);
    await this._saveConfig('ca_certificate', this.caCert);
    await this._saveConfig('ca_serial_counter', '1');
  }

  /**
   * Sign a CSR and return agent certificate.
   * @param {string} csrPem — PEM-encoded CSR from agent
   * @param {string} agentId — e.g. "aws-i-08ac..."
   * @returns {{ cert: string, serial: string, fingerprint: string, expiresAt: Date }}
   */
  async signCSR(csrPem, agentId) {
    const { execSync } = require('child_process');
    const fs = require('fs');
    const os = require('os');
    const path = require('path');

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sign-'));
    const caKeyPath = path.join(tmpDir, 'ca.key');
    const caCertPath = path.join(tmpDir, 'ca.crt');
    const csrPath = path.join(tmpDir, 'agent.csr');
    const certPath = path.join(tmpDir, 'agent.crt');
    const extPath = path.join(tmpDir, 'ext.cnf');

    try {
      // Write CA files
      fs.writeFileSync(caKeyPath, this.caKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      fs.writeFileSync(caCertPath, this.caCert);
      fs.writeFileSync(csrPath, csrPem);

      // Extensions config — embed agentId in SAN
      fs.writeFileSync(extPath, `
[agent]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyAgreement
extendedKeyUsage = clientAuth
subjectAltName = URI:urn:openlayvpn:agent:${agentId}
`);

      // Increment serial
      this.serial++;
      const serialHex = this.serial.toString(16).padStart(8, '0');
      await this._saveConfig('ca_serial_counter', String(this.serial));

      // Sign CSR
      execSync(`openssl x509 -req \
        -in "${csrPath}" \
        -CA "${caCertPath}" -CAkey "${caKeyPath}" \
        -set_serial 0x${serialHex} \
        -days ${AGENT_CERT_VALIDITY_DAYS} \
        -extfile "${extPath}" -extensions agent \
        -out "${certPath}"`, { stdio: 'pipe' });

      const certPem = fs.readFileSync(certPath, 'utf8');

      // Calculate fingerprint
      const certDer = crypto.createPublicKey(certPem); // just for parsing
      const x509 = new X509Certificate(certPem);
      const fingerprint = crypto.createHash('sha256')
        .update(Buffer.from(x509.raw))
        .digest('hex');

      const expiresAt = new Date();
      expiresAt.setDate(expiresAt.getDate() + AGENT_CERT_VALIDITY_DAYS);

      return {
        cert: certPem,
        serial: serialHex,
        fingerprint,
        expiresAt,
      };
    } finally {
      fs.rmSync(tmpDir, { recursive: true });
    }
  }

  /**
   * Verify an agent certificate was signed by our CA.
   * @param {string} certPem
   * @returns {{ valid: boolean, agentId: string|null, fingerprint: string|null }}
   */
  verifyCert(certPem) {
    try {
      const x509 = new X509Certificate(certPem);
      const caX509 = new X509Certificate(this.caCert);

      // Verify signature chain
      if (!x509.verify(caX509.publicKey)) {
        return { valid: false, agentId: null, fingerprint: null };
      }

      // Check expiry
      if (new Date(x509.validTo) < new Date()) {
        return { valid: false, agentId: null, fingerprint: null, reason: 'expired' };
      }

      // Extract agentId from SAN URI
      const san = x509.subjectAltName || '';
      const uriMatch = san.match(/URI:urn:openlayvpn:agent:(.+)/);
      const agentId = uriMatch ? uriMatch[1] : null;

      // Fallback: extract from CN
      const cnMatch = x509.subject.match(/CN=agent-(.+)/);
      const agentIdFromCN = cnMatch ? cnMatch[1] : null;

      const fingerprint = crypto.createHash('sha256')
        .update(Buffer.from(x509.raw))
        .digest('hex');

      return {
        valid: true,
        agentId: agentId || agentIdFromCN,
        fingerprint,
      };
    } catch (err) {
      console.error('[CA] Cert verification error:', err.message);
      return { valid: false, agentId: null, fingerprint: null };
    }
  }

  /**
   * Check if a certificate fingerprint is revoked.
   */
  async isRevoked(fingerprint) {
    const { rows } = await pool.query(
      'SELECT 1 FROM agent_certificates WHERE fingerprint = $1 AND revoked = TRUE',
      [fingerprint]
    );
    return rows.length > 0;
  }

  /**
   * Get CA certificate PEM (for agents to verify management server).
   */
  getCACert() {
    return this.caCert;
  }

  async _saveConfig(key, value) {
    await pool.query(
      `INSERT INTO ca_config (key, value) VALUES ($1, $2)
       ON CONFLICT (key) DO UPDATE SET value = $2`,
      [key, value]
    );
  }
}

const caManager = new CAManager();
module.exports = caManager;
