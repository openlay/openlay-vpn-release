const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const config = require('../config');

const CERT_DIR = path.resolve(config.tlsCert ? path.dirname(config.tlsCert) : './certs');
const AGENT_KEY_PATH = path.join(CERT_DIR, 'agent.key');
const AGENT_CERT_PATH = path.join(CERT_DIR, 'agent.crt');
const CA_CERT_PATH = path.join(CERT_DIR, 'ca.crt');

class CertManager {
  /**
   * Check if agent has a valid enrolled certificate.
   * @param {string} currentAgentId — resolved agentId for this machine
   * @returns {{ enrolled: boolean, certMismatch: boolean }}
   */
  check(currentAgentId) {
    if (!fs.existsSync(AGENT_CERT_PATH) || !fs.existsSync(AGENT_KEY_PATH)) {
      return { enrolled: false, certMismatch: false };
    }

    try {
      const certPem = fs.readFileSync(AGENT_CERT_PATH, 'utf8');
      const x509 = new crypto.X509Certificate(certPem);

      // Check expiry
      if (new Date(x509.validTo) < new Date()) {
        console.log('[certManager] Agent cert expired');
        return { enrolled: false, certMismatch: false };
      }

      // Check agentId in SAN URI
      const san = x509.subjectAltName || '';
      const uriMatch = san.match(/URI:urn:openlayvpn:agent:(.+)/);
      const certAgentId = uriMatch ? uriMatch[1] : null;

      // Also check CN fallback
      const cnMatch = x509.subject.match(/CN=agent-(.+)/);
      const certAgentIdFromCN = cnMatch ? cnMatch[1] : null;

      const storedAgentId = certAgentId || certAgentIdFromCN;

      if (storedAgentId && storedAgentId !== currentAgentId) {
        // EC2 clone: different instance-id → cert invalid
        console.log(`[certManager] Agent ID mismatch: cert=${storedAgentId} current=${currentAgentId}`);
        return { enrolled: false, certMismatch: true };
      }

      // Check cert will expire within 30 days (needs renewal)
      const thirtyDaysFromNow = new Date(Date.now() + 30 * 24 * 3600 * 1000);
      if (new Date(x509.validTo) < thirtyDaysFromNow) {
        console.log('[certManager] Agent cert expiring soon, needs renewal');
        return { enrolled: false, certMismatch: false };
      }

      return { enrolled: true, certMismatch: false };
    } catch (err) {
      console.error('[certManager] Error reading cert:', err.message);
      return { enrolled: false, certMismatch: false };
    }
  }

  /**
   * Generate a CSR (Certificate Signing Request) for enrollment.
   * @param {string} agentId
   * @returns {{ csr: string, keyPem: string }}
   */
  generateCSR(agentId) {
    fs.mkdirSync(CERT_DIR, { recursive: true });

    // Generate EC P-256 keypair
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
    });

    const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    fs.writeFileSync(AGENT_KEY_PATH, keyPem, { mode: 0o600 });

    // Generate CSR via openssl (temp file — /dev/stdout blocked by systemd PrivateTmp)
    const os = require('os');
    const csrTmpPath = path.join(os.tmpdir(), `agent-${Date.now()}.csr`);
    execSync(
      `openssl req -new -key "${AGENT_KEY_PATH}" -subj "/CN=agent-${agentId}" -out "${csrTmpPath}"`,
      { stdio: 'pipe' }
    );
    const csrPem = fs.readFileSync(csrTmpPath, 'utf8');
    try { fs.unlinkSync(csrTmpPath); } catch {}

    console.log(`[certManager] Generated CSR for agent-${agentId}`);
    return { csr: csrPem, keyPem };
  }

  /**
   * Store signed certificate and CA cert received from management.
   * @param {string} agentCertPem
   * @param {string} caCertPem
   */
  storeCert(agentCertPem, caCertPem) {
    fs.mkdirSync(CERT_DIR, { recursive: true });
    fs.writeFileSync(AGENT_CERT_PATH, agentCertPem);
    fs.writeFileSync(CA_CERT_PATH, caCertPem);
    console.log(`[certManager] Agent cert stored: ${AGENT_CERT_PATH}`);
    console.log(`[certManager] CA cert stored: ${CA_CERT_PATH}`);
  }

  /**
   * Delete cert files (for re-enrollment after clone detection).
   */
  clearCerts() {
    for (const f of [AGENT_CERT_PATH, AGENT_KEY_PATH, CA_CERT_PATH]) {
      try { fs.unlinkSync(f); } catch {}
    }
    console.log('[certManager] Certs cleared for re-enrollment');
  }

  /**
   * Get cert/key paths for mutual TLS.
   */
  getCertPaths() {
    return {
      cert: AGENT_CERT_PATH,
      key: AGENT_KEY_PATH,
      ca: CA_CERT_PATH,
    };
  }

  /**
   * Check if cert files exist.
   */
  hasCert() {
    return fs.existsSync(AGENT_CERT_PATH) && fs.existsSync(AGENT_KEY_PATH);
  }

  /**
   * Read cert PEM.
   */
  readCert() {
    return fs.readFileSync(AGENT_CERT_PATH, 'utf8');
  }

  readKey() {
    return fs.readFileSync(AGENT_KEY_PATH, 'utf8');
  }

  readCA() {
    return fs.existsSync(CA_CERT_PATH) ? fs.readFileSync(CA_CERT_PATH, 'utf8') : null;
  }
}

module.exports = new CertManager();
