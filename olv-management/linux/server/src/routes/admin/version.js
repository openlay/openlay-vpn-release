const { Router } = require('express');
const { spawn, execSync } = require('child_process');
const enterpriseContext = require('../../middleware/enterpriseContext');
const pkg = require('../../../package.json');

const router = Router();
router.use(enterpriseContext);

const ALLOWED_SERVICES = ['olv-management', 'olv-app-api'];

// GET /api/admin/version
router.get('/', (req, res) => {
  res.json({ version: pkg.version });
});

// POST /api/admin/version/update — root only
router.post('/update', (req, res) => {
  if (req.enterpriseRole !== 'root') {
    return res.status(403).json({ error: 'Root access required' });
  }

  res.json({ ok: true, message: 'Update started. Server will restart shortly.' });

  // Spawn update AFTER response is sent — update.sh will kill this process.
  // Run with sudo so systemctl/chown work even when the service user is not root.
  // Sudoers rule at /etc/sudoers.d/olv-management grants NOPASSWD for these commands.
  setImmediate(() => {
    const child = spawn('bash', ['-c',
      'sudo -n /usr/bin/git -C /opt/openlay-vpn-release pull && ' +
      'sudo -n /bin/bash /opt/openlay-vpn-release/olv-management/linux/update.sh'
    ], { detached: true, stdio: 'ignore' });
    child.unref();
  });
});

// GET /api/admin/version/logs?service=olv-management&lines=100 — root only
router.get('/logs', (req, res) => {
  if (req.enterpriseRole !== 'root') {
    return res.status(403).json({ error: 'Root access required' });
  }

  const service = ALLOWED_SERVICES.includes(req.query.service) ? req.query.service : 'olv-management';
  const lines = Math.min(Math.max(parseInt(req.query.lines) || 100, 10), 500);

  try {
    const output = execSync(
      `journalctl -u ${service} -n ${lines} --no-pager -o short-iso 2>&1`,
      { timeout: 5000, encoding: 'utf8' }
    );
    const logLines = output
      .split('\n')
      .filter(l => l.trim())
      .map(line => {
        // Parse: "2026-04-14T23:01:13+0000 hostname service[pid]: message"
        const match = line.match(/^(\S+)\s+\S+\s+\S+:\s+(.*)$/);
        if (match) {
          const message = match[2];
          const level = /error|fail|fatal/i.test(message) ? 'error'
            : /warn/i.test(message) ? 'warn' : 'info';
          return { timestamp: match[1], message, level };
        }
        return { timestamp: '', message: line, level: 'info' };
      });
    res.json({ service, lines: logLines, total: logLines.length });
  } catch (err) {
    res.json({ service, lines: [], total: 0, error: err.message });
  }
});

module.exports = router;
