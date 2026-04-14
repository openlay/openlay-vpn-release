const { Router } = require('express');
const { spawn } = require('child_process');
const enterpriseContext = require('../../middleware/enterpriseContext');
const pkg = require('../../../package.json');

const router = Router();
router.use(enterpriseContext);

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

  // Spawn update AFTER response is sent — update.sh will kill this process
  setImmediate(() => {
    const child = spawn('bash', ['-c',
      'cd /opt/openlay-vpn-release && git pull && cd olv-management/linux && bash update.sh'
    ], { detached: true, stdio: 'ignore' });
    child.unref();
  });
});

module.exports = router;
