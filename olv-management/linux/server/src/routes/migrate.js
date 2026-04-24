// POST /api/servers/:destId/migrate-from/:sourceId — root-only server clone.
//
// Orchestrates a one-shot copy from `sourceId` to `destId`. The destination
// must be empty (see migrateOrchestrator for exact rules). Source is left
// alone — admin decides when to decommission it.

const { Router } = require('express');
const enterpriseContext = require('../middleware/enterpriseContext');
const { migrateServer } = require('../services/migrateOrchestrator');

const router = Router({ mergeParams: true });
router.use(enterpriseContext);

router.post('/:sourceId', async (req, res) => {
  try {
    if (req.enterpriseRole !== 'root') {
      return res.status(403).json({ error: 'Root access required' });
    }
    const destId = parseInt(req.params.destId, 10);
    const sourceId = parseInt(req.params.sourceId, 10);
    if (!Number.isInteger(destId) || !Number.isInteger(sourceId)) {
      return res.status(400).json({ error: 'destId and sourceId must be integers' });
    }
    const body = req.body || {};
    // Accept both camelCase and snake_case — iOS admin's APIClient uses
    // convertToSnakeCase so the body arrives as {dry_run, rename_interfaces_from}.
    const dryRunBody = body.dryRun ?? body.dry_run;
    const renameBody = body.renameInterfacesFrom ?? body.rename_interfaces_from;
    const result = await migrateServer({
      sourceId,
      destId,
      renameInterfacesFrom: renameBody || {},
      dryRun: !!dryRunBody || req.query.dryRun === 'true' || req.query.dryRun === '1',
    });
    // rollback=true means migration failed and the dest was reverted; return
    // 500 so iOS clearly surfaces the failure, but keep the body structured.
    const status = result.rollback ? 500 : 200;
    res.status(status).json(result);
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
