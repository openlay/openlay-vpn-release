const { Router } = require('express');
const usersRouter = require('./users');
const devicesRouter = require('./devices');
const settingsRouter = require('./settings');
const versionRouter = require('./version');

const router = Router();

router.use('/users', usersRouter);
router.use('/devices', devicesRouter);
router.use('/settings', settingsRouter);
router.use('/version', versionRouter);

module.exports = router;
