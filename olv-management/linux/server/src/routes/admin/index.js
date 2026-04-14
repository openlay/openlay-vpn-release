const { Router } = require('express');
const usersRouter = require('./users');
const devicesRouter = require('./devices');
const settingsRouter = require('./settings');

const router = Router();

router.use('/users', usersRouter);
router.use('/devices', devicesRouter);
router.use('/settings', settingsRouter);

module.exports = router;
