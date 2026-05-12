const { Router } = require('express');
const usersRouter = require('./users');
const devicesRouter = require('./devices');
const settingsRouter = require('./settings');
const versionRouter = require('./version');
const enrollmentCodeRouter = require('./enrollment-code');
const enrollmentsRouter = require('./enrollments');
const deviceProfilesRouter = require('./device-profiles');
const meRouter = require('./me');
const sshKeysRouter = require('./sshKeys');
const serverDeployRouter = require('./serverDeploy');

const router = Router();

router.use('/me', meRouter);
router.use('/users', usersRouter);
router.use('/devices', devicesRouter);
router.use('/settings', settingsRouter);
router.use('/version', versionRouter);
router.use('/enrollment-code', enrollmentCodeRouter);
router.use('/enrollments', enrollmentsRouter);
router.use('/device-profiles', deviceProfilesRouter);
router.use('/ssh-keys', sshKeysRouter);
router.use('/servers/deploy', serverDeployRouter);

module.exports = router;
