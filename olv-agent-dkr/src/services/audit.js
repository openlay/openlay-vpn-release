const fs = require('fs');
const config = require('../config');

const entries = [];

function log(action, details = {}, req = null) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    details,
    ip: req?.ip || null,
  };

  entries.push(entry);
  if (entries.length > config.auditLogMax) entries.shift();

  if (config.auditLogFile) {
    fs.appendFile(config.auditLogFile, JSON.stringify(entry) + '\n', () => {});
  }
}

function getAll(limit = 100, offset = 0) {
  const sorted = entries.slice().reverse();
  return {
    total: sorted.length,
    entries: sorted.slice(offset, offset + limit),
  };
}

function middleware(action) {
  return (req, res, next) => {
    res.on('finish', () => {
      log(action, {
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        params: req.params,
      }, req);
    });
    next();
  };
}

module.exports = { log, getAll, middleware };
