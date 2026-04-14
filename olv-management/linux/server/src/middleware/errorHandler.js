function errorHandler(err, req, res, _next) {
  console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
  const status = err.status || 500;
  res.status(status).json({ error: err.message });
}

module.exports = errorHandler;
