// Central error handler. Two layers of protection:
//
//   - 4xx errors (validation, auth, not-found): we expose err.message to
//     the client since these are deterministic and user-facing.
//
//   - 5xx errors (unhandled exceptions, pg constraint failures, JSON
//     parse errors): log the full message + stack server-side but
//     return a generic "Internal server error" to the caller. The
//     previous `error: err.message` form leaked pg constraint names,
//     column names, and stack frame strings to every client — useful
//     to a developer in dev, an information leak in prod.
function errorHandler(err, req, res, _next) {
  const status = err.status || (err.statusCode) || 500;

  // Server-side: full detail incl. stack for 5xx.
  if (status >= 500) {
    console.error(`[ERROR] ${req.method} ${req.path}:`, err.message);
    if (err.stack) console.error(err.stack);
  } else {
    console.warn(`[WARN ${status}] ${req.method} ${req.path}:`, err.message);
  }

  // Client-side: redact 5xx messages, pass 4xx through.
  if (status >= 500) {
    return res.status(status).json({ error: 'Internal server error' });
  }
  res.status(status).json({ error: err.message || 'Bad request' });
}

// Helper for catch blocks that don't use next(err) — keeps the same
// "log full, send sanitised" rule without rewriting every route.
// Usage:
//   } catch (err) {
//     return sendError(res, err, req);
//   }
function sendError(res, err, req) {
  const fakeReq = req || { method: '?', path: res.req?.path || '?' };
  errorHandler(err, fakeReq, res, () => {});
}

module.exports = errorHandler;
module.exports.errorHandler = errorHandler;
module.exports.sendError = sendError;
