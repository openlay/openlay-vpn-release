const jwt = require('jsonwebtoken');
const config = require('../config');

// Default middleware — only accepts access (session) tokens. Refresh tokens
// are opaque bytes, never sent as Bearer JWTs, so this also rejects them
// implicitly. Legacy JWTs without a `typ` claim (issued before the split)
// are still accepted so existing sessions don't break on deploy.
function jwtAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorization header' });
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, config.jwtSecret);
    if (payload.typ && payload.typ !== 'access') {
      return res.status(401).json({ error: 'Wrong token type — access token required' });
    }
    req.user = {
      id: payload.sub,
      email: payload.email,
      status: payload.status,
      sessionId: payload.sid || null,
    };
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

module.exports = jwtAuth;
