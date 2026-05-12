// Per-IP rate limits for authentication + setup endpoints.
//
// Without these the prior code had no defence against credential
// stuffing on /auth/login, refresh-token rotation abuse on /auth/refresh,
// or guessing /setup/root-enroll's bearer. In-memory store is fine for
// a single-process management server; if we ever scale horizontally
// switch to a shared store (Redis).
const rateLimit = require('express-rate-limit');
const config = require('../config');

// Always-pass middleware. Used when RATE_LIMIT_DISABLED=true (tests,
// developer machines) so individual route mounts don't have to branch.
const passthrough = (_req, _res, next) => next();

function make(opts) {
  if (config.rateLimitDisabled) return passthrough;
  return rateLimit({
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many requests — slow down and try again later.' },
    ...opts,
  });
}

// Login: brute force is the threat. Tight cap per IP — legitimate users
// log in once or twice per session, attackers fire continuously.
const login = make({ windowMs: 15 * 60 * 1000, max: 10 });

// Refresh: hit every session boundary, can be frequent under churn.
const refresh = make({ windowMs: 15 * 60 * 1000, max: 60 });

// Apple Sign In: similar shape to login. JWKS lookups + audience checks
// are non-trivial CPU; protect from spam.
const apple = make({ windowMs: 15 * 60 * 1000, max: 20 });

// Root setup: one-shot bootstrap. Should never fire more than a
// handful of times — anything beyond that is an attacker guessing the
// setup token.
const setup = make({ windowMs: 60 * 60 * 1000, max: 5 });

module.exports = { login, refresh, apple, setup };
