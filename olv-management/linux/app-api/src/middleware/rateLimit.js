// Per-IP rate limits for the VPN-client-facing auth + enroll endpoints.
//
// app-api is internet-facing on port 443 — the gating point against
// credential stuffing on /api/auth/login, replay-probing on
// /api/auth/device, and 10-digit code guessing on /api/enroll. Each
// route gets its own bucket so a burst on enrollment doesn't starve
// auth attempts.
//
// In-memory store: single-process per host. If app-api scales
// horizontally, swap to a shared backend (Redis).
const rateLimit = require('express-rate-limit');

const passthrough = (_req, _res, next) => next();

function make(opts) {
  if (process.env.RATE_LIMIT_DISABLED === 'true') return passthrough;
  return rateLimit({
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many requests — slow down and try again later.' },
    ...opts,
  });
}

// Login / Apple Sign In — guarded against credential stuffing.
const login = make({ windowMs: 15 * 60 * 1000, max: 10 });
const apple = make({ windowMs: 15 * 60 * 1000, max: 20 });

// Device auth — legit clients hit this once per re-auth. Probing the
// signature replay defence is the threat.
const device = make({ windowMs: 15 * 60 * 1000, max: 30 });

// Device challenge — every legit auth fetches one; allow more.
const deviceChallenge = make({ windowMs: 15 * 60 * 1000, max: 60 });

// Enrollment: 10-digit code = 33 bits brute force. Per-IP cap caps
// guesses to ~10/hour, combined with per-code TTL (1h) makes the
// expected attack time astronomical.
const enroll = make({ windowMs: 60 * 60 * 1000, max: 10 });

// Enrollment App Attest challenge — slightly more permissive than
// /enroll itself but still bounded.
const enrollChallenge = make({ windowMs: 60 * 60 * 1000, max: 30 });

module.exports = { login, apple, device, deviceChallenge, enroll, enrollChallenge };
