// In-memory deploy job registry. Each job is a single remote-deploy
// operation: started, in-progress, then either success or failed.
// iOS polls GET /api/admin/servers/deploy/jobs/:id to render the live
// log + final result.
//
// Trade-off (accepted for MVP): server restart wipes the registry.
// The actual install.sh on the remote VM keeps running independently
// — restart only loses our visibility, not the deploy itself. Persist
// to Postgres later if this proves annoying.

const crypto = require('crypto');

const TTL_MS = 60 * 60 * 1000; // keep finished jobs visible for 1 hour
const MAX_LOG_LINES = 500;     // cap per job to bound memory

const jobs = new Map(); // jobId -> Job

class Job {
  constructor(id, meta) {
    this.id = id;
    this.status = 'pending';        // pending | running | success | failed
    this.log = [];
    this.error = null;
    this.createdAt = Date.now();
    this.updatedAt = this.createdAt;
    this.completedAt = null;
    this.meta = meta || {};         // free-form: { host, ssh_key_id, admin_user_id }
  }
  appendLog(line) {
    if (this.log.length >= MAX_LOG_LINES) {
      this.log.shift();
      this.log[0] = `[truncated — exceeded ${MAX_LOG_LINES} lines]`;
    }
    this.log.push(line);
    this.updatedAt = Date.now();
  }
}

function create(meta) {
  const id = crypto.randomUUID();
  const job = new Job(id, meta);
  jobs.set(id, job);
  return job;
}

function get(id) {
  return jobs.get(id);
}

function appendLog(id, line) {
  const job = jobs.get(id);
  if (!job) return;
  if (job.status === 'pending') job.status = 'running';
  job.appendLog(line);
}

function complete(id, error) {
  const job = jobs.get(id);
  if (!job) return;
  job.status = error ? 'failed' : 'success';
  job.error = error || null;
  job.completedAt = Date.now();
  job.updatedAt = job.completedAt;
}

/**
 * Drop jobs older than TTL. Called from the same hourly cleanup tick
 * that other expiry-style services use; for now we trigger from a
 * setInterval inside index.js.
 */
function gc() {
  const cutoff = Date.now() - TTL_MS;
  for (const [id, job] of jobs) {
    if (job.completedAt && job.completedAt < cutoff) jobs.delete(id);
  }
}

/** Snapshot suitable for the polling endpoint. */
function snapshot(id) {
  const job = jobs.get(id);
  if (!job) return null;
  return {
    id: job.id,
    status: job.status,
    log: job.log.slice(),
    error: job.error,
    created_at: new Date(job.createdAt).toISOString(),
    updated_at: new Date(job.updatedAt).toISOString(),
    completed_at: job.completedAt ? new Date(job.completedAt).toISOString() : null,
    meta: job.meta,
  };
}

module.exports = { create, get, appendLog, complete, gc, snapshot };
