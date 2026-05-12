// Local cache of the openlay-vpn-release repo. We git-clone (first call)
// or git-pull (subsequent), then build a deploy-ready tarball of
// `olv-agent-bsd/` with `agent.conf` pre-populated for the target host.
//
// Why a local cache:
//   - The remote-deploy flow needs the agent binaries on the management
//     server's disk so we can SCP them to the target FreeBSD VM.
//   - Cloning every deploy = slow + flaky (network blips). Caching means
//     we only pay the network cost when the upstream repo updates.
//   - `git pull` is incremental — fast on subsequent calls.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const crypto = require('crypto');

const REPO_URL    = 'https://github.com/openlay/openlay-vpn-release.git';
const REPO_BRANCH = 'main';
const CACHE_DIR   = process.env.OLV_RELEASE_CACHE || '/var/lib/openlay/release-cache';
const PULL_TTL_MS = 5 * 60 * 1000;  // 5 min — re-pull at most this often

let lastPulledAt = 0;

/**
 * Helper: spawn a process and capture stdout/stderr; reject on non-zero exit.
 * Used by the git + tar shells below.
 */
function run(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], ...opts });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    child.on('close', code => {
      if (code === 0) resolve(stdout);
      else reject(new Error(`${cmd} ${args.join(' ')} exited ${code}: ${stderr.trim()}`));
    });
    child.on('error', reject);
  });
}

/**
 * Ensure the local cache is present + recently fresh. Cheap when called
 * inside the TTL window.
 */
async function ensureFresh() {
  if (!fs.existsSync(CACHE_DIR)) {
    fs.mkdirSync(path.dirname(CACHE_DIR), { recursive: true });
    await run('git', ['clone', '--depth', '1', '--branch', REPO_BRANCH, REPO_URL, CACHE_DIR]);
    lastPulledAt = Date.now();
    return;
  }
  if (Date.now() - lastPulledAt < PULL_TTL_MS) return;

  // Hard-reset to upstream so any local cruft is wiped. The cache is
  // managed exclusively by this service — no human edits expected.
  await run('git', ['fetch', 'origin', REPO_BRANCH], { cwd: CACHE_DIR });
  await run('git', ['reset', '--hard', `origin/${REPO_BRANCH}`], { cwd: CACHE_DIR });
  lastPulledAt = Date.now();
}

/**
 * Read the `VERSION` file from the BSD agent dir. Used by the iOS UI to
 * show "you're deploying version X" before the user confirms.
 */
async function getVersion() {
  await ensureFresh();
  const versionFile = path.join(CACHE_DIR, 'olv-agent-bsd', 'VERSION');
  if (!fs.existsSync(versionFile)) return 'unknown';
  return fs.readFileSync(versionFile, 'utf8').trim();
}

/**
 * Build a tarball of `olv-agent-bsd/` with `agent.conf` pre-populated.
 * Caller is responsible for `fs.unlink`-ing the returned path when done.
 *
 * Substitutions inside agent.conf (replacing the SAMPLE values):
 *   MANAGEMENT_API_URL=<managementApiUrl>
 *   ENROLLMENT_TOKEN=<enrollmentToken>
 *
 * The original `agent.conf.sample` file stays untouched in the tarball
 * so install.sh's "copy sample → agent.conf if absent" branch is a no-op
 * (we already provided agent.conf).
 *
 * @returns {Promise<string>} absolute path to the tarball
 */
async function buildDeployTarball({ enrollmentToken, managementApiUrl }) {
  await ensureFresh();
  const srcDir = path.join(CACHE_DIR, 'olv-agent-bsd');
  if (!fs.existsSync(srcDir)) {
    throw new Error(`olv-agent-bsd missing from cache at ${srcDir}`);
  }

  // Stage in a unique tmp dir so concurrent deploys don't trample each
  // other's agent.conf substitution.
  const stamp = crypto.randomBytes(8).toString('hex');
  const stage = path.join(os.tmpdir(), `olv-deploy-${stamp}`);
  fs.mkdirSync(stage, { recursive: true });
  fs.cpSync(srcDir, path.join(stage, 'olv-agent-bsd'), { recursive: true });

  // Render agent.conf from the sample with our substitutions.
  const samplePath = path.join(stage, 'olv-agent-bsd', 'agent.conf.sample');
  if (!fs.existsSync(samplePath)) {
    throw new Error('agent.conf.sample missing from upstream repo');
  }
  let conf = fs.readFileSync(samplePath, 'utf8');
  conf = conf
    .replace(/^MANAGEMENT_API_URL=.*$/m, `MANAGEMENT_API_URL=${managementApiUrl}`)
    .replace(/^ENROLLMENT_TOKEN=.*$/m, `ENROLLMENT_TOKEN=${enrollmentToken}`);
  fs.writeFileSync(path.join(stage, 'olv-agent-bsd', 'agent.conf'), conf, { mode: 0o600 });

  // Tar it up. Using system tar; FreeBSD 14 base has bsdtar that reads
  // GNU tar format, so we don't need to be picky here.
  const tarballPath = path.join(os.tmpdir(), `olv-deploy-${stamp}.tar`);
  await run('tar', ['-cf', tarballPath, '-C', stage, 'olv-agent-bsd']);

  // Best-effort stage cleanup; OS will purge /tmp eventually anyway.
  fs.rmSync(stage, { recursive: true, force: true });

  return tarballPath;
}

module.exports = { ensureFresh, getVersion, buildDeployTarball, CACHE_DIR };
