// SSH-based deploy orchestrator. Two operations:
//
//   testConnection — quick OS detect + SSH auth check. Idempotent, no
//                    side effects on the remote host.
//   deploy         — full install: SCP tarball, run install.sh, capture
//                    log line-by-line (consumer streams to UI).
//
// Why ssh2 (vs spawning the system `ssh` binary):
//   - ssh2 accepts the private key as an in-memory PEM Buffer. Spawning
//     `ssh` would mean writing the decrypted DEK-recovered private key to
//     a temp file (with -o IdentityFile=/tmp/...) which leaks the key to
//     disk and is a pain to clean up reliably.
//   - Built-in stream handling for live log capture without parsing
//     stderr-stdout interleaving from a shell.

const fs = require('fs');
const { Client } = require('ssh2');

const CONNECT_TIMEOUT_MS = 10_000;
const READY_TIMEOUT_MS   = 15_000;
const COMMAND_TIMEOUT_MS = 5 * 60_000;  // install.sh can take a few minutes

/**
 * Open an SSH session, run a single one-off command, return collected
 * stdout. Used for the OS detection probe.
 *
 * @returns {Promise<{ stdout: string, stderr: string, exitCode: number }>}
 */
function execOnce(connectOpts, command) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error('Command timed out'));
    }, COMMAND_TIMEOUT_MS);

    conn.on('ready', () => {
      conn.exec(command, (err, stream) => {
        if (err) { clearTimeout(timer); conn.end(); return reject(err); }
        let stdout = '', stderr = '', exitCode = -1;
        stream.on('data', d => { stdout += d.toString(); });
        stream.stderr.on('data', d => { stderr += d.toString(); });
        stream.on('exit', code => { exitCode = code; });
        stream.on('close', () => {
          clearTimeout(timer);
          conn.end();
          resolve({ stdout, stderr, exitCode });
        });
      });
    });
    conn.on('error', err => { clearTimeout(timer); reject(err); });
    conn.connect({
      ...connectOpts,
      readyTimeout: READY_TIMEOUT_MS,
    });
  });
}

/**
 * Connect + probe OS info. Returns parsed info regardless of OS — the
 * caller decides whether to gate deploy on FreeBSD 14.
 *
 * @returns {Promise<{
 *   ok: boolean,
 *   uname?: string,
 *   freebsdVersion?: string,
 *   isFreeBSD14?: boolean,
 *   error?: string
 * }>}
 */
async function testConnection({ host, port, username = 'root', privateKeyPem }) {
  // JS default-param only triggers on `undefined`, but iOS sends an
  // explicit `null` when the user leaves the port field blank. Normalise
  // any falsy value to the standard SSH port.
  const sshPort = (typeof port === 'number' && port > 0) ? port : 22;
  try {
    const result = await execOnce(
      { host, port: sshPort, username, privateKey: privateKeyPem },
      // `uname -srm` works everywhere; freebsd-version is FreeBSD-only.
      // The `|| true` keeps exit-0 even when freebsd-version is missing.
      'uname -srm; (freebsd-version 2>/dev/null || true)'
    );
    const lines = result.stdout.trim().split('\n').map(l => l.trim()).filter(Boolean);
    const uname = lines[0] || '';
    const freebsdVersion = lines[1] || null;
    // uname format on FreeBSD: "FreeBSD 14.2-RELEASE amd64"
    const isFreeBSD14 = /^FreeBSD\s+14\./.test(uname) && /amd64|arm64/.test(uname);
    return { ok: true, uname, freebsdVersion, isFreeBSD14 };
  } catch (err) {
    return { ok: false, error: friendlySshError(err) };
  }
}

/**
 * Full deploy: SCP the tarball + run install.sh on the remote, streaming
 * output line-by-line to `onLogLine`.
 *
 * Strategy: instead of using SFTP (which adds a round trip per chunk),
 * we pipe the tarball over a single `tar -xf -` exec. Less code, fewer
 * places to fail, and no temp-file cleanup on the remote side.
 *
 * @param {{
 *   host: string, port?: number, username?: string,
 *   privateKeyPem: string|Buffer,
 *   tarballPath: string,
 *   onLogLine: (line: string) => void
 * }} opts
 * @returns {Promise<{ ok: boolean, error?: string }>}
 */
async function deploy({ host, port, username = 'root', privateKeyPem, tarballPath, onLogLine, suPassword, enrollmentToken, managementApiUrl }) {
  // Same normalisation as testConnection — null from iOS blank field.
  const sshPort = (typeof port === 'number' && port > 0) ? port : 22;
  // Always allocate PTY when SSH user isn't root — even if no password.
  // FreeBSD's su(8) reads the password from /dev/tty regardless of stdin,
  // so without a PTY it fails immediately with "su: Sorry" even when
  // root's password is empty. With a PTY allocated we can write the
  // password (which may be the empty string for AMIs with `nullok`) into
  // su's prompt.
  const needsPty = username !== 'root';
  // Coalesce nil/undefined to "" so the PTY write always succeeds.
  const passwordToSend = suPassword || '';

  // Shell-escape values that go into the install.sh env. Single-quote
  // wrap, escape any embedded single quotes via the standard `'\''`
  // dance. Tokens are base64url (no quotes), URLs are restricted, so
  // this is mostly belt-and-suspenders.
  const shellQuote = (s) => `'${String(s ?? '').replace(/'/g, "'\\''")}'`;
  const tokenQuoted = shellQuote(enrollmentToken);
  const urlQuoted   = shellQuote(managementApiUrl);
  // SFTP-upload the tarball first, then exec the extract + install in
  // a separate channel. We CANNOT pipe the tarball through the same PTY
  // we use for su's password prompt — PTY line discipline mangles
  // binary data (CR/LF translation, ^D=EOF, etc) and corrupts tar.
  //
  // The install command itself:
  //   1. sane PATH (non-interactive SSH on FreeBSD has a minimal PATH
  //      that misses /usr/local/{s,}bin — where pkg lives)
  //   2. mkdir staging + tar-extract from the uploaded file
  //   3. cd into the agent dir
  //   4. run install.sh — directly if already root, else via `su -m root`
  //
  // FreeBSD has NO sudo in base, but `su` is. When SSH'ing as a wheel
  // member (e.g. ec2-user on AWS), su prompts for root's password on
  // /dev/tty — which only exists when we allocate a PTY. Once allocated,
  // we watch for the prompt + write the password. Empty password is OK
  // when the AMI has `nullok` configured (common when root account is
  // "locked" — nullok still accepts empty input).
  const REMOTE_TARBALL = '/tmp/olv-deploy.tar';
  // Export MANAGEMENT_API_URL + ENROLLMENT_TOKEN before running
  // install.sh — the script checks these env vars first (lines 191-192
  // of upstream install.sh) and only falls back to interactive `read`
  // (which opens /dev/tty) when both are empty. /dev/tty doesn't exist
  // under non-interactive SSH exec, so the prompt path crashes with
  // "cannot open /dev/tty: Device not configured" — exact symptom we
  // hit before this fix.
  //
  // For the su path, env vars passed before `su -m` are inherited by
  // root's shell because `-m` preserves the caller's environment.
  const envExports =
    `export MANAGEMENT_API_URL=${urlQuoted} && ` +
    `export ENROLLMENT_TOKEN=${tokenQuoted} && `;
  const cmd =
    'export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin && ' +
    envExports +
    'rm -rf /tmp/olv-deploy && ' +
    'mkdir -p /tmp/olv-deploy && ' +
    `cd /tmp/olv-deploy && tar -xf ${REMOTE_TARBALL} && ` +
    'cd olv-agent-bsd && ' +
    'if [ "$(id -u)" -eq 0 ]; then ' +
      'sh ./install.sh; ' +
    'else ' +
      // Pass env vars through `su -m` via env(1) so root's shell sees them
      // even if the AMI's PAM strips env. Belt-and-suspenders with -m.
      `su -m root -c "MANAGEMENT_API_URL=${urlQuoted} ENROLLMENT_TOKEN=${tokenQuoted} cd /tmp/olv-deploy/olv-agent-bsd && sh ./install.sh"; ` +
    'fi';

  return new Promise((resolve) => {
    const conn = new Client();
    let resolved = false;
    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      conn.end();
      resolve(result);
    };

    const timer = setTimeout(
      () => finish({ ok: false, error: 'Deploy timed out (5 min)' }),
      COMMAND_TIMEOUT_MS
    );

    conn.on('ready', () => {
      onLogLine(`[ssh] connected to ${username}@${host}`);
      onLogLine('[sftp] uploading agent tarball ...');

      // Step 1: SFTP-upload the tarball to /tmp/olv-deploy.tar. Plain raw
      // bytes through the SFTP channel — no PTY, no line-discipline
      // mangling. ssh2's fastPut handles chunking + flow control.
      conn.sftp((sftpErr, sftp) => {
        if (sftpErr) {
          clearTimeout(timer);
          return finish({ ok: false, error: `sftp open failed: ${sftpErr.message}` });
        }
        sftp.fastPut(tarballPath, '/tmp/olv-deploy.tar', (putErr) => {
          if (putErr) {
            clearTimeout(timer);
            sftp.end();
            return finish({ ok: false, error: `tarball upload failed: ${putErr.message}` });
          }
          sftp.end();
          onLogLine('[sftp] upload done, running install.sh ...');

          // Step 2: exec install.sh, with PTY if we need to drive su.
          const execOpts = needsPty ? { pty: true } : {};
          conn.exec(cmd, execOpts, (err, stream) => {
            if (err) {
              clearTimeout(timer);
              return finish({ ok: false, error: `exec failed: ${err.message}` });
            }

            // Strip ANSI escape sequences (PTY can produce them) so the
            // iOS log view shows clean text.
            // eslint-disable-next-line no-control-regex
            const ansi = /\x1b\[[0-9;]*[a-zA-Z]/g;

            let buf = '';
            let suPromptHandled = false;
            const onChunk = (data) => {
              let chunk = data.toString().replace(ansi, '');

              // Watch for su's password prompt; write password into the
              // pty and replace the visible prompt in the log (don't want
              // a "Password:" line followed by mysterious progress).
              if (needsPty && !suPromptHandled && /[Pp]assword:?/.test(chunk)) {
                suPromptHandled = true;
                stream.write(passwordToSend + '\n');
                chunk = chunk.replace(/.*[Pp]assword:?.*/g, '[su] password sent');
              }

              buf += chunk;
              let nl;
              while ((nl = buf.indexOf('\n')) !== -1) {
                const line = buf.slice(0, nl).replace(/\r$/, '');
                buf = buf.slice(nl + 1);
                if (line.length > 0) onLogLine(line);
              }
            };
            stream.on('data', onChunk);
            // With PTY, stderr is folded into the same stream (no
            // separate stderr channel), so this listener is harmless
            // when pty=true.
            stream.stderr.on('data', d => onChunk(Buffer.from(`[stderr] ${d.toString()}`)));

            stream.on('close', (code) => {
              if (buf.length > 0) onLogLine(buf);
              clearTimeout(timer);
              if (code === 0) finish({ ok: true });
              else finish({ ok: false, error: `deploy command exited with code ${code} (see log)` });
            });
          });
        });
      });
    });

    conn.on('error', err => {
      clearTimeout(timer);
      finish({ ok: false, error: friendlySshError(err) });
    });

    conn.connect({
      host, port: sshPort, username, privateKey: privateKeyPem,
      readyTimeout: READY_TIMEOUT_MS,
    });
  });
}

/**
 * Map the most common ssh2 error codes to user-readable strings. The
 * iOS UI surfaces these directly to the admin during deploy.
 */
function friendlySshError(err) {
  const code = err.code || err.level;
  const msg = err.message || String(err);
  if (code === 'ECONNREFUSED') return `Connection refused (is sshd running on ${err.address || 'the host'}?)`;
  if (code === 'ENOTFOUND')    return `Host not found: ${err.hostname || err.message}`;
  if (code === 'ETIMEDOUT')    return 'Connection timed out';
  if (code === 'client-authentication') return 'SSH authentication failed (wrong key for this host?)';
  return msg;
}

module.exports = { testConnection, deploy };
