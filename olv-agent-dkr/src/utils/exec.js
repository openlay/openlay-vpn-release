const { execFile } = require('child_process');

function exec(cmd, args = [], opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 30000, ...opts }, (err, stdout, stderr) => {
      if (err) {
        const error = new Error(`Command failed: ${cmd} ${args.join(' ')}`);
        error.stderr = stderr;
        error.stdout = stdout;
        error.code = err.code;
        return reject(error);
      }
      resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

async function wg(...args) {
  return exec('wg', args);
}

async function wgQuick(...args) {
  return exec('wg-quick', args);
}

module.exports = { exec, wg, wgQuick };
