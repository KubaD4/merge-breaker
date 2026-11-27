// Runs every package install script (preinstall/install/postinstall) under strace, one at a time,
// with DECOY credentials planted. Network is disabled by the container (--network none).
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const REPO = '/work/repo';
const OUT = '/out';
const HOME = process.env.HOME || '/home/node';

// ---- plant decoys (fake values, clearly labelled) ----
const DECOY = 'MERGE-BREAKER-DECOY-VALUE-NOT-A-REAL-CREDENTIAL';
const decoys = {
  '.ssh/id_rsa': `decoy ssh key\n${DECOY}\n`,
  '.npmrc': `//registry.npmjs.org/:_authToken=${DECOY}\n`,
  '.aws/credentials': `[default]\naws_access_key_id=${DECOY}\naws_secret_access_key=${DECOY}\n`,
  '.config/gh/hosts.yml': `github.com:\n  oauth_token: ${DECOY}\n`,
};
for (const [rel, content] of Object.entries(decoys)) {
  const p = path.join(HOME, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content, { mode: 0o600 });
}
const decoyEnv = { GITHUB_TOKEN: DECOY, AWS_SECRET_ACCESS_KEY: DECOY, NPM_TOKEN: DECOY };

// ---- find packages with lifecycle install scripts ----
function findPackages(dir, acc = []) {
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return acc; }
  for (const e of entries) {
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.name.startsWith('@')) { findPackages(p, acc); continue; }
    const pj = path.join(p, 'package.json');
    if (fs.existsSync(pj)) {
      try {
        const j = JSON.parse(fs.readFileSync(pj, 'utf8'));
        for (const hook of ['preinstall', 'install', 'postinstall']) {
          if (j.scripts?.[hook]) acc.push({ name: j.name, version: j.version, hook, script: j.scripts[hook], dir: p });
        }
      } catch {}
      findPackages(path.join(p, 'node_modules'), acc);
    }
  }
  return acc;
}

const pkgs = findPackages(path.join(REPO, 'node_modules'));
const results = [];
pkgs.forEach((pkg, i) => {
  const trace = path.join(OUT, `trace-${i}.txt`);
  const t0 = Date.now();
  const r = spawnSync('strace', ['-f', '-qq', '-s', '256', '-e', 'trace=openat,execve,connect,unlink,unlinkat,rmdir',
    '-o', trace, 'sh', '-c', pkg.script], {
    cwd: pkg.dir, timeout: 20000, killSignal: 'SIGKILL',
    env: { PATH: process.env.PATH, HOME, MB_SANDBOX: '1', npm_package_name: pkg.name, npm_lifecycle_event: pkg.hook, ...decoyEnv },
  });
  results.push({
    ...pkg, dir: path.relative(REPO, pkg.dir), trace: path.basename(trace),
    exit: r.status, signal: r.signal, timedOut: r.error?.code === 'ETIMEDOUT' || r.signal === 'SIGKILL',
    ms: Date.now() - t0,
    stdout: String(r.stdout || '').slice(0, 2000), stderr: String(r.stderr || r.error?.message || '').slice(0, 2000),
  });
});
fs.writeFileSync(path.join(OUT, 'detonate.json'), JSON.stringify({ decoys: Object.keys(decoys), decoyEnv: Object.keys(decoyEnv), packages: results }, null, 2));
console.log(`detonated ${results.length} install script(s)`);
