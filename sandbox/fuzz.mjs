// Baseline fuzzer: no AI needed. It calls every exported function with hostile inputs, one worker per
// call, with a hard timeout. It detects crashes, hangs (ReDoS / infinite loops), prototype pollution and path escapes.
import { Worker, isMainThread, workerData, parentPort } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const PAYLOADS = [
  ['malformed-uri', 'q=%E0%A4%A'],
  ['redos', 'a'.repeat(34) + '!'],
  ['path-traversal', '../../../../etc/passwd'],
  ['xss', '<script>alert(1)</script>'],
  ['sqli', "' OR 1=1 --"],
  ['null-byte', 'file.txt\u0000.png'],
  ['huge-string', 'x'.repeat(5_000_000)],
  ['null', null],
  ['undefined', undefined],
  ['negative-qty', [{ price: 10, qty: -5 }]],
  ['nan', NaN],
  ['proto-pollution', '__JSON__{"__proto__":{"mbPolluted":"yes"}}'],
  ['nested-proto', '__JSON__{"a":{"__proto__":{"mbPolluted":"yes"}}}'],
];

if (isMainThread) {
  const repo = process.argv[2] || '/work/repo';
  const pj = JSON.parse(fs.readFileSync(path.join(repo, 'package.json'), 'utf8'));
  const entry = path.join(repo, pj.main || 'index.js');
  const mod = await import(pathToFileURL(entry).href);
  const fns = Object.entries(mod).filter(([, v]) => typeof v === 'function').map(([k, v]) => [k, v.length]);
  const results = [];
  for (const [fn, arity] of fns) {
    for (const [pname] of PAYLOADS) {
      for (const pos of arity >= 2 ? [0, 1] : [0]) {
        const r = await new Promise((resolve) => {
          const w = new Worker(new URL(import.meta.url), { workerData: { entry, fn, pname, pos, arity } });
          const timer = setTimeout(() => { w.terminate(); resolve({ outcome: 'hang', detail: 'killed after 2000 ms' }); }, 2000);
          w.on('message', (m) => { clearTimeout(timer); w.terminate(); resolve(m); });
          w.on('error', (e) => { clearTimeout(timer); resolve({ outcome: 'crash', detail: `${e.name}: ${e.message}` }); });
        });
        results.push({ fn, payload: pname, argPos: pos, ...r });
      }
    }
  }
  console.log('MB_FUZZ ' + JSON.stringify({ entry: path.relative(repo, entry), functions: fns.map((f) => f[0]), results }));
} else {
  const { entry, fn, pname, pos, arity } = workerData;
  const mod = await import(pathToFileURL(entry).href);
  let [, payload] = PAYLOADS.find(([n]) => n === pname);
  if (typeof payload === 'string' && payload.startsWith('__JSON__')) payload = JSON.parse(payload.slice(8));
  const args = arity >= 2 ? [{}, {}] : [];
  args[pos] = payload;
  try {
    const out = await mod[fn](...args);
    const polluted = ({}).mbPolluted === 'yes';
    const s = typeof out === 'string' ? out : '';
    if (polluted) parentPort.postMessage({ outcome: 'pollution', detail: 'Object.prototype.mbPolluted was set' });
    else if (pname === 'path-traversal' && /(^|\/)etc\/passwd$/.test(path.normalize(s)) && path.normalize(s).startsWith('/etc'))
      parentPort.postMessage({ outcome: 'path-escape', detail: `returned ${s}` });
    else if (pname === 'negative-qty' && typeof out === 'number' && out < 0)
      parentPort.postMessage({ outcome: 'logic', detail: `returned negative total ${out}` });
    else parentPort.postMessage({ outcome: 'ok', detail: s.slice(0, 80) || typeof out });
  } catch (e) {
    const handled = e && e.constructor === Error; // deliberate validation errors usually throw plain Error
    parentPort.postMessage({ outcome: handled ? 'rejected' : 'crash', detail: `${e?.name}: ${String(e?.message).slice(0, 160)}` });
  }
}
