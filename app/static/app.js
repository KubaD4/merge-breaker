const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
let current = null, es = null, timer = null;
const open = new Set();

const tok = () => sessionStorage.getItem('mbToken') || '';
// Each browser gets a random id; the server lists only the runs this browser started.
const cid = (() => { let c = localStorage.getItem('mbClient'); if (!c) { c = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2) + Date.now()); localStorage.setItem('mbClient', c); } return c; })();
async function api(path, opts = {}) {
  opts.headers = { ...(opts.headers || {}), 'X-Client-Id': cid, ...(tok() ? { 'X-Run-Token': tok() } : {}) };
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
}

async function loadConfig() {
  const c = await api('/api/config');
  $('#meta').innerHTML = `<span>Model <b>${esc(c.model)}</b></span><span>Inference <b>Vultr Serverless</b></span><span>Sandbox <b>${c.runtime === 'runsc' ? 'Docker + gVisor' : 'Docker'}</b></span>`;
}

const live = (s) => s === 'running' || s === 'queued';

async function loadJobs() {
  const jobs = await api('/api/jobs');
  $('#runDemo').disabled = jobs.some((j) => live(j.status));
  $('#jobs').innerHTML = jobs.map((j) => {
    const cls = live(j.status) ? 'live' : j.status !== 'done' ? '' : (j.counts.malicious_packages || j.counts.findings) ? 'bad' : 'ok';
    const t = new Date(j.created * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return `<li data-id="${j.id}" class="${j.id === current ? 'active' : ''}"><span class="nm"><span class="dot ${cls}"></span>${esc(j.label.split(' · ')[0].replace(' (demo repo)', '').replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, ''))}</span><span class="t">${t}</span></li>`;
  }).join('') || '<li class="empty">No runs from this browser yet</li>';
  document.querySelectorAll('#jobs li[data-id]').forEach((li) => (li.onclick = () => openJob(li.dataset.id)));
}

async function start(body) {
  try {
    const { id } = await api('/api/jobs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    openJob(id);
  } catch (e) { alert(e.message); }
}
$('#runDemo').onclick = () => start({ repo: 'demo', trigger: 'merge (simulated)' });
$('#customToggle').onclick = () => {
  const p = $('#customPanel'); p.hidden = !p.hidden;
  $('#customToggle').setAttribute('aria-expanded', String(!p.hidden));
};
$('#runCustom').onclick = async () => {
  const repo = $('#repoUrl').value.trim(), token = $('#token').value.trim();
  $('#customErr').textContent = '';
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/.test(repo)) { $('#customErr').textContent = 'Enter a GitHub URL like https://github.com/owner/repo.'; return; }
  if (!token) { $('#customErr').textContent = 'A run token is required. Use Run on demo repo to see the full pipeline.'; return; }
  try {
    const { id } = await api('/api/jobs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repo, token, trigger: 'manual' }) });
    sessionStorage.setItem('mbToken', token);
    openJob(id);
  } catch (e) { $('#customErr').textContent = /token/i.test(e.message) ? 'That token is not valid. Use Run on demo repo to see the full pipeline.' : e.message; }
};

function openJob(id) {
  current = id; open.clear();
  $('#intro').hidden = true; $('#job').hidden = false; $('#log').innerHTML = '';
  if (es) es.close();
  es = new EventSource(`/api/jobs/${id}/events?client=${encodeURIComponent(cid)}` + (tok() ? `&token=${encodeURIComponent(tok())}` : ''));
  es.onmessage = (m) => { addLog(JSON.parse(m.data)); clearTimeout(timer); timer = setTimeout(refresh, 250); };
  es.addEventListener('end', () => { es.close(); refresh(); loadJobs(); });
  refresh(); loadJobs();
}

function addLog(ev) {
  const d = document.createElement('div');
  d.className = 'k-' + ev.kind;
  d.innerHTML = `<span class="t">${ev.t.toFixed(1)}s</span>${esc(ev.msg)}`;
  const log = $('#log'); const end = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
  log.appendChild(d); if (end) log.scrollTop = log.scrollHeight;
}

async function refresh() {
  if (!current) return;
  const j = await api(`/api/jobs/${current}`);
  head(j); stages(j); supply(j); findings(j); containment(j);
}

function head(j) {
  const commit = (j.stages.fetch.note || '').match(/commit (\S+) (.*?);/);
  $('#sub').textContent = [j.label.replace(' (demo repo)', ''), commit ? commit[1] : '', j.trigger].filter(Boolean).join('  ·  ');
  if (j.report) {
    const b = j.report.block_merge;
    $('#verdict').innerHTML = `<span class="tag ${b ? 'block' : 'pass'}">${b ? 'Block merge' : 'Safe to merge'}</span>${esc(cap(j.report.headline.replace(/^(block this merge|no blocking issues)\s*[:.-]\s*/i, '')))}`;
    $('#sub').textContent += `  ·  verdict decided by rules from executed evidence${j.report.generated_by && j.report.generated_by !== 'rules' ? ', explained by ' + j.report.generated_by : ''}`;
  } else if (live(j.status)) {
    $('#verdict').innerHTML = `<span class="tag live">Running</span>Attacking this merge in the sandbox…`;
  } else {
    $('#verdict').innerHTML = `<span class="tag">${esc(j.status)}</span>`;
  }
}

const cap = (t) => t.charAt(0).toUpperCase() + t.slice(1);

function stages(j) {
  const names = { fetch: 'Fetch', detonate: 'Detonate', tests: 'Own tests', fuzz: 'Fuzz', guard: 'Injection scan', attack: 'AI attack', report: 'Report' };
  const short = (k, s) => {
    const n = s.note || '';
    if (k === 'fetch') return n.includes('commit') ? 'scripts disabled' : n;
    if (k === 'detonate') return (n.match(/^\d+ install script\(s\) detonated, \d+ flagged/) || [n])[0].replace(/^1 install script\(s\) detonated/, '1 script run').replace('install script(s) detonated', 'scripts run');
    if (k === 'tests') return n.replace('existing tests: ', '');
    if (k === 'fuzz') return (n.match(/\d+ hostile calls/) || [n])[0];
    if (k === 'guard') { const m = n.match(/(\d+) flagged, (\d+) line/); return m ? `${m[1]} flagged, ${m[2]} lines withheld` : n; }
    if (k === 'attack') return n.replace(/(\d+) attacks executed, (\d+) confirmed, (\d+) round\(s\)/, '$2 of $1 confirmed, $3 rounds');
    return '';
  };
  $('#stages').innerHTML = Object.entries(j.stages).map(([k, s]) =>
    `<li class="${s.status}"><b>${names[k]}</b><span class="s">${s.status === 'pending' ? '—' : esc(s.status)}</span><span class="n">${esc(short(k, s))}</span></li>`).join('');
}

function supply(j) {
  if (!j.supply_chain.length) {
    $('#supply').innerHTML = `<p class="empty">${j.stages.detonate.status === 'done' ? 'No install scripts in the dependency tree.' : 'Waiting for detonation.'}</p>`;
    return;
  }
  $('#supply').innerHTML = j.supply_chain.map((p) => {
    const rows = [];
    if (p.reads.length) rows.push(['Read', p.reads.map((r) => `${esc(r.what)} <span class="mono" style="color:var(--faint)">${esc(r.path)}</span>`).join('<br>')]);
    if (p.connects.length) rows.push(['Sent data to', p.connects.map((c) => `<span class="mono">${esc(c.ip)}:${esc(c.port)}</span> <span class="ok">blocked</span>`).join('<br>')]);
    if ((p.deletes || []).length) rows.push(['Tried to delete', p.deletes.map((d) => `<span class="mono">${esc(d.path)}</span> <span class="ok">${d.result === 'deleted' ? 'deleted' : d.result === 'EROFS' ? 'denied, read-only filesystem' : 'denied (' + esc(d.result) + ')'}</span>`).join('<br>')]);
    const sus = p.execs.filter((e) => e.suspicious);
    if (sus.length) rows.push(['Spawned', sus.map((e) => `<span class="mono">${esc(e.cmd)}</span>`).join('<br>')]);
    if (!rows.length) rows.push(['Activity', 'No access to credentials, network or shells']);
    return `<div class="pkg"><div class="top"><span class="state ${p.verdict}">${p.verdict}</span><span class="name">${esc(p.package)}@${esc(p.version)}</span><span class="hook">${esc(p.hook)} · <span class="mono">${esc(p.script)}</span></span></div>
      <dl class="facts">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl></div>`;
  }).join('') + (j.supply_chain.some((p) => p.reads.length) ? `<p class="aside" style="margin-top:12px">All credentials in the sandbox are decoys. The network was disabled, so nothing left.</p>` : '');
}

function findings(j) {
  const st = j.ai.status;
  const ai = { ok: '', refused: 'The model declined to write attacks for this run. Showing deterministic results only (proof of concept).', 'no-output': 'The model returned no usable attacks. Showing deterministic results only.', disabled: 'AI attacks disabled: no inference key configured.', error: 'Inference error. Showing deterministic results only.', pending: '' }[st] ?? '';
  $('#plan').textContent = j.ai.plan ? j.ai.plan : ai;
  const rep = Object.fromEntries((j.report?.items || []).map((i) => [i.ref, i]));
  const order = { high: 0, medium: 1, low: 2 };
  const fs = merge(j.findings).sort((a, b) => order[a.severity] - order[b.severity] || (a.source === 'ai-attack' ? -1 : 1));
  const lows = fs.filter((f) => f.severity === 'low');
  const shown = open.has('__low') ? fs : fs.filter((f) => f.severity !== 'low');
  $('#fcount').textContent = fs.length - lows.length || '';
  if (!fs.length) { $('#findings').innerHTML = `<p class="empty">${live(j.status) ? 'Waiting for results.' : 'Nothing reproduced.'}</p>`; return; }
  $('#findings').innerHTML = `<table><tr><th style="width:80px">Severity</th><th>Finding</th><th style="width:36%">Evidence</th><th style="width:110px">Found by</th></tr>${shown.map((f) => {
    const r = rep[f.id];
    const detail = open.has(f.id) ? `<tr class="detail"><td></td><td colspan="3"><div class="detail-body">
        ${r ? `<div><div class="k">Impact</div>${esc(r.explain)}</div><div><div class="k">Fix</div><span class="mono">${esc(r.fix)}</span></div>` : ''}
        <div><div class="k">Evidence</div><span class="mono">${esc(f.evidence)}</span></div>
        ${f.lines ? `<div><div class="k">Withheld from the agent</div>${f.lines.map((l) => `<span class="mono">line ${l.line}: ${esc(l.text)}</span>`).join('<br>')}</div>` : ''}
        ${f.voters ? `<div><div class="k">Voters</div>${esc(f.voters.join(' and '))} (${esc(f.agreement)})</div>` : ''}
        ${f.code ? `<div><div class="k">Attack script · round ${f.round}</div><pre>${esc(f.code)}</pre></div>` : ''}</div></td></tr>` : '';
    return `<tr class="f" data-id="${esc(f.id)}"><td><span class="sev ${f.severity}">${f.severity}</span></td><td>${esc(f.title)}</td><td class="ev">${f.status === 'hang' ? 'Hung; killed by the sandbox at the 8 s limit' : esc(f.evidence.split('\n')[0].split('; ')[0]).slice(0, 110)}</td><td class="src">${f.source === 'ai-attack' ? (f.also ? 'Agent + fuzzer' : 'Agent') : f.source === 'injection-scan' ? (f.voters.length > 1 ? 'Rules + Nemotron' : f.voters[0] === 'rules' ? 'Rules' : 'Nemotron') : 'Fuzzer'}</td></tr>${detail}`;
  }).join('')}</table>${lows.length ? `<button class="more" id="lowToggle">${open.has('__low') ? 'Hide' : 'Show'} ${lows.length} low-severity type errors</button>` : ''}`;
  const lt = $('#lowToggle'); if (lt) lt.onclick = () => { open.has('__low') ? open.delete('__low') : open.add('__low'); findings(j); };
  document.querySelectorAll('tr.f').forEach((tr) => (tr.onclick = () => { const id = tr.dataset.id; open.has(id) ? open.delete(id) : open.add(id); findings(j); }));
}

// Fold fuzzer findings into the agent finding for the same bug (same function, same class).
function merge(list) {
  const cls = { 'path-escape': 'traversal', hang: 'dos', pollution: 'pollution', logic: 'logic', crash: 'crash' };
  const agent = list.filter((f) => f.source === 'ai-attack').map((f) => ({ ...f }));
  const out = [...agent];
  for (const f of list.filter((x) => x.source !== 'ai-attack')) {
    const c = cls[f.category];
    const twin = agent.find((a) => (a.category === c || (c === 'dos' && a.status === 'hang')) && `${a.title} ${a.target}`.includes(f.target));
    if (twin) twin.also = f; else out.push(f);
  }
  return out;
}

function containment(j) {
  if (!j.containment.length) { $('#containment').innerHTML = '<p class="empty">No containers yet.</p>'; return; }
  $('#containment').innerHTML = `<p class="aside">Each stage runs in a fresh container: non-root, all capabilities dropped, read-only filesystem, no real secrets.</p>
  <table class="ct"><tr><th>Stage</th><th>Network</th><th>Limits</th><th>Result</th><th></th></tr>${j.containment.map((c) =>
    `<tr><td>${esc(c.stage)}</td><td>${c.network.startsWith('none') ? 'offline' : 'fetch only'}</td><td class="mono">${esc(c.memory)} · ${esc(c.cpus)} cpu · ${esc(c.pids)} pids · ${esc(c.timeout_s)}s</td>
     <td>${c.killed ? '<span class="killed">killed at limit</span>' : `exit ${esc(c.exit)}`} <span style="color:var(--faint)">${esc(c.seconds)}s</span></td><td class="gone">destroyed</td></tr>`).join('')}</table>`;
}

loadConfig(); loadJobs();
setInterval(loadJobs, 5000);
