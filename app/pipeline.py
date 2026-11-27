"""The Merge Breaker pipeline: fetch -> detonate install scripts -> fuzz -> AI attack loop -> report.
Untrusted repo code only ever runs inside throwaway sandbox containers (see sandbox.py)."""
import asyncio
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from . import injection, llm, sandbox, traces

DATA = Path(os.environ.get("MB_DATA", Path(__file__).resolve().parent.parent / "data"))
JOBS_DIR = DATA / "jobs"
DEMO_SRC = Path(__file__).resolve().parent.parent / "demo-target"
DEMO_BARE = DATA / "demo-target.git"
MAX_ATTACK_ROUNDS = int(os.environ.get("MB_ATTACK_ROUNDS", "3"))

JOBS: dict[str, "Job"] = {}
_sem = asyncio.Semaphore(int(os.environ.get("MB_MAX_JOBS", "1")))


class Job:
    def __init__(self, repo, trigger, label):
        self.id = time.strftime("%H%M%S-") + uuid.uuid4().hex[:4]
        self.repo = repo          # "demo" or https URL
        self.label = label
        self.trigger = trigger    # "button" | "merge (simulated)" | "github webhook"
        self.status = "queued"
        self.created = time.time()
        self.events = []
        self.stages = {s: {"status": "pending"} for s in ("fetch", "detonate", "tests", "fuzz", "guard", "attack", "report")}
        self.findings = []        # code findings
        self.supply_chain = []    # per-package detonation results
        self.containment = []     # per-container summaries
        self.report = None
        self.ai = {"model": llm.MODEL, "enabled": llm.enabled(), "status": "pending", "plan": "", "rounds": []}
        self.cond = asyncio.Condition()
        self.dir = JOBS_DIR / self.id

    def public(self, full=True):
        d = {k: getattr(self, k) for k in ("id", "repo", "label", "trigger", "status", "created", "stages", "ai")}
        d["guard"] = getattr(self, "guard", None)
        d["counts"] = {"findings": len(self.findings),
                       "malicious_packages": sum(1 for p in self.supply_chain if p["verdict"] == "MALICIOUS")}
        if full:
            d.update(findings=self.findings, supply_chain=self.supply_chain, containment=self.containment, report=self.report)
        return d

    async def emit(self, kind, msg, **data):
        ev = {"i": len(self.events), "t": round(time.time() - self.created, 1), "kind": kind, "msg": msg, **data}
        self.events.append(ev)
        async with self.cond:
            self.cond.notify_all()

    async def stage(self, name, status, note=""):
        self.stages[name] = {"status": status, "note": note}
        await self.emit("stage", f"{name}: {status}" + (f" ({note})" if note else ""), stage=name, status=status)

    def save(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "job.json").write_text(json.dumps({**self.public(), "events": self.events}, indent=1))


# ---------------------------------------------------------------- setup

def ensure_demo_repo():
    """Build a bare git repo from demo-target/ so the demo is cloned exactly like a real repo."""
    if DEMO_BARE.exists():
        return
    work = DATA / "demo-work"
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(DEMO_SRC, work, ignore=shutil.ignore_patterns("node_modules"))
    cmds = [["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
            ["git", "-c", "user.email=demo@merge-breaker.local", "-c", "user.name=Demo Dev", "commit", "-qm", "Merge PR #42: add receipt printer"]]
    import subprocess
    for c in cmds:
        subprocess.run(c, cwd=work, check=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(DEMO_BARE)], check=True)
    shutil.rmtree(work, ignore_errors=True)
    os.system(f"chmod -R a+rX {DEMO_BARE}")


def load_jobs():
    if not JOBS_DIR.exists():
        return
    for f in sorted(JOBS_DIR.glob("*/job.json"))[-30:]:
        try:
            d = json.loads(f.read_text())
        except Exception:
            continue
        j = Job.__new__(Job)
        j.__dict__.update({k: d.get(k) for k in ("id", "repo", "label", "trigger", "status", "created", "stages", "ai",
                                                   "findings", "supply_chain", "containment", "report")})
        j.events = d.get("events", [])
        j.cond = asyncio.Condition()
        j.dir = f.parent
        if j.status in ("queued", "running"):
            j.status = "interrupted"
        JOBS[j.id] = j


def submit(repo, trigger, label):
    job = Job(repo, trigger, label)
    JOBS[job.id] = job
    asyncio.create_task(_run(job))
    return job


async def _run(job):
    await job.emit("log", f"Queued: {job.label} (trigger: {job.trigger})")
    async with _sem:
        job.status = "running"
        try:
            await run_pipeline(job)
            job.status = "done"
        except Exception as e:  # never crash the control plane
            job.status = "error"
            await job.emit("error", f"Pipeline error: {type(e).__name__}: {e}")
        finally:
            await job.emit("done", f"Job {job.status}.")
            job.save()
            shutil.rmtree(job.dir / "repo", ignore_errors=True)  # lifecycle discipline: nothing of the repo survives


# ---------------------------------------------------------------- helpers

async def container(job, stage, flags, mounts, cmd, timeout):
    desc = sandbox.describe(flags)
    await job.emit("sandbox", f"[{stage}] starting throwaway container (network={desc['network']}, mem={desc.get('memory')}, timeout={timeout}s)",
                   stage=stage, containment=desc)
    r = await sandbox.run(flags, mounts, cmd, timeout)
    entry = {"stage": stage, "container": r["name"], **desc, "timeout_s": timeout, "seconds": r["seconds"],
             "exit": r["exit"], "killed": r["timed_out"], "removed": True}
    job.containment.append(entry)
    await job.emit("sandbox", f"[{stage}] container {r['name']} exited {r['exit']} after {r['seconds']}s"
                   + (" (KILLED at time limit)" if r["timed_out"] else "") + ", destroyed", stage=stage, containment=entry)
    return r


def repo_digest(repo: Path, limit=40000, redact=None):
    files, out, used = [], [], 0
    for p in sorted(repo.rglob("*")):
        rel = p.relative_to(repo)
        if any(part in ("node_modules", ".git", "vendor", "dist", "build") for part in rel.parts) or not p.is_file():
            continue
        files.append(str(rel))
        if p.suffix in (".js", ".mjs", ".cjs", ".ts", ".json") and p.name != "package-lock.json" and used < limit:
            drop = (redact or {}).get(str(rel), set())
            txt = "\n".join("[line withheld by Merge Breaker: suspected prompt injection]" if i in drop else l
                            for i, l in enumerate(p.read_text(errors="replace").splitlines(), 1))[: limit - used]
            used += len(txt)
            out.append(f"--- {rel} ---\n{txt}")
    return "FILES: " + ", ".join(files[:200]) + "\n\n" + "\n\n".join(out)


SEV = {"pollution": "high", "path-escape": "high", "hang": "high", "logic": "medium", "crash": "medium"}


def fuzz_findings(fz):
    """Group raw fuzz results into findings. Type-confusion TypeErrors on garbage input are folded into one low item."""
    groups = {}
    for r in fz.get("results", []):
        o = r["outcome"]
        if o in ("ok", "rejected"):
            continue
        if o == "crash" and r["detail"].startswith("TypeError"):
            key = (r["fn"], "type-confusion")
        else:
            key = (r["fn"], o)
        groups.setdefault(key, []).append(r)
    out = []
    for (fn, o), rs in groups.items():
        if o == "type-confusion":
            if len(rs) < 3:
                continue
            sev, title = "low", f"{fn}() throws TypeError on unexpected input types ({len(rs)} payloads)"
        else:
            sev = SEV.get(o, "medium")
            names = {"pollution": "prototype pollution", "path-escape": "path traversal escapes the upload dir",
                     "hang": "hangs (DoS), killed by the sandbox", "logic": "business-logic flaw", "crash": "unhandled exception"}
            title = f"{fn}(): {names.get(o, o)}"
        out.append({"id": f"fz-{fn}-{o}", "source": "fuzzer", "severity": sev, "title": title, "target": fn,
                    "category": o, "evidence": "; ".join(f"{r['payload']} -> {r['detail']}" for r in rs[:3]),
                    "reproduced": True})
    return out


def parse_attack_run(stdout):
    res = {}
    for m in re.finditer(r"MB_BEGIN (\S+)\n(.*?)\nMB_END \1 exit=(\d+)", stdout, re.S):
        aid, body, code = m.group(1), m.group(2), int(m.group(3))
        rm = re.findall(r"MB_RESULT (\{.*\})", body)
        verdict = None
        if rm:
            try:
                verdict = json.loads(rm[-1])
            except Exception:
                verdict = None
        if code == 137:
            status = "hang"
        elif verdict is not None:
            status = "vulnerable" if verdict.get("vulnerable") else "not-vulnerable"
        elif re.search(r"SyntaxError|ERR_MODULE_NOT_FOUND|Cannot find module|is not defined|does not provide an export", body) \
                and "/work/repo/src" not in body.split("\n    at ")[0]:
            status = "broken"
        elif re.search(r"at .*?/work/repo/(?!node_modules)", body):
            status = "crash"
        else:
            status = "broken" if code != 0 else "inconclusive"
        res[aid] = {"status": status, "exit": code, "evidence": (verdict or {}).get("evidence", ""), "output": body[-3000:]}
    return res


# ---------------------------------------------------------------- the pipeline

async def run_pipeline(job):
    job.dir.mkdir(parents=True, exist_ok=True)
    for sub in ("repo", "out", "attacks"):
        (job.dir / sub).mkdir(exist_ok=True)
    os.system(f"chmod -R 0777 {job.dir}")
    repo_dir, out_dir, att_dir = job.dir / "repo", job.dir / "out", job.dir / "attacks"

    # 1. FETCH: network on, but no repo code executes (scripts ignored)
    await job.stage("fetch", "running")
    mounts = [(str(repo_dir), "/work/repo", "rw")]
    if job.repo == "demo":
        mounts.append((str(DEMO_BARE), "/src", "ro"))
        src = "file:///src"
    else:
        src = job.repo
    fetch_cmd = ["sh", "-c",
                 f"git config --global --add safe.directory '*' && git clone -q --depth 1 '{src}' /work/repo && cd /work/repo && git log -1 --format='%h %s' && "
                 "if [ -f package-lock.json ]; then npm ci --ignore-scripts --no-audit --no-fund --loglevel=error; "
                 "else npm install --ignore-scripts --no-audit --no-fund --loglevel=error; fi"]
    r = await container(job, "fetch", sandbox.hardening(network="bridge", memory="2g", cpus="2", pids=512), mounts, fetch_cmd, 240)
    if r["exit"] != 0:
        await job.stage("fetch", "failed", (r["stderr"] or r["stdout"])[-300:])
        raise RuntimeError("fetch failed")
    commit = r["stdout"].strip().splitlines()[0] if r["stdout"].strip() else ""
    await job.stage("fetch", "done", f"commit {commit}; dependencies installed with --ignore-scripts")

    lock = repo_dir / "package-lock.json"
    flagged = []
    if lock.exists():
        try:
            pk = json.loads(lock.read_text()).get("packages", {})
            flagged = [k.replace("node_modules/", "") for k, v in pk.items() if v.get("hasInstallScript")]
        except Exception:
            pass
    await job.emit("log", f"Lockfile: {len(flagged)} package(s) declare install scripts: {', '.join(flagged) or 'none'}")

    # 2. DETONATE install scripts offline under strace with decoy secrets
    await job.stage("detonate", "running")
    r = await container(job, "detonate", sandbox.hardening(), [(str(repo_dir), "/work/repo", "rw"), (str(out_dir), "/out", "rw")],
                        ["node", "/opt/mb/detonate.mjs"], 120)
    det = {}
    try:
        det = json.loads((out_dir / "detonate.json").read_text())
    except Exception:
        await job.emit("error", "Detonation produced no report: " + (r["stderr"] or r["stdout"])[-300:])
    for p in det.get("packages", []):
        t = traces.parse((out_dir / p["trace"]).read_text(errors="replace") if (out_dir / p["trace"]).exists() else "")
        item = {"package": p["name"], "version": p["version"], "hook": p["hook"], "script": p["script"], **t,
                "exit": p["exit"], "timed_out": p["timedOut"], "ms": p["ms"]}
        job.supply_chain.append(item)
        msg = f"{p['name']}@{p['version']} {p['hook']}: {t['verdict']}"
        if t["reads"]:
            msg += " | read " + ", ".join(x["what"] for x in t["reads"])
        if t["connects"]:
            msg += " | tried to connect to " + ", ".join(f"{c['ip']}:{c['port']} ({c['result']})" for c in t["connects"])
        if t["execs"]:
            msg += " | spawned " + ", ".join(e["cmd"][:60] for e in t["execs"][:3])
        await job.emit("supply", msg, item=item)
    bad = [p for p in job.supply_chain if p["verdict"] != "CLEAN"]
    await job.stage("detonate", "done", f"{len(job.supply_chain)} install script(s) detonated, {len(bad)} flagged; decoys: {', '.join(det.get('decoys', []))}")

    # 3. TESTS: run the project's own test suite offline
    await job.stage("tests", "running")
    r = await container(job, "tests", sandbox.hardening(), [(str(repo_dir), "/work/repo", "ro")],
                        ["sh", "-c", "cd /work/repo && npm test > /tmp/t.txt 2>&1; e=$?; tail -25 /tmp/t.txt; echo MB_EXIT=$e"], 120)
    tail = (r["stdout"] + r["stderr"]).strip()
    code = re.search(r"MB_EXIT=(\d+)", tail)
    passed = re.search(r"(?:pass|passing|passed)\D{0,3}(\d+)|(\d+) (?:tests? )?pass", tail)
    count = (passed.group(1) or passed.group(2)) if passed else None
    if r["timed_out"]:
        note = "timed out"
    elif code and code.group(1) == "0":
        note = f"{count} passing" if count else "passing"
    else:
        note = "failing (or no test suite)"
    await job.stage("tests", "done", note)

    # 4a. FUZZ (deterministic, no AI)
    await job.stage("fuzz", "running")
    r = await container(job, "fuzz", sandbox.hardening(memory="1g"), [(str(repo_dir), "/work/repo", "ro")],
                        ["node", "/opt/mb/fuzz.mjs", "/work/repo"], 180)
    m = re.search(r"MB_FUZZ (\{.*\})", r["stdout"])
    fz = json.loads(m.group(1)) if m else {}
    ff = fuzz_findings(fz)
    for f in ff:
        job.findings.append(f)
        await job.emit("finding", f"[{f['severity'].upper()}] {f['title']}", finding=f)
    await job.stage("fuzz", "done", f"{len(fz.get('results', []))} hostile calls on {len(fz.get('functions', []))} exported functions, {len(ff)} findings"
                    if fz else "no exported functions found / fuzzer failed")

    # 4b. PROMPT-INJECTION SCAN before any model reads the code (rules + Vultr content-safety model vote)
    await job.stage("guard", "running")
    guard = await injection.scan(repo_dir)
    job.guard = {k: guard[k] for k in ("files", "model_flags", "model_error", "model")}
    for f in guard["findings"]:
        job.findings.append(f)
        await job.emit("finding", f"[{f['severity'].upper()}] {f['title']} ({' + '.join(f['voters'])})", finding=f)
    withheld = sum(len(v) for v in guard["redact"].values())
    await job.stage("guard", "done", f"{guard['files']} files checked by rules and {guard['model'] or 'no model'}; "
                    f"{len(guard['findings'])} flagged, {withheld} line(s) withheld from the agent")

    # 4c. AI ATTACK LOOP: plan -> write attacks -> execute in sandbox -> feed errors back -> retry
    await job.stage("attack", "running")
    if not llm.enabled():
        job.ai["status"] = "disabled"
        await job.stage("attack", "skipped", "no VULTR_INFERENCE_API_KEY configured")
    else:
        await attack_loop(job, repo_dir, att_dir, fz, guard["redact"])

    # 5. REPORT
    await job.stage("report", "running")
    await build_report(job)
    await job.stage("report", "done", job.report.get("headline", "") if job.report else "")


async def attack_loop(job, repo_dir, att_dir, fz, redact=None):
    fuzz_summary = "\n".join(f"- {f['title']}: {f['evidence'][:200]}" for f in job.findings if f["source"] == "fuzzer") or "(none)"
    await job.emit("ai", f"Asking {llm.MODEL} on Vultr Serverless Inference to plan attacks...")
    try:
        plan = await llm.plan_attacks(repo_digest(repo_dir, redact=redact), fuzz_summary)
    except Exception as e:
        job.ai["status"] = "error"
        await job.stage("attack", "failed", f"inference error: {e}")
        return
    job.ai["plan"] = plan["plan"]
    attacks = {}
    for a in plan["attacks"][:6]:
        a["id"] = re.sub(r"[^a-zA-Z0-9_]+", "_", str(a["id"]))[:40].strip("_").lower() or f"attack_{len(attacks)+1}"
        attacks[a["id"]] = a
    if not attacks:
        refused = llm.looks_like_refusal(plan["raw"])
        job.ai["status"] = "refused" if refused else "no-output"
        job.ai["raw"] = plan["raw"][:1500]
        await job.emit("ai", "Model " + ("REFUSED to write attacks" if refused else "returned no usable attacks")
                       + ". Showing deterministic fuzzer results only. The AI stage is a proof of concept for this run.")
        await job.stage("attack", "skipped", "model refused (proof-of-concept)" if refused else "model returned no attacks")
        return
    job.ai["status"] = "ok"
    if plan["usage"] and plan["usage"].get("model") and plan["usage"]["model"] != llm.MODEL:
        job.ai["model"] = plan["usage"]["model"]
        await job.emit("ai", f"{llm.MODEL} returned nothing; fell back to {job.ai['model']}.")
    await job.emit("ai", f"Plan: {plan['plan']}", usage=plan["usage"])
    for a in attacks.values():
        await job.emit("ai", f"Attack '{a['id']}' [{a.get('category')}] -> {a.get('target')}: {a.get('why', '')}")

    results = {}
    pending = dict(attacks)
    for rnd in range(1, MAX_ATTACK_ROUNDS + 1):
        for f in att_dir.glob("*.mjs"):
            f.unlink()
        for aid, a in pending.items():
            (att_dir / f"{aid}.mjs").write_text(a["code"])
        os.system(f"chmod -R a+r {att_dir}")
        r = await container(job, f"attack-round-{rnd}", sandbox.hardening(memory="512m"),
                            [(str(repo_dir), "/work/repo", "ro"), (str(att_dir), "/attacks", "ro")],
                            ["sh", "/opt/mb/run-attacks.sh"], 15 + 10 * len(pending))
        got = parse_attack_run(r["stdout"])
        broken = []
        for aid in pending:
            res = got.get(aid, {"status": "no-output", "output": r["stdout"][-500:], "evidence": "", "exit": None})
            results[aid] = {**res, "round": rnd}
            line = f"Round {rnd} · {aid}: {res['status'].upper()}"
            if res["status"] in ("vulnerable", "crash", "hang"):
                line += f" | {res['evidence'] or res['output'].strip().splitlines()[-1][:160] if res['output'].strip() else ''}"
            await job.emit("attack", line, attack=aid, result=res["status"])
            if res["status"] in ("broken", "no-output"):
                broken.append({"id": aid, "code": pending[aid]["code"], "output": res["output"]})
        job.ai["rounds"].append({"round": rnd, "ran": list(pending), "broken": [b["id"] for b in broken]})
        if not broken or rnd == MAX_ATTACK_ROUNDS:
            break
        await job.emit("ai", f"{len(broken)} attack script(s) failed to run. Feeding stderr back to the model to self-heal (round {rnd + 1})...")
        try:
            fixed, _ = await llm.fix_attacks(broken)
        except Exception as e:
            await job.emit("ai", f"Fix request failed: {e}")
            break
        pending = {}
        for fx in fixed:
            fx["id"] = re.sub(r"[^a-zA-Z0-9_]+", "_", str(fx.get("id", "")))[:40].strip("_").lower()
            if fx["id"] in attacks:
                attacks[fx["id"]]["code"] = fx["code"]
                pending[fx["id"]] = attacks[fx["id"]]
        if not pending:
            break

    confirmed = 0
    for aid, res in results.items():
        a = attacks[aid]
        if any(x in a.get("code", "") for x in ("curl ", "wget ", "| sh", "execSync(")):
            await job.emit("ai", f"Attack '{aid}' contained shell or download commands; the sandbox is offline and read-only, so they had no effect.")
        if res["status"] in ("vulnerable", "crash", "hang"):
            confirmed += 1
            sev = "high" if a.get("category") in ("dos", "injection", "traversal", "pollution") or res["status"] == "hang" else "medium"
            f = {"id": f"ai-{aid}", "source": "ai-attack", "severity": sev, "title": a.get("title", aid), "target": a.get("target", ""),
                 "category": a.get("category", ""), "evidence": res["evidence"] or res["output"][-400:],
                 "status": res["status"], "reproduced": True, "code": a["code"], "round": res["round"]}
            job.findings.append(f)
            await job.emit("finding", f"[{sev.upper()}] {f['title']} (AI attack, reproduced in sandbox)", finding=f)
    job.ai["results"] = {k: {"status": v["status"], "round": v["round"]} for k, v in results.items()}
    await job.stage("attack", "done", f"{len(results)} attacks executed, {confirmed} confirmed, {len(job.ai['rounds'])} round(s)")


def verdict(job):
    """The merge decision is computed from executed evidence only. No model can change it."""
    mal = [p for p in job.supply_chain if p["verdict"] == "MALICIOUS"]
    high = [f for f in job.findings if f["severity"] == "high"]
    inj = [f for f in job.findings if f["category"] == "prompt-injection"]
    block = bool(mal or high)
    parts = []
    if mal:
        parts.append(f"{len(mal)} malicious install script{'s' if len(mal) > 1 else ''}")
    if high:
        parts.append(f"{len(high)} high-severity finding{'s' if len(high) > 1 else ''}")
    if inj:
        parts.append(f"{len(inj)} prompt-injection attempt{'s' if len(inj) > 1 else ''}")
    rule = ("Block this merge: " if block else "No blocking issues: ") + (", ".join(parts) or f"{len(job.findings)} low/medium findings") + "."
    return block, rule


async def build_report(job):
    block, rule_headline = verdict(job)
    fallback = {"headline": rule_headline, "block_merge": block, "items": [], "generated_by": "rules", "decided_by": "rules"}
    if not llm.enabled() or job.ai.get("status") in ("refused", "error"):
        job.report = fallback
        return
    summary = []
    for p in job.supply_chain:
        if p["verdict"] != "MALICIOUS":
            continue
        summary.append(f"- supply:{p['package']} install script read DECOY secrets {[r['what'] for r in p['reads']]}, "
                       f"ATTEMPTED to connect to {[c['ip'] for c in p['connects']]} (blocked by the offline sandbox, nothing left), "
                       f"tried to delete {[d['path'] for d in p.get('deletes', [])]} (denied, read-only filesystem), "
                       f"ran {[e['cmd'] for e in p['execs']]}. In a normal CI or dev machine these would have been real secrets.")
    for f in job.findings:
        summary.append(f"- {f['id']} [{f['severity']}] {f['title']}: {f['evidence'][:200]}")
    summary.append(f"\nThe merge decision was already made by deterministic rules: {'BLOCK' if block else 'ALLOW'}. "
                   "Write the headline consistent with it.")
    try:
        rep, _ = await llm.write_report("\n".join(summary))
    except Exception:
        rep = None
    if not rep or not rep.get("headline"):
        job.report = fallback
        return
    model_says = bool(rep.get("block_merge"))
    rep["block_merge"] = block          # the rules decide, always
    rep["decided_by"] = "rules"
    rep["generated_by"] = llm.MODEL
    if model_says != block:
        rep["headline"] = rule_headline
        rep["model_disagreed"] = True
    job.report = rep
