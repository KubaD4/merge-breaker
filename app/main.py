"""Merge Breaker control plane (runs on the Vultr VM). Plans, dispatches and verifies; never runs repo code itself."""
import asyncio
import hashlib
import hmac
import json
import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import llm, pipeline, sandbox

STATIC = Path(__file__).resolve().parent / "static"
RUN_TOKEN = os.environ.get("MB_RUN_TOKEN", "")            # needed to scan arbitrary repos
WEBHOOK_SECRET = os.environ.get("MB_WEBHOOK_SECRET", "")
ALLOWED_REPOS = {r.strip().lower() for r in os.environ.get("MB_ALLOWED_REPOS", "").split(",") if r.strip()}
GITHUB_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+?(\.git)?/?$")

app = FastAPI(title="Merge Breaker")
_hits = defaultdict(deque)


@app.on_event("startup")
async def startup():
    pipeline.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    pipeline.ensure_demo_repo()
    pipeline.load_jobs()


def is_owner(request: Request) -> bool:
    """Owner = holds the run token. Visitors only ever see demo-repo runs."""
    tok = request.headers.get("X-Run-Token") or request.query_params.get("token") or ""
    return bool(RUN_TOKEN) and hmac.compare_digest(tok, RUN_TOKEN)


def visible(job, request) -> bool:
    return job.repo == "demo" or is_owner(request)


def rate_limit(ip, limit=8, window=3600):
    q = _hits[ip]
    now = time.time()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Rate limit: try again later")
    q.append(now)


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/api/config")
async def config():
    return {"model": llm.MODEL, "ai_enabled": llm.enabled(), "inference_base_url": llm.BASE_URL,
            "runtime": sandbox.RUNTIME or "runc", "custom_repos": bool(RUN_TOKEN), "webhook": bool(WEBHOOK_SECRET)}


@app.post("/api/jobs")
async def create_job(request: Request):
    body = await request.json()
    repo = (body.get("repo") or "demo").strip()
    trigger = body.get("trigger") or "button"
    if repo != "demo":
        if not RUN_TOKEN or not hmac.compare_digest(str(body.get("token", "")), RUN_TOKEN):
            raise HTTPException(403, "Scanning custom repos needs the run token (public visitors can run the demo repo).")
        if not GITHUB_URL.match(repo):
            raise HTTPException(400, "Only https://github.com/<owner>/<repo> URLs are accepted.")
    rate_limit(request.client.host if request.client else "?")
    if sum(1 for j in pipeline.JOBS.values() if j.status in ("queued", "running")) >= 3:
        raise HTTPException(429, "Queue is full, please wait for the current run.")
    label = "tiny-shop-api (demo repo) · Merge PR #42" if repo == "demo" else repo
    job = pipeline.submit(repo, trigger, label)
    return {"id": job.id}


@app.get("/api/jobs")
async def list_jobs(request: Request):
    jobs = [j for j in pipeline.JOBS.values() if visible(j, request)]
    return [j.public(full=False) for j in sorted(jobs, key=lambda j: j.created, reverse=True)][:30]


@app.get("/api/jobs/{jid}")
async def get_job(jid: str, request: Request):
    j = pipeline.JOBS.get(jid)
    if not j or not visible(j, request):
        raise HTTPException(404)
    return j.public()


@app.get("/api/jobs/{jid}/events")
async def events(jid: str, request: Request, since: int = 0):
    j = pipeline.JOBS.get(jid)
    if not j or not visible(j, request):
        raise HTTPException(404)

    async def gen():
        i = since
        while True:
            while i < len(j.events):
                yield f"data: {json.dumps(j.events[i])}\n\n"
                i += 1
            if j.status not in ("queued", "running") and i >= len(j.events):
                yield "event: end\ndata: {}\n\n"
                return
            if await request.is_disconnected():
                return
            try:
                async with j.cond:
                    await asyncio.wait_for(j.cond.wait(), timeout=15)
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/webhook/github")
async def github_webhook(request: Request):
    raw = await request.body()
    if not WEBHOOK_SECRET:
        raise HTTPException(503, "webhook not configured")
    sig = request.headers.get("X-Hub-Signature-256", "")
    good = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, good):
        raise HTTPException(401, "bad signature")
    event = request.headers.get("X-GitHub-Event", "")
    p = json.loads(raw or b"{}")
    if event == "ping":
        return {"ok": True}
    repo = p.get("repository", {})
    full = (repo.get("full_name") or "").lower()
    if full not in ALLOWED_REPOS:  # an empty allowlist accepts nothing
        raise HTTPException(403, "repo not allowed")
    merged_pr = event == "pull_request" and p.get("action") == "closed" and p.get("pull_request", {}).get("merged")
    push_main = event == "push" and p.get("ref") == f"refs/heads/{repo.get('default_branch', 'main')}"
    if not (merged_pr or push_main):
        return JSONResponse({"ignored": event}, status_code=202)
    url = repo.get("clone_url", "")
    if not GITHUB_URL.match(url):
        raise HTTPException(400, "unsupported repo url")
    what = f"PR #{p['pull_request']['number']} merged" if merged_pr else f"push {p.get('after', '')[:7]}"
    job = pipeline.submit(url, "github webhook", f"{full} · {what}")
    return {"id": job.id}
