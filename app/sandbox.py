"""Docker sandbox helpers. Every stage runs in a fresh, hardened, throwaway container."""
import asyncio
import os
import time
import uuid

IMAGE = os.environ.get("MB_IMAGE", "merge-breaker-sandbox:latest")
RUNTIME = os.environ.get("MB_RUNTIME", "")  # e.g. "runsc" for gVisor


def hardening(memory="1g", cpus="1", pids=256, network="none"):
    flags = [
        "--rm",
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids),
        "--memory", memory, "--memory-swap", memory,
        "--cpus", cpus,
        "--read-only",
        "--tmpfs", "/tmp:rw,exec,size=512m",
        "--tmpfs", "/home/node:rw,size=64m,uid=1000,gid=1000,mode=0700",
        "-e", "HOME=/home/node",
        "-e", "npm_config_cache=/tmp/npm-cache",
        "--network", network,
    ]
    if RUNTIME:
        flags += ["--runtime", RUNTIME]
    return flags


def describe(flags):
    """Human-readable containment summary for the UI."""
    d = {"network": "none (offline)", "user": "uid 1000 (non-root)", "capabilities": "all dropped",
         "rootfs": "read-only", "secrets": "none (decoys only)", "runtime": RUNTIME or "runc"}
    for i, f in enumerate(flags):
        if f == "--memory":
            d["memory"] = flags[i + 1]
        elif f == "--cpus":
            d["cpus"] = flags[i + 1]
        elif f == "--pids-limit":
            d["pids"] = flags[i + 1]
        elif f == "--network":
            d["network"] = "none (offline)" if flags[i + 1] == "none" else f"{flags[i+1]} (fetch only, no repo code runs)"
    return d


async def run(flags, mounts, cmd, timeout):
    """Run one container. Returns dict(exit, stdout, stderr, timed_out, seconds, name)."""
    name = f"mb-{uuid.uuid4().hex[:10]}"
    args = ["docker", "run", "--name", name, *flags]
    for host, ctr, mode in mounts:
        args += ["-v", f"{host}:{ctr}:{mode}"]
    args += [IMAGE, *cmd]
    t0 = time.time()
    proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    timed_out = False
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        k = await asyncio.create_subprocess_exec("docker", "kill", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await k.wait()
        out, err = await proc.communicate()
    # --rm removes it; make sure it is gone even after a kill
    rm = await asyncio.create_subprocess_exec("docker", "rm", "-f", name, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    await rm.wait()
    return {"exit": proc.returncode, "stdout": out.decode(errors="replace"), "stderr": err.decode(errors="replace"),
            "timed_out": timed_out, "seconds": round(time.time() - t0, 1), "name": name}
