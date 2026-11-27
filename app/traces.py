"""Parse strace output from install-script detonation into flagged behaviours (deterministic, no AI)."""
import re

LINE = re.compile(r'^(\d+)\s+(?:<\.\.\. (\w+) resumed>|(\w+)\()(.*)$')
SENSITIVE = [
    ("/home/node/.ssh", "SSH private key"),
    ("/home/node/.npmrc", "npm auth token"),
    ("/home/node/.aws", "AWS credentials"),
    ("/home/node/.config/gh", "GitHub CLI token"),
    ("/etc/shadow", "system password hashes"),
    ("/etc/passwd", "system user list"),
]
SUSPICIOUS_BIN = {"sh", "bash", "dash", "curl", "wget", "nc", "ncat", "python", "python3", "perl", "base64", "ssh", "scp"}


def parse(text):
    reads, probes, connects, execs, deletes = [], [], [], [], []
    rm_targets, del_results = [], []
    first_exec = True
    for raw in text.splitlines():
        m = LINE.match(raw)
        if not m:
            continue
        call = m.group(2) or m.group(3)
        rest = m.group(4)
        failed = re.search(r'=\s+-1\s+(\w+)', rest)
        if call == "openat":
            q = re.search(r'"([^"]+)"', rest)
            if not q:
                continue
            path = q.group(1)
            for prefix, label in SENSITIVE:
                if path.startswith(prefix):
                    (probes if failed else reads).append({"path": path, "what": label})
        elif call == "execve":
            q = re.findall(r'"([^"]*)"', rest)
            if not q:
                continue
            if first_exec:
                first_exec = False
                continue
            binary = q[0].rsplit("/", 1)[-1]
            if binary == "rm":
                rm_targets += [a for a in q[1:] if a.startswith("/") and not a.startswith(("/tmp", "/home/node"))]
            execs.append({"cmd": " ".join(q[1:6])[:200] or binary, "binary": binary, "suspicious": binary in SUSPICIOUS_BIN})
        elif call in ("unlink", "unlinkat", "rmdir"):
            del_results.append(failed.group(1) if failed else "deleted")
        elif call == "connect":
            if "AF_INET" not in rest:
                continue
            ip = re.search(r'inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6, "([^"]+)"', rest)
            port = re.search(r'htons\((\d+)\)', rest)
            connects.append({"ip": (ip.group(1) or ip.group(2)) if ip else "?", "port": port.group(1) if port else "?",
                             "result": failed.group(1) if failed else "attempted"})
    # dedupe
    def uniq(xs, key):
        seen, out = set(), []
        for x in xs:
            k = key(x)
            if k not in seen:
                seen.add(k)
                out.append(x)
        return out
    reads = uniq(reads, lambda x: x["path"])
    probes = uniq(probes, lambda x: x["path"])
    connects = uniq(connects, lambda x: (x["ip"], x["port"]))
    execs = uniq(execs, lambda x: x["cmd"])
    if rm_targets:
        denied = sum(1 for r in del_results if r != "deleted")
        done = len(del_results) - denied
        result = "EROFS" if denied and not done else ("deleted" if done and not denied else f"{denied} denied, {done} deleted")
        deletes = [{"path": t, "result": result} for t in dict.fromkeys(rm_targets)]
    cred = [r for r in reads if r["what"] not in ("system user list",)]
    if (cred and (connects or any(e["suspicious"] for e in execs))) or deletes:
        verdict = "MALICIOUS"
    elif cred or connects or any(e["suspicious"] for e in execs) or reads:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
    return {"verdict": verdict, "reads": reads, "probes": probes, "connects": connects, "execs": execs, "deletes": deletes}
