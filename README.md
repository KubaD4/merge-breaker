# Merge Breaker

Merge Breaker tests a repository after each merge to `main`. It runs everything inside throwaway sandboxes on a Vultr VM:

1. **Supply-chain detonation.** Every dependency install script (`preinstall`, `install`, `postinstall`) runs offline under `strace`, with decoy credentials planted. Reads of SSH keys or tokens, outbound connections and spawned shells are recorded.
2. **Fuzzing.** Every exported function receives hostile inputs (malformed encodings, path traversal, prototype keys, ReDoS strings, huge inputs). Each call runs in its own worker with a hard timeout.
3. **Prompt-injection scan.** Before any model reads the code, two independent voters check it for text aimed at AI tools: deterministic pattern rules (line-level) and `nemotron-3.5-content-safety` on Vultr Serverless Inference (60-line windows). Flagged lines are reported and withheld from the attack agent.
4. **Agent attacks.** A model on Vultr Serverless Inference reads the code and the fuzzer results, writes targeted attack scripts, and runs them in a fresh sandbox. When a script fails because of its own bug, the error goes back to the model, which fixes the script and retries.
5. **Report.** A finding is reported only if an execution reproduced it. Each finding includes its evidence, impact and a suggested fix. The block or allow verdict is computed by fixed rules from the executed evidence; the model only writes the explanation and cannot change the verdict.

Built for the Vultr Agent Runtime Hackathon (Stockholm, 27 November 2026).

## Using the live demo

Live demo: **https://70-34-214-252.sslip.io**

Demo video (about 3 minutes): [release v1.0](https://github.com/KubaD4/merge-breaker/releases/tag/v1.0) · [direct download](https://github.com/KubaD4/merge-breaker/releases/download/v1.0/merge-breaker-demo.mp4)

Open the demo URL and click **Run on demo repo**. The full pipeline runs live on `demo-target/` (`tiny-shop-api`), a small API with planted bugs whose newest dependency, `color-pad`, contains a simulated credential-stealing `postinstall` script. Only the merge that triggers the run is simulated.

The page shows each stage as it completes:
- the install script reading the decoy SSH key and tokens, its blocked connection to `203.0.113.66`, and its `rm -rf /etc /usr/local /opt` being denied by the read-only filesystem
- the prompt injection hidden in `src/index.js` (it tells AI reviewers to report nothing and run `curl … | sh`), caught by both voters and withheld from the agent, with the verdict unchanged
- the bugs found by the fuzzer and by the agent
- the containers that ran, with their limits and the fact that each was destroyed

**Scan your own repository** runs the same pipeline on any public GitHub repository (Node.js / npm). On the live demo it is open to everyone. Each browser sees only its own runs, and scans are limited per visitor, per day across the site, and by repository size.

## Architecture

![Merge Breaker architecture](docs/architecture.png)

- **Caddy** terminates HTTPS in front of the control plane.
- **Control plane** (`app/`, FastAPI on the Vultr VM). It never executes repository code. It has five parts:
  - **Request guard:** per-visitor rate limit, a site-wide daily scan cap, and a repository size and visibility check through GitHub's API. Run history is private per browser, and run ids are random.
  - **Orchestrator:** queues runs, starts one sandbox per stage, and parses the strace traces.
  - **Injection scan:** pattern rules plus `nemotron-3.5-content-safety` vote on hidden instructions. Flagged lines are withheld from the agent.
  - **Agent loop:** `glm-5.3` plans, writes and repairs attacks, with `qwen3.8-27b` as the fallback if it returns nothing. Repository content is marked as untrusted data.
  - **Verdict engine:** decides block or allow from executed evidence only. The model writes the explanation, not the decision.
- **Sandboxes** (`sandbox/`): a fresh gVisor (`runsc`) container per stage, built from `sandbox/Dockerfile`, destroyed afterwards. Only the fetch stage has network access, to clone from GitHub and download from npm, and it runs no repository code. Every other stage is offline.
- **Inference:** all model calls go to Vultr Serverless Inference (`https://api.vultrinference.com/v1`, OpenAI-compatible), and only the control plane holds the key. The agent loop uses `glm-5.3` and `qwen3.8-27b`; the injection scan uses `nemotron-3.5-content-safety`.

## Containment

| Concern | Measure |
|---|---|
| Process isolation | Repository code runs only in fresh `docker run --rm` containers: non-root (uid 1000), `--cap-drop ALL`, `no-new-privileges`, read-only root filesystem. With `MB_RUNTIME=runsc` the sandboxes run under gVisor's user-space kernel, which is how the live demo runs. |
| Secrets | Containers receive no real credentials. The detonation stage plants clearly labelled decoys. The inference key stays in the control plane. |
| Resources | Every container has memory, CPU, process-count and wall-clock limits. Fuzz calls time out at 2 s, attack scripts at 8 s. |
| Network | Every stage that executes repository code runs with `--network none`. The fetch stage has network access but runs nothing (`--ignore-scripts`). Host firewall rules drop container traffic to private ranges and the metadata service. |
| Lifecycle | Each container is removed after its stage, and the cloned repository is deleted when the run ends. |
| Prompt injection | Repository content is scanned by rules and a content-safety model before the agent sees it. Flagged lines are withheld, and the prompt marks the repository as untrusted data. The verdict is computed by rules, so a hijacked model cannot approve a merge. Anything the model writes still runs only in the offline sandbox. |
| Abuse | Repository scans are either open to everyone (`MB_OPEN_SCANS=1`) or gated by the owner's run token. When open, they are capped per visitor, per day site-wide (`MB_DAILY_SCANS`) and by repository size (`MB_MAX_REPO_MB`, checked through GitHub's API before cloning). Run history is private to the browser that started a run, and run ids are random. Webhooks need a valid HMAC signature and an allowlisted repository. Runs are queued, one at a time. |

## Running it

Requirements: Docker, Python 3.11+, and a Vultr Serverless Inference API key.

```bash
cp .env.example .env              # set VULTR_INFERENCE_API_KEY
docker build -t merge-breaker-sandbox:latest sandbox/
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --port 8080
```

### Deploying on Vultr

Create an Ubuntu 24.04 Cloud Compute instance, then run:

```bash
rsync -a --exclude .venv --exclude data --exclude .env ./ root@<ip>:/opt/merge-breaker/
scp .env root@<ip>:/opt/merge-breaker/.env
ssh root@<ip> 'bash /opt/merge-breaker/deploy/setup.sh <ip-with-dashes>.sslip.io'
```

`deploy/setup.sh` installs Docker, gVisor and Caddy (HTTPS). It also configures the firewall and the container egress rules, builds the sandbox image, and starts the app as a systemd service.

### Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `VULTR_INFERENCE_API_KEY` | Serverless Inference key (required for the agent stage) |
| `MB_MODEL`, `MB_FALLBACK_MODEL` | Primary and fallback models |
| `MB_REASONING_TOKENS` | Cap on the model's reasoning budget |
| `MB_RUNTIME` | `runsc` to run sandboxes under gVisor |
| `MB_RUN_TOKEN` | Owner token: sees all runs; required for repository scans when they are not open |
| `MB_OPEN_SCANS` | `1` lets anyone scan a public GitHub repository without a token; `0` requires the run token |
| `MB_DAILY_SCANS`, `MB_MAX_REPO_MB` | Site-wide daily scan cap and maximum repository size for open scans |
| `MB_WEBHOOK_SECRET`, `MB_ALLOWED_REPOS` | GitHub webhook: merges to the default branch trigger a run |

## Repository layout

```
app/            control plane: pipeline, sandbox runner, trace parser, model client, dashboard
sandbox/        sandbox image: install-script detonator, fuzzer, attack runner
demo-target/    deliberately vulnerable sample repository (see warning below)
deploy/         Vultr VM provisioning and systemd unit
```

> **Note:** `demo-target/` is intentionally vulnerable. `vendor/color-pad/install.js` (packed as `vendor/color-pad-1.4.2.tgz`) is a simulated malicious install script. It exits immediately unless it runs inside the Merge Breaker sandbox (`MB_SANDBOX=1`), it only ever reads the sandbox's decoy files, and its target `203.0.113.66` is a reserved TEST-NET address.

## Limits

- Supports Node.js / npm repositories only.
- The agent stage sees at most about 40,000 characters of source. On large repositories it covers only part of the code.
- Agent findings are confirmed by the attack script's own check, so review them on real codebases before acting on them.
- Decoy-based detection catches install scripts that touch credentials or the network during installation. It cannot catch code that stays dormant until runtime.

## Roadmap

- **Diff-scoped analysis.** Analyse only the files changed by the merge, plus the files they import, so the cost stays the same regardless of repository size.
- **Continuous adversarial testing.** Deploy the application in an isolated environment and alternate simulated normal traffic with attack traffic over a longer period. The report would then cover which attacks succeeded, whether any monitoring or rate limiting detected or blocked them, and how quickly. From those results, the agent would propose fixes and an intrusion-detection design tailored to that application: which signals to log, which patterns to alert on, and where to place the controls.
- **More ecosystems:** Python (`pip`/`setup.py` hooks), Go and Rust.
- **Pull-request comments:** post the verdict and findings directly on the merged pull request.
