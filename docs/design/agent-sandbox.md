# Design: one sandbox container per run (parked)

**Status:** proposed, not implemented. Contributions welcome — see [Next steps](../../README.md#next-steps--contributions-welcome).

## Why

Vigilo's agents read and act on the code they are assessing. A malicious repository can try to
prompt-inject them. Today the agents run as subprocesses of the Temporal worker, in the worker's
container and on the platform's Docker network. A compromised agent therefore runs with the
worker's reach: it could talk to Temporal and to the API's internal listener, and on a shared
worker it could reach other concurrent runs' data. See [`SECURITY.md`](../../SECURITY.md) for the
current model and its limits.

The goal is to make the run — not the platform — the trust boundary: everything an agent can
touch belongs to its own run.

## Shape

```
 vigilo_net:  ui · api · postgres · temporal · worker
                                    │  (private launcher network)
                              [sandbox launcher] ── docker.sock
                                    │  create / exec / kill / delete (fixed config only)
 Internet ── [egress proxy] ── sandbox network (internal) ── [sandbox: one per run]
                                                              runner → agents, harnesses, git
```

- **One sandbox container per run**, created when the run starts and reused by every agent of
  that run (surveyor, planner, investigators, provers, reviewer, remediator, reporter,
  supply-chain, integrity), by retries, and by the patch-verification harnesses. Destroyed when
  the run ends (workflow `finally`, API on cancel, launcher idle/lifetime reaper).
- **A small launcher service is the only holder of the Docker socket.** It creates sandboxes from
  a fixed configuration — non-root user, read-only root filesystem, `cap_drop: ALL`,
  `no-new-privileges`, memory/CPU/PID limits sized to the run's parallelism, and only that run's
  checkout mounted. The worker can ask it to *run something in a run's sandbox*; it cannot choose
  the image, mounts, network or privileges.
- **A runner process inside the sandbox** starts each agent in its own process group, receives the
  prompt (which carries the session cookie) on stdin — never argv, env or labels — streams output
  back, and kills the whole process tree on cancel, idle timeout or a dropped connection.
- **Network:** the sandbox sits on an internal network with no route to Temporal, the API,
  Postgres or other runs. It reaches the model endpoint, the target and the internet only through
  an egress proxy that blocks private ranges, cloud metadata and the platform networks. Internal
  test targets are reachable only on networks the operator lists. An allow-list mode is available
  for locked-down deployments.
- **Provider credentials** live in the launcher and are injected per agent exec; the worker holds
  none.
- **No git outside the sandbox** on a checkout an agent has touched (a planted `.git/config` such
  as `core.fsmonitor` would otherwise execute code in the worker). Worker-side readers of agent
  output open files without following symlinks.
- **Push moves to the API:** the API keeps a pristine copy of the repository from ingestion; after
  remediation the sandbox exports the fix branches as a git bundle, which the API verifies
  (`fsck`, refs limited to `fix/*`, descends from the scanned commit) and pushes from its own
  trusted repository. The GitLab token never leaves the API.
- **One engine:** with per-run sandboxes, the separate per-run worker container (`docker` engine)
  adds nothing; both engines become "shared worker orchestrates, per-run sandbox executes", and
  the API no longer needs Docker access.
- `VIGILO_AGENT_SANDBOX=docker|none` keeps the current in-worker mode for tests and local
  development, with a loud warning on every run that uses it.

## Work packages

1. **Launcher, runner, images, network, compose** — `src/sandboxd/`, the in-sandbox runner, a
   slim agent image, the egress proxy, compose and docs.
2. **Worker client and executors** — a `spawn()` client used by the three executors, sandbox
   lifecycle activities, workflow `finally`.
3. **Git and file hardening** — git and harness runs through the sandbox; symlink-safe readers.
4. **API delivery** — pristine snapshot at ingestion, bundle hand-off, push and MRs from the API.

## Tests that must pass

From inside a sandbox: no connection to `temporal:7233`, `api:8080/8081`, `postgres:5432` or the
launcher; no DNS for platform hosts; no access to private ranges or cloud metadata via the proxy;
only the run's own files visible; no Docker socket, no capabilities, read-only root filesystem;
fork-bomb and OOM contained. Lifecycle: cancel kills the process tree within seconds; a worker
crash leaves no running agent; every destroy path removes the sandbox.

## Residual risks (even with the sandbox)

Agents of the same run share one trust domain (by design); a compromised agent can exfiltrate
the model credential unless egress is allow-listed or a per-run model token is used; the
launcher holds the Docker socket (keep it minimal; rootless Docker, gVisor or Kata reduce kernel
risk); a shared sandbox network allows cross-run reachability until per-run networks are added.
