# Raft HA benchmark (Windows)

This benchmark exercises the production OnetDNS control path end to end:

1. authenticated `POST /v1/cluster/propose` requests,
2. encrypted and Ed25519-authenticated Raft transport,
3. WAL persistence and quorum commit,
4. application on every node,
5. DNS data-plane answers throughout healthy load and the leader-election gap,
6. leader termination, re-election, and the old leader's catch-up.

With `-ProposalCount 4096` or higher, the same harness also exposes automatic
log compaction through `snapshot_index` and `retained_log_entries`. The cluster
integration gate separately keeps one of three authenticated TCP nodes offline
across the compaction boundary, then proves `InstallSnapshot` plus suffix
recovery before it is allowed to pass.

It intentionally uses only PowerShell and .NET facilities already present on
Windows. No load generator, database, container, WSL, or administrator access
is required.

The script starts three isolated OnetDNS processes on loopback high ports. It
does not stop, replace, or reconfigure an existing OnetDNS service. Runtime
configuration, logs, samples, request records, and `summary.json` are retained
under `target/raft-ha/<timestamp>/`.

## Run

Build a separate release binary so a running `target/release/OnetDNS.exe` is
never replaced:

```powershell
cargo build --release -p onetdns --target-dir target/raft-ha-build
powershell -NoProfile -ExecutionPolicy Bypass -File benchmarks/raft-ha/run-windows.ps1
```

Useful parameters:

```powershell
benchmarks/raft-ha/run-windows.ps1 `
  -Binary target/raft-ha-build/release/OnetDNS.exe `
  -ProposalCount 32 `
  -Concurrency 32 `
  -Workload hot `
  -BaselineSeconds 5 `
  -BasePort 25053
```

`-Workload hot` (the default) changes `blocked_response_ttl`, exercising
consensus, durable configuration, and in-process hot application without a
service restart. `-Workload chain` changes `cache_size`, rebuilding and
atomically swapping the resolver chain while retaining listeners, the control
plane, and the process-owned Raft runtime. Keep the two results separate: the
first measures a scalar update and the second includes resolver construction.

The current configuration schema has 251 keys. Of those, 249 are applied in
place; only the Linux privilege-drop settings `run_as_user` and `run_as_group`
require a full service-generation replacement. The harness deliberately does
not mutate operating-system identities, so it has no synthetic "restart"
workload. Historical results in `RESULTS.md` that used `cache_size` as a restart
workload remain valid only for the older binaries that classified it that way.

`-Workload no_change` repeatedly proposes the already-active
`blocked_response_ttl` value. It still exercises authenticated transport,
consensus, the replicated log, and durable applied-index advancement while
skipping configuration writes and runtime replacement. This diagnostic mode
separates Raft bookkeeping cost from state-machine mutation cost; it is not a
substitute for either production workload above.

The runtime uses a bounded 64-request proposal queue and groups simultaneous
requests under the Raft transport's existing 256-entry / 512-KiB batch limits.
Every request still owns a distinct ordered log entry and completes only after
its own index is durably applied. A saturated queue fails fast instead of
growing memory without a bound.

The control listener admits 128 total connections and no more than 64
long-lived streams. This deliberately leaves 64 ordinary HTTP slots for the
maximum supported 64-way proposal run even when every streaming slot is in
use. Incomplete requests stay in a nonblocking admission state; a control-client
thread is created only after the complete header and declared body arrive. Pre-auth
request prefixes share one process-wide 8-MiB budget that remains charged until the
authoritative parser drops them. Control
and dashboard reader threads reserve 256 KiB of stack each; do not raise the
concurrency above 64 without changing and re-measuring that resource contract.
Shutdown tracking, request parsing, response writes, and dashboard reads share one
OS socket handle per connection instead of cloning it.

Use the companion harness to reproduce pre-authentication resource bounds with an
isolated single process. It creates its own config and output directory and stops only
the PID it started:

```powershell
.\benchmarks\raft-ha\run-control-admission.ps1 `
  -Binary target\codex-control-admission-release\release\OnetDNS.exe `
  -Mode one-byte -ClientCount 300

.\benchmarks\raft-ha\run-control-admission.ps1 `
  -Binary target\codex-control-admission-release\release\OnetDNS.exe `
  -Mode large-body -ClientCount 32
```

Both modes hold clients for five seconds, sample CPU and process resources, release
the clients, sample again after two seconds, and write `summary.json` below
`target/control-admission/<timestamp>-<mode>`.

The chosen base port reserves three DNS ports at `base..base+2`, three control
ports at `base+100..base+102`, and three Raft ports at
`base+200..base+202`. The script fails before startup if any port is occupied.

## Reported metrics

- initial election time and elected node/term;
- committed proposal throughput, error rate, and p50/p95/p99 latency (each
  request timer is captured as its own HTTP task completes, not after the
  whole concurrency batch finishes);
- leader and term stability throughout every load; rebuilding the resolver
  chain retains the process-owned Raft runtime, and any unsolicited election
  fails the benchmark after preserving artifacts;
- per-node CPU time, working set, private bytes, threads, and handles;
- time from leader termination to a new leader and to the first new commit;
- failed logical attempts during the unavailable interval;
- exact local DNS answer availability during load and on both surviving nodes
  from immediately after leader termination through the first new commit;
- restarted-node DNS readiness separately from full Raft catch-up time;
- an automatic log audit that rejects every error, panic, fatal/fail-stop, and
  every warning outside the intentional failure window; only
  `raft.peer_unreachable` after the scripted leader termination is expected;
- rejoined-node catch-up time, commit/applied/log-tail index convergence, and
  final config equality;
- per-node `snapshot_index` and retained suffix entry count, so a long-run test
  can prove that memory and disk no longer grow with total proposal history.

The three deterministic Ed25519 identities and shared credentials are public,
insecure benchmark fixtures. Never reuse them outside this loopback harness.
The DNS availability probe is also self-contained: every node serves
`raft-health.test A 192.0.2.123` from a local dynamic record, and the harness
checks transaction ID, QR, rcode, answer count, and the exact address without
contacting the configured public upstream. It samples one node every 100 ms
during proposal load and every failover loop iteration; these probe costs are
part of the measured service workload.
