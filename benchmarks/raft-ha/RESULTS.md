# Windows Raft HA results

Measured on 2026-07-19 UTC with three isolated one-worker processes on Windows
11 Enterprise, an Intel Core i7-14700 (28 logical processors), and 32 GiB RAM.
The final benchmark binary was built separately from the running service and
had SHA-256
`A6E765D2C40D784535795245CA75B16503D9C942DE0B56FE7C170B8BF627B0C3`.

## 2026-08-09 control-plane admission hardening

The hand-written control server originally used one thread per accepted connection. Its
loopback-only bind and 15-second absolute read deadline prevented remote or
indefinite retention, but a local process could still hold the old 256-thread
limit before authentication by sending only one byte of a partial HTTP request.
An isolated 300-client reproduction measured the following process deltas:

| Delta while partial requests were held | Old limit | 128-limit / 256-KiB-stack candidate | Reduction |
| --- | ---: | ---: | ---: |
| Server connections / threads | 256 / +256 | 128 / +128 | 50.000% |
| Handles | +1,537 | +769 | 49.967% |
| Working set | +8,650,752 B | +4,505,600 B | 47.917% |
| Private bytes | +16,097,280 B | +7,823,360 B | 51.399% |
| Virtual memory | +546,308,096 B | +36,700,160 B | 93.282% |

The candidate returned from 30/158/30 threads and 180/949/181 handles across
baseline/held/released samples. Total admission is now 128, streaming admission
remains 64, and both control-client and dashboard-reader threads reserve 256
KiB. Thus saturated streams still leave 64 normal API/Raft slots. Atomic slot
acquisition and release are pinned by a unit regression.

The same release binary (SHA-256
`A556C39547CA66030714CB05B300614158E4AA78D550A87A9F1173A66122B8BF`)
then passed a 64-way hot run: 64/64 successful proposals, zero load errors,
stable leader and term, final commit/applied/last indexes 75/75/75 on every
node, equal final configuration, and zero unexpected audited log lines. All
healthy load and failover DNS probes succeeded. The restarted node's first
pre-ready probe timed out as expected, served the exact local answer at
273.157 ms, and fully rejoined at 294.956 ms. The observed 66.719 commits/s is
a single-run correctness result, not evidence of a throughput improvement.

That bounded candidate still cloned each accepted socket for shutdown tracking
and request parsing; a dashboard connection cloned it a third time for its
reader thread. `SharedTcp` now shares the single OS socket through `Arc` for all
of those paths. The same 300-client reproduction was repeated three times with
release SHA-256
`0D10D45EC7E26DA2A3EDBE6D190DC02AE50805CD1CF7ACD18D87B3DA04B1B06D`:

| Delta with 128 partial requests | Cloned-socket candidate | Shared socket R1 | R2 | R3 |
| --- | ---: | ---: | ---: | ---: |
| Server connections / threads | 128 / +128 | 128 / +128 | 128 / +128 | 128 / +128 |
| Handles | +769 | **+512** | **+512** | **+512** |
| Working set | +4,505,600 B | +4,476,928 B | +4,427,776 B | +4,161,536 B |
| Private bytes | +7,823,360 B | +7,671,808 B | +7,688,192 B | +7,344,128 B |
| Virtual memory | +36,700,160 B | +36,700,160 B | +36,700,160 B | +36,700,160 B |

The exact handle delta fell by 257, or 33.420%, in every repetition and returned
to its baseline after release. Relative to the original 256-connection build,
the handle delta is 66.688% lower. The memory differences versus the single
bounded-candidate run are not used as improvement claims.

The shared-socket binary also passed the 64-way hot regression: 64/64 commits,
zero load errors, stable leader/term, final indexes 75 on all nodes, equal
configuration, every healthy load/failover DNS probe successful, and zero
unexpected log lines. Leader handles rose from the same 190 baseline to 447,
versus 576 for the cloned-socket candidate: load delta +257 versus +386, again
33.420% lower. Restarted-node DNS readiness/full catch-up were 279.184/305.102
ms. The one-run 60.160 commits/s remains a correctness observation, not a
throughput comparison.

The current listener removes the remaining thread-per-partial-request cost.
Accepted sockets stay nonblocking until the complete header and declared body
have arrived. Bytes consumed during admission are replayed unchanged to the
existing HTTP parser, while no-progress polling backs off from 10 to 250 ms.
Unlike a rejected `MSG_PEEK` prototype, consuming the prefix also makes a FIN
after a partial request observable without waiting for the 15-second deadline.

Three clean repetitions used release SHA-256
`9D277E03A77E853869D9EC6A831191BEF4C856655F3F5026CC9603A5AB82B992`:

| Delta with 128 partial requests | Shared threaded | Nonblocking R1 | R2 | R3 |
| --- | ---: | ---: | ---: | ---: |
| Server connections / worker threads | 128 / +128 | 128 / **+0** | 128 / **+0** | 128 / **+0** |
| Handles | +512 | **+128** | **+128** | **+128** |
| Working set | +4,476,928 B | +114,688 B | +126,976 B | +118,784 B |
| Private bytes | +7,688,192 B | +86,016 B | +114,688 B | +102,400 B |
| Virtual memory | +36,700,160 B | **+0 B** | **+0 B** | **+0 B** |
| CPU during the 5-second hold | not sampled | 31.25 ms | 31.25 ms | 46.875 ms |

Every repetition returned threads, handles, and virtual memory exactly to its
baseline within the two-second release window. Relative to the original
256-connection build, the handle delta is 91.672% lower, the worst observed
working-set delta is 98.532% lower, the worst private-byte delta is 99.288%
lower, and worker-thread and virtual-memory amplification are eliminated.

The same binary passed a fresh 64-way hot regression: 64/64 commits, zero load
errors, stable leader and term, index 75 and equal final configuration on all
nodes, all healthy load/failover DNS probes successful, and zero unexpected
log lines. Restarted-node DNS readiness/full catch-up were 276.717/293.170 ms.
The leader rose from 31 to 95 threads and 190 to 383 handles during load, so
only the 64 complete requests were promoted. The one-run 54.070 commits/s is a
correctness observation, not a throughput comparison.

The final admission stage adds one atomic 8-MiB budget shared by pending
prefixes and prefixes already handed to parser threads. A 16-MiB prototype was
rejected after its geometric `Vec` capacity growth produced a 31,887,360-byte
private-memory delta. Final release SHA-256
`A7B5139E6374FA70D3C36DBF6F0C7E36CFF017D69CF366A0831C10B00128510A`
was repeated three times on both attack shapes with
`run-control-admission.ps1`, which generates an isolated single-node config
instead of depending on a previous artifact:

| Final delta | 1-byte R1 | R2 | R3 | 1 MiB−1 B R1 | R2 | R3 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Server connections | 128 | 128 | 128 | 7 | 7 | 7 |
| Worker threads | **+0** | **+0** | **+0** | **+0** | **+0** | **+0** |
| Handles | +128 | +128 | +128 | +7 | +7 | +7 |
| Working set | +118,784 B | +110,592 B | +114,688 B | +8,323,072 B | +8,335,360 B | +7,553,024 B |
| Private bytes | +102,400 B | +94,208 B | +94,208 B | +15,818,752 B | +15,822,848 B | +15,020,032 B |
| Virtual memory | **+0 B** | **+0 B** | **+0 B** | +17,129,472 B | +17,002,496 B | +17,133,568 B |
| CPU during 5-second hold | 62.5 ms | 62.5 ms | 46.875 ms | 0 ms | 0 ms | 15.625 ms |

Every large-body client sent a valid 1,048,576-byte `Content-Length` header but
withheld the final byte. All 32 client writes completed; the server retained
only seven connections and rejected the rest without creating a worker. All
handle deltas returned to baseline in the two-second release window. The
allocator retained at most 1,081,344 private bytes after release, so this is
reported rather than called zero.

The final binary also passed 64-way Raft load with 64/64 successes, zero load
errors, stable leader/term, index 75 and equal configuration on all nodes, all
healthy DNS probes successful, and zero unexpected log lines. Restarted-node
DNS readiness/full catch-up were 293.407/410.005 ms. The leader rose by exactly
64 threads and 193 handles while the complete requests ran. The one-run 52.496
commits/s is a correctness observation, not a throughput comparison.

Artifacts:

- partial-request reproduction: `target/control-admission/20260809T011646Z`;
- shared-socket repetitions: `target/control-admission/20260809T013147Z`,
  `20260809T013205Z`, `20260809T013212Z`;
- bounded 64-way Raft regression: `target/raft-ha/20260809T011722Z`;
- shared-socket 64-way Raft regression: `target/raft-ha/20260809T013229Z`;
- nonblocking-admission repetitions:
  `target/control-admission/20260809T020219Z-admission-v1`,
  `20260809T020232Z-admission-v2`, `20260809T020311Z-admission-v4`;
- nonblocking-admission 64-way Raft regression:
  `target/raft-ha/20260809T020336Z`;
- final 1-byte repetitions: `target/control-admission/20260809T022607Z-one-byte`,
  `20260809T022640Z-one-byte`, `20260809T022704Z-one-byte`;
- final large-body repetitions: `target/control-admission/20260809T022619Z-large-body`,
  `20260809T022653Z-large-body`, `20260809T022716Z-large-body`;
- final 64-way Raft regression: `target/raft-ha/20260809T022006Z`.

The pending-proposal counter later gained a progress notification on its final
1-to-0 transition. This removes snapshot compaction's accidental dependence on
the apply thread's periodic tick without increasing any test deadline. The
focused snapshot transport regression passed 20/20 repetitions, and the stats
seed regression independently passed 100/100 after its unrelated mock-UDP
dependency was removed.

The resulting release binary has SHA-256
`254CD96D3247398ECB27C7D9E305D58833EE63A190C052DC162615FCEB3CCCD0`.
Its fresh 64-way hot run completed 64/64 proposals with zero errors, stable
leader and term, indexes 75/75/75 and equal configuration on all nodes, all
healthy DNS probes successful, and zero unexpected audited log lines.
Restarted-node DNS readiness/full catch-up were 292.368/494.500 ms. The
single-run 53.788 commits/s is not used as a performance claim. Artifact:
`target/raft-ha/20260809T023819Z`.

## 2026-08-09 DNS data-plane availability audit

The current dirty worktree was rebuilt in an isolated target. Every run in
this section used release binary SHA-256
`A507D44F74EDF85AAAD48E156A285D01AC36AF682F5E23DED86A2324028552C9`.

The previous harness proved the consensus control path but did not send a DNS
query while proposals, leader election, or recovery were in progress. It could
therefore report a healthy HA run even if the surviving DNS data planes had
stopped serving. The harness now gives every node a local
`raft-health.test A 192.0.2.123` record and checks the transaction ID, QR bit,
rcode, answer count, and exact address without contacting an upstream. It
samples one node every 100 ms during load and every failover iteration, checks
both survivors immediately after the leader is terminated, and records the
restarted node's DNS-ready time separately from full Raft catch-up.

Six 64-way hot repetitions completed with 384/384 successful proposals, no
proposal failure, stable leader/term during every healthy load, final
commit/applied/last index 75 on all nodes, and equal final configuration:

| Metric | R1 | R2 | R3 | R4 | R5 | R6 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Commits/s | 66.757 | 63.713 | 61.562 | 55.536 | 60.233 | 64.926 |
| p50 (ms) | 889.735 | 917.127 | 831.587 | 959.256 | 844.524 | 877.456 |
| p95 (ms) | 901.749 | 938.486 | 871.509 | 997.751 | 881.494 | 893.085 |
| p99 (ms) | 903.637 | 939.398 | 876.318 | 1,003.967 | 885.390 | 897.002 |
| Election after kill (ms) | 642.863 | 481.221 | 899.289 | 498.702 | 676.584 | 686.478 |
| First new commit (ms) | 1,060.360 | 886.541 | 1,363.513 | 905.309 | 1,076.793 | 1,092.895 |
| Restarted DNS ready (ms) | 289.490 | 275.044 | 295.543 | 277.292 | 278.489 | 286.845 |
| Full rejoin (ms) | 385.660 | 301.112 | 318.158 | 302.810 | 417.199 | 303.104 |
| DNS probes | 27/27 | 25/25 | 29/29 | 27/27 | 27/27 | 27/27 |

The load phase answered 43/43 probes and the leader-election interval answered
53/53; all service phases together answered 162/162 with no wrong address,
rcode, timeout, or packet mismatch. The largest load/failover probe latency was
10.793/9.020 ms. The restarted process resumed DNS in 275.044--295.543 ms and
fully caught up in 301.112--417.199 ms. Peak load working set was
14,393,344--14,589,952 B and the largest private-byte peak was 9,781,248 B.

The throughput median was 62.638 commits/s, but the six-run range was
55.536--66.757 and `(max-min)/mean` drift was 18.063%. These values are an
observed operational range, not evidence of a performance change from the
2026-08-08 binary. The data-plane correctness result is independent of that
timing drift.

The same binary crossed the production compaction threshold under DNS probes:

| 4,096 `no_change` metric | Result |
| --- | ---: |
| Successful proposals | 4,096 / 4,096 |
| Commits/s | 420.491 |
| p50 / p95 / p99 | 86.159 / 122.162 / 463.072 ms |
| DNS service probes | 85 / 85 |
| Election / first new commit | 453.055 / 871.519 ms |
| Restarted DNS ready / full rejoin | 297.665 / 323.135 ms |
| Snapshot index | 4,097 / 4,097 / 4,097 |
| Final commit/applied/last index | 4,107 / 4,107 / 4,107 |
| Retained suffix entries | 10 / 10 / 10 |
| Peak working set / private bytes | 16,650,240 / 11,767,808 B |
| State / WAL bytes after recovery | 156 each / 933--2,535 |

The 32-entry `chain` workload also completed 32/32 at 25.004 commits/s,
answered 27/27 DNS probes, kept leader/term stable, converged at index 43 with
equal `cache_size`, resumed DNS in 291.066 ms, and fully rejoined in 324.527 ms.

All five primary artifact sets were manually scanned: the only warning in each
was one `raft.peer_unreachable` after the scripted leader kill, and there was
no error, panic, fatal, or fail-stop line. The harness now enforces that rule
itself: warnings during healthy load and every severe line at any time fail the
run, while only `raft.peer_unreachable` timestamped after the intentional kill
is accepted. Three additional 64-way executions exercised this automatic gate
with unexpected count 0 and expected failover warning count 1 each.

Artifacts:

- hot: `target/raft-ha/20260809T005911Z`, `20260809T005920Z`,
  `20260809T005930Z`, `20260809T010203Z`, `20260809T010230Z`,
  `20260809T010239Z`;
- compaction: `target/raft-ha/20260809T005956Z`;
- resolver-chain replacement: `target/raft-ha/20260809T010014Z`.

## 2026-08-08 repeated current-worktree audit

The current dirty worktree was rebuilt in the isolated benchmark target. The
release binary used for every successful run below had SHA-256
`22C9E48E47735C01D6B11AFF3872D0C4F905A31CF7DE8B2B711AD5888427D3D8`.

The first 64-way hot run exposed a Windows availability defect after all 64 API
requests had committed. Node 3 reached log index 65 but stopped applying at
index 18 when an atomic configuration replacement returned transient access
denied (`os error 5`). The Raft state machine correctly failed closed rather
than acknowledging further application, but one short-lived Windows file
sharing collision unnecessarily removed a healthy replica from consensus.
`replace_file` now retries only access-denied, sharing-violation, and
lock-violation errors with a bounded 1/2/4/8/16/32/64/64 ms backoff (191 ms
maximum). Every other error returns immediately, and an unresolved transient
collision still reaches the existing fail-stop path. A unit test fixes both
the retry allowlist and the bound.

Three clean 64-way hot runs of the fixed binary then completed with no error,
warning, panic, or fail-stop log line:

| Metric | Run 1 | Run 2 | Run 3 |
| --- | ---: | ---: | ---: |
| Successful proposals | 64 / 64 | 64 / 64 | 64 / 64 |
| Error rate | 0% | 0% | 0% |
| Applied commits/s | 64.363 | 69.797 | 67.621 |
| Request p50 (ms) | 701.476 | 804.754 | 683.517 |
| Request p95 (ms) | 874.379 | 813.469 | 852.967 |
| Request p99 (ms) | 900.164 | 843.691 | 853.679 |
| Leader/term stable | yes | yes | yes |
| Intentional-kill election (ms) | 612.419 | 958.754 | 934.037 |
| First post-kill commit (ms) | 1,021.041 | 1,365.315 | 1,345.106 |
| Killed-node rejoin (ms) | 535.432 | 536.496 | 527.144 |
| Final commit/applied/last index | 75 / 75 / 75 | 75 / 75 / 75 | 75 / 75 / 75 |
| Peak load working set (B) | 14,942,208 | 14,794,752 | 14,430,208 |

The median observed throughput was 67.621 commits/s. These repetitions establish
correctness and an observed range, not a cross-version performance improvement:
election time is randomized and the host was not isolated for comparative
benchmarking.

The same binary also crossed the production compaction threshold with 4,096
`no_change` proposals:

| 4,096-entry metric | Result |
| --- | ---: |
| Successful proposals | 4,096 / 4,096 |
| Error rate | 0% |
| Applied commits/s | 476.732 |
| Request p50 / p95 / p99 | 87.178 / 105.356 / 456.086 ms |
| Leader/term during healthy load | node 3 / term 1, unchanged |
| Snapshot index | 4,097 / 4,097 / 4,097 |
| Final commit/applied/last index | 4,107 / 4,107 / 4,107 on all nodes |
| Retained suffix entries | 10 / 10 / 10 |
| Intentional-kill election / first commit | 900.137 / 1,304.805 ms |
| Killed-node rejoin and catch-up | 535.802 ms |
| Final replicated value | equal on all nodes |
| Leader load working-set / private peak | 15,970,304 / 10,706,944 B |

Finally, the harness audit found that its `restart` workload had drifted away
from production semantics: `cache_size` is now one of 249 in-place settings and
rebuilds only the resolver chain. The legacy workload and its artificial settle
delay were removed, with no compatibility alias. The replacement `chain`
workload committed 32/32 changes in eight four-way batches, kept node 1 / term 1
stable, survived leader termination, converged at index 43 on every node, and
rejoined in 555.792 ms. It produced no restart, consensus-reuse, warning, or
error event, as expected. Only `run_as_user` and `run_as_group` still require a
full service generation, and this loopback benchmark intentionally does not
mutate process identities.

Artifacts:

- `target/raft-ha/20260808T104548Z` (pre-fix transient replace failure)
- `target/raft-ha/20260808T105039Z`, `20260808T105050Z`,
  `20260808T105100Z` (three fixed 64-way hot repetitions)
- `target/raft-ha/20260808T105117Z` (4,096-entry snapshot threshold)
- `target/raft-ha/20260808T105709Z` (renamed 32-entry chain workload)

## 2026-08-01 current-worktree revalidation

The current dirty worktree was rebuilt in the isolated benchmark target. The
release binary SHA-256 was
`14AB129615682CD537762110B015BC4D11243F0E68DE9E11C880D928839FB725`.
Two production-path runs completed without an error, fatal, or panic log line.
They are correctness and resource observations from one run each, not an
interleaved throughput comparison with the older binaries below.

| 64-way hot metric | Result |
| --- | ---: |
| Successful proposals | 64 / 64 |
| Error rate | 0% |
| Applied commits/s | 61.425 |
| Request p50 / p95 / p99 | 824.557 / 888.399 / 890.379 ms |
| Leader/term during healthy load | node 1 / term 1, unchanged |
| Intentional-kill election / first commit | 1,475.691 / 1,887.780 ms |
| Killed-node rejoin and catch-up | 523.670 ms |
| Final commit/applied/last index | 75 / 75 / 75 on all nodes |
| Final replicated value | equal on all nodes |
| Leader load working-set / private peak | 13,795,328 / 9,314,304 B |

The production-threshold diagnostic then ran 4,096 `no_change` proposals with
the same binary. This keeps the authenticated transport, WAL barriers,
ordered state-machine application, and compaction work while excluding config
rewrite and service-generation replacement.

| 4,096-entry metric | Result |
| --- | ---: |
| Successful proposals | 4,096 / 4,096 |
| Error rate | 0% |
| Applied commits/s | 254.055 |
| Request p50 / p95 / p99 | 120.828 / 174.425 / 473.278 ms |
| Leader/term during healthy load | node 3 / term 1, unchanged |
| Snapshot index | 4,097 / 4,097 / 4,097 |
| Final commit/applied/last index | 4,107 / 4,107 / 4,107 on all nodes |
| Retained suffix entries | 10 / 10 / 10 |
| Intentional-kill election / first commit | 618.483 / 1,027.492 ms |
| Killed-node rejoin and catch-up | 527.736 ms |
| Final replicated value | equal on all nodes |
| Leader load working-set / private peak | 15,654,912 / 11,558,912 B |

The snapshot reclaimed 4,097 of 4,107 absolute indexes (99.76%) while every
node converged on the same snapshot, retained suffix, log tail, applied index,
and configuration after leader failure and rejoin.

Artifacts:

- `target/raft-ha/20260801T060901Z` (64-way hot)
- `target/raft-ha/20260801T060941Z` (4,096-entry snapshot threshold)

## 2026-07-26 process-owned consensus across service generations

The pre-fix release binary (`0D6C1E8...`) reproduced the remaining lifetime
gap with sixteen concurrent `cache_size` proposals: all 16 committed, but an
ordinary DNS service-generation replacement moved the healthy cluster from
term 1 to term 2 (`LeaderStable=false`). The artifact is
`target/raft-ha/20260726T030853Z`.

Raft transport, persistent consensus state, proposal workers, and apply worker
are now owned by the process instead of a DNS service generation. A matching
node ID, listen address, peer/key set, secret digest, and state path reuses the
same runtime while only its generation-specific hot-apply and restart target
is replaced. An actual change to those node-local fields still replaces the
runtime. The target swap and Raft config write share the config transaction
lock: an apply before the swap is detected as file drift by the new generation,
and an apply after it wakes the new generation directly.

The first post-fix release (`6F045D41...`) repeated the same sixteen-way test.
All 16 proposals committed, leader 2 and term 1 remained unchanged, and the
final configuration and log indexes converged on every node. A stronger run
then split 32 restart proposals into eight four-way batches so the cluster had
to cross repeated service-generation boundaries rather than one replacement.

| Repeated-generation metric | Result |
| --- | ---: |
| Successful proposals | 32 / 32 |
| Error rate | 0% |
| Applied commits/s | 4.902 |
| Request p50 / p95 / p99 | 63.926 / 434.002 / 435.794 ms |
| Leader/term during load | node 3 / term 1, unchanged |
| Leader stability required / observed | true / true |
| Intentional-kill election / first commit | 476.004 / 895.455 ms |
| Killed-node rejoin and catch-up | 1,140.101 ms |
| Final commit/applied/last index | 43 / 43 / 43 on all nodes |
| Final replicated value | equal on all nodes |

The two surviving process logs each contain one `raft.consensus_started` and
thirteen `raft.consensus_reused` events across the load and post-failure
configuration replacements. Only the intentionally killed process starts a
new consensus runtime after process re-execution. The single pre/post runs are
correctness brackets, not a throughput-improvement claim.

Artifacts:

- `target/raft-ha/20260726T031616Z` (same-shape sixteen-way post-fix bracket)
- `target/raft-ha/20260726T031712Z` (eight load batches and repeated generations)

## 2026-07-26 current-worktree durability and recovery audit

The current worktree was rebuilt in the isolated benchmark target. The final
binary SHA-256 was
`29C73264EADC3C3696238664A2945DE4305B48B620614DB2F52B5984073A294D`.
No runtime dependency or external load generator was added.

The audit found two production defects and one measurement gap:

1. A checksum failure in a complete WAL frame before another valid frame was
   treated like an incomplete crash tail. Startup could therefore silently
   roll durable term, vote, or log state back to the previous frame. Complete
   middle-frame corruption now fails closed, while an actual prefix of an
   interrupted final frame is still ignored and repaired on the next append.
2. A leader ignored the follower's authenticated last-index hint after a
   rejected append and decremented `next_index` one entry per round trip. A
   follower missing a long suffix now jumps directly to its reported tail plus
   one; the hint is bounded by the existing one-step fallback so it can never
   move progress forward or skip a conflict.
3. The harness required only equal commit/applied indexes while the report
   described full log-tail convergence. Equal `last_index` is now an explicit
   convergence condition and is recorded in `summary.json`.

The same 64-way hot workload was run once immediately before and after the
fixes. These are regression brackets, not enough repetitions for a throughput
improvement claim.

| 64-way hot metric | Before | After |
| --- | ---: | ---: |
| Binary SHA-256 prefix | `456D4C61` | `29C73264` |
| Successful proposals | 64 / 64 | 64 / 64 |
| Leader/term stable | yes | yes |
| Applied commits/s | 43.883 | 44.372 |
| Request p50 / p95 / p99 | 1268.163 / 1355.549 / 1358.752 ms | 1263.460 / 1355.266 / 1358.923 ms |
| Intentional-kill election | 610.463 ms | 711.031 ms |
| First post-kill commit | 1030.725 ms | 1126.839 ms |
| Rejoin and catch-up | 539.726 ms | 528.895 ms |
| Final commit indexes | 75 / 75 / 75 | 75 / 75 / 75 |
| Final last indexes | not recorded by old harness | 75 / 75 / 75 |
| Final replicated value | equal | equal |
| Leader load working-set peak | 14,491,648 B | 14,159,872 B |
| Leader load private-byte peak | 18,817,024 B | 18,255,872 B |

The post-fix run therefore shows no hot-load throughput, latency, or memory
regression. Election time varies with the randomized timeout and is reported,
not interpreted as an optimization result.

Before the process-owned lifetime fix, a separate full service-generation replacement run used 32 simultaneous
`cache_size` changes. All 32 proposals committed successfully at 13.048/s;
p50/p95/p99 were 732.655/802.043/803.448 ms. Rebuilding the three service
generations also recreated their Raft runtimes, so the leader changed and the
term moved from 1 to 2. This historical result exposed the lifetime gap; the
process-owned audit above supersedes it and now requires stability for every
workload. After the
subsequent intentional leader kill, a new proposal committed in 661.754 ms.
The killed node rejoined, performed its service replacement, and converged in
1480.888 ms; commit, applied, and last indexes were 53 on all nodes and the
three persisted configuration values were equal.

Artifacts:

- `target/raft-ha/20260726T012412Z` (pre-fix 64-way hot bracket)
- `target/raft-ha/20260726T012955Z` (post-fix 64-way hot bracket)
- `target/raft-ha/20260726T013323Z` (post-fix full restart)

## 2026-07-26 production-threshold state-machine snapshot audit

The release binary with SHA-256
`0D6C1E8B5A78FD8B1D8E6E0ECA4A86041AE8310A297B581216F308B0649AB214`
ran 4,096 concurrent-windowed `no_change` proposals. This isolates consensus,
authenticated transport, WAL durability, applied-index advancement, and log
compaction from configuration rewrite and service-generation costs.

| Metric | Result |
| --- | ---: |
| Successful proposals | 4,096 / 4,096 |
| Error rate | 0% |
| Applied commits/s | 144.858 |
| Request p50 / p95 / p99 | 338.335 / 407.318 / 509.125 ms |
| Leader/term stable during load | yes, node 1 / term 1 |
| Snapshot index after recovery | 4,097 / 4,097 / 4,097 |
| Final last index | 4,107 / 4,107 / 4,107 |
| Retained suffix entries | 10 / 10 / 10 |
| Base state file size | 156 / 156 / 156 B |
| WAL size after recovery | 933 / 2,535 / 2,624 B |
| Intentional-kill election / first commit | 1,552.656 / 1,968.598 ms |
| Killed-node rejoin and catch-up | 572.652 ms |
| Final replicated value | equal on all nodes |

The initial leader no-op plus 4,096 proposals produced snapshot index 4,097.
After the deliberate failure/recovery phase, every node retained only ten
post-snapshot entries out of 4,107 total indexes: **4,097 entries (99.76%) were
actually reclaimed** while absolute indexes and terms continued across the
snapshot boundary. Leader load working set peaked at 23,560,192 bytes; the two
followers peaked at 19,292,160 and 19,226,624 bytes. The leader's 91-thread
peak is the bounded 64-request HTTP load, not retained Raft history.

The authenticated three-node integration gate separately leaves a follower
offline across the compaction boundary, starts it with no log or application
state, and requires `InstallSnapshot` plus suffix application to reproduce the
leader's exact state. That gate completes in 0.84 seconds on this host. The
first version of the gate exposed a real self-deadlock: an `if let` temporary
held the Raft node mutex while the apply thread installed the state machine and
then tried to finalize the same node. Snapshot extraction now ends the lock
scope before any application callback or persistent completion ACK.

Artifact:

- `target/raft-ha/20260726T024834Z` (4,096-entry production threshold)

## 2026-07-21 current-worktree 64-way saturation

The latest worktree was rebuilt as an isolated release binary with SHA-256
`385C561F06A65D26F2D607988D9581DBD669AF7E09C4E5259B4BE95A3E249369` and
tested with 64 simultaneous hot-apply proposals. The first run exposed an
unsolicited election under otherwise healthy load: the leader's tick thread
was also executing every committed state-machine entry, so a long apply batch
suppressed heartbeats long enough for a follower to start term 2.

Raft time progression and state-machine application are now separate bounded
threads. The tick thread continues heartbeats while the apply thread executes
entries sequentially and checkpoints the same contiguous applied range. Log
ordering, quorum acknowledgement, WAL barriers, and per-request durable
completion are unchanged.

| 64-way hot-apply metric | Before separation | After separation |
| --- | ---: | ---: |
| Successful proposals | 64 / 64 | 64 / 64 |
| Load error rate | 0% | 0% |
| Leader/term stable during healthy load | **no** | **yes** |
| Load convergence | 1,560.722 ms | 1,179.496 ms |
| Applied commits/s | 41.007 | 54.260 |
| Request p50 / p95 / p99 | 838.832 / 895.844 / 906.827 ms | 1,020.484 / 1,102.560 / 1,103.890 ms |
| Intentional-kill election | invalidly preconditioned at 129.642 ms | 569.800 ms |
| First post-kill commit | invalidly preconditioned at 163.447 ms | 978.563 ms |
| Rejoin and catch-up | 538.179 ms | 528.975 ms |
| Final commit indexes | 76 / 76 / 76 | 75 / 75 / 75 |
| Final replicated value | equal on all nodes | equal on all nodes |

The corrected run gained 32.3% throughput and removed the healthy-load leader
change. The previous 129.642 ms failover number is withdrawn: the cluster had
already replaced its leader during load, so the subsequent forced kill began
with election timers in an unrepresentative state. The corrected intentional
failure result is consistent with the earlier 32-way measurements.

The extra apply worker costs one idle thread per node. The corrected run peaked
at 14,503,936 bytes working set and 21,823,488 bytes private memory on the
64-request leader; followers stayed below 11,469,000 bytes working set and
16,850,000 bytes private memory. The leader peaked at 91 threads and 566
handles while the control plane held 64 simultaneous HTTP requests. The
benchmark now records the post-load leader and term and fails if either changes
before the deliberate leader termination.

Artifacts:

- `target/raft-ha/20260721T205654Z` (reproduction before separation)
- `target/raft-ha/20260721T210353Z` (corrected stable run)

## Measurement correction and cumulative optimization

The original harness read every request timer only after all requests in the
batch had completed. Those old p50/p95/p99 values were therefore batch wall
time, not request latency, and are withdrawn. Success counts, convergence,
failover, recovery, and resource samples were not affected. The harness now
records each timer as its own HTTP task completes.

The corrected harness was run against the unchanged serialized binary
(`E422...496`, artifact `20260719T183337Z`), the HTTP-lock-only binary
(`975B...EDA`, median of three runs), and the final durable-batching binary
(`A6E7...B0C3`, median of three runs).

| Hot-apply metric | Serialized baseline | HTTP lock removed | Final median | Final vs baseline |
| --- | ---: | ---: | ---: | ---: |
| Successful proposals | 32 / 32 | 32 / 32 | 32 / 32 | no regression |
| Load convergence | 2,504.176 ms | 1,203.481 ms | 935.199 ms | -62.7% |
| Applied commits/s | 12.779 | 26.590 | 34.217 | +167.8% |
| Request p50 | 1,312.810 ms | 793.880 ms | 578.865 ms | -55.9% |
| Request p95 | 2,222.745 ms | 964.080 ms | 584.072 ms | -73.7% |
| Request p99 | 2,281.772 ms | 964.834 ms | 585.931 ms | -74.3% |

The first bottleneck was a process-wide HTTP mutation lock held for the entire
quorum wait. Raft already orders proposals in its log, while the state-machine
path independently serializes the config read-modify-write transaction. The
redundant outer lock forced consensus rounds one at a time. It is now bypassed
only for Raft proposals; normal local mutations remain serialized, and Raft
proposals remain state-changing, admin-only, audited, and readiness-gated.

The next bottleneck was one WAL append and `sync_all` per concurrent proposal,
followed by another `sync_all` per applied index on every node. A bounded
standard-library queue now groups simultaneous proposals under the existing
256-entry / 512-KiB replication limits. It never merges or drops semantic log
entries: every request receives its own contiguous index and waits until that
index is applied. The state machine still runs every entry in order, then
persists the contiguous applied range once. Commit-only progress is recovered
from the leader after a crash and is persisted together with `last_applied`;
term, vote, new log entries, and conflict truncation retain their original
durability barriers.

Direct decoding of the final leader WAL confirmed that the 32-request load was
stored as one proposal-log frame and one applied-completion frame. Removing
either remaining barrier would weaken the guarantee that a follower ACKs only
durable log data or that a successful request has durably recorded application.

## Final measurements

Every run used 32 proposals at concurrency 32, killed the elected leader,
committed one availability probe plus eight verification changes on the
surviving quorum, and restarted the killed node. Hot values are three-run
medians; full restart and no-change are separate confirmation runs.

| Metric | Hot apply (median of 3) | Full restart | No-change diagnostic |
| --- | ---: | ---: | ---: |
| Successful load proposals | 32 / 32 | 32 / 32 | 32 / 32 |
| Load error rate | 0% | 0% | 0% |
| Load convergence time | 935.199 ms | 2,238.906 ms | 746.313 ms |
| Applied commits/s | 34.217 | 14.293 | 42.877 |
| Request p50 | 578.865 ms | 546.192 ms | 462.428 ms |
| Request p95 | 584.072 ms | 547.929 ms | 466.032 ms |
| Request p99 | 585.931 ms | 549.879 ms | 476.357 ms |
| New-leader election after kill | 778.200 ms | 784.804 ms | 599.658 ms |
| First post-kill commit | 1,241.908 ms | 1,234.540 ms | 1,010.667 ms |
| Failed probes / attempts | 7-9 / 16-18 | 8 / 17 | 6 / 15 |
| Killed-node rejoin and catch-up | 538.383 ms | 527.423 ms | 537.744 ms |
| Final commit indexes | 43 / 43 / 43 | 53 / 53 / 53 | 43 / 43 / 43 |
| Final replicated value | equal on all nodes | equal on all nodes | equal on all nodes |

The final hot runs observed at most 12,836,864 bytes of working set and
19,087,360 bytes of private memory during load. The proposal worker adds one
idle thread per node (25 follower threads versus 24 before batching); the
leader peaked at 58 threads and 373 handles while serving 32 simultaneous HTTP
requests. The restart run peaked at 11,964,416 bytes working set and 18,534,400
bytes private memory.

Each final hot run recorded all 123 state-machine applications as
`mode=hot_reload`; the restart run recorded all 123 as
`mode=service_restart`; the no-change run recorded all 123 as
`mode=no_change`. All five final runs had zero error events, zero failed load
proposals, equal final configuration, and equal commit/applied indexes on every
node.

The final restart result improves the earlier restart confirmation from
12.221 to 14.293 commits/s (+17.0%), and reduces p95 from 931.356 to 547.929 ms
(-41.2%). The no-change diagnostic improves from 30.705 to 42.877 commits/s
(+39.6%). A 32-proposal concurrency-1 diagnostic remains intentionally
unbatched at 7.399 commits/s with an 80.612-ms p50, showing that group commit
accelerates burst load without weakening single-request durability.

## Defects found by the benchmark

The saturation and durability work exposed eighteen gaps instead of hiding them
behind averages:

1. A newly elected leader did not append a current-term no-op. An entry
   inherited from the previous term could therefore remain uncommitted until
   another client proposal arrived. Leaders now persist and replicate an
   internal no-op immediately after election.
2. Configuration restart removed the global Raft handle before already
   accepted control requests completed. A 32-way run consequently returned
   25 false "Raft not configured" errors. Service cleanup now drains accepted
   requests before shutting down Raft; the same workload succeeds 32 / 32.
3. The harness initially treated equal `commit_index` values as full
   convergence. It now also requires every node's `last_applied` to equal its
   commit index before inspecting replicated configuration.
4. Per-request timers were sampled after the entire batch completed, making
   every latency percentile approximate batch wall time. Completion is now
   captured independently for each HTTP task.
5. The control plane serialized every Raft proposal behind a process-wide
   mutation lock even though the replicated log and config transaction already
   provide the required ordering.
6. The durable log path forced one fsync and replication dispatch per
   simultaneous proposal. A bounded proposal worker now performs group commit
   while retaining a distinct ordered log entry and completion condition for
   every caller.
7. Applied indexes and commit-only metadata were fsynced one entry at a time.
   Sequential state-machine execution is now checkpointed as one contiguous
   range, and commit-only progress no longer causes a redundant fsync directly
   before the applied checkpoint.
8. The tick thread also executed the entire committed state-machine batch.
   A sufficiently long batch therefore suppressed leader heartbeats and caused
   an unsolicited election under healthy 64-way load. Tick/heartbeat and apply
   execution are now independent, and a three-node slow-apply regression plus
   the end-to-end harness enforce leader/term stability.
9. Complete middle-WAL corruption was silently accepted as a torn final tail.
   It now prevents startup instead of rolling stable consensus state back.
10. Rejected replication ignored the follower tail hint and recovered long
    missing suffixes one RPC at a time. The bounded hint now jumps directly to
    the earliest safe retry index.
11. The harness claimed log convergence without checking every node's
    `last_index`. It now requires full tail convergence, and every workload
    requires leader/term stability until the intentional failure phase.
12. Raft proposals could mutate node-local identity, listen, peer, and key
    settings. These fields are now rejected alongside secret-bearing fields;
    snapshots contain only cluster-managed configuration values.
13. WAL byte compaction did not reclaim the consensus log, so a long-running
    cluster eventually stopped at 100,000 entries. Applied prefixes are now
    replaced by durable state-machine snapshots every 4,096 entries.
14. Immediate compaction could erase an entry's term while its client was still
    waiting to verify that the same proposal committed. Compaction now waits
    until the bounded in-flight proposal count reaches zero.
15. A completed snapshot from an old leader remained eligible for installation
    after a higher term arrived. Pending snapshots are now bound to leader ID
    and leader term and are discarded on term change.
16. The apply worker held the node mutex through snapshot callback dispatch and
    deadlocked when finalizing the same snapshot. The pending payload is now
    cloned in a separate lock scope before application code runs.
17. The benchmark capped proposals at 300 and could never cross the production
    snapshot threshold. It now accepts long-run loads and records snapshot and
    retained-suffix indexes per node.
18. DNS service-generation replacement also destroyed and recreated the Raft
    runtime, forcing an election for ordinary `cache_size` changes. Consensus
    is now process-owned; generation callback replacement is serialized with
    Raft config application so concurrent changes cannot be lost at the swap.

Artifacts from the final runs are under:

- `target/raft-ha/20260719T190839Z` (final hot 1)
- `target/raft-ha/20260719T190847Z` (final hot 2)
- `target/raft-ha/20260719T190855Z` (final hot 3)
- `target/raft-ha/20260719T190925Z` (final no-change diagnostic)
- `target/raft-ha/20260719T190933Z` (final full restart)

The corrected serialized baseline remains at
`target/raft-ha/20260719T183337Z`.

## Scope

These are same-host loopback measurements, useful for deterministic protocol,
failure, persistence, and resource regression testing. They are not a claim
about multi-host network latency or a direct comparison with another DNS
engine. Run the same harness on the deployment hardware and network before
using the timing values as an operational SLO.
