# ELIOT Cognitive Completion Recovery — Task 03 Blocker Report

Date: 2026-08-01  
Repository: `projects/eliot-memory-os`  
Branch: `codex/cognitive-completion-v2`  
Starting pushed commit: `cfe38bed10eaa418927ec1eaed3f608d49c23a70`  
Disposition: **BLOCKED / SLO_NOT_MET**

## Executive result

Task 03 is not complete. The correctness part of the retrieval repair is
implemented and restored to a green state, but the required latency is not.
Normal L0 no longer performs the old unbounded six-kind paged scan. It uses a
revision-bound derived search projection with deterministic rebuild and an
idempotent post-commit outbox. The real cognitive retrieval suite passes 5/5.

The retained correctness-first PF1 result at 10,000 logical records is L0
680.3451 ms and L2 486.3797 ms. A bounded-posting experiment improved those
numbers to L0 236.7372 ms and L2 80.1493 ms, but subsequent attempts to close
the remaining L0 gap caused neutral-paraphrase recall regressions. Those
attempts were rolled back. PF2, PF3, and exact R01 were intentionally not run.

The repository is not left with a cognitive regression: after rollback,
SurrealQL validation, `cargo check -p eliot-store`, and the isolated real
retrieval suite all pass.

## Contract and stop decision

Task 03 required:

- 100,000 logical current records;
- 5,000 historical updates;
- four record kinds;
- warm L0 p95 no greater than 75 ms;
- small L2 p95 no greater than 150 ms;
- no more than 12 query terms;
- candidate handles capped before full rows;
- canonical tables as truth, with deterministic rebuild;
- no provider calls during retrieval certification.

The staged plan required PF1 at 10k before PF2/PF3/R01. PF1 passed the
2-second safety timeout but missed the final L0 target by 9.07x in the retained
implementation. Continuing immediately to 100k would have consumed minutes
without satisfying the readiness purpose of PF1. Repeated optimization branches
then caused new cognitive failures. Per the user stop rule and workspace
two-attempt rule, the optimization was stopped and escalated rather than turned
into open-ended test churn.

## Implemented and retained

### Derived search state

The following SurrealDB tables and indexes were added:

- `memory_search_projection`: one current row per project/handle;
- `memory_search_token`: project/token/handle postings;
- `memory_search_state`: applied project revision;
- `memory_search_outbox`: pending/applied derived dispatch state;
- unique project+handle projection index;
- project+lifecycle+kind+revision projection index;
- project+token+handle posting index;
- project+handle posting index;
- unique write outbox index;
- project+status+revision outbox index.

Canonical write order is:

1. commit the canonical envelope and pending outbox row;
2. derive the complete current projection rows from the accepted envelope;
3. replace each handle's postings idempotently;
4. advance `memory_search_state` only after the final bounded batch;
5. mark the outbox entry applied.

If step 2–5 fails, canonical truth is already committed and the outbox remains
pending. Replaying the same write returns an idempotent canonical receipt and
repeats only the convergent derived dispatch.

### Read correctness

Normal L0:

- verifies `projection_revision == scope_head.memory_revision`;
- rebuilds from canonical rows when missing or stale;
- supports an exact handle lookup;
- caps the candidate list at 256 before full projection rows are returned;
- restores the authoritative handle order in Rust;
- preserves the existing Rust ranker and 12-result response cap.

Lifecycle audit keeps the old paged path so archived/quarantined/forgotten and
other audit-only rows remain inspectable. Rebuild reads a stable canonical
revision, replaces the project projection deterministically, and advances the
derived revision only after all bounded batches.

### Transport and SurrealDB 3.1 repairs

Two live-only failures were repaired:

1. Colon-bearing strings such as `claim:<uuid>` were interpreted as SurrealDB
   record identities and truncated at a hyphen. Handles and record references
   now cross the RPC boundary as character fragments and are joined inside
   SurrealQL.
2. A one-row nested `SELECT` may be returned as an object instead of an array.
   Affected subqueries are normalized with wrapper/flatten/filter before array
   operations. The final `SELECT ... WHERE handle IN ...` does not guarantee
   input order, so the query returns an authoritative ordered handle list and
   Rust reorders the bounded rows.

## Attempt journal

### A. Correctness-first projection

Initial live isolated retrieval runs:

- first run: 2/5, unique-index collisions from record-id coercion;
- second run: 2/5, scalar/object results passed to `array::len`;
- focused repaired run: 1/1 pass;
- complete repaired run: 5/5 pass, 35.744 s test summary;
- EXPLAIN+rebuild focused run: 1/1 pass, 10.740 s test summary.

EXPLAIN confirms use of `idx_memory_search_token_posting`. The rebuild test
confirms the same ordered feature-score result before and after reconstruction.

### B. PF1 evidence publication

The first PF1 command was accidentally given a 60-second outer shell limit,
shorter than the 600-second test guardian. This killed the wrapper rather than
timing out a retrieval call. The exact isolated Surreal process was stopped via
its owned stop file. No production/default Surreal process was touched.

The interrupted run's exact roots remain because the later recursive cleanup
was rejected by the host command policy:

- `%TEMP%/eliot-governor-workspace-tests-47400-ec58419dc22849e1aa6d1a96ef5d798d`
- `%LOCALAPPDATA%/Eliot/tests/ec58419dc22849e1aa6d1a96ef5d798d`

There is no live process for that run. All subsequent harness runs cleaned their
owned temp and secret roots exactly.

The scale test now optionally writes its successful measurement JSON to an
explicit external path, preventing nextest success-output suppression or a
connection interruption from losing timings.

Retained correctness-first PF1:

| Metric | Result |
| --- | ---: |
| Logical records | 10,000 |
| Historical updates | 500 |
| Record kinds | 4 |
| Seed | 48,732 ms |
| Measured L0 | 680.3451 ms |
| Measured L2 | 486.3797 ms |
| Query wall | 1,166 ms |
| Per-query timeout | 2,000 ms |

### C. Bounded posting pages

The global posting aggregation and ambient fill were replaced experimentally
with per-term pages capped at 257, a union bounded to at most 3,084 postings,
and a final 256-handle cap. The retained experimental evidence is:

`%LOCALAPPDATA%/Eliot/cognitive-field/recovery-v3-task03/pf1-bounded-postings.json`

| Metric | Result |
| --- | ---: |
| Logical records | 10,000 |
| Historical updates | 500 |
| Seed | 55,620 ms |
| Measured L0 | 236.7372 ms |
| Measured L2 | 80.1493 ms |
| Query wall | 316 ms |

This proved that bounded postings materially reduce latency, but it did not
meet the 75 ms L0 target.

### D. N-gram primary and conditional fallback — rejected

Idea:

- store deterministic bigram/trigram postings;
- query at most two specific terms on the fast path;
- run an up-to-12-unigram fallback only when the primary admitted no memory.

Results:

- cognitive suite regressed from 5/5 to 2/5;
- fallback improved it to 3/5;
- a provider/argv/opaque-identifier paraphrase still returned no memory;
- a primary false positive could suppress fallback even when the expected
  candidate was absent;
- for long rows, n-grams could consume the 128-posting budget before unigrams.

The cascade was rejected rather than calibrated with another arbitrary score
threshold.

### E. Concurrent posting pages with Rust union — not accepted

Following the second Opus recommendation, an experimental implementation issued
per-term posting pages concurrently and moved overlap/authority aggregation to a
Rust `BTreeMap`, followed by one bounded row fetch. A protected Surreal variable
name was repaired (`$token` to `$search_token`), but the neutral provider/argv
case still failed. This branch was rolled back under the stop rule before scale
testing.

## Claude Code Opus 5 consultations

Both consultations were headless. No GUI was used.

Common invocation constraints:

- exact model `claude-opus-5`;
- existing session `703f5a06-7b30-4783-bce1-e74d4de580ba`;
- max effort, plan permission mode;
- strict empty MCP configuration;
- read-only allowed tools;
- no permission denial, web, MCP, or file write.

First consultation:

- 117.4 s wall / 114.102 s API;
- CLI-reported USD 2.342597;
- confirmed scalar/array normalization;
- required ordered handles to survive unordered final fetch;
- warned against object-level dedup and unnormalized inputs.

Second consultation:

- 144.2 s wall / 141.458 s API;
- CLI-reported USD 2.449322;
- rejected conditional fallback;
- recommended always unioning all admitted terms;
- recommended concurrent term pages and Rust aggregation;
- specified content-only deterministic posting selection;
- specified advisory DF derived by recomputation, never authoritative deltas;
- defined acceptance and stop probes.

## Final verification after rollback

| Check | Result | Duration |
| --- | --- | ---: |
| SurrealDB 3.1.4 validation of final retrieval query | PASS | included in final command |
| `cargo check -p eliot-store` | PASS | 2.24 s |
| Isolated real `memory_retrieval` suite | 5/5 PASS | 36.756 s test summary |
| Final harness end to end | PASS | 54.786 s |

The earlier non-isolated `cargo test` reported 5/5 in 11.1 s but all test bodies
returned immediately because the isolated Surreal environment variables were
absent. It is recorded as a discovery mistake and is not counted as behavioral
evidence.

## Next bounded work package

Do not resume with another conditional cascade. The next attempt should be a
small, instrumented proof package:

1. preserve the complete 5/5 neutral cognitive corpus as the first gate;
2. measure 10k, 30k, and 100k with the same capped query to estimate the
   scaling exponent;
3. attribute posting-page wall, aggregation/rank, and final-row-fetch time;
4. prove every query term used for admission survives deterministic posting
   selection on long identifier-heavy rows;
5. if parallel pages are retried, use a persistent connection/pool rather than
   opening one supervisor/transport per term;
6. add advisory document-frequency cache only by full/range recomputation;
7. require expected cognitive handles to rank within 128 of the 256 candidates;
8. stop if the final 256-row fetch alone exceeds about 50 ms or the capped path
   still scales approximately linearly with corpus size.

Only after PF1/PF2/PF3 pass should exact R01 be run once. Provider
certification must remain paused until R01 passes.

## Eliot writeback and exact readback

The final blocker was written through the running sealed product daemon, not by
opening a competing embedded SurrealKV owner. The authenticated path was the
headless `claude_governed` MCP profile over the daemon named pipe.

Canonical scope used for this handoff:

- project `461b9de3-26e9-8f15-89b1-fb3944e22941`;
- existing task `019fbc2c-9872-7ac3-9112-766c57674ed8` from the current
  provider-runtime cycle, because recovery Task 03 did not create a separate
  product task contract;
- daemon runtime `019fbd49-e2ac-7490-8fcd-6762e34d5c13`;
- auth generation `019fbd49-e2d0-7550-8cdc-a58b9487a16e`.

Reusable blocker candidate:

- write/receipt `b0c14f5f-569d-42ca-8966-32f71bf5dc28`;
- handle `claim:b0c14f5f-569d-42ca-8966-32f71bf5dc28`;
- status `candidate_committed`, `candidate_only=true`;
- memory revision advanced from 11 to 12;
- one primary and one secondary explicit file cue;
- controller reconciliation remains required.

The first recall probe used `scope=candidate_only`. That value was interpreted
as a retrieval scope rather than a lifecycle selector, so the new claim was
honestly reported as `scope_mismatch`. No retry-write was made. Exact
`eliot_fetch_l2` by the committed handle at revision 12 then returned the full
statement, provenance, negative constraints, task relation, and candidate
status with no missing handle.

Detailed failure observation:

- write/receipt `7b319d25-6a2a-4945-a6ca-1d23b6cf0727`;
- handle `observation:7b319d25-6a2a-4945-a6ca-1d23b6cf0727`;
- status `committed`;
- memory revision advanced to 13;
- exact `eliot_fetch_l2` returned the retained PF1 timings, the rejected faster
  path, the two failed cognitive approaches, final verification durations, and
  the explicit decision not to run PF2/PF3/R01.

The global raw SurrealDB MCP tool was not exposed in this Codex turn. The
product daemon path was used because it preserves the one-owner rule and adds
governed receipts. Repository-local `.eliot/` state was neither modified nor
staged.

After the two already completed Opus 5 consultations, the Claude Code Opus
quota became unavailable for roughly two hours. Antigravity Opus 4.6 remained
available, but no third consultation was spent: the stop condition and next
bounded experiment were already established, and another model call could not
turn the failed PF1 into acceptance evidence.

## Final finish gate

The final `clippy -D warnings` pass found three local maintainability findings:

1. the new retrieval row constructor had 20 positional arguments;
2. the exhaustive enum-to-SQL template table crossed Clippy's 100-line limit;
3. the scale harness intentionally prints its one machine-readable JSON result
   to stdout.

The constructor was repaired structurally with a named `RecallCandidateInput`,
which also prevents accidental field-order swaps. The two remaining lints have
narrow documented exceptions at the exact interfaces: splitting the exhaustive
template table would weaken its auditability, and stdout is part of the test
harness contract.

Final checks after that repair:

| Check | Result | Duration |
| --- | --- | ---: |
| `cargo clippy -p eliot-store --all-targets -- -D warnings` | PASS | 0.812 s |
| `cargo fmt --all -- --check` | PASS | included in 2.200 s combined check |
| `git diff --check` | PASS | included in 2.200 s combined check |
| SurrealDB validation of six touched `.surql` files | 6/6 PASS | 1.790 s |
| Post-refactor isolated real `memory_retrieval` suite | 5/5 PASS | 36.049 s test summary |
| Post-refactor isolated harness end to end | PASS | 48.394 s |

The first post-refactor harness command spawned a fresh `powershell.exe`; that
child rejected the local script under its ExecutionPolicy in 0.623 s before any
test or SurrealDB process started. It was retried in the already authorized
current PowerShell host. The successful run removed both its exact temporary
root and exact secret root, stopped all owned processes, made zero provider
calls, and reported no cleanup failure.

This finish gate verifies the retained implementation and report integrity; it
does not change the task disposition. PF1 still misses the required latency
SLO, so Task 03 and the overall recovery Goal remain blocked rather than
`DONE_VERIFIED`.

The finish-gate receipt was also persisted as
`observation:e445da7f-9a3e-40ab-bf6a-7da4bb8a5b59`; exact L2 readback at
revision 14 returned all check durations, cleanup facts, zero provider calls,
and the unchanged `FAILED_VERIFIER` disposition.
