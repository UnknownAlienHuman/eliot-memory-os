# ELIOT PROVIDER-RUNTIME-CONSOLIDATION
## Remove duplicate provider runtime paths, prove the real routes, then continue the existing completion plan

**Version:** 2.1 FINAL  
**Repository / branch:** `UnknownAlienHuman/eliot-memory-os` / `codex/cognitive-completion-v2`  
**Start:** `7bb7c8f4cef6db7c7df06f20eb94f7cd5ffa7a7d` or direct descendant  
**Supersedes:** pending `AUTH-LC-*`, `ANTIGRAVITY-REPAIR-*`, timeout-only and call-budget repairs  
**Before local behavior gates:** no provider calls  
**Forbidden:** GUI, Computer Use, new DB/framework/actor system/MCP tool, another runner, another timeout helper  
**After PASS:** continue Recovery Plan v3.0 automatically

---

# 1. Why this task exists

The last Antigravity fix changed `SharedAntigravityProcessExecutor`, but the failing
`external-agent mcp-smoke` used `run_external_agent_process` and another timeout profile.

Current branch also has:

| Duplicate policy/owner | Current symptom |
|---|---|
| several `ProviderTimeoutProfile` literals | fixing one route does not fix another |
| inner process deadline + outer `AdapterSupervisor` timeout | two clocks may cancel the same call differently |
| process restart policy + supervisor retry | two potential retry owners |
| hardcoded `max_calls: 16` inside adapter | transport code decides campaign policy |
| Antigravity-specific MCP tool arrays | drift from canonical MCP catalog |
| result parsing owns process closeout | timeout/no-output attempts remain `Running` |
| `[[test]] path="src/main.rs"` | whole binary compiles twice |
| legacy and current runtime contract types in one active module | compatibility shape can leak back into runtime |

Required result:

```text
one provider route-policy owner
one provider process runner
one retry owner
one campaign-budget owner
one MCP tool-profile owner
one process terminalization path
zero compatibility executors
```

---

# 2. Preserve and inventory

Before edits:

```powershell
git switch codex/cognitive-completion-v2
git status --short
git rev-parse HEAD
git merge-base --is-ancestor 7bb7c8f4cef6db7c7df06f20eb94f7cd5ffa7a7d HEAD
git diff --binary | Out-File `
  (Join-Path $env:TEMP "eliot-provider-runtime-before.patch") -Encoding utf8
```

Create and push:

```text
archive/cognitive-completion-v2-pre-provider-runtime-<short-sha>
```

Generate a private inventory for every provider route:

```text
entry -> adapter -> process executor -> timeout policy -> outer timeout
-> retry owner -> campaign owner -> MCP profile -> parser -> journal closeout.
```

Include external-agent smoke, managed host, cognitive Worker/Reader/Judge, UL cross-agent,
Antigravity delegation, reasoning/exam/refinement.

Run:

```powershell
rg -n "ProviderTimeoutProfile\s*\{" crates
rg -n "ProcessRestartPolicy\s*\{" crates
rg -n "run_supervised_process|run_external_agent_process|AntigravityProcessExecutor|SharedAntigravityProcessExecutor" crates
rg -n "max_calls:\s*[0-9]+|campaign_closed:" crates
rg -n "SAFE_AUDITOR_MCP_TOOLS|LEGACY_GOVERNED_MCP_TOOLS" crates
rg -n "Command::new|StdCommand::new|tokio::process::Command" crates/eliot-app crates/eliot-engine
```

Prove the exact `external-agent-smoke-antigravity` call graph and effective policy ID/deadlines.
Do not infer it from a helper test or report prose.

---

# 3. One provider route policy

Keep one factory in the existing provider-policy owner:

```rust
ProviderRoutePolicy::for_route(host, operation_class, declared_budget)
```

It returns one stable policy ID/hash with:

```text
spawn deadline
first-output deadline
optional idle deadline
absolute deadline
cancel/cleanup/reconcile grace
output limit
incremental-output capability
status-lookup capability
```

Rules:

1. `ProviderTimeoutProfile` cannot be constructed outside its owner.
2. Current CLI routes have **no dispatch-ack deadline**. No distinct parsed ack event exists.
3. Process spawn, dispatch start, provider ack and first output remain separate facts.
4. `AdapterSupervisor` derives its outer deadline from this same policy; manifest timeout does not
   independently override provider execution.
5. The actual policy ID/hash is bound into request, runtime contract, attempt and result evidence.
6. Same route + budget produces byte-identical policy.
7. Preserve declared provider budgets; do not increase them for PASS.
8. Move historical timeout decoding into an explicit `legacy` module if required.

Delete every inline provider timeout literal. Repository search may find provider profile
construction only inside the owner module/tests.

Commit:

```text
ARCH-01: centralize provider route policy
```

---

# 4. One runner and one retry owner

Generalize the existing `AntigravityProcessExecutor`; do not add a parallel seam.

Final interface:

```rust
trait ProviderProcessRunner
```

Implementations:

```text
SupervisedWindowsProcessRunner — production
ScriptedProviderProcessRunner — tests
```

Delete in the same migration:

```text
AntigravityProcessExecutor
AntigravitySupervisedProcessSpec/Output
SharedAntigravityProcessExecutor
run_external_agent_process as an independent lifecycle
other provider-specific process executors
```

Provider adapters receive `Arc<dyn ProviderProcessRunner>` from app composition.

## Runner rules

- It supervises exactly one process generation.
- Provider process specs use `RestartStrategy::Never`.
- It never redispatches a provider.
- It uses the existing Job Object, concurrent stdin/stdout/stderr and reap implementation.
- Provider routes may not create a per-call Tokio runtime/thread.
- Direct provider executable spawn outside `SupervisedWindowsProcessRunner` is forbidden.

All terminal states after spawn return a `ProviderProcessOutcome`, not `Err`:

```text
exit 0 / nonzero / timeout / cancellation / drain failure /
complete output followed by forced reap.
```

`Err` is only for validation or spawn failure before a process identity exists.

Outcome carries actual process, first/last-output, exit and cleanup timestamps plus
`ProcessReapReceipt`.

## Retry ownership

`AdapterSupervisor` keeps concurrency and circuit state but does not automatically redispatch an
external provider. The process runner also does not retry.

Only the campaign/controller may authorize a new call after journal evidence proves a safe
pre-dispatch failure.

Commit:

```text
ARCH-02: route every provider through one process runner
```

---

# 5. Campaign budget is not adapter policy

Remove `max_calls` and `campaign_closed` from adapter-created reservation requests.

Use the existing reservation owner as follows:

```text
controller opens one immutable campaign/budget record;
reservation references campaign ID + idempotency key;
reservation owner loads max/closed state from the campaign;
adapter cannot create or change the campaign limit.
```

One-shot smoke uses an explicit one-call campaign.

Historical ledgers remain readable. Old ceilings remain evidence but do not stop unrelated product
work.

---

# 6. MCP tools come from one catalog

`mcp_stdio/catalog.rs` is the tool owner.

Remove provider-maintained cognitive lists such as:

```text
SAFE_AUDITOR_MCP_TOOLS
LEGACY_GOVERNED_MCP_TOOLS
```

Resolve exact tools from one central access profile by role/purpose. Bind profile ID/hash into the
runtime contract.

Reader/Judge/Worker profiles stay bounded. Operator/doctor tools remain separate and are not mixed
into cognitive profiles.

---

# 7. Terminalize from process facts

Immediately after the runner returns, call one journal close operation:

```rust
ProviderInvocationJournal::record_process_terminal(...)
```

It records real:

```text
process start/exit/cleanup
first/last output
exit/signal
timeout class
process/job identity
reap receipt
stdout/stderr refs when capture succeeds
terminal process state
```

Only then:

```text
secret scan / spool / parse / schema validation /
ProviderExecutionEvidence / AgentResult admission.
```

A failure in capture, secret scanning, parsing, schema validation or closeout must not leave the
attempt `Running`.

If physical cleanup succeeded but journal persistence failed, create reconciliation-required state;
never rerun the provider.

Reconcile the two existing Antigravity attempts provider-free from exact OS/job/broker/receipt
evidence. Do not invent output.

Commit:

```text
ARCH-03: terminalize provider attempts from process facts
```

---

# 8. Remove remaining compatibility/test hacks

1. Move `CognitiveProviderRuntimeContract` and report-only compatibility types into
   `external_agent::legacy`; current runtime must not construct them.
2. Remove from `crates/eliot-app/Cargo.toml`:

```toml
[[test]]
name = "cognitive_field_runner"
path = "src/main.rs"
```

Use:

```text
cargo test -p eliot-app --bin eliot-governor cognitive_field_runner::tests
```

3. Move only provider process/policy/terminalization ownership out of large orchestration files.
   Do not refactor the whole application.
4. Add no new `too_many_lines` allowance in the new owner.
5. After migration, compatibility provider executors/runners remaining = `0`.

Commit:

```text
ARCH-04: remove duplicate provider and test paths
```

---

# 9. Exact-route behavior gate

No real model. Inject `ScriptedProviderProcessRunner` through normal
`AdapterRegistry -> AdapterSupervisor -> provider adapter`.

Maximum eight cases:

| Case | Required behavior |
|---|---|
| B1 | external-agent Antigravity delayed valid output survives former 5s boundary |
| B2 | managed-host Antigravity uses same runner/policy |
| B3 | true first-output timeout terminalizes and reaps; no replay |
| B4 | exit 0 with invalid JSON is terminal rejected, never `Running` |
| B5 | valid terminal output then hang: one result, forced reap, no duplicate |
| B6 | Claude/Antigravity/OpenCode + Worker/Reader/Judge resolve exact policy/tool hashes |
| B7 | adapter cannot choose campaign max; pre-created campaign is enforced |
| B8 | source gate: no inline policy, direct spawn, compatibility executor or duplicate main test |

Use virtual/scaled time. Combined behavior bodies target `<=10s`.

A helper-field assertion is not evidence; tests must enter through the production route.

Focused gate:

```powershell
cargo test -p eliot-types provider_route_policy
cargo test -p eliot-engine provider_invocation
cargo test -p eliot-engine adapter
cargo test -p eliot-app --bin eliot-governor provider_runtime
cargo test -p eliot-app --bin eliot-governor external_agent
cargo test -p eliot-app --bin eliot-governor managed
cargo test -p eliot-windows-ipc supervised_process
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
git diff --check
```

A zero-test filter is not evidence. No full workspace test.

---

# 10. Mandatory Opus 5 escalation, not premature STOP

Escalate when:

```text
two local hypotheses are falsified;
static graph and runtime trace disagree;
a fix seems to require another owner/abstraction;
the exact production route fails after a behavior-tested fix;
unknown provider outcome cannot be reconciled;
it is unclear which duplicate path is live/safe to delete.
```

Use:

```text
Claude Code headless CLI
exact model claude-opus-5
effort max
fresh read-only session
Read/Grep/Glob only
no GUI
no floating alias
no shell timeout below 20 minutes
```

Send only exact goal, canon invariants, HEAD, call graph, timeline, source anchors, tests,
falsified hypotheses, deletion candidates and one question.

One follow-up in the same session is allowed. Maximum three distinct consultations.

Verify advice against source and a behavior regression, then continue. Consultation is not a stop
condition.

---

# 11. Live regression and automatic continuation

After §9:

```text
build/activate one versioned candidate;
verify source/SHA/runtime;
require clean runtime and authority integrity.
```

Run one current-state smoke each:

```text
Claude
Antigravity gemini-3.6-flash-high
OpenCode opencode/mimo-v2.5-free
```

After each require exact policy/tool-profile hashes, provider-owned MCP call, schema-valid result,
terminal attempt, real exit/cleanup timestamps, complete reap, closed authority and clean integrity.

One repaired retry per provider is allowed only after exact defect + source fix + behavior test +
new candidate. No unchanged retry.

If one route still fails after its repaired retry:

```text
invoke Opus;
mark that route degraded;
continue independent Task 03 and Task 04;
repair the route before final Task 02/Task 05 certification.
```

When routes are green:

```text
finish Task 02;
continue existing Task 03;
continue existing Task 04;
run Task 05 once on the final Task-04 product head;
run Task 06 release/PR/CI/merge.
```

Do not rewrite Tasks 03–06.

---

# 12. Stop conditions

Return to the operator only when:

```text
authority/security/isolation/candidate-only must be weakened;
canonical data may be lost without reversible recovery;
post-dispatch unknown cannot be reconciled;
official provider authentication remains unavailable after official login;
source evidence plus Opus proves a real operator/product choice;
accepted work cannot be recovered from the archive ref.
```

Do not stop for compiler/tests/Clippy, old call ceilings, one failed smoke, one degraded provider,
required deletion, Cargo artifacts, Opus use or multiple necessary commits.

---

# 13. Final report

```text
PROVIDER-RUNTIME-CONSOLIDATION: PASS | BLOCKED

Start SHA / archive:
Commits:

Timeout constructors before/after:
Outer deadline owners before/after:
Retry owners before/after:
Process executors before/after:
Direct spawn sites before/after:
Hardcoded campaign limits before/after:
Provider MCP tool lists before/after:
Legacy runtime paths remaining:
Duplicate main test target:

Antigravity external-agent route:
Antigravity managed route:
Policy ID/hash:
Tool-profile ID/hash:
Runner:
First-output / absolute deadlines:

Attempt terminalization:
Legacy attempt reconciliation:
Behavior tests / focused gates:
Opus consultations:

Claude / Antigravity / OpenCode smokes:
Repaired retries:

Task 02 / 03 / 04 / 05 / 06:
Runtime integrity:
Authority integrity:
Orphan processes:
Unknown outcomes:
Current task / next action:
```

PASS requires:

```text
one policy owner;
one runner;
one retry owner;
one campaign owner;
one MCP profile owner;
zero compatibility executor;
zero direct provider spawn;
terminal attempts from process facts;
exact-route behavior tests green.
```
