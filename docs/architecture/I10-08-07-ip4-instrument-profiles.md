### I10.8.7. IP4 — instrument profiles

A profile is a versioned deterministic recipe:

```yaml
InstrumentProfile:
  profile_id:
  task_or_change_triggers:
  required_and_optional_instruments:
  stage_dependencies:
  selection_rules:
  target_layout:
  resource_and_timeout_policy:
  parsers:
  evidence_authority_and_coverage:
  negative_result_semantics:
  ranking_and_compaction:
  success_partial_failure_rules:
  exact_rerun_contract:
  context_projection:
```

Initial profiles:

| Profile | Instruments | Purpose |
|---|---|---|
| `compiler` | Cargo metadata, rustc/Clippy JSON, `rustc --explain` on demand | exact compilation/type/lint failures |
| `test` | nextest list JSON, affected nextest/JUnit, exact rerun | discovered tests, failures, hangs and runtime evidence |
| `snapshot` | approved snapshot framework in exploratory/sealed modes | exact expected/actual artifact difference |
| `test-strength` | base/candidate probe, changed-line coverage, selected mutation | detect green tests that do not exercise the change |
| `architecture` | Git, full Cargo graph, rust-analyzer/SCIP, optional heuristic scout | ownership, references, implementations and impact candidates |
| `dependency` | cargo-deny/hack and admitted unused-dependency analyzer | features, advisories, licenses and dependency hygiene |
| `concurrency` | Loom, Shuttle/paused time where admitted | ordering, cancellation, deadlock and retry invariants |
| `unsafe-ffi` | Miri, careful/sanitizer/fuzz/formal tools where supported | unsafe/FFI boundary evidence |
| `windows-runtime` | Job Object observer, ETW/WPR/ProcDump and fixtures | process, service, pipe and cleanup failures |
| `performance` | Criterion/Divan, hyperfine and admitted allocation/ETW probes | workload-bound regression evidence |

Profiles are added only when observed failure or product need justifies them. A profile is not another model agent.

