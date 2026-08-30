# Bootstrap compiler source instructions

<!-- eliot-doc-routing:start -->
## Mandatory documentation routing

Before changing code, configuration, tests, workflows, or normative prose, run
from the repository root:

```text
python scripts/docs_router.py route --path <repository/path> --topic "<causal property>"
```

Read every fragment marked **required**, then record the emitted receipt in the
work unit or pull request. Optional fragments are loaded only when the current
decision crosses their stated boundary. A legacy `ELIOT_*` compatibility map is
never an acceptable reading receipt.

If no non-baseline route matches, stop the mutation and add or obtain a route;
silence is not permission. See [`../../../docs/architecture/READING_PROTOCOL.md`](../../../docs/architecture/READING_PROTOCOL.md).
<!-- eliot-doc-routing:end -->


## Purpose and authority

This package owns three deterministic D0 compiler cells. It converts already
supplied immutable projections into content-addressed artifacts. It owns no
runtime lifecycle, canonical state, task meaning, policy, authority, finish,
provider execution, store access, or product-support verdict.

Read the repository `AGENTS.md`, `WORKFLOW.md`, the owning issue/PR, and the
applicable Architecture/Implementation fragments before changing this package.
Start every mutating unit from current `main` in its own issue-numbered branch.

## Functional capability cells

### `foundation.bootstrap.current-system-evidence`

Public core entrypoint:

```rust
CurrentSystemEvidenceCompiler::compile(
    SourceProjection<CurrentSystemEvidenceSource>,
) -> Result<CurrentSystemEvidenceSnapshot, BootstrapCompileError>
```

Narrow effect adapter:

```rust
capture::capture_snapshot(&Path) -> Result<SnapshotExecutionArtifact, CaptureError>
capture::write_snapshot_artifact(&SnapshotExecutionArtifact, &Path)
    -> Result<(), CaptureError>
```

Responsibility:

- validate one explicit source projection;
- preserve exact repository/source identity and dirty-state binding;
- represent unavailable, not-running, stale, conflicting, and unknown domains
  explicitly;
- compile deterministic canonical bytes and digest;
- bind the emitted artifact to an immutable execution receipt.

`lib.rs` is the pure compiler boundary. `capture.rs` is the only package-local
filesystem/process adapter. The compiler must never discover files, inspect a
PID, invoke Git, probe a service, or infer support. The adapter may observe only
what its public request and disclosure boundary explicitly authorize; it passes
observations to the compiler and cannot set support or proof status by prose.

Known open contract gap: the current snapshot representation is still flatter
than the complete five-domain/support/invalidation closure required by
Implementation I0.5. Do not disguise that gap as complete coverage. A source
migration must preserve compatibility deliberately and prove, at minimum:

- exactly one coverage disposition for `source`, `build`, `runtime`, `store`,
  and `integrations`;
- separation of observation availability, `ContractMaturity`,
  `ImplementationSupport`, and `EvidenceExecutionStatus`;
- source/evidence handles, blind boundaries, expiry, and invalidation set for
  every support claim;
- rejection of forged `CURRENT_VERIFIED` or `EXECUTED` state;
- `NOT_RUNNING` as a valid local domain observation rather than a global
  compiler failure.

Current prerequisite and ownership:

- issue #220 and draft PR #221 define the sole owner-neutral C0 contract for the
  I0.5 status dimensions and five-domain vocabulary;
- issue #216 owns the subsequent bootstrap snapshot migration;
- this package must consume `eliot-conformance-contracts`; it must not define a
  local copy of `ContractMaturity`, `ImplementationSupport`,
  `EvidenceExecutionStatus`, `SupportObservationState`, or `EvidenceDomain`;
- `SourceStatus` remains only the availability of one compiler input projection
  and must never be exported or interpreted as current implementation support;
- the existing schema string
  `eliot-current-system-evidence-snapshot-v2` is not evidence that the current
  flat wire shape conforms to normative snapshot v2;
- old flat bytes require an explicit legacy-partial/unknown import disposition;
  they cannot be reinterpreted silently as complete five-domain evidence;
- do not mutate snapshot source or serialized consumers until the status
  contract is implemented, package-proved, and compiled by a real bootstrap
  consumer fixture.

Return a ContractChallenge instead of creating a convenient bootstrap-owned
status vocabulary or mapping `EvidenceEvaluation` directly into support.

### `foundation.bootstrap.rule-catalogue`

Public core entrypoints:

```rust
compile_bootstrap_rule_catalogue(
    SourceProjection<BootstrapRuleSource>,
) -> Result<BootstrapRuleCatalogue, BootstrapCompileError>

provider_normative_gap()
    -> Result<ProviderNormativeProjection, BootstrapCompileError>
```

Responsibility:

- validate an explicitly supplied rule catalogue against its exact normative
  pair and provider revision;
- preserve exact rule identity, class, owner, scope, rationale, observable
  property, degraded behavior, and challenge path;
- produce deterministic catalogue and registry digests;
- emit the designated provider-owned GAP projection when an admitted catalogue
  is absent.

The GAP projection is intentional fail-closed behavior. It contains no synthetic
rules and never interprets arbitrary prose as executable authority. Do not fill
it from keyword matching, a language-model judgement, an old report, or a
convenient subset of the normative books.

### `foundation.bootstrap.work-unit-brief`

Public core entrypoints:

```rust
compile_bootstrap_brief(BootstrapBriefSource)
    -> Result<BootstrapBrief, BootstrapCompileError>

BootstrapBriefCompiler::compile(
    AgentWorkUnitBrief,
    &CurrentSystemEvidenceSnapshot,
) -> Result<BootstrapBrief, BootstrapCompileError>
```

Candidate-only outputs:

```rust
BootstrapFailureDraft::new(...)
BootstrapImprovementDraft::new(...)
```

Responsibility:

- bind one validated work-unit seed to the exact evidence snapshot, rule
  catalogue/projection, normative pair, source references, and coverage
  manifest;
- preserve included, excluded, absent, stale/conflicting, and unsearched
  normative scopes distinctly;
- emit deterministic content-addressed output with reversible expansion handles;
- keep failure and improvement drafts candidate-only until another governed
  owner imports or rejects them.

A brief is a projection, not a task admission, authority grant, support claim,
completion proof, canonical write, or architecture decision. Missing coverage
must remain visible. Silence never means permission.

## Shared invariants

All three cells are stateless and effect-free at the core boundary.

1. Canonicalization and digest construction are deterministic for equivalent
   admitted inputs. Sort only sets whose semantics are order-independent; never
   erase meaningful source order.
2. Empty, duplicate, conflicting, malformed, or unsupported exact identities
   fail with a typed `BootstrapCompileError`.
3. Missing evidence remains missing. Do not convert `UNKNOWN`, `UNAVAILABLE`,
   `NOT_RUNNING`, `STALE`, or `CONFLICTED` into a success/default value.
4. A Human-provided fact is an attributed observation. It cannot directly mint
   `CURRENT_VERIFIED`, `EXECUTED`, authority, or completion.
5. Provider/runtime/store/vendor types do not enter public bootstrap contracts.
6. A digest proves byte identity only. It does not prove semantic correctness,
   source competence, runtime operation, or product support.
7. Drafts and briefs never write Canonical Memory or Operational Recovery State.
8. No code in this package performs a model call, network call, service start,
   canonical-store query, runtime-status ownership, or broad repository scan.
9. Existing artifacts are never silently overwritten. Publication must preserve
   create-new/idempotent-readback behavior and exact bytes.
10. Keep the package dependency-light. A new dependency requires a real contract
    or adapter seam and must not import a higher runtime layer.
11. The bootstrap compiler may validate a support row but cannot decide or
    promote support; the supplied exact evidence and owner-neutral I0.5 contract
    determine the maximum representable state.
12. Observation availability, contract maturity, implementation support,
    evidence execution, epistemic status, process health and verifier outcome
    remain separate axes.

## Change routing

Use one causal unit and one primary mutable path scope.

- Contract/schema change: update the pure types/compiler and negative fixtures;
  identify every serialized consumer before changing compatibility.
- I0.5 status-contract change: work in `eliot-conformance-contracts` under #220;
  do not duplicate the types here.
- Snapshot-v2 migration: work under #216 only after the #220 package and first
  consumer fixture are proved.
- Capture change: stay in `capture.rs`; preserve the pure compiler boundary and
  attribute every observation to an exact capture route.
- Rule change: modify only provider-owned rule projection/validation behavior;
  never synthesize rule meaning locally.
- Brief change: preserve the Decision Safety Floor, normative coverage states,
  exact artifact references, and candidate-only ceiling.
- CLI, runtime, store, Governor, Kernel, or canonical import behavior belongs to
  its owning package and must be changed in a separate edge/integration unit.

Return a ContractChallenge instead of expanding this package when the requested
work needs:

- runtime/store/integration liveness ownership;
- current product-support promotion;
- arbitrary filesystem discovery or neighboring-root scans;
- policy, authority, task, finish, or canonical-write decisions;
- a second evidence/status owner;
- an unbounded synchronous traversal or model call;
- a schema guessed from prose where the field-level contract is not closed;
- silent reinterpretation of an existing flat snapshot as a stronger contract
  version.

## Proof

Minimum source/package proof for Rust changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-bootstrap --all-targets
cargo test --locked -p eliot-bootstrap
cargo clippy --locked -p eliot-bootstrap --all-targets -- -D warnings
```

Also run the exact affected consumer fixture for `bins/eliot` or `eliot-cli`
when the serialized snapshot, catalogue, brief, receipt, or public API changes.
A filesystem/capture change needs create-new, readback, dirty-tree, missing-Git,
wrong-root, and interrupted-publication coverage on the real adapter edge.

A snapshot-v2 change additionally requires:

```text
eliot-conformance-contracts package proof;
bootstrap imports every status/domain type from that package;
legacy-flat import remains explicit partial/unknown;
source-only evidence cannot claim runtime/store/integration support;
CURRENT_VERIFIED forgery and observation/support conflation negatives;
every serialized producer/consumer compatibility fixture.
```

Package proof establishes only the pure compiler or narrow capture behavior. It
does not establish live runtime/store/integration observation, current system
support, canonical import, Product Pulse, or release proof. Record every skipped,
unavailable, simulated, or unexecuted check exactly. Automatic GitHub Actions
must remain disabled; do not add or enable an automatic workflow to obtain a
status check.
