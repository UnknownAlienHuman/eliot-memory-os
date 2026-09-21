# 2244 integrated delivery — issue #1936 coverage denominators + compliance traces

- Branch: `codex/1936-coverage-traces-integration`
- Implementation commit (this delivery): `8f9a32d9b575ccbb3a870e57c0429a929967953a`
- Parent/merge base state: `f131a782223656fdc09e7b3f173d22e349986011` (merge of
  `origin/main@1a18895e` into worker base)
- Preserved original worker commit: `6ba2d5b940eba509aaca0d2eb719d565ca49f02a`
  (verified ancestor of HEAD via `git merge-base --is-ancestor`)
- Upstream observation at freeze time: `origin/main` now resolves to
  `f37966c30b8fa66ac90e439fb51d465ca422ddb6` (was `1a18895e` at brief time).
  This moved without any local fetch/pull/merge by this leaf (shared `.git`
  updated by the root controller sync). No rebase/merge performed; integration
  and re-sync are root-owned.
- Owning issue: #1936 (`OPEN`), PR: #2244 (`OPEN`, `work/1936-coverage-traces`).
  Root alone publishes; this leaf made local commits only, no fetch/push/main
  mutation. `gh issue/pr view` used read-only. No audits, no Perplexity.
- Scope owned: `crates/foundation/eliot-evaluation-contracts` only
  (`src/coverage_traces.rs` mutated; `src/lib.rs` untouched — the prepared
  two-file shape needed no `lib.rs` change for this hardening). No other
  worker files touched. Zero in-workspace consumers of the new surface exist
  (grep over `crates/`), so no external-consumer hunk was required.
- ELIOT governance tools unavailable in this environment — disclosed, no config
  repair attempted. Mandatory routing done via
  `python scripts/docs_read.py read --changed-from origin/main --topic coverage`
  (PASS). CBM CLI was available but not needed; no CBM queries made.

## Documentation routing receipts

- Route receipt ID: `sha256:8bc8bc9e0b049a459448e38071a7af8382d90dfd2b0c4dc6705a5de8fc2c72f8`
- Read receipt ID: `sha256:6e0ea5dfeb02a290a962a337787660d6437e8a218bb6f7458a22b43da59898da`
- Verified bundle SHA-256: `15b35502f8af0897cbace08c1645bc8f979721f129e49a0b5db1593269f89519`
  (`.eliot/docs-read-bundle.md`, 74274 bytes; local evidence only, not committed)
- Normative pair key: `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`
- Matched routes: `generic-source`
- Required handles: `A0.1 A0.2 A0.3 A0.4 A0.6 A2.3 A10.4 A14.8 I0.3 I0.4 I0.5
  I0.13 I0.14 I2.17 I2.20 I18`

### Required items (path + SHA-256, from read receipt)

| Path | SHA-256 |
|---|---|
| `AGENTS.md` | `e2508482aa659aae51df2e0dc0e7bbfa2b827dc8a8a854e7a1c4a7d06a334332` |
| `WORKFLOW.md` | `ba1119920d47f33b99ee51332d8951b009fc04ebe8512fb64966c6afbd9ff070` |
| `crates/AGENTS.md` | `91459415c207f25802e4c4182b7b0525ff644c3cc913c7be02032540a325e03f` |
| `docs/ARCHITECTURE_CONTRACT.md` | `d1e4c393cd7c953d8e41725eae404882236b13493ace74e4513c4cd894a9e846` |
| `docs/DEPENDENCY_POLICY.md` | `a69844d656e7cdac0b92fb4d1e6fbcd5d3e923c30ee706ec598acd3c3868933a` |
| `docs/architecture/READING_PROTOCOL.md` | `fc2ac357ecec293f7246a5ebc5c1e46f5407bb3574ffe39b6224e4d5aa6a3e25` |
| `workstreams/ACTIVE.toml` | `2bf61c09315add08bb0ec8fd2148f2f295b6abbf5e2e1e11b283204cada5b69b` |
| `docs/architecture/A00-01-purpose-of-the-architecture.md` (A0.1) | `ee540ede56579ec388e26da2b290759e78ad3bb8a70ba57d56364800a1692750` |
| `docs/architecture/A00-02-hierarchy-of-architectural-decisions.md` (A0.2) | `342c67f670714c83bb4c68693447fd7597bc4a662b87d4fa6bae09df3cbaf6e5` |
| `docs/architecture/A00-03-hard-boundaries.md` (A0.3) | `695fe5e156e0dde052556e23c34b008009348742d4fc4a1146393b8b13a48bc0` |
| `docs/architecture/A00-04-conflict-resolution.md` (A0.4) | `732d3b9a63973398e07e48691ba56f6538d9168f3102e0702a5ca2e08910f556` |
| `docs/architecture/A00-06-changing-the-architecture.md` (A0.6) | `c086ee01cc243b7d7dee465bc0ddfca0c36cc3a344b3b3e803a5eb94ff6f68a8` |
| `docs/architecture/A02-03-modular-architecture.md` (A2.3) | `6f7d0566576ddfcb88bae531421b58082b44e3ba6cd2b974f55a46990e26fd52` |
| `docs/architecture/A10-04-delegation.md` (A10.4) | `fd9c93b5e66ea93a0a2bb171706449ca8d07d2d48caeb99d1acdc57360014cd9` |
| `docs/architecture/A14-08-development-doctrine.md` (A14.8) | `c7da919cd6112e97780407b7a7ae9806185994c2de6a275ed2449cb1b9ca78bb` |
| `docs/architecture/I00-03-decision-sources.md` (I0.3) | `c5d7586399d8640484edaa3cb949495bc99a82b50dabddac029b2d08c2d716e8` |
| `docs/architecture/I00-04-change-classes.md` (I0.4) | `3c1fc91d692bee9494327b7f5375fbe45cddc00c27d5a0bf0dc3b40300a2ae45` |
| `docs/architecture/I00-05-conformance-support-and-evidence-status.md` (I0.5) | `bfb599eb462ebfb904ec97ba199a8447371bce91ab73b7bad9e71f150cb837f9` |
| `docs/architecture/I00-13-current-support-conformance-and-product-status.md` (I0.13) | `2d691986e973b4c9191cf5718f32b5035a8470b8355c5d82489df48c18651d2e` |
| `docs/architecture/I00-14-documentation-and-evidence-build-integrity.md` (I0.14) | `e645a72c291c89a4bc3e2eae99527aa2476dcfab0280e429df80405dbebe3fd9` |
| `docs/architecture/I02-17-parallel-agent-development-contract.md` (I2.17) | `6c333908b112859dbffe00c04a9e942b38c5d369a85d89d78788ab576a1d7cb1` |
| `docs/architecture/I02-20-module-contract-kit-crate-context-capsule-and-module-test-capsule.md` (I2.20) | `8a5d8276f2e1357eb58dd06acc7e5ac4017a4515048a5049c84e33849c381ef5` |
| `docs/architecture/I18-testing-and-instrumental-grounding-strategy.md` (I18) | `facd29dfe4a6fdb98a70f5a5decb7d960f8ca95419924828a44596c57940fb10` |

### Explicit reading attestation

I attest that before mutating code I opened the verified bundle
`.eliot/docs-read-bundle.md` and read every one of the 23 required items above
in full (not just the route), plus the owning issue #1936 body and PR #2244
metadata read-only via `gh`, the nearest `AGENTS.md` files (root and
`crates/`; no deeper `AGENTS.md` exists under
`crates/foundation/eliot-evaluation-contracts`), and the acceptance-authority
docs `docs/architecture/I07-23-raw-and-normalized-host-events.md` and
`docs/architecture/I07-22-host-runtime-identity-discovery-and-conformance.md`
in full. No optional fragments were needed beyond I7.22/I7.23, which the owning
issue cites directly. Scope did not expand beyond the receipt
(`crates/foundation/eliot-evaluation-contracts/src/coverage_traces.rs`,
`.../src/lib.rs`).

## What changed (commit `8f9a32d9`, 1 file, +143/−22)

Prepared implementation (worker commit `6ba2d5b9`) was sound on the three
acceptance-named paths but had four concrete gaps against I7.23:50 ("An absent
event is evidence of non-occurrence only when the applicable source/class is in
the denominator, its cursor interval is complete and no blind interval covers
the action… Gap, duplicate, reorder, payload-mutation and cross-scope replay
faults are part of the host-event conformance suite"). Fixed, not reported:

1. `absence_claim_admissible` ignored `sequence_faults.payload_mutations` — a
   payload-corrupted stream could still bless absence-of-event claims. Now
   requires `gaps == 0 && payload_mutations == 0`.
2. `coverage_percentage` ignored all sequence faults — a gapped denominator
   still rendered a percentage. Now returns `None` when `gaps > 0` or
   `payload_mutations > 0` (in addition to the existing
   complete/no-blind/total!=0 gates).
3. Unlocalized faults produced an *invalid* trace from a *valid* manifest:
   `gaps > 0` with zero blind intervals derived `TAINTED` naming nothing,
   failing the crate's own `validate` (same for `payload_mutations`). New
   manifest rule: sequence gaps or payload mutations require localized blind
   intervals (rejected fail-closed as malformed evidence shape). Rationale:
   counters come from the same cursor tracking that localizes missing ranges;
   a fault count without localization is inconsistent ingestion.
4. `UNKNOWN` from an incomplete-but-clean denominator derived with empty
   blocker vectors — also failing `validate` — and the trace did not carry
   denominator completeness at all. New required field
   `HostObservedComplianceTrace::denominator_completeness: CoverageCompleteness`
   (always set by `derive_compliance_trace` from the manifest): `PASS`
   additionally requires `Complete` (closes hand-construction of a partial
   `PASS`); `UNKNOWN` requires an incomplete denominator instead of concrete
   blockers; `TAINTED` keeps the strict name-a-blocker rule. Doc comments
   updated to state the invariant: valid manifest ⇒ derived trace validates
   (garbage-in still fails closed, never `PASS`).

Deliberate non-change: duplicates/reorders do **not** gate absence/percentage.
Per I7.23:14 reconnect replays are idempotent by stream cursor, so they are
recorded faults but not coverage holes. Flagged for root review.

Wire note: `denominator_completeness` is a required (non-defaulted) serialized
field. Safe today: PR #2244 is unmerged and grep over `crates/` confirms zero
consumers/producers of this surface.

## Proof executed (smallest meaningful package scope)

- Baseline before mutation: `cargo test -p eliot-evaluation-contracts` → 34/34.
- New tests written first; pre-fix run failed to compile on the missing
  `denominator_completeness` field (recorded gap evidence), then implemented.
- Post-fix: `cargo test -p eliot-evaluation-contracts` → **40/40 pass**
  (34 baseline + 6 new), doc-tests 0.
- `cargo clippy -p eliot-evaluation-contracts --all-targets -- -D warnings` →
  clean, zero warnings.
- `cargo fmt -p eliot-evaluation-contracts -- --check` → clean.
- No unchanged-test loops, no workspace-wide campaign (per brief).

## Acceptance map (issue #1936 criteria → evidence)

| Criterion | Result |
|---|---|
| Declared-complete run, no forbidden action → trace with explicit denominator + disposition | PASS — `complete_source_clean_run_yields_pass_with_explicit_denominator` (now also asserts carried `denominator_completeness`) |
| Same run + simulated cursor gap → `TAINTED`/`UNKNOWN` naming the blind interval, never `PASS` | PASS — `cursor_gap_yields_tainted_naming_blind_interval_never_pass`; plus `unlocalized_sequence_fault_is_rejected_fail_closed` and `cursor_gap_without_percentage_denominator_is_rejected` |
| Same run + undeclared shell read → `TAINTED`/`UNKNOWN` naming the access, never `PASS` | PASS — `undeclared_shell_read_yields_tainted_naming_access_never_pass` |
| Percentages/absence rejected unless source/class is in the declared complete denominator | PASS — `payload_mutation_blocks_absence_and_percentage_naming_blind_interval`, `payload_mutation_alone_blocks_absence_and_percentage`, `partial_denominator_clean_run_yields_unknown_with_explicit_completeness`, `pass_requires_complete_denominator` |

## Owning-issue completeness verdict: NOT complete — runtime path still needed

Issue #1936 is **not** closed by this work. What exists now is a validated
foundation pure contract: denominator shape, derivation function, disposition
rules, and admission gates, all under `ProofCeiling::Observation` with no
evaluator, no ingestion, and no live-runtime claim. The precise actual runtime
path still needed (outside this leaf's scope — no caller exists yet):

1. Host-event ingestion (I7.23 pipeline) must construct and persist an
   `ObservationCoverageManifest` per product/session/attempt/route fingerprint:
   expected sources/classes, per-stream cursor ranges, count dispositions,
   fault counters, localized blind intervals, per-material-action coverage,
   origin/sampling policy, completeness, ceiling, invalidation deps.
2. A consumer alongside ingestion must join the allowed Tool/Facet manifest
   digest to immutable host/runtime records (`ImmutableHostEvidence`) and call
   `derive_compliance_trace` — the natural home is the host-event conformance /
   evaluation-evidence owner (`crates/kernel/eliot-ipc` bridge area per the
   issue's "Code today", or its designated successor), coordinated by root.
3. Product Proof on a real run (complete → `PASS`; fault-injected → named
   `TAINTED`/`UNKNOWN`) before any claim above `CURRENT_UNVERIFIED`.

## Honest residuals / risks

- `origin/main` moved `1a18895e` → `f37966c3` during this work via root sync;
  this branch was intentionally **not** re-merged — root owns re-sync.
- `coverage_percentage(covered > total)` can return >100 %; unspecified by
  docs, left as-is rather than inventing clamp semantics.
- No Product Pulse / edge proof: no runnable edge exists for a pure contract
  with zero consumers; package proof is the honest ceiling
  (`Module Proof` at `OBSERVATION` ceiling, not product acceptance).
- `.eliot/` read bundle/receipts kept out of Git; only the two task files under
  `control-20260921/` are committed alongside the implementation.
