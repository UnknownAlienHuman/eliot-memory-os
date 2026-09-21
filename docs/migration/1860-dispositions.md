# 1860 disposition ledger — 73 unreachable + 11 excluded

Owner: `bins/eliotd` migration coordination. Verbs follow I19.3
(`KEEP / WRAP / EXTRACT / REWORK / REPLACE / RETIRE / UNKNOWN`); standalone rows
reuse the checked-in #1811 verbs verbatim. No row confers workspace, runtime,
state, authority, or production support admission.

Distribution over the 73 bins-unreachable workspace packages:
**KEEP 53 · REWORK 7 · RETIRE 6 · UNKNOWN 6 · WRAP 1**.
Excluded scope: **REWORK 3 · EXTRACT 1 · WRAP 7** over 11 packages.

## RETIRE (6) — gated, never silent

| Path | Package | Owner | Active reference |
|---|---|---|---|
| `crates/eliot-app` | eliot-app | bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189 | ACTIVE_REFERENCE |
| `crates/eliot-engine` | eliot-engine | bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189 | ACTIVE_REFERENCE |
| `crates/eliot-store` | eliot-store | bins/eliotd migration coordination (#1860); extraction owner #19; retirement owner #1189 | ACTIVE_REFERENCE |
| `crates/eliot-types` | eliot-types | bins/eliotd migration coordination (#1860); extraction owner #18; retirement owner #1189 | ACTIVE_REFERENCE |
| `crates/storage/eliot-backup` | eliot-backup | storage plane disposition owner #1716 (governed export path #1871; recoverability evidence #1873) | ACTIVE_REFERENCE |
| `crates/storage/eliot-ecxf` | eliot-ecxf | storage plane disposition owner #1716 (governed export path #1871) | ACTIVE_REFERENCE |

Rationale: the four aggregate crates are the `legacy-migration-facades` block;
RETIRE executes only after every unique production consumer migrates to the
documented current owner, gated on #1189 (T7-S9). The two storage export crates
are not selectable production fallbacks; RETIRE executes only via the #1716
disposition with #1871/#1873 evidence. All six retain ACTIVE_REFERENCE hits
today, which is exactly why deletion is gated rather than inferred.

## WRAP (1)

| Path | Package | Owner | Active reference |
|---|---|---|---|
| `crates/agent/eliot-agent-acp` | eliot-agent-acp | agent plane via bins/eliot-native-worker (#22); provider-neutral execution allocation #361 | ACTIVE_REFERENCE |

Rationale: provider-neutral ACP v1 stdio compatibility adapter referenced by the
native-worker adapter registry. WRAP behind the admitted native owner; never a
parallel agent runtime.

## REWORK (7) — prototype cells pending implementation and proof

| Path | Package | Owner | Active reference |
|---|---|---|---|
| `crates/smart/eliot-context-admission` | eliot-context-admission | smart.context.admission (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-context-assembly` | eliot-context-assembly | smart.context.assembly (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-context-measurement` | eliot-context-measurement | smart.context.measurement (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-cue-activation` | eliot-cue-activation | smart.cue.activation (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-cue-binding` | eliot-cue-binding | smart.cue.binding (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-cue-normalizer` | eliot-cue-normalizer | smart.cue.normalizer (module/package owner record) | ACTIVE_REFERENCE |
| `crates/smart/eliot-reactive-context-plan` | eliot-reactive-context-plan | smart.context.reactive_delivery_plan (module/package owner record) | ACTIVE_REFERENCE |

Rationale (#1811 semantics): concept valid, contract pending. REWORK before any
admission-to-runtime claim; integration via cognitive-wave-integrator.

## UNKNOWN (6) — explicit, fail-closed, owner-assigned

| Path | Package | Owner | Active reference |
|---|---|---|---|
| `crates/security/eliot-erasure` | eliot-erasure | security.erasure (component owner TBD); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |
| `crates/security/eliot-influence` | eliot-influence | security.influence (component owner TBD); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |
| `crates/smart/eliot-context` | eliot-context | smart.context (component owner TBD, ref #248); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |
| `crates/smart/eliot-cues` | eliot-cues | smart.cues (component owner TBD); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |
| `crates/smart/eliot-dreamer-core` | eliot-dreamer-core | smart.dreamer.core (component owner TBD); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |
| `crates/smart/eliot-memory-curation` | eliot-memory-curation | smart.memory.curation (component owner TBD); coordinated by bins/eliotd (#1860) | ACTIVE_REFERENCE |

Rationale: UNKNOWN is a disposition, not a gap — it blocks deletion of the
affected scope (I0.8) without blocking unrelated development, and it never
promotes. Each row names the experiment owner; the `bins/eliotd` coordinator
drives the follow-up, one causal owner per row.

## KEEP (53)

Instrument-plane support (owner #20 testd via registry #13 — never production
runtime dependencies):

`eliot-artifact`, `eliot-build-test-graph`, `eliot-code-cortex`,
`eliot-code-graph`, `eliot-diagnostic`, `eliot-empirical-profile`,
`eliot-graph-api`, `eliot-instrument-cargo`, `eliot-instrument-dotnet`,
`eliot-instrument-nextest`, `eliot-instrument-runner`, `eliot-instrument-rustc`,
`eliot-instrument-rustfmt`, `eliot-instrument-scip`, `eliot-observability`,
`eliot-product-evaluation`, `eliot-r13-harness`, `eliot-reports`,
`eliot-test-selection`, `eliot-verifier` (all under `crates/instrument/`,
all ACTIVE_REFERENCE).

Admitted capability cells awaiting production wiring (KEEP; no deletion;
functional-cell owner per `[package.metadata.eliot] lifecycle_owner`):

`eliot-dreamer-accessibility`, `eliot-dreamer-architecture-brief`,
`eliot-dreamer-clarification`, `eliot-dreamer-classification`,
`eliot-dreamer-concept`, `eliot-dreamer-configuration-plan`,
`eliot-dreamer-conflict-analysis`, `eliot-dreamer-development-diagnosis`,
`eliot-dreamer-episode`, `eliot-dreamer-failure`,
`eliot-dreamer-implementation-brief`, `eliot-dreamer-maintenance-plan`,
`eliot-dreamer-memory-repair`, `eliot-dreamer-orchestration-plan`,
`eliot-dreamer-procedure`, `eliot-dreamer-reconsolidation`,
`eliot-dreamer-relation`, `eliot-dreamer-research-synthesis`,
`eliot-dreamer-structure-repair`, `eliot-learning-contracts`
(`ready_for_wave_integration`), `eliot-learning-delta`,
`eliot-learning-overlay`, `eliot-learning-state-view`,
`eliot-memory-curation-contracts`, `eliot-memory-curation-screen`
(all ACTIVE_REFERENCE).

Named-owner KEEP rows:

| Path | Package | Owner |
|---|---|---|
| `crates/agent/eliot-swarm` | eliot-swarm | A-07 swarm planning cell (lifecycle_owner A-07) |
| `crates/foundation/eliot-test-support` | eliot-test-support | C0-10 test-support cell (lifecycle_owner C0-10) |
| `crates/meta/eliot-improvement` | eliot-improvement | meta plane owner #17 (doctor/repair family) |
| `crates/meta/eliot-learning-activation-assessment` | eliot-learning-activation-assessment | meta.learning.activation_assessment (admitted via #967 T8-AL1) |
| `crates/meta/eliot-self-quality` | eliot-self-quality | meta.self_quality.diagnosis (admitted via #967 T8-AL1) |
| `crates/storage/eliot-store-memory` | eliot-store-memory | storage plane owner #19 (non-runtime reference per #1715) |
| `workspace/tools/eliot-campaign-executor` | eliot-campaign-executor | workspace tooling owner (developer tool, not production runtime) |
| `workspace/tools/eliot-runtime-compiler` | eliot-runtime-compiler | workspace tooling owner (developer tool, not production runtime) |

## Excluded scope (11 standalone rows, verbatim #1811)

| Path | Package | Disposition | Owner | Active reference |
|---|---|---|---|---|
| `crates/foundation/eliot-memory-projection-contracts` | eliot-memory-projection-contracts | REWORK | foundation.memory.projection-contracts | ACTIVE_REFERENCE |
| `crates/governor/eliot-memory-projection-provider` | eliot-memory-projection-provider | REWORK | governor.memory.projection-provider | ACTIVE_REFERENCE |
| `crates/research/eliot-dreamer-source-assurance` | eliot-dreamer-source-assurance | EXTRACT | research.source-assurance-role-separation (#692 cell) | ACTIVE_REFERENCE |
| `crates/smart/eliot-context-compiler-wasm` | eliot-context-compiler-wasm | WRAP | smart.context.compiler-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-cue-activation-wasm` | eliot-cue-activation-wasm | WRAP | smart.cue.activation-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-dreamer-curation-wasm` | eliot-dreamer-curation-wasm | WRAP | smart.dreamer.curation-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-dreamer-cycle-wasm` | eliot-dreamer-cycle-wasm | WRAP | smart.dreamer.cycle-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-dreamer-orientation-wasm` | eliot-dreamer-orientation-wasm | WRAP | smart.dreamer.orientation-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-dreamer-research-wasm` | eliot-dreamer-research-wasm | WRAP | smart.dreamer.research-wasm | ACTIVE_REFERENCE |
| `crates/smart/eliot-memory-applicability` | eliot-memory-applicability | REWORK | smart.memory.applicability | ACTIVE_REFERENCE |
| `crates/smart/eliot-memory-curation-screen-wasm` | eliot-memory-curation-screen-wasm | WRAP | smart.memory.curation-screen-wasm | ACTIVE_REFERENCE |

Source of record: `workstreams/security/standalone-crate-dispositions.toml`
(untouched by this slice; mirrored here for single-hop review). The 13-wide
audit premise reconciles as these 11 packages plus the 3 non-production
`[workspace]` roots documented there (`mcpls.toml`, two `scripts/testdata/`
fixture workspaces), which are not supply-chain inputs. Any future `exclude`
entry without a matching disposition row fails the #1811 gate.

## Verification

`python scripts/migration_inventory_1860.py --check` rebuilds the denominator
from the live tree and fails closed unless every unreachable and every
standalone row carries an allowed disposition, a named owner, and an
active-reference status, and unless the impact graph and Product Proof plan
predicates hold. Current result: `PASS unreachable=73 standalone=11`.
