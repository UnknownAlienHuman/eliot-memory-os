<!-- generated: eliot-prototype-doc-index-v1 -->
# Nonmember prototype package ↔ documentation index

This committed file is a deterministic navigation projection for Cargo packages
that exist in the repository but are not admitted by the root
[`Cargo.toml`](../../Cargo.toml). Prototype presence is not workspace admission,
implementation completion, runtime support, or Product acceptance. Package-to-
documentation mappings come from [`logical-blocks.toml`](logical-blocks.toml),
the canonical [`HANDLE_INDEX.md`](../architecture/HANDLE_INDEX.md), and the
inherited [`crates/AGENTS.md`](../../crates/AGENTS.md) contract. Do not edit it
by hand.

```powershell
python scripts/code_navigation.py sync-index --root .
python scripts/code_navigation.py check --root .
```

## Coverage

- Nonmember Cargo packages: **44**.
- Explicitly classified prototypes: **44**.
- Governing logical blocks represented: **3**.

## Governing logical blocks

| Block | Governing handles |
|---|---|
| `foundation-contracts` | [`A2.3`](../architecture/HANDLE_INDEX.md)<br>[`I2.8`](../architecture/HANDLE_INDEX.md) |
| `smart-memory-context` | [`I12.13`](../architecture/HANDLE_INDEX.md)<br>[`I17.11`](../architecture/HANDLE_INDEX.md) |
| `supervision-meta` | [`I8.3`](../architecture/HANDLE_INDEX.md)<br>[`I14.25`](../architecture/HANDLE_INDEX.md) |

## Nonmember prototype packages

| Package manifest | Admission | Logical blocks |
|---|---|---|
| [`crates/foundation/eliot-conformance-contracts`](../../crates/foundation/eliot-conformance-contracts/Cargo.toml) | `nonmember prototype` | `foundation-contracts` |
| [`crates/meta/eliot-learning-activation-assessment`](../../crates/meta/eliot-learning-activation-assessment/Cargo.toml) | `nonmember prototype` | `supervision-meta` |
| [`crates/smart/eliot-context-admission`](../../crates/smart/eliot-context-admission/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-context-assembly`](../../crates/smart/eliot-context-assembly/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-context-candidates`](../../crates/smart/eliot-context-candidates/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-context-contracts`](../../crates/smart/eliot-context-contracts/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-cue-activation`](../../crates/smart/eliot-cue-activation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-cue-binding`](../../crates/smart/eliot-cue-binding/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-cue-index`](../../crates/smart/eliot-cue-index/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-cue-normalizer`](../../crates/smart/eliot-cue-normalizer/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-accessibility`](../../crates/smart/eliot-dreamer-accessibility/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-architecture-brief`](../../crates/smart/eliot-dreamer-architecture-brief/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-bundle`](../../crates/smart/eliot-dreamer-bundle/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-candidate-validation`](../../crates/smart/eliot-dreamer-candidate-validation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-claim-grounding`](../../crates/smart/eliot-dreamer-claim-grounding/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-clarification`](../../crates/smart/eliot-dreamer-clarification/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-classification`](../../crates/smart/eliot-dreamer-classification/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-concept`](../../crates/smart/eliot-dreamer-concept/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-configuration-plan`](../../crates/smart/eliot-dreamer-configuration-plan/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-conflict-analysis`](../../crates/smart/eliot-dreamer-conflict-analysis/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-contracts`](../../crates/smart/eliot-dreamer-contracts/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-curation`](../../crates/smart/eliot-dreamer-curation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-development-diagnosis`](../../crates/smart/eliot-dreamer-development-diagnosis/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-episode`](../../crates/smart/eliot-dreamer-episode/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-failure`](../../crates/smart/eliot-dreamer-failure/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-implementation-brief`](../../crates/smart/eliot-dreamer-implementation-brief/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-maintenance-plan`](../../crates/smart/eliot-dreamer-maintenance-plan/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-memory-repair`](../../crates/smart/eliot-dreamer-memory-repair/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-orchestration-plan`](../../crates/smart/eliot-dreamer-orchestration-plan/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-orientation`](../../crates/smart/eliot-dreamer-orientation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-probe-plan`](../../crates/smart/eliot-dreamer-probe-plan/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-procedure`](../../crates/smart/eliot-dreamer-procedure/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-reconsolidation`](../../crates/smart/eliot-dreamer-reconsolidation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-relation`](../../crates/smart/eliot-dreamer-relation/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-rival-model`](../../crates/smart/eliot-dreamer-rival-model/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-dreamer-structure-repair`](../../crates/smart/eliot-dreamer-structure-repair/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-epistemic-contracts`](../../crates/smart/eliot-epistemic-contracts/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-learning-contracts`](../../crates/smart/eliot-learning-contracts/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-learning-delta`](../../crates/smart/eliot-learning-delta/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-learning-overlay`](../../crates/smart/eliot-learning-overlay/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-learning-state-view`](../../crates/smart/eliot-learning-state-view/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-memory-curation-contracts`](../../crates/smart/eliot-memory-curation-contracts/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-memory-curation-screen`](../../crates/smart/eliot-memory-curation-screen/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |
| [`crates/smart/eliot-reactive-context-plan`](../../crates/smart/eliot-reactive-context-plan/Cargo.toml) | `nonmember prototype` | `smart-memory-context` |

## Proof boundary

A clean index proves manifest discovery, explicit prototype classification,
inherited documentation routing, logical-block coverage, resolvable
documentation handles, and byte-for-byte projection equality for the exact
checkout. It does not prove source implementation, buildability, workspace
admission, runtime wiring, semantic ownership, or Product acceptance.
