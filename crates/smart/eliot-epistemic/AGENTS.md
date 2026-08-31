# `eliot-epistemic` source instructions

## Purpose and owner boundary

`eliot-epistemic` is the current pure resolver for one question-scoped Current
Epistemic Position over an already admitted, immutable and fenced evidence read
set. It owns deterministic classification of supplied records into current
observations, support, rivals, stale material, supersession lineage, unknowns
and required inquiry.

It owns no evidence acquisition, canonical memory, status transition, model or
tool execution, probe scheduling, Context admission, task selection, authority,
finish decision or external effect.

Read issue #249 before changing current-freshness or supersession integrity.
Owner-neutral DTO extraction remains issue #38 and must not be hidden inside a
package-local resolver repair.

## Current resolution path

```text
owner-admitted PositionRequest
+ exact WorkScope and StateFence
→ validate record/evidence/fence identities
→ reject duplicate record, predecessor and self-supersession identities
→ separate exact-current from non-current freshness
→ resolve current observations, support, rivals, stale and unknown sets
→ retain explicit predecessor handles in supersession/provenance closure
→ emit deterministic CurrentEpistemicPosition and inquiry obligations.
```

## Integrity invariants

1. Only `ExactCandidate`, `ExactCommit`, and `ExactQuiescedWorktree` freshness
   may contribute to the current observed, supported, or rival position.
2. `KnownOlderSnapshot`, `Stale`, and `Unknown` freshness are non-current before
   status resolution; they require revalidation and cannot be rescued by a
   `Supported`, `Verified`, `Observed`, or `Contested` status.
3. A non-current `Unknown` record still preserves its subject-level unknown and
   evidence inquiry. Staleness must not erase the question.
4. Every explicit `EpistemicRecord.supersedes` handle is retained exactly once
   in `superseded_records` and the public provenance closure.
5. Self-supersession and duplicate predecessor handles fail closed.
6. Input permutation cannot change the emitted position, provenance or inquiry
   set.
7. The resolver never mutates source records, upgrades epistemic status,
   interprets retrieval count as support, or invents a missing owner contract.

## Deferred contract and edge work

Do not expand a resolver-integrity patch into:

```text
owner-neutral PositionRequest/EpistemicRecord/CurrentEpistemicPosition DTO
extraction under #38;
canonical evidence-provider reads or support-transition ownership;
verifier competence/independence contracts;
Investigation execution or scheduling;
Context provider/admission integration;
Dreamer model routing;
workspace/runtime admission or Product Pulse.
```

Return a ContractChallenge when requested work needs one of those owners or a
public wire migration rather than silently adding the contract to this crate.

## Proof

Minimum package proof for Rust changes:

```text
cargo fmt --all -- --check
cargo check --locked -p eliot-epistemic --all-targets
cargo test --locked -p eliot-epistemic
cargo clippy --locked -p eliot-epistemic --all-targets -- -D warnings
```

Focused fixtures must cover:

```text
known-older support cannot become current support;
unknown freshness preserves its subject gap;
all three exact-current freshness variants remain current;
explicit predecessor closure;
duplicate predecessor rejection;
self-supersession rejection;
input-permutation determinism.
```

Package proof establishes only pure resolver behavior. Canonical provider,
Context consumer, Investigation execution and the applicable Product Pulse
remain separate Edge/Product proofs. Report every unexecuted boundary exactly.
