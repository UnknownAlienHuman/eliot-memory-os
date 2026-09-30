# #2645 — Route owner bind (MC lane, BUILD/AGENTS)

Branch `fix/2645-route-reference-owner-MC1` from `origin/main@0738d7ef`.
Base already contains PRs #2745/#2955 (owner-derived column checks,
cursor/sequence applicability gate, replay column comparison).

## Outcome

Delivered the remaining product wiring inside the agent crates:
every retained requested/actual route reference is now bound to its
proper owner material before host-event staging, and that validated
relation is retained, replay-bound, and carried into coordinator
intake with re-verification at both ends.

## Product changes (3 files)

- `crates/agent/eliot-agent-api/src/host_event.rs`
  - New `ROUTE_BINDING_CONTRACT_VERSION` (`eliot-agent-api/route-binding-v1`).
  - New `CommittedRouteEvidence`: owner-qualified requested/actual
    digests, validated observation receipt identity (`self_digest`,
    resolving the exact receipt through its owner), binding version.
  - `CommittedHostEventIntake` carries the relation verbatim
    (4 new `#[serde(default)]` fields: old shapes still decode but
    fail `verify` instead of passing as verified).
  - `from_envelope` takes the retained relation and fully re-verifies
    before returning; `verify` enforces binding-version currency
    (`UnknownContractVersion`) and lineage/route agreement
    (session: all absent; execution-unit: requested present; actual
    without observation rejects; `Unobserved` receipt without observed
    route passes).
- `crates/agent/eliot-agent-api/src/lib.rs` — re-exports for the two
  new items.
- `crates/agent/eliot-agent-acp/src/durable_host_event_ingest.rs`
  - `DurableHostEventRecord::route_evidence` retained at staging.
  - `stage()` builds it from validated owner material
    (observation `self_digest` already self-digest-checked inside
    `validate_against`); replay exact-match extended with the
    relation conjunct, so changed route metadata under one event
    identity conflicts.
  - `to_coordinator_intake` mints with the retained relation;
    stale/drifted relations fail closed with typed errors, rows stay
    retained with restricted use.
- Untouched by design: `route_receipts.rs` (shared with #2641/#369,
  one-writer rule), `host_event_producer.rs` (session-only path
  byte-identical), coordinator (only reads envelope/receipt; tightened
  `verify` applies automatically), `StageAllowed`/`StageRedacted`
  shapes (redundant caller values stay independently verified).

## Checks run

- `git diff --check`: clean.
- `docs_read.py`: PASS, 54 required items, bundle SHA
  `1c8351b8…abd`; I7.23 and I15.19 read verbatim.
- `cargo fmt/clippy/test`: NOT RUN (lane rule: manager owns gates).
  Import order/line-widths were hand-matched to rustfmt greedy
  packing; single minter, no struct literals, no golden JSON, and no
  test call sites for the changed signatures were verified by
  workspace grep before editing.

## Could not complete in this lane

- Live execution-unit caller wiring: no production
  `physical_observation: Some(...)` caller exists in-tree (only the
  session-only producer). Minting observations in-crate would invent
  authority, which the issue forbids; the guard stays reachable via
  the public staging API for the bridge/ORS owner.
- Behavioral proofs (execution-unit binding, divergence/absence,
  replay/readback): TEST-PHASE — new tests are forbidden in this
  lane; proofs belong to the focused wave after manager gates.
