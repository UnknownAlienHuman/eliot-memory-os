# W3-01 decision — internal test-module extraction

Status: `ACCEPTED_RECOVERABLE_DEVIATION`

Authority: Root / Sol decision under Architecture `A0.6`, accepted on
2026-08-25. This decision changes only the physical placement named by W3-01;
it is not Product Proof, runtime authority, a canonical `TerminalWorkUpdate`,
or acceptance of any W2–W7 product property.

Owner: Root / Sol for the deviation and review; the W3-01 installation owner
for the bounded mechanical extraction and its verification.

Reason: the Recovery Program names a top-level integration `tests/` target,
but the current inline module depends on private and sealed same-crate
interfaces, cfg(test)-private constructors, and one process-local global test
lock. Moving it to an integration target would require public/security-surface
widening, alter qualified test identities, and split the serialization lock
across test binaries. Those effects violate W3-01's explicit non-goals.

Affected scope: replace the inline `#[cfg(test)] mod tests { ... }` body in
`crates/kernel/eliot-installation/src/lib.rs` with `#[cfg(test)] mod tests;`
and mechanically move the body to `src/tests.rs`, allowing only canonical
`rustfmt` indentation and behavior-equivalent test-only lint cleanup. The
module remains named `tests`, runs in the same lib-test binary, retains
same-crate privacy, and preserves the qualified test list.

Review condition: review only if an explicit test-facade and sealing design is
accepted that preserves the public authority boundary, every qualified test
identity, and the single-process lock semantics while moving the suite to a
top-level integration target.

Rollback: move the body from `src/tests.rs` back under the inline
`#[cfg(test)] mod tests { ... }`, remove `src/tests.rs`, and rerun the exact
pre/post test-list comparison plus the focused installation verifier. No
product state or persisted data is changed.

## Boundaries and proof ceiling

This deviation authorizes no production-logic change, public API change,
feature widening, Cargo-graph change, test behavior change, schema change,
external effect, hosted claim, or Product Pulse claim. The proof ceiling is a
mechanical source/STU extraction with an identical qualified lib-test list and
passing local installation checks.

The Program's stale line anchors and counts are evidence drift, not authority:
the execution owner must measure the current file immediately before moving
the block and bind the result to that current source.
