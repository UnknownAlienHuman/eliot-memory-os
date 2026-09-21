# PR body — 1936: record coverage denominators and compliance traces (integration)

Worker delivery at `8f9a32d9b575ccbb3a870e57c0429a929967953a` on branch
`codex/1936-coverage-traces-integration` (implements #1936). Preserves worker
commit `6ba2d5b9`; base merge `f131a782` over `origin/main@1a18895e`.
**Note:** `origin/main` has since moved to `f37966c3` via root sync — rebase/
merge left to the integration owner.

## Scope

- `crates/foundation/eliot-evaluation-contracts/src/coverage_traces.rs` only
  (new `ObservationCoverageManifest`, `HostObservedComplianceTrace`,
  `derive_compliance_trace`, `absence_claim_admissible`,
  `coverage_percentage`, plus 9 tests). No other files touched; zero
  in-workspace consumers, so no consumer hunks.

## What this proves (package proof, honest ceiling: Module Proof / OBSERVATION)

- `cargo test -p eliot-evaluation-contracts` → **40/40 pass**
- `cargo clippy -p eliot-evaluation-contracts --all-targets -- -D warnings` →
  clean; `cargo fmt --check` → clean
- Complete clean run → `PASS` with explicit denominator (now including
  `denominator_completeness`); cursor gap or undeclared shell read →
  `TAINTED` naming the blind interval/access, never `PASS`; percentages and
  absence claims require a complete, gap-free, payload-clean denominator;
  unlocalized sequence faults rejected fail-closed; `PASS` requires a complete
  denominator; `UNKNOWN` carries its incomplete denominator.

## Hardening vs the prepared worker commit

Payload mutations now block absence/percentage claims; percentages now check
sequence faults; fault localization is enforced on the manifest; the trace
carries denominator completeness. One deliberate call: duplicates/reorders
don't gate claims (idempotent replay per I7.23:14 — recorded, not holes).

## Documentation receipts (attestation in `control-20260921/2244-integrated-delivery.md`)

- Route `sha256:8bc8bc9e0b049a459448e38071a7af8382d90dfd2b0c4dc6705a5de8fc2c72f8`
  · Read `sha256:6e0ea5dfeb02a290a962a337787660d6437e8a218bb6f7458a22b43da59898da`
  · Bundle `15b35502f8af0897cbace08c1645bc8f979721f129e49a0b5db1593269f89519`
- Pair `sha256:3ea4dc3442f03d3a0020380854d45cdf20c9d5098197e0bfe1e80cf6f2b805ea`,
  routes `generic-source`, handles `A0.1 A0.2 A0.3 A0.4 A0.6 A2.3 A10.4 A14.8
  I0.3 I0.4 I0.5 I0.13 I0.14 I2.17 I2.20 I18` (full path/SHA table + explicit
  reading attestation in the delivery doc).

## Residuals (issue #1936 stays OPEN)

Pure foundation contract only — no ingestion wiring, no live-runtime claim.
Still needed: (1) I7.23 ingestion populates the manifest per fingerprint;
(2) a host-event-side consumer derives the trace from immutable records
(candidate: `crates/kernel/eliot-ipc` bridge area, root to assign);
(3) Product Proof on a real + fault-injected run. Wire note: new required
field `denominator_completeness` (safe: PR unmerged, zero consumers).
