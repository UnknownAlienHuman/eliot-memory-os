# W1 REPORT — issue #1788 (sector AGENTS, wave 5)

Base: origin/main 5e90c952. Branch: issue/1788-bootstrap-discovery-W1.
Worktree: C:\Development\Rust\projects\eliot-swarm\W1-1788.

## Docs routing

- Route receipt: sha256:f561fd60b44c827ac1ead785633a67bac4288ad6e7327d5d352a21fb927e47e3
- Read receipt: sha256:bebdc38c81c8713b191bf7b08a54dad383970f9837bf472ff1e3ad6ace6522dc
- Matched routes: ["generic-source"] (no non-baseline route for this path family;
  brief-linked authority sections read directly instead)
- Bundle SHA-256: aedfe3aa2daa0367b2402245509720f314cc808d1d25932cffdd909fbc40fab5
- Required handles read (verified bundle, attestation: yes): AGENTS.md,
  WORKFLOW.md, crates/AGENTS.md, crates/governor/AGENTS.md,
  docs/ARCHITECTURE_CONTRACT.md, docs/DEPENDENCY_POLICY.md,
  docs/architecture/READING_PROTOCOL.md, workstreams/ACTIVE.toml, plus
  A0.1/A0.2/A0.3/A0.4/A0.6/A2.3/A10.4/A14.8/I00.3/I00.4/I00.5/I00.13/I00.14/
  I02.17/I02.20/I18 fragments.
- Authority sections linked by the brief, read directly (canonical, take
  precedence over the stale "Code today" paragraph, which predates the
  scanner merge): docs/architecture/I04-02-resolution-order.md (I4.2,
  DiscoveryReadLease + forbidden list), docs/architecture/I04-03-bootstrapscanner.md
  (I4.3, 12 collection classes + ProvisionalScopeProfile shape).
- No COMMON-RULES.md / REMAINING.md / CHECKLIST.prev.json / CLAIM exist in
  this checkout; the cross-check refutation quoted below (from `gh issue view
  1788 --comments`) is the operative requirement source. Later beats earlier.

## Cross-check refutation under repair (quoted verbatim from the issue)

- "W1: key_matches is never called by the scanner, the lease model does not
  retain all claimed key components, and the derived lease reference is never
  verified before use."
- "W2: authorize_operation is an uncalled unconditional error helper and scan
  charges reads without invoking any forbidden-operation guard."
- "W3: The scanner explicitly performs no filesystem, process, credential, or
  store I/O and accepts caller evidence, so collected_classes only maps
  supplied field presence rather than collecting the required metadata."
- "W4: The scanner accepts arbitrary caller strings, performs only shape and
  bounds checks, and copies caller-supplied redaction identities instead of
  enforcing an exclusion or redaction boundary."
- "W5: The receipt is constructed and returned from a local value without a
  store or durable write, so the claimed persisted ScanDisclosureReceipt is
  not implemented."
- "W6: profile_for synthesizes a profile from supplied evidence, hard-codes
  an empty verifier_candidates list, and is reached only through the
  test-invoked scan path."
- "W7: The scanner accepts governing_source_refs but omits them from the
  returned ResolutionRequest, whose fields contain no
  governing-source-reference slot."
- "A1: The named acceptance caller is inside #[cfg(test)], and its fixture
  supplies empty optional evidence while asserting a hard-coded class set
  rather than proving production collection or exclusion."
- "A2: The boundaryless acceptance test is also inside #[cfg(test)] and the
  scan implementation has no non-test production caller, so this is only a
  test seam rather than product-wired behavior."

## Fix map (all in crates/governor/eliot-workscope/src/)

- W1: `DiscoveryReadLease` retains proposer_ref/session_ref/host_ref/
  root_filesystem_identity_ref (lib.rs); `issue_discovery_lease` populates
  them; new `DiscoveryLeaseKey`; `BootstrapScanner::scan` re-derives the
  lease reference and verifies the key binding through
  `DiscoveryReadLease::key_matches` before charging. A lease whose
  reference does not re-derive from the presented key is rejected
  (`BindingReceiptMismatch`) without consumption.
- W2: `deny_forbidden_operations()` invokes `authorize_operation` for all
  five `DiscoveryOperation`s and fails closed if the guard ever admits;
  `scan` runs it before charging.
- W3: typed intake — `BootstrapScanEvidence.attested_reads`; scan requires
  attested set == populated set exactly (`check_attested_reads`) before
  charging; `run_bootstrap_discovery` binds evidence to live
  `ObservedScopeResources` (root ∈ observed roots, fs identity ∈ observed
  instances, VCS refs == observed generation).
- W4: intake has no excluded-class fields (compile-time); redaction
  identities must be 64-hex digests (`digest()` at intake AND receipt
  validation), no longer copied opaque strings.
- W5: `ScanDisclosureStore` port + `ScanReceiptHandle`; `scan` durably
  writes the receipt and reports `Completed` only with a bound handle; a
  failed write fails the scan. A1 asserts the stored receipt equals the
  returned receipt. (Governor boundary forbids owning store mechanics, so
  the write implementation stays with the store owner behind this port.)
- W6: `scan` takes caller `verifier_candidates`; `run_bootstrap_discovery`
  supplies the owner's registered `policy.verifier_refs`; empty records a
  `verifiers` capability gap. A1 asserts the real candidate list.
- W7: `ResolutionRequest.governing_source_refs` slot added (resolver.rs,
  validated ≤32/unique/text) and populated by
  `ScannerResolverInputs::to_resolution_request`.
- A1/A2: both route through the non-test production caller
  `run_bootstrap_discovery`; A1 additionally proves observation binding,
  durable write, and real verifier candidates; A2 proves no persistence
  without a boundary.

## Fixup (test-strip, 2026-09-25, owner order: PRODUCT CODE ONLY)

- Rebased onto fresh origin/main (ef38df8b, no new commits; already up to
  date, no conflicts).
- Removed the 2 added `#[test]` functions
  (`wrong_lease_key_fails_closed_without_consumption`,
  `unattested_evidence_class_fails_closed_without_consumption`) from
  `crates/governor/eliot-workscope/src/lib.rs`. All product code stays:
  lease key components, `key_matches` call, authorize guard, attested
  intake, redaction, store port + handle, verifier candidates,
  `governing_source_refs` slot, `run_bootstrap_discovery` caller.
- Kept test-only fixtures that existing (pre-existing, modified) tests
  still need to compile (`bootstrap_key`, `bootstrap_observed`,
  `bootstrap_policy`, `bootstrap_discovery`, `TestReceiptStore`,
  `attested_reads`): they serve the rewritten A1/A2 bodies, not only the
  stripped proofs.
- Amended commit (b5bd0df6, message unchanged incl. `(#1788)` trailer);
  pushed with `--force-with-lease`. Working-tree `git diff origin/main`
  contains zero `#[test]` / `#[tokio::test]` / `mod tests` additions.
- A1/A2 dispositions in CHECKLIST.json are now TEST-PHASE with
  runtime-proof-missing reason (no test execution cited or run in this
  fixup); W1..W7 stay MET against production callers with compile-only
  gates. CHECKLIST base corrected to origin/main ef38df8b.
- No `cargo test` was run in this fixup (owner order). Docs receipts below
  are reused from the prior run and cited as such.

## Gate (fixup; CARGO_TARGET_DIR %TEMP%\opencode\eliot-w1-1788, offline, compile only)

- cargo check --locked --offline -p eliot-workscope --all-targets: PASS (exit 0)
- cargo fmt -p eliot-workscope -- --check: clean (exit 0)
- cargo clippy --locked --offline -p eliot-workscope --lib --no-deps -- -D warnings: zero
  warnings (exit 0)
- Prior run (superseded test-execution evidence, NOT cited as proof per
  owner order): cargo test --offline -p eliot-workscope gave 37 passed,
  0 failed (incl. a1/a2 + 2 now-stripped fail-closed proofs); dependent
  crates compiled via --no-run. Recorded here for history only.
- No workspace build, no verify.ps1, no `cargo test` in this fixup.

## Conformance

- I4.2 lease shape + forbidden list: satisfied (keyed lease, unconditional
  denial of all five forbidden ops on every scan).
- I4.3 collection classes + ProvisionalScopeProfile + model-free: satisfied
  (12 classes, deterministic confidence/recommendation, no model call;
  verifier candidates now caller-supplied, not synthesized).
- Governor boundary (crates/governor/AGENTS.md: no store/credential/process
  ownership): preserved — scanner still performs no I/O itself; durable
  write is a store-owner port; observations stay caller-supplied.

## Notes / deviations

- No v2 control files existed at start (no CLAIM/REMAINING/CHECKLIST.prev);
  created only REPORT.md + CHECKLIST.json here, uncommitted per protocol.
- Branch keeps the brief-directed `issue/1788-bootstrap-discovery-W1` form
  (reused existing worktree); explicit manager instruction takes priority
  over the repo `work/<n>-<slug>` pattern for this wave.
- #1787 remains OPEN but its implementation merged to main (PR #2528,
  commit b98274a0, ancestor of base); no BLOCKED-BY — this change compiles
  against merged #1787 types without modification of #1787 semantics
  (one additive validated field on ResolutionRequest, the slot this issue
  owns per the brief).
