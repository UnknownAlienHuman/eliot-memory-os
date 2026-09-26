# W1 fixup note — 2026-09-25 (test-strip, issue #1788)

- Rebased onto fresh origin/main ef38df8b (already up to date, no conflicts).
- Stripped 2 added #[test] fns from crates/governor/eliot-workscope/src/lib.rs
  (wrong_lease_key_*, unattested_evidence_class_*). Product code untouched.
- Verified working-tree diff vs origin/main: 0 added #[test]/#[tokio::test]/mod tests.
- Gates (offline, compile only, CARGO_TARGET_DIR %TEMP%\opencode\eliot-w1-1788):
  cargo fmt --check exit 0; cargo clippy --lib --no-deps -D warnings exit 0,
  zero warnings; cargo check --all-targets exit 0. No cargo test run.
- Amended + pushed --force-with-lease: b5bd0df6533cda740b166ea1b760fc19cbc1aa25.
- CHECKLIST.json: A1/A2 -> TEST-PHASE (runtime-proof-missing), W1..W7 MET on
  production callers with compile-only gates. REPORT.md fixup section added.
  Docs receipts reused from prior run (cited in REPORT.md).
