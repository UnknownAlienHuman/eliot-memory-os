# 837 D-WU-FINAL tests+fixtures — writer evidence (matrix layer only)

Base: `d8af3d91cebb4ecf302ff5226ef05b2241071215` — VERIFIED (`git rev-parse HEAD` exact match).
Branch: `work/837-final-tests` (fresh from base, clean worktree).
Worktree: `C:\Development\Rust\projects\eliot-swarm\mgr02-item-837-test`.
Scope: EXACTLY owned paths (disjoint from CLI writer; never touched `item-*`, `mgr02-item-837-cli`, `__main__.py`, child modules, Rust, workflows, AGENTS/index/router):
- `scripts/tests/test_work_unit_gate_integration.py` (extend to 42-case matrix)
- `scripts/testdata/work-unit-gate/integration/` (finite NEW fixtures)
- `.github/temporary/work-unit-837.md` (this evidence note only; absent at base per reader)

## Documentation routing (writer-owned paths)

Ran from worktree root before mutation:

```text
python scripts/docs_read.py read --path scripts/tests/test_work_unit_gate_integration.py --path scripts/testdata/work-unit-gate/integration --topic "work-unit gate integration test matrix" --output .eliot/docs-read-bundle.md --receipt-out .eliot/docs-read-receipt.json
```

Result: `DOC_READ: PASS receipt=sha256:b9cf878629981e8ec9f392ed749726b24e005137c9100ae3b40dfdb87c02e502 route=sha256:282f4135ad82bef942be7a5577dbdd59656b88b683d63ae81176b3a0f704fd69 required=26 bundle_sha256=e8e9b0eb38b1265558990f8df035e7bba78f8b726a21bb30a43fe36896e83286`

- route receipt ID: `sha256:282f4135ad82bef942be7a5577dbdd59656b88b683d63ae81176b3a0f704fd69`
- read receipt ID: `sha256:b9cf878629981e8ec9f392ed749726b24e005137c9100ae3b40dfdb87c02e502`
- matched routes: `workspace-governance`
- required items: 26 (AGENTS.md, Cargo.toml, WORKFLOW.md, docs/ARCHITECTURE_CONTRACT.md, docs/DEPENDENCY_POLICY.md, docs/architecture/READING_PROTOCOL.md, workstreams/ACTIVE.toml + fragments A0.1-A0.4 etc.)
- normative pair: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`
- verified bundle SHA-256: `e8e9b0eb38b1265558990f8df035e7bba78f8b726a21bb30a43fe36896e83286` (recomputed via hashlib, match)

ATTESTATION: I read the full verified bundle (99652 bytes) and receipt, plus WORKFLOW.md, workstreams/ACTIVE.toml, issue 837 (full body via `gh issue view 837`), the four arch files (I17-14 42 lines, I18-07 47 lines, I18-21 15 lines, I18-27 16 lines), and the exact frozen child APIs (contracts 834 lines, assignment_source 761, descriptor_runner 1564, case_binding 821, cohort 469) with one-hop callers. Reader recon (`reader.md` 170 lines, route `c3a1425e...`, read `0cc8e116...`, bundle `737b2567...`) was read as navigation, not as current-state authority. A route alone was not treated as reading evidence.

Reader preflight cited: base `d8af3d91...` verified, `__main__.py` ABSENT, `integration/` ABSENT, `.github/temporary/work-unit-837.md` ABSENT — all confirmed still absent before my mutation (except my own new fixtures/note).

## Frozen fixture paths (17 files, exact, no more without issue revision)

- `scripts/testdata/work-unit-gate/integration/README.md`
- `scripts/testdata/work-unit-gate/integration/descriptors/selected-python.toml`
- `scripts/testdata/work-unit-gate/integration/descriptors/selected-rust.toml`
- `scripts/testdata/work-unit-gate/integration/descriptors/selected-metadata.toml`
- `scripts/testdata/work-unit-gate/integration/descriptors/standalone-local.toml`
- `scripts/testdata/work-unit-gate/integration/descriptors/membership-required.toml`
- `scripts/testdata/work-unit-gate/integration/descriptors/planned-future.toml`
- `scripts/testdata/work-unit-gate/integration/repos/python-tiny/sample.py`
- `scripts/testdata/work-unit-gate/integration/repos/python-tiny/test_sample.py`
- `scripts/testdata/work-unit-gate/integration/repos/python-tiny/test_markers.py`
- `scripts/testdata/work-unit-gate/integration/repos/rust-tiny/Cargo.toml`
- `scripts/testdata/work-unit-gate/integration/repos/rust-tiny/src/lib.rs`
- `scripts/testdata/work-unit-gate/integration/repos/metadata-tiny/module.toml`
- `scripts/testdata/work-unit-gate/integration/repos/metadata-tiny/check.py`
- `scripts/testdata/work-unit-gate/integration/captures/offline-capture.json`
- `scripts/testdata/work-unit-gate/integration/vectors/redaction-canaries.txt`
- `scripts/testdata/work-unit-gate/integration/vectors/ordering-vectors.json`

Shapes reuse `descriptor-runner/{python-tiny,rust-tiny}` (tiny bounded suites, offline, stdlib/zero-dep) with distinct 837 content; no runner algorithm copied. Descriptors decode via `decode_descriptor` with `.github/work-units/<n>.toml` filename binding; `planned-future.toml` references `future-only/not-yet-created.py` (missing-implementation fixture for 837/39).

## Test matrix (42 markers, 49 methods)

- Existing 9 `LegacyCompletionSafetyTests` methods preserved byte-identical (including 837/14 discovery-without-execution, 837/23 no-cargo diagnostic). No weakening/deletion per I18-27.
- New `WorkUnitGateMatrixTests` adds 40 methods for cases 1-13,15-22,24-42 (each `# WORK_UNIT_CASE: 837/<n>` immediately above its `def test_`, verified: 42 markers total, unique 1..42, 0 bad immediacy, 49 `def test_` total).
- Deterministic fake child ports assert failure paths (live-timeout, offline-stale, dup modes, arbitrary flags) never canned pass; real tiny repos exercise actual `decode_descriptor`/`parse_rust_discovery`/`bind_python_suite`/`resolve_metadata_entrypoint`/`parse_python_markers`/`materialize_catalogue`/`materialize_selection_plan`/`cohort_digest`/`canonical_sha256`/`snapshot/compare`/`cleanup_verdict`/`phase_verdict`. No live model/Product, no network, no cargo execution, no skips, no label-echo oracles.

## Verification (honest, CLI-absent expected)

- `python -m py_compile scripts/tests/test_work_unit_gate_integration.py` → exit 0.
- `python -m unittest scripts.tests.test_work_unit_gate_integration -v` → Ran 49 tests, 39 pass, 10 tests error (17 error instances, 0 failures). All 17 errors are `FileNotFoundError: scripts/work_unit_gate/__main__.py` (CLI writer owns it; integrator binds). Failing tests are exactly the 10 CLI-contract cases: 837/1,6,24 (8 subtests),25,26,27,29,30,35,41. All 30 direct-API + 9 legacy tests pass.
- `git diff --check` → clean (only CRLF advisory, no whitespace errors).
- `git status` → ONLY owned paths: `M scripts/tests/test_work_unit_gate_integration.py`, `?? scripts/testdata/work-unit-gate/integration/`, `?? .github/temporary/work-unit-837.md`.

No Rust, no workflows, no AGENTS/index/router edits, no child-module edits, no fetch/pull/push.
