# 837 D-WU-FINAL integration — evidence (CLI + matrix + 8 verifier cures)

Base: `d8af3d91cebb4ecf302ff5226ef05b2241071215` (cherry-pick parents verified).
Branch: `work/837-final-integration` (fresh worktree `mgr02-item-837-int`).
Cherry-picks (in order, zero conflicts, both sides' claimed-scope kept):
- CLI `1c413c01cc46b79bc5bdacb691d311c09c90bc6a` (`work/837-final-cli`)
- TEST `f3817ca3d6e05cf606050acaf9ae7c5da9c6013c` (`work/837-final-tests`)
Verifier FAIL report applied: `.swarm/runs/20260912T115840Z/workers/MGR02/items/837/verifier.md`
(8 must-fix cures); reader: `.../items/837/reader.md`.

## Documentation routing (integration-owned paths)

Ran from worktree root before mutation:

```text
python scripts/docs_read.py read --path scripts/verify-work-unit.py --path scripts/work_unit_gate/__main__.py --path scripts/tests/test_work_unit_gate_integration.py --path scripts/testdata/work-unit-gate/integration --path .github/temporary/work-unit-837.md --topic "work-unit gate final integration cures" --output <temp>/docs-read-bundle-837-int.md --receipt-out <temp>/docs-read-receipt-837-int.json
```

Result: `DOC_READ: PASS receipt=sha256:7e2e17ffb4bb13e38dd5cc77d7bb82fe290733fa94e0041d1b549932757cab97 route=sha256:be439c9fb926b976fa0eda82e44167cc26a3674da765177da8a4ad9ab4ebef3c required=56 bundle_sha256=567bd21ab6955d34c870c4b4b99124a72281c1fa32645fabba0e8dfaa0cfef4d`

- route receipt ID: `sha256:be439c9fb926b976fa0eda82e44167cc26a3674da765177da8a4ad9ab4ebef3c`
- read receipt ID: `sha256:7e2e17ffb4bb13e38dd5cc77d7bb82fe290733fa94e0041d1b549932757cab97`
- matched routes: `instrument-verification`, `workspace-governance`
- required items: 56 (8 files + 48 fragments)
- required file handles: AGENTS.md, Cargo.toml, WORKFLOW.md, docs/ARCHITECTURE_CONTRACT.md, docs/DEPENDENCY_POLICY.md, docs/architecture/READING_PROTOCOL.md, scripts/verify.ps1, workstreams/ACTIVE.toml
- normative pair: `sha256:105558fc8957e150fab407b4fc5818ec49dc784f23f246f42dc9d3ca5843196b`
- verified bundle SHA-256: `567bd21ab6955d34c870c4b4b99124a72281c1fa32645fabba0e8dfaa0cfef4d` (recomputed via hashlib, match)

ATTESTATION: I read the full receipt JSON, verified the bundle hash, read the
required fragment sections, and directly read the four arch files (I17-14 42
lines, I18-07 47 lines, I18-21 15 lines, I18-27 16 lines), issue 837 (full body
via `gh issue view`), the frozen child APIs (exact signatures + binding/parse
semantics used below), and verifier.md + reader.md in full. A route alone was
not treated as reading evidence.

I18-27 blind-review note: this candidate changes implementation
(`__main__.py`) and oracle (`test_...py`) together. The oracle delta is
mechanically derived from the verifier's must-fix list (#1 flag parity, #7
guard narrowing, #8 decode spy) plus the unchanged frozen CLI contract and
frozen child APIs — no oracle authority created by assertion. Test bodies for
837/1,25,27,29 were extended with controller-admitted temp fixtures (offline
snapshot + sidecar + tiny suite) so the previously CLI-absent cases execute
honestly; no case deleted, no assertion weakened (all 42 markers intact, 9
legacy methods byte-preserved).

## Frozen CLI contract (ONE contract, both sides byte-for-byte)

| Dimension | Frozen spelling |
|---|---|
| Proof kinds (`--proof`) | `catalogue-only` \| `selected` \| `full-project` |
| Selector | `--issue NUMBER` (repeatable, distinct; comma lists split) xor `--crate NAME` (closed lookup) for `selected`; none otherwise |
| Source mode | `--live` xor `--offline-capture PATH` (mutually exclusive, no fallback); required for `selected`/`full-project`, forbidden for `catalogue-only` |
| Projection | human (default) \| `--json` |
| JSON keys | `proof`/`selection`/`selection_label`/`scope`/`counts`/`missing_evidence`/`blocked_evidence`/`failed_evidence`/`identities`/`proof_ceiling`/`digest`/`terminal`/`terminal_detail`/`exit`/`completion` |
| Exits | 0 requested proof satisfied; 1 contract/incomplete; 2 usage/config/internal |
| Offline authority | digests only from controller sidecar `<capture>.admission.json` (`snapshot_sha256`, `producer`, `capture_receipt_sha256`, `freshness_policy_sha256`, `max_age_seconds`); never from the snapshot payload |

Rejected alternatives (TEST-side labels, removed): `selected-package`,
`--select`, `--offline`, `--format human/json`, `proof_kind`/`result` keys.

## The 8 cures (file:line cites against the cure commit)

1. Frozen contract above (`__main__.py:96-110` contract block,
   `:310-345` argparse; `test_...py:10-32` docstring, `:304-310`, `:391-397`,
   `:692`, `:717`, `:740-741`, `:772` invocations + `proof`/`terminal`/`exit`
   keys; `run_gate` translates argparse `SystemExit(2)` to code 2). Table
   documented here.
2. Measured shape/package (`__main__.py:1584-1660`): `source_items=len(before)`
   (snapshot_protected), `public_items=len(markers)` (parse_source_markers),
   `test_items`=EXECUTED_PASS count (compose_execution_record path), guards
   from reconciled accounting, results mirror combine priority. No `max()`,
   no assumed PASS.
3. Offline sidecar (`__main__.py:900-945`): digests from
   `<capture>.admission.json`; snapshot bytes validated by #849 only.
4. Real rust binding (`__main__.py:1251-1300` caller runs frozen
   `build_cargo_build_command` + `parse_cargo_build_stream`;
   `_rust_binary_binding` binds observed test-profile artifacts with hashed
   bytes; `_rust_package_binding` assembles metadata from observed artifacts
   + closed workspace tables via frozen `bind_package_observation`).
   Missing binary/observation is incomplete (exit 1), never canned
   (`"0"*64`/`[]`/`missing-test-binary` deleted).
5. Deleted orchestration `rglob("Cargo.toml")`+substring discovery and regex
   TOML peek; lookup/peek via frozen `cohort.decode_cohort_descriptor`
   (strict, no binding claim), binding only via
   `descriptor_runner.parse_descriptor`/`resolve_package_manifest`/`bind_*`;
   workspace admission from closed root manifest only (stdlib tomllib,
   workspace use). Legacy diagnostic preserved untouched.
6. Single decode per file: crate lookup reuses cohort-decoded
   `decoded_all`/`raw_all`; each file sees `decode_descriptor` at most once
   per run (selected via parse-internal, others explicit once).
7. 837/35 narrowed (`test_...py:1033-1056`): allows stdlib
   `argparse`/`tomllib` (CLI/workspace-admission use); forbids local
   acquisition/parsers/argv builders + network/markdown clients.
8. 837/25 spies the CLI decode entry (`test_...py:823-885`): patched
   `descriptor_runner.decode_descriptor` counts once per distinct file (2
   files → 2 calls, 1 each, never twice for one) with catalogue-only running
   no subprocess; multi-descriptor plan retained via direct APIs. Vacuous
   `counting_decode` self-call deleted. `_selected_unit_for_crate`
   (`__main__.py:404-415`) derives the issue from the decoded catalogue.
   Incidental honest fix in scope: runner phase verdict now uses the measured
   `("execute", outcome)` pair instead of the descriptor phase label (the old
   call always raised UNKNOWN_PHASE_OUTCOME, masked as source-unavailable).

Kept: redaction/exits/catalogue-only/no-recursion; digests via
`canonical_sha256`/`cohort_digest` only (no label echo); no child-algorithm
copies; 42 markers 1..42 intact + 9 legacy preserved; no Rust/workflows/
AGENTS/router/child edits. Scope: only the 5 claimed prefixes.

## Verification (honest, this worktree)

- `python -m py_compile scripts/verify-work-unit.py scripts/work_unit_gate/__main__.py scripts/tests/test_work_unit_gate_integration.py` → exit 0
- `python -m unittest scripts.tests.test_work_unit_gate_integration -v` → Ran 49, OK (9 legacy + 40 matrix; 42/42 markers green; the 17 CLI-absent errors are gone by CLI binding + flag parity)
- `python scripts/verify-work-unit.py --help` → exit 0; frozen examples spot-checked (catalogue-only / selected offline / failures)
- `git diff --check` → clean; `git status` → only 5 claimed prefixes
- `cargo clippy --locked --workspace --all-targets` → recorded honestly
- `pwsh -NoProfile -File scripts/verify.ps1 -Profile Quick` → VERIFY_RESULT recorded honestly
