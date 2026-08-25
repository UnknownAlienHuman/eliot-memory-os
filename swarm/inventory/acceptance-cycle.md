# W1-03 — acceptance dependency cycle (content-bound evidence)

Authority: `EVIDENCE_ONLY`. This inventory is a static acceptance graph artifact; it is not a canonical `TerminalWorkUpdate`, product proof, runtime proof, or activation decision.

## Bound source bytes

- reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md :: 1ea03c0ac5ee46abaa2201589c5c8356f1ef23550b5696cf3312b85e9aebeefb
- docs/tasks/RECOVERY_PROGRAM_v1.md :: 688c8f947a52f81ccdb204f0390fa6ef9c7930c6ccc72aa6cabb3070b9c3bd0a
- docs/ARCHITECTURE_CONTRACT.md :: 5f2ce7992e027847c678544261482e5e89aaa7a8a6a468c35aaa1d8df711e386
- docs/normative/ELIOT_ARCHITECTURE.md :: 58e71a2bdb10925c63d85a708ed768aee8617bed0fb52eb044478ec20ab439d8
- docs/normative/ELIOT_IMPLEMENTATION.md :: c216fb7f6fdbc62d108c748be6f61ca7ef9e5d24e5bb13af2677c31a58460c0b
- docs/normative/INDEX.md :: 75832cc59f8267e788757112ab6e7a6d8be723e48907c8508bd99f5185384465
- docs/normative/README.md :: 73fe1441d1629ff7abda3929eea2f32333d452b60f92f86eb3d87acb6a948b2c
- docs/normative/PROJECTION_NOTICE.md :: 51f836c9be9fff478cf0472cfe17669a19e45a7ae093c4ae082eb19386820224
- docs/normative/projection-manifest.tsv :: 1d280b15b5acb99bfc0e1e2a6c4dab669a0d5d9967191383d4e3ea9d04e8db1c
- scripts/verify-normative.ps1 :: b960ed2f487ddbcaa827ca525d152643f10acb630034c8040b4af7897b252363

## Repository provenance boundary

`docs/ARCHITECTURE_CONTRACT.md`, the repository `docs/normative/` projections, `docs/normative/projection-manifest.tsv`, and `scripts/verify-normative.ps1` are bound by repository-relative path, SHA-256, and lexical anchors. The W0 normative verifier enforces projection/contract hash equality; W1-03 does not independently reassert equality with an external canonical location and does not read one.

## Exact seven-cell graph

The graph contains exactly seven cells: `C0-12`, `C0-13`, `A-01`, `A-03`, `A-05`, `G-03`, and `G-10`.

| Node | Criterion |
|---|---|
| `C0-12` | Versioned, schema-bound security/disclosure/influence contract; fail-closed construction; provider-issued verifier, declassification, disclosure and selection evidence; Q-01 duplicate owner removed. |
| `C0-13` | Canonical-byte/revision-bound evaluation contract; provider-issued independent evidence; closed verdict/outcome matrix; exact fence/source/artifact/proof-ceiling bindings. |
| `A-01` | Admitted agent launch path with exact authority, freshness, integrity, taint, privacy, verifier, fence and effect checks; NARROW seals unit/scope/route; no raw launch bypass. |
| `A-03` | The A-03 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate. |
| `A-05` | The A-05 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate. |
| `G-03` | Owner-admitted TaskContract from TaskSelectionEvidence, WorkScope/project identity and source binding; verification bound to task revision/fence/artifact/freshness/proof ceiling; durable canonical lifecycle. |
| `G-10` | RequestMeta-bound asynchronous blueprint/registry with verifier-bound fresh readiness, complete route fingerprint, resolved bindings and exact Cargo integration. |

## Directed acceptance edges

Edges are provider → consumer acceptance dependencies, not runtime or Cargo call edges.

| ID | Edge | Class | Derivation |
|---|---|---|---|
| `E1` | `C0-12` → `C0-13` | proof/evidence | derived_provider_consumer_from_explicit_ledger_requirements |
| `E2` | `C0-13` → `G-03` | proof/evidence | derived_acceptance_binding_not_runtime_call_edge |
| `E3` | `G-03` → `A-01` | product | ledger_explicit_cross_cell_prerequisite |
| `E4` | `G-10` → `A-01` | product | derived_route_readiness_prerequisite |
| `E5` | `A-01` → `C0-13` | proof/evidence | derived_candidate_to_independent_verdict |
| `E6` | `A-03` → `C0-13` | proof/evidence | derived_shared_trio_boundary |
| `E7` | `A-05` → `C0-13` | proof/evidence | derived_shared_trio_boundary |
| `E8` | `G-10` → `C0-12` | proof/evidence | derived_source_provenance_and_route_binding |

No A-01/A-03/A-05 ordering edge and no runtime cycle is asserted.

## SCC and concrete cut

The sole non-singleton SCC is exactly `{C0-13, G-03, A-01}` with witness cycle `C0-13 → G-03 → A-01 → C0-13`. `C0-12`, `A-03`, `A-05`, and `G-10` are singleton SCCs in this seven-cell internal graph.

The minimum vertex cut for that witness SCC is concretely size one. Equal cuts are `{A-01}`, `{C0-13}`, and `{G-03}`; selected cut is `{A-01}`. This is a graph result, not an activation decision.

## A-01 Recoverable Deviation proposal

Status: `PROPOSAL_ONLY_NOT_ACTIVATED`.

Only A-01's pre-execution admission boundary may return a typed `PLAN_GAP`/`UNAVAILABLE` candidate naming missing provider identities and the bound source digest set. It may not start a process, issue `DispatchPermit`, widen authority, mint verifier evidence, or emit `VERIFIED_COMPLETE`. A-03 and A-05 remain blocked for real execution. Root acceptance is required; no acceptance is recorded here.

Review requires independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate. Rollback revokes the proposal, restores normal admission, preserves negative evidence, and reruns the graph/trio checks.

Proof ceiling: static ledger/document graph only; no Cargo, runtime, provider, or canonical-result execution proof.

Reproduce:

```powershell
pwsh -NoProfile -File scripts/gen-acceptance-cycle.ps1
pwsh -NoProfile -File scripts/verify-acceptance-cycle.ps1
```