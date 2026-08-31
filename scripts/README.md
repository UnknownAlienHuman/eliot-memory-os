# Supported repository scripts

Scripts are narrow wrappers around current source contracts. Their presence does
not create authority, implementation support, runtime readiness, or Product
Proof. Start from the owning issue/PR, use the smallest applicable entrypoint,
and preserve the proof ceiling stated below.

A script without a current consumer, owner, failure boundary, proof ceiling, and
removal path is retired rather than kept as archaeology. Generated reports,
receipts, bundles, caches, and runtime state are local/CI evidence and are not
committed as repository authority.

## Repository verification and documentation pipeline

| Script | Purpose | Proof ceiling |
|---|---|---|
| `verify.ps1` | Windows developer verification for documentation, normative identity, architecture boundaries, agent guardrails/routes, source hygiene, protocol policy, Cargo metadata, formatting, and workspace check | Source/build candidate only |
| `verify.sh` | Unix entrypoint for the same PowerShell-owned bounded verification profile | Source/build candidate only |
| `verify-normative.ps1` | Recompute canonical Architecture/Implementation digests and pair key; reject predecessor copies | Normative artifact identity only |
| `verify-normative.sh` | Unix-compatible normative-pair verifier | Normative artifact identity only |
| `docs_shards.py` | Public documentation front door: generate/check routed instruction surfaces and verify reconstructed shards, Markdown paths, anchors, exclusions, and exact path case | Normative content/layout and Markdown-link integrity only |
| `docs_shards_core.py` | Byte-preserved sharding/reconstruction implementation called by `docs_shards.py`; not a separate operator entrypoint | Internal documentation implementation |
| `docs_router.py` | Public router front door: reject unsafe paths, include deletions in changed-path routing, and emit bounded content-addressed route receipts | Documentation routing evidence only |
| `docs_router_core.py` | Byte-preserved router implementation called by `docs_router.py`; not a separate operator entrypoint | Internal documentation implementation |
| `docs_read.py` | Verify routed files/fragments by hash and byte count, materialize a bounded bundle, and emit a read receipt | Documentation reading evidence only |
| `verify-doc-code-conformance.py` | Public conformance front door for reader instructions, workflow claims, retired/nonexistent references, script/binary maps, owner bindings, and documentation-pipeline integrity | Static repository path/inventory/instruction consistency only |
| `doc_code_conformance_core.py` | Established deterministic DCC-001…DCC-007 implementation called by the public conformance front door | Internal conformance implementation |
| `audit-architecture-boundaries.py` | Detect forbidden dependencies, SurrealDB leakage, untracked direct process launch, placeholders, and exact tracked debt | Static source/build architecture evidence only |
| `verify-agent-guardrails.py` | Require bounded nearest-path owner/proof/stop instructions for declared source subtrees | Routing/control-plane evidence only |
| `audit-runtime-source-hygiene.py` | Expose unsafe, panic/unwrap/expect, ambient configuration, unbounded-output, blocking-sleep, and source-concentration signals | Static source-quality evidence only |
| `verify-agent-bridge-protocol.py` | Reject raw canonical Frame ingress, host-minted authority fields, validation bypass, correlation loss, and mandatory cancellation prose | Static protocol/source-policy evidence only |
| `verify-lint-policy.ps1` | Verify the Rust lint-policy configuration and declared exceptions | Static source-policy evidence only |
| `requirements-verification.txt` | Python dependency manifest for repository verification scripts | Verification dependency manifest |

The three public documentation entrypoints are intentionally small front doors.
Their `*_core.py` modules retain the established implementations while the front
doors own security/portability checks and focused negative fixtures. Call the
public filenames, not the core modules.

Run the documentation checks locally from the exact candidate checkout:

```powershell
python -m py_compile scripts/docs_shards.py scripts/docs_shards_core.py scripts/docs_router.py scripts/docs_router_core.py scripts/docs_read.py scripts/verify-doc-code-conformance.py scripts/doc_code_conformance_core.py
python scripts/docs_shards.py self-test
python scripts/docs_shards.py verify --root .
python scripts/docs_router.py self-test
python scripts/docs_router.py check --root .
python scripts/docs_read.py self-test
python scripts/verify-doc-code-conformance.py --self-test
python scripts/verify-doc-code-conformance.py --root . --json-out .eliot/doc-code-conformance.json
```

Issue #291 owns the conformance gate. Its policy is
`config/doc-code-conformance.toml`; findings fail nonzero:

- `DCC-001` — verified-reader contract drift across instruction/generator surfaces;
- `DCC-002` — workflow documentation differs from actual trigger source;
- `DCC-003` — retired or unstable documentation authority references;
- `DCC-004` — maintained top-level script missing from this map;
- `DCC-005` — root Cargo `bins/*` composition package missing from `PROJECT_MAP`;
- `DCC-006` — stale current-owner/work reference;
- `DCC-007` — missing/wrong-case `docs/...` path or unknown normative handle;
- `DCC-010` — Markdown scan omits required generated/local exclusions;
- `DCC-011` — changed-path routing loses deletions;
- `DCC-012` — Markdown paths are not checked for exact case cross-platform;
- `DCC-013` — drive-qualified paths are accepted as repository-relative.

The conformance gate remains outside `just quick` until the complete exact
candidate reports zero findings and the result is recorded in the owning PR.
A clean result still proves no Architecture semantics, compilation, runtime
behavior, authority correctness, Product acceptance, or release support.

## Agent route, host, and model-selection utilities

| Script | Purpose | Proof ceiling |
|---|---|---|
| `verify-agent-route-bundles.py` | Verify static shape and safety guardrails of agent route bundles | Static profile/schema evidence only |
| `agent_route_bundle_checks.py` | Supporting route-bundle schema/profile checks | Internal script module |
| `agent_route_contract.py` | Host declarations, findings, and errors for agent-route contracts | Internal contract module |
| `agent_host_bundle.py` | Build and validate bounded host-bundle projections | Internal projection module |
| `materialize-agent-host-bundle.py` | Materialize one bounded agent-host bundle from repository contracts | Generated candidate artifact only |
| `verify-agent-host-bundles.py` | Validate host-bundle inputs and generated projection boundaries | Static profile/projection evidence only |
| `agent_model_selector.py` | Development-only model-selection differential oracle; not the production routing owner | Candidate/oracle evidence only |
| `select-agent-models.py` | CLI wrapper around the development-only model-selection oracle | Candidate/oracle evidence only |

These tools do not prove a current provider account, model availability, quota,
process launch, cancellation containment, route admission, task completion, or
provider-independent verification.

## Antigravity and Swarm bounded probes

| Script | Purpose | Proof ceiling |
|---|---|---|
| `antigravity_runtime_preflight.py` | Validate Antigravity executable identity, version/help fingerprints, configuration and fail-closed preflight records without a model call | Runtime-integration candidate/preflight evidence only |
| `run-antigravity-runtime-preflight.py` | Operator wrapper for one exact Antigravity runtime preflight | Same exact preflight ceiling; no provider/model execution proof |
| `verify-antigravity-runtime-preflight.py` | Deterministic positive/negative fixtures for the Antigravity preflight contract | Static/preflight verification only |
| `swarm_product_pulse.py` | Deterministic provider-free Swarm control-plane pulse over supplied immutable fixtures | Control-plane candidate evidence only |
| `verify-swarm-product-pulse.py` | Verify Swarm pulse fixture shape, fail-closed boundaries, and expected dispositions | Static fixture/policy evidence only |

A preflight that identifies an executable or parses help is not evidence that a
model ran, quota was available, a provider route was admitted, cancellation was
contained, or a real Product Pulse passed. The provider-free Swarm pulse cannot
be promoted to live multi-agent/runtime proof.

## Release and installation

| Script | Purpose | Boundary |
|---|---|---|
| `build-eliot-windows-x64-release.ps1` | Build declared Windows x64 release inputs and an unsigned bundle | Build/staging only |
| `finalize-eliot-windows-x64-release.ps1` | Sign/finalize and independently read back declared release artifacts | Release-artifact evidence only |
| `invoke-eliot-windows-x64-production.ps1` | Execute the manifest-bound production invocation/installation flow | Live acceptance remains issue #11 |

Read `docs/release/WINDOWS_X64_RELEASE.md` before use. The canonical operator
surface is `eliot.exe`; scripts do not create a parallel CLI or direct
storage/process authority.

## Integration packaging and probes

| Script | Purpose | Boundary |
|---|---|---|
| `build-claude-desktop-extension.ps1` | Build the Claude Desktop extension package from repository sources | Package construction only |
| `test-claude-connector.ps1` | Run the bounded Claude connector probe/fixture path | Exact integration-fingerprint evidence only |
| `eliot-mcp-reference-client.ps1` | Reference MCP client for protocol/bridge diagnostics | Diagnostic/client evidence only |
| `run-isolated-tests.ps1` | Provision an owned Windows/Surreal test namespace and run one selected package/test profile | Exact selected Module/Edge evidence only |

Provider versions, accounts, routes, and host behavior are requalified per issue;
an old successful probe is not current support. An in-memory/fake test is not
real store/runtime proof.

## Admission rule for a new script

A new script requires:

- one current owning issue and consumer;
- a stable source contract or command it wraps;
- exact inputs, identity, side effects, cleanup, and failure behavior;
- a declared proof ceiling;
- no hidden credentials, broad filesystem mutation, or alternative authority
  path;
- an exact entry in this map and a removal condition.

Campaign names, milestone numbers, `final`/`certified` labels, dated audit
wrappers, and aliases around legacy binaries are rejected. Current findings
belong in the issue/PR or local/CI artifacts, not in a new committed report.
