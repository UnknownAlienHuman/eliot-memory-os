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
| `read_freeze_digest.py` | Reproducible-digest readback for the Wave 1 static field contract freeze | Static field contract only |
| `docs_shards.py` | Public documentation front door: generate/check routed instruction surfaces and verify reconstructed shards, Markdown paths, anchors, exclusions, and exact path case | Normative content/layout and Markdown-link integrity only |
| `docs_shards_core.py` | Byte-preserved sharding/reconstruction implementation called by `docs_shards.py`; not a separate operator entrypoint | Internal documentation implementation |
| `docs_router.py` | Public router front door: reject unsafe paths, include deletions in changed-path routing, and emit bounded content-addressed route receipts | Documentation routing evidence only |
| `docs_router_core.py` | Byte-preserved router implementation called by `docs_router.py`; not a separate operator entrypoint | Internal documentation implementation |
| `docs_read.py` | Verify routed files/fragments by hash and byte count, materialize a bounded bundle, and emit a read receipt | Documentation reading evidence only |
| `docs_closure_audit.py` | Temporary independent audit of shard reconstruction, original Git blobs, generated indexes, operational references, and workstream issue-state parity | Audit evidence for the current documentation closure only; remove after closure |
| `verify-work-unit.py` | Retired legacy source-shape diagnostic for one capability cell: reads `[acceptance]` from the crate's `module.toml` for hints only; always reports completion=NOT_VERIFIED and never accepts a work unit — acceptance is decided by the owning contract plus independent review | Hints only; no work unit is accepted by this entrypoint |
| `code_navigation.py` | Navigate current Cargo packages, Rust files, logical blocks, and documentation routes (supported commands: `check`, `sync-index`, `package-docs-self-test`, `prototype-docs-self-test`, `self-test`, `list`, `route`) | Repository navigation and static path/dependency consistency only |
| `verify-standalone-crates.py` | Runs fmt, clippy and tests for every crate that declares its own `[workspace]` and is neither a workspace member nor an excluded capability cell | Package proof for crates no other gate reaches; admits nothing to the workspace |
| `verify-doc-code-conformance.py` | Public conformance front door for reader instructions, workflow claims, retired/nonexistent references, script/binary maps, owner bindings, and documentation-pipeline integrity | Static repository path/inventory/instruction consistency only |
| `verify-process-deadline-owner.py` | Source-shape discriminator for the #83 failure where a resumed process receives a start receipt while the wall-deadline owner thread is never spawned | Static source-shape evidence only; not Windows containment or wall-time proof |
| `doc_code_conformance_core.py` | Established deterministic DCC-001…DCC-007 implementation called by the public conformance front door | Internal conformance implementation |
| `audit-architecture-boundaries.py` | Detect forbidden dependencies, SurrealDB leakage, untracked direct process launch, placeholders, and exact tracked debt | Static source/build architecture evidence only |
| `verify-agent-guardrails.py` | Require bounded nearest-path owner/proof/stop instructions for declared source subtrees | Routing/control-plane evidence only |
| `verify-core-daemon-inventory.py` | Verify the core-daemon inventory identity, owner references, proof requirements, exclusions, and fixed proof ceiling | Static inventory/routing evidence only |
| `audit-runtime-source-hygiene.py` | Expose unsafe, panic/unwrap/expect, ambient configuration, unbounded-output, blocking-sleep, and source-concentration signals | Static source-quality evidence only |
| `verify-agent-bridge-protocol.py` | Reject raw canonical Frame ingress, host-minted authority fields, validation bypass, correlation loss, and mandatory cancellation prose | Static protocol/source-policy evidence only |
| `verify-wasm-toolchain.py` | Check the declared WASI component target without installing or executing external binaries | Offline toolchain declaration evidence only |
| `verify-workstream-routing.py` | Verify workstream routing, assignment boundaries, non-overlapping mutable scopes, and owner projections | Static workstream routing and control-plane evidence only |
| `verify-github-workflows.py` | Verify GitHub workflows, action SHA pinning, minimal permissions, hash-locked Python/NuGet dependencies (including the Operator harness lock), pip hash discipline, and test execution | Static workflow and dependency-input evidence only |
| `verify-agent-host-surfaces.py` | One manual verification entrypoint for all agent host surfaces (issue #250) | Manual source and fake-runtime integration evidence only |
| `verify-release-claim-boundary.py` | Verify the build-success claim boundary stays bound to source and build identity (issue #1855) | Static release-claim policy evidence only |
| `migration_inventory_1860.py` | Publish required migration inventory, dispositions, impact graph, and Product Proof plan (issue #1860) | Static migration inventory evidence only |
| `verify-dependency-policy.py` | Verify multi-ecosystem dependency admission, scanner tool pinning, inventory completeness, lockfiles, and advisory evidence | Static and advisory admission evidence only |
| `crate_reachability_inventory.py` | Generate deterministic support-neutral Cargo package reachability and source-shape inventory | Reachability and source-shape evidence only |
| `audit-work-unit-assignments.py` | Deterministic fail-closed assignment-integrity oracle over a frozen complete repository/GitHub snapshot (#818) | Assignment integrity oracle evidence only |
| `audit-serde-boundary-closure.py` | Serde-boundary closure coordinator (#710, Slice A) | Static source/boundary evidence only |
| `long_lived_collection_inventory.py` | Deterministic source-bound inventory of mutable collections in long-lived owners (#885) | Static source classification only |
| `serde_boundary_inventory.py` | Deterministic serialized-boundary inventory and finite repair allocations (#929, freezing the F-DENY denominator for #710) | Static source classification only |
| `wasm_component_lane.py` | Affected-component WASM build/test lane selector and evidence helper (#764) | Build/test lane selection only |
| `verify-legacy-config-retirement.py` | Verify legacy config filenames, modes, roots, and module manifests stay retired (#1219) | Static source and packaging evidence only |
| `context_measurement_inventory.py` | Deterministic source-bound inventory of serialized-context measurement cases with closed classification and frozen denominator (#866) | Static source classification only |
| `audit_cue_kind_retirement.py` | Cross-package `CueKind` retirement oracle library over the static source/wire/caller denominator (#835); exercised by `scripts/tests/test_cue_kind_retirement.py` | Static source denominator evidence only |
| `verify-excluded-dispositions-1811.py` | Fail-closed excluded/standalone disposition gate over standalone packages and root exclude entries with consumption evidence checks (#1811) | Static source and packaging evidence only |
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

The conformance policy introduced by issue #291 lives at
`config/doc-code-conformance.toml`; findings fail nonzero:

- `DCC-001` — verified-reader contract drift across instruction/generator surfaces;
- `DCC-002` — workflow documentation differs from actual trigger source;
- `DCC-003` — retired or unstable documentation authority references (rejects path-qualified and bare normative line numbers and ranges);
- `DCC-004` — maintained top-level script missing from this map;
- `DCC-005` — root Cargo `bins/*` composition package missing from `PROJECT_MAP`;
- `DCC-006` — stale current-owner/work reference;
- `DCC-007` — missing/wrong-case `docs/...` path or unknown normative handle;
- `DCC-010` — Markdown scan omits required generated/local exclusions;
- `DCC-011` — changed-path routing loses deletions;
- `DCC-012` — Markdown paths are not checked for exact case cross-platform;
- `DCC-013` — drive-qualified paths are accepted as repository-relative.

The conformance self-test and repository audit run from `just quick` and
`scripts/verify.ps1`; `scripts/verify.sh` delegates to the same PowerShell-owned
profile. Any finding fails the normal local verification path. The proof ceiling
for documentation/source conformance is static reference-shape consistency only;
a clean result proves no Architecture semantics, compilation, runtime behavior,
authority correctness, Product acceptance, or release support.

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
| `provision-surrealdb-release.py` | Materialize pinned SurrealDB evidence into project-local ignored state | Local evidence provision only |
| `build-eliot-windows-x64-release.ps1` | Build declared Windows x64 release inputs and an unsigned bundle | Build/staging only |
| `finalize-eliot-windows-x64-release.ps1` | Sign/finalize and independently read back declared release artifacts | Release-artifact evidence only |
| `write-operator-build-receipt.ps1` | Write the commit-bound Eliot.Operator build receipt consumed by `build-eliot-windows-x64-release.ps1` (#2391) | Operator build-input evidence only |
| `install-pipeline.ps1` | Root-controller install pipeline with an optional step-0 developer reset, then materialization and installation apply | Installation orchestration only |
| `invoke-eliot-windows-x64-production.ps1` | Execute the manifest-bound production invocation/installation flow | Live acceptance remains issue #11 |
| `reset-developer-install.ps1` | Return a developer machine to the "not installed" state for the `system_service` profile (issue #1375) | Developer machine reset only; not a product uninstall |

Read `docs/release/WINDOWS_X64_RELEASE.md` before use. The canonical operator
surface is `eliot.exe`; scripts do not create a parallel CLI or direct
storage/process authority.

### Developer reset (`install-pipeline.ps1 -Reset`, #1375)

`install-pipeline.ps1 -Reset` runs `reset-developer-install.ps1` as step 0 and
then exits 0, so the next normal install starts from a machine that is not
installed. `install-pipeline.ps1 -Reset -Install` resets and then continues into
step 4 and step 5. Both accept `-WhatIf`, which prints the exact same artifact
list and mutates nothing. The reset targets the same root the pipeline installs
into (`-Anchor`, default `C:\ProgramData`).

```powershell
# What the reset would find, without touching anything
.\scripts\install-pipeline.ps1 -Reset -WhatIf

# Return the machine to "not installed"
.\scripts\install-pipeline.ps1 -Reset
```

The reset removes exactly these machine-level artifacts, each read out of current
installation source rather than guessed:

| Artifact | Owner evidence | Action |
|---|---|---|
| `EliotHost`, `EliotWatchdog` services | `crates/foundation/eliot-runtime-contracts/src/installation_activation.rs::InstallationScmRole::service_name`, `bins/eliot-watchdog/src/lib.rs::SERVICE_NAME` | `sc.exe stop`, `sc.exe delete`, then wait until `sc.exe query` reports the service absent |
| EliotHost-to-EliotWatchdog service-object control grant | `crates/kernel/eliot-installation/src/scm_approval.rs` | Removed with the SCM service object by `sc.exe delete`; no separate ACL step exists |
| Any process whose image is under `<Anchor>\Eliot` | staged roles in `crates/kernel/eliot-installation/src/package_planner.rs::REQUIRED_PACKAGE_ROLES` and `bins/eliot/src/source_bundle_materializer.rs::REQUIRED_ROLES` | Terminated, selected by image path so no process outside the installation root is targeted |
| `<Anchor>\Eliot` installation root | `crates/kernel/eliot-installation/src/package_planner.rs` (`staging_root` must equal `profile_anchor_root\Eliot\packages`), `scripts/invoke-eliot-windows-x64-production.ps1::New-ProductionMaterializeContract` | Moved aside to `Eliot-reset-<UTC timestamp>`, never recursively deleted, so prior state stays inspectable |
| Credential Manager targets `eliot/installer-root/v1/*` | `crates/kernel/eliot-installation/src/transaction.rs::InstallationSecretReference::validate` | `cmdkey /delete` |

Deliberately never touched, with the reason:

- `%LOCALAPPDATA%\Eliot` — the owner's live legacy ELIOT data, not part of the
  `system_service` installation root.
- `eliot/store/v1/*` credentials — the legacy Store target namespace
  (`crates/kernel/eliot-installation/src/credential_provision.rs::validate_store_credential_target`).
- Windows registry — no installation code path creates a registry key. Services
  exist only as SCM objects (`crates/kernel/eliot-platform-windows/src/lib.rs::CreateServiceW`,
  `::ChangeServiceConfig2W`) and are removed by `sc.exe delete`; the only registry
  reads in the install path are the read-only Windows SDK kit-root lookups in
  `scripts/build-eliot-windows-x64-release.ps1`.
- Protected directories and file DACLs — they are created on paths inside the
  installation root and travel with the moved directory.
- Named pipes and the `EliotHost` Event Log source — kernel objects that vanish
  with the process, and `crates/kernel/eliot-platform-windows/src/event_log.rs::report_local_event`
  never registers an Event Log source.

The reset is idempotent: on a clean machine it finds nothing, prints
`RESET: nothing to reset (machine is clean)` and exits 0. If any artifact could
not be returned to the absent state, that artifact is reported and the reset exits
non-zero, so a partial reset is never mistaken for a clean machine. This is a
developer-machine reset only. It is not the product uninstall lifecycle (I3.13)
and it is not install rollback machinery for a broken first install (#1325 / T10,
deferred to the production phase by owner decision 2026-09-14).

## Integration packaging and probes

| Script | Purpose | Boundary |
|---|---|---|
| `build-claude-desktop-extension.ps1` | Build the Claude Desktop extension package from repository sources | Package construction only |
| `test-claude-connector.ps1` | Run the bounded Claude connector probe/fixture path | Exact integration-fingerprint evidence only |
| `eliot-mcp-reference-client.ps1` | Reference MCP client for protocol/bridge diagnostics | Diagnostic/client evidence only |
| `run-isolated-tests.ps1` | Provision an owned Windows/Surreal test namespace and run one selected package/test profile | Exact selected Module/Edge evidence only |
| `scripts/integration/ignored_test_inventory.py` | Derive the exact ignored-test denominator and environment classification (#905) | Ignored-test identity and environment classification only |

The ignored-test inventory entrypoint (`scripts/integration/ignored_test_inventory.py`)
derives the exact bounded denominator of ignored Rust tests across workspace packages,
reconciling admitted test sources with compiled libtest listings, and classifying each
item against required environments (Store, Runtime, Git, External credentials). Its
proof ceiling is `IGNORED_TEST_IDENTITY_AND_ENVIRONMENT_CLASSIFICATION_ONLY`; it performs
no test execution, provisions no background state, and touches no credentials.

Run its internal self-tests locally:

```powershell
python scripts/integration/ignored_test_inventory.py --self-test
```

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
