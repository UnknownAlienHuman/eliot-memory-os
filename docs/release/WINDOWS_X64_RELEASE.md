# Windows x64 Release

`scripts/build-eliot-windows-x64-release.ps1` stages an intentionally unsigned bundle containing the release governor while the legacy `crates/eliot-app` crate is a workspace member (plus `eliot-agent-bridge.exe` at the bundle root when `-ClaudeCodeFrontDoor agent-bridge` is selected for the flagged Claude Code front door, issue #1719), six Cargo runtime executables (`eliot.exe`, `eliot-host.exe`, `eliot-watchdog.exe`, `eliot-kernel.exe`, `eliot-store-surreal.exe`, and `eliotd.exe`), a caller-pinned canonical `surreal.exe`, required Eliot.Operator publish output, config templates, canonical host integration packages, shared skills, migrations, and operations/release runbooks. The canary materializer admits exactly six runtime roles: `runtime/eliot-host.exe`, `runtime/eliot-watchdog.exe`, `runtime/eliot-kernel.exe`, `runtime/eliot-store-surreal.exe`, `runtime/surreal.exe`, and `runtime/eliotd.exe`. The shipped `runtime/eliot.exe` is an additional install-authoritative CLI trust role signed by the same finalizer; Governor and Eliot.Operator payload remain outside this exact signing scope. The tracked `docs/release/SURREALDB_WINDOWS_X64.lock.json` record binds the canonical external binary to version `3.1.4`, Windows x64 PE machine `8664`, and SHA-256 `13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1`. `runtime/RUNTIME_ARTIFACTS.json` is a verified build-artifact input: it records the pinned source commit and catalog SHA-256, exact source kind, version, and Windows x64 architecture for each Cargo target and for the externally supplied database binary. It explicitly carries `installation_approval: not-issued` and `signature_evidence: not-issued`; it is not a signed `CandidateManifest` and does not perform installation, SCM registration, or activation. Host plugins live under their owning `integrations/<host>` tree; the bundle does not create a second top-level plugin copy. While the legacy crate is present, the Codex surface is a self-contained local marketplace at `integrations/codex/marketplace.json` with its plugin at `integrations/codex/plugins/eliot-governor` and the release Governor copied into that plugin's `bin` directory. The marketplace and plugin subtree leave the release together with the governor binary only under an owner-proven retirement (issue #2892): an accepted #18 retirement receipt must verify for the exact release source commit with the complete consumer denominator, or the plan/stage aborts — source absence alone, and any flag or malformed Cargo metadata, never retires anything. A receipt-admitted retired release carries no Codex marketplace or plugin subtree, so no shipped plugin ever names a missing command (governor disposition `retired`; see the Claude Code front door paragraph below). Its default output root is `%LOCALAPPDATA%\Eliot\packages`; `-OutputRoot` accepts an explicit absolute path or a repository-relative override.

The catalog keeps the installed `3.1.4` observation separate from the project-local patched candidate. `patched_candidate` binds the official `3.2.0` Windows x64 artifact and its source/advisory evidence. A real staging run with `-UseProjectLocalSurreal` invokes `scripts/provision-surrealdb-release.py`, consumes `.eliot/dependency-policy/surrealdb/v3.2.0/surreal-v3.2.0.windows-amd64.exe`, and copies that verified byte set to `runtime/surreal.exe`; it never changes the shared `C:\Tools\SurrealDB` installation.

After the Windows release build, the builder refreshes the candidate's exact-version OSV response and consumes `.eliot/dependency-policy/surrealdb/v3.2.0/selected-release-policy-receipt.json`. The unsigned bundle carries `runtime/SURREALDB_RELEASE_POLICY_RECEIPT.json`, `runtime/SURREALDB_RELEASE_OSV_QUERY.json`, and `runtime/SURREALDB_RELEASE_OSV_RESPONSE.json`; `-VerifyBundle` rechecks their hashes and joins against the selected artifact, release catalogue, and staged provisioner receipt. The receipt leaves `release_admission` as `INCOMPLETE` while applicability of crates.io advisory records to the distributed binary remains unestablished. The installed `3.1.4` advisory findings remain part of the separate `current-advisories` result.

Use `-PlanOnly` to inspect paths and contents without building or writing a bundle. For a builder-owned Operator build, pass `-BuildOperator`: the release builder runs the pinned WinUI project through locked `dotnet publish`, and the project's `AfterTargets=Publish` target writes `OPERATOR_BUILD_RECEIPT.json` from the successful publish inputs and actual output files. The builder consumes that same invocation-bound receipt when staging and independently verifies its source, tool, protocol, executable, and publish-file hashes. Alternatively, `-OperatorSource <published-directory>` accepts only a directory carrying the same source-bound receipt. The script refuses a Governor-only package and refuses to overwrite an existing versioned bundle.

While the legacy crate is present, the Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`. Its sole MCP server is `eliot`, resolves `bin/eliot-governor.exe` relative to the plugin root, and starts the `codex_controller` profile for every project. This contract holds only in the retained governor disposition; a receipt-admitted retired release carries no Codex marketplace or plugin subtree. The plugin command deliberately omits `--host`; live session binding remains the authority for host identity. Codex discovers `hooks/hooks.json` by convention, so the plugin manifest does not carry the unsupported `hooks` field.

The tracked `plugin.json` (shipped while the legacy crate is present) is cache-neutral: its version is the base SemVer, currently `0.1.0`, with no `+codex` build metadata. `PlanOnly` reports this as `codex_plugin_base_version`, and `RELEASE.json` records the same value. The installer must not rewrite either source or release payload. It materializes only its ELIOT-owned personal-plugin copy as `<base-version>+codex.<deterministic-content-token>` before invoking the Codex plugin lifecycle. The token is stable for the complete Codex cache contract and changes when the bundled Governor, MCP, hooks, skills, or plugin metadata change. Codex executes the SHA-256-verified Governor inside that immutable cache, so a binary-only update receives a new add-only version. A timestamp-only token is reserved for manual local-development iteration.

Claude Code front door (issue #1719, OSP1 step 1'): exactly one host moves off the legacy Governor MCP entry behind an explicit flag; Codex, OpenCode, and Claude Desktop keep their `eliot-governor` entries while the flag is absent, and every legacy entrypoint (`daemon run`, `service run`, `hook`, `mcp stdio`) on every host refuses with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the canonical-route receipt once `ELIOT_CLAUDE_FRONT_DOOR=agent-bridge` selects the new stack (entrypoint gating owned by the #1858 track). The bundle switch `-ClaudeCodeFrontDoor legacy|agent-bridge` (retained-source default `legacy`) provisions the selected command: `legacy` stages today's set unchanged, while `agent-bridge` additionally builds `bins/eliot-agent-bridge` (`cargo --frozen -p eliot-agent-bridge --bin eliot-agent-bridge`) and stages `eliot-agent-bridge.exe` at the bundle root next to `eliot-governor.exe` with the same provenance gates (Cargo metadata, Windows x64 PE, secret scan, SHA-256). `PlanOnly` reports the selection as `claude_code_front_door` (selection, operator flag `ELIOT_CLAUDE_FRONT_DOOR`, legacy availability/command/argv, bridge argv, provisioned path, other-hosts disposition) alongside the top-level `governor`/`governor_disposition` and the disposition-conditioned `includes`, `RELEASE.json` binds the staged bridge digest, and verification requires the bridge file, digest, and PE identity exactly when `agent-bridge` is selected — and requires its absence when `legacy` is selected — so a bundle never ships a flagged command that does not exist. The bridge runs `eliot-agent-bridge mcp --profile SPINE_FUNCTIONAL --transport stdio --client-declaration <installation-absolute>/agent-bridge/client-declaration-v2.json` (the leading `mcp` token selects the MCP JSON-RPC front door per the #2562 entrypoint contract; the tokenless argv keeps serving the private `op` stdio clients); the declaration file itself stays installation-owned and is never invented by the bundle. The operator launch flag `ELIOT_CLAUDE_FRONT_DOOR=agent-bridge` (unset means legacy) is consumed by entrypoint gating (owned by #1858) and Claude MCP bridge delegation (owned by #2562 with the #1858/#77 track); this bundle slice only guarantees the selected command exists. The staged bridge remains outside the Authenticode signing scope like the Governor and fails closed in the finalizer denominator until an explicit signed role lands. Retention disposition: `eliot-governor.exe`, the `governor-gated-legacy` include, and the Codex plugin bundled binary stay (recorded in `STAGED_PAYLOAD_MANIFEST.json` under the `#1189-legacy-retirement` gate as retained explicitly by #1719) because Codex, OpenCode, Claude Desktop, and the default (flag-absent) Claude Code path still execute that entry point. Governor disposition (issue #1719 decision record `retire-decision`, for the PR body): Work option 1 — retire the governor artifact — is implemented conditionally. While `crates/eliot-app` is a workspace member, the disposition is `retained-legacy-entrypoint` and an omitted `-ClaudeCodeFrontDoor` keeps the `legacy` default; retirement is owner-proven (issue #2892), never presence-driven: the typed resolver returns `Retained`, `RetirementCandidate`, `Retired`, or `MalformedOrAmbiguous`, and only an accepted #18 receipt that verifies for the exact source commit with the complete consumer denominator selects `Retired` (no governor build, no `governor-gated-legacy` include, and the Codex marketplace/plugin subtree leaves the release together with the binary). Missing/duplicated package, missing target, metadata failure, unexpected shape, and source absence without a verified receipt abort explicitly; no ambient switch exists. The receipt-admitted retired plan carries an explicit `retired` `governor_disposition` bound to the receipt digest (the plan, `STAGED_PAYLOAD_MANIFEST.json`, `RELEASE.json`, and `SHA256SUMS.json` carry the same evidence identity, and the verifier recomputes it from the pinned commit instead of trusting the builder string), omits the legacy Claude include (emitting `claude-frontdoor-retired`), and records the receipt-admitted per-consumer replacement or explicit product-removal decision (no `eliot setup` substitution is claimed without owning Product contract proof; a missing replacement stays blocked/partial). Under accepted receipt-admitted retirement, omitting `-ClaudeCodeFrontDoor` selects `agent-bridge` and makes the layout stageable; the `-PlanRetiredGovernor` simulation also selects `agent-bridge` when omitted, solely for its rendered layout. An explicit `legacy` selection for either retired layout fails before `-PlanOnly` emits a plan or staging begins. The simulation remains visibly `SIMULATED_NOT_ADMITTED` and cannot stage, verify, sign, or publish. Installer and runtime role requirements stay separate: what the installer's `BUNDLE_BINARIES`/`REQUIRED_ROLES` need does not decide what the shipped host integrations need, so retirement requires the complete consumer denominator with a per-consumer admitted replacement or explicit removal decision — an installer-only argument never retires a runtime host surface. Re-home (Work option 2) is not implemented here and is refused: the `codex_controller` profile is implemented only under the legacy `crates/eliot-app/src/mcp_stdio.rs` (with its submodules) — zero implementers exist in `bins/`, in `crates/surfaces/eliot-mcp`, or anywhere else — so no current-owner entry point exists, and the behavior home is the `eliot-mcp` track per canon. Per I19.1 (no deletion before data/behavior owner and replacement proof) nothing is deleted in this slice; the legacy deletion itself stays owned by #18. Proof sketch without deletion: `-PlanRetiredGovernor` with `-PlanOnly` renders the retired layout for inspection only; it writes no bundle, alters no release artifacts/receipts/verification inputs, is never selected from ambient environment, and cannot stage, verify, sign, or publish. The actual post-deletion bundle proof required by A1 remains pending; the simulation is not that proof. Already-generated self-declared retired plans/bundles are simulated/unadmitted, must be rebuilt from an accepted receipt, and are never grandfathered.

```powershell
$releaseRoot = Join-Path $env:LOCALAPPDATA 'Eliot\packages'
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build-eliot-windows-x64-release.ps1 `
  -Version 0.1.0-rc1 -OutputRoot $releaseRoot -BuildOperator `
  -UseProjectLocalSurreal
```

Verify an existing staged bundle without rebuilding or changing it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build-eliot-windows-x64-release.ps1 `
  -VerifyBundle (Join-Path $releaseRoot 'eliot-windows-x64-0.1.0-rc1-unsigned')
```

Finalize one verified runtime-canary bundle without rebuilding, installing, or
registering services. Every value below is explicit: the SignTool path, the
certificate store and exact thumbprint, and the approved RFC3161 endpoint. The
certificate must have `HasPrivateKey=true` and the Code Signing EKU. The
finalizer signs the six materializer roles plus the install-authoritative
`runtime/eliot.exe` CLI trust role, requests SHA-256 file and
timestamp digests, performs independent `Get-AuthenticodeSignature`/WinTrust
readback plus exact-exit-zero `signtool verify /pa /all /v /tw` for every role,
and parses the embedded RFC3161 CMS token. The token must use the Microsoft
RFC3161 unauthenticated attribute, carry a SHA-256 TSTInfo messageImprint over
the Authenticode SignerInfo signature, have a valid CMS signature, and name the
same timestamp certificate returned by WinTrust. The finalizer recomputes all
file sizes and SHA-256 values and publishes a new create-only directory through
its retained native staging handle. Drive-relative and root-relative paths are
rejected; all filesystem inputs must be drive-rooted or exact UNC paths.

```powershell
$unsignedBundle = Join-Path $releaseRoot 'eliot-windows-x64-0.1.0-rc1-unsigned'
$signedBundle = Join-Path $releaseRoot 'eliot-windows-x64-0.1.0-rc1'
$signTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'
$signerThumbprint = '<exact-40-hex-thumbprint>'

& powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/finalize-eliot-windows-x64-release.ps1 `
  -UnsignedBundle $unsignedBundle `
  -SignedBundle $signedBundle `
  -SignToolPath $signTool `
  -CertificateStoreLocation 'Cert:\CurrentUser\My' `
  -CertificateThumbprint $signerThumbprint `
  -TimestampUrl 'http://timestamp.digicert.com'
if ($LASTEXITCODE -ne 75) {
  throw "finalizer did not return the mandatory reconciliation exit 75: $LASTEXITCODE"
}
```

A directory commit is deliberately never a success terminal. Even when the
immediate post-move signature, manifest, hash, identity, and flush readback is
green, the finalizer emits `COMMITTED_UNKNOWN` with reason
`MUTABLE_DIRECTORY_REQUIRES_CONSUMER_RECONCILIATION` and exits 75. The output
directory is retained and must not be deleted, retried into, adopted, or treated
as distribution/install authority.

After exit 75, `-VerifyBundle` remains available for read-only diagnostics
against the unchanged unsigned source and committed destination. It resolves
the exact public Code Signing certificate, thumbprint, and EKU but does not
require its private key:

```powershell
& powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/finalize-eliot-windows-x64-release.ps1 `
  -UnsignedBundle $unsignedBundle `
  -VerifyBundle $signedBundle `
  -SignToolPath $signTool `
  -CertificateStoreLocation 'Cert:\CurrentUser\My' `
  -CertificateThumbprint $signerThumbprint `
  -TimestampUrl 'http://timestamp.digicert.com'
if ($LASTEXITCODE -ne 0) { throw 'signed-bundle snapshot verification failed' }
```

`-VerifyBundle` alone is only a point-in-time snapshot and cannot authorize a
later path-based CLI launch. The canonical production launcher derives only
`runtime/eliot.exe` from `SignedBundle`, retains no-follow bundle/runtime/file
handles that deny write and delete, reruns the seven-role public verification,
creates that exact CLI suspended, binds the process image path, start time,
volume/file identity, bytes, SHA-256, signer, Code Signing EKU and RFC3161
evidence, then resumes while every fence remains live through child completion.
There is no caller-supplied executable or unsigned compatibility path. Set
every variable below to its reviewed absolute/canonical value:

```powershell
$productionLauncher = Join-Path $repo 'scripts\invoke-eliot-windows-x64-production.ps1'
& $productionLauncher `
  -UnsignedBundle $unsignedBundle `
  -SignedBundle $signedBundle `
  -SignToolPath $signTool `
  -CertificateStoreLocation 'Cert:\CurrentUser\My' `
  -CertificateThumbprint $signerThumbprint `
  -TimestampUrl 'http://timestamp.digicert.com' `
  -OutputBundle $phaseABundle `
  -Output $transactionPlan `
  -Store $transactionStore `
  -Generation $generation `
  -Installation $installation `
  -LineageId $lineageId `
  -Sequence $sequence `
  -TransactionId $transactionId `
  -StagingRoot $phaseAStagingRoot `
  -MinimumStoreAvailableBytes $minimumStoreAvailableBytes `
  -RecoveryCommand $recoveryCommand `
  -Profile system_service `
  -ProfileAnchorRoot $profileAnchorRoot `
  -InstallationKey $installationKey
if ($LASTEXITCODE -ne 0) { throw 'authoritative source-bundle materialization failed or requires reconciliation' }
```

For profiled installs (`-Profile system_service` or `-Profile user_mode`),
`-StagingRoot` must be exactly
`<ProfileAnchorRoot>\Eliot\packages`. The launcher retains and validates the
existing profile anchor and rejects noncanonical or reparse-point paths, but it
does not require, create, repair, or adopt the future `packages` directory when
it is absent. Durable installer `CreateRoot`/`ApplyAcl`/`StagePackage` owns that
creation and protected-root binding. An already-provisioned staging root is
still pinned and read back; `portable_dev` retains its existing requirement for
an already-existing staging directory.

That Rust materializer independently rechecks the exact six PE Authenticode and
hash contracts and atomically publishes the exact nine-role Phase-A bundle. Its
`SOURCE_BUNDLE_MATERIALIZED` result is the first authoritative handoff; neither
the finalizer's exit 75 nor standalone `-VerifyBundle` can substitute for that
child result. The launcher itself reports success only after capturing the
exact ordered `GENERATED` then `SOURCE_BUNDLE_MATERIALIZED` JSON objects and
reopening the create-new transaction output, Store, bundle identity, and all
nine published roles against the final receipt.

The finalizer accepts only an explicit absolute HTTP(S) RFC3161 URL because
the installed SignTool/provider determines which approved endpoint is valid;
cryptographic timestamp readback is mandatory, so a URL that does not produce
a timestamp cannot finalize a bundle. `-PlanOnly` validates the explicit
signing contract without touching the input. `-VerifyBundle` independently
rechecks the signed manifests, exact signer/timestamp evidence, all sizes and
hashes, and all seven signing-role signatures (the six materializer roles plus
the CLI trust role). Verification requires the unsigned source
bundle and the same external SignTool/store/thumbprint/timestamp policy; signed
JSON is never allowed to attest its own signer policy. Signing requires the
exact certificate's private key and real X509 Code Signing EKU; verification
requires the exact public certificate, thumbprint, and EKU but correctly does
not require the verifier to possess the private key. Its result is explicitly a
read-only snapshot and carries no durable installation authority. The
production launcher closes the snapshot-to-process gap by retaining the exact
CLI and directory identities before invoking this verifier and through the
complete child lifetime.

Staging is allocated with one relative `NtCreateFile(FILE_CREATE |
FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT)` operation under a retained
no-follow destination-parent handle. That operation returns the newly created
root ownership handle; there is no create-then-open adoption gap. Every child
directory and file is likewise created create-new relative to its retained
parent handle. Child directory identities remain fenced through the complete
pre-commit validation. After manifest finalization, every inventory file is
also opened no-follow with neither write nor delete sharing and bound to its exact relative
path, single-link native identity, SHA-256, and size; reparse and hardlinked
files are rejected. Windows does not permit an ancestor
directory rename while descendant handles remain open, so those child and file
handles are released only at the commit boundary; the staging-root,
unsigned-source, and publication-parent handles remain retained. Publication uses
direct `NtSetInformationFile(FileRenameInformation=10)` on the staging-root
handle with `ReplaceIfExists=FALSE`, the retained parent handle in
`RootDirectory`, and exactly one relative destination leaf. The destination
therefore cannot be process-path-resolved, adopted, or replaced. Immediately after publication every file is reacquired no-follow with
neither write nor delete sharing and must match the pre-commit identity/hash/size. Those handles
remain retained across the path-based verifier and are rehashed directly before
the terminal readback; the exact full inventory is also read back again to reject
observed late additions. These checks can reject a mutation observed during the
immediate readback, but a mutable Windows directory namespace cannot be frozen
through a consumer handoff. Consequently the finalizer has no success terminal.

The exact source inventory is read back after copy and before commit. Only the
seven PE certificate-table changes (six materializer roles plus the CLI trust
role), the three manifest rewrites, and the exact
`SIGNING_REQUIRED.txt` to `SIGNING_VERIFIED.json` marker transition are allowed;
all non-role paths, hashes, and sizes remain byte-identical. Each PE normalized
image prefix must also remain identical after excluding only the checksum and
certificate-directory fields and the appended aligned WIN_CERTIFICATE table.
The staging owner marker is retained from its atomic creation and removed with
`FileDispositionInfoEx` on that exact handle, never by pathname. Pre-commit
failures quarantine the partial directory with its token; the
finalizer never performs recursive pathname cleanup, because closing an
identity fence before deletion would reintroduce a substitution window. After
the handle-bound move, the destination is reopened no-follow and the complete
verifier runs again while its root identity remains pinned. Any post-commit
path, directory-contour identity, signature, manifest, or checksum uncertainty
returns `COMMITTED_UNKNOWN`; the CLI emits that typed JSON and exits 75, never
zero. A completely green immediate readback also returns `COMMITTED_UNKNOWN`
with the normal mutable-directory reconciliation reason. The finalizer never
deletes or adopts the committed destination and never reports
`SIGNED_PUBLISHED`.

Staging requires a clean tracked source tree. Repository resources are enumerated from the pinned commit tree, and each file is filter-hashed against that commit both before and after copying; staged deletions, ignored, untracked, dirty-tracked, or concurrently changed content cannot enter the bundle under a false source attestation. Real staging always rebuilds every declared runtime package/bin target from the unchanged pinned tree — plus the Governor while the legacy crate is present (retired disposition: the governor build, the gated-legacy include, and the Codex plugin subtree are omitted together instead of failing); `-SkipBuild` is rejected. Before copying, the script validates all six package/bin names against `cargo metadata --format-version 1 --no-deps`, builds each explicitly with `--locked --offline`, and fails closed if any exact release executable is absent or not a Windows x64 PE. `-UseProjectLocalSurreal` invokes the project-local provisioner, requires its receipt to state `shared_installation_touched=false`, verifies the locked artifact bytes, size, PE machine, catalog candidate, and receipt digest, then consumes only the project-local artifact path and copies it to `runtime/surreal.exe`. The legacy `SurrealExe` mode remains an explicit absolute-path compatibility input for the separately observed installation; it never resolves through PATH or an environment fallback and still rejects reparse paths. No dependency download is permitted during Cargo packaging; the project-local provisioner performs only its own pinned evidence materialization. The Governor and runtime executables are admitted only from the release directory reported by `cargo metadata`, which is normally outside OneDrive; Operator publish output is restricted to its runtime extension allowlist and excludes PDBs. A pinned OneDrive source file is accepted only when it is resident and exposes neither a link target nor offline/unpinned/recall attributes. Every copied bundle entry must still be a regular non-reparse file. Secret-like filenames, private-key/provider/AWS/JWT signatures, Basic authorization, and credential assignments in text payloads are rejected before checksum generation and again during verification. Run `tests/release-security/run-tests.ps1` for the provider-free negative smoke.

`RELEASE.json` pins the exact Git source commit, the cache-neutral `codex_plugin_base_version`, the complete runtime artifact list (filename, source kind, digest, version, and architecture), the consumed SurrealDB identity plus project-local provisioning receipt when `-UseProjectLocalSurreal` is selected, and the Operator schema/protocol/hash. The staged form marks the bundle unsigned, records `signature_evidence: not-issued`, and keeps it unavailable for distribution. `SHA256SUMS.json` repeats the source commit and inventories every staged file with SHA-256 and byte length; verification also recomputes every entry in `runtime/RUNTIME_ARTIFACTS.json` and rejects a missing, substituted, extra, non-x64, version-drifting, or changed runtime executable. It otherwise rejects a source-binding mismatch, missing file, changed file, duplicate/unsafe path, unmanifested payload, secret-scan finding, malformed Codex marketplace/plugin metadata, a release plugin version containing `+codex` metadata or differing from `RELEASE.json`, a non-controller MCP profile, or (retained disposition only) a plugin binary whose hash differs from the root Governor. A retired bundle must instead contain neither the governor executable nor the Codex plugin subtree. A completed signing pass writes exact `signed=true`, `signature_policy=authenticode-rfc3161`, `signed_scope=runtime-materializer-six-plus-cli-pe-roles`, and identical structured signature evidence into `RELEASE.json`, `runtime/RUNTIME_ARTIFACTS.json`, and `SHA256SUMS.json`, plus `SIGNING_VERIFIED.json`; the old `SIGNING_REQUIRED.txt` marker is removed. Those fields remain evidence rather than publication authority. No unsigned manifest can masquerade as signed, and the Rust source-bundle materializer remains the independent WinTrust `AuthenticodeVerdict::Valid` gate for all six runtime roles and the first authoritative nine-role handoff. Run both `tests/release-security/run-tests.ps1` and `tests/release-security/finalize-signing-tests.ps1` for provider-free negative coverage.

The provider-free process-bound launcher suite
`tests/release-security/trusted-cli-launch-tests.ps1` covers the static and
negative boundaries without live signing or installation. It proves that the
shipped script rejects dot-source, has no raw argument/verifier/hook surface,
derives all six Phase-A executable paths from one retained signed bundle, and
rejects mixed roles, `--help` false zero, and missing or substituted final
receipts. It does not claim a standalone shipped success path: deterministic
CI cannot produce public-trust/RFC3161 evidence without a signing provider.

The explicit machine gate
`tests/release-security/trusted-cli-live-signing-tests.ps1` supplies that proof
when a real Code Signing certificate/private key, public trust, `signtool.exe`,
and RFC3161 URL are available. It builds an x64 protocol fixture, invokes the
unchanged finalizer and its public `-VerifyBundle` path, then invokes the
unchanged production launcher through its real suspended-child contour and
requires exact `GENERATED` then `SOURCE_BUNDLE_MATERIALIZED`, Store/output and
ordered nine-role readback. It also rejects signed-role and CLI substitution.
The gate is opt-in and temp-root-only; it never installs the product, changes
SCM, requests UAC, or writes `ProgramData`/`.eliot`. Run it once under
PowerShell 7 and once under Windows PowerShell 5.1 with explicit
`-SignToolPath`, `-CertificateThumbprint`, `-CertificateStoreLocation`, and
`-TimestampUrl` values, plus `-SurrealExePath` bound to the source-pinned
SurrealDB release binary.

Upgrade is backup-gated: take and verify a fresh logical backup, complete the isolated restore/MCP drill, generate the production cutover manifest, and preserve the prior signed bundle, service command, config, and data root until the new release passes doctor and Operator smoke. Roll back with the exact commands in the reviewed cutover manifest; never delete either data root during the cutover window.
