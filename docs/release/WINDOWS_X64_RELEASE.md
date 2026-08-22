# Windows x64 Release

`scripts/build-eliot-windows-x64-release.ps1` stages an intentionally unsigned bundle containing the release governor, six Cargo runtime executables (`eliot.exe`, `eliot-host.exe`, `eliot-watchdog.exe`, `eliot-kernel.exe`, `eliot-store-surreal.exe`, and `eliotd.exe`), a caller-pinned canonical `surreal.exe`, required Eliot.Operator publish output, config templates, canonical host integration packages, shared skills, migrations, and operations/release runbooks. The canary materializer admits exactly six runtime roles: `runtime/eliot-host.exe`, `runtime/eliot-watchdog.exe`, `runtime/eliot-kernel.exe`, `runtime/eliot-store-surreal.exe`, `runtime/surreal.exe`, and `runtime/eliotd.exe`. The shipped `runtime/eliot.exe` is an additional install-authoritative CLI trust role signed by the same finalizer; Governor and Eliot.Operator payload remain outside this exact signing scope. The tracked `docs/release/SURREALDB_WINDOWS_X64.lock.json` record binds the canonical external binary to version `3.1.4`, Windows x64 PE machine `8664`, and SHA-256 `13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1`. `runtime/RUNTIME_ARTIFACTS.json` is a verified build-artifact input: it records the pinned source commit and catalog SHA-256, exact source kind, version, and Windows x64 architecture for each Cargo target and for the externally supplied database binary. It explicitly carries `installation_approval: not-issued` and `signature_evidence: not-issued`; it is not a signed `CandidateManifest` and does not perform installation, SCM registration, or activation. Host plugins live under their owning `integrations/<host>` tree; the bundle does not create a second top-level plugin copy. The Codex surface is a self-contained local marketplace at `integrations/codex/marketplace.json` with its plugin at `integrations/codex/plugins/eliot-governor` and the release Governor copied into that plugin's `bin` directory. Its default output root is `%LOCALAPPDATA%\Eliot\packages`; `-OutputRoot` accepts an explicit absolute path or a repository-relative override.

Use `-PlanOnly` to inspect paths and contents without building or writing a bundle. Every real staging run requires `-OperatorSource <published-directory>` containing `Eliot.Operator.exe`; the script refuses a Governor-only package and refuses to overwrite an existing versioned bundle.

The Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`. Its sole MCP server is `eliot`, resolves `bin/eliot-governor.exe` relative to the plugin root, and starts the `codex_controller` profile for every project. The plugin command deliberately omits `--host`; live session binding remains the authority for host identity. Codex discovers `hooks/hooks.json` by convention, so the plugin manifest does not carry the unsupported `hooks` field.

The tracked and released `plugin.json` is cache-neutral: its version is the base SemVer, currently `0.1.0`, with no `+codex` build metadata. `PlanOnly` reports this as `codex_plugin_base_version`, and `RELEASE.json` records the same value. The installer must not rewrite either source or release payload. It materializes only its ELIOT-owned personal-plugin copy as `<base-version>+codex.<deterministic-content-token>` before invoking the Codex plugin lifecycle. The token is stable for the complete Codex cache contract and changes when the bundled Governor, MCP, hooks, skills, or plugin metadata change. Codex executes the SHA-256-verified Governor inside that immutable cache, so a binary-only update receives a new add-only version. A timestamp-only token is reserved for manual local-development iteration.

```powershell
$operatorPublish = Join-Path $env:LOCALAPPDATA 'Eliot\build\operator-publish'
$releaseRoot = Join-Path $env:LOCALAPPDATA 'Eliot\packages'
dotnet publish apps/Eliot.Operator/Eliot.Operator.csproj -c Release -r win-x64 `
  --self-contained false -o $operatorPublish
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build-eliot-windows-x64-release.ps1 `
  -Version 0.1.0-rc1 -OutputRoot $releaseRoot -OperatorSource $operatorPublish `
  -SurrealExe C:\Tools\SurrealDB\surreal.exe `
  -SurrealVersion 3.1.4 `
  -SurrealSha256 <caller-supplied-64-hex-digest>
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

Staging requires a clean tracked source tree. Repository resources are enumerated from the pinned commit tree, and each file is filter-hashed against that commit both before and after copying; staged deletions, ignored, untracked, dirty-tracked, or concurrently changed content cannot enter the bundle under a false source attestation. Real staging always rebuilds the Governor and every declared runtime package/bin target from the unchanged pinned tree; `-SkipBuild` is rejected. Before copying, the script validates all six package/bin names against `cargo metadata --format-version 1 --no-deps`, builds each explicitly with `--locked --offline`, and fails closed if any exact release executable is absent or not a Windows x64 PE. `SurrealExe` must be an explicit absolute path naming `surreal.exe`; the script never resolves it through PATH or an environment fallback, rejects reparse paths, requires the caller-supplied SHA-256/version pins to match the tracked lock record, and verifies the file bytes and PE machine statically without launching the payload. The resolved verified absolute path is the only copy source. No dependency download is permitted during packaging. The Governor and runtime executables are admitted only from the release directory reported by `cargo metadata`, which is normally outside OneDrive; Operator publish output is restricted to its runtime extension allowlist and excludes PDBs. A pinned OneDrive source file is accepted only when it is resident and exposes neither a link target nor offline/unpinned/recall attributes. Every copied bundle entry must still be a regular non-reparse file. Secret-like filenames, private-key/provider/AWS/JWT signatures, Basic authorization, and credential assignments in text payloads are rejected before checksum generation and again during verification. Run `tests/release-security/run-tests.ps1` for the provider-free negative smoke.

`RELEASE.json` pins the exact Git source commit, the cache-neutral `codex_plugin_base_version`, the complete runtime artifact list (filename, source kind, digest, version, and architecture), the caller-pinned SurrealDB identity, and the Operator schema/protocol/hash. The staged form marks the bundle unsigned, records `signature_evidence: not-issued`, and keeps it unavailable for distribution. `SHA256SUMS.json` repeats the source commit and inventories every staged file with SHA-256 and byte length; verification also recomputes every entry in `runtime/RUNTIME_ARTIFACTS.json` and rejects a missing, substituted, extra, non-x64, version-drifting, or changed runtime executable. It otherwise rejects a source-binding mismatch, missing file, changed file, duplicate/unsafe path, unmanifested payload, secret-scan finding, malformed Codex marketplace/plugin metadata, a release plugin version containing `+codex` metadata or differing from `RELEASE.json`, a non-controller MCP profile, or a plugin binary whose hash differs from the root Governor. A completed signing pass writes exact `signed=true`, `signature_policy=authenticode-rfc3161`, `signed_scope=runtime-materializer-six-plus-cli-pe-roles`, and identical structured signature evidence into `RELEASE.json`, `runtime/RUNTIME_ARTIFACTS.json`, and `SHA256SUMS.json`, plus `SIGNING_VERIFIED.json`; the old `SIGNING_REQUIRED.txt` marker is removed. Those fields remain evidence rather than publication authority. No unsigned manifest can masquerade as signed, and the Rust source-bundle materializer remains the independent WinTrust `AuthenticodeVerdict::Valid` gate for all six runtime roles and the first authoritative nine-role handoff. Run both `tests/release-security/run-tests.ps1` and `tests/release-security/finalize-signing-tests.ps1` for provider-free negative coverage.

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
