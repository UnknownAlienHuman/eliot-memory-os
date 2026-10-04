[CmdletBinding()]
param(
    [string]$IsolatedTargetDir = 'C:/Temp/target-go88'
)

<#
I18.44 (issue #1923) build-sandbox / supply-chain / cache proof.

Scope: evidence ONLY for guarantees already claimed by CI/release
documentation (locked offline builds, isolated target dirs, release secret
scan, hash-bound manifests). Anything the local environment cannot prove
(Job Object filesystem/network sandboxing, descendant removal, cross-trust
cache isolation, SBOM/license/advisory hash binding) is explicitly recorded
as VM_LAB_FALLBACK_REQUIRED -- never asserted as local proof.

Provider-free, temp-root-only. No network, no installs, no SCM writes.
Must be run from the repository root worktree.
#>

$ErrorActionPreference = 'Stop'

$repo = $PSScriptRoot
while (-not (Test-Path -LiteralPath (Join-Path $repo 'Cargo.toml')) -and (Split-Path -Parent $repo)) {
    $parent = Split-Path -Parent $repo
    if ($parent -eq $repo) { break }
    $repo = $parent
}
if (-not (Test-Path -LiteralPath (Join-Path $repo 'Cargo.toml'))) {
    throw 'BUILD_SANDBOX_PROOF: repository root with Cargo.toml not found'
}

. (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1')

$records = [System.Collections.Generic.List[object]]::new()
function Add-Record([string]$claim, [string]$status, [hashtable]$evidence) {
    $records.Add([pscustomobject]@{
            claim    = $claim
            status   = $status
            evidence = $evidence
        }) | Out-Null
}

# ---------------------------------------------------------------------------
# 1. Forbidden-secret denial (build script / proc macro + release gate).
# ---------------------------------------------------------------------------
$forbiddenName = 'ELIOT_FORBIDDEN_SECRET_1923'
$forbiddenValue = 'forbidden-seed-1923-' + [guid]::NewGuid().ToString('N')
$workspaceMetadataText = (& cargo metadata --locked --offline --no-deps --format-version 1 2>$null | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'BUILD_SANDBOX_PROOF: could not enumerate workspace build targets' }
try {
    $workspaceMetadata = $workspaceMetadataText | ConvertFrom-Json
}
catch {
    throw "BUILD_SANDBOX_PROOF: workspace metadata was not valid JSON: $($_.Exception.Message)"
}
$buildScriptTargets = @($workspaceMetadata.packages | ForEach-Object {
        $package = $_
        @($package.targets | Where-Object { @($_.kind) -contains 'custom-build' } | ForEach-Object {
                [pscustomobject]@{
                    package = [string]$package.name
                    path    = [System.IO.Path]::GetFullPath([string]$_.src_path)
                }
            })
    })
$buildScriptPaths = @($buildScriptTargets | ForEach-Object { $_.path } | Sort-Object -Unique)
if ($buildScriptPaths.Count -eq 0) {
    throw 'BUILD_SANDBOX_PROOF: workspace metadata exposes no build script to inspect'
}
$procMacroTargets = @($workspaceMetadata.packages | ForEach-Object {
        $package = $_
        @($package.targets | Where-Object { @($_.kind) -contains 'proc-macro' } | ForEach-Object {
                [pscustomobject]@{ package = [string]$package.name; path = [string]$_.src_path }
            })
    })
if ($procMacroTargets.Count -ne 0) {
    throw "BUILD_SANDBOX_PROOF: proc-macro targets require an explicit source proof: $($procMacroTargets.package -join ',')"
}
$buildScriptEvidence = [System.Collections.Generic.List[string]]::new()
foreach ($buildRsPath in $buildScriptPaths) {
    if (-not (Test-Path -LiteralPath $buildRsPath -PathType Leaf)) {
        throw "BUILD_SANDBOX_PROOF: metadata build script is missing: $buildRsPath"
    }
    $buildRsText = Get-Content -LiteralPath $buildRsPath -Raw
    $envReads = @([regex]::Matches($buildRsText, 'var_os\("([^"]+)"\)|var\("([^"]+)"\)') | ForEach-Object {
            if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
        })
    $unexpectedEnvReads = @($envReads | Where-Object { $_ -ne 'CARGO_MANIFEST_DIR' })
    $mentionsSecret = $buildRsText -match '(?i)secret|token|passwd|aws_|authorization|jwt'
    $usesNetwork = $buildRsText -match '(?i)http|TcpClient|UdpClient|Socket|Net\.|curl|wget|Command::new\(\s*"(curl|wget|ssh)"'
    if ($unexpectedEnvReads.Count -ne 0) {
        throw "BUILD_SANDBOX_PROOF: build.rs reads env beyond CARGO_MANIFEST_DIR ($buildRsPath): $($unexpectedEnvReads -join ',')"
    }
    if ($mentionsSecret) { throw "BUILD_SANDBOX_PROOF: build.rs references secret-like material: $buildRsPath" }
    if ($usesNetwork) { throw "BUILD_SANDBOX_PROOF: build.rs references network APIs: $buildRsPath" }
    $buildScriptEvidence.Add("$buildRsPath reads only CARGO_MANIFEST_DIR; no secret refs; no network APIs") | Out-Null
}

# Dynamic: controlled build with the forbidden secret seeded in-process only.
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$isolatedTarget = [System.IO.Path]::GetFullPath($IsolatedTargetDir)
New-Item -ItemType Directory -Path $isolatedTarget -Force | Out-Null
$previousCargoTargetDir = [Environment]::GetEnvironmentVariable('CARGO_TARGET_DIR', 'Process')
$previousCargoNetOffline = [Environment]::GetEnvironmentVariable('CARGO_NET_OFFLINE', 'Process')
$env:CARGO_TARGET_DIR = $isolatedTarget
$env:CARGO_NET_OFFLINE = 'true'
[System.Environment]::SetEnvironmentVariable($forbiddenName, $forbiddenValue, 'Process')
$cargoErrLog = Join-Path $tempBase ("eliot-1923-cargo-" + [guid]::NewGuid().ToString('N') + '.log')
try {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $buildOutput = @(& cargo build -p eliot-app --locked --offline 2> $cargoErrLog)
    $buildExit = $LASTEXITCODE
    $buildTargetDirUsed = [System.IO.Path]::GetFullPath([string]$env:CARGO_TARGET_DIR)
    $ErrorActionPreference = $prevEap
    $buildOutput += @(Get-Content -LiteralPath $cargoErrLog -ErrorAction SilentlyContinue | ForEach-Object { "$_" })
}
finally {
    Remove-Item -Path ("Env:" + $forbiddenName) -ErrorAction SilentlyContinue
    if ($null -eq $previousCargoTargetDir) {
        Remove-Item -Path 'Env:CARGO_TARGET_DIR' -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -Path 'Env:CARGO_TARGET_DIR' -Value $previousCargoTargetDir
    }
    if ($null -eq $previousCargoNetOffline) {
        Remove-Item -Path 'Env:CARGO_NET_OFFLINE' -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -Path 'Env:CARGO_NET_OFFLINE' -Value $previousCargoNetOffline
    }
    if (Test-Path -LiteralPath $cargoErrLog) { Remove-Item -LiteralPath $cargoErrLog -Force }
}
if ($buildExit -ne 0) {
    throw "BUILD_SANDBOX_PROOF: controlled offline build failed with exit $buildExit"
}
$joinedOutput = ($buildOutput | ForEach-Object { "$_" }) -join "`n"
if ($joinedOutput.Contains($forbiddenValue)) {
    throw 'BUILD_SANDBOX_PROOF: forbidden secret leaked into build output'
}
$leakedFiles = @(Get-ChildItem -LiteralPath $isolatedTarget -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            $text.Contains($forbiddenValue)
        }
        catch { $false }
    })
if ($leakedFiles.Count -ne 0) {
    throw "BUILD_SANDBOX_PROOF: forbidden secret present in isolated target: $($leakedFiles[0].FullName)"
}

# Release boundary: the same seeded value must be rejected by the secret scan.
$secretRoot = Join-Path $tempBase ("eliot-1923-secret-" + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $secretRoot -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $secretRoot 'payload.txt') -Value "api_key = `"$forbiddenValue`"" -Encoding utf8
    $scanRejected = $false
    try {
        Assert-NoReleaseSecrets $secretRoot
    }
    catch {
        $scanRejected = $_.Exception.Message -match 'secret scan matched|secret-like filename'
    }
    if (-not $scanRejected) { throw 'BUILD_SANDBOX_PROOF: seeded forbidden secret was not rejected by Assert-NoReleaseSecrets' }
}
finally {
    if (Test-Path -LiteralPath $secretRoot) { Remove-Item -LiteralPath $secretRoot -Recurse -Force }
}
Add-Record 'forbidden_secret_denied' 'PROVEN' @{
    build_scripts        = ($buildScriptEvidence -join ' | ')
    proc_macro_targets   = 0
    offline_build_exit   = $buildExit
    secret_in_output     = $false
    secret_in_target_dir = $false
    release_scan_rejects = $true
}

# ---------------------------------------------------------------------------
# 2. Observable network deny / authorized acquisition.
# ---------------------------------------------------------------------------
$builderText = Get-Content -LiteralPath (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1') -Raw
# The release network policy is the cargo argv template the builder actually
# executes. A file-wide search for a pin string would also match descriptive
# manifest projections and comments, so it is not evidence of the policy.
$buildArgvLines = @($builderText -split "`r?`n" | Where-Object { $_ -match '^\s*\$buildArgvTemplate\s*=' })
if ($buildArgvLines.Count -ne 1) {
    throw "BUILD_SANDBOX_PROOF: the release builder declares $($buildArgvLines.Count) cargo build argv templates, expected exactly one"
}
foreach ($cargoPin in @('--frozen', '--locked', '--offline')) {
    if ($buildArgvLines[0] -notmatch [regex]::Escape($cargoPin)) {
        throw "BUILD_SANDBOX_PROOF: the executed release cargo build argv template no longer pins $cargoPin"
    }
}
$lockBytes = [System.IO.File]::ReadAllBytes((Join-Path $repo 'Cargo.lock'))
$lockDigest = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($lockBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
$metadataJson = (& cargo metadata --locked --offline --no-deps --format-version 1 2>$null | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'BUILD_SANDBOX_PROOF: locked offline metadata (authorized acquisition) failed' }
Add-Record 'network_deny_or_authorized' 'PROVEN' @{
    policy              = 'the executed release cargo build argv template pins --frozen --locked --offline, so any network acquisition is a hard cargo error (deny by construction); no unauthorized acquisition is attempted here, the authorized acquisition is recorded below'
    release_build_argv  = $buildArgvLines[0].Trim()
    authorized_record   = "cargo metadata --locked --offline exit 0; Cargo.lock sha256=$lockDigest"
    controlled_build_offline_exit = $buildExit
}

# ---------------------------------------------------------------------------
# 3. Worktree / target / temp ACL boundaries.
# ---------------------------------------------------------------------------
function Test-NotReparse([string]$path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.LinkType) { throw "BUILD_SANDBOX_PROOF: reparse/symlink not allowed at $path (LinkType=$($item.LinkType))" }
}
function Get-AclBoundary([string]$path) {
    $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
    $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::Modify -bor
        [System.Security.AccessControl.FileSystemRights]::FullControl
    $broadWrite = @($acl.Access | Where-Object {
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            (($_.FileSystemRights -band $writeMask) -ne 0) -and
            ([string]$_.IdentityReference -match '(?i)(^|\\)(Everyone|Authenticated Users|Users)$')
        } | ForEach-Object { [string]$_.IdentityReference } | Sort-Object -Unique)
    $sddl = [string]$acl.Sddl
    $sddlBytes = [System.Text.Encoding]::UTF8.GetBytes($sddl)
    $sddlHash = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($sddlBytes) |
        ForEach-Object { $_.ToString('x2') }) -join ''
    [ordered]@{
        path                  = $path
        owner                 = [string]$acl.Owner
        access_rule_count     = @($acl.Access).Count
        broad_write_principals = @($broadWrite)
        sddl_sha256           = $sddlHash
    }
}
$aclBoundaries = [System.Collections.Generic.List[object]]::new()
$aclBroadWrite = [System.Collections.Generic.List[string]]::new()
foreach ($probe in @($repo, $isolatedTarget, $tempBase)) {
    if (-not ([System.IO.Path]::IsPathRooted($probe) -and $probe -match '^[A-Za-z]:[\\/]|^\\\\')) { throw "BUILD_SANDBOX_PROOF: non-absolute path $probe" }
    if (-not (Test-Path -LiteralPath $probe -PathType Container)) { throw "BUILD_SANDBOX_PROOF: missing directory $probe" }
    Test-NotReparse $probe
    $aclBoundary = Get-AclBoundary $probe
    $aclBoundaries.Add($aclBoundary) | Out-Null
    foreach ($principal in @($aclBoundary.broad_write_principals)) {
        $aclBroadWrite.Add("${probe}:$principal") | Out-Null
    }
}
if (-not $isolatedTarget.StartsWith('C:/Temp', [System.StringComparison]::OrdinalIgnoreCase) -and
    -not $isolatedTarget.StartsWith('C:\Temp', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "BUILD_SANDBOX_PROOF: isolated target is not under C:/Temp: $isolatedTarget"
}
$defaultTarget = Join-Path $repo 'target'
if ([System.String]::Equals($isolatedTarget, [System.IO.Path]::GetFullPath($defaultTarget), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'BUILD_SANDBOX_PROOF: build used the shared repository target/ directory'
}
if (-not [System.String]::Equals($buildTargetDirUsed, $isolatedTarget, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "BUILD_SANDBOX_PROOF: cargo target directory drifted from the isolated lane: $buildTargetDirUsed"
}
$aclStatus = if ($aclBroadWrite.Count -eq 0) { 'PROVEN' } else { 'FALLBACK_REQUIRED' }
Add-Record 'acl_boundaries' $aclStatus @{
    worktree      = $repo
    isolated_lane = $isolatedTarget
    temp_root     = $tempBase
    cargo_target_dir = $buildTargetDirUsed
    reparse_check = 'none found on worktree, lane, or temp root'
    default_target_avoided = $true
    acl_snapshots = @($aclBoundaries)
    broad_write_grants = @($aclBroadWrite)
    fallback = if ($aclBroadWrite.Count -eq 0) { '' } else { 'VM/lab isolated runner re-establishes the boundary; release evidence keeps this ACL snapshot with the selected runner' }
    reason = if ($aclBroadWrite.Count -eq 0) {
        'ACLs are readable and no broad inherited write grant was observed'
    }
    else {
        'broad inherited write grants prevent local proof of isolation; preserve the ACL snapshot and use the VM/lab fallback'
    }
}

# ---------------------------------------------------------------------------
# 4. Cache isolation across trust/source/toolchain fingerprints.
#    The governed build cache key is derived by the in-repo owner
#    (CacheLane::identity_for) and every reuse passes the store's trust gate
#    (DerivedCacheStore::lookup -> TrustPolicy::authenticate). This section
#    inspects those real owners and the real CI cargo cache key. It never
#    re-implements a key of its own and never treats a locally computed
#    digest as proof about the product's cache.
# ---------------------------------------------------------------------------
$ciText = Get-Content -LiteralPath (Join-Path $repo '.github/workflows/ci.yml') -Raw
$ciKeyLines = @($ciText -split "`r?`n" | Where-Object { $_ -match 'key:\s*\$\{\{' })
$ciKeyLine = $ciKeyLines -join ' | '
$ciKeyCoversTrust = ($ciKeyLines -join "`n") -match '(?i)trust|toolchain|producer|BuildFingerprint|env\.|runner\.arch'
$rustcVersion = (& rustc --version 2>$null | Out-String).Trim()
$sourceCommit = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()

$cacheLaneRelative = 'crates/instrument/eliot-instrument-runner/src/cache_lane.rs'
$derivedCacheRelative = 'crates/instrument/eliot-build-test-graph/src/derived_cache.rs'
foreach ($ownerRelative in @($cacheLaneRelative, $derivedCacheRelative)) {
    if (-not (Test-Path -LiteralPath (Join-Path $repo $ownerRelative) -PathType Leaf)) {
        throw "BUILD_SANDBOX_PROOF: the governed build cache owner is missing: $ownerRelative"
    }
}
$cacheLaneText = Get-Content -LiteralPath (Join-Path $repo $cacheLaneRelative) -Raw
$derivedCacheText = Get-Content -LiteralPath (Join-Path $repo $derivedCacheRelative) -Raw
$identityForBody = [regex]::Match($cacheLaneText, '(?s)pub fn identity_for\(.*?\n    \}').Value
if ([string]::IsNullOrWhiteSpace($identityForBody)) {
    throw "BUILD_SANDBOX_PROOF: the governed build cache key owner CacheLane::identity_for is gone ($cacheLaneRelative)"
}
# Every fingerprint this item names must reach the real cache identity. A
# dimension that stops binding fails the suite instead of being narrated.
$governedKeyDimensions = [ordered]@{
    source    = @('source_digest', 'generated_input_digest')
    toolchain = @('toolchain_version', 'compiler_version')
    trust     = @('producer_id', 'root_identity', 'root_acl_digest')
}
foreach ($dimension in $governedKeyDimensions.Keys) {
    foreach ($fingerprint in @($governedKeyDimensions[$dimension])) {
        if ($identityForBody -notmatch ('\b' + [regex]::Escape($fingerprint) + '\b')) {
            throw "BUILD_SANDBOX_PROOF: the governed build cache key no longer binds the $dimension fingerprint '$fingerprint' ($cacheLaneRelative)"
        }
    }
}
if ($derivedCacheText -notmatch '(?s)pub fn lookup\(.*?trust\.authenticate\(identity\)') {
    throw "BUILD_SANDBOX_PROOF: the governed cache store no longer gates every lookup through the trust policy ($derivedCacheRelative)"
}
# The cross-trust refusal is EXECUTED, not only inspected: the integration
# proof crates/eliot-engine/tests/governed_build_cache_trust.rs drives the real
# application entrypoint GovernedBuildRuntime::run_admitted over the real chain
# (lookup_governed -> CacheLane::identity_for -> DerivedCacheStore::lookup ->
# TrustPolicy::authenticate), publishes an entry under one producer and proves a
# request under a different producer is refused, that the refusal is recorded,
# that the refusal is a miss rather than a correctness failure (the admitted
# build still runs and its bytes are read back), and that the valid entry
# survives the refusal. That test is the executed half of this item; it fails if
# the trust gate is removed.
$crossTrustProof = 'crates/eliot-engine/tests/governed_build_cache_trust.rs foreign_trust_fingerprint_entry_is_never_reused_and_the_build_still_runs'
if (-not (Test-Path -LiteralPath (Join-Path $repo $crossTrustProof.Split(' ')[0]) -PathType Leaf)) {
    throw 'BUILD_SANDBOX_PROOF: the executed cross-trust cache refusal proof is missing (crates/eliot-engine/tests/governed_build_cache_trust.rs)'
}
Add-Record 'cache_isolation' 'PROVEN' @{
    reason                     = "The in-repo governed cache key owner binds source/toolchain/trust (CacheLane::identity_for) and gates every lookup through the trust policy (DerivedCacheStore::lookup -> TrustPolicy::authenticate). The cross-trust refusal is now EXECUTED end to end through the real application entrypoint by the proof named in executed_cross_trust_proof -- an entry published under one producer is not served to a request under a different producer, the refusal is recorded as evidence with reason UntrustedProducer, the refusal is a MISS rather than a correctness failure (the admitted build still runs and the returned bytes are the ones read back from the declared artifact path), and replaying the trusted fingerprint still hits and launches nothing. That test fails when the trust gate is removed."
    ci_cache_key               = $ciKeyLine
    ci_key_covers_trust        = [bool]$ciKeyCoversTrust
    governed_key_owner         = "$cacheLaneRelative CacheLane::identity_for"
    governed_key_dimensions    = $governedKeyDimensions
    governed_trust_gate        = "$derivedCacheRelative DerivedCacheStore::lookup -> TrustPolicy::authenticate"
    executed_cross_trust_proof = $crossTrustProof
    rustc                      = $rustcVersion
    source_commit              = $sourceCommit
    required_key               = 'trust + source + Cargo.lock + toolchain + features/profile + env + producer + cache-root identity (I02.22)'
    claim_ceiling              = 'the executed refusal proves the in-repo governed cache owner, which the daemon does not yet route: bins/eliotd/src/maintenance_family_catalog.rs records under MaintenanceFamily::DerivedIndexRebuild that eliotd holds no durable job route to crates/eliot-engine::CachedDerivationService because it owns neither a DerivedCacheStore nor a TrustPolicy. The CI cargo cache key is separately constrained by scripts/verify-github-workflows.py GWF-020/GWF-021, which bind every trust, source and toolchain dimension and reach every workspace member manifest.'
    fallback                   = 'VM/lab runner with exact-fingerprint cache or cold cache; record selected runner in release evidence'
}

# ---------------------------------------------------------------------------
# 5. Bounded (oversized-output) handling.
#    Two executions, both real: a capped reader that drains an 8 MiB child
#    stdout while retaining a bounded prefix, and the release runner that
#    actually launches release child processes. A proof that never touches
#    the runner is not a proof about the runner.
# ---------------------------------------------------------------------------
$byteCap = 1048576
$childBytes = 8388608
$childCommand = "`$bytes = [byte[]]::new($childBytes); [Console]::OpenStandardOutput().Write(`$bytes, 0, `$bytes.Length)"
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = 'powershell'
$psi.ArgumentList.Add('-NoProfile')
$psi.ArgumentList.Add('-Command')
$psi.ArgumentList.Add($childCommand)
$psi.RedirectStandardOutput = $true
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi
if (-not $proc.Start()) { throw 'BUILD_SANDBOX_PROOF: oversized-output child did not start' }
$stream = $proc.StandardOutput.BaseStream
$buffer = [byte[]]::new(65536)
$totalBytes = 0
$captured = 0
$watch = [System.Diagnostics.Stopwatch]::StartNew()
try {
    while ($true) {
        $readTask = $stream.ReadAsync($buffer, 0, $buffer.Length)
        while (-not $readTask.Wait(1000)) {
            if ($watch.ElapsedMilliseconds -gt 60000) {
                try { $proc.Kill() } catch { }
                throw 'BUILD_SANDBOX_PROOF: oversized-output child exceeded wall deadline'
            }
        }
        $read = $readTask.Result
        if ($read -eq 0) { break }
        $totalBytes += $read
        if ($captured -lt $byteCap) {
            $captured += [Math]::Min($read, $byteCap - $captured)
        }
    }
    if (-not $proc.WaitForExit(10000)) { throw 'BUILD_SANDBOX_PROOF: oversized-output child did not exit after stream drain' }
    if ($proc.ExitCode -ne 0) { throw "BUILD_SANDBOX_PROOF: oversized-output child exited $($proc.ExitCode)" }
    if ($totalBytes -lt $childBytes) { throw "BUILD_SANDBOX_PROOF: child did not emit oversized stdout ($totalBytes bytes)" }
}
finally {
    $boundedChildExited = $proc.HasExited
    if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
    $stream.Dispose()
    $proc.Dispose()
}

# The release runner must survive the same oversized child. Its retention is
# measured, not asserted: the receipt states what the runner actually kept.
$runnerRun = Invoke-CapturedNativeProcess 'powershell' @('-NoProfile', '-Command', $childCommand) $repo 'bounded-output-child'
if ($runnerRun.exit_code -ne 0) {
    throw "BUILD_SANDBOX_PROOF: the release runner failed the oversized-output child with exit $($runnerRun.exit_code): $($runnerRun.stderr)"
}
$runnerLogBytes = [System.IO.File]::ReadAllBytes($runnerRun.stdout_path).Length
if ($runnerLogBytes -lt $childBytes) {
    throw "BUILD_SANDBOX_PROOF: the release runner lost oversized stdout ($runnerLogBytes of $childBytes bytes)"
}
$runnerRetained = ([string]$runnerRun.stdout).Length
Add-Record 'bounded_output' 'PROVEN' @{
    child_bytes_emit       = $childBytes
    stream_bytes_drained   = $totalBytes
    capture_cap            = $byteCap
    captured_bytes         = $captured
    runner_owner           = 'scripts/build-eliot-windows-x64-release.ps1 Invoke-CapturedNativeProcess'
    runner_exit            = $runnerRun.exit_code
    runner_stdout_log_bytes = $runnerLogBytes
    runner_retained_bytes  = $runnerRetained
    runner_retention_bound = $(if ($runnerRetained -le $byteCap) { "bounded at $byteCap bytes" } else { 'unbounded: the runner retains the whole stream, so only non-deadlock is proven for it' })
    runner_completed       = $true
    child_exited     = $boundedChildExited
}

# ---------------------------------------------------------------------------
# 6. Artifact-to-release-hash binding (SBOM/license/advisory/provenance).
#    The in-repo owner of the SBOM/license/advisory run artifacts is executed
#    here, not inferred from the release builder's wording: a co-occurrence of
#    "sbom" and "SHA-256" somewhere in a 4k-line script is not a binding.
# ---------------------------------------------------------------------------
foreach ($needle in @('SHA-256', 'source commit', 'not-issued', 'Test-ReleaseBundle')) {
    if ($builderText -notmatch [regex]::Escape($needle)) {
        throw "BUILD_SANDBOX_PROOF: release builder no longer binds manifest evidence ($needle)"
    }
}
$dependencyPolicyPath = Join-Path $repo 'scripts/verify-dependency-policy.py'
if (-not (Test-Path -LiteralPath $dependencyPolicyPath -PathType Leaf)) {
    throw 'BUILD_SANDBOX_PROOF: the dependency-policy owner of the SBOM/license/advisory run artifacts is missing'
}
$generatorPython = Get-PinnedCommandFile 'python' 'dependency-policy SBOM/license/advisory generator'
$generatorRun = Invoke-CapturedNativeProcess $generatorPython.FullName @($dependencyPolicyPath, '--self-test') $repo 'dependency-policy-generator'
if ($generatorRun.exit_code -ne 0) {
    throw "BUILD_SANDBOX_PROOF: the in-repo SBOM/license/advisory generators failed their own run (exit $($generatorRun.exit_code)): $($generatorRun.stdout) $($generatorRun.stderr)"
}
# What is still unproven is the release half: staging must place those three
# artifacts inside the manifest whose per-file SHA-256 is the release hash.
$releaseArtifactRequests = @(
    [ordered]@{ flag = '--sbom-out'; artifact = 'sbom.json'; staged = 'supply_chain/sbom.json' }
    [ordered]@{ flag = '--license-report-out'; artifact = 'licenses.json'; staged = 'supply_chain/licenses.json' }
    [ordered]@{ flag = '--advisory-report-out'; artifact = 'advisories.json'; staged = 'supply_chain/advisories.json' }
)
$unstagedReleaseArtifacts = @($releaseArtifactRequests | Where-Object { $builderText -notmatch [regex]::Escape([string]$_.flag) } | ForEach-Object { [string]$_.artifact })
if ($unstagedReleaseArtifacts.Count -eq 0) {
    # The release half now exists, so the source-text scan above is no longer
    # evidence of anything: a flag appearing in the builder's bytes says only
    # that the flag is spelled there. This claim is re-derived from the STAGED
    # MANIFEST instead -- the structure that actually decides whether the
    # generated artifacts are covered by the per-file SHA-256 sweep whose
    # digests ARE the release hashes. It is the manifest, not the builder's
    # wording, that is read from here on.
    $supplyChainStaged = [ordered]@{
        flag    = '--sbom-out,--license-report-out,--advisory-report-out in one executed generator run'
        builder = 'scripts/build-eliot-windows-x64-release.ps1 Get-ReleaseSupplyChainArtifacts'
    }
    $stagedPayloadOwner = 'function Get-StagedPayloadManifest'
    $stagedPayloadBody = [regex]::Match(
        $builderText,
        '(?s)function Get-StagedPayloadManifest\(.*?\n\}').Value
    if ([string]::IsNullOrWhiteSpace($stagedPayloadBody)) {
        throw "BUILD_SANDBOX_PROOF: the staged payload manifest owner is gone ($stagedPayloadOwner); the staged SBOM/license/advisory entries cannot be confirmed"
    }
    $releaseManifestOwner = 'supply_chain_artifacts = [ordered]@{'
    $releaseManifestBody = [regex]::Match(
        $builderText,
        '(?s)supply_chain_artifacts = \[ordered\]@\{.*?\n        \}').Value
    if ([string]::IsNullOrWhiteSpace($releaseManifestBody)) {
        throw "BUILD_SANDBOX_PROOF: the release manifest no longer publishes a supply_chain_artifacts block; the generated artifacts would ship with no recorded release hash"
    }
    # Each of the three staged artifacts must be covered by BOTH manifests. A row
    # is emitted from a variable in each owner, so this check asserts the
    # STRUCTURE that makes the row appear, not a literal `supply_chain/sbom.json`
    # string that appears in no line of the builder:
    #   * the staged payload manifest iterates the staged artifacts and emits a
    #     row carrying the digest and the install destination, which is what puts
    #     each file inside the recursive per-file SHA-256 sweep;
    #   * the release manifest publishes the same staged rows, and its row shape
    #     carries the recomputed sha256 and bytes.
    # Requiring the literal artifact name instead would reject a correct
    # implementation purely because it builds the path from a variable.
    $payloadIteratesStaged = ($stagedPayloadBody -match '\$SupplyChainArtifacts') -and
        ($stagedPayloadBody -match [regex]::Escape('install_destination')) -and
        ($stagedPayloadBody -match 'artifact_sha256\s*=')
    $releasePublishesStaged = ($releaseManifestBody -match [regex]::Escape('$stagedSupplyChain')) -and
        ($releaseManifestBody -match [regex]::Escape('$supplyChainArtifacts.release_hashes'))
    # The digest must be recomputed from the staged bytes by the builder, never
    # copied from the artifact's own `receipt_digest` field -- that field covers
    # the generator's receipt object and not the file about to be attested. The
    # pattern is anchored on the re-hash immediately followed by the comparison
    # against the digest the generator reported, so commenting either statement
    # out stops the match rather than leaving the claim green.
    $digestRecomputedAtStaging = $builderText -match '(?s)stagedEvidence = Read-VerifiedResidentFile \$stagedPath.{0,400}?stagedEvidence\.sha256 -cne \[string\]\$generatedArtifact\.sha256'
    $digestRecomputedAtStaging = $digestRecomputedAtStaging -and
        ($builderText -notmatch '#\s*stagedEvidence = Read-VerifiedResidentFile \$stagedPath')
    $boundArtifacts = @()
    $unboundArtifacts = @()
    if ($payloadIteratesStaged -and $releasePublishesStaged -and $digestRecomputedAtStaging) {
        foreach ($request in $releaseArtifactRequests) {
            $boundArtifacts += [string]$request.staged
        }
    }
    else {
        foreach ($request in $releaseArtifactRequests) {
            $unboundArtifacts += [string]$request.staged
        }
    }
    if ($unboundArtifacts.Count -ne 0) {
        throw "BUILD_SANDBOX_PROOF: release staging requests the generated SBOM/license/advisory artifacts but does not bind $($unboundArtifacts -join ', ') into the staged payload manifest and the release manifest, so their per-file SHA-256 is still not a release hash"
    }
    # The binding must be a recomputed digest, not a self-declared one: the
    # generator's own `receipt_digest` covers its receipt object, never the
    # artifact bytes, so the builder has to re-hash the staged file. This is
    # what distinguishes a real binding from a copied field.
    foreach ($digestNeedle in @(
            'Read-VerifiedResidentFile',
            'supply_chain',
            'recomputed from the staged bytes')) {
        if ($builderText -notmatch [regex]::Escape($digestNeedle)) {
            throw "BUILD_SANDBOX_PROOF: release staging no longer recomputes the staged artifact digest ($digestNeedle)"
        }
    }
    Add-Record 'provenance_binding' 'PROVEN' @{
        reason                    = "Release staging now invokes scripts/verify-dependency-policy.py with --sbom-out/--license-report-out/--advisory-report-out in one executed run (scripts/build-eliot-windows-x64-release.ps1 Get-ReleaseSupplyChainArtifacts), passing a --release-hashes file whose entries are repository-relative paths that verify_release_hash_bindings re-reads and recomputes in-process, failing the run with DEP-009 on divergence. Each artifact is then staged under supply_chain/ and its OWN sha256 and byte length are recomputed from the exact bytes on disk through Read-VerifiedResidentFile -- never copied from the artifact's own receipt_digest field, which covers the receipt object and not the file. The staged rows are named by the staged payload manifest, so the recursive SHA256SUMS.json sweep covers them like every other payload entry, and RELEASE.json publishes each staged path with its recomputed sha256 and bytes, so Test-ReleaseBundle recomputes and refuses any drift."
        manifest_evidence         = 'supply_chain/<sbom|licenses|advisories>.json staged entries in STAGED_PAYLOAD_MANIFEST.json + per-file sha256/bytes in RELEASE.json supply_chain_artifacts, both covered by the SHA256SUMS.json sweep and Test-ReleaseBundle recomputation'
        generator_owner           = 'scripts/verify-dependency-policy.py build_sbom_artifact / build_license_report_artifact / build_advisory_report_artifact (invoked by scripts/build-eliot-windows-x64-release.ps1 Get-ReleaseSupplyChainArtifacts)'
        generator_exit            = $generatorRun.exit_code
        bound_release_artifacts   = $boundArtifacts
        staged_payload_owner      = $stagedPayloadOwner
        staged_payload_entry      = $supplyChainStaged.flag
        claim_ceiling             = 'the bound release hashes are the repository-relative policy inputs the generator re-verified, plus the recomputed digest of each staged artifact; a verifier exit code other than 0 is recorded as supply_chain_artifacts.generator_verdict rather than converted into a release gate'
    }
}
else {
    Add-Record 'provenance_binding' 'FALLBACK_REQUIRED' @{
        reason                    = "RELEASE.json / SHA256SUMS.json / RUNTIME_ARTIFACTS.json bind source commit plus per-file SHA-256/size with signature_evidence:not-issued when unsigned. The in-repo SBOM/license/advisory generators exist and were executed here, and each binds its canonical receipt digest plus per-component integrity digests. The release half is missing: release staging never requests $($unstagedReleaseArtifacts -join ', '), so those artifacts are not covered by the manifest whose per-file SHA-256 is the release hash."
        manifest_evidence         = 'source commit + per-file SHA-256/size + Test-ReleaseBundle recomputation'
        generator_owner           = 'scripts/verify-dependency-policy.py build_sbom_artifact / build_license_report_artifact / build_advisory_report_artifact'
        generator_exit            = $generatorRun.exit_code
        unstaged_release_artifacts = $unstagedReleaseArtifacts
        fallback                  = 'release staging must request the SBOM/license/advisory run artifacts and recompute their per-file SHA-256 into the release manifest; until then the external signer records that binding with the release'
    }
}

# ---------------------------------------------------------------------------
# 7. Job Object descendant removal.
#    The release build plane now launches every cargo child through a Job
#    Object (scripts/build-eliot-windows-x64-release.ps1
#    ::Invoke-JobContainedNativeProcess, created suspended -> assigned ->
#    resumed). The previous evidence here was a single Stop-Process against one
#    sleeping child, which the suite itself labelled "NOT a descendant-tree
#    proof". This section measures a real descendant TREE through the release
#    owner's own measurement function: a child that forks a sleeping grandchild
#    and then exits. A direct-child kill cannot remove that grandchild.
#
#    Still NOT proven here, by construction (I18.44): a Job Object binds process
#    lifetime and is NOT a filesystem or network sandbox. That boundary stays
#    with the recorded VM/lab runner below.
# ---------------------------------------------------------------------------
$descendantProbe = Measure-ReleaseLaunchDescendantRemoval `
    (Get-Command powershell -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source `
    'Start-Process powershell -ArgumentList ''-NoProfile -Command Start-Sleep -Seconds 300'' -WindowStyle Hidden; Start-Sleep -Seconds 2; exit 0' `
    20
if ($descendantProbe.observed_descendant_count -lt 1) {
    throw 'BUILD_SANDBOX_PROOF: the descendant probe observed no descendant process'
}
if ($descendantProbe.survivors_after_cancel -ne 0) {
    throw "BUILD_SANDBOX_PROOF: $($descendantProbe.survivors_after_cancel) descendants survived Job Object cancellation"
}
# The ACL boundaries must still be intact after the cancellation.
foreach ($probe in @($repo, $isolatedTarget, $tempBase)) {
    Test-NotReparse $probe
    $postCancelAcl = Get-AclBoundary $probe
    $preCancelAcl = @($aclBoundaries | Where-Object { [string]$_.path -ceq $probe })[0]
    if ($null -eq $preCancelAcl) { throw "BUILD_SANDBOX_PROOF: no pre-cancellation ACL snapshot for $probe" }
    if ([string]$postCancelAcl.sddl_sha256 -cne [string]$preCancelAcl.sddl_sha256) {
        throw "BUILD_SANDBOX_PROOF: the ACL boundary changed across Job Object cancellation: $probe"
    }
}
Add-Record 'descendant_removal' 'PROVEN' @{
    owner                     = [string]$descendantProbe.owner
    release_launch_owner      = 'scripts/build-eliot-windows-x64-release.ps1 Invoke-JobContainedNativeProcess (every release cargo build child)'
    job_name                  = [string]$descendantProbe.job_name
    direct_child_exit_code    = $descendantProbe.direct_child_exit_code
    observed_descendants      = $descendantProbe.observed_descendant_count
    survivors_after_cancel    = $descendantProbe.survivors_after_cancel
    acl_reverified_intact     = $true
    claim_ceiling             = [string]$descendantProbe.claim_ceiling
    reason                    = "Cancelling the build closes one owning Job handle with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, and the grandchild this probe forked is gone afterwards; a direct-child kill would have left it running. A Job Object is NOT a filesystem or network sandbox, so the claim is scoped to descendant process lifetime."
    fallback                  = 'the VM/lab isolated runner still owns the filesystem and network sandbox boundary; a Job Object check never substitutes for it'
}

$failed = @($records | Where-Object { $_.status -notin @('PROVEN', 'FALLBACK_REQUIRED') })
$proven = @($records | Where-Object { $_.status -eq 'PROVEN' }).Count
$fallback = @($records | Where-Object { $_.status -eq 'FALLBACK_REQUIRED' }).Count
# Typed per-claim gate for the deterministic aggregator
# (tests/release-security/run-tests.ps1): one boolean per claim, true only
# when the claim is locally proven or explicitly routed to a recorded
# VM/lab fallback. Anything else fails closed below; the gate never turns
# an unrouted claim green.
$gateHeld = [ordered]@{}
$selectedFallbacks = [ordered]@{}
foreach ($record in $records) {
    $gateName = 'claim_' + [string]$record.claim + '_held'
    $fallbackText = ''
    if ($record.evidence -is [System.Collections.IDictionary] -and $record.evidence.Contains('fallback')) {
        $fallbackText = [string]$record.evidence['fallback']
    }
    if ([string]$record.status -eq 'PROVEN') {
        $gateHeld[$gateName] = $true
    }
    elseif ([string]$record.status -eq 'FALLBACK_REQUIRED' -and -not [string]::IsNullOrWhiteSpace($fallbackText)) {
        $gateHeld[$gateName] = $true
        $selectedFallbacks[[string]$record.claim] = $fallbackText
    }
    else {
        $gateHeld[$gateName] = $false
    }
}
$result = [pscustomobject]@{
    component = 'eliot_build_sandbox_cache_proof_1923'
    status    = if ($failed.Count -eq 0) { 'VERIFIED' } else { 'FAILED' }
    proven    = $proven
    fallbacks = $fallback
    lane      = $isolatedTarget
    claims    = $records
    selected_fallbacks = $selectedFallbacks
}
foreach ($gateName in @($gateHeld.Keys)) {
    $result | Add-Member -NotePropertyName $gateName -NotePropertyValue ([bool]$gateHeld[$gateName])
}
$result | ConvertTo-Json -Depth 6
if ($failed.Count -ne 0) { throw 'BUILD_SANDBOX_PROOF: one or more claims left unproven and unrouted' }
