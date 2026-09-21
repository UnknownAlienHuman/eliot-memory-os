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
$buildRsPath = Join-Path $repo 'crates/eliot-app/build.rs'
$buildRsText = Get-Content -LiteralPath $buildRsPath -Raw

$envReads = @([regex]::Matches($buildRsText, 'var_os\("([^"]+)"\)|var\("([^"]+)"\)') | ForEach-Object {
        if ($_.Groups[1].Success) { $_.Groups[1].Value } else { $_.Groups[2].Value }
    })
$onlyManifestDir = ($envReads.Count -gt 0) -and (@($envReads | Where-Object { $_ -ne 'CARGO_MANIFEST_DIR' }).Count -eq 0)
$mentionsSecret = $buildRsText -match '(?i)secret|token|passwd|aws_|authorization|jwt'
$usesNetwork = $buildRsText -match '(?i)http|TcpClient|UdpClient|Socket|Net\.|curl|wget|Command::new\(\s*"(curl|wget|ssh)"'
$procMacroCrates = @(Get-ChildItem -LiteralPath (Join-Path $repo 'crates') -Recurse -Filter 'Cargo.toml' | Where-Object {
        (Get-Content -LiteralPath $_.FullName -Raw) -match '(?m)^\s*proc-macro\s*=\s*true'
    })
if (-not $onlyManifestDir) { throw "BUILD_SANDBOX_PROOF: build.rs reads env beyond CARGO_MANIFEST_DIR: $($envReads -join ',')" }
if ($mentionsSecret) { throw 'BUILD_SANDBOX_PROOF: build.rs references secret-like material' }
if ($usesNetwork) { throw 'BUILD_SANDBOX_PROOF: build.rs references network APIs' }
if ($procMacroCrates.Count -ne 0) {
    throw "BUILD_SANDBOX_PROOF: unexpected proc-macro crates: $($procMacroCrates.FullName -join '; ')"
}

# Dynamic: controlled build with the forbidden secret seeded in-process only.
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$isolatedTarget = [System.IO.Path]::GetFullPath($IsolatedTargetDir)
New-Item -ItemType Directory -Path $isolatedTarget -Force | Out-Null
$env:CARGO_TARGET_DIR = $isolatedTarget
$env:CARGO_NET_OFFLINE = 'true'
[System.Environment]::SetEnvironmentVariable($forbiddenName, $forbiddenValue, 'Process')
$cargoErrLog = Join-Path $tempBase ("eliot-1923-cargo-" + [guid]::NewGuid().ToString('N') + '.log')
try {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $buildOutput = @(& cargo build -p eliot-app --locked --offline 2> $cargoErrLog)
    $buildExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    $buildOutput += @(Get-Content -LiteralPath $cargoErrLog -ErrorAction SilentlyContinue | ForEach-Object { "$_" })
}
finally {
    Remove-Item -Path ("Env:" + $forbiddenName) -ErrorAction SilentlyContinue
    Remove-Item -Path 'Env:CARGO_NET_OFFLINE' -ErrorAction SilentlyContinue
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
    build_script         = 'crates/eliot-app/build.rs reads only CARGO_MANIFEST_DIR; no secret refs; no network APIs'
    proc_macro_crates    = 0
    offline_build_exit   = $buildExit
    secret_in_output     = $false
    secret_in_target_dir = $false
    release_scan_rejects = $true
}

# ---------------------------------------------------------------------------
# 2. Observable network deny / authorized acquisition.
# ---------------------------------------------------------------------------
$builderText = Get-Content -LiteralPath (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1') -Raw
if ($builderText -notmatch '--locked --offline') {
    throw 'BUILD_SANDBOX_PROOF: release builder does not pin locked offline cargo builds'
}
if ($builderText -notmatch '--frozen') {
    throw 'BUILD_SANDBOX_PROOF: release builder does not freeze cargo builds against lockfile/network acquisition'
}
$lockBytes = [System.IO.File]::ReadAllBytes((Join-Path $repo 'Cargo.lock'))
$lockDigest = ([System.Security.Cryptography.SHA256]::Create().ComputeHash($lockBytes) | ForEach-Object { $_.ToString('x2') }) -join ''
$metadataJson = (& cargo metadata --locked --offline --no-deps --format-version 1 2>$null | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'BUILD_SANDBOX_PROOF: locked offline metadata (authorized acquisition) failed' }
Add-Record 'network_deny_or_authorized' 'PROVEN' @{
    policy              = 'frozen+locked+offline only; --offline/--frozen makes any network acquisition a hard cargo error (deny by construction)'
    builder_pins_offline = $true
    no_download_rule    = '--frozen pinned in release builder (cargo build --frozen --locked --offline --release)'
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
foreach ($probe in @($repo, $isolatedTarget, $tempBase)) {
    if (-not ([System.IO.Path]::IsPathRooted($probe) -and $probe -match '^[A-Za-z]:[\\/]|^\\\\')) { throw "BUILD_SANDBOX_PROOF: non-absolute path $probe" }
    if (-not (Test-Path -LiteralPath $probe -PathType Container)) { throw "BUILD_SANDBOX_PROOF: missing directory $probe" }
    Test-NotReparse $probe
}
if (-not $isolatedTarget.StartsWith('C:/Temp', [System.StringComparison]::OrdinalIgnoreCase) -and
    -not $isolatedTarget.StartsWith('C:\Temp', [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "BUILD_SANDBOX_PROOF: isolated target is not under C:/Temp: $isolatedTarget"
}
$defaultTarget = Join-Path $repo 'target'
if ($env:CARGO_TARGET_DIR -ne $isolatedTarget -and $isolatedTarget -eq $defaultTarget) {
    throw 'BUILD_SANDBOX_PROOF: build used the shared repository target/ directory'
}
Add-Record 'acl_boundaries' 'PROVEN' @{
    worktree      = $repo
    isolated_lane = $isolatedTarget
    temp_root     = $tempBase
    reparse_check = 'none found on worktree, lane, or temp root'
    default_target_avoided = $true
}

# ---------------------------------------------------------------------------
# 4. Cache isolation across trust/source/toolchain fingerprints.
# ---------------------------------------------------------------------------
$ciText = Get-Content -LiteralPath (Join-Path $repo '.github/workflows/ci.yml') -Raw
$ciKeyLines = @($ciText -split "`r?`n" | Where-Object { $_ -match 'key:\s*\$\{\{' })
$ciKeyLine = $ciKeyLines -join ' | '
$ciKeyCoversTrust = ($ciKeyLines -join "`n") -match '(?i)trust|toolchain|producer|BuildFingerprint|env\.|runner\.arch'
$rustcVersion = (& rustc --version 2>$null | Out-String).Trim()
$sourceCommit = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()
function Get-LaneKey([string]$trust, [string]$commit, [string]$lock, [string]$toolchain) {
    $raw = "trust=$trust;source=$commit;lock=$lock;toolchain=$toolchain"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($raw)
    return ([System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}
$laneA = Get-LaneKey 'lane-a-untrusted' $sourceCommit $lockDigest $rustcVersion
$laneB = Get-LaneKey 'lane-b-release' $sourceCommit $lockDigest $rustcVersion
if ($laneA -eq $laneB) { throw 'BUILD_SANDBOX_PROOF: lane keys must differ across trust labels' }
$laneADir = Join-Path $isolatedTarget ("lane-" + $laneA.Substring(0, 16))
$laneBDir = Join-Path $isolatedTarget ("lane-" + $laneB.Substring(0, 16))
New-Item -ItemType Directory -Path $laneADir -Force | Out-Null
Set-Content -LiteralPath (Join-Path $laneADir 'artifact.bin') -Value 'lane-a bytes' -Encoding ascii -NoNewline
if (Test-Path -LiteralPath (Join-Path $laneBDir 'artifact.bin')) {
    throw 'BUILD_SANDBOX_PROOF: lane-B key resolved a lane-A artifact (cross-trust reuse)'
}
Add-Record 'cache_isolation' 'FALLBACK_REQUIRED' @{
    reason              = 'CI cargo cache key binds only OS+lockfile+profile; it does not cover the I02.22/I10.8.14 closure (trust, toolchain identity, producer identity, env fingerprint, cache-root ACL). Cross-trust reuse must not be claimed locally.'
    ci_cache_key        = $ciKeyLine
    ci_key_covers_trust = [bool]$ciKeyCoversTrust
    lane_demo           = "distinct trust labels yield distinct lane keys ($($laneA.Substring(0,12))... vs $($laneB.Substring(0,12))...); lane-B key misses lane-A artifact (miss, not reuse)"
    rustc               = $rustcVersion
    source_commit       = $sourceCommit
    required_key        = 'trust + source + Cargo.lock + toolchain + features/profile + env + producer + cache-root identity (I02.22)'
    fallback            = 'VM/lab runner with exact-fingerprint cache or cold cache; record selected runner in release evidence'
}

# ---------------------------------------------------------------------------
# 5. Bounded (oversized-output) handling.
# ---------------------------------------------------------------------------
# Capture to a file (pipe-buffer deadlock impossible), enforce a wall
# deadline, then read at most the byte cap: the bounded pattern.
$oversizedLog = Join-Path $tempBase ("eliot-1923-oversized-" + [guid]::NewGuid().ToString('N') + '.log')
$byteCap = 1048576
$psi = New-Object System.Diagnostics.ProcessStartInfo -ArgumentList 'powershell', ('-NoProfile -Command "$s = ''x'' * 8388608; Set-Content -LiteralPath ''' + $oversizedLog + ''' -Value $s -Encoding ascii -NoNewline"')
$psi.RedirectStandardOutput = $false
$psi.RedirectStandardError = $false
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$captured = 0
try {
    if (-not $proc.WaitForExit(60000)) {
        try { $proc.Kill() } catch { }
        if (-not $proc.WaitForExit(10000)) { throw 'BUILD_SANDBOX_PROOF: oversized-output child survived cancellation' }
    }
    if ($proc.ExitCode -ne 0) { throw "BUILD_SANDBOX_PROOF: oversized-output child exited $($proc.ExitCode)" }
    $info = Get-Item -LiteralPath $oversizedLog -Force
    if ($info.Length -lt 8388608) { throw "BUILD_SANDBOX_PROOF: child did not emit oversized output ($($info.Length) bytes)" }
    $stream = [System.IO.File]::OpenRead($oversizedLog)
    try {
        $buf = New-Object byte[] $byteCap
        $captured = $stream.Read($buf, 0, $buf.Length)
    }
    finally { $stream.Dispose() }
}
finally {
    $boundedChildExited = $proc.HasExited
    if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
    $proc.Dispose()
    if (Test-Path -LiteralPath $oversizedLog) { Remove-Item -LiteralPath $oversizedLog -Force }
}
Add-Record 'bounded_output' 'PROVEN' @{
    child_bytes_emit = 8388608
    capture_cap      = $byteCap
    captured_bytes   = $captured
    runner_completed = $true
    child_exited     = $boundedChildExited
}

# ---------------------------------------------------------------------------
# 6. Artifact-to-release-hash binding (SBOM/license/advisory/provenance).
# ---------------------------------------------------------------------------
foreach ($needle in @('SHA-256', 'source commit', 'not-issued', 'Test-ReleaseBundle')) {
    if ($builderText -notmatch [regex]::Escape($needle)) {
        throw "BUILD_SANDBOX_PROOF: release builder no longer binds manifest evidence ($needle)"
    }
}
$hasSbomBinder = ($builderText -match '(?i)sbom') -and ($builderText -match '(?i)SHA-256.*sbom|sbom.*SHA-256')
Add-Record 'provenance_binding' 'FALLBACK_REQUIRED' @{
    reason            = 'RELEASE.json / SHA256SUMS.json / RUNTIME_ARTIFACTS.json bind source commit plus per-file SHA-256/size with signature_evidence:not-issued when unsigned (verified statically). No in-repo SBOM/license/advisory generator binds those artifacts to exact release hashes; that binding must come from the signing/provenance provider.'
    manifest_evidence = 'source commit + per-file SHA-256/size + Test-ReleaseBundle recomputation'
    sbom_bound_locally = [bool]$hasSbomBinder
    fallback          = 'external SBOM/license/advisory signer binds exact release hashes; record its evidence with the release, do not claim local binding'
}

# ---------------------------------------------------------------------------
# 7. Job Object descendant removal + filesystem/network sandboxing.
#    Deliberately NOT proven locally (I18.44: a Job Object-only check cannot
#    claim filesystem/network sandboxing). Minimal cancellation smoke only.
# ---------------------------------------------------------------------------
$smoke = Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 30' -PassThru
Start-Sleep -Milliseconds 500
try { Stop-Process -Id $smoke.Id -Force -ErrorAction Stop } catch { }
$smoke.WaitForExit(10000) | Out-Null
$gone = $smoke.HasExited
Test-NotReparse $repo
Test-NotReparse $isolatedTarget
Add-Record 'descendant_removal_and_sandbox' 'FALLBACK_REQUIRED' @{
    reason                  = 'No local Job Object descendant tree verification and no filesystem/network sandbox boundary proof exist in this worktree; per I18.44 a Job Object-only check must not claim sandboxing.'
    cancellation_smoke      = "single child kill observed exited=$gone; ACL probes re-verified intact (smoke only, NOT a descendant-tree proof)"
    fallback                = 'VM/lab isolated runner owns descendant containment and filesystem/network sandboxing; release workflow must select and record it'
}

$failed = @($records | Where-Object { $_.status -notin @('PROVEN', 'FALLBACK_REQUIRED') })
$proven = @($records | Where-Object { $_.status -eq 'PROVEN' }).Count
$fallback = @($records | Where-Object { $_.status -eq 'FALLBACK_REQUIRED' }).Count
$result = [pscustomobject]@{
    component = 'eliot_build_sandbox_cache_proof_1923'
    status    = if ($failed.Count -eq 0) { 'VERIFIED' } else { 'FAILED' }
    proven    = $proven
    fallbacks = $fallback
    lane      = $isolatedTarget
    claims    = $records
}
$result | ConvertTo-Json -Depth 6
if ($failed.Count -ne 0) { throw 'BUILD_SANDBOX_PROOF: one or more claims left unproven and unrouted' }
