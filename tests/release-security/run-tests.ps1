[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1')

$metadata = (& cargo metadata --format-version 1 --no-deps 2>$null | Out-String) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'failed to load Cargo metadata for runtime artifact contract tests'
}
$runtimePlan = @(Get-RuntimeArtifactPlan $metadata)
$expectedRuntime = @(
    'eliot/eliot/cli/runtime/eliot.exe'
    'eliot-host/eliot-host/host/runtime/eliot-host.exe'
    'eliot-watchdog/eliot-watchdog/watchdog/runtime/eliot-watchdog.exe'
    'eliot-kernel/eliot-kernel/kernel/runtime/eliot-kernel.exe'
    'eliot-store-surreal/eliot-store-surreal/store_bridge/runtime/eliot-store-surreal.exe'
    'eliotd/eliotd/daemon/runtime/eliotd.exe'
)
$actualRuntime = @($runtimePlan | ForEach-Object { "$($_.package)/$($_.binary)/$($_.role)/$($_.relative_path)" })
if ($actualRuntime.Count -ne $expectedRuntime.Count -or
    (Compare-Object -ReferenceObject $expectedRuntime -DifferenceObject $actualRuntime).Count -ne 0) {
    throw 'Cargo runtime package/bin contract does not match the SystemService contour'
}
$missingMetadata = [pscustomobject]@{
    target_directory = $metadata.target_directory
    packages = @($metadata.packages | Where-Object { [string]$_.name -ne 'eliot-watchdog' })
}
$missingRejected = $false
try {
    Get-RuntimeArtifactPlan $missingMetadata | Out-Null
}
catch {
    $missingRejected = $_.Exception.Message -match 'eliot-watchdog'
}
if (-not $missingRejected) {
    throw 'missing runtime package metadata was not rejected'
}

$externalPathRejected = $false
try {
    Get-VerifiedPinnedSurrealArtifact 'surreal.exe' ('0' * 64) '3.1.4' | Out-Null
}
catch {
    $externalPathRejected = $_.Exception.Message -match 'explicit absolute path'
}
if (-not $externalPathRejected) {
    throw 'implicit PATH/relative surreal.exe resolution was not rejected'
}

$externalPinRejected = $false
try {
    Get-VerifiedPinnedSurrealArtifact (Join-Path $env:SystemRoot 'System32\cmd.exe') ('0' * 64) '3.1.4' | Out-Null
}
catch {
    $externalPinRejected = $_.Exception.Message -match 'resident regular non-reparse|canonical surreal.exe'
}
if (-not $externalPinRejected) {
    throw 'non-canonical surreal executable substitution was not rejected'
}

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$root = Join-Path $tempBase "eliot-release-security-$([guid]::NewGuid().ToString('N'))"
try {
    $fixtureRepo = Join-Path $root 'repo'
    $source = Join-Path $fixtureRepo 'payload'
    $destination = Join-Path $root 'copied'
    New-Item -ItemType Directory -Path $source -Force | Out-Null
    $notPe = Join-Path $root 'not-pe.exe'
    Set-Content -LiteralPath $notPe -Value 'not a PE' -Encoding ascii
    $architectureRejected = $false
    try {
        Assert-WindowsX64Pe $notPe 'not-pe.exe'
    }
    catch {
        $architectureRejected = $_.Exception.Message -match 'not a PE executable'
    }
    if (-not $architectureRejected) {
        throw 'non-PE external artifact was not rejected'
    }
    Set-Content -LiteralPath (Join-Path $source 'tracked.txt') -Value 'tracked release payload' -Encoding utf8
    Set-Content -LiteralPath (Join-Path $source 'untracked.txt') -Value 'must not be staged' -Encoding utf8
    & git -C $fixtureRepo init --quiet
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to initialize release security fixture repository'
    }
    & git -C $fixtureRepo add -- payload/tracked.txt
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to stage the tracked release security fixture'
    }
    & git -C $fixtureRepo -c user.name=Eliot -c user.email=eliot.invalid commit --quiet -m fixture
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to commit the tracked release security fixture'
    }
    $sourceCommit = (& git -C $fixtureRepo rev-parse HEAD | Out-String).Trim()

    Copy-TrackedTree $fixtureRepo $sourceCommit 'payload' $destination
    if (-not (Test-Path -LiteralPath (Join-Path $destination 'tracked.txt') -PathType Leaf)) {
        throw 'tracked payload was not copied'
    }
    if (Test-Path -LiteralPath (Join-Path $destination 'untracked.txt')) {
        throw 'untracked payload crossed the release boundary'
    }

    Set-Content -LiteralPath (Join-Path $source 'tracked.txt') -Value 'dirty tracked payload' -Encoding utf8
    $dirtyRejected = $false
    try {
        Copy-TrackedTree $fixtureRepo $sourceCommit 'payload' (Join-Path $root 'dirty-copy')
    }
    catch {
        $dirtyRejected = $_.Exception.Message -match 'differs from pinned commit'
    }
    if (-not $dirtyRejected) {
        throw 'dirty tracked payload was not rejected against the pinned commit'
    }

    $scanRoot = Join-Path $root 'scan'
    New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
    $syntheticCredential = 'github_' + 'pat_' + ('A' * 40)
    Set-Content -LiteralPath (Join-Path $scanRoot 'payload.json') -Value "{`"api_key`":`"$syntheticCredential`"}" -Encoding utf8
    $rejected = $false
    try {
        Assert-NoReleaseSecrets $scanRoot
    }
    catch {
        $rejected = $_.Exception.Message -match 'secret scan matched'
    }
    if (-not $rejected) {
        throw 'high-confidence credential fixture was not rejected'
    }
    Remove-Item -LiteralPath (Join-Path $scanRoot 'payload.json')
    $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbGlvdCJ9.signaturebytes'
    [System.IO.File]::WriteAllText(
        (Join-Path $scanRoot 'utf16.txt'),
        "Authorization: Basic mustnotpersist12`r`n$jwt",
        [System.Text.Encoding]::Unicode)
    $utf16Rejected = $false
    try {
        Assert-NoReleaseSecrets $scanRoot
    }
    catch {
        $utf16Rejected = $_.Exception.Message -match 'secret scan matched'
    }
    if (-not $utf16Rejected) {
        throw 'UTF-16 credential fixture was not rejected'
    }

    $documentationRoot = Join-Path $root 'documentation-scan'
    $operationsDocs = Join-Path $documentationRoot 'docs\operations'
    New-Item -ItemType Directory -Path $operationsDocs -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $operationsDocs 'SURREALDB_CREDENTIAL_AUTHORITY.md') -Value '# Credential authority' -Encoding utf8
    Assert-NoReleaseSecrets $documentationRoot

    Set-Content -LiteralPath (Join-Path $scanRoot 'credential.json') -Value '{"status":"redacted"}' -Encoding utf8
    $secretNameRejected = $false
    try {
        Assert-NoReleaseSecrets $scanRoot
    }
    catch {
        $secretNameRejected = $_.Exception.Message -match 'secret-like filename'
    }
    if (-not $secretNameRejected) {
        throw 'secret-like non-document filename was not rejected'
    }

    [ordered]@{
        component = 'eliot_release_security_smoke'
        status = 'VERIFIED'
        tracked_only_copy = $true
        dirty_tracked_rejected = $true
        secret_fixture_rejected = $true
        utf16_fixture_rejected = $true
        credential_document_name_allowed = $true
        secret_filename_rejected = $true
        surreal_path_pin_required = $true
        surreal_filename_pin_rejected = $true
        non_pe_artifact_rejected = $true
    } | ConvertTo-Json -Depth 3
}
finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
