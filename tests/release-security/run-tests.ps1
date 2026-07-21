[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1')

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$root = Join-Path $tempBase "eliot-release-security-$([guid]::NewGuid().ToString('N'))"
try {
    $fixtureRepo = Join-Path $root 'repo'
    $source = Join-Path $fixtureRepo 'payload'
    $destination = Join-Path $root 'copied'
    New-Item -ItemType Directory -Path $source -Force | Out-Null
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

    [ordered]@{
        component = 'eliot_release_security_smoke'
        status = 'VERIFIED'
        tracked_only_copy = $true
        dirty_tracked_rejected = $true
        secret_fixture_rejected = $true
        utf16_fixture_rejected = $true
    } | ConvertTo-Json -Depth 3
}
finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
