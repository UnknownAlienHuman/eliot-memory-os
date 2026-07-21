[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$localAppData = [IO.Path]::GetFullPath(
    [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
)
$testsRoot = [IO.Path]::GetFullPath((Join-Path $localAppData 'Eliot\tests'))
$testsPrefix = $testsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$sentinel = [IO.Path]::GetFullPath((Join-Path $testsRoot ("l14-unrelated-sentinel-{0}" -f [guid]::NewGuid().ToString('N'))))
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$probeRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ("eliot-l14-harness-probe-{0}" -f [guid]::NewGuid().ToString('N'))))

if (-not $sentinel.StartsWith($testsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFullPath((Split-Path $sentinel -Parent)) -ine $testsRoot) {
    throw 'harness sibling sentinel escaped the exact LOCALAPPDATA test root'
}
if (-not $probeRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'harness probe output escaped TEMP'
}

$ambientBefore = @{}
foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME')) {
    $ambientBefore[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

New-Item -ItemType Directory -Force $sentinel, $probeRoot | Out-Null
[IO.File]::WriteAllText((Join-Path $sentinel 'unrelated.txt'), 'task-owned sentinel')

try {
    $stdout = Join-Path $probeRoot 'stdout.txt'
    $stderr = Join-Path $probeRoot 'stderr.txt'
    $pwsh = (Get-Command pwsh.exe).Source
    $process = Start-Process -FilePath $pwsh -ArgumentList @(
        '-NoProfile',
        '-File',
        (Join-Path $repo 'scripts\run-isolated-tests.ps1'),
        '-InjectFailureAfterSecretSetup'
    ) -WorkingDirectory $repo -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
        -PassThru -WindowStyle Hidden
    if (-not $process.WaitForExit(30000)) {
        Stop-Process -Id $process.Id -Force
        throw 'bounded harness failure probe exceeded 30 seconds'
    }

    $lines = @(Get-Content -LiteralPath $stdout | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    })
    if ($lines.Count -eq 0) {
        throw "bounded harness failure probe emitted no report; exit=$($process.ExitCode)"
    }
    $report = $lines[-1] | ConvertFrom-Json
    $unrelatedUntouched = Test-Path -LiteralPath (Join-Path $sentinel 'unrelated.txt') -PathType Leaf
    $ambientPreserved = $true
    foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME')) {
        if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne $ambientBefore[$name]) {
            $ambientPreserved = $false
        }
    }
    $ownedRoot = [IO.Path]::GetFullPath([string]$report.owned_secret_root)

    if ($process.ExitCode -ne 97 -or
        $report.workspace_test_exit_code -ne 97 -or
        -not $report.bounded_failure_exercised -or
        -not $report.secret_reparse_checked -or
        -not $report.secret_acl_restricted -or
        -not $report.owned_secret_root_removed -or
        -not $report.temp_root_removed -or
        -not $report.ambient_user_roots_preserved -or
        -not $ambientPreserved -or
        -not $unrelatedUntouched -or
        (Test-Path -LiteralPath $ownedRoot) -or
        $report.secret_cleanup_scope -cne 'exact_recorded_run_root_only' -or
        [string]$report.secret_config_path -notmatch '^%LOCALAPPDATA%/Eliot/tests/[0-9a-f]{32}/secrets/surreal_root_password\.txt$' -or
        $report.provider_calls -ne 0) {
        throw "bounded harness failure probe contract mismatch; exit=$($process.ExitCode)"
    }

    [ordered]@{
        component = 'eliot_l14_harness_security_focused'
        failure_probe = 'passed'
        exit_code = $process.ExitCode
        ambient_user_roots_preserved = $true
        owned_secret_root_removed = $true
        unrelated_localappdata_sibling_untouched = $true
        secret_reparse_checked = $true
        secret_acl_restricted = $true
        secret_cleanup_scope = 'exact_recorded_run_root_only'
        provider_calls = 0
    } | ConvertTo-Json -Compress
}
finally {
    if ($sentinel.StartsWith($testsPrefix, [StringComparison]::OrdinalIgnoreCase) -and
        [IO.Path]::GetFullPath((Split-Path $sentinel -Parent)) -ieq $testsRoot -and
        (Test-Path -LiteralPath $sentinel)) {
        Remove-Item -LiteralPath $sentinel -Recurse -Force
    }
    if ($probeRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $probeRoot)) {
        Remove-Item -LiteralPath $probeRoot -Recurse -Force
    }
}
