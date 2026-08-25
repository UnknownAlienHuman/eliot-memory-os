[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SchemaVersion = 'eliot-stu-observation-v1'
$Formula = 'ceil(UTF-8 bytes / 3)'
$WarningThreshold = 45000
$HardThreshold = 100000

function Fail([string] $Message) {
    throw "STU_MEASURE_FAIL: $Message"
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $gitOutput = @(& git -C $repoRoot ls-files --cached -- '*.rs' 2>&1)
    $gitExit = $LASTEXITCODE
    if ($gitExit -ne 0) {
        Fail "git ls-files exited ${gitExit}: $($gitOutput -join ' ')"
    }

    $relativePaths = @(
        $gitOutput |
            ForEach-Object { $_.ToString().Trim() } |
            Where-Object { $_ -ne '' }
    )
    if ($relativePaths.Count -eq 0) {
        Fail 'tracked Rust source set is empty'
    }
    [Array]::Sort($relativePaths, [StringComparer]::Ordinal)

    $utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
    $observations = [System.Collections.Generic.List[object]]::new()
    $seen = @{}

    foreach ($relativePath in $relativePaths) {
        if ($relativePath.Contains("`r") -or $relativePath.Contains("`n")) {
            Fail "tracked path contains a line break: $relativePath"
        }
        $normalizedPath = $relativePath.Replace('\', '/')
        if ($seen.ContainsKey($normalizedPath)) {
            Fail "duplicate tracked path: $normalizedPath"
        }
        $seen[$normalizedPath] = $true

        $nativeRelativePath = $normalizedPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $fullPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $nativeRelativePath))
        $rootPrefix = $repoRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            Fail "tracked path escapes repository root: $normalizedPath"
        }
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            Fail "tracked Rust file is missing: $normalizedPath"
        }

        $bytes = [IO.File]::ReadAllBytes($fullPath)
        try {
            $utf8Strict.GetString($bytes) | Out-Null
        }
        catch {
            Fail "tracked Rust file is not valid UTF-8: $normalizedPath"
        }
        $stu = [long][math]::Ceiling($bytes.Length / 3.0)
        if ($stu -ge $HardThreshold) {
            $label = 'AT_OR_ABOVE_100000'
        }
        elseif ($stu -ge $WarningThreshold) {
            $label = 'AT_OR_ABOVE_45000'
        }
        else {
            $label = 'BELOW_45000'
        }
        [void]$observations.Add([ordered]@{
                path = $normalizedPath
                utf8_bytes = [long]$bytes.Length
                stu = $stu
                provisional_label = $label
                blocking = $false
            })
    }

    $document = [ordered]@{
        schema_version = $SchemaVersion
        status = 'PROVISIONAL_NON_BLOCKING'
        formula = $Formula
        scope = 'tracked Rust source files (*.rs)'
        thresholds = [ordered]@{
            observation_45000 = $WarningThreshold
            observation_100000 = $HardThreshold
        }
        observations = $observations.ToArray()
    }
    # Keep each stdout record bounded for hosted Windows runners.  A compact
    # document currently exceeds 64 KiB on one line even though the payload is
    # valid; pretty JSON preserves the complete evidence while giving the
    # runner ordinary line boundaries to stream.
    $json = $document | ConvertTo-Json -Depth 8
    Write-Output $json
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
