[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "LINT_POLICY_VERIFY_FAIL: $Message"
}

function Read-Utf8([string] $Path) {
    try {
        return [Text.UTF8Encoding]::new($false, $true).GetString(
            [IO.File]::ReadAllBytes($Path)
        )
    }
    catch {
        Fail "cannot read strict UTF-8 file: $Path"
    }
}

function Read-TomlTable([string] $Text, [string] $Name) {
    $entries = [ordered]@{}
    $inside = $false
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*\[([^]]+)\]\s*$') {
            if ($inside) {
                break
            }
            $inside = $Matches[1] -ceq $Name
            continue
        }
        if (-not $inside) {
            continue
        }
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed -notmatch '^([A-Za-z0-9_-]+)\s*=\s*(.+?)\s*$') {
            Fail "unsupported entry in [$Name]: $trimmed"
        }
        $key = $Matches[1]
        if ($entries.Contains($key)) {
            Fail "duplicate key [$Name].$key"
        }
        $entries[$key] = ($Matches[2] -replace '\s+', '')
    }
    return $entries
}

function Assert-ExactTable(
    [string] $Subject,
    [System.Collections.IDictionary] $Expected,
    [System.Collections.IDictionary] $Actual
) {
    $expectedKeys = @($Expected.Keys | Sort-Object)
    $actualKeys = @($Actual.Keys | Sort-Object)
    if (($expectedKeys -join "`n") -cne ($actualKeys -join "`n")) {
        Fail "$Subject keys differ: expected=$($expectedKeys -join ',') actual=$($actualKeys -join ',')"
    }
    foreach ($key in $expectedKeys) {
        if ([string] $Expected[$key] -cne [string] $Actual[$key]) {
            Fail "$Subject value differs for ${key}: expected=$($Expected[$key]) actual=$($Actual[$key])"
        }
    }
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $rootManifest = Read-Utf8 (Join-Path $repoRoot 'Cargo.toml')
    $workspaceClippy = Read-TomlTable $rootManifest 'workspace.lints.clippy'
    if ($workspaceClippy.Count -eq 0) {
        Fail 'workspace.lints.clippy is empty or missing'
    }

    $ffiManifests = @(
        'bins/eliot-host/Cargo.toml'
        'bins/eliot-watchdog/Cargo.toml'
        'crates/eliot-windows-ipc/Cargo.toml'
        'crates/kernel/eliot-ipc/Cargo.toml'
        'crates/kernel/eliot-platform-windows/Cargo.toml'
    )
    $safeManifests = @(
        'crates/instrument/eliot-instrument-cargo/Cargo.toml'
        'crates/instrument/eliot-instrument-dotnet/Cargo.toml'
        'crates/instrument/eliot-instrument-runner/Cargo.toml'
        'crates/instrument/eliot-process-executor/Cargo.toml'
        'crates/kernel/eliot-host-state/Cargo.toml'
        'crates/supervision/eliot-watchdog-core/Cargo.toml'
    )

    foreach ($relativePath in $ffiManifests) {
        $text = Read-Utf8 (Join-Path $repoRoot $relativePath)
        Assert-ExactTable "$relativePath [lints.clippy]" $workspaceClippy (Read-TomlTable $text 'lints.clippy')

        $rust = Read-TomlTable $text 'lints.rust'
        if (-not $rust.Contains('unsafe_code') -or $rust['unsafe_code'] -cne '"allow"') {
            Fail "$relativePath must declare unsafe_code = `"allow`""
        }
        $allowedRustKeys = @('unsafe_code', 'unsafe_op_in_unsafe_fn')
        foreach ($key in $rust.Keys) {
            if ($allowedRustKeys -cnotcontains $key) {
                Fail "$relativePath has a non-minimal Rust lint override: $key"
            }
        }
        if ($rust.Contains('unsafe_op_in_unsafe_fn') -and $rust['unsafe_op_in_unsafe_fn'] -cne '"deny"') {
            Fail "$relativePath unsafe_op_in_unsafe_fn must be deny when declared"
        }
    }

    foreach ($relativePath in $safeManifests) {
        $text = Read-Utf8 (Join-Path $repoRoot $relativePath)
        $lints = Read-TomlTable $text 'lints'
        if ($lints.Count -ne 1 -or -not $lints.Contains('workspace') -or $lints['workspace'] -cne 'true') {
            Fail "$relativePath must inherit exactly [lints] workspace = true"
        }
        if ((Read-TomlTable $text 'lints.rust').Count -ne 0 -or
            (Read-TomlTable $text 'lints.clippy').Count -ne 0) {
            Fail "$relativePath mixes workspace inheritance with package lint overrides"
        }
    }

    $tracked = @(& git -C $repoRoot ls-files -- '*/Cargo.toml')
    if ($LASTEXITCODE -ne 0) {
        Fail 'git ls-files failed while discovering unsafe exceptions'
    }
    $discovered = @(
        foreach ($relativePath in $tracked) {
            $text = Read-Utf8 (Join-Path $repoRoot $relativePath)
            $rust = Read-TomlTable $text 'lints.rust'
            if ($rust.Contains('unsafe_code') -and $rust['unsafe_code'] -ceq '"allow"') {
                $relativePath.Replace('\', '/')
            }
        }
    ) | Sort-Object
    $expected = @($ffiManifests | Sort-Object)
    if (($discovered -join "`n") -cne ($expected -join "`n")) {
        Fail "unsafe exception set differs: expected=$($expected -join ',') actual=$($discovered -join ',')"
    }

    Write-Output "LINT_POLICY_VERIFY_PASS ffi_profiles=$($ffiManifests.Count) inherited_profiles=$($safeManifests.Count) clippy_keys=$($workspaceClippy.Count)"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
