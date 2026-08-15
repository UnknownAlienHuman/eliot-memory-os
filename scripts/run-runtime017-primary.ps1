[CmdletBinding()]
param(
    [string]$TargetRoot = "",
    [string]$ReportRoot = "",
    [switch]$KeepTarget
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($TargetRoot)) {
    $TargetRoot = Join-Path $env:TEMP "eliot-runtime017-primary-target"
}
if ([string]::IsNullOrWhiteSpace($ReportRoot)) {
    $ReportRoot = Join-Path $repo "artifacts/runtime017-primary"
}
$TargetRoot = [IO.Path]::GetFullPath($TargetRoot)
$ReportRoot = [IO.Path]::GetFullPath($ReportRoot)

if ($TargetRoot.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase)) {
    throw "TargetRoot must be outside the repository/worktrees: $TargetRoot"
}

New-Item -ItemType Directory -Force -Path $TargetRoot, $ReportRoot | Out-Null
$env:CARGO_TARGET_DIR = Join-Path $TargetRoot "cargo"
$env:CARGO_INCREMENTAL = "0"
$env:CARGO_BUILD_JOBS = "4"
$dotnetRoot = Join-Path $TargetRoot "dotnet"
New-Item -ItemType Directory -Force -Path $env:CARGO_TARGET_DIR, $dotnetRoot | Out-Null

$summary = [ordered]@{
    schema_version = "eliot-runtime017-primary-validation-v1"
    repo = $repo
    source_head = (& git -C $repo rev-parse HEAD).Trim()
    cargo_target_dir = $env:CARGO_TARGET_DIR
    dotnet_target_dir = $dotnetRoot
    started_at = (Get-Date).ToUniversalTime().ToString("o")
    steps = @()
    status = "running"
}

function Invoke-Step {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$Command
    )
    $log = Join-Path $ReportRoot ("{0}.log" -f $Name)
    $started = Get-Date
    try {
        & $Command *>&1 | Tee-Object -FilePath $log
        if ($LASTEXITCODE -ne 0) {
            throw "$Name exited with code $LASTEXITCODE"
        }
        $summary.steps += [ordered]@{
            name = $Name
            status = "passed"
            seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
            log = $log
        }
    }
    catch {
        $summary.steps += [ordered]@{
            name = $Name
            status = "failed"
            seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 3)
            log = $log
            error = $_.Exception.Message
        }
        throw
    }
}

try {
    Push-Location $repo
    Invoke-Step "01-generate-lockfile" { cargo generate-lockfile }
    Invoke-Step "02-metadata" { cargo metadata --no-deps --format-version 1 }
    Invoke-Step "03-fmt" { cargo fmt --all -- --check }
    Invoke-Step "04-check" { cargo check --workspace --all-targets }
    Invoke-Step "05-clippy" { cargo clippy --workspace --all-targets -- -D warnings }
    Invoke-Step "06-dotnet-restore" {
        dotnet restore apps/Eliot.Operator/Eliot.Operator.csproj `
            -p:BaseIntermediateOutputPath="$dotnetRoot/obj/" `
            -p:OutputPath="$dotnetRoot/bin/"
    }
    Invoke-Step "07-dotnet-build" {
        dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore `
            -p:BaseIntermediateOutputPath="$dotnetRoot/obj/" `
            -p:OutputPath="$dotnetRoot/bin/"
    }
    Invoke-Step "08-cargo-build" { cargo build --workspace --all-targets }
    $summary.status = "passed"
}
catch {
    $summary.status = "failed"
    $summary.error = $_.Exception.Message
    throw
}
finally {
    Pop-Location -ErrorAction SilentlyContinue
    $summary.finished_at = (Get-Date).ToUniversalTime().ToString("o")
    $summary.target_bytes = if (Test-Path $TargetRoot) {
        (Get-ChildItem -LiteralPath $TargetRoot -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    } else { 0 }
    $summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReportRoot "summary.json") -Encoding utf8
    if (-not $KeepTarget -and (Test-Path $TargetRoot)) {
        Remove-Item -LiteralPath $TargetRoot -Recurse -Force
    }
}
