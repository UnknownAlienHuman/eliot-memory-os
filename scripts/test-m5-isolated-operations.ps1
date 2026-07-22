[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
try {
    & cargo build -p eliot-app
    if ($LASTEXITCODE -ne 0) {
        throw "M5 current Governor build failed with exit code $LASTEXITCODE"
    }
    $env:ELIOT_M5_GOVERNOR_EXE = (Resolve-Path -LiteralPath 'target/debug/eliot-governor.exe').Path
    & cargo test -p eliot-engine --test operations_runbook -- --nocapture
    if ($LASTEXITCODE -ne 0) {
        throw "M5 isolated backup/restore test failed with exit code $LASTEXITCODE"
    }
}
finally {
    Remove-Item Env:ELIOT_M5_GOVERNOR_EXE -ErrorAction SilentlyContinue
    Pop-Location
}
