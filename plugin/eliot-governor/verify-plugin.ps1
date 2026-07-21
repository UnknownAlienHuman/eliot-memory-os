$ErrorActionPreference = "Stop"

$pluginRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $pluginRoot "..\..")

Push-Location $repoRoot
try {
    cargo run -p eliot-app -- plugin verify
    cargo run -p eliot-app -- phase-f0 closeout
} finally {
    Pop-Location
}
