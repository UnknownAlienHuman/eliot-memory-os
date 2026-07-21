$ErrorActionPreference = "Stop"

$pluginRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $pluginRoot "..\..")
$binary = Join-Path $repoRoot "target\debug\eliot-governor.exe"

Push-Location $repoRoot
try {
    cargo build -p eliot-app
} finally {
    Pop-Location
}

$bundleBin = Join-Path $pluginRoot "bin"
New-Item -ItemType Directory -Path $bundleBin -Force | Out-Null
Copy-Item -LiteralPath $binary -Destination (Join-Path $bundleBin "eliot-governor.exe") -Force

Push-Location $repoRoot
try {
    cargo run -p eliot-app -- plugin verify
} finally {
    Pop-Location
}
