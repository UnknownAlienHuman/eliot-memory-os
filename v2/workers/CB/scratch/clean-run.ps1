param([string]$Pattern = 'summary')
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
# Remove ONLY run roots this suite's own fixture created: leaf carries the
# fixture run id, owner marker names the fixture owner, marker is ours.
$runId = '0123456789abcdef0123456789abcdef'
$base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
foreach ($r in @(Get-ChildItem -LiteralPath $base -Directory -Filter 'eliot-store-*' -ErrorAction SilentlyContinue)) {
    if (($r.Name -split '-')[2] -ne $runId) { continue }
    $markerPath = Join-Path $r.FullName '.eliot-harness-owner.json'
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { continue }
    try { $rec = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    if ([string]$rec.run_id -ne $runId -or [string]$rec.owner -ne 'store-test-owner') { continue }
    Remove-Item -LiteralPath $r.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
$ErrorActionPreference = 'Stop'
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -NonInteractive -File 'scripts\tests\IntegrationHarness.Store.Tests.ps1' 2>&1 | Select-String -Pattern $Pattern | Out-String -Width 400
"pwsh-exit=$LASTEXITCODE"