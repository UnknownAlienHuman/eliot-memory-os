$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
function Remove-HarnessFixtureRoots {
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
}
Remove-HarnessFixtureRoots
"===== RUN 1 (fixture roots cleaned) ====="
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -NonInteractive -File 'scripts\tests\IntegrationHarness.Store.Tests.ps1' 2>&1 |
    Select-String -Pattern 'HarnessError|AssertionFailed|summary|note: store assertion' | Out-String -Width 400
"===== RUN 2 (no clean; roots left by run 1) ====="
& 'C:\Program Files\PowerShell\7\pwsh.exe' -NoProfile -NonInteractive -File 'scripts\tests\IntegrationHarness.Store.Tests.ps1' 2>&1 |
    Select-String -Pattern 'HarnessError|AssertionFailed|summary|note: store assertion' | Out-String -Width 400