$pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
$bad = 0
foreach ($c in 1..22) {
    $out = & $pwsh -NoProfile -NonInteractive -File 'scripts\tests\IntegrationHarness.Store.Tests.ps1' -CaseId $c 2>&1 | Out-String
    $code = $LASTEXITCODE
    $json = ($out -split "`n" | Where-Object { $_ -like '{*' } | Select-Object -First 1)
    $outcome = ''
    try { $outcome = ($json | ConvertFrom-Json).outcome } catch { $outcome = '<no json>' }
    $flag = ''
    if ($code -ne 0 -or $outcome -ne 'Passed') { $flag = '   <-- FAIL'; $bad++ }
    "case {0,2}  exit={1}  outcome={2}{3}" -f $c, $code, $outcome, $flag
}
"standalone failures = $bad"