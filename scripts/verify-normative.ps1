[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$verifier = Join-Path $PSScriptRoot 'docs_shards.py'

python $verifier self-test
if ($LASTEXITCODE -ne 0) {
    throw "VERIFY_NORMATIVE_FAIL: documentation verifier self-test failed"
}

python $verifier verify --root $repoRoot --normative-only
if ($LASTEXITCODE -ne 0) {
    throw "VERIFY_NORMATIVE_FAIL: sharded normative pair verification failed"
}

Write-Output 'NORMATIVE_VERIFY: PASS layout=eliot-doc-shards-v1 authority=main'
