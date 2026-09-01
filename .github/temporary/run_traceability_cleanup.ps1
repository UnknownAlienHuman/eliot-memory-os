[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$originalBase = '35a0c7de93c84489684adf7730dca236f8335162'
$originalTree = '9c79b86ea5dc050415b9b0e4079e8ffe410eb917'
$branchName = 'fix/530-normative-traceability'
$setupHead = (git rev-parse HEAD).Trim()
$mergeBase = (git merge-base HEAD $originalBase).Trim()
if ($mergeBase -ne $originalBase) {
    throw "Branch does not descend from the declared base: $mergeBase"
}

$testTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
if (-not [IO.Path]::IsPathFullyQualified($testTemp) -or -not (Test-Path -LiteralPath $testTemp -PathType Container)) {
    throw "Runner temp is not an existing absolute directory: $testTemp"
}
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:CARGO_TARGET_DIR = Join-Path $testTemp 'eliot-issue-530-target'
$env:CARGO_INCREMENTAL = '0'
$env:CARGO_BUILD_JOBS = '4'
$env:CARGO_TERM_COLOR = 'always'
$env:RUST_BACKTRACE = '1'

New-Item -ItemType Directory -Force -Path .eliot | Out-Null

python -m pip install --disable-pip-version-check --no-input -r scripts/requirements-verification.txt
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python .github/temporary/traceability_cleanup.py --root .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
git diff --name-only | Out-File -FilePath .eliot/working-paths.txt -Encoding utf8

Remove-Item -LiteralPath .github/temporary/traceability_cleanup.py -Force
Remove-Item -LiteralPath .github/workflows/issue-530-traceability-cleanup.yml -Force

$paths = @(git diff --name-only $originalBase)
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
if ($paths.Count -lt 4) {
    throw "Expected a repository-wide comment cleanup; only $($paths.Count) paths changed"
}
foreach ($path in $paths) {
    $allowed = $path.EndsWith('.rs') -or
        $path -eq 'config/doc-code-conformance.toml' -or
        $path -eq 'scripts/doc_code_conformance_lib/normative_references.py' -or
        $path -eq 'scripts/doc_code_conformance_lib/rust_comments.py' -or
        $path -eq '.github/temporary/run_traceability_cleanup.ps1'
    if (-not $allowed) {
        throw "Unexpected candidate path: $path"
    }
}
$paths | Sort-Object | Out-File -FilePath .eliot/prepublish-paths.txt -Encoding utf8

python -m py_compile scripts/verify-doc-code-conformance.py scripts/doc_code_conformance_core.py scripts/doc_code_conformance_lib/*.py
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/verify-doc-code-conformance.py --self-test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/verify-doc-code-conformance.py --root . --json-out .eliot/doc-code-conformance.json
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

python scripts/docs_shards.py self-test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/docs_shards.py verify --root .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/docs_router.py self-test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/docs_router.py check --root .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
python scripts/docs_read.py self-test
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

pwsh -NoProfile -File scripts/verify.ps1
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

git diff --check $originalBase
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Remove-Item -LiteralPath .github/temporary/run_traceability_cleanup.ps1 -Force
if ((Test-Path -LiteralPath .github/temporary) -and -not (Get-ChildItem -LiteralPath .github/temporary -Force)) {
    Remove-Item -LiteralPath .github/temporary -Force
}

$finalPaths = @(git diff --name-only $originalBase)
foreach ($path in $finalPaths) {
    $allowed = $path.EndsWith('.rs') -or
        $path -eq 'config/doc-code-conformance.toml' -or
        $path -eq 'scripts/doc_code_conformance_lib/normative_references.py' -or
        $path -eq 'scripts/doc_code_conformance_lib/rust_comments.py'
    if (-not $allowed) {
        throw "Unexpected final path: $path"
    }
}
if ($finalPaths -contains '.github/temporary/traceability_cleanup.py' -or
    $finalPaths -contains '.github/temporary/run_traceability_cleanup.ps1' -or
    $finalPaths -contains '.github/workflows/issue-530-traceability-cleanup.yml') {
    throw 'Temporary execution files remain in the final diff'
}
$finalPaths | Sort-Object | Out-File -FilePath .eliot/final-paths.txt -Encoding utf8

git config user.name 'github-actions[bot]'
git config user.email '41898282+github-actions[bot]@users.noreply.github.com'
git add -A
$staged = @(git diff --cached --name-only)
if ($staged.Count -eq 0) {
    throw 'No candidate changes are staged'
}

git fetch --no-tags origin main
$remoteMain = (git rev-parse origin/main).Trim()
$remoteTree = (git rev-parse 'origin/main^{tree}').Trim()
if ($remoteTree -ne $originalTree) {
    throw "main content changed during verification: $remoteMain tree=$remoteTree"
}

git reset --soft $remoteMain
git commit -m 'fix(docs): retire invalid normative traceability' -m 'Remove the nonexistent I2.2 and pre-sharding documentation identities from Rust comments, validate plain Rust comment handles against the canonical indexes, and remove only satisfied legacy allowances. Runtime tokens remain unchanged.' -m 'Closes #530.'
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$candidate = (git rev-parse HEAD).Trim()
git push --force-with-lease="refs/heads/$branchName`:$setupHead" origin "HEAD:refs/heads/$branchName"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

@{
    status = 'PASS'
    setup_head = $setupHead
    parent = $remoteMain
    candidate = $candidate
    changed_paths = $finalPaths
} | ConvertTo-Json -Depth 8 | Out-File -FilePath .eliot/publication.json -Encoding utf8

Write-Host "TRACEABILITY_PUBLICATION: PASS candidate=$candidate paths=$($finalPaths.Count)"
