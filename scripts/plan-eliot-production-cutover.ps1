[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$Config,
    [Parameter(Mandatory)]
    [string]$ProposedDataRoot,
    [Parameter(Mandatory)]
    [string]$Executable,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$resolvedExecutable = (Resolve-Path -LiteralPath $Executable).Path
$resolvedConfig = (Resolve-Path -LiteralPath $Config).Path
$json = & $resolvedExecutable --config $resolvedConfig cutover plan `
    --proposed-data-root $ProposedDataRoot `
    --executable $resolvedExecutable
if ($LASTEXITCODE -ne 0) {
    throw "cutover preflight failed with exit code $LASTEXITCODE"
}
if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $json | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
$json
