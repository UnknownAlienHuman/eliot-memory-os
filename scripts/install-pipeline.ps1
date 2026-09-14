<#
.SYNOPSIS
    Root-controller install pipeline, steps 0 (optional developer reset), 4, and 5.

.DESCRIPTION
    Pipeline orchestrator:
    - Step 0 (if -Reset): Runs reset-developer-install.ps1. If -not $Install, exits 0.
    - Step 4: Runs invoke-eliot-windows-x64-production.ps1 for phase-a materialization.
    - Step 5: Runs eliot.exe installation apply for durable effects.
    Supports -WhatIf / dry-run.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Reset,
    [string]$Version = '0.1.0-rc11',
    [string]$Repo = (Resolve-Path "$PSScriptRoot\..").Path,
    [string]$LogDir,
    [string]$ReleaseRoot = (Join-Path $env:LOCALAPPDATA 'Eliot\packages'),
    [string]$SignTool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe',
    [string]$Thumbprint = 'FA2E37C6BF28E31154E7047552A22EB020AD9467',
    [string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$Installation = 'eliot-default',
    [string]$LineageId = 'eliot-default-lineage',
    [string]$Anchor = 'C:\ProgramData',
    [switch]$Install
)

$ErrorActionPreference = 'Stop'
$WhatIf = [bool]$WhatIfPreference

# Step 0: Developer reset
if ($Reset) {
    Write-Host "INSTALL step0 reset-developer-install"
    $global:LASTEXITCODE = 0
    & "$PSScriptRoot\reset-developer-install.ps1" -WhatIf:$WhatIf
    if ($LASTEXITCODE -ne 0) {
        throw "reset-developer-install failed with exit code $LASTEXITCODE"
    }
    if (-not $Install) {
        $global:LASTEXITCODE = 0
        exit 0
    }
}

$unsignedBundle = Join-Path $ReleaseRoot "eliot-windows-x64-$Version-unsigned"
$signedBundle   = Join-Path $ReleaseRoot "eliot-windows-x64-$Version"

$generation     = "generation-$Version"
$transactionId  = "install-$Version-" + (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$sha            = [System.Security.Cryptography.SHA256]::Create()
$installationKey = -join ($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Installation)) | ForEach-Object { $_.ToString('x2') })

$stagingRoot   = Join-Path $Anchor 'Eliot\packages'          # must be exactly <anchor>\Eliot\packages
$work          = Join-Path $env:LOCALAPPDATA "Eliot\install\$transactionId"

if ([string]::IsNullOrWhiteSpace($LogDir)) {
    $LogDir = Join-Path $work 'logs'
}

$outputBundle  = Join-Path $ReleaseRoot "eliot-windows-x64-$Version-phase-a-$transactionId"
$planOutput    = Join-Path $work 'transaction-plan.json'
$store         = Join-Path $work 'transaction.redb'
$recovery      = "eliot installation recover --store `"$store`" --transaction-id $transactionId"

Write-Host "INSTALL start transaction=$transactionId profile=system_service anchor=$Anchor key=$($installationKey.Substring(0,12))..."

if ($WhatIf) {
    Write-Host "WhatIf: [Planned step 4] Invoke production launcher:"
    Write-Host "  Launcher: `"$Repo\scripts\invoke-eliot-windows-x64-production.ps1`""
    Write-Host "  UnsignedBundle: $unsignedBundle"
    Write-Host "  SignedBundle: $signedBundle"
    Write-Host "  SignTool: $SignTool"
    Write-Host "  CertificateStoreLocation: Cert:\CurrentUser\My"
    Write-Host "  CertificateThumbprint: $Thumbprint"
    Write-Host "  TimestampUrl: $TimestampUrl"
    Write-Host "  OutputBundle: $outputBundle"
    Write-Host "  PlanOutput: $planOutput"
    Write-Host "  Store: $store"
    Write-Host "  Generation: $generation"
    Write-Host "  Installation: $Installation"
    Write-Host "  LineageId: $LineageId"
    Write-Host "  TransactionId: $transactionId"
    Write-Host "  StagingRoot: $stagingRoot"
    Write-Host "  Anchor: $Anchor"
    Write-Host "  InstallationKey: $installationKey"
    Write-Host "WhatIf: [Planned step 5] Apply installation:"
    Write-Host "  Executable: $(Join-Path $signedBundle 'runtime\eliot.exe')"
    Write-Host "  Arguments: installation apply --store `"$store`" --transaction-id $transactionId"
    $global:LASTEXITCODE = 0
    exit 0
}

if (-not (Test-Path -LiteralPath $work)) {
    New-Item -ItemType Directory -Force -Path $work | Out-Null
}
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

if (-not (Test-Path -LiteralPath $signedBundle)) {
    Write-Host "INSTALL STOP signed bundle missing: $signedBundle"
    $global:LASTEXITCODE = 10
    exit 10
}

# 4 ---------------------------------------------------------------------------------------------
& "$Repo\scripts\invoke-eliot-windows-x64-production.ps1" `
  -UnsignedBundle $unsignedBundle -SignedBundle $signedBundle -SignToolPath $SignTool `
  -CertificateStoreLocation 'Cert:\CurrentUser\My' -CertificateThumbprint $Thumbprint `
  -TimestampUrl $TimestampUrl `
  -OutputBundle $outputBundle -Output $planOutput -Store $store `
  -Generation $generation -Installation $Installation -LineageId $LineageId -Sequence 1 `
  -TransactionId $transactionId -StagingRoot $stagingRoot -MinimumStoreAvailableBytes 1073741824 `
  -RecoveryCommand $recovery -Profile system_service -ProfileAnchorRoot $Anchor `
  -InstallationKey $installationKey *> "$LogDir\4-production-launcher.log"
$rc = $LASTEXITCODE
$materialized = Select-String -Path "$LogDir\4-production-launcher.log" -Pattern 'SOURCE_BUNDLE_MATERIALIZED' -Quiet
Write-Host "INSTALL step4 production-launcher rc=$rc SOURCE_BUNDLE_MATERIALIZED=$materialized store=$(Test-Path -LiteralPath $store)"
if ($rc -ne 0 -or -not $materialized) {
    Write-Host "INSTALL STOP step4 - see `"$LogDir\4-production-launcher.log`""
    $global:LASTEXITCODE = 4
    exit 4
}

# 5 ---------------------------------------------------------------------------------------------
$cli = Join-Path $signedBundle 'runtime\eliot.exe'
& $cli installation apply --store $store --transaction-id $transactionId *> "$LogDir\5-installation-apply.log"
$rc = $LASTEXITCODE
Write-Host "INSTALL step5 installation-apply rc=$rc"
$svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Eliot' -or $_.DisplayName -match 'Eliot' } | ForEach-Object { "$($_.Name)=$($_.Status)/$($_.StartType)" }
Write-Host "INSTALL services: $($svc -join ', ')"
if ($rc -ne 0) {
    Write-Host "INSTALL STOP step5 rc=$rc - see `"$LogDir\5-installation-apply.log`"; rollback: $recovery"
    $global:LASTEXITCODE = 5
    exit 5
}
Write-Host "INSTALL done transaction=$transactionId store=$store"
$global:LASTEXITCODE = 0
exit 0
