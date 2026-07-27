[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Config,

    [Parameter(Mandatory = $true)]
    [string]$Confirm,

    [string]$Governor
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expectedConfirmation = 'CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY'
if ($Confirm -ne $expectedConfirmation) {
    throw "The exact confirmation token is required: $expectedConfirmation"
}

if (-not $Governor) {
    if ($env:ELIOT_UL_GOVERNOR_EXE) {
        $Governor = $env:ELIOT_UL_GOVERNOR_EXE
    }
    else {
        $Governor = Join-Path $env:LOCALAPPDATA 'Eliot\build\eliot-memory-os-target\release\eliot-governor.exe'
    }
}

$governorPath = (Resolve-Path -LiteralPath $Governor).Path
$configPath = (Resolve-Path -LiteralPath $Config).Path
$oneDrive = if ($env:OneDrive) {
    [System.IO.Path]::GetFullPath($env:OneDrive).TrimEnd('\')
}
else {
    $null
}
if ($oneDrive -and $governorPath.StartsWith($oneDrive, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "UL-11 requires the release Governor outside OneDrive: $governorPath"
}

& $governorPath --config $configPath ul cross-agent doctor
if ($LASTEXITCODE -ne 0) {
    throw "UL cross-agent doctor failed with exit code $LASTEXITCODE"
}

& $governorPath --config $configPath ul cross-agent run --confirm $Confirm
if ($LASTEXITCODE -ne 0) {
    throw "UL cross-agent certification failed with exit code $LASTEXITCODE"
}
