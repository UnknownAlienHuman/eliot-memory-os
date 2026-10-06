# Issue #1858 A1/AUD6: unit tests for Get-EntrypointReadbackClass.
# Pure decision, no process, no install, no manifest.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'lib' 'entrypoint-inventory.ps1')

function Assert-Class([string]$Case, [string]$Actual, [string]$Expected) {
    if ($Actual -cne $Expected) {
        throw "case $Case expected class $Expected, got $Actual"
    }
}

$cutover = 'status=ERROR code=LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER canonical_route=r'
$redirectErr = 'status=REDIRECT canonical_route=r'
$redirectOut = 'status=ERROR code=LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER canonical_route=r'

Assert-Class 'hook-commands' (Get-EntrypointReadbackClass 'eliot-governor.exe' @('hook-cmd') '' '' 0 $false $false) 'hook'
Assert-Class 'hook-variable' (Get-EntrypointReadbackClass '$host\bin\x.exe' @() '' '' 0 $false $false) 'hook'
Assert-Class 'hook-env-marker' (Get-EntrypointReadbackClass '{env:X}\bin\x.exe' @() '' '' 0 $false $false) 'hook'
Assert-Class 'evidence-null' (Get-EntrypointReadbackClass $null @() '' '' 0 $false $false) 'evidence_only'
Assert-Class 'evidence-blank' (Get-EntrypointReadbackClass '   ' @() '' '' 0 $false $false) 'evidence_only'
Assert-Class 'legacy-reject' (Get-EntrypointReadbackClass 'eliot-governor.exe' @() $cutover '' 1 $true $false) 'legacy_reject'
Assert-Class 'legacy-redirect' (Get-EntrypointReadbackClass 'eliot-governor.exe' @() $redirectOut $redirectErr 1 $true $false) 'legacy_redirect'
Assert-Class 'redirect-needs-pair' (Get-EntrypointReadbackClass 'eliot-governor.exe' @() 'code=LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER canonical_route=r' $redirectErr 1 $true $false) 'legacy_reject'
Assert-Class 'direct-bridge' (Get-EntrypointReadbackClass 'eliot-agent-bridge.exe' @() '{"tools":["eliot.state"]}' '' 0 $false $true) 'direct_canonical_bridge'
Assert-Class 'direct-hook' (Get-EntrypointReadbackClass 'eliot-agent-bridge.exe' @() '{"continue":true}' '' 0 $false $true) 'direct_canonical_bridge'
Assert-Class 'bridge-no-marker' (Get-EntrypointReadbackClass 'eliot-agent-bridge.exe' @() '{"tools":[]}' '' 0 $false $true) 'unmatched'
Assert-Class 'bridge-needs-exit0' (Get-EntrypointReadbackClass 'eliot-agent-bridge.exe' @() '{"tools":["eliot.state"]}' '' 69 $false $true) 'unmatched'
Assert-Class 'unmatched-quiet' (Get-EntrypointReadbackClass 'eliot-governor.exe' @() 'hello' '' 0 $false $false) 'unmatched'
Assert-Class 'unmatched-non1' (Get-EntrypointReadbackClass 'eliot-governor.exe' @() $cutover '' 2 $true $false) 'unmatched'

Write-Output 'READBACK-CLASS-OK'
