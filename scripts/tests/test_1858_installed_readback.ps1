# Issue #1858 A1/AUD6: live readback over a local staged root.
# Copies the built exes into a TEMP install root with a fixture staged
# manifest, runs Invoke-InstalledEntrypointReadback without -WhatIf, and
# requires the typed classes: legacy_reject/legacy_redirect PASS on the
# retired governor arms, direct_canonical_bridge PASS on the bridge catalog
# arm, hook/evidence_only typed NOT_PERFORMED. No host install is claimed:
# the fixture root stands in for the staged bundle layout only.
param(
    [Parameter(Mandatory = $true)][string]$GovernorExe,
    [Parameter(Mandatory = $true)][string]$BridgeExe
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'lib' 'entrypoint-inventory.ps1')

if (-not (Test-Path -LiteralPath $GovernorExe -PathType Leaf)) { throw "governor exe absent: $GovernorExe" }
if (-not (Test-Path -LiteralPath $BridgeExe -PathType Leaf)) { throw "bridge exe absent: $BridgeExe" }
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('r1858-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    Copy-Item -LiteralPath $GovernorExe -Destination (Join-Path $root 'eliot-governor.exe')
    Copy-Item -LiteralPath $BridgeExe -Destination (Join-Path $root 'eliot-agent-bridge.exe')
    $behaviors = @(
        [ordered]@{ entrypoint = 'eliot-governor.exe daemon run'; launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('daemon', 'run') } },
        [ordered]@{ entrypoint = 'eliot-governor.exe service run'; launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('service', 'run') } },
        [ordered]@{ entrypoint = 'eliot-governor.exe mcp stdio codex'; launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('mcp', 'stdio', '--host', 'codex', '--profile', 'codex_controller') } },
        [ordered]@{ entrypoint = 'eliot-governor.exe mcp stdio claude'; launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('mcp', 'stdio', '--host', 'claude', '--profile', 'default') } },
        [ordered]@{ entrypoint = 'bridge hook session-start'; launch_configuration = [ordered]@{ command = 'eliot-agent-bridge.exe'; args = @('hook', 'session-start') } },
        [ordered]@{ entrypoint = 'hook entry'; launch_configuration = [ordered]@{ command = 'eliot-agent-bridge.exe'; hook_commands = @('hook SessionStart') } },
        [ordered]@{ entrypoint = 'evidence entry'; launch_configuration = [ordered]@{} }
    )
    $manifest = [ordered]@{ entries = @([ordered]@{ path = 'eliot-governor.exe'; entrypoint_behaviors = $behaviors }) }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'STAGED_PAYLOAD_MANIFEST.json') -Encoding utf8
    $snapshot = Invoke-InstalledEntrypointReadback $root '' @() 60
    $results = @($snapshot.results)
    if ($results.Count -ne $behaviors.Count) { throw "expected $($behaviors.Count) records, got $($results.Count)" }
    foreach ($record in $results) {
        $class = [string]$record.readback_class
        $status = [string]$record.status
        if ($record.entrypoint -like 'eliot-governor.exe *') {
            if ($class -notin @('legacy_reject', 'legacy_redirect')) { throw "$($record.entrypoint): expected a legacy class, got $class" }
            if ($status -cne 'PASS') { throw "$($record.entrypoint): expected PASS, got $status ($($record.detail))" }
        }
        elseif ($record.entrypoint -ceq 'bridge hook session-start') {
            if ($class -cne 'direct_canonical_bridge') { throw "bridge hook: expected direct_canonical_bridge, got $class" }
            if ($status -cne 'PASS') { throw "bridge hook: expected PASS, got $status ($($record.detail))" }
        }
        elseif ($record.entrypoint -ceq 'hook entry') {
            if ($class -cne 'hook' -or $status -cne 'NOT_PERFORMED') { throw "hook: expected hook/NOT_PERFORMED, got $class/$status" }
        }
        elseif ($record.entrypoint -ceq 'evidence entry') {
            if ($class -cne 'evidence_only' -or $status -cne 'NOT_PERFORMED') { throw "evidence: expected evidence_only/NOT_PERFORMED, got $class/$status" }
        }
        else { throw "unexpected record $($record.entrypoint)" }
    }
    if ([string]$snapshot.proof_ceiling -cnotmatch 'readback_class') { throw 'snapshot proof ceiling does not name the typed classes' }
    Write-Output 'READBACK-INSTALL-OK'
}
finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
