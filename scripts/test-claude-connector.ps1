[CmdletBinding()]
param(
    [switch]$SkipCargoTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$referenceClient = Join-Path $PSScriptRoot 'eliot-mcp-reference-client.ps1'
$packageRoot = if ($env:ELIOT_PACKAGE_ROOT) {
    [System.IO.Path]::GetFullPath($env:ELIOT_PACKAGE_ROOT)
} else {
    Join-Path $env:LOCALAPPDATA 'Eliot\packages'
}
$reportRoot = Join-Path $env:LOCALAPPDATA 'Eliot\reports\claude-connector'
$reportPath = Join-Path $reportRoot 'latest.json'
$steps = [System.Collections.Generic.List[object]]::new()

function Assert-True {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) { throw $Message }
}

function Add-PassedStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [hashtable]$Evidence = @{}
    )
    $steps.Add([ordered]@{ name = $Name; status = 'passed'; evidence = $Evidence })
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $output = @(& $FilePath @ArgumentList 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code ${LASTEXITCODE}: $($output -join [Environment]::NewLine)"
    }
    return ($output -join [Environment]::NewLine)
}

function Assert-CompactClaudeSurface {
    param(
        [Parameter(Mandatory = $true)][string]$HostSurface,
        [Parameter(Mandatory = $true)][string]$Governor
    )
    $arguments = @{ project_key = 'eliot-memory-os' } | ConvertTo-Json -Compress
    $json = & $referenceClient `
        -EliotExe $Governor `
        -HostSurface $HostSurface `
        -Instance default `
        -ToolName eliot_project_identity `
        -ToolArgumentsJson $arguments `
        -ClientName "eliot-${HostSurface}-connector-test" `
        -TimeoutSeconds 60
    $result = $json | ConvertFrom-Json -Depth 40
    $expectedTools = @(
        'eliot_task_state',
        'eliot_agent_candidate_submit',
        'eliot_host_session_status',
        'eliot_project_identity',
        'eliot_current_state',
        'eliot_recall_l0',
        'eliot_fetch_l2',
        'eliot_compile_packet_l3',
        'eliot_memory_influence_trace',
        'eliot_agent_delegate',
        'eliot_agent_result',
        'eliot_agent_result_disposition'
    ) | Sort-Object
    $actualTools = @($result.tool_names | Sort-Object)
    Assert-True ($result.status -eq 'passed') "$HostSurface MCP reference client did not pass"
    Assert-True ($result.profile -eq 'claude_governed') "$HostSurface resolved the wrong compact access profile"
    Assert-True (@(Compare-Object $actualTools $expectedTools).Count -eq 0) "$HostSurface compact tool set drifted"
    Assert-True (@($result.prompt_names).Count -eq 4) "$HostSurface must expose four prompts"
    Assert-True ($null -eq $result.tool_call_error) "$HostSurface project identity returned an MCP error"
    Add-PassedStep "${HostSurface}_mcp_surface" @{
        governor = $Governor
        tools = $actualTools.Count
        prompts = @($result.prompt_names).Count
        profile = $result.profile
    }
}

Push-Location $repoRoot
try {
    $metadata = (Invoke-NativeChecked 'cargo' @('metadata', '--format-version', '1', '--no-deps') 'Cargo metadata') | ConvertFrom-Json
    $governorExe = Join-Path ([string]$metadata.target_directory) 'release\eliot-governor.exe'
    Assert-True (Test-Path -LiteralPath $governorExe -PathType Leaf) "release Governor binary is missing: $governorExe"
    Assert-True (Test-Path -LiteralPath $referenceClient -PathType Leaf) "reference client is missing: $referenceClient"

    $family = (Invoke-NativeChecked $governorExe @('host', 'doctor', '--host', 'claude') 'Claude family doctor') | ConvertFrom-Json -Depth 50
    Assert-True ($family.status -eq 'ready') 'Claude family doctor is not ready'
    Assert-True ([int]$family.active_surface_count -eq 1) 'Claude must expose exactly one active ELIOT surface'
    Assert-True ($family.selected_surface -eq 'claude_code_plugin') 'Claude Code must be the selected surface for this smoke'
    Assert-True ([bool]$family.surfaces.claude_code_plugin.active) 'Claude Code plugin is not active'
    Assert-True (-not [bool]$family.surfaces.claude_desktop_mcpb.active) 'Claude Desktop MCPB must be inactive in Code mode'
    Assert-True (@($family.conflicts).Count -eq 0) 'Claude family doctor reported an integration conflict'
    Add-PassedStep 'claude_family_single_surface' @{
        selected_surface = $family.selected_surface
        active_surface_count = $family.active_surface_count
        claude_version = $family.detected_claude_code_version
    }

    $claudeExe = [string]$family.detected_claude_code_executable
    Assert-True (Test-Path -LiteralPath $claudeExe -PathType Leaf) "Claude executable is missing: $claudeExe"
    $inventory = (Invoke-NativeChecked $claudeExe @('plugin', 'list', '--json') 'Claude official plugin inventory') | ConvertFrom-Json -Depth 30
    $eliotEntries = @($inventory | Where-Object { $_.id -like 'eliot@*' })
    Assert-True ($eliotEntries.Count -eq 1) "Claude inventory contains $($eliotEntries.Count) ELIOT plugins instead of one"
    $plugin = $eliotEntries[0]
    Assert-True ($plugin.id -eq 'eliot@eliot-local') "unexpected Claude plugin id: $($plugin.id)"
    Assert-True ([bool]$plugin.enabled) 'official Claude plugin is disabled'
    $pluginRoot = [string]$plugin.installPath
    Assert-True (Test-Path -LiteralPath $pluginRoot -PathType Container) "installed plugin root is missing: $pluginRoot"
    Invoke-NativeChecked $claudeExe @('plugin', 'validate', '--strict', $pluginRoot) 'Claude strict plugin validation' | Out-Null

    $skills = @(Get-ChildItem -LiteralPath (Join-Path $pluginRoot 'skills') -Directory)
    $hooks = Get-Content -LiteralPath (Join-Path $pluginRoot 'hooks\hooks.json') -Raw | ConvertFrom-Json -Depth 30
    $hookEvents = @($hooks.hooks.PSObject.Properties.Name)
    $mcp = Get-Content -LiteralPath (Join-Path $pluginRoot '.mcp.json') -Raw | ConvertFrom-Json -Depth 20
    Assert-True ($skills.Count -eq 4) "installed plugin contains $($skills.Count) skills instead of four"
    Assert-True ($hookEvents.Count -eq 8) "installed plugin contains $($hookEvents.Count) hook events instead of eight"
    Assert-True (@($mcp.mcpServers.PSObject.Properties.Name).Count -eq 1) 'installed plugin must declare exactly one MCP server'
    Assert-True ($null -ne $mcp.mcpServers.eliot) 'installed plugin MCP server must be named eliot'

    $mcpList = Invoke-NativeChecked $claudeExe @('mcp', 'list') 'Claude MCP health probe'
    Assert-True ($mcpList -match 'plugin:eliot:eliot:.*Connected') 'Claude ELIOT MCP server is not connected'
    Add-PassedStep 'claude_official_plugin' @{
        id = $plugin.id
        version = $plugin.version
        install_path = $pluginRoot
        skills = $skills.Count
        hooks = $hookEvents.Count
        mcp_connected = $true
    }

    $installedGovernor = Join-Path $pluginRoot 'bin\eliot-governor.exe'
    Assert-True (Test-Path -LiteralPath $installedGovernor -PathType Leaf) "installed Governor is missing: $installedGovernor"
    $releaseSha256 = (Get-FileHash -LiteralPath $governorExe -Algorithm SHA256).Hash
    $installedSha256 = (Get-FileHash -LiteralPath $installedGovernor -Algorithm SHA256).Hash
    Assert-True ($releaseSha256 -eq $installedSha256) 'installed Claude Governor differs from the canonical release binary'

    $packageReportPath = Join-Path $packageRoot 'claude\compatibility-report.json'
    Assert-True (Test-Path -LiteralPath $packageReportPath -PathType Leaf) "Claude Desktop package report is missing: $packageReportPath"
    $packageReport = Get-Content -LiteralPath $packageReportPath -Raw | ConvertFrom-Json -Depth 20
    $desktopGovernor = Join-Path $packageRoot 'claude-desktop-mcpb\eliot-governor\server\eliot-governor.exe'
    $desktopManifest = Join-Path $packageRoot 'claude-desktop-mcpb\eliot-governor\manifest.json'
    Assert-True (Test-Path -LiteralPath $desktopGovernor -PathType Leaf) 'staged Desktop Governor is missing'
    Assert-True (Test-Path -LiteralPath $desktopManifest -PathType Leaf) 'generated Desktop manifest is missing'
    $desktopSha256 = (Get-FileHash -LiteralPath $desktopGovernor -Algorithm SHA256).Hash
    Assert-True ($releaseSha256 -eq $desktopSha256) 'staged Desktop Governor differs from the canonical release binary'
    $generatedManifest = Get-Content -LiteralPath $desktopManifest -Raw | ConvertFrom-Json -Depth 50
    Assert-True (@($generatedManifest.tools).Count -eq 12) 'generated MCPB manifest must contain twelve tools'
    Assert-True (@($generatedManifest.prompts).Count -eq 4) 'generated MCPB manifest must contain four prompts'
    Assert-True ([bool]$generatedManifest.tools_generated) 'MCPB tools were not marked generated'
    Assert-True ([bool]$generatedManifest.prompts_generated) 'MCPB prompts were not marked generated'
    Add-PassedStep 'binary_and_package_parity' @{
        governor_sha256 = $releaseSha256
        package_sha256 = $packageReport.package_sha256
        mcpb_cli_version = $packageReport.mcpb_cli_version
        tools = @($generatedManifest.tools).Count
        prompts = @($generatedManifest.prompts).Count
    }

    Assert-CompactClaudeSurface -HostSurface 'claude' -Governor $installedGovernor
    Assert-CompactClaudeSurface -HostSurface 'claude-desktop' -Governor $desktopGovernor

    if (-not $SkipCargoTests) {
        Invoke-NativeChecked 'cargo' @('test', '-p', 'eliot-app', '--test', 'plugin_hooks', '--', '--nocapture', '--test-threads=1') 'Claude hook tests' | Out-Null
        Add-PassedStep 'claude_hook_tests' @{ command = 'cargo test -p eliot-app --test plugin_hooks' }

        Invoke-NativeChecked 'cargo' @('test', '-p', 'eliot-app', 'claude_', '--', '--nocapture', '--test-threads=1') 'Claude integration unit tests' | Out-Null
        Add-PassedStep 'claude_integration_tests' @{ command = 'cargo test -p eliot-app claude_' }
    }

    New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
    $report = [ordered]@{
        schema_version = 'eliot-claude-connector-test-v2'
        status = 'passed'
        selected_surface = 'claude_code_plugin'
        cargo_tests_skipped = [bool]$SkipCargoTests
        steps = $steps
        generated_at = [DateTimeOffset]::UtcNow.ToString('O')
    }
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $reportPath -Encoding utf8
    $report | ConvertTo-Json -Depth 12
}
finally {
    Pop-Location
}
