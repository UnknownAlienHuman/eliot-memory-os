[CmdletBinding()]
param(
    [switch]$SkipCargoTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$governorExe = Join-Path $repoRoot 'target\release\eliot-governor.exe'
$referenceClient = Join-Path $PSScriptRoot 'eliot-mcp-reference-client.ps1'
$reportRoot = Join-Path $repoRoot '.eliot-governor\reports\claude-connector'
$reportPath = Join-Path $reportRoot 'latest.json'
$steps = [System.Collections.Generic.List[object]]::new()

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Add-PassedStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [hashtable]$Evidence = @{}
    )

    $steps.Add([ordered]@{
        name = $Name
        status = 'passed'
        evidence = $Evidence
    })
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $output = @(& $FilePath @ArgumentList 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Description failed with exit code ${exitCode}: $($output -join [Environment]::NewLine)"
    }
    return ($output -join [Environment]::NewLine)
}

function Assert-CompactClaudeSurface {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HostSurface,

        [Parameter(Mandatory = $true)]
        [string]$InstalledGovernor
    )

    $projectIdentityArguments = @{ project_key = $repoRoot } | ConvertTo-Json -Compress
    $json = & $referenceClient `
        -EliotExe $InstalledGovernor `
        -HostSurface $HostSurface `
        -Instance default `
        -ToolName eliot_project_identity `
        -ToolArgumentsJson $projectIdentityArguments `
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
    )
    $actualTools = @($result.tool_names | Sort-Object)
    $sortedExpectedTools = @($expectedTools | Sort-Object)

    Assert-True ($result.status -eq 'passed') "$HostSurface MCP reference client did not pass"
    Assert-True ($result.profile -eq 'claude_desktop') "$HostSurface resolved the wrong access profile"
    Assert-True ($actualTools.Count -eq 12) "$HostSurface exposed $($actualTools.Count) tools instead of 12"
    Assert-True (@(Compare-Object $actualTools $sortedExpectedTools).Count -eq 0) "$HostSurface compact tool set drifted"
    Assert-True (@($result.prompt_names).Count -eq 4) "$HostSurface exposed $(@($result.prompt_names).Count) prompts instead of 4"
    Assert-True ($null -eq $result.tool_call_error) "$HostSurface project identity read returned an MCP error"
    Assert-True ($null -ne $result.tool_call) "$HostSurface project identity read returned no structured content"

    Add-PassedStep "${HostSurface}_mcp_surface" @{
        installed_governor = $InstalledGovernor
        tools = $actualTools.Count
        prompts = @($result.prompt_names).Count
        profile = $result.profile
        agent_session_id = $result.agent_session.agent_session_id
    }
}

Push-Location $repoRoot
try {
    Assert-True (Test-Path -LiteralPath $governorExe -PathType Leaf) "release Governor binary is missing: $governorExe"
    Assert-True (Test-Path -LiteralPath $referenceClient -PathType Leaf) "reference client is missing: $referenceClient"

    $claudeDoctorText = Invoke-NativeChecked $governorExe @('host', 'doctor', '--host', 'claude') 'Claude Code doctor'
    $claudeDoctor = $claudeDoctorText | ConvertFrom-Json -Depth 40
    Assert-True ([bool]$claudeDoctor.ready) 'Claude Code doctor is not ready'
    Assert-True ([bool]$claudeDoctor.skill_pack.valid) 'Claude Code skill pack is invalid'
    Assert-True (@($claudeDoctor.skill_pack.entries).Count -eq 4) 'Claude Code does not expose exactly four ELIOT skills'
    Assert-True ([bool]$claudeDoctor.bundle.config_valid) 'Claude Code MCP config is invalid'
    Assert-True ([bool]$claudeDoctor.bundle.lifecycle_valid) 'Claude Code hooks config is invalid'
    Add-PassedStep 'claude_code_doctor' @{
        version = $claudeDoctor.profile.version
        skills = @($claudeDoctor.skill_pack.entries).Count
        pack_hash = $claudeDoctor.skill_pack.pack_hash
    }

    $desktopDoctorText = Invoke-NativeChecked $governorExe @('host', 'doctor', '--host', 'claude-desktop') 'Claude Desktop doctor'
    $desktopDoctor = $desktopDoctorText | ConvertFrom-Json -Depth 40
    Assert-True ([bool]$desktopDoctor.ready) 'Claude Desktop doctor is not ready'
    Assert-True ([bool]$desktopDoctor.install_receipt_exists) 'Claude Desktop install receipt is missing'
    Assert-True (-not [bool]$desktopDoctor.manual_claude_config_edit) 'Claude Desktop was installed by a manual config edit'
    Assert-True (-not [bool]$desktopDoctor.provider_auth_read_or_modified) 'Claude Desktop install touched provider authentication'
    Add-PassedStep 'claude_desktop_doctor' @{
        extension_id = $desktopDoctor.extension.extension_id
        version = $desktopDoctor.extension.version
        registry_hash = $desktopDoctor.extension.registry_hash
    }

    Invoke-NativeChecked $governorExe @('host', 'skill-lint') 'Claude skill lint' | Out-Null
    Add-PassedStep 'claude_skill_lint'

    $claudeExe = [string]$claudeDoctor.profile.executable_path
    Assert-True (Test-Path -LiteralPath $claudeExe -PathType Leaf) "Claude Code executable is missing: $claudeExe"
    $claudeVersion = Invoke-NativeChecked $claudeExe @('--version') 'Claude Code version probe'
    Assert-True ($claudeVersion -match '^2\.1\.207\b') "unexpected Claude Code version: $claudeVersion"

    $claudePluginRoot = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.claude\skills\eliot'
    $claudeInstalledGovernor = Join-Path $claudePluginRoot 'bin\eliot-governor.exe'
    Assert-True (Test-Path -LiteralPath $claudeInstalledGovernor -PathType Leaf) "installed Claude Code Governor is missing: $claudeInstalledGovernor"
    Invoke-NativeChecked $claudeExe @('plugin', 'validate', '--strict', $claudePluginRoot) 'Claude Code strict plugin validation' | Out-Null
    $mcpList = Invoke-NativeChecked $claudeExe @('mcp', 'list') 'Claude Code MCP health probe'
    Assert-True ($mcpList -match 'plugin:eliot:eliot:.*Connected') 'Claude Code ELIOT MCP server is not connected'
    Add-PassedStep 'claude_code_plugin_and_mcp' @{
        version = $claudeVersion.Trim()
        plugin_root = $claudePluginRoot
        mcp_connected = $true
    }

    $desktopInstalledGovernor = Join-Path ([string]$desktopDoctor.extension.extension_path) 'server\eliot-governor.exe'
    Assert-True (Test-Path -LiteralPath $desktopInstalledGovernor -PathType Leaf) "installed Claude Desktop Governor is missing: $desktopInstalledGovernor"
    $releaseSha256 = (Get-FileHash -LiteralPath $governorExe -Algorithm SHA256).Hash
    $claudeSha256 = (Get-FileHash -LiteralPath $claudeInstalledGovernor -Algorithm SHA256).Hash
    $desktopSha256 = (Get-FileHash -LiteralPath $desktopInstalledGovernor -Algorithm SHA256).Hash
    Assert-True ($releaseSha256 -eq $claudeSha256) 'Claude Code installed Governor differs from the release binary'
    Assert-True ($releaseSha256 -eq $desktopSha256) 'Claude Desktop installed Governor differs from the release binary'

    $packagePath = [string]$desktopDoctor.package_path
    Assert-True (Test-Path -LiteralPath $packagePath -PathType Leaf) "Claude Desktop MCPB package is missing: $packagePath"
    $packageSha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Assert-True ($packageSha256 -eq ([string]$desktopDoctor.extension.registry_hash).ToLowerInvariant()) 'Claude Desktop registry hash differs from the current MCPB package'
    Add-PassedStep 'installed_binary_and_package_parity' @{
        governor_sha256 = $releaseSha256
        package_sha256 = $packageSha256.ToUpperInvariant()
    }

    Assert-CompactClaudeSurface -HostSurface 'claude' -InstalledGovernor $claudeInstalledGovernor
    Assert-CompactClaudeSurface -HostSurface 'claude-desktop' -InstalledGovernor $desktopInstalledGovernor

    if (-not $SkipCargoTests) {
        Invoke-NativeChecked 'cargo' @('test', '-p', 'eliot-app', '--bin', 'eliot-governor', 'claude_desktop_', '--', '--nocapture', '--test-threads=1') 'Claude compact-profile tests' | Out-Null
        Add-PassedStep 'claude_compact_profile_tests' @{ command = 'cargo test -p eliot-app --bin eliot-governor claude_desktop_ -- --nocapture --test-threads=1' }

        $previousGovernorConfig = $env:ELIOT_GOVERNOR_CONFIG
        $previousPluginRoot = $env:ELIOT_GOVERNOR_PLUGIN_ROOT
        $env:ELIOT_GOVERNOR_CONFIG = Join-Path $repoRoot '.eliot-governor\config\governor.toml'
        $env:ELIOT_GOVERNOR_PLUGIN_ROOT = Join-Path $repoRoot 'plugin\eliot-governor'
        try {
            Invoke-NativeChecked 'cargo' @('test', '-p', 'eliot-app', '--test', 'plugin_hooks', '--', '--nocapture', '--test-threads=1') 'Claude plugin hook tests' | Out-Null
        }
        finally {
            if ($null -eq $previousGovernorConfig) {
                Remove-Item Env:ELIOT_GOVERNOR_CONFIG -ErrorAction SilentlyContinue
            } else {
                $env:ELIOT_GOVERNOR_CONFIG = $previousGovernorConfig
            }
            if ($null -eq $previousPluginRoot) {
                Remove-Item Env:ELIOT_GOVERNOR_PLUGIN_ROOT -ErrorAction SilentlyContinue
            } else {
                $env:ELIOT_GOVERNOR_PLUGIN_ROOT = $previousPluginRoot
            }
        }
        Add-PassedStep 'claude_plugin_hook_tests' @{ command = 'cargo test -p eliot-app --test plugin_hooks -- --nocapture --test-threads=1' }

        $testPasswordRoot = Join-Path $env:LOCALAPPDATA 'Eliot\tests\claude-connector'
        New-Item -ItemType Directory -Path $testPasswordRoot -Force | Out-Null
        $env:ELIOT_TEST_SURREAL_PASSWORD_FILE = Join-Path $testPasswordRoot 'surreal-password.txt'
        try {
            Invoke-NativeChecked 'cargo' @('test', '-p', 'eliot-app', '--test', 'multi_agent_access', 'facade_reconnects_after_rotation_and_replay_does_not_duplicate_memory', '--', '--exact', '--nocapture', '--test-threads=1') 'Claude facade reconnect test' | Out-Null
        }
        finally {
            Remove-Item Env:ELIOT_TEST_SURREAL_PASSWORD_FILE -ErrorAction SilentlyContinue
        }
        Add-PassedStep 'claude_facade_reconnect_test' @{ command = 'cargo test -p eliot-app --test multi_agent_access facade_reconnects_after_rotation_and_replay_does_not_duplicate_memory -- --exact --nocapture --test-threads=1' }
    }

    New-Item -ItemType Directory -Path $reportRoot -Force | Out-Null
    $report = [ordered]@{
        schema_version = 'eliot-claude-connector-test-v1'
        status = 'passed'
        scope = @('claude-code-connector', 'claude-desktop-mcpb')
        excluded = @('workspace-check', 'workspace-clippy', 'workspace-tests', 'other-phase-tests')
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
