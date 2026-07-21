[CmdletBinding()]
param(
    [string]$GovernorExe,
    [string]$McpbCli,
    [string]$PnpmCli,
    [string]$NpxCli
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceRoot = Join-Path $repoRoot 'integrations\claude\claude-desktop\mcpb'
$targetRoot = Join-Path $repoRoot 'target\claude-desktop-mcpb\eliot-governor'
$targetParent = [System.IO.Path]::GetFullPath((Split-Path $targetRoot -Parent))
$distRoot = Join-Path $repoRoot 'dist\claude'

if (-not $GovernorExe) {
    $GovernorExe = Join-Path $repoRoot 'target\release\eliot-governor.exe'
}
$GovernorExe = [System.IO.Path]::GetFullPath($GovernorExe)
if (-not (Test-Path -LiteralPath $GovernorExe -PathType Leaf)) {
    throw "release Governor binary is missing: $GovernorExe"
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'manifest.json') -PathType Leaf)) {
    throw "Claude Desktop manifest is missing under $sourceRoot"
}
$sourceManifest = Get-Content -LiteralPath (Join-Path $sourceRoot 'manifest.json') -Raw | ConvertFrom-Json
$packagePath = Join-Path $distRoot "eliot-$($sourceManifest.version)-windows-x64.mcpb"

if (Test-Path -LiteralPath $targetRoot) {
    $resolvedTarget = [System.IO.Path]::GetFullPath($targetRoot)
    if (-not $resolvedTarget.StartsWith($targetParent + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refusing to clean staging path outside target parent: $resolvedTarget"
    }
    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
}
New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $targetRoot 'server') -Force | Out-Null
New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
Copy-Item -Path (Join-Path $sourceRoot '*') -Destination $targetRoot -Recurse -Force
Copy-Item -LiteralPath $GovernorExe -Destination (Join-Path $targetRoot 'server\eliot-governor.exe')

if (-not $McpbCli) {
    $resolved = Get-Command mcpb -ErrorAction SilentlyContinue
    if ($resolved) {
        $McpbCli = $resolved.Source
    }
}
if (-not $PnpmCli -and -not $McpbCli) {
    $resolved = Get-Command pnpm -ErrorAction SilentlyContinue
    if ($resolved) {
        $PnpmCli = $resolved.Source
    }
}
if (-not $NpxCli -and -not $McpbCli -and -not $PnpmCli) {
    $resolved = Get-Command npx -ErrorAction SilentlyContinue
    if ($resolved) {
        $NpxCli = $resolved.Source
    }
}
if (-not $McpbCli -and -not $PnpmCli -and -not $NpxCli) {
    throw 'official MCPB CLI is unavailable; pass -McpbCli, -PnpmCli, or -NpxCli (the package runner is used only as a one-shot packager)'
}

function Invoke-Mcpb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    if ($McpbCli) {
        & $McpbCli @Arguments
    } elseif ($PnpmCli) {
        & $PnpmCli dlx '@anthropic-ai/mcpb@latest' @Arguments
    } else {
        & $NpxCli --yes '@anthropic-ai/mcpb@latest' @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "mcpb $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-McpbVersion {
    if ($McpbCli) {
        $output = @(& $McpbCli --version)
    } elseif ($PnpmCli) {
        $output = @(& $PnpmCli dlx '@anthropic-ai/mcpb@latest' --version)
    } else {
        $output = @(& $NpxCli --yes '@anthropic-ai/mcpb@latest' --version)
    }
    if ($LASTEXITCODE -ne 0) {
        throw "mcpb --version failed with exit code $LASTEXITCODE"
    }
    return ($output | Select-Object -First 1).Trim()
}

$mcpbVersion = Get-McpbVersion
$stagedGovernor = Join-Path $targetRoot 'server\eliot-governor.exe'
$buildManifest = [ordered]@{
    schema_version = 'eliot-claude-desktop-build-v1'
    extension_version = $sourceManifest.version
    target = 'windows-x64'
    mcpb_cli_version = $mcpbVersion
    manifest_schema = $sourceManifest.'$schema'
    manifest_sha256 = (Get-FileHash -LiteralPath (Join-Path $targetRoot 'manifest.json') -Algorithm SHA256).Hash
    governor_sha256 = (Get-FileHash -LiteralPath $stagedGovernor -Algorithm SHA256).Hash
    governor_source = $GovernorExe
    server_entry_point = $sourceManifest.server.entry_point
    host_argument = 'claude-desktop'
    another_governor_or_store_bundled = $false
    credentials_or_project_files_bundled = $false
    generated_at = [DateTimeOffset]::UtcNow.ToString('O')
}
$buildManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $targetRoot 'BUILD-MANIFEST.json') -Encoding utf8

Invoke-Mcpb validate $targetRoot
if (Test-Path -LiteralPath $packagePath) {
    Remove-Item -LiteralPath $packagePath -Force
}
Invoke-Mcpb pack $targetRoot $packagePath

$manifestPath = Join-Path $targetRoot 'manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$canonicalPath = Join-Path $repoRoot 'integrations\claude\canonical\connector.json'
$canonicalBytes = (Get-Item -LiteralPath $canonicalPath).Length
$package = Get-Item -LiteralPath $packagePath
$report = [ordered]@{
    schema_version = 'eliot-claude-desktop-package-report-v1'
    package = $package.FullName
    package_bytes = $package.Length
    package_sha256 = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash
    governor_sha256 = (Get-FileHash -LiteralPath $GovernorExe -Algorithm SHA256).Hash
    manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
    manifest_version = $manifest.manifest_version
    extension_version = $manifest.version
    mcpb_cli_version = $mcpbVersion
    server_type = $manifest.server.type
    entry_point = $manifest.server.entry_point
    host_argument = 'claude-desktop'
    compatibility = $manifest.compatibility
    another_governor_or_store_bundled = $false
    credentials_or_project_files_bundled = $false
    packager = if ($McpbCli) {
        $McpbCli
    } elseif ($PnpmCli) {
        "$PnpmCli dlx @anthropic-ai/mcpb@latest"
    } else {
        "$NpxCli --yes @anthropic-ai/mcpb@latest"
    }
    generated_at = [DateTimeOffset]::UtcNow.ToString('O')
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $distRoot 'compatibility-report.json') -Encoding utf8

$footprint = [ordered]@{
    schema_version = 'eliot-host-context-footprint-v1'
    host_surface = 'claude-desktop-mcpb'
    always_on_canonical_metadata_bytes = $canonicalBytes
    manifest_bytes = (Get-Item -LiteralPath $manifestPath).Length
    declared_tools = @($manifest.tools).Count
    generated_live_tool_upper_bound = 12
    declared_prompts = @($manifest.prompts).Count
    full_architecture_injected = $false
    full_skill_bodies_injected = $false
    expansion_policy = 'current state and handles first; exact evidence only on request'
    generated_at = [DateTimeOffset]::UtcNow.ToString('O')
}
$footprint | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $distRoot 'host-context-footprint.json') -Encoding utf8

Write-Output "CLAUDE_DESKTOP_MCPB=$packagePath"
Write-Output "CLAUDE_DESKTOP_MCPB_SHA256=$($report.package_sha256)"
