[CmdletBinding()]
param(
    [string]$BridgeExe,
    [string]$ClientDeclaration,
    [string]$McpbCli,
    [string]$PnpmCli,
    [string]$NpxCli
)

$ErrorActionPreference = 'Stop'

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)
    $stream = [System.IO.File]::OpenRead($LiteralPath)
    try {
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '')
        }
        finally {
            $sha256.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceRoot = Join-Path $repoRoot 'integrations\claude\claude-desktop\mcpb'

# The MCPB CLI version is a build input. Resolving it as `@latest` means the
# same source can produce different package bytes on different days for reasons
# nobody recorded, so the exact verified version is pinned in source.
$toolVersions = Get-Content -LiteralPath (Join-Path $repoRoot 'tool-versions.json') -Raw | ConvertFrom-Json
$mcpbPackage = "$($toolVersions.tools.mcpb_cli.package)@$($toolVersions.tools.mcpb_cli.version)"

# The repository lives in OneDrive. Staging and package output are rebuildable
# and must not be synced: this is the same rule that kept 124 GB of Cargo output
# out of the source tree.
$packageCacheRoot = if ($env:ELIOT_PACKAGE_ROOT) {
    $env:ELIOT_PACKAGE_ROOT
} else {
    Join-Path $env:LOCALAPPDATA 'Eliot\packages'
}
$targetRoot = Join-Path $packageCacheRoot 'claude-desktop-mcpb\eliot-agent-bridge'
$targetParent = [System.IO.Path]::GetFullPath((Split-Path $targetRoot -Parent))
$distRoot = Join-Path $packageCacheRoot 'claude'

if (-not $BridgeExe) {
    # Cargo output is redirected out of OneDrive. Cargo metadata is the source
    # of truth even when an environment or developer-local config overrides it.
    # The default packager input is the pinned bridge build
    # (`cargo --locked -p eliot-agent-bridge --bin eliot-agent-bridge`).
    $metadataText = @(& cargo metadata --format-version 1 --no-deps 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed: $($metadataText -join [Environment]::NewLine)"
    }
    $cargoTargetDir = [string](($metadataText -join [Environment]::NewLine) | ConvertFrom-Json).target_directory
    if (-not $cargoTargetDir) { throw 'cargo metadata returned no target_directory' }
    $BridgeExe = Join-Path $cargoTargetDir 'release\eliot-agent-bridge.exe'
}
$BridgeExe = [System.IO.Path]::GetFullPath($BridgeExe)
if (-not (Test-Path -LiteralPath $BridgeExe -PathType Leaf)) {
    throw "release bridge binary is missing: $BridgeExe"
}
if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot 'manifest.json') -PathType Leaf)) {
    throw "Claude Desktop manifest is missing under $sourceRoot"
}
$sourceManifest = Get-Content -LiteralPath (Join-Path $sourceRoot 'manifest.json') -Raw | ConvertFrom-Json
$packagePath = Join-Path $distRoot "eliot-$($sourceManifest.version)-windows-x64.mcpb"
$bridgeSha256 = Get-Sha256Hex $BridgeExe
$priorReportPath = Join-Path $distRoot 'compatibility-report.json'
if (Test-Path -LiteralPath $priorReportPath -PathType Leaf) {
    $priorReport = Get-Content -LiteralPath $priorReportPath -Raw | ConvertFrom-Json
    if ([string]$priorReport.extension_version -eq [string]$sourceManifest.version -and
        [string]$priorReport.bridge_sha256 -and
        -not ([string]$priorReport.bridge_sha256).Equals($bridgeSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Claude Desktop extension version $($sourceManifest.version) already identifies different package bytes; bump integrations/claude/claude-desktop/mcpb/manifest.json before rebuilding"
    }
}

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
Copy-Item -LiteralPath $BridgeExe -Destination (Join-Path $targetRoot 'server\eliot-agent-bridge.exe')

# Producer (issue #18 P3): stage the installation-owned client declaration
# by COPY, never generation — the same rule as the Claude Code front-door
# staging (crates/eliot-app/src/host_runtime/integration.rs:2723-2741).
# Resolution order: explicit -ClientDeclaration (caller-supplied
# installation-owned file wins); otherwise the installation root holding
# the approved bridge binary (<root>/agent-bridge/client-declaration-v2.json
# beside <root>/bin/eliot-agent-bridge.exe). Symlinks are refused. Absent
# everywhere: stage nothing here — the launch-argv gate below refuses the
# package with the producer contract instead of shipping an unlaunchable
# bundle.
$declarationSource = $null
if ($ClientDeclaration) {
    $resolvedDeclaration = [System.IO.Path]::GetFullPath($ClientDeclaration)
    if (-not (Test-Path -LiteralPath $resolvedDeclaration -PathType Leaf)) {
        throw "explicit -ClientDeclaration is missing: $resolvedDeclaration"
    }
    $declarationSource = $resolvedDeclaration
} else {
    $bridgeParent = Split-Path $BridgeExe -Parent
    $installedDeclaration = Join-Path (Split-Path $bridgeParent -Parent) 'agent-bridge\client-declaration-v2.json'
    if (Test-Path -LiteralPath $installedDeclaration -PathType Leaf) {
        $declarationSource = [System.IO.Path]::GetFullPath($installedDeclaration)
    }
}
$stagedDeclarationSha256 = $null
$stagedDeclarationSource = $null
if ($declarationSource) {
    if ((Get-Item -LiteralPath $declarationSource).LinkType) {
        throw "refuse client declaration symlink: $declarationSource"
    }
    $stagedDeclarationDir = Join-Path $targetRoot 'server\agent-bridge'
    New-Item -ItemType Directory -Path $stagedDeclarationDir -Force | Out-Null
    Copy-Item -LiteralPath $declarationSource -Destination (Join-Path $stagedDeclarationDir 'client-declaration-v2.json') -Force
    $stagedDeclarationSha256 = Get-Sha256Hex (Join-Path $stagedDeclarationDir 'client-declaration-v2.json')
    $stagedDeclarationSource = $declarationSource
}

# The bridge is the only tool/prompt catalog authority. The tracked manifest
# is deliberately just a package template; materialize the MCPB metadata from
# the exact binary being bundled so package claims cannot drift from runtime.
$catalogOutput = @(& $BridgeExe mcp catalog --host claude --surface desktop)
if ($LASTEXITCODE -ne 0) {
    throw "bridge MCP catalog generation failed with exit code $LASTEXITCODE"
}
$catalog = ($catalogOutput -join [Environment]::NewLine) | ConvertFrom-Json
if ($catalog.schema_version -ne 'eliot-mcp-catalog-v2') {
    throw "unexpected bridge MCP catalog schema: $($catalog.schema_version)"
}
if (@($catalog.mcpb_tools).Count -eq 0 -or @($catalog.mcpb_prompts).Count -eq 0) {
    throw 'bridge MCP catalog did not produce MCPB tools and prompts'
}
$targetManifestPath = Join-Path $targetRoot 'manifest.json'
$targetManifest = Get-Content -LiteralPath $targetManifestPath -Raw | ConvertFrom-Json
$targetManifest.tools = @($catalog.mcpb_tools)
$targetManifest.tools_generated = $true
$targetManifest.prompts = @($catalog.mcpb_prompts)
$targetManifest.prompts_generated = $true
$targetManifestJson = $targetManifest | ConvertTo-Json -Depth 50
[System.IO.File]::WriteAllText(
    $targetManifestPath,
    $targetManifestJson + [Environment]::NewLine,
    (New-Object System.Text.UTF8Encoding($false))
)

# The staged manifest launch argv names an installation-owned client
# declaration (issue #18 W12/AUD-5848256288-2). The packager must not invent
# installation authority, so a staged package whose launch declaration is
# absent fails here with the producer contract instead of shipping a bundle
# whose entry point cannot launch: the installation side materializes
# server/agent-bridge/client-declaration-v2.json (agent-bridge profile
# contract), and the bridge re-validates it (path shape, digest, live Kernel
# challenge) before serving.
$launchArgs = @($targetManifest.server.mcp_config.args)
for ($i = 0; $i -lt $launchArgs.Count; $i++) {
    if ($launchArgs[$i] -eq '--client-declaration' -and ($i + 1) -lt $launchArgs.Count) {
        $declaredRelative = [string]$launchArgs[$i + 1] -replace '^\$\{__dirname\}/', ''
        $stagedDeclaration = Join-Path $targetRoot ($declaredRelative -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $stagedDeclaration -PathType Leaf)) {
            throw "refusing to package a Desktop bundle whose launch declaration is absent: $declaredRelative is not staged under $targetRoot. The client declaration is installation-owned (materialized by the installation side under the agent-bridge profile contract); the packager must not invent it. Wire the installer producer before packaging."
        }
    }
}

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
        & $PnpmCli dlx $mcpbPackage @Arguments
    } else {
        & $NpxCli --yes $mcpbPackage @Arguments
    }
    if ($LASTEXITCODE -ne 0) {
        throw "mcpb $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}

function Get-McpbVersion {
    if ($McpbCli) {
        $output = @(& $McpbCli --version)
    } elseif ($PnpmCli) {
        $output = @(& $PnpmCli dlx $mcpbPackage --version)
    } else {
        $output = @(& $NpxCli --yes $mcpbPackage --version)
    }
    if ($LASTEXITCODE -ne 0) {
        throw "mcpb --version failed with exit code $LASTEXITCODE"
    }
    return ($output | Select-Object -First 1).Trim()
}

$mcpbVersion = Get-McpbVersion
# A pin that is never checked is a comment. If an explicitly supplied CLI or a
# cached package runner resolves to something else, the package was not built
# with the toolchain this repository claims, and the build says so.
$pinnedMcpbVersion = $toolVersions.tools.mcpb_cli.version
if ($mcpbVersion -ne $pinnedMcpbVersion) {
    throw "MCPB CLI version mismatch: tool-versions.json pins $pinnedMcpbVersion but the packager reports $mcpbVersion"
}
$stagedBridge = Join-Path $targetRoot 'server\eliot-agent-bridge.exe'
$buildManifest = [ordered]@{
    schema_version = 'eliot-claude-desktop-build-v1'
    extension_version = $sourceManifest.version
    target = 'windows-x64'
    mcpb_cli_version = $mcpbVersion
    manifest_schema = $sourceManifest.'$schema'
    manifest_sha256 = Get-Sha256Hex (Join-Path $targetRoot 'manifest.json')
    bridge_sha256 = $bridgeSha256
    bridge_source = $BridgeExe
    declaration_sha256 = $stagedDeclarationSha256
    declaration_source = $stagedDeclarationSource
    server_entry_point = $sourceManifest.server.entry_point
    host_argument = 'claude-desktop'
    another_bridge_or_store_bundled = $false
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
    package_sha256 = Get-Sha256Hex $packagePath
    bridge_sha256 = $bridgeSha256
    manifest_sha256 = Get-Sha256Hex $manifestPath
    manifest_version = $manifest.manifest_version
    extension_version = $manifest.version
    mcpb_cli_version = $mcpbVersion
    server_type = $manifest.server.type
    entry_point = $manifest.server.entry_point
    host_argument = 'claude-desktop'
    compatibility = $manifest.compatibility
    another_bridge_or_store_bundled = $false
    credentials_or_project_files_bundled = $false
    packager = if ($McpbCli) {
        $McpbCli
    } elseif ($PnpmCli) {
        "$PnpmCli dlx $mcpbPackage"
    } else {
        "$NpxCli --yes $mcpbPackage"
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
