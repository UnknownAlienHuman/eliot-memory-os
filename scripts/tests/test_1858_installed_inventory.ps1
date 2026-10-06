# Issue #1858 W0/AUD2/AUD5: installed-config resolution proof.
# Calls Get-LegacyEntrypointDispositions twice against the enclosing
# repository: once without an install root (template rows stay
# SOURCE_DECLARED, installed_command_observed false) and once with a TEMP
# install root carrying installed-style configs (literal bridge path plus
# absolute installation-owned declaration). Requires INSTALLED_BYTES basis,
# installed_command_observed true and declaration present on the Claude Code,
# Desktop and OpenCode surfaces. The TEMP bundle root carries staged Codex
# bytes copied from the tree; TEMP install/installed files are removed after.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'lib' 'entrypoint-inventory.ps1')

# Caller-provided helpers (production hosts: scripts/build-eliot-windows-x64-release.ps1).
function Get-GitBlobHash([string]$Repo, [string]$Commit, [string]$RelativePath) {
    $hash = (& git -C $Repo rev-parse "$Commit`:$RelativePath" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $hash -notmatch '^[0-9a-f]{40,64}$') {
        throw "failed to resolve pinned source blob: $RelativePath"
    }
    return $hash
}
function Get-FilteredFileHash([string]$Repo, [string]$RelativePath, [string]$FilePath) {
    $hash = (& git -C $Repo hash-object "--path=$RelativePath" $FilePath 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $hash -notmatch '^[0-9a-f]{40,64}$') {
        throw "failed to hash release source file: $RelativePath"
    }
    return $hash
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$SourceCommit = (git -C $RepoRoot rev-parse HEAD 2>$null | Out-String).Trim()
if ([string]::IsNullOrWhiteSpace($SourceCommit)) { throw 'cannot resolve repository HEAD for the pinned inventory' }

function New-InstalledConfig([string]$Dir, [string]$Relative, [string]$Content) {
    $full = Join-Path $Dir $Relative
    $parent = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Set-Content -LiteralPath $full -Value $Content -Encoding utf8 -NoNewline
}

$bundle = Join-Path ([System.IO.Path]::GetTempPath()) ('b1858-' + [Guid]::NewGuid().ToString('N'))
$install = Join-Path ([System.IO.Path]::GetTempPath()) ('i1858-' + [Guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $bundle | Out-Null
    New-Item -ItemType Directory -Path $install | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $bundle 'integrations/codex/plugins/eliot-governor/hooks') -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'plugin/eliot-governor/.mcp.json') -Destination (Join-Path $bundle 'integrations/codex/plugins/eliot-governor/.mcp.json') -Force
    Copy-Item -LiteralPath (Join-Path $RepoRoot 'plugin/eliot-governor/hooks/hooks.json') -Destination (Join-Path $bundle 'integrations/codex/plugins/eliot-governor/hooks/hooks.json') -Force

    $template = Get-LegacyEntrypointDispositions $RepoRoot $SourceCommit $bundle $null
    foreach ($name in @('Claude Code MCP stdio profile SPINE_FUNCTIONAL', 'Claude Desktop MCP stdio profile SPINE_FUNCTIONAL', 'OpenCode MCP stdio profile SPINE_FUNCTIONAL')) {
        $row = @($template | Where-Object { [string]$_.launch_configuration.entrypoint -ceq $name })[0]
        if ($null -eq $row) { throw "template inventory missing $name" }
        if ([string]$row.launch_configuration.inventory_basis -cnotlike 'SOURCE_DECLARED*') { throw "$name template basis is not SOURCE_DECLARED" }
        if ([bool]$row.launch_configuration.installed_command_observed) { throw "$name template claims an observed installed command" }
    }

    $bridgeExe = 'C:\inst-test\bin\eliot-agent-bridge.exe'
    New-InstalledConfig $install 'agent-bridge/client-declaration-v2.json' '{}'
    $declaration = Join-Path $install 'agent-bridge/client-declaration-v2.json'
    $mcpArgs = @('mcp', '--profile', 'SPINE_FUNCTIONAL', '--transport', 'stdio', '--client-declaration', $declaration)
    New-InstalledConfig $install 'integrations/claude/eliot/.mcp.json' (([ordered]@{ mcpServers = [ordered]@{ eliot = [ordered]@{ command = $bridgeExe; args = $mcpArgs } } } | ConvertTo-Json -Depth 6))
    New-InstalledConfig $install 'integrations/claude/claude-desktop/mcpb/manifest.json' (([ordered]@{ server = [ordered]@{ mcp_config = [ordered]@{ command = $bridgeExe; args = $mcpArgs } } } | ConvertTo-Json -Depth 6))
    New-InstalledConfig $install 'integrations/opencode/opencode.json' (([ordered]@{ mcp = [ordered]@{ eliot = [ordered]@{ command = @($bridgeExe) + $mcpArgs } } } | ConvertTo-Json -Depth 6))

    $installed = Get-LegacyEntrypointDispositions $RepoRoot $SourceCommit $bundle $null $install
    foreach ($name in @('Claude Code MCP stdio profile SPINE_FUNCTIONAL', 'Claude Desktop MCP stdio profile SPINE_FUNCTIONAL', 'OpenCode MCP stdio profile SPINE_FUNCTIONAL')) {
        $row = @($installed | Where-Object { [string]$_.launch_configuration.entrypoint -ceq $name })[0]
        if ($null -eq $row) { throw "installed inventory missing $name" }
        if ([string]$row.launch_configuration.inventory_basis -cnotlike 'INSTALLED_BYTES*') { throw "$name installed basis is not INSTALLED_BYTES" }
        if (-not [bool]$row.launch_configuration.installed_command_observed) { throw "$name installed command not observed" }
        if (-not [bool]$row.launch_configuration.installed_declaration_present) { throw "$name installed declaration not present" }
        if ([string]$row.launch_configuration.command -cne $bridgeExe) { throw "$name installed command mismatch" }
    }
    Write-Output 'INSTALLED-INVENTORY-OK'
}
finally {
    Remove-Item -LiteralPath $bundle -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $install -Recurse -Force -ErrorAction SilentlyContinue
}
