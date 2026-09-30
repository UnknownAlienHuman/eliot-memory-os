# Issue #1858 (inventory/manifest slice): exact-bytes entrypoint inventory.
#
# Get-LegacyEntrypointDispositions enumerates every retained legacy
# entrypoint consumer by READING the exact staged/installed bytes -- never a
# manually mirrored table that can drift. Pinned source launch configs are
# read from the working tree and verified byte-identical to the pinned source
# blob (fail closed on drift); staged launch configs are read from the staged
# bundle and verified byte-identical to the same pinned blob. The product
# disposition is the accepted unconditional cutover (FRONT DOOR step 1'):
# every non-canonical entrypoint refuses or redirects with the stable code
# LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER plus the canonical-route receipt and no
# ambient operator flag; ELIOT_CLAUDE_FRONT_DOOR survives only as refusal
# evidence. Accordingly no retained launch config may name the Bridge binary
# directly (delegation is in-binary via
# crates/eliot-app/src/main.rs::delegate_host_mcp_to_agent_bridge) and none
# may select the cutover flag: either shape drift throws.
#
# Invoke-InstalledEntrypointReadback is the AUD6 invocation+readback
# mechanism: it resolves the exact installed command+environment per consumer
# from the staged manifest, invokes each retained entrypoint on a live
# Windows install, and matches the cutover code plus canonical-route receipt.
# The release builder calls it with -WhatIf to stage the readback plan
# snapshot (no process is ever launched by the builder); the operator runs it
# without -WhatIf on the isolated TEST-PHASE machine. Until then the manifest
# records observed_behavior NOT_PERFORMED with this symbol.
function Read-PinnedConsumerBytes([string]$Repo, [string]$SourceCommit, [string]$RelativePath) {
    $relative = [string]$RelativePath
    $file = Get-Item -LiteralPath (Join-Path $Repo $relative) -ErrorAction Stop
    if (-not ($file -is [System.IO.FileInfo])) {
        throw "entrypoint consumer is not a regular file: $relative"
    }
    $expectedHash = Get-GitBlobHash $Repo $SourceCommit $relative
    $sourceHash = Get-FilteredFileHash $Repo $relative $file.FullName
    if ($sourceHash -ne $expectedHash) {
        throw "entrypoint consumer differs from pinned commit: $relative"
    }
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    return [ordered]@{
        relative_path = $relative
        sha256 = [string]$sha256
        bytes = [int64]$bytes.Length
        text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    }
}

function Read-StagedConsumerBytes([string]$Repo, [string]$SourceCommit, [string]$BundleRoot, [string]$SourceRelativePath, [string]$StagedRelativePath) {
    $stagedFull = Join-Path $BundleRoot ([string]$StagedRelativePath)
    $file = Get-Item -LiteralPath $stagedFull -ErrorAction Stop
    if (-not ($file -is [System.IO.FileInfo])) {
        throw "staged entrypoint consumer is not a regular file: $StagedRelativePath"
    }
    $expectedHash = Get-GitBlobHash $Repo $SourceCommit ([string]$SourceRelativePath)
    $stagedHash = Get-FilteredFileHash $Repo ([string]$SourceRelativePath) $file.FullName
    if ($stagedHash -ne $expectedHash) {
        throw "staged entrypoint consumer differs from pinned commit: $StagedRelativePath"
    }
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    return [ordered]@{
        source_path = [string]$SourceRelativePath
        staged_path = [string]$StagedRelativePath
        sha256 = [string]$sha256
        bytes = [int64]$bytes.Length
        text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
    }
}

function Get-StringSha256([string]$Text) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hasher.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Convert-ConsumerJson([string]$Text, [string]$RelativePath) {
    try {
        return $Text | ConvertFrom-Json
    }
    catch {
        throw "entrypoint consumer is not valid JSON: $RelativePath"
    }
}

function Get-EnvMember([object]$JsonObject) {
    if ($null -eq $JsonObject) {
        return $null
    }
    $property = $JsonObject.PSObject.Properties['env']
    if ($property) {
        return $property.Value
    }
    return $null
}

function Get-LegacyEntrypointDispositions([string]$RepoRoot, [string]$SourceCommit, [string]$BundleRoot, [object]$FrontDoorBridge) {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        throw 'entrypoint inventory requires the repository root'
    }
    if ([string]::IsNullOrWhiteSpace($SourceCommit)) {
        throw 'entrypoint inventory requires the pinned source commit'
    }
    if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
        throw 'entrypoint inventory requires the staged bundle root'
    }
    $notObserved = [ordered]@{
        status = 'NOT_PERFORMED'
        detail = 'No installed Windows runtime invocation was performed by the release builder. Run scripts/lib/entrypoint-inventory.ps1::Invoke-InstalledEntrypointReadback on the installed release; until then only source behavior is declared.'
    }
    $bridgeStaged = $null -ne $FrontDoorBridge
    $bridgeBinding = if ($bridgeStaged) {
        "beside-governor eliot-agent-bridge.exe (sha256 $([string]$FrontDoorBridge.sha256), bytes $([int64]$FrontDoorBridge.bytes))"
    }
    else {
        $null
    }
    # Delegated-host behavior under the accepted unconditional cutover: the
    # three delegated hosts at the default profile always emit the stderr
    # REDIRECT receipt and delegate to the approved Bridge; when the Bridge
    # is not staged in this bundle the same invocation returns structured
    # ERROR instead. No ambient operator flag is consulted on either path.
    $delegatedBehavior = if ($bridgeStaged) {
        "Unconditionally emit the stderr REDIRECT receipt (LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER plus canonical_route) and delegate to the approved Bridge at $bridgeBinding; child status wins on success, resolution/launch failure emits structured ERROR with no legacy fallback. No Governor, Store, WAL, or writer object is constructed on this path."
    }
    else {
        'The approved Bridge is not staged in this bundle, so the delegated redirect has no target: unconditionally return structured ERROR with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER before legacy mcp stdio with no ambient operator flag. No legacy serving path remains.'
    }
    $consumers = @()

    $claudeMcp = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'integrations/claude/eliot/.mcp.json'
    $claudeMcpJson = Convert-ConsumerJson $claudeMcp.text 'integrations/claude/eliot/.mcp.json'
    $claudeServer = $claudeMcpJson.mcpServers.eliot
    if ([string]$claudeServer.command -ne '${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe') {
        throw 'Claude Code MCP server command drifted from the inventoried bytes: integrations/claude/eliot/.mcp.json'
    }
    $claudeArgs = @($claudeServer.args)
    $claudeExpectedArgs = @('mcp', 'stdio', '--host', 'claude', '--instance', 'default')
    if (($claudeArgs -join "`0") -cne ($claudeExpectedArgs -join "`0")) {
        throw 'Claude Code MCP server argv drifted from the inventoried bytes: integrations/claude/eliot/.mcp.json'
    }
    $consumers += [ordered]@{
        entrypoint = 'Claude Code MCP stdio --host claude'
        source_config = 'integrations/claude/eliot/.mcp.json'
        packaged_config = $null
        inventory_basis = 'PINNED_SOURCE_BYTES: working-tree bytes verified identical to the pinned source blob; this launch config ships with the Claude plugin install, not the Windows bundle.'
        source_sha256 = [string]$claudeMcp.sha256
        source_bytes = [int64]$claudeMcp.bytes
        staged_sha256 = $null
        staged_bytes = $null
        command = [string]$claudeServer.command
        args = @($claudeArgs)
        configured_environment = Get-EnvMember $claudeServer
        effective_cutover_value = 'NOT_OBSERVED (may be inherited by the process; never gates behavior)'
        behavior = $delegatedBehavior
        canonical_route = 'Claude Code agent-bridge declaration and Kernel canonical configuration route.'
    }

    $claudeHooks = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'integrations/claude/eliot/hooks/hooks.json'
    $claudeHooksJson = Convert-ConsumerJson $claudeHooks.text 'integrations/claude/eliot/hooks/hooks.json'
    $claudeHookCommands = @()
    foreach ($hookEvent in @($claudeHooksJson.hooks.PSObject.Properties)) {
        foreach ($group in @($hookEvent.Value)) {
            foreach ($hook in @($group.hooks)) {
                $claudeHookCommands += [ordered]@{
                    event = [string]$hookEvent.Name
                    command = [string]$hook.command
                    args = @($hook.args)
                }
            }
        }
    }
    if ($claudeHookCommands.Count -eq 0) {
        throw 'Claude Code hooks inventory is empty: integrations/claude/eliot/hooks/hooks.json'
    }
    foreach ($hook in $claudeHookCommands) {
        if ([string]$hook.command -ne '${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe') {
            throw "Claude Code hook command drifted from the inventoried bytes: $($hook.event)"
        }
    }
    $consumers += [ordered]@{
        entrypoint = 'Claude Code plugin hook <event>'
        source_config = 'integrations/claude/eliot/hooks/hooks.json'
        packaged_config = $null
        inventory_basis = 'PINNED_SOURCE_BYTES: working-tree bytes verified identical to the pinned source blob; this launch config ships with the Claude plugin install, not the Windows bundle.'
        source_sha256 = [string]$claudeHooks.sha256
        source_bytes = [int64]$claudeHooks.bytes
        staged_sha256 = $null
        staged_bytes = $null
        command = '${CLAUDE_PLUGIN_ROOT}/bin/eliot-governor.exe'
        hook_commands = @($claudeHookCommands)
        configured_environment = 'No env member in hooks.json; effective value NOT_OBSERVED.'
        effective_cutover_value = 'NOT_OBSERVED (may be inherited by the process; never gates behavior)'
        behavior = 'Unconditionally refuse with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER plus the canonical-route receipt at the dispatch entry gate before hook handling, with no ambient operator flag; the Bridge implements no hook/host-event argv, so hooks are refused, never served. No legacy serving path remains.'
        canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
    }

    $desktop = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'integrations/claude/claude-desktop/mcpb/manifest.json'
    $desktopJson = Convert-ConsumerJson $desktop.text 'integrations/claude/claude-desktop/mcpb/manifest.json'
    $desktopConfig = $desktopJson.server.mcp_config
    if ([string]$desktopConfig.command -ne '${__dirname}/server/eliot-governor.exe') {
        throw 'Claude Desktop MCP server command drifted from the inventoried bytes: integrations/claude/claude-desktop/mcpb/manifest.json'
    }
    $desktopArgs = @($desktopConfig.args)
    $desktopExpectedArgs = @('mcp', 'stdio', '--host', 'claude-desktop', '--instance', 'default')
    if (($desktopArgs -join "`0") -cne ($desktopExpectedArgs -join "`0")) {
        throw 'Claude Desktop MCP server argv drifted from the inventoried bytes: integrations/claude/claude-desktop/mcpb/manifest.json'
    }
    $consumers += [ordered]@{
        entrypoint = 'Claude Desktop MCP stdio --host claude-desktop'
        source_config = 'integrations/claude/claude-desktop/mcpb/manifest.json'
        packaged_config = $null
        inventory_basis = 'PINNED_SOURCE_BYTES: working-tree bytes verified identical to the pinned source blob; the MCPB server entry ships through MCPB packaging, not the Windows bundle.'
        source_sha256 = [string]$desktop.sha256
        source_bytes = [int64]$desktop.bytes
        staged_sha256 = $null
        staged_bytes = $null
        command = [string]$desktopConfig.command
        args = @($desktopArgs)
        configured_environment = Get-EnvMember $desktopConfig
        effective_cutover_value = 'NOT_OBSERVED (never gates behavior)'
        behavior = $delegatedBehavior
        canonical_route = 'Claude Desktop agent-bridge declaration and Kernel canonical configuration route.'
    }

    $opencode = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'integrations/opencode/opencode.json'
    $opencodeJson = Convert-ConsumerJson $opencode.text 'integrations/opencode/opencode.json'
    $opencodeCommand = @($opencodeJson.mcp.eliot.command)
    $opencodeExpected = @('{env:ELIOT_GOVERNOR_EXE}', 'mcp', 'stdio', '--host', 'opencode', '--instance', 'default')
    if (($opencodeCommand -join "`0") -cne ($opencodeExpected -join "`0")) {
        throw 'OpenCode MCP server command drifted from the inventoried bytes: integrations/opencode/opencode.json'
    }
    $consumers += [ordered]@{
        entrypoint = 'OpenCode MCP stdio --host opencode'
        source_config = 'integrations/opencode/opencode.json'
        packaged_config = $null
        inventory_basis = 'PINNED_SOURCE_BYTES: working-tree bytes verified identical to the pinned source blob; this launch config ships with the OpenCode host install, not the Windows bundle.'
        source_sha256 = [string]$opencode.sha256
        source_bytes = [int64]$opencode.bytes
        staged_sha256 = $null
        staged_bytes = $null
        command = [string]$opencodeCommand[0]
        args = @($opencodeCommand | Select-Object -Skip 1)
        configured_environment = 'No MCP env member; command resolves the executable through ELIOT_GOVERNOR_EXE.'
        effective_cutover_value = 'NOT_OBSERVED (never gates behavior)'
        behavior = $delegatedBehavior
        canonical_route = 'OpenCode agent-bridge declaration and Kernel canonical configuration route.'
    }

    $opencodePlugin = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'integrations/opencode/plugins/eliot.js'
    if ($opencodePlugin.text -notmatch 'if \(process\.env\.ELIOT_GOVERNOR_EXE\) return process\.env\.ELIOT_GOVERNOR_EXE' -or
        $opencodePlugin.text -notmatch 'LOCALAPPDATA\}/Eliot/host-integrations/opencode/bin/eliot-governor\.exe') {
        throw 'OpenCode plugin executable resolution drifted from the inventoried bytes: integrations/opencode/plugins/eliot.js'
    }
    $consumers += [ordered]@{
        entrypoint = 'OpenCode plugin bridge executable resolution'
        source_config = 'integrations/opencode/plugins/eliot.js'
        packaged_config = $null
        inventory_basis = 'PINNED_SOURCE_BYTES: working-tree bytes verified identical to the pinned source blob; this script ships with the OpenCode host install, not the Windows bundle.'
        source_sha256 = [string]$opencodePlugin.sha256
        source_bytes = [int64]$opencodePlugin.bytes
        staged_sha256 = $null
        staged_bytes = $null
        command = 'ELIOT_GOVERNOR_EXE else %LOCALAPPDATA%/Eliot/host-integrations/opencode/bin/eliot-governor.exe'
        args = @()
        configured_environment = 'Script resolution only; MCP server environment comes from integrations/opencode/opencode.json, not this script.'
        effective_cutover_value = 'NOT_OBSERVED (never gates behavior)'
        behavior = 'Script resolution only; the resolved eliot-governor.exe MCP invocation follows the OpenCode MCP entry above (unconditional redirect when the Bridge is staged, structured ERROR otherwise). This script stages no cutover selection.'
        canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
    }

    $codexMcp = Read-StagedConsumerBytes $RepoRoot $SourceCommit $BundleRoot 'plugin/eliot-governor/.mcp.json' 'integrations/codex/plugins/eliot-governor/.mcp.json'
    $codexMcpJson = Convert-ConsumerJson $codexMcp.text 'integrations/codex/plugins/eliot-governor/.mcp.json'
    $codexServers = @($codexMcpJson.mcpServers.PSObject.Properties)
    if ($codexServers.Count -ne 1 -or $codexServers[0].Name -ne 'eliot') {
        throw 'staged Codex plugin must expose exactly one MCP server named eliot'
    }
    $codexServer = $codexServers[0].Value
    if ([string]$codexServer.command -ne 'bin/eliot-governor.exe' -or [string]$codexServer.cwd -ne '.') {
        throw 'staged Codex MCP server command drifted from the inventoried bytes: integrations/codex/plugins/eliot-governor/.mcp.json'
    }
    $codexArgs = @($codexServer.args)
    $codexExpectedArgs = @('mcp', 'stdio', '--profile', 'codex_controller', '--instance', 'default')
    if (($codexArgs -join "`0") -cne ($codexExpectedArgs -join "`0")) {
        throw 'staged Codex MCP server argv drifted from the inventoried bytes: integrations/codex/plugins/eliot-governor/.mcp.json'
    }
    $consumers += [ordered]@{
        entrypoint = 'Codex MCP stdio profile codex_controller'
        source_config = 'plugin/eliot-governor/.mcp.json'
        packaged_config = 'integrations/codex/plugins/eliot-governor/.mcp.json'
        inventory_basis = 'EXACT_STAGED_BYTES: staged bundle bytes verified identical to the pinned source blob.'
        source_sha256 = [string]$codexMcp.sha256
        source_bytes = [int64]$codexMcp.bytes
        staged_sha256 = [string]$codexMcp.sha256
        staged_bytes = [int64]$codexMcp.bytes
        command = [string]$codexServer.command
        cwd = [string]$codexServer.cwd
        args = @($codexArgs)
        configured_environment = Get-EnvMember $codexServer
        effective_cutover_value = 'NOT_OBSERVED (never gates behavior)'
        behavior = 'Unconditionally return structured ERROR with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER before legacy mcp stdio with no ambient operator flag; the codex_controller profile has no Bridge contour (behavior home is the eliot-mcp track per canon) and is never delegated. No legacy serving path remains.'
        canonical_route = $null
    }

    $codexHooks = Read-StagedConsumerBytes $RepoRoot $SourceCommit $BundleRoot 'plugin/eliot-governor/hooks/hooks.json' 'integrations/codex/plugins/eliot-governor/hooks/hooks.json'
    $codexHooksJson = Convert-ConsumerJson $codexHooks.text 'integrations/codex/plugins/eliot-governor/hooks/hooks.json'
    $codexHookCommands = @()
    foreach ($hookEvent in @($codexHooksJson.hooks.PSObject.Properties)) {
        foreach ($group in @($hookEvent.Value)) {
            foreach ($hook in @($group.hooks)) {
                $codexHookCommands += [ordered]@{
                    event = [string]$hookEvent.Name
                    command = [string]$hook.command
                    args = @($hook.args)
                }
            }
        }
    }
    if ($codexHookCommands.Count -eq 0) {
        throw 'staged Codex hooks inventory is empty: integrations/codex/plugins/eliot-governor/hooks/hooks.json'
    }
    foreach ($hook in $codexHookCommands) {
        if ([string]$hook.command -notmatch '"\$\{PLUGIN_ROOT\}\\bin\\eliot-governor\.exe" hook ') {
            throw "staged Codex hook command drifted from the inventoried bytes: $($hook.event)"
        }
    }
    $consumers += [ordered]@{
        entrypoint = 'Codex plugin hook <event>'
        source_config = 'plugin/eliot-governor/hooks/hooks.json'
        packaged_config = 'integrations/codex/plugins/eliot-governor/hooks/hooks.json'
        inventory_basis = 'EXACT_STAGED_BYTES: staged bundle bytes verified identical to the pinned source blob.'
        source_sha256 = [string]$codexHooks.sha256
        source_bytes = [int64]$codexHooks.bytes
        staged_sha256 = [string]$codexHooks.sha256
        staged_bytes = [int64]$codexHooks.bytes
        hook_commands = @($codexHookCommands)
        configured_environment = 'No cutover flag declared; effective value NOT_OBSERVED.'
        effective_cutover_value = 'NOT_OBSERVED (never gates behavior)'
        behavior = 'Unconditionally refuse with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER plus the canonical-route receipt at the dispatch entry gate before hook handling, with no ambient operator flag; the Bridge implements no hook/host-event argv, so hooks are refused, never served. No legacy serving path remains.'
        canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
    }

    # Product-code evidence (A1 impl/caller binding): the pinned
    # crates/eliot-app/src/main.rs must carry the single dispatch entry gate
    # and the delegated-host MCP branch; any relocation of the gate symbols
    # throws here so the manifest never describes a stale wiring.
    $appMain = Read-PinnedConsumerBytes $RepoRoot $SourceCommit 'crates/eliot-app/src/main.rs'
    foreach ($symbol in @(
            'front_door_cutover::gate_legacy_entrypoint',
            'BRIDGE_DELEGATED_MCP_HOSTS',
            'delegate_host_mcp_to_agent_bridge',
            'visible_alias = "seal-provider-plan"'
        )) {
        if ($appMain.text -notmatch [regex]::Escape($symbol)) {
            throw "product cutover wiring drifted from the inventoried bytes: crates/eliot-app/src/main.rs no longer contains $symbol"
        }
    }

    # Cutover-selection assertion (AUD2, unconditional disposition): the
    # cutover travels via in-binary delegation, so no retained launch config
    # may name the Bridge binary directly and none may select the cutover
    # flag (it survives only as refusal evidence and never gates).
    foreach ($consumer in $consumers) {
        foreach ($field in @('command')) {
            if ([string]$consumer.$field -match 'eliot-agent-bridge\.exe') {
                throw "no retained launch config may name the Bridge binary directly: $($consumer.entrypoint)"
            }
        }
        foreach ($hook in @($consumer.hook_commands)) {
            if ([string]$hook.command -match 'eliot-agent-bridge\.exe' -or (@($hook.args) -join ' ') -match 'eliot-agent-bridge\.exe') {
                throw "no retained hook command may name the Bridge binary directly: $($consumer.entrypoint)"
            }
        }
        $env = $consumer.configured_environment
        $flagSelected = $false
        if ($env -is [System.Collections.IDictionary]) {
            $flagSelected = $env.Contains('ELIOT_CLAUDE_FRONT_DOOR')
        }
        elseif ($null -ne $env) {
            $flagSelected = $null -ne $env.PSObject.Properties['ELIOT_CLAUDE_FRONT_DOOR']
        }
        if ($flagSelected) {
            throw "no retained launch config may select the cutover flag: $($consumer.entrypoint)"
        }
    }

    $dispositions = @(
        foreach ($consumer in $consumers) {
            [ordered]@{
                entrypoint = $consumer.entrypoint
                behavior = $consumer.behavior
                canonical_route = $consumer.canonical_route
                launch_configuration = $consumer
                source_behavior_status = 'SOURCE_DECLARED'
                observed_behavior = $notObserved
            }
        }
        [ordered]@{
            entrypoint = 'eliot-governor.exe daemon run'
            behavior = 'Unconditionally refuse with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER at the dispatch entry gate before DbClientSet/CanonicalStore start or ControlWal/WriterActor construction, with no ambient operator flag; no legacy serving path remains.'
            canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
            launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('daemon', 'run'); environment = 'Caller-provided; effective value NOT_OBSERVED.' }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
        [ordered]@{
            entrypoint = 'eliot-governor.exe service run'
            behavior = 'Unconditionally refuse with LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER at the dispatch entry gate before legacy service handling, with no ambient operator flag; no legacy serving path remains. No SCM registration in this slice names the legacy governor: the Windows service identities are EliotHost/EliotWatchdog, owned by bins/eliot-host + bins/eliot-watchdog through eliot_platform_windows::ELIOT_HOST_SERVICE_NAME.'
            canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
            launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('service', 'run'); environment = 'Caller-provided; effective value NOT_OBSERVED.' }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
        [ordered]@{
            entrypoint = 'Windows SCM service registrations (EliotHost/EliotWatchdog)'
            behavior = 'Out of the legacy-governor slice: SCM registrations name the Host/Watchdog service binaries (bins/eliot-host, bins/eliot-watchdog), never eliot-governor.exe; the governor service arm above is refused unconditionally at the dispatch entry gate.'
            canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
            launch_configuration = [ordered]@{
                owner = 'bins/eliot-host/src/scm_launch.rs + bins/eliot-watchdog/src/scm_launch.rs via eliot_platform_windows::ELIOT_HOST_SERVICE_NAME'
                command = 'service binary (not eliot-governor.exe)'
            }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
        [ordered]@{
            entrypoint = 'compatibility alias seal-provider-plan'
            behavior = 'Same-dispatch alias of the seal subcommand (visible_alias in crates/eliot-app/src/main.rs, pinned above): not a separate entrypoint or authority; the aliased invocation funnels through dispatch_command and is refused unconditionally at the entry gate like every other non-stdio arm.'
            canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
            launch_configuration = [ordered]@{ command = 'eliot-governor.exe'; args = @('seal-provider-plan'); environment = 'Caller-provided; effective value NOT_OBSERVED.' }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
        [ordered]@{
            entrypoint = 'eliot.exe setup/canary legacy-owner checks'
            behavior = 'When governor.toml exists, the Governor process is running, or the OS observation is unknown, fail closed with the corresponding legacy cutover code and canonical-route receipt.'
            canonical_route = 'Kernel canonical configuration route; installed route NOT_OBSERVED.'
            launch_configuration = [ordered]@{ command = 'eliot.exe'; args = @('setup'); environment = 'Legacy-owner check; installed invocation NOT_OBSERVED.' }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
        [ordered]@{
            entrypoint = 'cutover gate evidence (crates/eliot-app/src/main.rs)'
            behavior = 'Pinned product-code evidence binding the manifest to the single production caller: crates/eliot-app/src/main.rs::dispatch_command gates every non-canonical arm through crates/eliot-app/src/front_door_cutover.rs::gate_legacy_entrypoint; delegated MCP hosts (BRIDGE_DELEGATED_MCP_HOSTS) redirect through delegate_host_mcp_to_agent_bridge.'
            canonical_route = 'Kernel canonical configuration route.'
            launch_configuration = [ordered]@{
                source_config = 'crates/eliot-app/src/main.rs'
                source_sha256 = [string]$appMain.sha256
                source_bytes = [int64]$appMain.bytes
                gate = 'crates/eliot-app/src/front_door_cutover.rs::gate_legacy_entrypoint'
                caller = 'crates/eliot-app/src/main.rs::dispatch_command'
            }
            source_behavior_status = 'SOURCE_DECLARED'
            observed_behavior = $notObserved
        }
    )
    return $dispositions
}

function Invoke-InstalledEntrypointReadback {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [string]$InstallRoot,
        [string]$SnapshotPath,
        [string[]]$Only = @(),
        [int]$TimeoutSeconds = 60
    )
    $resolved = (Resolve-Path -LiteralPath $InstallRoot).Path
    $manifestPath = Join-Path $resolved 'STAGED_PAYLOAD_MANIFEST.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "installed readback requires the staged payload manifest: $manifestPath"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $governorEntry = @($manifest.entries | Where-Object { [string]$_.path -ceq 'eliot-governor.exe' })
    if ($governorEntry.Count -ne 1) {
        throw 'installed readback requires exactly one staged eliot-governor.exe manifest entry'
    }
    $behaviors = @($governorEntry[0].entrypoint_behaviors)
    if ($behaviors.Count -eq 0) {
        throw 'installed readback requires entrypoint_behaviors in the staged payload manifest'
    }
    $cutoverCode = 'LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER'
    $results = @()
    foreach ($behavior in $behaviors) {
        $name = [string]$behavior.entrypoint
        if ($Only.Count -ne 0 -and -not ($Only -contains $name)) {
            continue
        }
        $launch = $behavior.launch_configuration
        $record = [ordered]@{
            entrypoint = $name
            status = 'NOT_PERFORMED'
            detail = ''
            exit_code = $null
            stdout_sha256 = $null
            stderr_sha256 = $null
            cutover_code_observed = $false
            canonical_route_observed = $false
        }
        $hookCommands = @($launch.hook_commands | Where-Object { $null -ne $_ })
        if ($hookCommands.Count -ne 0) {
            $record.detail = 'hook commands resolve host-install variables at host install time; bundle readback cannot invoke them without the host install. Invoke each staged hook command on the host and match the cutover code plus canonical-route receipt.'
            $results += $record
            continue
        }
        if ($null -eq $launch.command) {
            $record.detail = 'this disposition carries no invocable command (evidence or registration record); nothing to invoke.'
            $results += $record
            continue
        }
        $command = [string]$launch.command
        $argv = @($launch.args | Where-Object { $null -ne $_ })
        $exePath = $null
        if (-not [string]::IsNullOrWhiteSpace($command) -and -not ($command -match '[\$%\{]')) {
            $exePath = Join-Path $resolved $command
            if ((-not (Test-Path -LiteralPath $exePath -PathType Leaf)) -and $launch.packaged_config) {
                $packagedDir = Split-Path -Parent ([string]$launch.packaged_config)
                $exePath = Join-Path (Join-Path $resolved $packagedDir) $command
            }
        }
        if ($null -eq $exePath -or -not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
            if ([string]::IsNullOrWhiteSpace($command) -or ($command -match '[\$%\{]')) {
                $record.detail = "installed command is anchored at a host-install variable ($command); bundle readback cannot resolve it without the host install. Invoke it on the host and match the cutover code plus canonical-route receipt."
            }
            else {
                $record.detail = "installed executable is absent from this install root: $command"
            }
            $results += $record
            continue
        }
        if ($PSCmdlet.ShouldProcess($name, 'invoke installed entrypoint and read back the cutover receipt')) {
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo.FileName = $exePath
            $process.StartInfo.Arguments = ($argv | ForEach-Object { "`"$_`"" }) -join ' '
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            $process.StartInfo.CreateNoWindow = $true
            try {
                [void]$process.Start()
                if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
                    try {
                        $process.Kill()
                    }
                    catch {
                    }
                    $record.status = 'TIMEOUT'
                    $record.detail = "installed invocation exceeded ${TimeoutSeconds}s and was killed; rerun on the isolated TEST-PHASE machine."
                    $results += $record
                    continue
                }
                $stdout = $process.StandardOutput.ReadToEnd()
                $stderr = $process.StandardError.ReadToEnd()
                $record.exit_code = $process.ExitCode
                $record.stdout_sha256 = [string](Get-StringSha256 $stdout)
                $record.stderr_sha256 = [string](Get-StringSha256 $stderr)
                $record.cutover_code_observed = ($stdout + "`n" + $stderr) -cmatch $cutoverCode
                $record.canonical_route_observed = ($stdout + "`n" + $stderr) -cmatch 'canonical_route'
                if ($record.cutover_code_observed -and $record.canonical_route_observed) {
                    $record.status = 'PASS'
                    $record.detail = 'installed invocation returned the stable cutover code plus the canonical-route receipt.'
                }
                else {
                    $record.status = 'FAIL'
                    $record.detail = 'installed invocation completed without the stable cutover code plus canonical-route receipt.'
                }
            }
            catch {
                $record.status = 'FAIL'
                $record.detail = "installed invocation failed to launch: $($_.Exception.Message)"
            }
            finally {
                $process.Dispose()
            }
        }
        else {
            $record.detail = "planned invocation: $exePath $($argv -join ' '); rerun without -WhatIf on the isolated TEST-PHASE machine."
        }
        $results += $record
    }
    $snapshot = [ordered]@{
        schema = 'eliot-installed-entrypoint-readback-v1'
        install_root = [string]$resolved
        cutover_code = [string]$cutoverCode
        proof_ceiling = 'installed-Windows invocation with stdout/stderr capture and receipt match; hook and host-variable-anchored commands require the host install and stay NOT_PERFORMED here'
        results = @($results)
    }
    if (-not [string]::IsNullOrWhiteSpace($SnapshotPath)) {
        # The snapshot write is forced: under -WhatIf the invocation planning
        # stays dry (no process is launched) but the plan file itself must be
        # staged beside the manifest.
        $snapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $SnapshotPath -Encoding utf8 -WhatIf:$false
    }
    return $snapshot
}
