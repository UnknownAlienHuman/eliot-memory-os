[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [string]$OutputRoot = (Join-Path $env:LOCALAPPDATA 'Eliot\packages'),
    [string]$OperatorSource,
    [switch]$SkipBuild,
    [switch]$PlanOnly,
    [string]$VerifyBundle
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Assert-SafeRelativePath([string]$Path, [string]$Purpose) {
    $normalized = $Path.Replace('\', '/')
    $segments = @($normalized -split '/')
    if (-not $normalized -or [System.IO.Path]::IsPathRooted($normalized) -or $segments -contains '..' -or $segments -contains '') {
        throw "$Purpose path is unsafe: $Path"
    }
    return $normalized
}

function Assert-NoSecretFile([System.IO.FileInfo]$File, [string]$RelativePath) {
    $relative = $RelativePath.Replace('\', '/')
    $sensitiveName = '(?i)(^|[/._-])(secret|token|credential|private[-_]?key|password)([/._-]|$)|(^|/)\.(env($|\.)|envrc$|netrc$|npmrc$)|\.(pfx|p12|kdbx)$|(^|/)id_(rsa|ed25519)$'
    $isTrackedDocumentation = $relative.StartsWith('docs/', [System.StringComparison]::OrdinalIgnoreCase) -and
        $File.Extension.Equals('.md', [System.StringComparison]::OrdinalIgnoreCase)
    if ([regex]::IsMatch($relative, $sensitiveName) -and -not $isTrackedDocumentation) {
        throw "release payload contains a secret-like filename: $relative"
    }

    $patterns = [ordered]@{
        private_key = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
        provider_credential = '(?i)(github_pat_|gh[pousr]_|(?<![A-Za-z0-9])sk-|xox[baprs]-)[A-Za-z0-9_-]{8,}'
        aws_access_key = 'AKIA[0-9A-Z]{16}'
        compact_jwt = 'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'
        credential_assignment = '(?i)(api[_-]?(key|token)|client[_-]?secret|access[_-]?token|refresh[_-]?token|aws[_-]?secret[_-]?access[_-]?key|password|secret)\s*[:=]\s*["'']?[A-Za-z0-9+/_=.-]{12,}'
        basic_authorization = '(?i)authorization\s*:\s*basic\s+[A-Za-z0-9+/=]{12,}'
    }
    $textExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.config', '.html', '.js', '.json', '.md', '.ps1', '.surql', '.toml', '.txt', '.xml', '.yaml', '.yml')) {
        [void]$textExtensions.Add($extension)
    }
    $stream = [System.IO.File]::Open($File.FullName, 'Open', 'Read', 'Read')
    try {
        $buffer = [byte[]]::new(1048576)
        $carry = ''
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $chunk = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read).Replace("`0", '')
            $candidate = $carry + $chunk
            foreach ($pattern in $patterns.GetEnumerator()) {
                if ($pattern.Key -in @('provider_credential', 'compact_jwt', 'credential_assignment', 'basic_authorization') -and -not $textExtensions.Contains($File.Extension)) {
                    continue
                }
                if ([regex]::IsMatch($candidate, $pattern.Value)) {
                    throw "release payload secret scan matched $($pattern.Key): $relative"
                }
            }
            $carry = if ($candidate.Length -gt 512) { $candidate.Substring($candidate.Length - 512) } else { $candidate }
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-NoReleaseSecrets([string]$Root) {
    $resolved = (Resolve-Path -LiteralPath $Root).Path
    foreach ($item in Get-ChildItem -LiteralPath $resolved -Force -Recurse) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $relative = $item.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
            throw "release payload contains a reparse point: $relative"
        }
        if ($item -is [System.IO.FileInfo]) {
            $relative = $item.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
            Assert-NoSecretFile $item $relative
        }
    }
}

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

function Assert-TrackedSourceFile([System.IO.FileSystemInfo]$File, [string]$RelativePath) {
    if (-not ($File -is [System.IO.FileInfo])) {
        throw "tracked release source is not a regular file: $RelativePath"
    }
    if (($File.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
        return
    }

    # Files On-Demand keeps resident files inside a pinned OneDrive tree as
    # ordinary FileInfo objects with the cloud reparse bit set. Permit only
    # that opaque, fully resident form. Symbolic links expose LinkType/Target;
    # offline, unpinned, and recall-on-access placeholders carry one of the
    # non-resident attribute bits below and remain forbidden.
    $linkTargets = @($File.Target) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    $nonResidentMask = [int64]0x00541000
    if (-not [string]::IsNullOrWhiteSpace([string]$File.LinkType) -or
        $linkTargets.Count -ne 0 -or
        (([int64]$File.Attributes -band $nonResidentMask) -ne 0)) {
        throw "tracked release source is not a resident regular file: $RelativePath"
    }
}

function Copy-TrackedTree([string]$Repo, [string]$SourceCommit, [string]$Source, [string]$Destination) {
    $sourcePath = Assert-SafeRelativePath $Source 'tracked source'
    $tracked = @(& git -C $Repo ls-tree -r --name-only $SourceCommit -- $sourcePath)
    if ($LASTEXITCODE -ne 0) {
        throw "failed to enumerate pinned release source: $sourcePath"
    }
    if ($tracked.Count -eq 0) {
        throw "tracked release source is empty: $sourcePath"
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($relative in $tracked) {
        $normalized = Assert-SafeRelativePath $relative 'tracked file'
        if (-not $normalized.StartsWith("$sourcePath/", [System.StringComparison]::Ordinal)) {
            throw "git returned a file outside the requested release source: $normalized"
        }
        $sourceFile = Get-Item -LiteralPath (Join-Path $Repo $normalized)
        Assert-TrackedSourceFile $sourceFile $normalized
        $suffix = $normalized.Substring($sourcePath.Length + 1)
        $expectedHash = Get-GitBlobHash $Repo $SourceCommit $normalized
        $sourceHash = Get-FilteredFileHash $Repo $normalized $sourceFile.FullName
        if ($sourceHash -ne $expectedHash) {
            throw "tracked release source differs from pinned commit: $normalized"
        }
        Assert-NoSecretFile $sourceFile "$sourcePath/$suffix"
        $target = Join-Path $Destination $suffix.Replace('/', '\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $sourceFile.FullName -Destination $target
        $copiedHash = Get-FilteredFileHash $Repo $normalized $target
        if ($copiedHash -ne $expectedHash) {
            throw "release source changed while being copied: $normalized"
        }
    }
}

function Copy-OperatorPayload([string]$Source, [string]$Destination) {
    $resolved = (Resolve-Path -LiteralPath $Source).Path
    $allowedExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($extension in @('.dll', '.exe', '.html', '.json', '.mui', '.png', '.pri', '.winmd', '.xbf')) {
        [void]$allowedExtensions.Add($extension)
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $resolved -Force -Recurse) {
        $relative = $item.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Operator payload contains a reparse point: $relative"
        }
        if (-not ($item -is [System.IO.FileInfo])) {
            continue
        }
        if ($item.Extension -ieq '.pdb') {
            continue
        }
        if (-not $allowedExtensions.Contains($item.Extension)) {
            throw "Operator payload contains an unapproved file type: $relative"
        }
        Assert-NoSecretFile $item "operator/$relative"
        $target = Join-Path $Destination $relative.Replace('/', '\')
        New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
        Copy-Item -LiteralPath $item.FullName -Destination $target
    }
}

function Test-ReleaseBundle([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    Assert-NoReleaseSecrets $resolved
    $required = @(
        'eliot-governor.exe',
        'operator/Eliot.Operator.exe',
        'config',
        'integrations',
        'integrations/codex/marketplace.json',
        'integrations/codex/plugins/eliot-governor/.codex-plugin/plugin.json',
        'integrations/codex/plugins/eliot-governor/.mcp.json',
        'integrations/codex/plugins/eliot-governor/README.md',
        'integrations/codex/plugins/eliot-governor/bin/eliot-governor.exe',
        'integrations/codex/plugins/eliot-governor/hooks/hooks.json',
        'integrations/codex/plugins/eliot-governor/skills/eliot-finish/SKILL.md',
        'integrations/codex/plugins/eliot-governor/skills/eliot-recover/SKILL.md',
        'integrations/codex/plugins/eliot-governor/skills/eliot-remember/SKILL.md',
        'integrations/codex/plugins/eliot-governor/skills/eliot-work/SKILL.md',
        'skills',
        'migrations',
        'docs/operations',
        'docs/release',
        'RELEASE.json',
        'SHA256SUMS.json',
        'SIGNING_REQUIRED.txt'
    )
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolved $relative))) {
            throw "release bundle is missing required asset: $relative"
        }
    }

    $codexRoot = Join-Path $resolved 'integrations/codex'
    $codexPluginRoot = Join-Path $codexRoot 'plugins/eliot-governor'
    $marketplace = Get-Content -LiteralPath (Join-Path $codexRoot 'marketplace.json') -Raw | ConvertFrom-Json
    $marketplacePlugins = @($marketplace.plugins)
    if ([string]$marketplace.name -ne 'eliot-system' -or
        $marketplacePlugins.Count -ne 1 -or
        [string]$marketplacePlugins[0].name -ne 'eliot-governor' -or
        [string]$marketplacePlugins[0].source.source -ne 'local' -or
        [string]$marketplacePlugins[0].source.path -ne './plugins/eliot-governor' -or
        [string]$marketplacePlugins[0].policy.installation -ne 'INSTALLED_BY_DEFAULT' -or
        [string]$marketplacePlugins[0].policy.authentication -ne 'ON_INSTALL' -or
        [string]$marketplacePlugins[0].category -ne 'Developer Tools') {
        throw 'release Codex marketplace does not expose exactly one installed-by-default ELIOT plugin'
    }

    $release = Get-Content -LiteralPath (Join-Path $resolved 'RELEASE.json') -Raw | ConvertFrom-Json
    $plugin = Get-Content -LiteralPath (Join-Path $codexPluginRoot '.codex-plugin/plugin.json') -Raw | ConvertFrom-Json
    if ([string]$plugin.name -ne 'eliot-governor' -or
        [string]$plugin.version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
        [string]$plugin.version -ne [string]$release.codex_plugin_base_version -or
        [string]$plugin.author.name -ne 'ELIOT' -or
        [string]$plugin.skills -ne './skills/' -or
        [string]$plugin.mcpServers -ne './.mcp.json' -or
        [string]$plugin.interface.displayName -ne 'ELIOT Governor' -or
        $plugin.PSObject.Properties.Name -contains 'hooks') {
        throw 'release Codex plugin manifest does not match the canonical cache-neutral base contract'
    }

    $mcp = Get-Content -LiteralPath (Join-Path $codexPluginRoot '.mcp.json') -Raw | ConvertFrom-Json
    $serverProperties = @($mcp.mcpServers.PSObject.Properties)
    if ($serverProperties.Count -ne 1 -or $serverProperties[0].Name -ne 'eliot') {
        throw 'release Codex plugin must expose exactly one MCP server named eliot'
    }
    $server = $serverProperties[0].Value
    if ([string]$server.type -ne 'stdio' -or
        [string]$server.command -ne 'bin/eliot-governor.exe' -or
        [string]$server.cwd -ne '.' -or
        $server.enabled -ne $true -or
        $server.required -ne $true) {
        throw 'release Codex MCP server transport is not the required local plugin binary'
    }
    $expectedArgs = @('mcp', 'stdio', '--profile', 'codex_controller', '--instance', 'default')
    $actualArgs = @($server.args)
    if ($actualArgs.Count -ne $expectedArgs.Count) {
        throw 'release Codex MCP server has the wrong argument count'
    }
    for ($index = 0; $index -lt $expectedArgs.Count; $index++) {
        if ([string]$actualArgs[$index] -ne $expectedArgs[$index]) {
            throw "release Codex MCP server argument $index is not canonical"
        }
    }
    $rootGovernorHash = (Get-FileHash -LiteralPath (Join-Path $resolved 'eliot-governor.exe') -Algorithm SHA256).Hash
    $pluginGovernorHash = (Get-FileHash -LiteralPath (Join-Path $codexPluginRoot 'bin/eliot-governor.exe') -Algorithm SHA256).Hash
    if ($rootGovernorHash -ne $pluginGovernorHash) {
        throw 'release Codex plugin binary differs from the release Governor binary'
    }

    $manifest = Get-Content -LiteralPath (Join-Path $resolved 'SHA256SUMS.json') -Raw | ConvertFrom-Json
    if ([string]$release.source_commit -notmatch '^[0-9a-f]{40}$' -or $release.source_commit -ne $manifest.source_commit) {
        throw 'release source commit is missing, malformed, or differs from the checksum manifest'
    }
    $declared = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($file in $manifest.files) {
        $relative = ([string]$file.path).Replace('\', '/')
        $segments = @($relative -split '/')
        if ([System.IO.Path]::IsPathRooted($relative) -or $segments -contains '..' -or $segments -contains '') {
            throw "release checksum path is unsafe: $relative"
        }
        if (-not $declared.Add($relative)) {
            throw "release checksum path is duplicated: $relative"
        }
        $candidate = Join-Path $resolved $relative.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "release checksum target is missing: $relative"
        }
        $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $file.sha256 -or (Get-Item -LiteralPath $candidate).Length -ne $file.bytes) {
            throw "release checksum mismatch: $relative"
        }
    }
    $actualPayload = @(Get-ChildItem -LiteralPath $resolved -File -Recurse | ForEach-Object {
        $_.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
    } | Where-Object { $_ -ne 'SHA256SUMS.json' })
    foreach ($relative in $actualPayload) {
        if (-not $declared.Contains($relative)) {
            throw "release bundle contains an unmanifested file: $relative"
        }
    }
    if ($actualPayload.Count -ne $declared.Count) {
        throw "release manifest/file count mismatch: declared=$($declared.Count) actual=$($actualPayload.Count)"
    }
    [ordered]@{ component = 'eliot_windows_x64_release_verify'; status = 'VERIFIED_UNSIGNED'; bundle = $resolved; files = $manifest.files.Count }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

if ($VerifyBundle) {
    Test-ReleaseBundle $VerifyBundle | ConvertTo-Json -Depth 5
    exit 0
}

$bundleName = "eliot-windows-x64-$Version-unsigned"
$resolvedOutputRoot = if ([System.IO.Path]::IsPathRooted($OutputRoot)) {
    [System.IO.Path]::GetFullPath($OutputRoot)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $repo $OutputRoot))
}
$bundle = Join-Path $resolvedOutputRoot $bundleName
$cargoMetadata = (& cargo metadata --format-version 1 --no-deps 2>$null | Out-String) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $cargoMetadata.target_directory) {
    throw 'failed to resolve the Cargo target directory'
}
$governorPath = Join-Path ([string]$cargoMetadata.target_directory) 'release\eliot-governor.exe'
$sourceCommit = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'failed to resolve the release source commit'
}
$codexPluginSource = Join-Path $repo 'plugin/eliot-governor'
$codexPluginManifestPath = Join-Path $codexPluginSource '.codex-plugin/plugin.json'
$codexPluginManifest = Get-Content -LiteralPath $codexPluginManifestPath -Raw | ConvertFrom-Json
$codexPluginBaseVersion = [string]$codexPluginManifest.version
if ([string]$codexPluginManifest.name -ne 'eliot-governor' -or
    $codexPluginBaseVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
    throw 'Codex release source must use a cache-neutral base SemVer without +codex metadata'
}
$plan = [ordered]@{
    component = 'eliot_windows_x64_release'
    version = $Version
    source_commit = $sourceCommit
    architecture = 'windows-x64'
    signed = $false
    source_policy = 'pinned-commit-tracked-files-only'
    secret_scan = 'required-before-manifest-and-on-verification'
    output = $bundle
    governor = $governorPath
    operator_source = $OperatorSource
    codex_marketplace_source = (Join-Path $repo 'integrations/codex/marketplace.json')
    codex_plugin_source = $codexPluginSource
    codex_plugin_base_version = $codexPluginBaseVersion
    codex_mcp_profile = 'codex_controller'
    includes = @('governor', 'operator', 'config', 'integrations', 'codex-marketplace', 'codex-plugin', 'skills', 'migrations', 'operations-runbooks')
    signing_required_before_public_distribution = $true
}

if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 5
    exit 0
}

    if (-not $OperatorSource) {
    throw 'OperatorSource is required for every staged release; use -PlanOnly to inspect without artifacts'
}

Push-Location $repo
try {
    $trackedChanges = @(& git status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to inspect the release source tree'
    }
    if ($trackedChanges.Count -gt 0) {
        throw 'release staging requires a clean tracked source tree'
    }
    if ($SkipBuild) {
        throw 'SkipBuild is not permitted for staged releases because it cannot prove Governor source provenance'
    }
    & cargo build --release -p eliot-app
    if ($LASTEXITCODE -ne 0) {
        throw "cargo release build failed with exit code $LASTEXITCODE"
    }
    $postBuildCommit = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()
    $postBuildChanges = @(& git -C $repo status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $postBuildCommit -ne $sourceCommit -or $postBuildChanges.Count -gt 0) {
        throw 'release source changed during the Governor build'
    }

    $governor = $governorPath
    if (-not (Test-Path -LiteralPath $governor -PathType Leaf)) {
        throw "release governor executable is missing: $governor"
    }

    if (Test-Path -LiteralPath $bundle) {
        throw "release bundle already exists; choose another version or output root: $bundle"
    }
    New-Item -ItemType Directory -Path $bundle | Out-Null
    Assert-NoSecretFile (Get-Item -LiteralPath $governor) 'eliot-governor.exe'
    Copy-Item -LiteralPath $governor -Destination $bundle
    Copy-TrackedTree $repo $sourceCommit 'config' (Join-Path $bundle 'config')
    Copy-TrackedTree $repo $sourceCommit 'integrations' (Join-Path $bundle 'integrations')
    $codexPluginRoot = Join-Path $bundle 'integrations/codex/plugins/eliot-governor'
    Copy-TrackedTree $repo $sourceCommit 'plugin/eliot-governor' $codexPluginRoot
    $codexPluginBin = Join-Path $codexPluginRoot 'bin'
    New-Item -ItemType Directory -Path $codexPluginBin -Force | Out-Null
    Copy-Item -LiteralPath $governor -Destination (Join-Path $codexPluginBin 'eliot-governor.exe')
    Copy-TrackedTree $repo $sourceCommit 'plugin/eliot-antigravity-official' (Join-Path $bundle 'integrations/antigravity/official-plugin')
    Copy-TrackedTree $repo $sourceCommit 'integrations/agent-skills' (Join-Path $bundle 'skills')
    Copy-TrackedTree $repo $sourceCommit 'migrations' (Join-Path $bundle 'migrations')
    Copy-TrackedTree $repo $sourceCommit 'docs/operations' (Join-Path $bundle 'docs/operations')
    Copy-TrackedTree $repo $sourceCommit 'docs/release' (Join-Path $bundle 'docs/release')

    $resolvedOperator = (Resolve-Path -LiteralPath $OperatorSource).Path
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedOperator 'Eliot.Operator.exe') -PathType Leaf)) {
        throw "OperatorSource does not contain Eliot.Operator.exe: $resolvedOperator"
    }
    Copy-OperatorPayload $resolvedOperator (Join-Path $bundle 'operator')

    $operatorContracts = Get-Content -LiteralPath (Join-Path $repo 'apps/Eliot.Operator/Protocol/OperatorContracts.cs') -Raw
    $schemaVersion = [regex]::Match($operatorContracts, 'SchemaVersion = "([^"]+)"').Groups[1].Value
    $protocolVersion = [regex]::Match($operatorContracts, 'IpcProtocolVersion = "([^"]+)"').Groups[1].Value
    $protocolHash = [regex]::Match($operatorContracts, 'PinnedContractHash = "([0-9a-f]{64})"').Groups[1].Value
    if (-not $schemaVersion -or -not $protocolVersion -or -not $protocolHash) {
        throw 'failed to read the pinned Operator protocol contract'
    }
    [ordered]@{
        component = 'eliot_windows_x64_release'
        version = $Version
        source_commit = $sourceCommit
        governor_version = $Version
        operator_schema_version = $schemaVersion
        operator_protocol_version = $protocolVersion
        operator_protocol_hash = $protocolHash
        codex_plugin_base_version = $codexPluginBaseVersion
        architecture = 'windows-x64'
        signed = $false
        public_distribution_ready = $false
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $bundle 'RELEASE.json') -Encoding utf8

    @'
This bundle is intentionally unsigned. Before public distribution:
1. Sign every shipped .exe and .dll with the organization EV/OV Authenticode certificate.
2. Verify with: Get-AuthenticodeSignature <file>.
3. Rebuild SHA256SUMS.json after signing.
4. Timestamp signatures using the certificate provider's RFC3161 service.
'@ | Set-Content -LiteralPath (Join-Path $bundle 'SIGNING_REQUIRED.txt') -Encoding utf8

    Assert-NoReleaseSecrets $bundle
    $hashes = Get-ChildItem -LiteralPath $bundle -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $relativePath = $_.FullName.Substring($bundle.Length).TrimStart([char]'\').Replace('\', '/')
            [ordered]@{
                path = $relativePath
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                bytes = $_.Length
            }
        }
    [ordered]@{
        component = 'eliot_windows_x64_release_manifest'
        version = $Version
        source_commit = $sourceCommit
        architecture = 'windows-x64'
        signed = $false
        files = @($hashes)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bundle 'SHA256SUMS.json') -Encoding utf8
    $verification = Test-ReleaseBundle $bundle
    $plan.status = 'STAGED_UNSIGNED'
    $plan.verification = $verification
    $plan | ConvertTo-Json -Depth 5
}
finally {
    Pop-Location
}
