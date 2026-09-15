[CmdletBinding()]
param(
    [string]$Version = '0.1.0',
    [string]$OutputRoot = (Join-Path $env:LOCALAPPDATA 'Eliot\packages'),
    [string]$OperatorSource,
    [string]$SurrealExe,
    [string]$SurrealSha256,
    [string]$SurrealVersion,
    [switch]$SkipBuild,
    [switch]$PlanOnly,
    [Alias('VerifyBundle')]
    [string]$BuilderVerifyBundle
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$surrealCatalogRelativePath = 'docs/release/SURREALDB_WINDOWS_X64.lock.json'
$runtimeArtifactDefinitions = @(
    [pscustomobject]@{
        package = 'eliot'
        binary = 'eliot'
        role = 'cli'
        relative_path = 'runtime/eliot.exe'
    }
    [pscustomobject]@{
        package = 'eliot-host'
        binary = 'eliot-host'
        role = 'host'
        relative_path = 'runtime/eliot-host.exe'
    }
    [pscustomobject]@{
        package = 'eliot-watchdog'
        binary = 'eliot-watchdog'
        role = 'watchdog'
        relative_path = 'runtime/eliot-watchdog.exe'
    }
    [pscustomobject]@{
        package = 'eliot-kernel'
        binary = 'eliot-kernel'
        role = 'kernel'
        relative_path = 'runtime/eliot-kernel.exe'
    }
    [pscustomobject]@{
        package = 'eliot-store-surreal'
        binary = 'eliot-store-surreal'
        role = 'store_bridge'
        relative_path = 'runtime/eliot-store-surreal.exe'
    }
    [pscustomobject]@{
        package = 'eliotd'
        binary = 'eliotd'
        role = 'daemon'
        relative_path = 'runtime/eliotd.exe'
    }
    [pscustomobject]@{
        package = 'eliot-doctor'
        binary = 'eliot-doctor'
        role = 'doctor'
        relative_path = 'runtime/eliot-doctor.exe'
    }
    [pscustomobject]@{
        package = 'eliot-testd'
        binary = 'eliot-testd'
        role = 'testd'
        relative_path = 'runtime/eliot-testd.exe'
    }
    [pscustomobject]@{
        package = 'eliot-native-worker'
        binary = 'eliot-native-worker'
        role = 'native_worker'
        relative_path = 'runtime/eliot-native-worker.exe'
    }
)

function Get-RuntimeArtifactDefinitions {
    return @($runtimeArtifactDefinitions | ForEach-Object {
            [pscustomobject]@{
                package = [string]$_.package
                binary = [string]$_.binary
                role = [string]$_.role
                relative_path = [string]$_.relative_path
            }
        })
}

function Get-RuntimeArtifactPlan([object]$Metadata) {
    if (-not $Metadata -or [string]::IsNullOrWhiteSpace([string]$Metadata.target_directory)) {
        throw 'Cargo metadata did not provide a target directory for runtime artifacts'
    }
    $targetDirectory = [System.IO.Path]::GetFullPath([string]$Metadata.target_directory)
    $packages = @{}
    foreach ($package in @($Metadata.packages)) {
        $packageName = [string]$package.name
        if ($packageName -and $packages.ContainsKey($packageName)) {
            throw "Cargo metadata contains a duplicate package name: $packageName"
        }
        if ($packageName) {
            $packages[$packageName] = $package
        }
    }

    $plan = foreach ($definition in Get-RuntimeArtifactDefinitions) {
        if (-not $packages.ContainsKey($definition.package)) {
            throw "Cargo metadata is missing required runtime package: $($definition.package)"
        }
        $targets = @($packages[$definition.package].targets | Where-Object {
                [string]$_.name -eq $definition.binary -and @($_.kind) -contains 'bin'
            })
        if ($targets.Count -ne 1) {
            throw "Cargo metadata must expose exactly one binary target '$($definition.binary)' for package '$($definition.package)'"
        }
        [pscustomobject]@{
            package = $definition.package
            binary = $definition.binary
            role = $definition.role
            relative_path = $definition.relative_path
            path = Join-Path $targetDirectory "release\$($definition.binary).exe"
        }
    }
    return @($plan)
}

function Get-VerifiedRuntimeArtifacts([object[]]$Plan, [string]$Version) {
    $artifacts = foreach ($entry in @($Plan)) {
        if (-not (Test-Path -LiteralPath $entry.path -PathType Leaf)) {
            throw "required runtime executable is missing: $($entry.path)"
        }
        $file = Get-Item -LiteralPath $entry.path
        Assert-NoSecretFile $file $entry.relative_path
        [void](Assert-WindowsX64Pe $file.FullName $entry.relative_path)
        [ordered]@{
            package = $entry.package
            binary = $entry.binary
            role = $entry.role
            path = $entry.relative_path
            source = 'cargo'
            version = $Version
            architecture = 'windows-x64'
            linker_version = (Get-WindowsPeLinkerVersion $file.FullName $entry.relative_path)
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = $file.Length
        }
    }
    return @($artifacts)
}

function Get-WindowsPeMachine([string]$Path, [string]$RelativePath) {
    $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        $dos = [byte[]]::new(64)
        if ($stream.Read($dos, 0, $dos.Length) -ne $dos.Length -or
            $dos[0] -ne 0x4d -or $dos[1] -ne 0x5a) {
            throw "release artifact is not a PE executable: $RelativePath"
        }
        $peOffset = [System.BitConverter]::ToInt32($dos, 0x3c)
        if ($peOffset -lt 64 -or $peOffset -gt 16MB -or
            $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) -ne $peOffset) {
            throw "release artifact has an invalid PE header: $RelativePath"
        }
        $header = [byte[]]::new(6)
        if ($stream.Read($header, 0, $header.Length) -ne $header.Length -or
            $header[0] -ne 0x50 -or $header[1] -ne 0x45 -or
            $header[2] -ne 0 -or $header[3] -ne 0) {
            throw "release artifact has an invalid PE signature: $RelativePath"
        }
        $machine = [System.BitConverter]::ToUInt16($header, 4)
        return ('{0:X4}' -f $machine)
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-WindowsX64Pe([string]$Path, [string]$RelativePath) {
    $machine = Get-WindowsPeMachine $Path $RelativePath
    if ($machine -cne '8664') {
        throw "release artifact is not Windows x64 (machine=0x$machine): $RelativePath"
    }
}

function Assert-PinnedExternalPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose must be an explicit absolute path; PATH and environment lookup are forbidden"
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (-not ($file -is [System.IO.FileInfo]) -or
        ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [string]::IsNullOrWhiteSpace([string]$file.LinkType) -or
        @($file.Target | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0) {
        throw "$Purpose must be a resident regular non-reparse file: $resolved"
    }
    $parent = $file.Directory
    while ($parent) {
        if (($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose parent directory is a reparse point: $($parent.FullName)"
        }
        $next = $parent.Parent
        if (-not $next -or $next.FullName -eq $parent.FullName) { break }
        $parent = $next
    }
    return $file
}

function Get-VerifiedSurrealCatalog([string]$Repo, [string]$SourceCommit) {
    $catalogPath = Join-Path $Repo $surrealCatalogRelativePath
    if (-not (Test-Path -LiteralPath $catalogPath -PathType Leaf)) {
        throw "tracked SurrealDB artifact catalog is missing: $surrealCatalogRelativePath"
    }
    $catalogFile = Get-Item -LiteralPath $catalogPath
    $catalogBlob = Get-GitBlobHash $Repo $SourceCommit $surrealCatalogRelativePath
    $catalogSourceHash = Get-FilteredFileHash $Repo $surrealCatalogRelativePath $catalogFile.FullName
    if ($catalogSourceHash -ne $catalogBlob) {
        throw "tracked SurrealDB artifact catalog differs from pinned source commit: $surrealCatalogRelativePath"
    }
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json
    if ([string]$catalog.schema -ne 'eliot-external-release-artifact-lock-v1' -or
        [string]$catalog.artifact -cne 'surreal.exe' -or
        [string]$catalog.relative_path -cne 'runtime/surreal.exe' -or
        [string]$catalog.version -cne '3.1.4' -or
        [string]$catalog.architecture -cne 'windows-x64' -or
        [string]$catalog.pe_machine -cne '8664' -or
        [string]$catalog.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'tracked SurrealDB artifact catalog is missing its canonical filename/version/architecture/digest binding'
    }
    [pscustomobject]@{
        path = $catalogPath
        relative_path = $surrealCatalogRelativePath
        source_commit = $SourceCommit
        sha256 = (Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash.ToLowerInvariant()
        artifact = [string]$catalog.artifact
        runtime_path = [string]$catalog.relative_path
        version = [string]$catalog.version
        architecture = [string]$catalog.architecture
        pe_machine = [string]$catalog.pe_machine
        artifact_sha256 = ([string]$catalog.sha256).ToLowerInvariant()
    }
}

function Get-VerifiedPinnedSurrealArtifact([string]$Path, [string]$ExpectedSha256, [string]$ExpectedVersion, [object]$Catalog) {
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'SurrealSha256 must be the caller-supplied 64-character SHA-256 pin'
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) {
        throw 'SurrealVersion must be the caller-supplied exact file version pin'
    }
    if (-not $Catalog -or [string]$Catalog.runtime_path -cne 'runtime/surreal.exe') {
        throw 'SurrealDB artifact catalog is required for the canonical runtime path'
    }
    if ($ExpectedSha256.ToLowerInvariant() -cne [string]$Catalog.artifact_sha256 -or
        $ExpectedVersion -cne [string]$Catalog.version) {
        throw 'SurrealVersion and SurrealSha256 must match the tracked SurrealDB artifact catalog'
    }
    $file = Assert-PinnedExternalPath $Path 'SurrealExe'
    if ($file.Name -cne 'surreal.exe') {
        throw "SurrealExe must name the canonical surreal.exe file: $($file.FullName)"
    }
    Assert-NoSecretFile $file 'runtime/surreal.exe'
    [void](Assert-WindowsX64Pe $file.FullName 'runtime/surreal.exe')
    $actualSha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $pinnedSha256 = $ExpectedSha256.ToLowerInvariant()
    if ($actualSha256 -ne $pinnedSha256) {
        throw "SurrealExe SHA-256 does not match the caller-supplied pin: $($file.FullName)"
    }
    $machine = Get-WindowsPeMachine $file.FullName 'runtime/surreal.exe'
    if ($machine -cne [string]$Catalog.pe_machine) {
        throw "SurrealExe PE machine does not match the tracked catalog: expected $($Catalog.pe_machine), actual $machine"
    }
    [ordered]@{
        package = 'surrealdb'
        binary = 'surreal'
        role = 'database'
        path = 'runtime/surreal.exe'
        source = 'caller-pinned-absolute-path'
        version = $ExpectedVersion
        architecture = 'windows-x64'
        catalog_path = $Catalog.relative_path
        catalog_sha256 = $Catalog.sha256
        catalog_source_commit = $Catalog.source_commit
        pe_machine = $Catalog.pe_machine
        sha256 = $actualSha256
        bytes = $file.Length
        signature_policy = 'pre-release-unsigned'
        signature_evidence = 'not-issued'
    }
}

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

function Resolve-PinnedFileTarget([string]$Path, [string]$Purpose) {
    # Rustup shims (cargo/rustc) are symbolic links to rustup.exe and some
    # vendor installs (Git) expose hardlinks. A hardlink with no outstanding
    # target is a direct resident directory entry, not a redirection, so it
    # is accepted; symbolic links are followed to their final resident file
    # (depth-capped) and every hop is recorded. Reparse points, junctions,
    # and ambiguous targets remain forbidden.
    $candidate = Get-Item -LiteralPath $Path -ErrorAction Stop
    $chain = @([string]$candidate.FullName)
    $depth = 0
    while (-not [string]::IsNullOrWhiteSpace([string]$candidate.LinkType) -and
        -not ([string]$candidate.LinkType -ceq 'HardLink' -and
            @($candidate.Target | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -eq 0)) {
        $depth++
        if ($depth -gt 8) {
            throw "$Purpose link chain is too deep: $($chain -join ' -> ')"
        }
        $targets = @($candidate.Target | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        if ($targets.Count -ne 1) {
            throw "$Purpose link target is ambiguous: $($candidate.FullName)"
        }
        $next = [string]$targets[0]
        if (-not [System.IO.Path]::IsPathRooted($next)) {
            $next = Join-Path $candidate.Directory.FullName $next
        }
        $candidate = Get-Item -LiteralPath $next -ErrorAction Stop
        $chain += [string]$candidate.FullName
    }
    $pinned = Get-Item -LiteralPath $candidate.FullName -ErrorAction Stop
    if (-not ($pinned -is [System.IO.FileInfo]) -or
        (($pinned.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) -or
        @($pinned.Target | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0 -or
        (-not [string]::IsNullOrWhiteSpace([string]$pinned.LinkType) -and [string]$pinned.LinkType -cne 'HardLink')) {
        throw "$Purpose must be a resident regular file: $($pinned.FullName)"
    }
    # Execution always uses the verified invoked path (chain head, e.g. a
    # rustup shim that proxies argv[0] to the pinned toolchain). The final
    # link target is the pinned identity. Every hop's parent chain must be
    # free of reparse points so the verified path cannot be redirected.
    foreach ($hop in @($chain)) {
        $hopParent = (Get-Item -LiteralPath $hop -ErrorAction Stop).Directory
        while ($hopParent) {
            if (($hopParent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "$Purpose parent directory is a reparse point: $($hopParent.FullName)"
            }
            $nextParent = $hopParent.Parent
            if (-not $nextParent -or $nextParent.FullName -eq $hopParent.FullName) { break }
            $hopParent = $nextParent
        }
    }
    return [pscustomobject]@{ file = $pinned; chain = @($chain) }
}

function Get-PinnedCommandFile([string]$Name, [string]$Purpose) {
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
    if (-not $command -or [string]::IsNullOrWhiteSpace([string]$command.Source)) {
        throw "$Purpose command is not resolvable as an application: $Name"
    }
    return (Resolve-PinnedFileTarget ([string]$command.Source) $Purpose).file
}

function Get-WindowsPeLinkerVersion([string]$Path, [string]$RelativePath) {
    $stream = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
    try {
        $dos = [byte[]]::new(64)
        if ($stream.Read($dos, 0, $dos.Length) -ne $dos.Length) {
            throw "release artifact has an unreadable DOS header: $RelativePath"
        }
        $peOffset = [System.BitConverter]::ToInt32($dos, 0x3c)
        $optionalOffset = $peOffset + 4 + 20
        if ($optionalOffset -lt 64 -or $optionalOffset -gt 16MB -or
            $stream.Seek($optionalOffset, [System.IO.SeekOrigin]::Begin) -ne $optionalOffset) {
            throw "release artifact has an invalid PE optional header: $RelativePath"
        }
        $optional = [byte[]]::new(4)
        if ($stream.Read($optional, 0, $optional.Length) -ne $optional.Length) {
            throw "release artifact has an unreadable PE optional header: $RelativePath"
        }
        $magic = [System.BitConverter]::ToUInt16($optional, 0)
        if ($magic -ne 0x10b -and $magic -ne 0x20b) {
            throw "release artifact has an unknown PE optional magic: $RelativePath"
        }
        return ('{0}.{1}' -f [int]$optional[2], [int]$optional[3])
    }
    finally {
        $stream.Dispose()
    }
}

function Get-BuildEnvIdentity {
    $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($name in @('PATH', 'SystemRoot', 'windir', 'OS', 'PROCESSOR_ARCHITECTURE', 'NUMBER_OF_PROCESSORS',
            'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'RUSTC', 'RUSTFLAGS', 'RUSTDOCFLAGS',
            'CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'TARGET', 'HOST', 'PROFILE', 'OPT_LEVEL', 'DEBUG',
            'WindowsSdkDir', 'WindowsSDKVersion', 'WindowsSdkVersion', 'LIB', 'INCLUDE', 'LIBPATH',
            'VSINSTALLDIR', 'VSCMD_VER', 'VCINSTALLDIR', 'VCToolsInstallDir', 'VCToolsVersion',
            'UCRTVersion', 'UniversalCRTSdkDir', 'DOTNET_ROOT', 'DOTNET_CLI_TELEMETRY_OPTOUT',
            'NUGET_PACKAGES', 'MSBuildSDKsPath')) {
        [void]$names.Add($name)
    }
    $pairs = foreach ($entry in Get-ChildItem Env:) {
        if ($names.Contains($entry.Name) -or
            $entry.Name.StartsWith('CARGO_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $entry.Name.StartsWith('VSCMD_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $entry.Name.StartsWith('DOTNET_', [System.StringComparison]::OrdinalIgnoreCase) -or
            $entry.Name.StartsWith('NUGET_', [System.StringComparison]::OrdinalIgnoreCase)) {
            '{0}={1}' -f $entry.Name, [string]$entry.Value
        }
    }
    # Only the digest is recorded: values may embed machine-local layout and
    # must not leak raw into the distributable receipt. Any value change
    # alters the digest and fails future input-equality comparison.
    $canonical = (@($pairs | Sort-Object) -join "`n")
    $digestBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [System.Text.Encoding]::UTF8.GetBytes($canonical))
    [ordered]@{
        names = @($pairs | ForEach-Object { ($_ -split '=', 2)[0] } | Sort-Object -Unique)
        digest = (($digestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
}

function Assert-IsolatedSourceTree([string]$Repo, [string]$SourceCommit, [string]$Phase) {
    $head = (& git -C $Repo rev-parse HEAD 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') {
        throw "failed to resolve the release source commit ($Phase)"
    }
    if ($head -ne $SourceCommit) {
        throw "release source isolation violated ($Phase): HEAD $head is not the pinned source commit $SourceCommit"
    }
    $status = @(& git -C $Repo status --porcelain --untracked-files=all 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "failed to inspect the release source tree ($Phase)"
    }
    if ($status.Count -gt 0) {
        $suffix = if ($status.Count -gt 1) { " (+$($status.Count - 1) more)" } else { '' }
        throw "release staging requires an isolated clean source tree ($Phase): $($status[0])$suffix"
    }
    if (Test-Path -LiteralPath (Join-Path $Repo '.cargo')) {
        throw 'release staging rejects local .cargo configuration: .cargo'
    }
    [ordered]@{
        phase = $Phase
        head = $head
        tracked_clean = $true
        untracked_rejected = $true
        cargo_config_absent = $true
    }
}

function Copy-PinnedSourceFile([string]$Repo, [string]$SourceCommit, [string]$Source, [string]$Destination) {
    $relative = Assert-SafeRelativePath $Source 'tracked source file'
    $sourceFile = Get-Item -LiteralPath (Join-Path $Repo $relative) -ErrorAction Stop
    Assert-TrackedSourceFile $sourceFile $relative
    $expectedHash = Get-GitBlobHash $Repo $SourceCommit $relative
    $sourceHash = Get-FilteredFileHash $Repo $relative $sourceFile.FullName
    if ($sourceHash -ne $expectedHash) {
        throw "tracked release source differs from pinned commit: $relative"
    }
    Assert-NoSecretFile $sourceFile $relative
    $parent = Split-Path -Parent $Destination
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    Copy-Item -LiteralPath $sourceFile.FullName -Destination $Destination
    $copiedHash = Get-FilteredFileHash $Repo $relative $Destination
    if ($copiedHash -ne $expectedHash) {
        throw "release source changed while being copied: $relative"
    }
}

function Get-ToolchainBuildReceipt([string]$Repo, [string]$SourceCommit, [object]$CargoMetadata, [string]$Mode) {
    if ($Mode -ne 'plan' -and $Mode -ne 'stage') {
        throw "toolchain receipt mode must be plan or stage: $Mode"
    }
    $cargoCommand = Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1
    if (-not $cargoCommand -or [string]::IsNullOrWhiteSpace([string]$cargoCommand.Source)) {
        throw 'Cargo command is not resolvable as an application: cargo'
    }
    $cargoResolved = Resolve-PinnedFileTarget ([string]$cargoCommand.Source) 'Cargo'
    $cargoFile = $cargoResolved.file
    $cargoInvokePath = [string]$cargoResolved.chain[0]
    $gitFile = Get-PinnedCommandFile 'git' 'Git'
    $cargoVersion = (& $cargoInvokePath --version 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($cargoVersion)) {
        throw 'failed to resolve the Cargo version identity'
    }
    $rustcSibling = Join-Path $cargoFile.Directory.FullName 'rustc.exe'
    if (Test-Path -LiteralPath $rustcSibling -PathType Leaf) {
        $rustcResolved = Resolve-PinnedFileTarget $rustcSibling 'rustc (cargo sibling)'
    }
    else {
        $rustcCommand = Get-Command rustc -CommandType Application -ErrorAction Stop | Select-Object -First 1
        if (-not $rustcCommand -or [string]::IsNullOrWhiteSpace([string]$rustcCommand.Source)) {
            throw 'rustc command is not resolvable as an application: rustc'
        }
        $rustcResolved = Resolve-PinnedFileTarget ([string]$rustcCommand.Source) 'rustc'
    }
    $rustcFile = $rustcResolved.file
    $rustcInvokePath = [string]$rustcResolved.chain[0]
    $rustcVersion = (& $rustcInvokePath --version 2>$null | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($rustcVersion)) {
        throw 'failed to resolve the rustc version identity'
    }
    $rustcDetail = @(& $rustcInvokePath -vV 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to resolve the rustc verbose version identity'
    }
    $releaseLine = @($rustcDetail | Where-Object { $_ -match '^release:\s*(\S+)' })
    $hostLine = @($rustcDetail | Where-Object { $_ -match '^host:\s*(\S+)' })
    $commitLine = @($rustcDetail | Where-Object { $_ -match '^commit-hash:\s*(\S+)' })
    $llvmLine = @($rustcDetail | Where-Object { $_ -match '^LLVM version:\s*(\S+)' })
    if ($releaseLine.Count -ne 1 -or $hostLine.Count -ne 1) {
        throw 'rustc verbose version is missing its release/host identity'
    }
    $targetTriple = ([regex]::Match($hostLine[0], '^host:\s*(\S+)')).Groups[1].Value
    if ($targetTriple -cne 'x86_64-pc-windows-msvc') {
        throw "release toolchain target is not Windows x64 MSVC: $targetTriple"
    }
    $cfgLines = @(& $rustcInvokePath --print cfg 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to resolve the rustc target configuration identity'
    }
    foreach ($expected in @('target_arch="x86_64"', 'target_os="windows"', 'target_env="msvc"')) {
        if (@($cfgLines | Where-Object { $_ -eq $expected }).Count -ne 1) {
            throw "rustc target configuration is not Windows x64 MSVC: missing $expected"
        }
    }
    $toolchainRel = 'rust-toolchain.toml'
    $lockRel = 'Cargo.lock'
    foreach ($rel in @($toolchainRel, $lockRel)) {
        if (-not (Test-Path -LiteralPath (Join-Path $Repo $rel) -PathType Leaf)) {
            throw "release toolchain input is missing from the pinned source tree: $rel"
        }
    }
    $toolchainFile = Get-Item -LiteralPath (Join-Path $Repo $toolchainRel)
    $lockFile = Get-Item -LiteralPath (Join-Path $Repo $lockRel)
    $toolchainHash = (Get-FileHash -LiteralPath $toolchainFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $lockHash = (Get-FileHash -LiteralPath $lockFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ((Get-FilteredFileHash $Repo $toolchainRel $toolchainFile.FullName) -ne (Get-GitBlobHash $Repo $SourceCommit $toolchainRel)) {
        throw "release toolchain input differs from pinned source commit: $toolchainRel"
    }
    if ((Get-FilteredFileHash $Repo $lockRel $lockFile.FullName) -ne (Get-GitBlobHash $Repo $SourceCommit $lockRel)) {
        throw "release dependency lock differs from pinned source commit: $lockRel"
    }
    $channel = ([regex]::Match((Get-Content -LiteralPath $toolchainFile.FullName -Raw), 'channel\s*=\s*"([^"]+)"')).Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($channel)) {
        throw 'pinned rust-toolchain.toml does not declare its channel'
    }
    if ($cargoVersion -notlike "*$channel*" -or $rustcVersion -notlike "*$channel*") {
        throw "active Cargo/rustc identity does not match the pinned toolchain channel: $channel"
    }
    $metadataArgv = @('metadata', '--frozen', '--locked', '--offline', '--format-version', '1', '--no-deps')
    $buildArgvTemplate = @('build', '--frozen', '--locked', '--offline', '--release', '-p', '<package>', '--bin', '<binary>')
    $buildScripts = foreach ($definition in (Get-RuntimeArtifactDefinitions)) {
        $member = @(@($CargoMetadata.packages) | Where-Object { [string]$_.name -eq $definition.package })
        if ($member.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$member[0].manifest_path)) {
            throw "Cargo metadata is missing the manifest path for runtime package: $($definition.package)"
        }
        $manifestFull = [string]$member[0].manifest_path
        $manifestRelative = Assert-SafeRelativePath (
            $manifestFull.Substring((Join-Path $Repo '').Length).TrimStart([char]'\').Replace('\', '/')
        ) 'cargo member manifest'
        $memberDir = Split-Path -Parent $manifestFull
        $scriptCandidate = Join-Path $memberDir 'build.rs'
        if (Test-Path -LiteralPath $scriptCandidate -PathType Leaf) {
            $scriptRelative = Assert-SafeRelativePath (
                $scriptCandidate.Substring((Join-Path $Repo '').Length).TrimStart([char]'\').Replace('\', '/')
            ) 'cargo build script'
            $scriptFile = Get-Item -LiteralPath $scriptCandidate
            $scriptHash = (Get-FileHash -LiteralPath $scriptFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            if ((Get-FilteredFileHash $Repo $scriptRelative $scriptFile.FullName) -ne (Get-GitBlobHash $Repo $SourceCommit $scriptRelative)) {
                throw "cargo build script differs from pinned source commit: $scriptRelative"
            }
            [ordered]@{ package = $definition.package; path = $scriptRelative; present = $true; sha256 = $scriptHash }
        }
        else {
            [ordered]@{ package = $definition.package; path = $null; present = $false; sha256 = $null }
        }
    }
    $trackedBuildScripts = @(& git -C $Repo ls-tree -r --name-only $SourceCommit 2>$null |
        Where-Object { $_ -like '*/build.rs' -or $_ -eq 'build.rs' })
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to enumerate pinned cargo build scripts'
    }
    $dependencyClosure = 'plan-deferred'
    if ($Mode -eq 'stage') {
        $closureDigests = foreach ($definition in (Get-RuntimeArtifactDefinitions + @([pscustomobject]@{ package = 'eliot-app' }))) {
            $tree = (& $cargoInvokePath tree --frozen --offline --edges normal,build -p $definition.package --prefix none 2>$null | Out-String)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($tree)) {
                throw "failed to resolve the frozen dependency closure for package: $($definition.package)"
            }
            $treeDigest = (([System.Security.Cryptography.SHA256]::Create().ComputeHash(
                [System.Text.Encoding]::UTF8.GetBytes($tree)) | ForEach-Object { $_.ToString('x2') }) -join '')
            [ordered]@{ package = $definition.package; tree_sha256 = $treeDigest }
        }
        $dependencyClosure = @($closureDigests)
    }
    $linkCandidates = foreach ($candidate in @(Get-Command -CommandType Application link.exe -All -ErrorAction SilentlyContinue)) {
        $candidatePath = [string]$candidate.Source
        if (-not [string]::IsNullOrWhiteSpace($candidatePath) -and (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            [ordered]@{
                path = $candidatePath
                sha256 = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }
    }
    $vsInstallerRoot = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
    $vsWhere = Join-Path $vsInstallerRoot 'vswhere.exe'
    if (Test-Path -LiteralPath $vsWhere -PathType Leaf) {
        $vsInstalls = @(& $vsWhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $linker = [ordered]@{ policy = 'msvc-link-via-rustc'; vswhere = $vsWhere; msvc_installations = @($vsInstalls); link_candidates = @($linkCandidates) }
    }
    else {
        $linker = [ordered]@{ policy = 'msvc-link-via-rustc'; vswhere = $null; msvc_installations = @(); link_candidates = @($linkCandidates) }
    }
    $sdkRoots = @()
    foreach ($hive in @('HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots')) {
        if (Test-Path -LiteralPath $hive) {
            $kitsRoot = (Get-ItemProperty -LiteralPath $hive -Name KitsRoot10 -ErrorAction SilentlyContinue).KitsRoot10
            if (-not [string]::IsNullOrWhiteSpace([string]$kitsRoot)) {
                $sdkRoots += [ordered]@{ hive = $hive; kits_root_10 = [string]$kitsRoot }
            }
        }
    }
    $dotnetCommand = Get-Command dotnet -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($dotnetCommand -and -not [string]::IsNullOrWhiteSpace([string]$dotnetCommand.Source)) {
        $dotnetVersion = (& ([string]$dotnetCommand.Source) --version 2>$null | Out-String).Trim()
        $dotnetSdks = (& ([string]$dotnetCommand.Source) --list-sdks 2>$null | Out-String).Trim()
        $dotnet = [ordered]@{ path = [string]$dotnetCommand.Source; version = $dotnetVersion; list_sdks = $dotnetSdks }
    }
    else {
        $dotnet = [ordered]@{ path = $null; version = $null; list_sdks = $null }
    }
    [ordered]@{
        mode = $Mode
        source_commit = $SourceCommit
        cargo = [ordered]@{
            invoked_path = [string]$cargoCommand.Source
            path = $cargoFile.FullName
            link_chain = @($cargoResolved.chain)
            version = $cargoVersion
            sha256 = (Get-FileHash -LiteralPath $cargoFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        git = [ordered]@{
            path = $gitFile.FullName
            version = ((& $gitFile.FullName --version 2>$null | Out-String).Trim())
            sha256 = (Get-FileHash -LiteralPath $gitFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        rustc = [ordered]@{
            invoked_path = [string]$rustcResolved.chain[0]
            path = $rustcFile.FullName
            link_chain = @($rustcResolved.chain)
            version = $rustcVersion
            release = ([regex]::Match($releaseLine[0], '^release:\s*(\S+)')).Groups[1].Value
            commit = $(if ($commitLine.Count -eq 1) { ([regex]::Match($commitLine[0], '^commit-hash:\s*(\S+)')).Groups[1].Value } else { $null })
            llvm = $(if ($llvmLine.Count -eq 1) { ([regex]::Match($llvmLine[0], '^LLVM version:\s*(\S+)')).Groups[1].Value } else { $null })
        }
        powershell = [ordered]@{
            version = $PSVersionTable.PSVersion.ToString()
            edition = [string]$PSVersionTable.PSEdition
        }
        target_triple = $targetTriple
        rust_toolchain = [ordered]@{ path = $toolchainRel; sha256 = $toolchainHash; channel = $channel }
        cargo_lock = [ordered]@{ path = $lockRel; sha256 = $lockHash }
        build = [ordered]@{
            metadata_argv = @($metadataArgv)
            build_argv_template = @($buildArgvTemplate)
            features_policy = 'default-features-only (no --features, --all-features, or --no-default-features flag)'
        }
        env = (Get-BuildEnvIdentity)
        build_scripts = @($buildScripts)
        tracked_build_scripts = @($trackedBuildScripts)
        dependency_closure = $dependencyClosure
        linker = $linker
        windows_sdk = [ordered]@{ installed_roots = @($sdkRoots) }
        dotnet = $dotnet
    }
}

function Get-VerifiedOperatorBuildReceipt([string]$Repo, [string]$SourceCommit, [string]$OperatorSource) {
    $resolved = (Resolve-Path -LiteralPath $OperatorSource).Path
    $receiptPath = Join-Path $resolved 'OPERATOR_BUILD_RECEIPT.json'
    if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
        throw "OperatorSource does not carry its locked build receipt: $receiptPath"
    }
    $exePath = Join-Path $resolved 'Eliot.Operator.exe'
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "OperatorSource does not contain Eliot.Operator.exe: $resolved"
    }
    $csprojRel = 'apps/Eliot.Operator/Eliot.Operator.csproj'
    $lockRel = 'apps/Eliot.Operator/packages.lock.json'
    $contractsRel = 'apps/Eliot.Operator/Protocol/OperatorContracts.cs'
    foreach ($rel in @($csprojRel, $lockRel, $contractsRel)) {
        $pinnedFile = Get-Item -LiteralPath (Join-Path $Repo $rel) -ErrorAction Stop
        Assert-TrackedSourceFile $pinnedFile $rel
        if ((Get-FilteredFileHash $Repo $rel $pinnedFile.FullName) -ne (Get-GitBlobHash $Repo $SourceCommit $rel)) {
            throw "pinned Operator input differs from source commit: $rel"
        }
    }
    $csprojXml = [xml](Get-Content -LiteralPath (Join-Path $Repo $csprojRel) -Raw)
    $propertyGroups = @($csprojXml.Project.PropertyGroup)
    $pinnedFramework = @($propertyGroups | ForEach-Object { [string]$_.TargetFramework } | Where-Object { $_ }) | Select-Object -First 1
    $pinnedRid = @($propertyGroups | ForEach-Object { [string]$_.RuntimeIdentifier } | Where-Object { $_ }) | Select-Object -First 1
    $pinnedPlatform = @($propertyGroups | ForEach-Object { [string]$_.PlatformTarget } | Where-Object { $_ }) | Select-Object -First 1
    $pinnedAppSdk = $null
    foreach ($group in @($csprojXml.Project.ItemGroup)) {
        foreach ($reference in @($group.PackageReference)) {
            if ([string]$reference.Include -ceq 'Microsoft.WindowsAppSDK') {
                $pinnedAppSdk = [string]$reference.Version
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($pinnedFramework) -or [string]::IsNullOrWhiteSpace($pinnedRid) -or
        [string]::IsNullOrWhiteSpace($pinnedPlatform) -or [string]::IsNullOrWhiteSpace($pinnedAppSdk)) {
        throw 'pinned Operator project does not declare its framework/runtime/platform/AppSDK identity'
    }
    $contractsText = Get-Content -LiteralPath (Join-Path $Repo $contractsRel) -Raw
    $pinnedSchema = ([regex]::Match($contractsText, 'SchemaVersion =\s*"([^"]+)"')).Groups[1].Value
    $pinnedProtocol = ([regex]::Match($contractsText, 'IpcProtocolVersion =\s*"([^"]+)"')).Groups[1].Value
    $pinnedContractHash = ([regex]::Match($contractsText, 'PinnedContractHash =\s*"([0-9a-f]{64})"')).Groups[1].Value
    if ([string]::IsNullOrWhiteSpace($pinnedSchema) -or [string]::IsNullOrWhiteSpace($pinnedProtocol) -or
        [string]$pinnedContractHash -notmatch '^[0-9a-f]{64}$') {
        throw 'failed to read the pinned Operator protocol contract'
    }
    $pinnedLockHash = (Get-FileHash -LiteralPath (Join-Path $Repo $lockRel) -Algorithm SHA256).Hash.ToLowerInvariant()
    $pinnedCsprojHash = (Get-FileHash -LiteralPath (Join-Path $Repo $csprojRel) -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
    if ([string]$receipt.schema -cne 'eliot-operator-build-receipt-v1') {
        throw 'Operator build receipt is missing its canonical schema'
    }
    if ([string]$receipt.source_commit -cne $SourceCommit) {
        throw 'Operator build receipt is not bound to the release source commit'
    }
    if ([string]$receipt.target_framework -cne $pinnedFramework -or
        [string]$receipt.runtime_identifier -cne $pinnedRid -or
        [string]$receipt.platform -cne $pinnedPlatform -or
        [string]$receipt.configuration -cne 'Release' -or
        [string]$receipt.windows_app_sdk_version -cne $pinnedAppSdk) {
        throw 'Operator build receipt does not match the pinned Operator project identity'
    }
    if ($receipt.restore_locked_mode -ne $true) {
        throw 'Operator build receipt must attest a locked NuGet restore'
    }
    if ([string]$receipt.packages_lock_sha256 -cne $pinnedLockHash -or
        [string]$receipt.csproj_sha256 -cne $pinnedCsprojHash) {
        throw 'Operator build receipt does not bind the pinned NuGet lock and project bytes'
    }
    if ([string]$receipt.contracts.schema_version -cne $pinnedSchema -or
        [string]$receipt.contracts.ipc_protocol_version -cne $pinnedProtocol -or
        [string]$receipt.contracts.contract_hash -cne $pinnedContractHash) {
        throw 'Operator build receipt does not bind the pinned Operator protocol contract'
    }
    if ([string]$receipt.artifact.path -cne 'Eliot.Operator.exe' -or
        [string]$receipt.artifact.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [int64]$receipt.artifact.bytes -le 0) {
        throw 'Operator build receipt is missing its canonical artifact binding'
    }
    $exeFile = Get-Item -LiteralPath $exePath
    Assert-NoSecretFile $exeFile 'operator/Eliot.Operator.exe'
    [void](Assert-WindowsX64Pe $exeFile.FullName 'operator/Eliot.Operator.exe')
    $actualExeHash = (Get-FileHash -LiteralPath $exeFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualExeHash -cne [string]$receipt.artifact.sha256 -or $exeFile.Length -ne [int64]$receipt.artifact.bytes) {
        throw 'Operator payload does not match its locked build receipt'
    }
    if ([string]::IsNullOrWhiteSpace([string]$receipt.sdk.dotnet_sdk) -or
        [string]::IsNullOrWhiteSpace([string]$receipt.tests.suite) -or
        [string]$receipt.tests.result -cne 'pass' -or
        [string]$receipt.tests.source_commit -cne $SourceCommit) {
        throw 'Operator build receipt is missing its SDK identity or passing conformance-test evidence'
    }
    [ordered]@{
        source = $resolved
        receipt_path = $receiptPath
        receipt_sha256 = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash.ToLowerInvariant()
        target_framework = $pinnedFramework
        runtime_identifier = $pinnedRid
        platform = $pinnedPlatform
        windows_app_sdk_version = $pinnedAppSdk
        packages_lock_sha256 = $pinnedLockHash
        csproj_sha256 = $pinnedCsprojHash
        schema_version = $pinnedSchema
        protocol_version = $pinnedProtocol
        protocol_hash = $pinnedContractHash
        exe_sha256 = $actualExeHash
        exe_bytes = $exeFile.Length
        dotnet_sdk = [string]$receipt.sdk.dotnet_sdk
        tests_suite = [string]$receipt.tests.suite
    }
}

function Get-StagedPayloadManifest([string]$SourceCommit, [string]$Version, [object]$RuntimePlan, [string]$CodexPluginBaseVersion) {
    $entries = @()
    foreach ($artifact in @($RuntimePlan)) {
        $entries += [ordered]@{
            path = [string]$artifact.relative_path
            selection = "cargo --frozen -p $([string]$artifact.package) --bin $([string]$artifact.binary)"
            owner = "cargo-package:$([string]$artifact.package)"
            install_destination = 'runtime/'
            generation = $SourceCommit
            proof_ceiling = 'unsigned-build-evidence (Authenticode scope is Part B)'
            gate = $null
        }
    }
    $entries += [ordered]@{
        path = 'runtime/surreal.exe'
        selection = 'caller-pinned-absolute-path bound to tracked SurrealDB artifact catalog'
        owner = 'external-lock:docs/release/SURREALDB_WINDOWS_X64.lock.json'
        install_destination = 'runtime/'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence with explicit pre-release-unsigned disposition (Authenticode scope is Part B)'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'runtime/RUNTIME_ARTIFACTS.json'
        selection = 'generated verified-build manifest'
        owner = 'scripts/build-eliot-windows-x64-release.ps1'
        install_destination = 'runtime/'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'eliot-governor.exe'
        selection = 'cargo --frozen -p eliot-app --bin eliot-governor'
        owner = 'cargo-package:eliot-app'
        install_destination = './'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence (retirement scope is Part B after #1189)'
        gate = '#1189-legacy-retirement (GATED: retained explicitly, never by repository presence)'
    }
    $entries += [ordered]@{
        path = 'operator/'
        selection = 'locked Operator build receipt (OPERATOR_BUILD_RECEIPT.json) pinned to source commit'
        owner = 'apps/Eliot.Operator (#1137)'
        install_destination = 'operator/'
        generation = $SourceCommit
        proof_ceiling = 'owner-attested receipt with passing conformance evidence (same-transaction build is #1137 follow-on)'
        gate = '#1137-operator-build'
    }
    $entries += [ordered]@{
        path = 'integrations/codex/marketplace.json'
        selection = 'pinned source file'
        owner = 'integrations/codex'
        install_destination = 'integrations/codex/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (provider route scope is Part B after #1217)'
        gate = '#1217-provider-host-integration-route (GATED: retained explicitly, never wholesale)'
    }
    $entries += [ordered]@{
        path = 'integrations/codex/plugins/eliot-governor/'
        selection = 'pinned source tree plus built governor binary'
        owner = 'plugin/eliot-governor'
        install_destination = 'integrations/codex/plugins/eliot-governor/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (provider route scope is Part B after #1217)'
        gate = '#1217-provider-host-integration-route (GATED: retained explicitly, never wholesale)'
    }
    $entries += [ordered]@{
        path = 'integrations/antigravity/official-plugin/'
        selection = 'pinned source tree'
        owner = 'plugin/eliot-antigravity-official'
        install_destination = 'integrations/antigravity/official-plugin/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (owning-manifest binding is kernel-widen follow-on)'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'skills/'
        selection = 'pinned source tree'
        owner = 'integrations/agent-skills'
        install_destination = 'skills/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (skill-pack manifest binding is kernel-widen follow-on)'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'docs/operations/'
        selection = 'pinned source tree'
        owner = 'docs/operations'
        install_destination = 'docs/operations/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (reference only)'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'docs/release/'
        selection = 'pinned source tree (binds the SurrealDB artifact catalog)'
        owner = 'docs/release'
        install_destination = 'docs/release/'
        generation = $SourceCommit
        proof_ceiling = 'pinned-blob evidence (reference only)'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'RELEASE.json'
        selection = 'generated release receipt (binds source, toolchain, payload manifest, operator receipt)'
        owner = 'scripts/build-eliot-windows-x64-release.ps1'
        install_destination = './'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'SHA256SUMS.json'
        selection = 'generated checksum manifest over every staged file'
        owner = 'scripts/build-eliot-windows-x64-release.ps1'
        install_destination = './'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'SIGNING_REQUIRED.txt'
        selection = 'generated pre-release signing boundary marker'
        owner = 'scripts/build-eliot-windows-x64-release.ps1'
        install_destination = './'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'STAGED_PAYLOAD_MANIFEST.json'
        selection = 'generated install-manifest denominator for this staged generation'
        owner = 'scripts/build-eliot-windows-x64-release.ps1'
        install_destination = './'
        generation = $SourceCommit
        proof_ceiling = 'unsigned-build-evidence'
        gate = $null
    }
    $entries += [ordered]@{
        path = 'operator/OPERATOR_BUILD_RECEIPT.json'
        selection = 'locked Operator build receipt copied from the verified Operator source'
        owner = 'apps/Eliot.Operator (#1137)'
        install_destination = 'operator/'
        generation = $SourceCommit
        proof_ceiling = 'owner-attested receipt with passing conformance evidence'
        gate = '#1137-operator-build'
    }
    [ordered]@{
        schema = 'eliot-staged-payload-manifest-v1'
        component = 'eliot_windows_x64_staged_payload_manifest'
        version = $Version
        source_commit = $SourceCommit
        architecture = 'windows-x64'
        denominator_policy = 'registry-selected-only-no-wholesale'
        codex_plugin_base_version = $CodexPluginBaseVersion
        entries = @($entries)
        exclusions = @(
            [ordered]@{
                path = 'config'
                reason = 'no owning install-manifest selection at this receipt; wholesale config copy is forbidden'
                gate = '#1219-config-disposition'
            }
            [ordered]@{
                path = 'migrations'
                reason = 'no owning install-manifest selection at this receipt; wholesale migration copy is forbidden'
                gate = '#1221-schema-migration-disposition'
            }
            [ordered]@{
                path = 'integrations/** except codex/marketplace.json, codex/plugins/eliot-governor/, antigravity/official-plugin/'
                reason = 'non-Codex integration roots enter only via owning-manifest selection; wholesale integrations copy is forbidden'
                gate = '#1217-provider-host-integration-route'
            }
        )
    }
}

function Test-ReleaseBundle([string]$Path) {
    $resolved = (Resolve-Path -LiteralPath $Path).Path
    Assert-NoReleaseSecrets $resolved
    $required = @(
        'eliot-governor.exe',
        'runtime/eliot.exe',
        'runtime/eliot-host.exe',
        'runtime/eliot-watchdog.exe',
        'runtime/eliot-kernel.exe',
        'runtime/eliot-store-surreal.exe',
        'runtime/eliotd.exe',
        'runtime/eliot-doctor.exe',
        'runtime/eliot-testd.exe',
        'runtime/eliot-native-worker.exe',
        'runtime/surreal.exe',
        'runtime/RUNTIME_ARTIFACTS.json',
        'operator/Eliot.Operator.exe',
        'operator/OPERATOR_BUILD_RECEIPT.json',
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
        'docs/operations',
        'docs/release',
        'STAGED_PAYLOAD_MANIFEST.json',
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
    if ($release.signed -ne $false -or
        [string]$release.signature_policy -ne 'pre-release-unsigned' -or
        [string]$release.signature_evidence -ne 'not-issued' -or
        $release.public_distribution_ready -ne $false) {
        throw 'RELEASE.json is missing the explicit pre-release signing boundary'
    }
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
        $server.required -ne $false) {
        throw 'release Codex MCP server transport is not the enabled fail-open local plugin binary'
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

    $payloadManifest = Get-Content -LiteralPath (Join-Path $resolved 'STAGED_PAYLOAD_MANIFEST.json') -Raw | ConvertFrom-Json
    if ([string]$payloadManifest.schema -cne 'eliot-staged-payload-manifest-v1' -or
        [string]$payloadManifest.denominator_policy -cne 'registry-selected-only-no-wholesale' -or
        [string]$payloadManifest.source_commit -cne [string]$release.source_commit -or
        [string]$payloadManifest.version -cne [string]$release.version -or
        [string]$payloadManifest.architecture -cne 'windows-x64' -or
        @($payloadManifest.entries).Count -le 0) {
        throw 'staged payload manifest is missing its registry-selected-only denominator binding'
    }
    $excludedPaths = @($payloadManifest.exclusions | ForEach-Object { [string]$_.path })
    if (-not ($excludedPaths -contains 'config') -or -not ($excludedPaths -contains 'migrations')) {
        throw 'staged payload manifest must exclude wholesale config and migrations roots'
    }
    foreach ($excluded in @('config', 'migrations')) {
        if (Test-Path -LiteralPath (Join-Path $resolved $excluded)) {
            throw "release bundle contains an excluded wholesale root: $excluded"
        }
    }
    $integrationsRoot = Join-Path $resolved 'integrations'
    foreach ($item in Get-ChildItem -LiteralPath $integrationsRoot -File -Recurse) {
        $integrationRelative = $item.FullName.Substring($integrationsRoot.Length).TrimStart([char]'\').Replace('\', '/')
        $integrationAllowed = $false
        foreach ($prefix in @('codex/marketplace.json', 'codex/plugins/eliot-governor/', 'antigravity/official-plugin/')) {
            if ($prefix.EndsWith('/')) {
                if ($integrationRelative.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $integrationAllowed = $true
                }
            }
            elseif ($integrationRelative -eq $prefix) {
                $integrationAllowed = $true
            }
        }
        if (-not $integrationAllowed) {
            throw "release bundle contains an unmanifested integration payload: integrations/$integrationRelative"
        }
    }
    if ([string]$release.payload_denominator_policy -cne 'registry-selected-only-no-wholesale' -or
        [string]$release.staged_payload_manifest_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath (Join-Path $resolved 'STAGED_PAYLOAD_MANIFEST.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$release.staged_payload_manifest_sha256) {
        throw 'RELEASE.json staged payload manifest binding differs from STAGED_PAYLOAD_MANIFEST.json'
    }

    $operatorReceipt = Get-Content -LiteralPath (Join-Path $resolved 'operator/OPERATOR_BUILD_RECEIPT.json') -Raw | ConvertFrom-Json
    if ([string]$operatorReceipt.schema -cne 'eliot-operator-build-receipt-v1' -or
        [string]$operatorReceipt.source_commit -cne [string]$release.source_commit) {
        throw 'bundled Operator build receipt is not bound to the release source commit'
    }
    $operatorExePath = Join-Path $resolved 'operator/Eliot.Operator.exe'
    $operatorExeFile = Get-Item -LiteralPath $operatorExePath
    if ([string]$operatorReceipt.artifact.path -cne 'Eliot.Operator.exe' -or
        [string]$operatorReceipt.artifact.sha256 -cne (Get-FileHash -LiteralPath $operatorExePath -Algorithm SHA256).Hash.ToLowerInvariant() -or
        [int64]$operatorReceipt.artifact.bytes -ne $operatorExeFile.Length) {
        throw 'bundled Operator build receipt does not bind the staged Operator executable'
    }
    $releaseOperator = $release.operator_build
    if (-not $releaseOperator -or
        [string]$releaseOperator.receipt_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        (Get-FileHash -LiteralPath (Join-Path $resolved 'operator/OPERATOR_BUILD_RECEIPT.json') -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$releaseOperator.receipt_sha256 -or
        [string]$operatorReceipt.target_framework -cne [string]$releaseOperator.target_framework -or
        [string]$operatorReceipt.runtime_identifier -cne [string]$releaseOperator.runtime_identifier -or
        [string]$operatorReceipt.platform -cne [string]$releaseOperator.platform -or
        [string]$operatorReceipt.windows_app_sdk_version -cne [string]$releaseOperator.windows_app_sdk_version -or
        [string]$operatorReceipt.packages_lock_sha256 -cne [string]$releaseOperator.packages_lock_sha256 -or
        [string]$operatorReceipt.contracts.contract_hash -cne [string]$releaseOperator.protocol_hash -or
        [string]$operatorReceipt.tests.result -cne 'pass') {
        throw 'RELEASE.json Operator build binding differs from OPERATOR_BUILD_RECEIPT.json'
    }

    $releaseToolchain = $release.toolchain_build
    if (-not $releaseToolchain -or
        [string]$releaseToolchain.source_commit -cne [string]$release.source_commit -or
        [string]$releaseToolchain.target_triple -cne 'x86_64-pc-windows-msvc' -or
        [string]$releaseToolchain.cargo_lock.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]$releaseToolchain.rust_toolchain.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$releaseToolchain.cargo.version) -or
        [string]::IsNullOrWhiteSpace([string]$releaseToolchain.rustc.version)) {
        throw 'RELEASE.json is missing its frozen toolchain and dependency-lock identity'
    }

    $runtimeManifestPath = Join-Path $resolved 'runtime/RUNTIME_ARTIFACTS.json'
    $runtimeManifest = Get-Content -LiteralPath $runtimeManifestPath -Raw | ConvertFrom-Json
    if ([string]$runtimeManifest.schema -ne 'eliot-runtime-artifact-set-v1' -or
        [string]$runtimeManifest.source_commit -notmatch '^[0-9a-f]{40}$' -or
        [string]$runtimeManifest.installation_approval -ne 'not-issued' -or
        $runtimeManifest.signed -ne $false -or
        [string]$runtimeManifest.signature_policy -ne 'pre-release-unsigned' -or
        [string]$runtimeManifest.signature_evidence -ne 'not-issued') {
        throw 'runtime artifact manifest is missing its verified-build-only boundary'
    }
    if ([string]$runtimeManifest.source_commit -ne [string]$release.source_commit -or
        [string]$runtimeManifest.version -ne [string]$release.version -or
        [string]$runtimeManifest.architecture -ne 'windows-x64' -or
        [string]$runtimeManifest.catalog_path -ne $surrealCatalogRelativePath) {
        throw 'runtime artifact manifest does not match RELEASE.json'
    }
    $expectedRuntime = @(Get-RuntimeArtifactDefinitions)
    $declaredRuntime = @($runtimeManifest.artifacts)
    if ($declaredRuntime.Count -ne ($expectedRuntime.Count + 1)) {
        throw "runtime artifact manifest count mismatch: declared=$($declaredRuntime.Count) expected=$($expectedRuntime.Count + 1)"
    }
    $runtimePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($expected in $expectedRuntime) {
        $entry = @($declaredRuntime | Where-Object {
                [string]$_.package -eq $expected.package -and [string]$_.binary -eq $expected.binary
            })
        if ($entry.Count -ne 1) {
            throw "runtime artifact manifest is missing or duplicates $($expected.package)/$($expected.binary)"
        }
        $entry = $entry[0]
        if ([string]$entry.role -ne $expected.role -or [string]$entry.path -ne $expected.relative_path -or
            [string]$entry.source -ne 'cargo' -or [string]$entry.version -ne [string]$release.version -or
            [string]$entry.architecture -ne 'windows-x64' -or
            [string]$entry.sha256 -notmatch '^[0-9a-f]{64}$' -or [int64]$entry.bytes -le 0) {
            throw "runtime artifact manifest has invalid metadata for $($expected.package)/$($expected.binary)"
        }
        $relative = ([string]$entry.path).Replace('\', '/')
        if (-not $runtimePaths.Add($relative) -or $relative -ne $expected.relative_path) {
            throw "runtime artifact manifest path is duplicated or non-canonical: $relative"
        }
        $candidate = Join-Path $resolved $relative.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "runtime artifact is missing: $relative"
        }
        $file = Get-Item -LiteralPath $candidate
        $actualHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne [string]$entry.sha256 -or $file.Length -ne [int64]$entry.bytes) {
            throw "runtime artifact digest mismatch: $relative"
        }
        Assert-WindowsX64Pe $candidate $relative
    }
    $surrealEntries = @($declaredRuntime | Where-Object {
            [string]$_.package -eq 'surrealdb' -and [string]$_.binary -eq 'surreal'
        })
    if ($surrealEntries.Count -ne 1) {
        throw 'runtime artifact manifest must contain exactly one caller-pinned surrealdb/surreal artifact'
    }
    $surrealEntry = $surrealEntries[0]
    if ([string]$surrealEntry.role -ne 'database' -or
        [string]$surrealEntry.path -ne 'runtime/surreal.exe' -or
        [string]$surrealEntry.source -ne 'caller-pinned-absolute-path' -or
        [string]$surrealEntry.catalog_path -ne $surrealCatalogRelativePath -or
        [string]$surrealEntry.catalog_source_commit -ne [string]$runtimeManifest.source_commit -or
        [string]$surrealEntry.catalog_sha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$surrealEntry.pe_machine -ne '8664' -or
        [string]$surrealEntry.version -ne [string]$runtimeManifest.surreal_version -or
        [string]$surrealEntry.architecture -ne 'windows-x64' -or
        [string]$surrealEntry.sha256 -notmatch '^[0-9a-f]{64}$' -or
        [int64]$surrealEntry.bytes -le 0 -or
        [string]$surrealEntry.signature_policy -ne 'pre-release-unsigned' -or
        [string]$surrealEntry.signature_evidence -ne 'not-issued') {
        throw 'caller-pinned surrealdb artifact metadata is missing or non-canonical'
    }
    if (-not $runtimePaths.Add('runtime/surreal.exe')) {
        throw 'caller-pinned surrealdb artifact path is duplicated'
    }
    $surrealPath = Join-Path $resolved 'runtime/surreal.exe'
    $surrealFile = Get-Item -LiteralPath $surrealPath
    if ((Get-FileHash -LiteralPath $surrealPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$surrealEntry.sha256 -or
        $surrealFile.Length -ne [int64]$surrealEntry.bytes -or
        (Get-WindowsPeMachine $surrealPath 'runtime/surreal.exe') -cne [string]$surrealEntry.pe_machine) {
        throw 'caller-pinned surrealdb artifact readback mismatch'
    }
    [void](Assert-WindowsX64Pe $surrealPath 'runtime/surreal.exe')
    $catalogPath = Join-Path $resolved $surrealCatalogRelativePath
    if ((Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne [string]$surrealEntry.catalog_sha256) {
        throw 'bundled SurrealDB artifact catalog digest mismatch'
    }
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json
    if ([string]$catalog.schema -ne 'eliot-external-release-artifact-lock-v1' -or
        [string]$catalog.artifact -cne 'surreal.exe' -or
        [string]$catalog.relative_path -cne 'runtime/surreal.exe' -or
        [string]$catalog.version -cne [string]$surrealEntry.version -or
        [string]$catalog.architecture -ne 'windows-x64' -or
        [string]$catalog.pe_machine -ne [string]$surrealEntry.pe_machine -or
        [string]$catalog.sha256 -cne [string]$surrealEntry.sha256) {
        throw 'bundled SurrealDB artifact catalog content does not bind the shipped artifact'
    }
    $releaseRuntimeEntries = @($release.runtime_artifacts)
    if ([string]$release.runtime_artifact_catalog_path -ne $surrealCatalogRelativePath -or
        [string]$release.runtime_artifact_catalog_sha256 -ne [string]$surrealEntry.catalog_sha256 -or
        [string]$release.runtime_artifact_catalog_source_commit -ne [string]$release.source_commit -or
        [int]$release.runtime_artifact_count -ne $declaredRuntime.Count -or
        $releaseRuntimeEntries.Count -ne $declaredRuntime.Count) {
        throw 'RELEASE.json runtime artifact count does not match RUNTIME_ARTIFACTS.json'
    }
    foreach ($entry in $declaredRuntime) {
        $releaseEntry = @($releaseRuntimeEntries | Where-Object {
                [string]$_.package -eq [string]$entry.package -and [string]$_.binary -eq [string]$entry.binary
            })
        if ($releaseEntry.Count -ne 1 -or
            [string]$releaseEntry[0].path -ne [string]$entry.path -or
            [string]$releaseEntry[0].sha256 -ne [string]$entry.sha256 -or
            [string]$releaseEntry[0].version -ne [string]$entry.version -or
            [string]$releaseEntry[0].architecture -ne [string]$entry.architecture) {
            throw 'RELEASE.json runtime artifact binding differs from RUNTIME_ARTIFACTS.json'
        }
    }
    $runtimeToolchain = $runtimeManifest.toolchain
    if (-not $runtimeToolchain -or
        [string]$runtimeToolchain.cargo_lock_sha256 -cne [string]$releaseToolchain.cargo_lock.sha256 -or
        [string]$runtimeToolchain.rust_toolchain_sha256 -cne [string]$releaseToolchain.rust_toolchain.sha256 -or
        [string]$runtimeToolchain.cargo_version -cne [string]$releaseToolchain.cargo.version -or
        [string]$runtimeToolchain.rustc_version -cne [string]$releaseToolchain.rustc.version -or
        [string]$runtimeToolchain.target_triple -cne 'x86_64-pc-windows-msvc') {
        throw 'runtime artifact manifest toolchain identity differs from RELEASE.json'
    }
    foreach ($entry in $declaredRuntime) {
        if ([string]$entry.source -eq 'cargo' -and [string]$entry.linker_version -cnotmatch '^\d+\.\d+$') {
            throw "runtime artifact is missing its linker version evidence: $([string]$entry.path)"
        }
    }
    $actualRuntimeExecutables = @(Get-ChildItem -LiteralPath (Join-Path $resolved 'runtime') -Filter '*.exe' -File |
        ForEach-Object { $_.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/') })
    if ($actualRuntimeExecutables.Count -ne ($expectedRuntime.Count + 1) -or
        @($actualRuntimeExecutables | Where-Object { -not $runtimePaths.Contains($_) }).Count -ne 0) {
        throw 'runtime directory contains an unmanifested executable'
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

if ($BuilderVerifyBundle) {
    Test-ReleaseBundle $BuilderVerifyBundle | ConvertTo-Json -Depth 5
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
$cargoPinnedCommand = Get-Command cargo -CommandType Application -ErrorAction Stop | Select-Object -First 1
if (-not $cargoPinnedCommand -or [string]::IsNullOrWhiteSpace([string]$cargoPinnedCommand.Source)) {
    throw 'Cargo command is not resolvable as an application: cargo'
}
$cargoInvokePath = [string]$cargoPinnedCommand.Source
[void](Resolve-PinnedFileTarget $cargoInvokePath 'Cargo')
$cargoMetadata = (& $cargoInvokePath metadata --frozen --locked --offline --format-version 1 --no-deps 2>$null | Out-String) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $cargoMetadata.target_directory) {
    throw 'failed to resolve the Cargo target directory'
}
$runtimeArtifactPlan = Get-RuntimeArtifactPlan $cargoMetadata
$governorPath = Join-Path ([string]$cargoMetadata.target_directory) 'release\eliot-governor.exe'
$sourceCommit = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'failed to resolve the release source commit'
}
$surrealCatalog = Get-VerifiedSurrealCatalog $repo $sourceCommit
$verifiedPinnedSurreal = Get-VerifiedPinnedSurrealArtifact $SurrealExe $SurrealSha256 $SurrealVersion $surrealCatalog
$planToolchain = Get-ToolchainBuildReceipt $repo $sourceCommit $cargoMetadata 'plan'
$resolvedSurrealExe = (Resolve-Path -LiteralPath $SurrealExe).Path
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
    source_policy = 'pinned-commit-isolated-tree-only (tracked-clean untracked-rejected no-local-.cargo; cargo --frozen)'
    secret_scan = 'required-before-manifest-and-on-verification'
    toolchain = $planToolchain
    payload_denominator = 'registry-selected-only-no-wholesale (STAGED_PAYLOAD_MANIFEST.json; config/migrations excluded; integrations allowlisted)'
    operator_binding = 'locked-build-receipt-required (OPERATOR_BUILD_RECEIPT.json pinned to source commit; arbitrary OperatorSource rejected)'
    output = $bundle
    governor = $governorPath
    operator_source = $OperatorSource
    codex_marketplace_source = (Join-Path $repo 'integrations/codex/marketplace.json')
    codex_plugin_source = $codexPluginSource
    codex_plugin_base_version = $codexPluginBaseVersion
    codex_mcp_profile = 'codex_controller'
    surreal = [ordered]@{
        path = $verifiedPinnedSurreal.path
        sha256 = $verifiedPinnedSurreal.sha256
        version = $verifiedPinnedSurreal.version
        architecture = $verifiedPinnedSurreal.architecture
        source = $verifiedPinnedSurreal.source
        catalog_path = $surrealCatalog.relative_path
        catalog_sha256 = $surrealCatalog.sha256
        catalog_source_commit = $surrealCatalog.source_commit
    }
    runtime_artifacts = @($runtimeArtifactPlan | ForEach-Object {
            [ordered]@{
                package = $_.package
                binary = $_.binary
                role = $_.role
                path = $_.relative_path
                build_path = $_.path
            }
        })
    includes = @('governor-gated-legacy', 'runtime-artifacts', 'pinned-surrealdb', 'operator-receipt-bound', 'codex-marketplace-gated', 'codex-plugin-gated', 'skills', 'antigravity-official-plugin', 'operations-runbooks', 'release-catalogue')
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
    $preBuildIsolation = Assert-IsolatedSourceTree $repo $sourceCommit 'pre-build'
    $stageToolchain = Get-ToolchainBuildReceipt $repo $sourceCommit $cargoMetadata 'stage'
    if ($SkipBuild) {
        throw 'SkipBuild is not permitted for staged releases because it cannot prove Governor source provenance'
    }
    & $cargoInvokePath build --frozen --locked --offline --release -p eliot-app --bin eliot-governor
    if ($LASTEXITCODE -ne 0) {
        throw "cargo Governor release build failed with exit code $LASTEXITCODE"
    }
    foreach ($artifact in $runtimeArtifactPlan) {
        & $cargoInvokePath build --frozen --locked --offline --release -p $artifact.package --bin $artifact.binary
        if ($LASTEXITCODE -ne 0) {
            throw "cargo runtime release build failed for $($artifact.package)/$($artifact.binary) with exit code $LASTEXITCODE"
        }
    }
    $postBuildIsolation = Assert-IsolatedSourceTree $repo $sourceCommit 'post-build'

    $governor = $governorPath
    if (-not (Test-Path -LiteralPath $governor -PathType Leaf)) {
        throw "release governor executable is missing: $governor"
    }
    $verifiedRuntimeArtifacts = @(Get-VerifiedRuntimeArtifacts $runtimeArtifactPlan $Version)
    $governorLinkerVersion = Get-WindowsPeLinkerVersion $governor 'eliot-governor.exe'
    $peLinkerVersions = @(@($verifiedRuntimeArtifacts | ForEach-Object { [string]$_.linker_version }) + @($governorLinkerVersion) | Sort-Object -Unique)
    $stageToolchain.linker = [ordered]@{
        policy = 'msvc-link-via-rustc'
        vswhere = $stageToolchain.linker.vswhere
        msvc_installations = @($stageToolchain.linker.msvc_installations)
        link_candidates = @($stageToolchain.linker.link_candidates)
        pe_linker_versions = @($peLinkerVersions)
    }

    if (Test-Path -LiteralPath $bundle) {
        throw "release bundle already exists; choose another version or output root: $bundle"
    }
    New-Item -ItemType Directory -Path $bundle | Out-Null
    Assert-NoSecretFile (Get-Item -LiteralPath $governor) 'eliot-governor.exe'
    Copy-Item -LiteralPath $governor -Destination $bundle
    $runtimeRoot = Join-Path $bundle 'runtime'
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    foreach ($artifact in $runtimeArtifactPlan) {
        Copy-Item -LiteralPath $artifact.path -Destination (Join-Path $bundle $artifact.relative_path)
    }
    Copy-Item -LiteralPath $resolvedSurrealExe -Destination (Join-Path $bundle 'runtime/surreal.exe')
    [ordered]@{
        schema = 'eliot-runtime-artifact-set-v1'
        component = 'eliot_runtime_verified_build_artifacts'
        version = $Version
        source_commit = $sourceCommit
        architecture = 'windows-x64'
        catalog_path = $surrealCatalog.relative_path
        catalog_sha256 = $surrealCatalog.sha256
        catalog_source_commit = $surrealCatalog.source_commit
        build_profile = 'release'
        signed = $false
        signature_policy = 'pre-release-unsigned'
        signature_evidence = 'not-issued'
        installation_approval = 'not-issued'
        toolchain = [ordered]@{
            cargo_version = [string]$stageToolchain.cargo.version
            rustc_version = [string]$stageToolchain.rustc.version
            target_triple = [string]$stageToolchain.target_triple
            cargo_lock_sha256 = [string]$stageToolchain.cargo_lock.sha256
            rust_toolchain_sha256 = [string]$stageToolchain.rust_toolchain.sha256
            build_argv_template = @($stageToolchain.build.build_argv_template)
            features_policy = [string]$stageToolchain.build.features_policy
        }
        surreal_version = $verifiedPinnedSurreal.version
        artifacts = @($verifiedRuntimeArtifacts + $verifiedPinnedSurreal)
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runtimeRoot 'RUNTIME_ARTIFACTS.json') -Encoding utf8
    Copy-PinnedSourceFile $repo $sourceCommit 'integrations/codex/marketplace.json' (Join-Path $bundle 'integrations/codex/marketplace.json')
    $codexPluginRoot = Join-Path $bundle 'integrations/codex/plugins/eliot-governor'
    Copy-TrackedTree $repo $sourceCommit 'plugin/eliot-governor' $codexPluginRoot
    $codexPluginBin = Join-Path $codexPluginRoot 'bin'
    New-Item -ItemType Directory -Path $codexPluginBin -Force | Out-Null
    Copy-Item -LiteralPath $governor -Destination (Join-Path $codexPluginBin 'eliot-governor.exe')
    Copy-TrackedTree $repo $sourceCommit 'plugin/eliot-antigravity-official' (Join-Path $bundle 'integrations/antigravity/official-plugin')
    Copy-TrackedTree $repo $sourceCommit 'integrations/agent-skills' (Join-Path $bundle 'skills')
    Copy-TrackedTree $repo $sourceCommit 'docs/operations' (Join-Path $bundle 'docs/operations')
    Copy-TrackedTree $repo $sourceCommit 'docs/release' (Join-Path $bundle 'docs/release')

    $verifiedOperator = Get-VerifiedOperatorBuildReceipt $repo $sourceCommit $OperatorSource
    Copy-OperatorPayload $verifiedOperator.source (Join-Path $bundle 'operator')
    Copy-Item -LiteralPath $verifiedOperator.receipt_path -Destination (Join-Path $bundle 'operator/OPERATOR_BUILD_RECEIPT.json')
    $stagedPayloadManifest = Get-StagedPayloadManifest $sourceCommit $Version $runtimeArtifactPlan $codexPluginBaseVersion
    $stagedPayloadManifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bundle 'STAGED_PAYLOAD_MANIFEST.json') -Encoding utf8
    $stagedPayloadManifestHash = (Get-FileHash -LiteralPath (Join-Path $bundle 'STAGED_PAYLOAD_MANIFEST.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    [ordered]@{
        component = 'eliot_windows_x64_release'
        version = $Version
        source_commit = $sourceCommit
        governor_version = $Version
        operator_schema_version = $verifiedOperator.schema_version
        operator_protocol_version = $verifiedOperator.protocol_version
        operator_protocol_hash = $verifiedOperator.protocol_hash
        codex_plugin_base_version = $codexPluginBaseVersion
        runtime_artifacts_manifest = 'runtime/RUNTIME_ARTIFACTS.json'
        runtime_artifact_catalog_path = $surrealCatalog.relative_path
        runtime_artifact_catalog_sha256 = $surrealCatalog.sha256
        runtime_artifact_catalog_source_commit = $surrealCatalog.source_commit
        runtime_artifact_count = $runtimeArtifactPlan.Count + 1
        runtime_artifacts = @($verifiedRuntimeArtifacts + $verifiedPinnedSurreal | ForEach-Object {
                [ordered]@{
                    package = $_.package
                    binary = $_.binary
                    role = $_.role
                    path = $_.path
                    source = $_.source
                    version = $_.version
                    architecture = $_.architecture
                    sha256 = $_.sha256
                    bytes = $_.bytes
                }
            })
        architecture = 'windows-x64'
        signed = $false
        signature_policy = 'pre-release-unsigned'
        signature_evidence = 'not-issued'
        public_distribution_ready = $false
        payload_denominator_policy = 'registry-selected-only-no-wholesale'
        staged_payload_manifest_sha256 = $stagedPayloadManifestHash
        source_isolation = [ordered]@{
            pre_build = $preBuildIsolation
            post_build = $postBuildIsolation
        }
        toolchain_build = $stageToolchain
        operator_build = [ordered]@{
            receipt_sha256 = $verifiedOperator.receipt_sha256
            target_framework = $verifiedOperator.target_framework
            runtime_identifier = $verifiedOperator.runtime_identifier
            platform = $verifiedOperator.platform
            windows_app_sdk_version = $verifiedOperator.windows_app_sdk_version
            packages_lock_sha256 = $verifiedOperator.packages_lock_sha256
            csproj_sha256 = $verifiedOperator.csproj_sha256
            schema_version = $verifiedOperator.schema_version
            protocol_version = $verifiedOperator.protocol_version
            protocol_hash = $verifiedOperator.protocol_hash
            exe_sha256 = $verifiedOperator.exe_sha256
            exe_bytes = $verifiedOperator.exe_bytes
            dotnet_sdk = $verifiedOperator.dotnet_sdk
            tests_suite = $verifiedOperator.tests_suite
        }
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $bundle 'RELEASE.json') -Encoding utf8

    @'
This bundle is intentionally unsigned. Before public distribution:
1. Sign the six materializer runtime PE roles and the install-authoritative runtime/eliot.exe CLI trust role with the organization EV/OV Authenticode certificate.
2. Use scripts/invoke-eliot-windows-x64-production.ps1 for the authoritative handoff; it retains runtime/eliot.exe, reruns seven-role public readback, and binds a suspended child before resume.
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
