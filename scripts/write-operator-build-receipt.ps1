[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$PublishDirectory,
    [Parameter(Mandatory = $true)][string]$ReceiptPath,
    [Parameter(Mandatory = $true)][string]$SourceCommit,
    [Parameter(Mandatory = $true)][string]$InvocationId,
    [Parameter(Mandatory = $true)][string]$DotnetPath,
    [Parameter(Mandatory = $true)][string]$TargetFramework,
    [Parameter(Mandatory = $true)][string]$RuntimeIdentifier,
    [Parameter(Mandatory = $true)][string]$Platform,
    [Parameter(Mandatory = $true)][string]$Configuration,
    [Parameter(Mandatory = $true)][string]$RestoreLockedMode,
    [Parameter(Mandatory = $true)][string]$SelfContained,
    [Parameter(Mandatory = $true)][string]$WindowsAppSDKSelfContained,
    [Parameter(Mandatory = $true)][string]$UseWinUI,
    [Parameter(Mandatory = $true)][string]$WindowsPackageType,
    [Parameter(Mandatory = $true)][string]$DotnetSdk,
    [Parameter(Mandatory = $true)][string]$MSBuildVersion
)

$ErrorActionPreference = 'Stop'

function Get-CommitBoundInput([string]$Root, [string]$Commit, [string]$RelativePath) {
    $path = Join-Path $Root $RelativePath.Replace('/', '\')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Operator build input is missing: $RelativePath"
    }
    $workingBlob = (& git -C $Root hash-object "--path=$RelativePath" $path 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $workingBlob -notmatch '^[0-9a-f]{40}$') {
        throw "failed to hash Operator build input: $RelativePath"
    }
    $commitBlob = (& git -C $Root rev-parse "$Commit`:$RelativePath" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commitBlob -notmatch '^[0-9a-f]{40}$' -or $workingBlob -cne $commitBlob) {
        throw "Operator build input differs from source commit ${Commit}: $RelativePath"
    }
    $file = Get-Item -LiteralPath $path
    [ordered]@{
        path = $RelativePath
        git_blob_sha1 = $workingBlob
        sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = [int64]$file.Length
    }
}

function Get-PeMachine([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    $reader = New-Object System.IO.BinaryReader -ArgumentList $stream
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) {
            throw 'Operator executable does not have a valid DOS header'
        }
        $stream.Position = 0x3c
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 64 -or $peOffset -gt ($stream.Length - 6)) {
            throw 'Operator executable has an invalid PE header offset'
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw 'Operator executable does not have a valid PE signature'
        }
        return ('{0:x4}' -f $reader.ReadUInt16())
    }
    finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$publish = (Resolve-Path -LiteralPath $PublishDirectory).Path
$receiptFullPath = [System.IO.Path]::GetFullPath($ReceiptPath)
$expectedReceiptPath = [System.IO.Path]::GetFullPath((Join-Path $publish 'OPERATOR_BUILD_RECEIPT.json'))
if (-not $receiptFullPath.Equals($expectedReceiptPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Operator build receipt must be written to the exact publish directory output path'
}
if ($SourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Operator build receipt source commit must be a full Git SHA'
}
$parsedInvocationId = [guid]::Empty
if (-not [guid]::TryParseExact($InvocationId, 'D', [ref]$parsedInvocationId) -or
    $parsedInvocationId.ToString('D') -cne $InvocationId.ToLowerInvariant()) {
    throw 'Operator build receipt invocation ID must be a canonical GUID'
}

$observedHead = (& git -C $repo rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $observedHead -cne $SourceCommit) {
    throw "Operator build is not running at its requested source commit: expected $SourceCommit, observed $observedHead"
}
$sourceStatus = @(& git -C $repo status --porcelain --untracked-files=all 2>$null)
if ($LASTEXITCODE -ne 0 -or $sourceStatus.Count -gt 0) {
    throw 'Operator build receipt requires a clean, tracked source tree'
}

$projectRelative = 'apps/Eliot.Operator/Eliot.Operator.csproj'
$lockRelative = 'apps/Eliot.Operator/packages.lock.json'
$contractsRelative = 'apps/Eliot.Operator/Protocol/OperatorContracts.cs'
$producerRelative = 'scripts/write-operator-build-receipt.ps1'
$projectInput = Get-CommitBoundInput $repo $SourceCommit $projectRelative
$lockInput = Get-CommitBoundInput $repo $SourceCommit $lockRelative
$contractsInput = Get-CommitBoundInput $repo $SourceCommit $contractsRelative
$producerInput = Get-CommitBoundInput $repo $SourceCommit $producerRelative

$projectXml = [xml](Get-Content -LiteralPath (Join-Path $repo $projectRelative) -Raw)
$propertyGroups = @($projectXml.Project.PropertyGroup)
$pinnedFramework = @($propertyGroups | ForEach-Object { [string]$_.TargetFramework } | Where-Object { $_ }) | Select-Object -First 1
$pinnedRuntime = @($propertyGroups | ForEach-Object { [string]$_.RuntimeIdentifier } | Where-Object { $_ }) | Select-Object -First 1
$pinnedPlatform = @($propertyGroups | ForEach-Object { [string]$_.PlatformTarget } | Where-Object { $_ }) | Select-Object -First 1
$pinnedSelfContained = @($propertyGroups | ForEach-Object { [string]$_.SelfContained } | Where-Object { $_ }) | Select-Object -First 1
$pinnedAppSdkSelfContained = @($propertyGroups | ForEach-Object { [string]$_.WindowsAppSDKSelfContained } | Where-Object { $_ }) | Select-Object -First 1
$pinnedUseWinUI = @($propertyGroups | ForEach-Object { [string]$_.UseWinUI } | Where-Object { $_ }) | Select-Object -First 1
$pinnedPackageType = @($propertyGroups | ForEach-Object { [string]$_.WindowsPackageType } | Where-Object { $_ }) | Select-Object -First 1
$pinnedAppSdkVersion = $null
foreach ($group in @($projectXml.Project.ItemGroup)) {
    foreach ($reference in @($group.PackageReference)) {
        if ([string]$reference.Include -ceq 'Microsoft.WindowsAppSDK') {
            $pinnedAppSdkVersion = [string]$reference.Version
        }
    }
}
if ([string]$TargetFramework -cne $pinnedFramework -or
    [string]$RuntimeIdentifier -cne $pinnedRuntime -or
    [string]$Platform -cne $pinnedPlatform -or
    $Configuration -cne 'Release' -or
    $RestoreLockedMode -notmatch '^(?i:true)$' -or
    $SelfContained -cne $pinnedSelfContained -or
    $WindowsAppSDKSelfContained -cne $pinnedAppSdkSelfContained -or
    $UseWinUI -cne $pinnedUseWinUI -or
    $WindowsPackageType -cne $pinnedPackageType -or
    [string]::IsNullOrWhiteSpace($pinnedAppSdkVersion)) {
    throw 'observed WinUI publish properties do not match the pinned Operator project and locked-restore policy'
}

$contractsText = Get-Content -LiteralPath (Join-Path $repo $contractsRelative) -Raw
$schemaVersion = ([regex]::Match($contractsText, 'SchemaVersion =\s*"([^"]+)"')).Groups[1].Value
$protocolVersion = ([regex]::Match($contractsText, 'IpcProtocolVersion =\s*"([^"]+)"')).Groups[1].Value
$contractHash = ([regex]::Match($contractsText, 'PinnedContractHash =\s*"([0-9a-f]{64})"')).Groups[1].Value
if (-not $schemaVersion -or -not $protocolVersion -or $contractHash -notmatch '^[0-9a-f]{64}$') {
    throw 'Operator protocol contract identity could not be read from its pinned source'
}

$dotnet = (Resolve-Path -LiteralPath $DotnetPath).Path
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf) -or [string]::IsNullOrWhiteSpace($DotnetSdk) -or [string]::IsNullOrWhiteSpace($MSBuildVersion)) {
    throw 'Operator publish receipt is missing the observed dotnet executable or SDK identity'
}
$dotnetSha256 = (Get-FileHash -LiteralPath $dotnet -Algorithm SHA256).Hash.ToLowerInvariant()

$allowedExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($extension in @('.dll', '.exe', '.html', '.json', '.mui', '.png', '.pri', '.winmd', '.xbf')) {
    [void]$allowedExtensions.Add($extension)
}
$files = @()
foreach ($item in Get-ChildItem -LiteralPath $publish -Force -Recurse) {
    $relative = $item.FullName.Substring($publish.Length).TrimStart([char[]]@('\', '/')).Replace('\', '/')
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Operator publish output contains a reparse point: $relative"
    }
    if (-not ($item -is [System.IO.FileInfo]) -or $relative -ceq 'OPERATOR_BUILD_RECEIPT.json') {
        continue
    }
    if ($item.Extension -ieq '.pdb') {
        continue
    }
    if (-not $allowedExtensions.Contains($item.Extension)) {
        throw "Operator publish output contains an unapproved file type: $relative"
    }
    $files += [pscustomobject]@{
        path = $relative
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = [int64]$item.Length
    }
}
$files = @($files | Sort-Object -Property path -CaseSensitive)
$exe = @($files | Where-Object { $_.path -ceq 'Eliot.Operator.exe' })
if ($exe.Count -ne 1 -or [int64]$exe[0].bytes -le 0 -or (Get-PeMachine (Join-Path $publish 'Eliot.Operator.exe')) -cne '8664') {
    throw 'Operator publish output must contain one nonempty Windows x64 Eliot.Operator.exe'
}

$receipt = [ordered]@{
    schema = 'eliot-operator-build-receipt-v2'
    created_at_utc = [DateTimeOffset]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
    source_commit = $observedHead
    invocation_id = $parsedInvocationId.ToString('D')
    target_framework = $pinnedFramework
    runtime_identifier = $pinnedRuntime
    platform = $pinnedPlatform
    configuration = $Configuration
    windows_app_sdk_version = $pinnedAppSdkVersion
    restore_locked_mode = $true
    packages_lock_sha256 = $lockInput.sha256
    csproj_sha256 = $projectInput.sha256
    source_inputs = @($projectInput, $lockInput, $contractsInput)
    producer = [ordered]@{
        path = $producerRelative
        sha256 = $producerInput.sha256
    }
    contracts = [ordered]@{
        path = $contractsRelative
        sha256 = $contractsInput.sha256
        schema_version = $schemaVersion
        ipc_protocol_version = $protocolVersion
        contract_hash = $contractHash
    }
    sdk = [ordered]@{
        dotnet_path = $dotnet
        dotnet_sha256 = $dotnetSha256
        dotnet_sdk = $DotnetSdk
        msbuild_version = $MSBuildVersion
    }
    build = [ordered]@{
        target = 'Publish'
        result = 'succeeded'
        invocation_id = $parsedInvocationId.ToString('D')
        target_framework = $pinnedFramework
        runtime_identifier = $pinnedRuntime
        platform = $pinnedPlatform
        configuration = $Configuration
        restore_locked_mode = $true
        self_contained = ($SelfContained -ieq 'true')
        windows_app_sdk_self_contained = ($WindowsAppSDKSelfContained -ieq 'true')
        use_winui = ($UseWinUI -ieq 'true')
        windows_package_type = $WindowsPackageType
    }
    artifact = [ordered]@{
        path = 'Eliot.Operator.exe'
        sha256 = [string]$exe[0].sha256
        bytes = [int64]$exe[0].bytes
        pe_machine = '8664'
    }
    artifacts = [ordered]@{
        files = $files
    }
}

$json = $receipt | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($receiptFullPath, $json + "`n", [System.Text.UTF8Encoding]::new($false))
$receiptSha256 = (Get-FileHash -LiteralPath $receiptFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "OPERATOR_BUILD_RECEIPT_WRITTEN=$receiptFullPath SHA256=$receiptSha256 INVOCATION=$($parsedInvocationId.ToString('D'))"
