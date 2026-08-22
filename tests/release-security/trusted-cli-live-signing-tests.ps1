[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SignToolPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$CertificateThumbprint,

    [ValidateSet('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')]
    [string]$CertificateStoreLocation = 'Cert:\CurrentUser\My',

    [Parameter(Mandatory = $true)]
    [string]$TimestampUrl,

    [Parameter(Mandatory = $true)]
    [string]$SurrealExePath,

    [string]$PowerShellPath = (Get-Process -Id $PID).Path,

    [string]$CSharpCompilerPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
)

$ErrorActionPreference = 'Stop'
$testRepo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$builderScript = Join-Path $testRepo 'scripts\build-eliot-windows-x64-release.ps1'
$finalizerScript = Join-Path $testRepo 'scripts\finalize-eliot-windows-x64-release.ps1'
$launcherScript = Join-Path $testRepo 'scripts\invoke-eliot-windows-x64-production.ps1'
$helperSource = Join-Path $PSScriptRoot 'fixtures\EliotMaterializerProtocolHelper.cs'
foreach ($requiredFile in @(
        $builderScript, $finalizerScript, $launcherScript, $helperSource,
        $SignToolPath, $SurrealExePath, $PowerShellPath, $CSharpCompilerPath)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "live signing gate requires an explicit existing file: $requiredFile"
    }
}
$signTool = (Resolve-Path -LiteralPath $SignToolPath).Path
if ([System.IO.Path]::GetFileName($signTool) -ine 'signtool.exe') {
    throw 'live signing gate requires an exact signtool.exe path'
}
$childPowerShell = (Resolve-Path -LiteralPath $PowerShellPath).Path
$compiler = (Resolve-Path -LiteralPath $CSharpCompilerPath).Path
$pinnedSurrealExecutable = (Resolve-Path -LiteralPath $SurrealExePath).Path
if ([System.IO.Path]::GetFileName($pinnedSurrealExecutable) -cne 'surreal.exe') {
    throw 'live signing gate requires an explicit exact surreal.exe path'
}
$normalizedThumbprint = $CertificateThumbprint.ToLowerInvariant()
$certificate = Get-Item -LiteralPath "$CertificateStoreLocation\$CertificateThumbprint" -ErrorAction Stop
$codeSigningExtension = @($certificate.Extensions | Where-Object {
        [string]$_.Oid.Value -eq '2.5.29.37' -and
        $_.Format($false) -match '1\.3\.6\.1\.5\.5\.7\.3\.3'
    })
if ($certificate.HasPrivateKey -ne $true -or $codeSigningExtension.Count -ne 1) {
    throw 'live signing gate requires the exact certificate private key and Code Signing EKU'
}

$trackedBefore = @(& git -C $testRepo status --porcelain --untracked-files=no)
if ($LASTEXITCODE -ne 0 -or $trackedBefore.Count -ne 0) {
    throw 'live signing gate requires a clean tracked source tree'
}
$sourceCommit = (& git -C $testRepo rev-parse HEAD 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'live signing gate could not bind the source commit'
}
$launcherHashBefore = (Get-FileHash -LiteralPath $launcherScript -Algorithm SHA256).Hash
$finalizerHashBefore = (Get-FileHash -LiteralPath $finalizerScript -Algorithm SHA256).Hash

# Import only the unsigned fixture builder primitives. The production
# finalizer and launcher are always executed byte-for-byte as standalone child
# scripts below; neither is dot-sourced, rewritten, or given a test hook.
. $builderScript

function ConvertTo-NativeCommandLineArgument {
    param([AllowEmptyString()][string]$Argument)
    if ($null -eq $Argument) { $Argument = '' }
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') { return $Argument }
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') { $backslashes++; continue }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes))
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) { [void]$builder.Append(('\' * ($backslashes * 2))) }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$TimeoutMilliseconds = 300000
    )
    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FilePath
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    if ($start.PSObject.Properties.Name -contains 'ArgumentList') {
        foreach ($argument in $Arguments) { $start.ArgumentList.Add([string]$argument) }
    }
    else {
        $start.Arguments = (@($Arguments | ForEach-Object {
                    ConvertTo-NativeCommandLineArgument ([string]$_)
                }) -join ' ')
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw "failed to start child process: $FilePath" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            try { $process.Kill() } catch {}
            throw "child process timed out: $FilePath"
        }
        $process.WaitForExit()
        return [pscustomobject]@{
            exit_code = [int]$process.ExitCode
            stdout = [string]$stdoutTask.GetAwaiter().GetResult()
            stderr = [string]$stderrTask.GetAwaiter().GetResult()
        }
    }
    finally { $process.Dispose() }
}

function Write-Utf8Json([string]$Path, [object]$Value) {
    $text = $Value | ConvertTo-Json -Depth 20
    [System.IO.File]::WriteAllText($Path, "$text`n", [System.Text.UTF8Encoding]::new($false))
}

function Get-FileFact([string]$Path) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    return [pscustomobject]@{
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = [int64]$item.Length
    }
}

function New-LiveUnsignedBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$HelperExecutable,
        [Parameter(Mandatory = $true)][string]$SurrealExecutable
    )
    $version = '0.1.0-live-signing-test'
    $bundle = Join-Path $Root 'unsigned-bundle'
    $runtimeRoot = Join-Path $bundle 'runtime'
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

    [System.IO.File]::Copy($HelperExecutable, (Join-Path $bundle 'eliot-governor.exe'), $false)
    $runtimeDefinitions = @(Get-RuntimeArtifactDefinitions)
    $runtimeArtifacts = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in $runtimeDefinitions) {
        $target = Join-Path $bundle ([string]$definition.relative_path).Replace('/', '\')
        [System.IO.File]::Copy($HelperExecutable, $target, $false)
        $fact = Get-FileFact $target
        [void]$runtimeArtifacts.Add([ordered]@{
                package = [string]$definition.package
                binary = [string]$definition.binary
                role = [string]$definition.role
                path = [string]$definition.relative_path
                source = 'cargo'
                version = $version
                architecture = 'windows-x64'
                sha256 = [string]$fact.sha256
                bytes = [int64]$fact.bytes
                signature_policy = 'pre-release-unsigned'
                signature_evidence = 'not-issued'
            })
    }
    $surrealPath = Join-Path $runtimeRoot 'surreal.exe'
    [System.IO.File]::Copy($SurrealExecutable, $surrealPath, $false)
    $surrealFact = Get-FileFact $surrealPath

    Copy-TrackedTree $testRepo $sourceCommit 'config' (Join-Path $bundle 'config')
    Copy-TrackedTree $testRepo $sourceCommit 'integrations' (Join-Path $bundle 'integrations')
    $codexPluginRoot = Join-Path $bundle 'integrations\codex\plugins\eliot-governor'
    Copy-TrackedTree $testRepo $sourceCommit 'plugin/eliot-governor' $codexPluginRoot
    $codexPluginBin = Join-Path $codexPluginRoot 'bin'
    New-Item -ItemType Directory -Path $codexPluginBin -Force | Out-Null
    [System.IO.File]::Copy(
        $HelperExecutable, (Join-Path $codexPluginBin 'eliot-governor.exe'), $false)
    Copy-TrackedTree $testRepo $sourceCommit 'plugin/eliot-antigravity-official' `
        (Join-Path $bundle 'integrations\antigravity\official-plugin')
    Copy-TrackedTree $testRepo $sourceCommit 'integrations/agent-skills' (Join-Path $bundle 'skills')
    Copy-TrackedTree $testRepo $sourceCommit 'migrations' (Join-Path $bundle 'migrations')
    Copy-TrackedTree $testRepo $sourceCommit 'docs/operations' (Join-Path $bundle 'docs\operations')
    Copy-TrackedTree $testRepo $sourceCommit 'docs/release' (Join-Path $bundle 'docs\release')

    $operatorRoot = Join-Path $bundle 'operator'
    New-Item -ItemType Directory -Path $operatorRoot -Force | Out-Null
    [System.IO.File]::Copy($HelperExecutable, (Join-Path $operatorRoot 'Eliot.Operator.exe'), $false)

    $catalogRelative = 'docs/release/SURREALDB_WINDOWS_X64.lock.json'
    $catalogPath = Join-Path $bundle $catalogRelative.Replace('/', '\')
    $catalog = Get-Content -LiteralPath $catalogPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ([string]$catalog.schema -cne 'eliot-external-release-artifact-lock-v1' -or
        [string]$catalog.artifact -cne 'surreal.exe' -or
        [string]$catalog.relative_path -cne 'runtime/surreal.exe' -or
        [string]$catalog.architecture -cne 'windows-x64' -or
        [string]$catalog.pe_machine -cne '8664' -or
        [string]$catalog.sha256 -cne [string]$surrealFact.sha256) {
        throw 'explicit surreal.exe does not match the source-pinned release catalog'
    }
    $catalogFact = Get-FileFact $catalogPath
    $surrealArtifact = [ordered]@{
        package = 'surrealdb'
        binary = 'surreal'
        role = 'database'
        path = 'runtime/surreal.exe'
        source = 'caller-pinned-absolute-path'
        catalog_path = $catalogRelative
        catalog_source_commit = $sourceCommit
        catalog_sha256 = [string]$catalogFact.sha256
        pe_machine = '8664'
        version = [string]$catalog.version
        architecture = 'windows-x64'
        sha256 = [string]$surrealFact.sha256
        bytes = [int64]$surrealFact.bytes
        signature_policy = 'pre-release-unsigned'
        signature_evidence = 'not-issued'
    }
    $allRuntimeArtifacts = @($runtimeArtifacts) + @([pscustomobject]$surrealArtifact)
    Write-Utf8Json (Join-Path $runtimeRoot 'RUNTIME_ARTIFACTS.json') ([ordered]@{
            schema = 'eliot-runtime-artifact-set-v1'
            component = 'eliot_runtime_verified_build_artifacts'
            version = $version
            source_commit = $sourceCommit
            architecture = 'windows-x64'
            catalog_path = $catalogRelative
            catalog_sha256 = [string]$catalogFact.sha256
            catalog_source_commit = $sourceCommit
            build_profile = 'release'
            signed = $false
            signature_policy = 'pre-release-unsigned'
            signature_evidence = 'not-issued'
            installation_approval = 'not-issued'
            surreal_version = [string]$catalog.version
            artifacts = $allRuntimeArtifacts
        })

    $pluginManifest = Get-Content -LiteralPath `
        (Join-Path $codexPluginRoot '.codex-plugin\plugin.json') -Raw | ConvertFrom-Json
    Write-Utf8Json (Join-Path $bundle 'RELEASE.json') ([ordered]@{
            component = 'eliot_windows_x64_release'
            version = $version
            source_commit = $sourceCommit
            governor_version = $version
            codex_plugin_base_version = [string]$pluginManifest.version
            runtime_artifacts_manifest = 'runtime/RUNTIME_ARTIFACTS.json'
            runtime_artifact_catalog_path = $catalogRelative
            runtime_artifact_catalog_sha256 = [string]$catalogFact.sha256
            runtime_artifact_catalog_source_commit = $sourceCommit
            runtime_artifact_count = $allRuntimeArtifacts.Count
            runtime_artifacts = @($allRuntimeArtifacts | ForEach-Object {
                    [ordered]@{
                        package = [string]$_.package
                        binary = [string]$_.binary
                        role = [string]$_.role
                        path = [string]$_.path
                        source = [string]$_.source
                        version = [string]$_.version
                        architecture = [string]$_.architecture
                        sha256 = [string]$_.sha256
                        bytes = [int64]$_.bytes
                    }
                })
            architecture = 'windows-x64'
            signed = $false
            signature_policy = 'pre-release-unsigned'
            signature_evidence = 'not-issued'
            public_distribution_ready = $false
        })
    [System.IO.File]::WriteAllText(
        (Join-Path $bundle 'SIGNING_REQUIRED.txt'),
        "Machine-gate fixture: seven Authenticode roles require RFC3161 signing.`n",
        [System.Text.UTF8Encoding]::new($false))

    Assert-NoReleaseSecrets $bundle
    $hashes = @(Get-ChildItem -LiteralPath $bundle -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($bundle.Length).TrimStart([char]'\').Replace('\', '/')
                sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                bytes = [int64]$_.Length
            }
        })
    Write-Utf8Json (Join-Path $bundle 'SHA256SUMS.json') ([ordered]@{
            component = 'eliot_windows_x64_release_manifest'
            version = $version
            source_commit = $sourceCommit
            architecture = 'windows-x64'
            signed = $false
            files = $hashes
        })
    $verification = Test-ReleaseBundle $bundle
    if ([string]$verification.status -cne 'VERIFIED_UNSIGNED') {
        throw 'machine-gate fixture did not pass the canonical unsigned verifier'
    }
    return $bundle
}

function Invoke-ChildPowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][string[]]$ScriptArguments
    )
    return Invoke-CapturedProcess $childPowerShell `
        (@('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $Script) +
            $ScriptArguments)
}

function New-LaunchPaths([string]$Root, [string]$Name) {
    $contour = Join-Path $Root $Name
    $destination = Join-Path $contour 'destination'
    $staging = Join-Path $contour 'staging'
    $anchor = Join-Path $contour 'anchor'
    New-Item -ItemType Directory -Path $destination, $staging, $anchor -Force | Out-Null
    return [pscustomobject]@{
        output_bundle = Join-Path $destination 'phase-a'
        output = Join-Path $destination 'transaction.json'
        store = Join-Path $destination 'transaction.redb'
        staging = $staging
        anchor = $anchor
        transaction_id = "transaction-$Name"
    }
}

function Invoke-ShippedLauncher {
    param(
        [Parameter(Mandatory = $true)][string]$UnsignedBundle,
        [Parameter(Mandatory = $true)][string]$SignedBundle,
        [Parameter(Mandatory = $true)][object]$Paths
    )
    return Invoke-ChildPowerShellScript $launcherScript @(
        '-UnsignedBundle', $UnsignedBundle,
        '-SignedBundle', $SignedBundle,
        '-SignToolPath', $signTool,
        '-CertificateStoreLocation', $CertificateStoreLocation,
        '-CertificateThumbprint', $CertificateThumbprint,
        '-TimestampUrl', $TimestampUrl,
        '-OutputBundle', [string]$Paths.output_bundle,
        '-Output', [string]$Paths.output,
        '-Store', [string]$Paths.store,
        '-Generation', 'generation-live-signing-test',
        '-Installation', 'installation-live-signing-test',
        '-LineageId', 'lineage-live-signing-test',
        '-Sequence', '1',
        '-TransactionId', [string]$Paths.transaction_id,
        '-StagingRoot', [string]$Paths.staging,
        '-MinimumStoreAvailableBytes', '1',
        '-RecoveryCommand', "eliot installation recover --store exact --transaction-id $($Paths.transaction_id)",
        '-Profile', 'portable_dev',
        '-ProfileAnchorRoot', [string]$Paths.anchor)
}

function Assert-NoMaterializeOutputs([object]$Paths, [string]$Purpose) {
    foreach ($path in @($Paths.output_bundle, $Paths.output, $Paths.store)) {
        if ([System.IO.File]::Exists([string]$path) -or [System.IO.Directory]::Exists([string]$path)) {
            throw "$Purpose created output before rejecting a substituted signed bundle: $path"
        }
    }
}

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$gateRoot = Join-Path $tempBase "eliot-trusted-cli-live-signing-$([guid]::NewGuid().ToString('N'))"
try {
    New-Item -ItemType Directory -Path $gateRoot | Out-Null
    $helperExecutable = Join-Path $gateRoot 'EliotMaterializerProtocolHelper.exe'
    $compilerOutput = @(& $compiler /nologo /target:exe /platform:x64 /optimize+ `
            "/out:$helperExecutable" $helperSource 2>&1)
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $helperExecutable -PathType Leaf)) {
        throw "x64 materializer protocol helper compilation failed: $($compilerOutput -join [Environment]::NewLine)"
    }
    Assert-WindowsX64Pe $helperExecutable 'EliotMaterializerProtocolHelper.exe' | Out-Null
    if ([string](Get-AuthenticodeSignature -LiteralPath $helperExecutable).Status -cne 'NotSigned') {
        throw 'fresh materializer protocol helper must start at the unsigned boundary'
    }

    $unsignedBundle = New-LiveUnsignedBundle `
        $gateRoot $helperExecutable $pinnedSurrealExecutable
    $signedBundle = Join-Path $gateRoot 'signed-bundle'
    $finalization = Invoke-ChildPowerShellScript $finalizerScript @(
        '-UnsignedBundle', $unsignedBundle,
        '-SignedBundle', $signedBundle,
        '-SignToolPath', $signTool,
        '-CertificateStoreLocation', $CertificateStoreLocation,
        '-CertificateThumbprint', $CertificateThumbprint,
        '-TimestampUrl', $TimestampUrl)
    if ($finalization.exit_code -ne 75 -or [string]::IsNullOrWhiteSpace($finalization.stdout)) {
        throw "real finalization did not return typed COMMITTED_UNKNOWN/75: exit=$($finalization.exit_code) stderr=$($finalization.stderr)"
    }
    $finalizationReceipt = $finalization.stdout | ConvertFrom-Json
    if ([string]$finalizationReceipt.status -cne 'COMMITTED_UNKNOWN' -or
        -not (Test-Path -LiteralPath $signedBundle -PathType Container)) {
        throw 'real finalization did not publish the signed machine-gate fixture'
    }

    $publicVerification = Invoke-ChildPowerShellScript $finalizerScript @(
        '-UnsignedBundle', $unsignedBundle,
        '-VerifyBundle', $signedBundle,
        '-SignToolPath', $signTool,
        '-CertificateStoreLocation', $CertificateStoreLocation,
        '-CertificateThumbprint', $CertificateThumbprint,
        '-TimestampUrl', $TimestampUrl)
    if ($publicVerification.exit_code -ne 0 -or
        -not [string]::IsNullOrWhiteSpace($publicVerification.stderr)) {
        throw "real VerifyBundle failed: exit=$($publicVerification.exit_code) stderr=$($publicVerification.stderr)"
    }
    $verificationReceipt = $publicVerification.stdout | ConvertFrom-Json
    if ([string]$verificationReceipt.status -cne 'VERIFIED_SIGNED' -or
        [int]$verificationReceipt.roles -ne 7 -or
        $verificationReceipt.durable_install_authority -ne $false) {
        throw 'real VerifyBundle did not return the exact seven-role read-only snapshot'
    }

    $successPaths = New-LaunchPaths $gateRoot 'success'
    $success = Invoke-ShippedLauncher $unsignedBundle $signedBundle $successPaths
    if ($success.exit_code -ne 0 -or -not [string]::IsNullOrWhiteSpace($success.stderr)) {
        throw "shipped launcher success contour failed: exit=$($success.exit_code) stderr=$($success.stderr)"
    }
    $successReceipt = $success.stdout | ConvertFrom-Json
    if ([string]$successReceipt.schema -cne 'eliot-production-materialize-launch-v2' -or
        [string]$successReceipt.status -cne 'SOURCE_BUNDLE_MATERIALIZED' -or
        $successReceipt.child_succeeded -ne $true -or [int]$successReceipt.exit_code -ne 0 -or
        @($successReceipt.signed_roles).Count -ne 7 -or
        @($successReceipt.output_readback.roles).Count -ne 9 -or
        [string]$successReceipt.generated_receipt.status -cne 'GENERATED' -or
        [string]$successReceipt.materialized_receipt.status -cne 'SOURCE_BUNDLE_MATERIALIZED' -or
        [string]$successReceipt.cli.signer_thumbprint -cne $normalizedThumbprint) {
        throw 'shipped launcher did not return the exact signed process/receipt/readback success contract'
    }
    $expectedMaterializedRoles = @(
        'eliot-host.exe', 'eliot-watchdog.exe', 'eliot-kernel.exe',
        'eliot-store-surreal.exe', 'surreal.exe', 'eliotd.exe',
        'generation.json', 'eliotd-governor.json', 'eliotd.json')
    $actualMaterializedRoles = @($successReceipt.materialized_receipt.files | ForEach-Object {
            [string]$_.relative_path
        })
    if (($actualMaterializedRoles -join "`n") -cne ($expectedMaterializedRoles -join "`n")) {
        throw 'shipped launcher success receipt changed the exact ordered nine-role inventory'
    }
    foreach ($role in $expectedMaterializedRoles[0..5]) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $successPaths.output_bundle $role)
        if ([string]$signature.Status -cne 'Valid' -or
            ([string]$signature.SignerCertificate.Thumbprint).Replace(' ', '').ToLowerInvariant() -cne
                $normalizedThumbprint) {
            throw "materialized executable lost its Authenticode identity: $role"
        }
    }

    $roleSubstitutionBundle = Join-Path $gateRoot 'signed-role-substitution'
    Copy-Item -LiteralPath $signedBundle -Destination $roleSubstitutionBundle -Recurse
    [System.IO.File]::Copy(
        $helperExecutable,
        (Join-Path $roleSubstitutionBundle 'runtime\eliot-host.exe'),
        $true)
    $roleSubstitutionPaths = New-LaunchPaths $gateRoot 'role-substitution'
    $roleSubstitution = Invoke-ShippedLauncher `
        $unsignedBundle $roleSubstitutionBundle $roleSubstitutionPaths
    if ($roleSubstitution.exit_code -eq 0) {
        throw 'shipped launcher accepted an unsigned substituted Phase-A role'
    }
    Assert-NoMaterializeOutputs $roleSubstitutionPaths 'Phase-A role substitution'

    $cliSubstitutionBundle = Join-Path $gateRoot 'signed-cli-substitution'
    Copy-Item -LiteralPath $signedBundle -Destination $cliSubstitutionBundle -Recurse
    [System.IO.File]::Copy(
        $helperExecutable,
        (Join-Path $cliSubstitutionBundle 'runtime\eliot.exe'),
        $true)
    $cliSubstitutionPaths = New-LaunchPaths $gateRoot 'cli-substitution'
    $cliSubstitution = Invoke-ShippedLauncher `
        $unsignedBundle $cliSubstitutionBundle $cliSubstitutionPaths
    if ($cliSubstitution.exit_code -eq 0) {
        throw 'shipped launcher accepted an unsigned substituted CLI image'
    }
    Assert-NoMaterializeOutputs $cliSubstitutionPaths 'CLI substitution'

    if ((Get-FileHash -LiteralPath $launcherScript -Algorithm SHA256).Hash -cne $launcherHashBefore -or
        (Get-FileHash -LiteralPath $finalizerScript -Algorithm SHA256).Hash -cne $finalizerHashBefore) {
        throw 'live signing gate mutated a shipped production script'
    }
    $trackedAfter = @(& git -C $testRepo status --porcelain --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedAfter.Count -ne 0) {
        throw 'live signing gate changed the tracked source tree'
    }

    [ordered]@{
        component = 'eliot_trusted_cli_live_signing_tests'
        status = 'VERIFIED'
        source_commit = $sourceCommit
        powershell = $childPowerShell
        signer_thumbprint = $normalizedThumbprint
        real_rfc3161_finalization = $true
        real_verify_bundle = $true
        shipped_launcher_bytes_invoked = $true
        create_suspended_helper_executed = $true
        generated_then_materialized_protocol = $true
        exact_nine_role_readback = $true
        materialized_six_pe_authenticode_valid = $true
        phase_a_role_substitution_rejected = $true
        cli_substitution_rejected = $true
        no_product_install_scm_or_uac = $true
    } | ConvertTo-Json -Depth 5
}
finally {
    $resolvedGateRoot = [System.IO.Path]::GetFullPath($gateRoot)
    if ($resolvedGateRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedGateRoot)) {
        Remove-Item -LiteralPath $resolvedGateRoot -Recurse -Force
    }
}
