[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$launcherScript = Join-Path $repo 'scripts\invoke-eliot-windows-x64-production.ps1'
$finalizerScript = Join-Path $repo 'scripts\finalize-eliot-windows-x64-release.ps1'
$launcherTokens = $null
$launcherParseErrors = $null
$launcherAst = [System.Management.Automation.Language.Parser]::ParseFile(
    $launcherScript,
    [ref]$launcherTokens,
    [ref]$launcherParseErrors)
if ($launcherParseErrors.Count -ne 0) {
    throw "trusted CLI launcher has parser errors: $($launcherParseErrors[0].Message)"
}
$expectedLauncherParameters = @(
    'CertificateStoreLocation', 'CertificateThumbprint', 'Generation', 'Installation',
    'InstallationKey', 'LineageId', 'MinimumStoreAvailableBytes', 'Output', 'OutputBundle',
    'Profile', 'ProfileAnchorRoot', 'RecoveryCommand', 'Sequence', 'SignedBundle',
    'SignToolPath', 'StagingRoot', 'Store', 'TimestampUrl', 'TransactionId', 'UnsignedBundle') |
    Sort-Object
$actualLauncherParameters = @(
    $launcherAst.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath } |
        Sort-Object)
if (($actualLauncherParameters -join "`n") -cne ($expectedLauncherParameters -join "`n")) {
    throw "canonical launcher exposes a raw argument, role path, executable, or verifier bypass: $($actualLauncherParameters -join ', ')"
}
$launcherText = [System.IO.File]::ReadAllText($launcherScript)
foreach ($forbidden in @(
        'EliotArguments', 'BundleVerifier', 'BeforeResumeTestHook',
        '[scriptblock]', 'Invoke-PinnedEliotCliProcess')) {
    if ($launcherText.IndexOf($forbidden, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        throw "shipped launcher retains a production-callable injection surface: $forbidden"
    }
}
if ($launcherText -match '(?m)^\s*Test-ReleaseBundle\b' -or
    $launcherText -notmatch '(?m)^\s*Invoke-ReleaseBundleInputVerification\b') {
    throw 'canonical launcher reached through the builder verifier instead of the sealed finalizer verifier'
}
$productionFunctions = @($launcherAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq 'Invoke-ProductionEliotMaterializeSourceBundle'
        }, $true))
if ($productionFunctions.Count -ne 1) {
    throw 'canonical typed materialize function is missing or duplicated'
}
$productionFunctionParameters = @(
    $productionFunctions[0].Body.ParamBlock.Parameters |
        ForEach-Object { $_.Name.VariablePath.UserPath } |
        Sort-Object)
$expectedProductionFunctionParameters = @(
    'Contract', 'Rfc3161Url', 'SignTool', 'StoreLocation', 'Thumbprint') | Sort-Object
if (($productionFunctionParameters -join "`n") -cne
    ($expectedProductionFunctionParameters -join "`n")) {
    throw 'canonical typed materialize function exposes an unexpected invocation override'
}

if (-not $env:SystemRoot) { throw 'trusted CLI launcher tests require Windows' }
$sourceExecutable = Join-Path $env:SystemRoot 'System32\cmd.exe'
$substituteExecutable = Join-Path $env:SystemRoot 'System32\where.exe'
$launcherSignTool = (Get-Process -Id $PID).Path
if ([string]::IsNullOrWhiteSpace($launcherSignTool)) {
    throw 'trusted CLI launcher test process path is unavailable for standalone contour validation'
}
foreach ($path in @($sourceExecutable, $substituteExecutable)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "trusted CLI launcher fixture executable is unavailable: $path"
    }
}

$thumbprint = '0123456789abcdef0123456789abcdef01234567'
$fixtureTimestampUrl = 'http://timestamp.example.test/rfc3161'
$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$root = Join-Path $tempBase "eliot-trusted-cli-launch-$([guid]::NewGuid().ToString('N'))"
$global:EliotTrustedCliTestBeforeResume = $null
$global:EliotTrustedCliTestAfterProcess = $null
$global:EliotTrustedCliTestProcessArguments = $null
$global:EliotTrustedCliTestDerivedArguments = $null

function Write-FixtureJson([string]$Path, [object]$Value) {
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-TestSignedRoleDefinitions {
    return @(
        [pscustomobject]@{ role = 'cli'; path = 'runtime/eliot.exe' }
        [pscustomobject]@{ role = 'host'; path = 'runtime/eliot-host.exe' }
        [pscustomobject]@{ role = 'watchdog'; path = 'runtime/eliot-watchdog.exe' }
        [pscustomobject]@{ role = 'kernel'; path = 'runtime/eliot-kernel.exe' }
        [pscustomobject]@{ role = 'store_bridge'; path = 'runtime/eliot-store-surreal.exe' }
        [pscustomobject]@{ role = 'database'; path = 'runtime/surreal.exe' }
        [pscustomobject]@{ role = 'daemon'; path = 'runtime/eliotd.exe' }
    )
}

function New-TestRoleReceipt([object]$Definition, [string]$Path) {
    return [ordered]@{
        role = [string]$Definition.role
        role_path = ([string]$Definition.path).Replace('\', '/')
        status = 'Valid'
        signer_thumbprint = $thumbprint
        signer_subject = 'CN=Eliot Launcher Fixture'
        timestamped = $true
        timestamp_url = $fixtureTimestampUrl
        timestamp_protocol = 'RFC3161'
        timestamp_attribute_oid = '1.3.6.1.4.1.311.3.3.1'
        timestamp_message_imprint_algorithm_oid = '2.16.840.1.101.3.4.2.1'
        timestamp_message_imprint = ('ab' * 32)
        timestamp_cms_signature_valid = $true
        timestamp_certificate_thumbprint = ('89' * 20)
        timestamp_certificate_subject = 'CN=Fixture Timestamp'
        signer_signature_sha256 = ('cd' * 32)
        signtool_verify_exit_code = 0
        signtool_verify_policy = '/pa /all /v /tw'
        verifier = 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS'
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = [int64](Get-Item -LiteralPath $Path).Length
    }
}

function New-TrustedCliFixture([string]$Name) {
    $fixtureRoot = Join-Path $root $Name
    $unsigned = Join-Path $fixtureRoot 'unsigned'
    $signed = Join-Path $fixtureRoot 'signed bundle'
    $runtime = Join-Path $signed 'runtime'
    $destination = Join-Path $fixtureRoot 'destination'
    $staging = Join-Path $fixtureRoot 'staging'
    $anchor = Join-Path $fixtureRoot 'anchor'
    New-Item -ItemType Directory -Path $unsigned, $runtime, $destination, $staging, $anchor -Force | Out-Null
    $receipts = [System.Collections.Generic.List[object]]::new()
    $artifacts = [System.Collections.Generic.List[object]]::new()
    $checksums = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in @(Get-TestSignedRoleDefinitions)) {
        $path = Join-Path $signed ([string]$definition.path).Replace('/', '\')
        Copy-Item -LiteralPath $sourceExecutable -Destination $path
        $receipt = New-TestRoleReceipt $definition $path
        [void]$receipts.Add($receipt)
        [void]$artifacts.Add([ordered]@{
                package = 'eliot'
                binary = [System.IO.Path]::GetFileNameWithoutExtension($path)
                role = [string]$definition.role
                path = ([string]$definition.path).Replace('\', '/')
                sha256 = [string]$receipt.sha256
                bytes = [int64]$receipt.bytes
                signature_policy = 'authenticode-rfc3161'
                signature_evidence = $receipt
            })
        [void]$checksums.Add([ordered]@{
                path = ([string]$definition.path).Replace('\', '/')
                sha256 = [string]$receipt.sha256
                bytes = [int64]$receipt.bytes
            })
    }
    $evidence = [ordered]@{
        status = 'VERIFIED'
        signer = [ordered]@{
            store_location = 'Cert:\CurrentUser\My'
            thumbprint = $thumbprint
            subject = 'CN=Eliot Launcher Fixture'
            has_private_key = $true
            code_signing_eku = '1.3.6.1.5.5.7.3.3'
        }
        timestamp = [ordered]@{
            url = $fixtureTimestampUrl
            protocol = 'RFC3161'
            digest_algorithm = 'sha256'
            digest_algorithm_oid = '2.16.840.1.101.3.4.2.1'
            attribute_oid = '1.3.6.1.4.1.311.3.3.1'
        }
        verifier = 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS'
        roles = @($receipts)
    }
    $common = [ordered]@{
        signed = $true
        signature_policy = 'authenticode-rfc3161'
        signed_scope = 'runtime-materializer-six-plus-cli-pe-roles'
        signature_evidence = $evidence
    }
    Write-FixtureJson (Join-Path $signed 'RELEASE.json') ([ordered]@{
            signed = $common.signed
            signature_policy = $common.signature_policy
            signed_scope = $common.signed_scope
            signature_evidence = $common.signature_evidence
            runtime_artifacts = @($artifacts)
        })
    Write-FixtureJson (Join-Path $runtime 'RUNTIME_ARTIFACTS.json') ([ordered]@{
            signed = $common.signed
            signature_policy = $common.signature_policy
            signed_scope = $common.signed_scope
            signature_evidence = $common.signature_evidence
            artifacts = @($artifacts)
        })
    Write-FixtureJson (Join-Path $signed 'SHA256SUMS.json') ([ordered]@{
            signed = $common.signed
            signature_policy = $common.signature_policy
            signed_scope = $common.signed_scope
            signature_evidence = $common.signature_evidence
            files = @($checksums)
        })
    Write-FixtureJson (Join-Path $signed 'SIGNING_VERIFIED.json') ([ordered]@{
            schema = 'eliot-authenticode-signing-verification-v1'
            signature_evidence = $evidence
        })
    return [pscustomobject]@{
        root = $fixtureRoot
        unsigned = $unsigned
        signed = $signed
        runtime = $runtime
        destination = $destination
        staging = $staging
        anchor = $anchor
        cli = Join-Path $runtime 'eliot.exe'
        output_bundle = Join-Path $destination 'phase-a'
        output = Join-Path $destination 'transaction.json'
        store = Join-Path $destination 'transaction.redb'
        marker = Join-Path $fixtureRoot 'child-started.txt'
    }
}

function New-TestContract([object]$Fixture) {
    return New-ProductionMaterializeContract `
        -UnsignedBundlePath $Fixture.unsigned `
        -SignedBundlePath $Fixture.signed `
        -OutputBundlePath $Fixture.output_bundle `
        -OutputPath $Fixture.output `
        -StorePath $Fixture.store `
        -GenerationValue 'generation-test' `
        -InstallationValue 'installation-test' `
        -LineageIdValue 'lineage-test' `
        -SequenceValue 1 `
        -TransactionIdValue 'transaction:test' `
        -StagingRootPath $Fixture.staging `
        -MinimumStoreAvailableBytesValue 1 `
        -RecoveryCommandValue 'eliot installation recover --store exact --transaction-id transaction:test' `
        -ProfileValue 'portable_dev' `
        -ProfileAnchorRootPath $Fixture.anchor `
        -InstallationKeyValue $null
}

function Get-TestBundleVerification([object]$Contract, [string]$Signed) {
    return [pscustomobject]@{
        component = 'eliot_windows_x64_release_verify'
        status = 'VERIFIED_SIGNED'
        verification_kind = 'READ_ONLY_SNAPSHOT'
        durable_install_authority = $false
        bundle = $Signed
        signed_scope = 'runtime-materializer-six-plus-cli-pe-roles'
        roles = 7
        files = 4
    }
}

function New-IdentityFact([object]$Observation) {
    return [ordered]@{
        volume_serial_number = [uint32]$Observation.volume_serial_number
        file_index = [uint64]$Observation.file_index
    }
}

function Complete-TestMaterializeOutputs([object]$Contract, [object]$ProcessOutcome) {
    [System.IO.Directory]::CreateDirectory([string]$Contract.output_bundle) | Out-Null
    foreach ($name in @(
            'eliot-host.exe', 'eliot-watchdog.exe', 'eliot-kernel.exe',
            'eliot-store-surreal.exe', 'surreal.exe', 'eliotd.exe')) {
        [System.IO.File]::Copy(
            (Join-Path ([string]$Contract.signed_bundle) "runtime\$name"),
            (Join-Path ([string]$Contract.output_bundle) $name),
            $false)
    }
    foreach ($name in @('generation.json', 'eliotd-governor.json', 'eliotd.json')) {
        [System.IO.File]::WriteAllText(
            (Join-Path ([string]$Contract.output_bundle) $name),
            "{`"fixture`":`"$name`"}`n",
            [System.Text.UTF8Encoding]::new($false))
    }
    [System.IO.File]::WriteAllText(
        [string]$Contract.output,
        "{`"transaction_id`":`"$($Contract.transaction_id)`"}`n",
        [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllBytes([string]$Contract.store, [byte[]](1, 2, 3, 4, 5, 6, 7, 8))
    $bundlePin = New-NativeDirectoryPin ([string]$Contract.output_bundle) $false
    try {
        $directoryIdentity = [ordered]@{
            volume_serial_number = [uint32]$bundlePin.identity.VolumeSerialNumber
            file_index = [uint64]$bundlePin.identity.FileIndex
        }
    }
    finally { Close-NativeDirectoryPin $bundlePin }
    $files = [System.Collections.Generic.List[object]]::new()
    foreach ($definition in $script:ProductionMaterializedRoles) {
        $path = Join-Path ([string]$Contract.output_bundle) ([string]$definition.name)
        $handle = [EliotReleaseNativeFileSystem]::OpenFileReadFence($path)
        try {
            $observation = Get-PinnedCliObservation $handle $path
            [void]$files.Add([ordered]@{
                    relative_path = [string]$definition.name
                    executable = [bool]$definition.executable
                    size = [int64]$observation.bytes
                    sha256 = [string]$observation.sha256
                    source_identity = New-IdentityFact $observation
                    destination_identity = New-IdentityFact $observation
                    pe = $(if ($definition.executable) { [ordered]@{ fixture = $true } } else { $null })
                    authenticode = $(if ($definition.executable) { [ordered]@{ status = 'Valid' } } else { $null })
                })
        }
        finally { $handle.Dispose() }
    }
    $generated = [ordered]@{
        contract = 'eliot.kernel.installation'
        contract_version = '3.0.0'
        status = 'GENERATED'
        transaction_id = [string]$Contract.transaction_id
        generation = [string]$Contract.generation
        output = [string]$Contract.output
        store = [string]$Contract.store
        source_publication_bound = $true
        durable_authority = 'DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID'
        output_role = 'DIAGNOSTIC_NON_IMPORTABLE'
    }
    $materialized = [ordered]@{
        contract = 'eliot.kernel.installation'
        contract_version = '3.0.0'
        status = 'SOURCE_BUNDLE_MATERIALIZED'
        handoff = 'SOURCE_PUBLICATION_BOUND_TO_GENERATED_PLAN'
        transaction_id = [string]$Contract.transaction_id
        generation = [string]$Contract.generation
        output = [string]$Contract.output
        store = [string]$Contract.store
        durable_authority = 'DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID'
        output_role = 'DIAGNOSTIC_NON_IMPORTABLE'
        bundle_path = [string]$Contract.output_bundle
        evidence_digest = ('ef' * 32)
        file_count = 9
        files = @($files)
        source_identity = $directoryIdentity
        directory_publication = [ordered]@{
            source_identity = $directoryIdentity
            destination_identity = $directoryIdentity
        }
    }
    $ProcessOutcome.StandardOutput =
        ($generated | ConvertTo-Json -Depth 20) + "`n" +
        ($materialized | ConvertTo-Json -Depth 20) + "`n"
    $ProcessOutcome.StandardError = ''
}

function Get-ArgumentValue([string[]]$Arguments, [string]$Flag) {
    $indices = @()
    for ($index = 0; $index -lt $Arguments.Count; $index++) {
        if ([string]$Arguments[$index] -ceq $Flag) { $indices += $index }
    }
    if ($indices.Count -ne 1 -or $indices[0] + 1 -ge $Arguments.Count) {
        throw "typed materialize argument is missing or duplicated: $Flag"
    }
    return [string]$Arguments[$indices[0] + 1]
}

try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null

    # The canonical script is an operation, not a library. Reject dot-source
    # before any production function becomes callable in the caller's scope.
    $dotSourceRejected = $false
    try {
        . $launcherScript
    }
    catch {
        $dotSourceRejected = $_.Exception.Message -match 'cannot be dot-sourced'
    }
    if (-not $dotSourceRejected -or
        (Get-Command Invoke-ProductionEliotMaterializeSourceBundle -ErrorAction SilentlyContinue)) {
        throw 'shipped launcher remained callable/injectable after dot-source'
    }

    # Generate one disposable test-only copy. The shipped script remains free
    # of verifier/process hooks; replacements exist only below the Temp root.
    $instrumented = $launcherText
    $dotSourceGuard = @'
if ($MyInvocation.InvocationName -eq '.') {
    throw 'the canonical production materialize launcher cannot be dot-sourced'
}
'@.TrimEnd()
    $instrumented = $instrumented.Replace($dotSourceGuard, @'
if ($false) {
    throw 'test-only generated launcher copy'
}
'@.TrimEnd())
    $finalizerLiteral = $finalizerScript.Replace("'", "''")
    $instrumented = $instrumented.Replace(
        "`$finalizerScript = Join-Path `$PSScriptRoot 'finalize-eliot-windows-x64-release.ps1'",
        "`$finalizerScript = '$finalizerLiteral'")
    $verificationPattern = '(?ms)^        \$plan = New-AuthenticodeVerificationPlan .*?^        \$verification = Test-FinalizedReleaseBundle `\r?\n            \$signed \$null \$baseline \$plan \$certificateIdentity\r?\n'
    $verificationReplacement = (@'
        $verification = Get-TestBundleVerification $Contract $signed
'@
    ) + [Environment]::NewLine
    $instrumented = [regex]::Replace(
        $instrumented, $verificationPattern, $verificationReplacement, 1)
    $argumentAnchor = '        $arguments = New-ProductionMaterializeArguments $Contract $rolePins'
    $instrumented = $instrumented.Replace($argumentAnchor, @'
        $arguments = New-ProductionMaterializeArguments $Contract $rolePins
        $global:EliotTrustedCliTestDerivedArguments = @($arguments)
        if ($global:EliotTrustedCliTestProcessArguments) {
            $arguments = @(& $global:EliotTrustedCliTestProcessArguments $Contract $arguments)
        }
'@.TrimEnd())
    $beforeResumeAnchor = "        Assert-ProductionMaterializeOutputsAbsent `$Contract 'materialize suspended-child boundary'"
    $instrumented = $instrumented.Replace($beforeResumeAnchor, @'
        Assert-ProductionMaterializeOutputsAbsent $Contract 'materialize suspended-child boundary'
        if ($global:EliotTrustedCliTestBeforeResume) {
            & $global:EliotTrustedCliTestBeforeResume ([pscustomobject]@{
                    contract = $Contract
                    cli_path = $cliPath
                    process_id = [uint32]$created.ProcessId
                    process_start_time_100ns = [uint64]$created.StartTime100ns
                    process_image_path = [string]$created.ImagePath
                })
        }
'@.TrimEnd())
    $afterProcessAnchor = '        $processOutcome = $process.ResumeAndWait()'
    $instrumented = $instrumented.Replace($afterProcessAnchor, @'
        $processOutcome = $process.ResumeAndWait()
        if ($global:EliotTrustedCliTestAfterProcess) {
            & $global:EliotTrustedCliTestAfterProcess $Contract $processOutcome
        }
'@.TrimEnd())
    $topLevelAnchor = 'foreach ($required in @{'
    $instrumented = $instrumented.Replace($topLevelAnchor, @'
if ($MyInvocation.InvocationName -eq '.') { return }

foreach ($required in @{
'@.TrimEnd())
    if ($instrumented -ceq $launcherText -or
        $instrumented.Contains('New-AuthenticodeVerificationPlan')) {
        throw 'test-only launcher copy instrumentation did not bind all intended anchors'
    }
    $instrumentedPath = Join-Path $root 'instrumented-launcher.ps1'
    [System.IO.File]::WriteAllText(
        $instrumentedPath, $instrumented, [System.Text.UTF8Encoding]::new($false))
    . $instrumentedPath

    $normal = New-TrustedCliFixture 'normal'
    $normalContract = New-TestContract $normal
    $standaloneSignTool = Join-Path $normal.root 'signtool.exe'
    Copy-Item -LiteralPath $launcherSignTool -Destination $standaloneSignTool

    # Exercise the shipped launcher as a standalone operation.  This must use
    # its real finalizer/builder load contour; the fixture is intentionally
    # incomplete only on the unsigned side so the canonical verifier is the
    # first production gate reached.  No signing, installation, SCM, or child
    # process is allowed to occur on this path.
    $standaloneVerifierRejected = $false
    $standaloneVerifierMessage = ''
    try {
        & $launcherScript `
            -UnsignedBundle $normal.unsigned `
            -SignedBundle $normal.signed `
            -SignToolPath $standaloneSignTool `
            -CertificateStoreLocation 'Cert:\CurrentUser\My' `
            -CertificateThumbprint $thumbprint `
            -TimestampUrl $fixtureTimestampUrl `
            -OutputBundle (Join-Path $normal.root 'standalone-output-bundle') `
            -Output (Join-Path $normal.root 'standalone-output.json') `
            -Store (Join-Path $normal.root 'standalone-store.redb') `
            -Generation 'generation-test' `
            -Installation 'installation-test' `
            -LineageId 'lineage-test' `
            -Sequence 1 `
            -TransactionId 'transaction:standalone' `
            -StagingRoot $normal.staging `
            -MinimumStoreAvailableBytes 1 `
            -RecoveryCommand 'eliot installation recover --store exact --transaction-id transaction:standalone' `
            -Profile 'portable_dev' `
            -ProfileAnchorRoot $normal.anchor | Out-Null
    }
    catch {
        $standaloneVerifierMessage = [string]$_.Exception.Message
        $standaloneVerifierRejected = $standaloneVerifierMessage -match
            'release bundle is missing required asset: eliot-governor\.exe'
    }
    if (-not $standaloneVerifierRejected -or
        $standaloneVerifierMessage -match "Test-ReleaseBundle.*not recognized|cannot find the term") {
        throw "standalone launcher did not reach the sealed unsigned-bundle verifier: $standaloneVerifierMessage"
    }

    $normalState = [pscustomobject]@{ observed_suspended = $false }
    $global:EliotTrustedCliTestProcessArguments = {
        param($contract, $derived)
        return @('/d', '/c', "echo launched>$($normal.marker)")
    }.GetNewClosure()
    $global:EliotTrustedCliTestBeforeResume = {
        param($context)
        if (Test-Path -LiteralPath $normal.marker) {
            throw 'trusted CLI child executed before retained identity gate'
        }
        if ([uint32]$context.process_id -eq 0 -or
            -not (Test-ExactWindowsPath ([string]$context.process_image_path) $normal.cli)) {
            throw 'trusted CLI suspended process evidence is not exact'
        }
        $normalState.observed_suspended = $true
    }.GetNewClosure()
    $global:EliotTrustedCliTestAfterProcess = {
        param($contract, $outcome)
        Complete-TestMaterializeOutputs $contract $outcome
    }
    $normalOutcome = Invoke-ProductionEliotMaterializeSourceBundle `
        -Contract $normalContract `
        -SignTool $substituteExecutable `
        -StoreLocation 'Cert:\CurrentUser\My' `
        -Thumbprint $thumbprint `
        -Rfc3161Url $fixtureTimestampUrl
    if (-not $normalState.observed_suspended -or
        -not (Test-Path -LiteralPath $normal.marker -PathType Leaf) -or
        [string]$normalOutcome.status -cne 'SOURCE_BUNDLE_MATERIALIZED' -or
        [int]$normalOutcome.exit_code -ne 0 -or
        @($normalOutcome.signed_roles).Count -ne 7 -or
        @($normalOutcome.output_readback.roles).Count -ne 9) {
        throw 'normal typed trusted materialize launch was not fully receipt-bound'
    }
    $derived = @($global:EliotTrustedCliTestDerivedArguments)
    if ([string]$derived[0] -cne 'installation' -or
        [string]$derived[1] -cne 'materialize-source-bundle') {
        throw 'typed launcher derived a non-materialize command'
    }
    $expectedRoleArguments = [ordered]@{
        '--eliot-host' = 'eliot-host.exe'
        '--eliot-watchdog' = 'eliot-watchdog.exe'
        '--eliot-kernel' = 'eliot-kernel.exe'
        '--eliot-store-surreal' = 'eliot-store-surreal.exe'
        '--surreal' = 'surreal.exe'
        '--eliotd' = 'eliotd.exe'
    }
    foreach ($entry in $expectedRoleArguments.GetEnumerator()) {
        $actual = Get-ArgumentValue $derived ([string]$entry.Key)
        $expected = Join-Path $normal.runtime ([string]$entry.Value)
        if (-not (Test-ExactWindowsPath $actual $expected)) {
            throw "typed launcher mixed or overrode signed role $($entry.Key)"
        }
    }

    $mixed = New-TrustedCliFixture 'mixed-bundle'
    $mixedContract = New-TestContract $mixed
    Copy-Item -LiteralPath $substituteExecutable `
        -Destination (Join-Path $mixed.runtime 'eliot-host.exe') -Force
    $global:EliotTrustedCliTestAfterProcess = $null
    $mixedRejected = $false
    try {
        Invoke-ProductionEliotMaterializeSourceBundle `
            -Contract $mixedContract -SignTool $substituteExecutable `
            -StoreLocation 'Cert:\CurrentUser\My' -Thumbprint $thumbprint `
            -Rfc3161Url $fixtureTimestampUrl | Out-Null
    }
    catch { $mixedRejected = $_.Exception.Message -match 'retained bytes do not match' }
    if (-not $mixedRejected -or (Test-Path -LiteralPath $mixed.marker)) {
        throw 'mixed signed-bundle role was not rejected before child execution'
    }

    $preexisting = New-TrustedCliFixture 'preexisting-output'
    [System.IO.File]::WriteAllText(
        $preexisting.output,
        "{`"foreign`":true}`n",
        [System.Text.UTF8Encoding]::new($false))
    $preexistingRejected = $false
    try { New-TestContract $preexisting | Out-Null }
    catch { $preexistingRejected = $_.Exception.Message -match 'absent create-new path' }
    if (-not $preexistingRejected) {
        throw 'preexisting transaction output was accepted for production materialization'
    }

    $help = New-TrustedCliFixture 'help-false-zero'
    $helpContract = New-TestContract $help
    $global:EliotTrustedCliTestProcessArguments = {
        return @('/d', '/c', 'echo ELIOT help')
    }
    $global:EliotTrustedCliTestBeforeResume = $null
    $global:EliotTrustedCliTestAfterProcess = $null
    $helpRejected = $false
    try {
        Invoke-ProductionEliotMaterializeSourceBundle `
            -Contract $helpContract -SignTool $substituteExecutable `
            -StoreLocation 'Cert:\CurrentUser\My' -Thumbprint $thumbprint `
            -Rfc3161Url $fixtureTimestampUrl | Out-Null
    }
    catch { $helpRejected = $_.Exception.Message -match 'non-JSON|exactly GENERATED' }
    if (-not $helpRejected -or
        (Test-Path -LiteralPath $help.output_bundle) -or
        (Test-Path -LiteralPath $help.output) -or
        (Test-Path -LiteralPath $help.store)) {
        throw '--help/textual false-zero was accepted as materialization success'
    }

    $missing = New-TrustedCliFixture 'missing-receipt'
    $missingContract = New-TestContract $missing
    $global:EliotTrustedCliTestProcessArguments = { return @('/d', '/c', 'ver >nul') }
    $global:EliotTrustedCliTestAfterProcess = {
        param($contract, $outcome)
        $outcome.StandardOutput = ([ordered]@{
                contract = 'eliot.kernel.installation'; contract_version = '3.0.0'
                status = 'GENERATED'; transaction_id = [string]$contract.transaction_id
                generation = [string]$contract.generation; output = [string]$contract.output
                store = [string]$contract.store; source_publication_bound = $true
                durable_authority = 'DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID'
                output_role = 'DIAGNOSTIC_NON_IMPORTABLE'
            } | ConvertTo-Json)
        $outcome.StandardError = ''
    }
    $missingRejected = $false
    try {
        Invoke-ProductionEliotMaterializeSourceBundle `
            -Contract $missingContract -SignTool $substituteExecutable `
            -StoreLocation 'Cert:\CurrentUser\My' -Thumbprint $thumbprint `
            -Rfc3161Url $fixtureTimestampUrl | Out-Null
    }
    catch { $missingRejected = $_.Exception.Message -match 'exactly GENERATED' }
    if (-not $missingRejected) { throw 'missing final materialization receipt was accepted' }

    $substituted = New-TrustedCliFixture 'substituted-receipt'
    $substitutedContract = New-TestContract $substituted
    $global:EliotTrustedCliTestAfterProcess = {
        param($contract, $outcome)
        Complete-TestMaterializeOutputs $contract $outcome
        $objects = @(ConvertFrom-ProductionJsonObjectStream ([string]$outcome.StandardOutput))
        $objects[1].store = Join-Path $substituted.destination 'foreign.redb'
        $outcome.StandardOutput =
            ($objects[0] | ConvertTo-Json -Depth 20) + "`n" +
            ($objects[1] | ConvertTo-Json -Depth 20) + "`n"
    }.GetNewClosure()
    $substitutedRejected = $false
    try {
        Invoke-ProductionEliotMaterializeSourceBundle `
            -Contract $substitutedContract -SignTool $substituteExecutable `
            -StoreLocation 'Cert:\CurrentUser\My' -Thumbprint $thumbprint `
            -Rfc3161Url $fixtureTimestampUrl | Out-Null
    }
    catch { $substitutedRejected = $_.Exception.Message -match 'exact typed handoff' }
    if (-not $substitutedRejected) { throw 'substituted materialization receipt was accepted' }

    $boundary = New-TrustedCliFixture 'verifier-launch-boundary'
    $boundaryContract = New-TestContract $boundary
    $boundaryState = [pscustomobject]@{
        process_id = [uint32]0
        cli_write_blocked = $false
        role_write_blocked = $false
        cli_rename_blocked = $false
        evidence_write_blocked = $false
        directory_rename_blocked = $false
    }
    $global:EliotTrustedCliTestProcessArguments = {
        return @('/d', '/c', "echo launched>$($boundary.marker)")
    }.GetNewClosure()
    $global:EliotTrustedCliTestBeforeResume = {
        param($context)
        $boundaryState.process_id = [uint32]$context.process_id
        foreach ($probe in @(
                [pscustomobject]@{ path = $boundary.cli; field = 'cli_write_blocked' }
                [pscustomobject]@{ path = (Join-Path $boundary.runtime 'eliot-host.exe'); field = 'role_write_blocked' }
                [pscustomobject]@{ path = (Join-Path $boundary.signed 'RELEASE.json'); field = 'evidence_write_blocked' }
            )) {
            $stream = $null
            try {
                $stream = [System.IO.File]::Open(
                    $probe.path, [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            }
            catch { $boundaryState.($probe.field) = $true }
            finally { if ($stream) { $stream.Dispose() } }
        }
        try { [System.IO.File]::Move($boundary.cli, "$($boundary.cli).substituted") }
        catch { $boundaryState.cli_rename_blocked = $true }
        try { [System.IO.Directory]::Move($boundary.signed, "$($boundary.signed).substituted") }
        catch { $boundaryState.directory_rename_blocked = $true }
        throw 'intentional verifier-to-launch substitution probe abort'
    }.GetNewClosure()
    $global:EliotTrustedCliTestAfterProcess = $null
    $boundaryRejected = $false
    try {
        Invoke-ProductionEliotMaterializeSourceBundle `
            -Contract $boundaryContract -SignTool $substituteExecutable `
            -StoreLocation 'Cert:\CurrentUser\My' -Thumbprint $thumbprint `
            -Rfc3161Url $fixtureTimestampUrl | Out-Null
    }
    catch {
        $boundaryRejected = $_.Exception.Message -match 'intentional verifier-to-launch substitution probe abort'
    }
    $candidateStillLive = $false
    if ($boundaryState.process_id -ne 0) {
        $candidateStillLive = $null -ne (Get-Process -Id $boundaryState.process_id -ErrorAction SilentlyContinue)
    }
    if (-not $boundaryRejected -or $candidateStillLive -or
        -not $boundaryState.cli_write_blocked -or -not $boundaryState.role_write_blocked -or
        -not $boundaryState.cli_rename_blocked -or -not $boundaryState.evidence_write_blocked -or
        -not $boundaryState.directory_rename_blocked -or
        (Test-Path -LiteralPath $boundary.marker)) {
        throw 'verifier-to-launch substitution did not fail closed with all seven role fences live'
    }

    [ordered]@{
        component = 'eliot_trusted_cli_launch_tests'
        status = 'VERIFIED'
        typed_materialize_only = $true
        standalone_production_verifier_failure_contour = $true
        no_raw_arguments_or_role_override = $true
        no_dot_source_verifier_or_hook_injection = $true
        exact_seven_signed_roles_retained = $true
        exact_six_phase_a_paths_derived = $true
        create_suspended_identity_bound = $true
        generated_then_materialized_receipt_required = $true
        output_store_bundle_create_new_readback = $true
        nine_role_receipt_identity_hash_bound = $true
        mixed_bundle_rejected = $true
        help_false_zero_rejected = $true
        missing_receipt_rejected = $true
        substituted_receipt_rejected = $true
        verifier_launch_substitution_blocked = $true
        failed_suspended_child_reaped = $true
        no_live_signing_or_installation = $true
    } | ConvertTo-Json -Depth 4
}
finally {
    $global:EliotTrustedCliTestBeforeResume = $null
    $global:EliotTrustedCliTestAfterProcess = $null
    $global:EliotTrustedCliTestProcessArguments = $null
    $global:EliotTrustedCliTestDerivedArguments = $null
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
