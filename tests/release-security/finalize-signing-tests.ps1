[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repo 'scripts/finalize-eliot-windows-x64-release.ps1')

function Assert-Throws([scriptblock]$Action, [string]$Pattern, [string]$Message) {
    $thrown = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $thrown = $true
        if ([string]$_.Exception.Message -notmatch $Pattern) {
            throw "$Message (unexpected error: $($_.Exception.Message))"
        }
    }
    if (-not $thrown) {
        throw $Message
    }
}

function New-FakeSignature([string]$Status, [string]$SignerThumbprint, [string]$SignerSubject, [bool]$WithTimestamp) {
    $timestamp = if ($WithTimestamp) {
        [pscustomobject]@{
            Thumbprint = ('b' * 40)
            Subject = 'CN=Fixture RFC3161 TSA'
        }
    }
    else {
        $null
    }
    [pscustomobject]@{
        Status = $Status
        SignerCertificate = if ($Status -eq 'Valid') {
            [pscustomobject]@{
                Thumbprint = $SignerThumbprint
                Subject = $SignerSubject
            }
        }
        else { $null }
        TimeStamperCertificate = $timestamp
    }
}

function New-FakeUnsignedPe([string]$Path, [byte]$Marker) {
    $bytes = [byte[]]::new(512)
    $bytes[0] = 0x4d
    $bytes[1] = 0x5a
    [System.Array]::Copy([System.BitConverter]::GetBytes([int32]0x80), 0, $bytes, 0x3c, 4)
    $bytes[0x80] = 0x50
    $bytes[0x81] = 0x45
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]0x8664), 0, $bytes, 0x84, 2)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]0x00f0), 0, $bytes, 0x94, 2)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]0x020b), 0, $bytes, 0x98, 2)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]16), 0, $bytes, 0x104, 4)
    $bytes[0x1f0] = $Marker
    [System.IO.File]::WriteAllBytes($Path, $bytes)
}

function Set-FakeAuthenticodeCertificateTable([string]$Path, [byte]$Marker) {
    $unsigned = [System.IO.File]::ReadAllBytes($Path)
    $certificateOffset = $unsigned.Length
    $signed = [byte[]]::new($unsigned.Length + 16)
    [System.Array]::Copy($unsigned, 0, $signed, 0, $unsigned.Length)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]$certificateOffset), 0, $signed, 0x128, 4)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]16), 0, $signed, 0x12c, 4)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint32]16), 0, $signed, $certificateOffset, 4)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]0x0200), 0, $signed, $certificateOffset + 4, 2)
    [System.Array]::Copy([System.BitConverter]::GetBytes([uint16]0x0002), 0, $signed, $certificateOffset + 6, 2)
    for ($index = 8; $index -lt 16; $index++) { $signed[$certificateOffset + $index] = $Marker }
    [System.IO.File]::WriteAllBytes($Path, $signed)
}

function New-FakeRfc3161Evidence {
    [pscustomobject]@{
        protocol = 'RFC3161'
        attribute_oid = '1.3.6.1.4.1.311.3.3.1'
        tst_info_content_type_oid = '1.2.840.113549.1.9.16.1.4'
        message_imprint_algorithm = 'sha256'
        message_imprint_algorithm_oid = '2.16.840.1.101.3.4.2.1'
        message_imprint = ('d' * 64)
        signer_signature_sha256 = ('d' * 64)
        generalized_time = '20260822010101Z'
        timestamp_certificate_thumbprint = ('b' * 40)
        timestamp_certificate_subject = 'CN=Fixture RFC3161 TSA'
        cms_signature_valid = $true
    }
}

$tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$root = Join-Path $tempBase "eliot-finalize-signing-$([guid]::NewGuid().ToString('N'))"
$source = Join-Path $root 'unsigned'
$tool = Join-Path $root 'signtool.exe'
$thumbprint = ('a' * 40)
$signerSubject = 'CN=Fixture Eliot Code Signing'
$codeSigningUsages = [System.Security.Cryptography.OidCollection]::new()
[void]$codeSigningUsages.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3'))
$codeSigningExtension = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
    $codeSigningUsages,
    $false)
$fakeCertificate = [pscustomobject]@{
    Thumbprint = $thumbprint
    Subject = $signerSubject
    HasPrivateKey = $true
    Extensions = @($codeSigningExtension)
}

try {
    New-Item -ItemType Directory -Path (Join-Path $source 'runtime') -Force | Out-Null
    Set-Content -LiteralPath $tool -Value 'fake tool; never executed' -Encoding ascii
    $roles = @(Get-AuthenticodeRoleDefinitions)
    $roleMarker = 1
    foreach ($role in $roles) {
        New-FakeUnsignedPe (Join-Path $source $role.path) ([byte]$roleMarker)
        $roleMarker++
    }
    New-FakeUnsignedPe (Join-Path $source 'runtime/eliot.exe') ([byte]99)
    Set-Content -LiteralPath (Join-Path $source 'SIGNING_REQUIRED.txt') -Value 'unsigned fixture' -Encoding utf8
    Set-Content -LiteralPath (Join-Path $source 'NOTICE.txt') -Value 'immutable non-role fixture' -Encoding utf8
    $runtimeArtifacts = foreach ($role in $roles) {
        $artifactPath = Join-Path $source $role.path
        [ordered]@{
            package = "fixture-$($role.role)"
            binary = ([System.IO.Path]::GetFileNameWithoutExtension([string]$role.path).Replace('-', '_'))
            role = [string]$role.role
            path = [string]$role.path
            source = 'fixture'
            version = '0.1.0'
            architecture = 'windows-x64'
            sha256 = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = [int64](Get-Item -LiteralPath $artifactPath).Length
        }
    }
    $cliPath = Join-Path $source 'runtime/eliot.exe'
    $runtimeArtifacts = @([ordered]@{
            package = 'eliot'
            binary = 'eliot'
            role = 'cli'
            path = 'runtime/eliot.exe'
            source = 'fixture'
            version = '0.1.0'
            architecture = 'windows-x64'
            sha256 = (Get-FileHash -LiteralPath $cliPath -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = [int64](Get-Item -LiteralPath $cliPath).Length
        }) + @($runtimeArtifacts)
    $releaseArtifacts = foreach ($artifact in $runtimeArtifacts) {
        [ordered]@{
            package = $artifact.package
            binary = $artifact.binary
            role = $artifact.role
            path = $artifact.path
            source = $artifact.source
            version = $artifact.version
            architecture = $artifact.architecture
            sha256 = $artifact.sha256
            bytes = $artifact.bytes
        }
    }
    Set-Content -LiteralPath (Join-Path $source 'runtime/RUNTIME_ARTIFACTS.json') -Value (
        [ordered]@{
            schema = 'eliot-runtime-artifact-set-v1'
            component = 'fixture'
            version = '0.1.0'
            source_commit = ('1' * 40)
            architecture = 'windows-x64'
            signed = $false
            signature_evidence = 'not-issued'
            installation_approval = 'not-issued'
            artifacts = @($runtimeArtifacts)
        } | ConvertTo-Json -Depth 10) -Encoding utf8
    Set-Content -LiteralPath (Join-Path $source 'RELEASE.json') -Value (
        [ordered]@{
            component = 'fixture'
            version = '0.1.0'
            source_commit = ('1' * 40)
            architecture = 'windows-x64'
            signed = $false
            signature_policy = 'pre-release-unsigned'
            signature_evidence = 'not-issued'
            public_distribution_ready = $false
            codex_plugin_base_version = '0.1.0'
            runtime_artifact_count = $releaseArtifacts.Count
            runtime_artifacts = @($releaseArtifacts)
        } | ConvertTo-Json -Depth 10) -Encoding utf8
    $sourceHashes = Get-ReleaseFileInventory $source -ExcludeChecksumManifest
    Set-Content -LiteralPath (Join-Path $source 'SHA256SUMS.json') -Value (
        [ordered]@{
            component = 'fixture'
            version = '0.1.0'
            source_commit = ('1' * 40)
            architecture = 'windows-x64'
            signed = $false
            files = @($sourceHashes)
        } | ConvertTo-Json -Depth 10) -Encoding utf8

    $plan = New-AuthenticodeSigningPlan `
        $source `
        (Join-Path $root 'signed-success') `
        $tool `
        'Cert:\CurrentUser\My' `
        $thumbprint `
        'http://timestamp.example.test/rfc3161'
    if ([string]$plan.schema -ne 'eliot-authenticode-signing-plan-v1' -or
        @($plan.roles).Count -ne 6 -or
        [string]$plan.file_digest_algorithm -cne 'sha256' -or
        [string]$plan.timestamp_digest_algorithm -cne 'sha256') {
        throw 'pure signing plan does not bind the exact six roles and SHA-256 algorithms'
    }
    $finalizerSource = [System.IO.File]::ReadAllText((Join-Path $repo 'scripts/finalize-eliot-windows-x64-release.ps1'))
    foreach ($requiredNativeContract in @(
            'NtCreateFile(',
            'FILE_ADD_SUBDIRECTORY',
            'FILE_CREATE',
            'FILE_DIRECTORY_FILE',
            'SetFileInformationByHandle(',
            'NtSetInformationFile(',
            'FILE_RENAME_INFORMATION_CLASS = 10',
            'Encoding.Unicode.GetBytes(destinationLeaf)',
            'destinationParent.DangerousGetHandle()',
            'FILE_DISPOSITION_INFO_EX_CLASS = 21',
            'Marshal.WriteByte(buffer, 0, 0)',
            'DeleteFileByHandle(',
            'OpenFileReadFence(',
            'identity.NumberOfLinks != 1',
            'FlushDirectoryHandle')) {
        if ($finalizerSource.IndexOf($requiredNativeContract, [System.StringComparison]::Ordinal) -lt 0) {
            throw "native create/publish source contract is missing: $requiredNativeContract"
        }
    }
    foreach ($forbiddenNativeContract in @(
            'CreateDirectoryW',
            'MoveFileExW',
            'FILE_RENAME_INFO_CLASS = 3',
            'FILE_RENAME_INFO_EX_CLASS',
            'Encoding.Unicode.GetBytes(destinationPath)')) {
        if ($finalizerSource.IndexOf($forbiddenNativeContract, [System.StringComparison]::Ordinal) -ge 0) {
            throw "obsolete create/open or pathname publication primitive returned: $forbiddenNativeContract"
        }
    }
    if ($finalizerSource -match 'Remove-Item[^\r\n]*-Recurse') {
        throw 'production finalizer reintroduced recursive pathname cleanup'
    }
    if ($finalizerSource -match 'Remove-Item[^\r\n]*\$marker') {
        throw 'production finalizer reintroduced pathname marker deletion'
    }
    $signToolArgs = @(Get-SignToolArguments $plan (Join-Path $source 'runtime/eliot-host.exe'))
    foreach ($requiredArgument in @('/fd', 'sha256', '/td', '/tr', '/sha1', '/s', '/u', $thumbprint)) {
        if (-not ($signToolArgs -contains $requiredArgument)) {
            throw "SignTool argument contract is missing $requiredArgument"
        }
    }
    if (-not ($signToolArgs -contains 'http://timestamp.example.test/rfc3161') -or
        -not ($signToolArgs -contains 'My') -or
        -not ($signToolArgs -contains '1.3.6.1.5.5.7.3.3')) {
        throw 'SignTool argument contract lost the explicit timestamp/store/EKU binding'
    }
    $roleArgumentPath = Join-Path $source 'runtime/eliot-host.exe'
    $expectedSignToolArgs = @(
        'sign', '/fd', 'sha256', '/tr', 'http://timestamp.example.test/rfc3161', '/td', 'sha256',
        '/sha1', $thumbprint, '/s', 'My', '/u', '1.3.6.1.5.5.7.3.3', $roleArgumentPath)
    if ($signToolArgs.Count -ne $expectedSignToolArgs.Count) { throw 'SignTool signing argv count is not exact' }
    for ($index = 0; $index -lt $expectedSignToolArgs.Count; $index++) {
        if ([string]$signToolArgs[$index] -cne [string]$expectedSignToolArgs[$index]) {
            throw "SignTool signing argv order differs at index $index"
        }
    }
    $expectedVerifyArgs = @('verify', '/pa', '/all', '/v', '/tw', $roleArgumentPath)
    $verifyArgs = @(Get-SignToolVerifyArguments $roleArgumentPath)
    for ($index = 0; $index -lt $expectedVerifyArgs.Count; $index++) {
        if ([string]$verifyArgs[$index] -cne [string]$expectedVerifyArgs[$index]) {
            throw "SignTool verify argv order differs at index $index"
        }
    }

    $tstPrefix = @(
        0x30, 0x4f,
        0x02, 0x01, 0x01,
        0x06, 0x03, 0x2a, 0x03, 0x04,
        0x30, 0x31,
        0x30, 0x0d,
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00,
        0x04, 0x20)
    $tstSuffix = @(0x02, 0x01, 0x01, 0x18, 0x0f) + @([System.Text.Encoding]::ASCII.GetBytes('20260822010101Z'))
    $tstBytes = [byte[]]($tstPrefix + @((1..32 | ForEach-Object { 0xdd })) + $tstSuffix)
    $tstEvidence = Read-Rfc3161TstInfo $tstBytes
    if ([string]$tstEvidence.message_imprint_algorithm_oid -cne '2.16.840.1.101.3.4.2.1' -or
        [string]$tstEvidence.message_imprint -cne ('dd' * 32) -or
        [string]$tstEvidence.generalized_time -cne '20260822010101Z') {
        throw 'pure RFC3161 TSTInfo parser did not bind SHA-256 messageImprint/genTime'
    }

    # Pure certificate checks: the certificate is a value object containing a
    # real X509EnhancedKeyUsageExtension; no certificate is generated or stored.
    Assert-CodeSigningCertificate $fakeCertificate 'Cert:\CurrentUser\My' $thumbprint | Out-Null
    $wrongKey = $fakeCertificate.PSObject.Copy()
    $wrongKey.HasPrivateKey = $false
    Assert-CodeSigningCertificateIdentity $wrongKey 'Cert:\CurrentUser\My' $thumbprint | Out-Null
    Assert-Throws { Assert-CodeSigningCertificate $wrongKey 'Cert:\CurrentUser\My' $thumbprint } 'private key' 'missing private key was accepted'
    $wrongEku = $fakeCertificate.PSObject.Copy()
    $wrongUsages = [System.Security.Cryptography.OidCollection]::new()
    [void]$wrongUsages.Add([System.Security.Cryptography.Oid]::new('1.2.3.4'))
    $wrongEku.Extensions = @(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($wrongUsages, $false))
    Assert-Throws { Assert-CodeSigningCertificate $wrongEku 'Cert:\CurrentUser\My' $thumbprint } 'Code Signing EKU' 'wrong EKU was accepted'
    $fakeOidExtension = $fakeCertificate.PSObject.Copy()
    $fakeOidExtension.Extensions = @([pscustomobject]@{
            Oid = [pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.3' }
            EnhancedKeyUsages = @()
        })
    Assert-Throws { Assert-CodeSigningCertificate $fakeOidExtension 'Cert:\CurrentUser\My' $thumbprint } 'Code Signing EKU' 'fake extension OID was accepted as an EKU'
    $fakeEnhancedKeyUsageExtension = $fakeCertificate.PSObject.Copy()
    $fakeEnhancedKeyUsageExtension.Extensions = @([pscustomobject]@{
            Oid = [pscustomobject]@{ Value = '2.5.29.37' }
            EnhancedKeyUsages = @([pscustomobject]@{ Value = '1.3.6.1.5.5.7.3.3' })
        })
    Assert-Throws {
        Assert-CodeSigningCertificate $fakeEnhancedKeyUsageExtension 'Cert:\CurrentUser\My' $thumbprint
    } 'Code Signing EKU' 'fake EnhancedKeyUsages value object was accepted as a real X509 EKU extension'

    $state = [pscustomobject]@{
        signedRoleNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        events = [System.Collections.Generic.List[string]]::new()
        signCount = 0
        badTimestamp = $false
        missingRfc3161Token = $false
        verifyWarning = $false
        mutateSource = $false
        mutateNonRole = $false
        mutateNonRoleDirectory = $false
        substituteSigner = $false
        failAt = 0
    }
    $inputValidator = {
        param($path)
        [void]$state.events.Add("input-validated:$([System.IO.Path]::GetFileName($path))")
        $manifest = Get-Content -LiteralPath (Join-Path $path 'RELEASE.json') -Raw | ConvertFrom-Json
        if ($manifest.signed -ne $false) { throw 'fixture source unexpectedly signed' }
    }
    $certificateResolver = {
        param($storeLocation, $requestedThumbprint)
        [void]$state.events.Add('certificate-resolved')
        $fakeCertificate
    }
    $signToolInvoker = {
        param($path, $arguments, $file)
        $state.signCount++
        [void]$state.events.Add("sign:$([System.IO.Path]::GetFileName($file))")
        foreach ($requiredArgument in @('/fd', 'sha256', '/td', '/tr', '/sha1', '/s', '/u')) {
            if (-not (@($arguments) -contains $requiredArgument)) { throw "fake SignTool omitted $requiredArgument" }
        }
        if ($state.failAt -gt 0 -and $state.signCount -eq $state.failAt) {
            throw 'fake SignTool partial failure'
        }
        Set-FakeAuthenticodeCertificateTable $file ([byte]$state.signCount)
        [void]$state.signedRoleNames.Add([System.IO.Path]::GetFileName($file))
        if ($state.signCount -eq 1 -and $state.mutateSource) {
            Add-Content -LiteralPath (Join-Path $source 'NOTICE.txt') -Value 'source mutation'
        }
        if ($state.signCount -eq 1 -and $state.mutateNonRole) {
            $stageRoot = Split-Path -Parent (Split-Path -Parent $file)
            Add-Content -LiteralPath (Join-Path $stageRoot 'runtime/eliot.exe') -Value 'non-role mutation'
        }
        if ($state.signCount -eq 1 -and $state.mutateNonRoleDirectory) {
            $stageRoot = Split-Path -Parent (Split-Path -Parent $file)
            New-Item -ItemType Directory -Path (Join-Path $stageRoot 'unexpected-empty-directory') | Out-Null
        }
    }
    $signToolVerifier = {
        param($path, $arguments, $file)
        $expected = @(Get-SignToolVerifyArguments $file)
        if (@($arguments).Count -ne $expected.Count) { throw 'fake SignTool verify argv count differs' }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if ([string]$arguments[$index] -cne [string]$expected[$index]) { throw "fake SignTool verify argv differs at $index" }
        }
        if ($state.verifyWarning) { throw 'signtool verify failed or warned with exit code 2' }
        [pscustomobject]@{ exit_code = 0; arguments = @($arguments) }
    }
    $signatureReader = {
        param($path)
        $full = [System.IO.Path]::GetFullPath($path)
        if ($full.StartsWith([System.IO.Path]::GetFullPath($source), [System.StringComparison]::OrdinalIgnoreCase)) {
            [void]$state.events.Add("read-unsigned:$([System.IO.Path]::GetFileName($path))")
            return New-FakeSignature 'NotSigned' $thumbprint $signerSubject $false
        }
        if (-not $state.signedRoleNames.Contains([System.IO.Path]::GetFileName($full))) {
            return New-FakeSignature 'NotSigned' $thumbprint $signerSubject $false
        }
        [void]$state.events.Add("read-signed:$([System.IO.Path]::GetFileName($path))")
        $actualThumbprint = if ($state.substituteSigner) { ('c' * 40) } else { $thumbprint }
        $actualSubject = if ($state.substituteSigner) { 'CN=Wrong Signer' } else { $signerSubject }
        New-FakeSignature 'Valid' $actualThumbprint $actualSubject (-not $state.badTimestamp)
    }
    $timestampTokenReader = {
        param($path)
        if ($state.missingRfc3161Token) { return $null }
        New-FakeRfc3161Evidence
    }
    $outputValidator = {
        param($path, $reader, $baseline, $expectedPlan, $expectedCertificate, $verifier, $tokenReader)
        [void]$state.events.Add('output-validated')
        Test-FinalizedReleaseBundle $path $reader $baseline $expectedPlan $expectedCertificate $verifier $tokenReader | Out-Null
    }

    $success = Invoke-ReleaseBundleFinalization -Plan $plan -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier `
        -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader -CertificateResolver $certificateResolver `
        -InputValidator $inputValidator -OutputValidator $outputValidator
    if ([string]$success.status -cne 'COMMITTED_UNKNOWN' -or
        [string]$success.reason -cne 'MUTABLE_DIRECTORY_REQUIRES_CONSUMER_RECONCILIATION' -or
        [string]$success.immediate_readback -cne 'VERIFIED_SIGNED_SNAPSHOT' -or
        $success.durable_install_authority -ne $false -or
        [string]$success.next_authoritative_handoff -cne 'eliot installation materialize-source-bundle' -or
        -not (Test-Path -LiteralPath $plan.signed_bundle -PathType Container) -or
        $state.signCount -ne 6) {
        throw 'normal finalization did not commit exactly six signed roles as typed mutable-directory uncertainty'
    }
    $sourceRelease = Get-Content -LiteralPath (Join-Path $source 'RELEASE.json') -Raw | ConvertFrom-Json
    if ($sourceRelease.signed -ne $false -or -not (Test-Path -LiteralPath (Join-Path $source 'SIGNING_REQUIRED.txt'))) {
        throw 'failed finalization mutated or adopted the unsigned source bundle'
    }
    $firstSign = @($state.events | Where-Object { $_ -like 'sign:*' })[0]
    $lastRead = @($state.events | Where-Object { $_ -like 'read-signed:*' })[-1]
    $stagingValidation = @($state.events | Where-Object { $_ -like 'input-validated:*.partial' })[0]
    if (-not $firstSign -or -not $lastRead -or $state.events.IndexOf($firstSign) -lt 0 -or
        -not $stagingValidation -or $state.events.IndexOf($stagingValidation) -gt $state.events.IndexOf($firstSign) -or
        $state.events.IndexOf('output-validated') -lt $state.events.IndexOf($lastRead)) {
        throw 'signing/readback/final-validation ordering was not observed'
    }
    $snapshotVerification = Test-FinalizedReleaseBundle $plan.signed_bundle $signatureReader `
        (New-ReleaseFinalizationBaseline $source) $plan $wrongKey $signToolVerifier $timestampTokenReader
    if ([string]$snapshotVerification.status -cne 'VERIFIED_SIGNED' -or
        [string]$snapshotVerification.verification_kind -cne 'READ_ONLY_SNAPSHOT' -or
        $snapshotVerification.durable_install_authority -ne $false -or
        $wrongKey.HasPrivateKey -ne $false) {
        throw 'VerifyBundle snapshot did not accept the exact public certificate without claiming install authority'
    }
    $mutatedRolePath = Join-Path $plan.signed_bundle 'runtime/eliot-host.exe'
    $mutatedRoleBytes = [System.IO.File]::ReadAllBytes($mutatedRolePath)
    try {
        $changedRoleBytes = [byte[]]$mutatedRoleBytes.Clone()
        $changedRoleBytes[0x1f0] = $changedRoleBytes[0x1f0] -bxor 0x01
        [System.IO.File]::WriteAllBytes($mutatedRolePath, $changedRoleBytes)
        Assert-Throws {
            Test-FinalizedReleaseBundle $plan.signed_bundle $signatureReader `
                (New-ReleaseFinalizationBaseline $source) $plan $wrongKey $signToolVerifier $timestampTokenReader | Out-Null
        } 'SHA256SUMS|PE image|hash/size|differs' 'a mutated materializer-facing Authenticode role passed VerifyBundle'
    }
    finally {
        [System.IO.File]::WriteAllBytes($mutatedRolePath, $mutatedRoleBytes)
    }
    Test-FinalizedReleaseBundle $plan.signed_bundle $signatureReader `
        (New-ReleaseFinalizationBaseline $source) $plan $wrongKey $signToolVerifier $timestampTokenReader | Out-Null
    if ((Get-FinalizationProcessExitCode $success) -ne 75) {
        throw 'normal committed finalization did not map to reconciliation exit 75'
    }
    Assert-Throws {
        Get-FinalizationProcessExitCode ([pscustomobject]@{ status = 'SIGNED_PUBLISHED' }) | Out-Null
    } 'unexpected status' 'SIGNED_PUBLISHED unexpectedly mapped to process success'
    Assert-Throws {
        Get-FinalizationProcessExitCode ([pscustomobject]@{ status = 'UNKNOWN_SUCCESS' }) | Out-Null
    } 'unexpected status' 'an unknown finalization status mapped to process success'

    function New-CasePlan([string]$Name) {
        New-AuthenticodeSigningPlan $source (Join-Path $root $Name) $tool 'Cert:\CurrentUser\My' $thumbprint 'http://timestamp.example.test/rfc3161'
    }
    function Invoke-Case(
        [string]$Name,
        [scriptblock]$Resolver = $certificateResolver,
        [bool]$ExpectQuarantinedPartial = $true
    ) {
        $casePlan = New-CasePlan $Name
        $partialBefore = @(Get-ChildItem -LiteralPath $root -Filter '*.partial' -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
        Assert-Throws {
            Invoke-ReleaseBundleFinalization -Plan $casePlan -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier `
                -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader -CertificateResolver $Resolver `
                -InputValidator $inputValidator -OutputValidator $outputValidator
        } 'failed|missing|mismatch|not|substitution|timestamp|partial|private key|EKU|changed|differs|warned|RFC3161' "negative case did not fail: $Name"
        if (Test-Path -LiteralPath $casePlan.signed_bundle) {
            throw "negative case published a finalized bundle: $Name"
        }
        $partialAfter = @(Get-ChildItem -LiteralPath $root -Filter '*.partial' -Force -ErrorAction SilentlyContinue | ForEach-Object FullName)
        $newPartials = @($partialAfter | Where-Object { $partialBefore -notcontains $_ })
        if ($ExpectQuarantinedPartial -and $newPartials.Count -ne 1) {
            throw "negative case did not retain exactly one quarantined partial: $Name"
        }
        if (-not $ExpectQuarantinedPartial -and $newPartials.Count -ne 0) {
            throw "negative case staged before its pre-staging policy failure: $Name"
        }
        $state.signCount = 0
        [void]$state.signedRoleNames.Clear()
        $state.badTimestamp = $false
        $state.missingRfc3161Token = $false
        $state.verifyWarning = $false
        $state.mutateSource = $false
        $state.mutateNonRole = $false
        $state.mutateNonRoleDirectory = $false
        $state.substituteSigner = $false
        $state.failAt = 0
    }

    # Missing certificate, wrong certificate properties, missing timestamp,
    # signer substitution, and partial signing all fail before publication.
    $missingCertificate = { param($storeLocation, $requestedThumbprint) throw 'certificate missing' }
    Invoke-Case 'signed-missing-cert' $missingCertificate $false
    $wrongCertificate = { param($storeLocation, $requestedThumbprint) $wrongKey }
    Invoke-Case 'signed-wrong-cert' $wrongCertificate $false
    $state.badTimestamp = $true
    Invoke-Case 'signed-missing-timestamp'
    $state.badTimestamp = $false
    $state.substituteSigner = $true
    Invoke-Case 'signed-substituted-signer'
    $state.substituteSigner = $false
    $state.failAt = 3
    Invoke-Case 'signed-partial-tool-failure'
    $state.missingRfc3161Token = $true
    Invoke-Case 'signed-legacy-or-no-rfc3161-token'
    $state.verifyWarning = $true
    Invoke-Case 'signed-signtool-timestamp-warning'
    $state.mutateNonRole = $true
    Invoke-Case 'signed-non-role-mutation'
    $state.mutateNonRoleDirectory = $true
    Invoke-Case 'signed-non-role-directory-mutation'
    $noticeBytes = [System.IO.File]::ReadAllBytes((Join-Path $source 'NOTICE.txt'))
    $state.mutateSource = $true
    Invoke-Case 'signed-source-mutation'
    [System.IO.File]::WriteAllBytes((Join-Path $source 'NOTICE.txt'), $noticeBytes)

    foreach ($invalidPath in @('C:relative\bundle', '\root-relative\bundle', 'relative\bundle')) {
        Assert-Throws { Get-FullyQualifiedWindowsPath $invalidPath 'fixture path' } 'fully-qualified|drive-relative|root-relative' "unsafe path was accepted: $invalidPath"
    }

    # The atomic directory create must return the ownership fence in the same
    # native operation. A would-be create-then-open substitution cannot move the
    # new object while that no-delete-sharing fence is retained.
    $atomicSwap = [pscustomobject]@{ blocked = $false; displaced = $null }
    $atomicParentPin = $null
    $atomicOwnership = $null
    try {
        $atomicParentPin = New-NativeDirectoryPin $root $false $true
        $atomicHook = {
            param($path, $fence)
            $atomicSwap.displaced = "$path.displaced"
            try {
                [System.IO.Directory]::Move($path, $atomicSwap.displaced)
            }
            catch {
                $atomicSwap.blocked = $true
            }
        }
        $atomicOwnership = New-OwnedStagingDirectory `
            -Parent $root `
            -Leaf 'atomic-create-open-substitution' `
            -ParentPin $atomicParentPin `
            -AfterAtomicCreateHook $atomicHook
        if (-not $atomicSwap.blocked -or -not (Test-OwnedStagingIdentity $atomicOwnership)) {
            throw 'atomic create-new ownership fence allowed create-to-open substitution'
        }
        Remove-OwnedStagingDirectory $atomicOwnership
    }
    finally {
        Close-OwnedStagingFences $atomicOwnership
        Close-NativeDirectoryPin $atomicParentPin
    }
    if (-not (Test-Path -LiteralPath $atomicOwnership.path -PathType Container) -or
        ($atomicSwap.displaced -and (Test-Path -LiteralPath $atomicSwap.displaced))) {
        throw 'atomic staging collision cleanup deleted or displaced the owned partial'
    }

    # If every fence is deliberately lost and a foreign tree is substituted at
    # the old staging pathname, failure cleanup must quarantine both trees and
    # must never recurse through that pathname.
    $cleanupSwap = [pscustomobject]@{ original = $null; displaced = $null; sentinel = $null }
    $cleanupPlan = New-CasePlan 'signed-cleanup-substitution'
    $cleanupHook = {
        param($owned)
        $cleanupSwap.original = [string]$owned.path
        $cleanupSwap.displaced = "$($owned.path).owned-displaced"
        Close-OwnedStagingFences $owned
        [System.IO.Directory]::Move($owned.path, $cleanupSwap.displaced)
        [System.IO.Directory]::CreateDirectory($owned.path) | Out-Null
        $cleanupSwap.sentinel = Join-Path $owned.path 'foreign-sentinel.txt'
        Set-Content -LiteralPath $cleanupSwap.sentinel -Value 'foreign owner' -Encoding ascii
    }
    Assert-Throws {
        Invoke-ReleaseBundleFinalization -Plan $cleanupPlan -SignToolInvoker $signToolInvoker `
            -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader `
            -CertificateResolver $certificateResolver -InputValidator $inputValidator -OutputValidator $outputValidator `
            -AfterStagingCreateHook $cleanupHook
    } 'unavailable|changed|identity' 'cleanup substitution was adopted or reported as success'
    if (-not (Test-Path -LiteralPath $cleanupSwap.displaced -PathType Container) -or
        -not (Test-Path -LiteralPath $cleanupSwap.sentinel -PathType Leaf)) {
        throw 'cleanup substitution deleted an owned or foreign directory'
    }

    $staleBundle = Join-Path $root 'stale-internal-hashes'
    Copy-Item -LiteralPath $source -Destination $staleBundle -Recurse
    $staleRuntimePath = Join-Path $staleBundle 'runtime/RUNTIME_ARTIFACTS.json'
    $staleRuntime = Get-Content -LiteralPath $staleRuntimePath -Raw | ConvertFrom-Json
    $staleRuntime.artifacts[0].sha256 = ('f' * 64)
    $staleRuntime | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $staleRuntimePath -Encoding utf8
    Assert-Throws { Assert-RuntimeArtifactBindings $staleBundle } 'stale|hash/size' 'stale internal artifact hash was accepted'

    $foreignStage = Join-Path $root '.concurrent.authenticode-fixed.partial'
    New-Item -ItemType Directory -Path $foreignStage | Out-Null
    Set-Content -LiteralPath (Join-Path $foreignStage 'sentinel.txt') -Value 'foreign owner' -Encoding ascii
    $fixedStagingPath = { param($parent, $leaf, $token) $foreignStage }
    Assert-Throws {
        New-OwnedStagingDirectory $root 'concurrent' $fixedStagingPath | Out-Null
    } 'create-new|already exists|exists' 'concurrently created staging directory was adopted'
    if (-not (Test-Path -LiteralPath (Join-Path $foreignStage 'sentinel.txt') -PathType Leaf)) {
        throw 'concurrent staging collision deleted the foreign owner sentinel'
    }

    $existing = Join-Path $root 'signed-no-replace'
    New-Item -ItemType Directory -Path $existing -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $existing 'sentinel.txt') -Value 'keep' -Encoding ascii
    Assert-Throws {
        New-AuthenticodeSigningPlan $source $existing $tool 'Cert:\CurrentUser\My' $thumbprint 'http://timestamp.example.test/rfc3161' | Out-Null
    } 'already exists|overwrite|adoption' 'preexisting output was adopted or overwritten'
    if ((Get-Content -LiteralPath (Join-Path $existing 'sentinel.txt') -Raw) -cne "keep`r`n" -and
        (Get-Content -LiteralPath (Join-Path $existing 'sentinel.txt') -Raw) -cne "keep`n") {
        throw 'preexisting output sentinel changed'
    }

    # Exercise the production NtSetInformationFile(FileRenameInformation=10)
    # seam directly. The retained parent handle and relative destination leaf
    # must preserve both the owned source and a colliding foreign destination.
    $nativeCollisionTarget = Join-Path $root 'native-relative-publish-collision'
    New-Item -ItemType Directory -Path $nativeCollisionTarget | Out-Null
    $nativeCollisionSentinel = Join-Path $nativeCollisionTarget 'foreign-sentinel.txt'
    Set-Content -LiteralPath $nativeCollisionSentinel -Value 'foreign destination' -Encoding ascii
    $nativeCollisionParentPin = $null
    $nativeCollisionOwnership = $null
    try {
        $nativeCollisionParentPin = New-NativeDirectoryPin $root $false $true
        $nativeCollisionOwnership = New-OwnedStagingDirectory `
            -Parent $root `
            -Leaf 'native-relative-publish-source' `
            -ParentPin $nativeCollisionParentPin
        Assert-Throws {
            [EliotReleaseNativeFileSystem]::PublishDirectoryHandleCreateNew(
                $nativeCollisionOwnership.root_fence.handle,
                $nativeCollisionParentPin.handle,
                'native-relative-publish-collision')
        } 'handle-relative create-new directory publication failed|already exists' 'direct NT relative-leaf publish replaced a colliding destination'
        if (-not (Test-OwnedStagingIdentity $nativeCollisionOwnership) -or
            -not (Test-Path -LiteralPath $nativeCollisionOwnership.path -PathType Container) -or
            -not (Test-Path -LiteralPath (Join-Path $nativeCollisionOwnership.path $script:StagingOwnerMarker) -PathType Leaf) -or
            -not (Test-Path -LiteralPath $nativeCollisionSentinel -PathType Leaf) -or
            -not ((Get-Content -LiteralPath $nativeCollisionSentinel -Raw) -match '^foreign destination')) {
            throw 'direct NT relative-leaf publish collision did not preserve both directory identities'
        }
    }
    finally {
        Close-OwnedStagingFences $nativeCollisionOwnership
        Close-NativeDirectoryPin $nativeCollisionParentPin
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $concurrentOutputPlan = New-CasePlan 'signed-concurrent-output'
    $concurrentOutputValidator = {
        param($path, $reader, $baseline, $expectedPlan, $expectedCertificate, $verifier, $tokenReader)
        Test-FinalizedReleaseBundle $path $reader $baseline $expectedPlan $expectedCertificate $verifier $tokenReader | Out-Null
        if ([string]::Compare($path, [string]$expectedPlan.signed_bundle, $true) -ne 0 -and
            -not (Test-Path -LiteralPath $expectedPlan.signed_bundle)) {
            New-Item -ItemType Directory -Path $expectedPlan.signed_bundle | Out-Null
            Set-Content -LiteralPath (Join-Path $expectedPlan.signed_bundle 'sentinel.txt') -Value 'concurrent owner' -Encoding ascii
        }
    }
    Assert-Throws {
        Invoke-ReleaseBundleFinalization -Plan $concurrentOutputPlan -SignToolInvoker $signToolInvoker `
            -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader `
            -CertificateResolver $certificateResolver -InputValidator $inputValidator -OutputValidator $concurrentOutputValidator
    } 'handle-relative create-new directory publication failed|already exists' 'concurrently created output was adopted or replaced'
    if (-not (Test-Path -LiteralPath (Join-Path $concurrentOutputPlan.signed_bundle 'sentinel.txt') -PathType Leaf)) {
        throw 'concurrently created output was deleted or overwritten'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $childSubstitutionPlan = New-CasePlan 'signed-child-contour-substitution'
    $afterChildReleaseSubstitution = {
        param($owned)
        $runtime = Join-Path $owned.path 'runtime'
        $displaced = Join-Path $owned.path 'runtime.owned-displaced'
        [System.IO.Directory]::Move($runtime, $displaced)
        [System.IO.Directory]::CreateDirectory($runtime) | Out-Null
        Set-Content -LiteralPath (Join-Path $runtime 'foreign.txt') -Value 'substituted child' -Encoding ascii
    }
    $childSubstitutionOutcome = Invoke-ReleaseBundleFinalization -Plan $childSubstitutionPlan `
        -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader `
        -TimestampTokenReader $timestampTokenReader -CertificateResolver $certificateResolver `
        -InputValidator $inputValidator -OutputValidator $outputValidator `
        -AfterChildFencesReleasedHook $afterChildReleaseSubstitution
    if ([string]$childSubstitutionOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        -not (Test-Path -LiteralPath (Join-Path $childSubstitutionPlan.signed_bundle 'runtime.owned-displaced') -PathType Container) -or
        -not (Test-Path -LiteralPath (Join-Path $childSubstitutionPlan.signed_bundle 'runtime/foreign.txt') -PathType Leaf)) {
        throw 'released child-contour substitution was deleted, adopted, or reported as success'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $releaseWindowMutationPlan = New-CasePlan 'signed-release-window-file-mutation'
    $afterContourReleaseMutation = {
        param($owned)
        Add-Content -LiteralPath (Join-Path $owned.path 'NOTICE.txt') -Value 'release-window mutation'
    }
    $releaseWindowMutationOutcome = Invoke-ReleaseBundleFinalization -Plan $releaseWindowMutationPlan `
        -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader `
        -TimestampTokenReader $timestampTokenReader -CertificateResolver $certificateResolver `
        -InputValidator $inputValidator -OutputValidator $outputValidator `
        -AfterChildFencesReleasedHook $afterContourReleaseMutation
    if ([string]$releaseWindowMutationOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        -not (Test-Path -LiteralPath $releaseWindowMutationPlan.signed_bundle -PathType Container) -or
        -not ((Get-Content -LiteralPath (Join-Path $releaseWindowMutationPlan.signed_bundle 'NOTICE.txt') -Raw) -match 'release-window mutation')) {
        throw 'file mutation after staging contour release was adopted or reported as success'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $postValidatorAdditionPlan = New-CasePlan 'signed-postvalidator-file-addition'
    $afterFinalValidatorAddition = {
        param($destination, $fileContour, $owned)
        Set-Content -LiteralPath (Join-Path $destination 'unexpected-after-validator.txt') `
            -Value 'unmanifested' -Encoding ascii
    }
    $postValidatorAdditionOutcome = Invoke-ReleaseBundleFinalization -Plan $postValidatorAdditionPlan `
        -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader `
        -TimestampTokenReader $timestampTokenReader -CertificateResolver $certificateResolver `
        -InputValidator $inputValidator -OutputValidator $outputValidator `
        -AfterFinalValidatorHook $afterFinalValidatorAddition
    if ([string]$postValidatorAdditionOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        -not (Test-Path -LiteralPath (Join-Path $postValidatorAdditionPlan.signed_bundle 'unexpected-after-validator.txt') -PathType Leaf)) {
        throw 'post-validator file addition bypassed the final exact inventory readback'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $postValidatorMutationPlan = New-CasePlan 'signed-postvalidator-file-mutation'
    $postValidatorMutation = [pscustomobject]@{
        write_blocked_while_fenced = $false
        rename_blocked_while_fenced = $false
        delete_blocked_while_fenced = $false
    }
    $afterFinalValidatorMutation = {
        param($destination, $fileContour, $owned)
        $notice = Join-Path $destination 'NOTICE.txt'
        try {
            Add-Content -LiteralPath $notice -Value 'must be blocked while fenced'
        }
        catch {
            $postValidatorMutation.write_blocked_while_fenced = $true
        }
        try {
            [System.IO.File]::Move($notice, "$notice.renamed")
        }
        catch {
            $postValidatorMutation.rename_blocked_while_fenced = $true
        }
        try {
            Remove-Item -LiteralPath $notice -Force
        }
        catch {
            $postValidatorMutation.delete_blocked_while_fenced = $true
        }
        Close-RetainedReleaseFileContour $fileContour
        Add-Content -LiteralPath $notice -Value 'postvalidator mutation'
    }
    $postValidatorMutationOutcome = Invoke-ReleaseBundleFinalization -Plan $postValidatorMutationPlan `
        -SignToolInvoker $signToolInvoker -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader `
        -TimestampTokenReader $timestampTokenReader -CertificateResolver $certificateResolver `
        -InputValidator $inputValidator -OutputValidator $outputValidator `
        -AfterFinalValidatorHook $afterFinalValidatorMutation
    if (-not $postValidatorMutation.write_blocked_while_fenced -or
        -not $postValidatorMutation.rename_blocked_while_fenced -or
        -not $postValidatorMutation.delete_blocked_while_fenced -or
        [string]$postValidatorMutationOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        -not ((Get-Content -LiteralPath (Join-Path $postValidatorMutationPlan.signed_bundle 'NOTICE.txt') -Raw) -match 'postvalidator mutation')) {
        throw 'post-validator file mutation bypassed the retained final file contour'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $postCommitPlan = New-CasePlan 'signed-postcommit-readback-unknown'
    $postCommitValidator = {
        param($path, $reader, $baseline, $expectedPlan, $expectedCertificate, $verifier, $tokenReader)
        Test-FinalizedReleaseBundle $path $reader $baseline $expectedPlan $expectedCertificate $verifier $tokenReader | Out-Null
        if ([string]::Compare($path, [string]$expectedPlan.signed_bundle, $true) -eq 0) {
            throw 'injected postcommit readback failure'
        }
    }
    $postCommitOutcome = Invoke-ReleaseBundleFinalization -Plan $postCommitPlan -SignToolInvoker $signToolInvoker `
        -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader `
        -CertificateResolver $certificateResolver -InputValidator $inputValidator -OutputValidator $postCommitValidator
    if ([string]$postCommitOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        (Get-FinalizationProcessExitCode $postCommitOutcome) -ne 75 -or
        -not (Test-Path -LiteralPath $postCommitPlan.signed_bundle -PathType Container)) {
        throw 'postcommit readback failure was not retained as COMMITTED_UNKNOWN'
    }

    $state.signCount = 0
    [void]$state.signedRoleNames.Clear()
    $substitutionPlan = New-CasePlan 'signed-postcommit-path-substitution'
    $afterMoveSubstitution = {
        param($destination, $owned)
        $displaced = "$destination.displaced"
        # Simulate catastrophic loss of the retained ownership fence. The
        # finalizer must return typed uncertainty and must not delete either
        # the displaced owned bundle or the substituted foreign directory.
        Close-OwnedStagingFences $owned
        [System.IO.Directory]::Move($destination, $displaced)
        [System.IO.Directory]::CreateDirectory($destination) | Out-Null
        Set-Content -LiteralPath (Join-Path $destination 'foreign.txt') -Value 'substituted' -Encoding ascii
    }
    $substitutionOutcome = Invoke-ReleaseBundleFinalization -Plan $substitutionPlan -SignToolInvoker $signToolInvoker `
        -SignToolVerifier $signToolVerifier -SignatureReader $signatureReader -TimestampTokenReader $timestampTokenReader `
        -CertificateResolver $certificateResolver -InputValidator $inputValidator -OutputValidator $outputValidator `
        -AfterMoveHook $afterMoveSubstitution
    if ([string]$substitutionOutcome.status -cne 'COMMITTED_UNKNOWN' -or
        -not (Test-Path -LiteralPath "$($substitutionPlan.signed_bundle).displaced" -PathType Container) -or
        -not (Test-Path -LiteralPath (Join-Path $substitutionPlan.signed_bundle 'foreign.txt') -PathType Leaf)) {
        throw 'postcommit path substitution was deleted, adopted, or reported as success'
    }

    [ordered]@{
        component = 'eliot_release_finalize_signing_tests'
        status = 'VERIFIED'
        exact_roles = 6
        explicit_signtool_store_timestamp = $true
        missing_certificate_rejected = $true
        wrong_certificate_rejected = $true
        fake_eku_object_rejected = $true
        public_certificate_verification_accepted = $true
        verify_bundle_is_read_only_snapshot = $true
        materializer_role_mutation_rejected = $true
        missing_timestamp_rejected = $true
        missing_rfc3161_token_rejected = $true
        signtool_warning_rejected = $true
        signer_substitution_rejected = $true
        partial_signing_rejected = $true
        source_mutation_rejected = $true
        non_role_mutation_rejected = $true
        non_role_directory_mutation_rejected = $true
        stale_internal_hash_rejected = $true
        drive_relative_path_rejected = $true
        concurrent_staging_not_adopted = $true
        atomic_create_open_substitution_blocked = $true
        failed_partial_quarantined = $true
        cleanup_substitution_not_deleted = $true
        child_contour_substitution_typed_unknown = $true
        release_window_file_mutation_typed_unknown = $true
        postvalidator_file_mutation_typed_unknown = $true
        postvalidator_file_addition_typed_unknown = $true
        retained_file_fence_blocks_writes = $true
        retained_file_fence_blocks_rename_delete = $true
        marker_deleted_by_retained_handle = $true
        postcommit_failure_typed_unknown = $true
        committed_unknown_exit_code_nonzero = $true
        normal_commit_requires_consumer_reconciliation = $true
        signed_published_exit_rejected = $true
        postcommit_substitution_typed_unknown = $true
        preexisting_output_not_replaced = $true
        concurrent_output_not_replaced = $true
        native_atomic_create_publish_fixture = $true
        native_relative_publish_collision_preserved_both = $true
        unsigned_source_preserved = $true
        no_live_signtool_or_certificate_creation = $true
    } | ConvertTo-Json -Depth 4
}
finally {
    $resolvedRoot = [System.IO.Path]::GetFullPath($root)
    if ($resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
