# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Runtime — isolated Windows runtime topology provisioner (#911).
# Closed 9-op provider interface (ValidateRequirement, Plan, Allocate, Start,
# ObserveReadiness, ResetForTest, CollectEvidence, Stop, VerifyCleanup) mirroring
# the Core.psm1 Invoke pattern (closed dispatcher, binding shape, injected-clock
# deadline, no forbidden authority: testDenominator/providerChoice/command/argv/
# executable/shellCommand/testPassed/markPassed/verdictOverride).
# Fail-closed: exact RUNTIME class + target component + revision
# eliot.integration.runtime-provider.v1 + lock (eliot-host.exe 1.0.0 windows-x64
# pe 8664 isolated-foreground sha 6356df03...a0fc); mutation-free Plan deriving the
# component graph (kernel <- host <- governor <- watchdog; bridge <- host,governor)
# plus Store/Git receipt requirements; unique run-owned installation/session/config/
# data/log/temp/artifact identities + canonical F-PIPE namespace + user-scoped
# isolated-foreground principal; per-executable digest + PE target/profile before
# launch; Job Object (or accepted equivalent) containment before descendants escape;
# request/observed handle separation; owner-issued generation/fence/epoch (never
# minted); authenticated peer handshake; liveness never proves subsystem readiness;
# stale/foreign/expired receipts never restore readiness; unknown launches require
# reconciliation without retry/reuse; owner-only reset; reverse-order shutdown +
# owned-tree-only termination (never by label/pipe/PID alone); full descendant/job/
# pipe/mutex/handle/lock/root verification; idempotent cleanup preserving the primary
# failure; bounded redacted evidence; ELIOT_GOVERNOR_CONFIG only as a versioned
# run-local receipt via the Core-protected channel. All clocks/seams injected; no
# download, spawn, or sleep here. Proof ceiling: RUNTIME-PROVIDER-ISOLATED-ONLY.
Set-StrictMode -Version Latest
$Script:RuntimeTestClass = 'RUNTIME'
$Script:RuntimeProviderName = 'eliot-runtime-windows-isolated'
$Script:RuntimeProviderRevision = 'eliot.integration.runtime-provider.v1'
$Script:RuntimeInterfaceVersion = 'eliot.integration.harness-provider.v1'
$Script:RuntimeArtifact = 'eliot-host.exe'
$Script:RuntimeRelativePath = 'runtime/eliot-host.exe'
$Script:RuntimeVersion = '1.0.0'
$Script:RuntimeArchitecture = 'windows-x64'
$Script:RuntimePeMachine = '8664'
$Script:RuntimePeProfile = 'isolated-foreground'
$Script:RuntimeDigest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'
$Script:RuntimeOwnedRootMarker = 'eliot-harness-owned-root-v1'
$Script:RuntimePipePrefix = 'eliot-fpipe-'
$Script:RuntimePipeDevicePrefix = '\\.\pipe\'
$Script:RuntimeGovernorConfigName = 'ELIOT_GOVERNOR_CONFIG'
$Script:RuntimeGovernorConfigVersion = 'governor-config-v1'
$Script:RuntimeGovernorConfigChannel = 'core-protected'
$Script:RuntimeStoreReceiptRevision = 'eliot.integration.store-provider.v1'
$Script:RuntimeGitReceiptRevision = 'eliot.integration.git-provider.v1'
$Script:RuntimePrincipalScope = 'user-isolated-foreground'
$Script:RuntimeComponents = @('kernel', 'host', 'governor', 'watchdog', 'bridge')
$Script:RuntimeLaunchOrder = @('kernel', 'host', 'governor', 'watchdog', 'bridge')
$Script:RuntimeShutdownOrder = @('bridge', 'watchdog', 'governor', 'host', 'kernel')
$Script:RuntimeComponentDependencies = @{ kernel = @(); host = @('kernel'); governor = @('host'); watchdog = @('governor'); bridge = @('host', 'governor') }
$Script:RuntimeClosedOperations = @('ValidateRequirement', 'Plan', 'Allocate', 'Start', 'ObserveReadiness', 'ResetForTest', 'CollectEvidence', 'Stop', 'VerifyCleanup')
$Script:RuntimeTerminalDispositions = @('Passed', 'AssertionFailed', 'TimedOut', 'ProcessCrashed', 'InfrastructureBlocked', 'UnsupportedExternalCredential', 'HarnessError', 'Cancelled', 'NotExecutedDueToPriorContamination')
$Script:RuntimeForbiddenPlanKeys = @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')
$Script:RuntimeForbiddenResultKeys = @('testDenominator', 'providerChoice', 'chooseProvider', 'command', 'argv', 'executable', 'shellCommand', 'testPassed', 'markPassed', 'verdictOverride')
$Script:RuntimeAllowedChildEnv = @('PATH', 'SystemRoot', 'TEMP', 'TMP', 'OS', 'PATHEXT', 'COMSPEC')
$Script:RuntimeAllowedRootChildren = @('.eliot-harness-owner.json', 'installation', 'session', 'config', 'data', 'logs', 'temp', 'artifacts')
$Script:RuntimeReservedLeafPattern = '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'
$Script:RuntimeAcceptedContainments = @('job-object', 'job-object-equivalent')
$Script:RuntimeAcceptedProvenances = @('acquired-verified', 'cached-reverified', 'built-verified')
function Get-RuntimeProviderIdentity {
    [CmdletBinding()]
    param()
    return @{ testClass = $Script:RuntimeTestClass; providerName = $Script:RuntimeProviderName; providerRevision = $Script:RuntimeProviderRevision; interfaceVersion = $Script:RuntimeInterfaceVersion; artifact = $Script:RuntimeArtifact; relativePath = $Script:RuntimeRelativePath; version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; digest = $Script:RuntimeDigest }
}
function Get-RuntimeLockIdentity {
    [CmdletBinding()]
    param()
    return @{ artifact = $Script:RuntimeArtifact; relativePath = $Script:RuntimeRelativePath; version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; sha256 = $Script:RuntimeDigest }
}
function Get-RuntimeClosedOperations {
    [CmdletBinding()]
    param()
    return @($Script:RuntimeClosedOperations)
}
function Get-RuntimeTerminalDispositions {
    [CmdletBinding()]
    param()
    return @($Script:RuntimeTerminalDispositions)
}
function Test-RuntimeDigestFormat {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Digest)
    if ([string]::IsNullOrWhiteSpace($Digest)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-DIGEST: digest is empty.') }
    if ($Digest -cnotmatch '^[0-9a-f]{64}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-DIGEST: digest must be 64 lowercase hex.') }
    return $true
}
function Test-RuntimeClosedOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Operation)
    if ([string]::IsNullOrWhiteSpace($Operation)) { throw [System.ArgumentException]::new('RUNTIME-UNKNOWN-OPERATION: operation name is empty.') }
    foreach ($allowed in $Script:RuntimeClosedOperations) { if ($Operation -ceq $allowed) { return $true } }
    throw [System.ArgumentException]::new("RUNTIME-UNKNOWN-OPERATION: '$Operation' is not a member of the closed Runtime provider interface.")
}
function Test-RuntimeTerminalDisposition {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Disposition)
    if ([string]::IsNullOrWhiteSpace($Disposition)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-DISPOSITION: disposition is empty.') }
    foreach ($allowed in $Script:RuntimeTerminalDispositions) { if ($Disposition -ceq $allowed) { return $true } }
    throw [System.ArgumentException]::new("RUNTIME-INVALID-DISPOSITION: '$Disposition' is not an accepted terminal disposition.")
}
function Resolve-RuntimeDeadline {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter()][AllowNull()][scriptblock]$Clock, [Parameter(Mandatory)][string]$Operation)
    if (-not $Binding.ContainsKey('deadlineUtc') -or [string]::IsNullOrWhiteSpace([string]$Binding['deadlineUtc'])) { throw [System.ArgumentException]::new('RUNTIME-INVALID-BINDING: binding is missing deadlineUtc.') }
    $deadline = [System.DateTimeOffset]::Parse([string]$Binding['deadlineUtc'])
    $now = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observed = (& $Clock)
        if ($observed -is [System.DateTimeOffset]) { $now = $observed }
        elseif ($observed -is [System.DateTime]) { $now = [System.DateTimeOffset]::new($observed.ToUniversalTime()) }
        else { throw [System.ArgumentException]::new('RUNTIME-INVALID-CLOCK: injected clock must return DateTimeOffset.') }
    }
    $remaining = [int]($deadline - $now).TotalSeconds
    if ($remaining -le 0) { throw [System.TimeoutException]::new("RUNTIME-DEADLINE-EXCEEDED: operation '$Operation' has no remaining bound.") }
    return $remaining
}
function Test-RuntimeBindingShape {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding)
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-BINDING: binding is missing '$field'.") }
    }
    if ([string]$Binding['runId'] -cnotmatch '^[0-9a-f]{32}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-BINDING: runId must be 32 lowercase hex.') }
    $gen = 0
    try { $gen = [int]$Binding['generation'] } catch { throw [System.ArgumentException]::new('RUNTIME-INVALID-BINDING: generation must be a positive integer.') }
    if ($gen -le 0) { throw [System.ArgumentException]::new('RUNTIME-INVALID-BINDING: generation must be positive.') }
    foreach ($key in @($Binding.Keys)) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            if ([string]$key -ieq $forbidden) { throw [System.InvalidOperationException]::new("RUNTIME-BINDING-FORBIDDEN: binding must not carry '$key'.") }
        }
    }
    return $true
}
function Test-RuntimeProviderResultClosed {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Result, [Parameter(Mandatory)][hashtable]$Binding)
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in $Script:RuntimeForbiddenResultKeys) {
            if ([string]$key -ieq $forbidden) { throw [System.InvalidOperationException]::new("RUNTIME-PROVIDER-FORBIDDEN: provider result must not contain '$key'.") }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) { throw [System.InvalidOperationException]::new('RUNTIME-PROVIDER-FORBIDDEN: provider must not change the run identity.') }
    return $true
}
function Invoke-RuntimeProviderOperation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Operation, [Parameter(Mandatory)][hashtable]$Provider, [Parameter(Mandatory)][hashtable]$Binding, [Parameter()][hashtable]$Arguments, [Parameter()][AllowNull()][scriptblock]$Clock)
    [void](Test-RuntimeClosedOperation -Operation $Operation)
    if ($null -eq $Provider -or $Provider.Count -eq 0) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PROVIDER: provider table is empty.') }
    if (-not $Provider.ContainsKey($Operation)) { throw [System.ArgumentException]::new("RUNTIME-UNKNOWN-OPERATION: provider has no implementation for '$Operation'.") }
    $implementation = $Provider[$Operation]
    if ($implementation -isnot [scriptblock]) { throw [System.ArgumentException]::new("RUNTIME-INVALID-PROVIDER: operation '$Operation' must map to a scriptblock.") }
    [void](Test-RuntimeBindingShape -Binding $Binding)
    [void](Resolve-RuntimeDeadline -Binding $Binding -Clock $Clock -Operation $Operation)
    $context = @{ operation = $Operation; binding = $Binding; arguments = $Arguments }
    $raw = $null
    try { $raw = (& $implementation $context) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-PROVIDER-FAILED:$Operation : $($_.Exception.Message)") }
    if ($null -eq $raw) { throw [System.InvalidOperationException]::new("RUNTIME-PROVIDER-FAILED:$Operation : provider returned no result.") }
    $result = @{}
    if ($raw -is [hashtable]) { $result = $raw }
    elseif ($raw -is [psobject]) { foreach ($prop in $raw.PSObject.Properties) { $result[[string]$prop.Name] = $prop.Value } }
    else { throw [System.InvalidOperationException]::new("RUNTIME-PROVIDER-FAILED:$Operation : provider result must be a hashtable.") }
    [void](Test-RuntimeProviderResultClosed -Result $result -Binding $Binding)
    return $result
}
function Invoke-RuntimeValidateRequirement {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Requirement, [Parameter(Mandatory)][hashtable]$Lock)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    foreach ($field in @('testClass', 'target', 'providerRevision')) {
        if (-not $Requirement.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Requirement[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-REQUIREMENT: requirement is missing '$field'.") }
    }
    if ([string]$Requirement['testClass'] -cne $Script:RuntimeTestClass) { throw [System.InvalidOperationException]::new("RUNTIME-UNSUPPORTED-CLASS: requirement class '$($Requirement['testClass'])' is not RUNTIME.") }
    $reqTarget = [string]$Requirement['target']
    if ($reqTarget -cnotin $Script:RuntimeComponents) { throw [System.InvalidOperationException]::new("RUNTIME-UNKNOWN-TARGET: requirement target '$reqTarget' is not a topology component.") }
    if ([string]$Requirement['providerRevision'] -cne $Script:RuntimeProviderRevision) { throw [System.InvalidOperationException]::new("RUNTIME-UNSUPPORTED-REVISION: provider revision '$($Requirement['providerRevision'])' is not '$($Script:RuntimeProviderRevision)'.") }
    if ([string]$Binding['testClass'] -cne $Script:RuntimeTestClass) { throw [System.InvalidOperationException]::new('RUNTIME-BINDING-MISMATCH: binding testClass is not RUNTIME.') }
    if ([string]$Binding['providerRevision'] -cne $Script:RuntimeProviderRevision) { throw [System.InvalidOperationException]::new('RUNTIME-BINDING-MISMATCH: binding providerRevision mismatch.') }
    if ([string]$Binding['providerName'] -cne $Script:RuntimeProviderName) { throw [System.InvalidOperationException]::new('RUNTIME-BINDING-MISMATCH: binding providerName mismatch.') }
    foreach ($field in @('version', 'architecture', 'peMachine', 'peProfile', 'sha256', 'artifact')) {
        if (-not $Lock.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Lock[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-LOCK: lock is missing '$field'.") }
    }
    $lockSpec = @{ version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; artifact = $Script:RuntimeArtifact }
    foreach ($field in @($lockSpec.Keys)) {
        if ([string]$Lock[$field] -cne $lockSpec[$field]) { throw [System.InvalidOperationException]::new("RUNTIME-LOCK-MISMATCH: lock field '$field' does not match the accepted runtime identity.") }
    }
    [void](Test-RuntimeDigestFormat -Digest ([string]$Lock['sha256']))
    if ([string]$Lock['sha256'] -cne $Script:RuntimeDigest) { throw [System.InvalidOperationException]::new('RUNTIME-LOCK-MISMATCH: lock digest does not match the accepted runtime identity.') }
    return @{ runId = [string]$Binding['runId']; testClass = $Script:RuntimeTestClass; target = $reqTarget; providerName = $Script:RuntimeProviderName; providerRevision = $Script:RuntimeProviderRevision; version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; digest = $Script:RuntimeDigest; artifact = $Script:RuntimeArtifact; artifactState = 'artifact-accepted'; accepted = $true }
}
function Invoke-RuntimePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Requirement)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    if ([string]$Requirement['testClass'] -cne $Script:RuntimeTestClass) { throw [System.InvalidOperationException]::new('RUNTIME-UNSUPPORTED-CLASS: plan requirement class is not RUNTIME.') }
    if ([string]$Requirement['providerRevision'] -cne $Script:RuntimeProviderRevision) { throw [System.InvalidOperationException]::new('RUNTIME-UNSUPPORTED-REVISION: plan requirement revision mismatch.') }
    if ([string]$Requirement['target'] -cnotin $Script:RuntimeComponents) { throw [System.InvalidOperationException]::new('RUNTIME-UNKNOWN-TARGET: plan requirement target is not a topology component.') }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $resources = @()
    foreach ($component in $Script:RuntimeComponents) {
        $resources += @{ resourceKey = ('runtime-' + $component); component = $component; testClass = $Script:RuntimeTestClass; providerRevision = $Script:RuntimeProviderRevision; runId = $runId; owner = $owner; generation = $gen; dependsOn = @($Script:RuntimeComponentDependencies[$component]) }
    }
    $requiredReceipts = @(
        @{ kind = 'store-receipt'; testClass = 'STORE'; providerRevision = $Script:RuntimeStoreReceiptRevision; runId = $runId },
        @{ kind = 'git-receipt'; testClass = 'GIT'; providerRevision = $Script:RuntimeGitReceiptRevision; runId = $runId })
    foreach ($resource in $resources) {
        foreach ($key in @($resource.Keys)) {
            foreach ($forbidden in $Script:RuntimeForbiddenPlanKeys) {
                if ([string]$key -ieq $forbidden) { throw [System.InvalidOperationException]::new("RUNTIME-PLAN-FORBIDDEN: plan resource must not carry '$key'.") }
            }
        }
    }
    return @{ runId = $runId; testClass = $Script:RuntimeTestClass; target = [string]$Requirement['target']; providerName = $Script:RuntimeProviderName; providerRevision = $Script:RuntimeProviderRevision; owner = $owner; generation = $gen; resources = $resources; requiredReceipts = $requiredReceipts; mutationFree = $true }
}
function Resolve-RuntimeOwnedPath {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RunRoot, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ExpectedRunId)
    if ([string]::IsNullOrWhiteSpace($RunRoot)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: RunRoot is empty.') }
    if ([string]::IsNullOrWhiteSpace($Path)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: Path is empty.') }
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.') }
    $rootFull = [System.IO.Path]::GetFullPath($RunRoot)
    if ([System.IO.Path]::IsPathFullyQualified($Path)) { $candidate = [System.IO.Path]::GetFullPath($Path) }
    else { $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $Path)) }
    $prefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ine $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-PATH-ESCAPE: path escapes the admitted run root: $candidate") }
    if (-not [string]::IsNullOrEmpty([System.IO.Path]::GetFileName($candidate)) -and ([System.IO.Path]::GetFileName($candidate) -match $Script:RuntimeReservedLeafPattern)) { throw [System.InvalidOperationException]::new("RUNTIME-RESERVED-PATH: reserved device name rejected: $candidate") }
    foreach ($segment in ($candidate.Substring($rootFull.Length).Split([System.IO.Path]::DirectorySeparatorChar))) {
        if ($segment -match $Script:RuntimeReservedLeafPattern) { throw [System.InvalidOperationException]::new("RUNTIME-RESERVED-PATH: reserved device segment rejected: $segment") }
    }
    $probe = $candidate
    while ($null -ne $probe -and $probe.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw [System.InvalidOperationException]::new("RUNTIME-REPARSE-ESCAPE: path crosses a reparse point: $($entry.FullName)") }
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    $cursor = Split-Path -Parent $candidate
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and $cursor.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $marker = Join-Path $cursor '.eliot-harness-owner.json'
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            try {
                $recorded = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($recorded.run_id -cne $ExpectedRunId) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: owner marker belongs to another run: $cursor") }
            } catch [System.InvalidOperationException] { throw }
            catch { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: owner marker unreadable at: $cursor") }
            break
        }
        if ($cursor -ieq $rootFull) { break }
        $next = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($next) -or $next -eq $cursor) { break }
        $cursor = $next
    }
    return $candidate
}
function Get-RuntimeChildEnv {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Ambient)
    $filtered = @{}
    foreach ($key in @($Ambient.Keys)) {
        if ($key -cnotin $Script:RuntimeAllowedChildEnv) { continue }
        $upper = ([string]$key).ToUpperInvariant()
        if ($upper.Contains('TOKEN') -or $upper.Contains('SECRET') -or $upper.Contains('CREDENTIAL') -or $upper.Contains('PASSWORD') -or $upper.Contains('KEY')) { continue }
        $value = [string]$Ambient[$key]
        if ([System.Text.Encoding]::UTF8.GetByteCount($value) -gt 4096) { throw [System.InvalidOperationException]::new("RUNTIME-ENV-BOUND: child env value exceeds byte cap: $key") }
        $filtered[$key] = $value
    }
    return $filtered
}
function New-RuntimeEphemeralCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$CredentialId, [Parameter()][AllowNull()][scriptblock]$Entropy)
    if ([string]::IsNullOrWhiteSpace($CredentialId)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CREDENTIAL: credential id is empty.') }
    if ($CredentialId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-CREDENTIAL: credential id has an invalid shape.') }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or [string]::IsNullOrWhiteSpace($nonce)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-ENTROPY: entropy must return nonempty text.') }
    } else {
        $bytes = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $nonce = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    }
    if ($nonce -cnotmatch '^[0-9a-f]{16,128}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-ENTROPY: entropy nonce must be lowercase hex.') }
    return @{ credentialId = $CredentialId; credentialHandle = ('handle:' + $CredentialId + ':' + $nonce.Substring(0, 8)); secret = ('runtime-ephemeral-' + $nonce); ephemeral = $true }
}
function Test-RuntimePrincipalShape {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Principal)
    foreach ($field in @('principal', 'sessionId', 'scope')) {
        if (-not $Principal.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Principal[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-PRINCIPAL: principal is missing '$field'.") }
    }
    if ([string]$Principal['sessionId'] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-PRINCIPAL: sessionId has an invalid shape.') }
    if ([string]$Principal['scope'] -cne $Script:RuntimePrincipalScope) { throw [System.InvalidOperationException]::new("RUNTIME-PRINCIPAL-SCOPE: principal scope '$($Principal['scope'])' is not user-scoped isolated foreground execution.") }
    return $true
}
function Test-RuntimeProviderReceipt {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Receipt)
    foreach ($field in @('testClass', 'providerRevision', 'runId', 'digest', 'issuer')) {
        if (-not $Receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Receipt[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-RECEIPT: provider receipt is missing '$field'.") }
    }
    $class = [string]$Receipt['testClass']
    if ($class -cne 'STORE' -and $class -cne 'GIT') { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-CLASS: provider receipt class '$class' is not an accepted dependency lane.") }
    $expectedRevision = $Script:RuntimeStoreReceiptRevision
    $expectedIssuer = 'store-provider-owner'
    if ($class -ceq 'GIT') { $expectedRevision = $Script:RuntimeGitReceiptRevision; $expectedIssuer = 'git-provider-owner' }
    if ([string]$Receipt['providerRevision'] -cne $expectedRevision) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-REVISION: provider receipt revision is not the accepted lane revision.') }
    if ([string]$Receipt['runId'] -cnotmatch '^[0-9a-f]{32}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-RECEIPT: receipt runId must be 32 lowercase hex.') }
    [void](Test-RuntimeDigestFormat -Digest ([string]$Receipt['digest']))
    if ([string]$Receipt['issuer'] -cne $expectedIssuer) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-UNFABRICABLE: receipt issuer is not the lane owner; self-minted receipts are rejected.') }
    return $true
}
function Get-RuntimeRedactedText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$Secrets, [ValidateRange(1, 16777216)][int]$MaxBytes = 65536)
    $redacted = $Text
    try {
        if ($null -ne $Secrets) {
            foreach ($secret in $Secrets) {
                if ([string]::IsNullOrEmpty($secret)) { continue }
                $redacted = $redacted.Replace($secret, '[redacted-runtime-secret]')
            }
        }
        $redacted = [regex]::Replace($redacted, '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring|governorconfig)\s*[:=]\s*\S+', '$1=[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)ELIOT_GOVERNOR_CONFIG\s*=\s*\S+', 'ELIOT_GOVERNOR_CONFIG=[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)runtime_[a-z_]*(pass|secret|token|key)[a-z_]*\s*=\s*\S+', '[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)(frame|payload|memory|command|argv|environ)\s*\{[^}]{0,4096}\}', '$1 [redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)[A-Za-z]:\\Users\\[^\\/:*?"<>|]+', '[redacted-user-path]')
    } catch {
        return [pscustomobject]@{ text = ''; bytes = 0; truncated = $false; failed = $true }
    }
    try { $bytes = [System.Text.Encoding]::UTF8.GetBytes($redacted) }
    catch { return [pscustomobject]@{ text = ''; bytes = 0; truncated = $false; failed = $true } }
    $truncated = $bytes.Length -gt $MaxBytes
    $output = $redacted
    if ($truncated) {
        try {
            $output = [System.Text.Encoding]::UTF8.GetString($bytes, $bytes.Length - $MaxBytes, $MaxBytes)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
        } catch { return [pscustomobject]@{ text = ''; bytes = 0; truncated = $true; failed = $true } }
    }
    return [pscustomobject]@{ text = $output; bytes = $bytes.Length; truncated = $truncated; failed = $false }
}
function Invoke-RuntimeAllocate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][string]$BaseTemp, [Parameter()][AllowNull()][scriptblock]$Entropy, [Parameter()][AllowNull()][scriptblock]$NamespaceReservation)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    if ([string]$Plan['runId'] -cne [string]$Binding['runId']) { throw [System.InvalidOperationException]::new('RUNTIME-ALLOCATION-MISMATCH: plan run identity does not match binding.') }
    if ([string]::IsNullOrWhiteSpace($BaseTemp)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: BaseTemp is empty.') }
    $runId = [string]$Binding['runId']
    $baseFull = [System.IO.Path]::GetFullPath($BaseTemp)
    $lower = $baseFull.ToLowerInvariant()
    if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) { throw [System.InvalidOperationException]::new('RUNTIME-FORBIDDEN-ROOT: allocation base crossed a forbidden host boundary.') }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-ENTROPY: entropy must return lowercase hex.') }
    } else { $nonce = $runId.Substring(0, 8) }
    $runRoot = [System.IO.Path]::GetFullPath((Join-Path $baseFull ("eliot-runtime-{0}-{1}" -f $runId, $nonce)))
    $prefix = $baseFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $runRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-PATH-ESCAPE: allocated run root escaped its base: $runRoot") }
    $roots = @{}
    foreach ($leaf in @('installation', 'session', 'config', 'data', 'logs', 'temp', 'artifacts')) {
        $full = [System.IO.Path]::GetFullPath((Join-Path $runRoot $leaf))
        [void](Resolve-RuntimeOwnedPath -RunRoot $runRoot -Path $full -ExpectedRunId $runId)
        $roots[$leaf] = $full
    }
    $pipeNamespace = ($Script:RuntimePipePrefix + $runId.Substring(0, 8))
    if ($pipeNamespace -cnotmatch '^[A-Za-z0-9_.-]{1,64}$') { throw [System.InvalidOperationException]::new('RUNTIME-ALLOCATION-MISMATCH: derived pipe namespace has an invalid shape.') }
    $sessionId = ('sess-' + $nonce)
    $principal = @{ principal = [string]$Binding['owner']; sessionId = $sessionId; scope = $Script:RuntimePrincipalScope }
    [void](Test-RuntimePrincipalShape -Principal $principal)
    if ($null -eq $NamespaceReservation) { throw [System.ArgumentException]::new('RUNTIME-MISSING-RESERVATION: a namespace-reservation seam is required; no pipe is created here.') }
    $reservation = $null
    try { $reservation = (& $NamespaceReservation @{ runId = $runId; pipeNamespace = $pipeNamespace; sessionId = $sessionId }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-NAMESPACE-CONFLICT: reservation failed: $($_.Exception.Message)") }
    $reserved = ''
    if ($reservation -is [hashtable] -and $reservation.ContainsKey('pipeNamespace')) { $reserved = [string]$reservation['pipeNamespace'] }
    elseif ($reservation -is [string]) { $reserved = $reservation }
    else { throw [System.InvalidOperationException]::new('RUNTIME-NAMESPACE-CONFLICT: reservation must return a pipe-namespace mapping.') }
    if ($reserved -cne $pipeNamespace) { throw [System.InvalidOperationException]::new('RUNTIME-NAMESPACE-CONFLICT: reserved namespace does not match the derived canonical namespace.') }
    return @{ runId = $runId; runRoot = $runRoot; installationRoot = $roots['installation']; sessionRoot = $roots['session']; configRoot = $roots['config']; dataRoot = $roots['data']; logRoot = $roots['logs']; tempRoot = $roots['temp']; artifactRoot = $roots['artifacts']; ownerMarker = $Script:RuntimeOwnedRootMarker; pipeNamespace = $pipeNamespace; sessionId = $sessionId; principal = $principal; owner = [string]$Binding['owner']; generation = [int]$Binding['generation']; allocationSeed = $nonce }
}
function Invoke-RuntimeStart {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][AllowNull()][scriptblock]$Acquisition, [Parameter(Mandatory)][AllowNull()][scriptblock]$Launcher, [Parameter(Mandatory)][AllowNull()][scriptblock]$OwnerIssuance, [Parameter()][AllowNull()][scriptblock]$Entropy)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-START-MISMATCH: allocation run identity does not match binding.') }
    foreach ($field in @('runRoot', 'installationRoot', 'sessionRoot', 'configRoot', 'pipeNamespace', 'sessionId')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing '$field'.") }
    }
    if ($null -eq $Acquisition) { throw [System.ArgumentException]::new('RUNTIME-MISSING-ACQUISITION: an acquisition seam is required; no download is performed here.') }
    if ($null -eq $Launcher) { throw [System.ArgumentException]::new('RUNTIME-MISSING-LAUNCHER: a process-launcher seam is required; no live spawn is performed here.') }
    if ($null -eq $OwnerIssuance) { throw [System.ArgumentException]::new('RUNTIME-MISSING-ISSUANCE: an owner-issuance seam is required; generation/fence/epoch are never locally minted.') }
    $receipt = $null
    try { $receipt = (& $Acquisition @{ runId = $runId; artifact = $Script:RuntimeArtifact }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ACQUISITION-FAILED: $($_.Exception.Message)") }
    if ($null -eq $receipt -or $receipt -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-ACQUISITION-FAILED: acquisition must return a hashtable receipt.') }
    foreach ($field in @('version', 'architecture', 'peMachine', 'peProfile', 'digest', 'provenance', 'runtimePath')) {
        if (-not $receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$receipt[$field])) { throw [System.InvalidOperationException]::new("RUNTIME-ACQUISITION-FAILED: receipt is missing '$field'.") }
    }
    if ([string]$receipt['version'] -ieq 'latest') { throw [System.InvalidOperationException]::new('RUNTIME-LATEST-REJECTED: floating latest tag is never accepted.') }
    $binarySpec = @{ version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile }
    foreach ($field in @($binarySpec.Keys)) {
        if ([string]$receipt[$field] -cne $binarySpec[$field]) { throw [System.InvalidOperationException]::new("RUNTIME-BINARY-MISMATCH: receipt field '$field' does not match the accepted runtime identity.") }
    }
    [void](Test-RuntimeDigestFormat -Digest ([string]$receipt['digest']))
    if ([string]$receipt['digest'] -cne $Script:RuntimeDigest) { throw [System.InvalidOperationException]::new('RUNTIME-DIGEST-MISMATCH: binary digest does not match the accepted runtime identity.') }
    $provenance = [string]$receipt['provenance']
    if ($provenance -cnotin $Script:RuntimeAcceptedProvenances) {
        if ($provenance -ieq 'caller-hash' -or $provenance -ieq 'caller-supplied') { throw [System.InvalidOperationException]::new('RUNTIME-CALLER-HASH-REJECTED: caller-supplied hashes never establish provenance.') }
        throw [System.InvalidOperationException]::new("RUNTIME-PROVENANCE-MISSING: provenance '$provenance' is not an accepted verified acquisition.")
    }
    $runtimePath = [string]$receipt['runtimePath']
    if (-not $runtimePath.EndsWith($Script:RuntimeArtifact, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new('RUNTIME-ACQUISITION-FAILED: runtime path does not name the approved artifact.') }
    $issuance = $null
    try { $issuance = (& $OwnerIssuance @{ runId = $runId }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ISSUANCE-FAILED: $($_.Exception.Message)") }
    if ($null -eq $issuance -or $issuance -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: owner issuance must return a hashtable.') }
    foreach ($field in @('generation', 'fence', 'epoch', 'owner')) {
        if (-not $issuance.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$issuance[$field])) { throw [System.InvalidOperationException]::new("RUNTIME-ISSUANCE-FAILED: owner issuance is missing '$field'.") }
    }
    $issuedGen = 0
    $issuedEpoch = 0
    try { $issuedGen = [int]$issuance['generation']; $issuedEpoch = [int]$issuance['epoch'] }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issued generation/epoch are not integers.') }
    if ($issuedGen -ne [int]$Binding['generation']) { throw [System.InvalidOperationException]::new('RUNTIME-FENCE-NOT-OWNER: issued generation does not match the binding generation.') }
    if ([string]$issuance['owner'] -cne [string]$Binding['owner']) { throw [System.InvalidOperationException]::new('RUNTIME-FENCE-NOT-OWNER: issuance owner does not match the binding owner; locally minted fences are rejected.') }
    if ($issuedEpoch -le 0) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issued epoch must be positive.') }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-ENTROPY: entropy must return lowercase hex.') }
    } else { $nonce = $runId.Substring(16, 8) }
    $pipeNamespace = [string]$Allocation['pipeNamespace']
    $sessionId = [string]$Allocation['sessionId']
    $childEnv = Get-RuntimeChildEnv -Ambient @{ PATH = $runtimePath; TEMP = ([string]$Allocation['runRoot']) }
    $observed = @{}
    $requestKeys = @{}
    foreach ($component in $Script:RuntimeLaunchOrder) {
        $requestKey = ('req-' + $component + '-' + $nonce)
        $pipe = ($Script:RuntimePipeDevicePrefix + $pipeNamespace + '-' + $component)
        $fixedArgv = @($runtimePath, 'run', '--component', $component, '--pipe', $pipe, '--session', $sessionId)
        $single = $null
        try { $single = (& $Launcher @{ runId = $runId; component = $component; argv = $fixedArgv; pipe = $pipe; sessionId = $sessionId; childEnv = $childEnv; requestKey = $requestKey }) }
        catch {
            $message = $_.Exception.Message
            if ($message -match '(?i)lost-response|timeout|unknown') {
                return @{ runId = $runId; launchState = 'ReconciliationRequired'; requested = @{ component = $component; requestKey = $requestKey; pipe = $pipe }; observed = $null; invocation = @{ argvCount = $fixedArgv.Count; pipe = $pipe; component = $component }; binary = @{ version = $Script:RuntimeVersion; digest = [string]$receipt['digest']; provenance = $provenance }; retryPermitted = $false; failure = ('lost-response-owned:' + $message) }
            }
            throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: $message")
        }
        if ($null -eq $single -or $single -isnot [hashtable]) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: launcher must return a hashtable observation for '$component'.") }
        if (-not $single.ContainsKey('observedPid') -or -not $single.ContainsKey('observedNonce') -or -not $single.ContainsKey('containment')) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: launcher observation is missing pid/nonce/containment for '$component'.") }
        $observedPid = 0
        try { $observedPid = [int]$single['observedPid'] } catch { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: observed pid is not an integer for '$component'.") }
        if ($observedPid -le 0) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: observed pid is not positive for '$component'.") }
        if ([string]$single['observedNonce'] -ceq $nonce) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: requested and observed nonces must be distinct handles for '$component'.") }
        if ([string]$single['containment'] -cnotin $Script:RuntimeAcceptedContainments) { throw [System.InvalidOperationException]::new("RUNTIME-CONTAINMENT-MISSING: component '$component' entered without Job Object containment proof; execution is not recognized.") }
        $observed[$component] = @{ pid = $observedPid; nonce = [string]$single['observedNonce']; containment = [string]$single['containment']; pipe = $pipe; requestKey = $requestKey }
        $requestKeys[$component] = $requestKey
    }
    return @{ runId = $runId; launchState = 'launch-registered'; containedObserved = $true; requested = @{ requestKeys = $requestKeys; pipeNamespace = $pipeNamespace; sessionId = $sessionId }; observed = $observed; invocation = @{ argvCount = 8; artifact = $Script:RuntimeArtifact }; binary = @{ version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; digest = [string]$receipt['digest']; provenance = $provenance }; ownerIssuance = @{ generation = $issuedGen; fence = [string]$issuance['fence']; epoch = $issuedEpoch; owner = [string]$issuance['owner'] }; pipeNamespace = $pipeNamespace; sessionId = $sessionId }
}
function Invoke-RuntimeObserveReadiness {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$StartReceipt, [Parameter(Mandatory)][AllowNull()][scriptblock]$ProcessObserver, [Parameter(Mandatory)][AllowNull()][scriptblock]$PipeObserver, [Parameter(Mandatory)][AllowNull()][scriptblock]$TopologyClient, [Parameter()][AllowNull()][scriptblock]$Clock)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    [void](Resolve-RuntimeDeadline -Binding $Binding -Clock $Clock -Operation 'ObserveReadiness')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: start receipt run identity is foreign.') }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable])) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt carries no observed process handles.') }
    foreach ($component in $Script:RuntimeComponents) {
        $entry = $null
        if ($StartReceipt['observed'].ContainsKey($component)) { $entry = $StartReceipt['observed'][$component] }
        if ($null -eq $entry -or ($entry -isnot [hashtable]) -or -not $entry.ContainsKey('pid') -or -not $entry.ContainsKey('pipe')) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-STALE: start receipt observation is incomplete for '$component'.") }
    }
    if ($null -eq $ProcessObserver -or $null -eq $PipeObserver -or $null -eq $TopologyClient) { throw [System.ArgumentException]::new('RUNTIME-MISSING-OBSERVER: process, pipe, and topology-client seams are all required.') }
    $ownedNamespace = ''
    if ($StartReceipt.ContainsKey('pipeNamespace')) { $ownedNamespace = [string]$StartReceipt['pipeNamespace'] }
    $ownedSession = ''
    if ($StartReceipt.ContainsKey('sessionId')) { $ownedSession = [string]$StartReceipt['sessionId'] }
    $client = (& $TopologyClient @{ runId = $runId; pipeNamespace = $ownedNamespace; sessionId = $ownedSession })
    if ($null -eq $client -or $client -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-CLIENT-FAILED: topology client must return a hashtable.') }
    foreach ($field in @('peerAuthenticated', 'peerId', 'handshakeDigest', 'generation', 'fence', 'epoch', 'components')) {
        if (-not $client.ContainsKey($field)) { throw [System.InvalidOperationException]::new("RUNTIME-CLIENT-FAILED: client receipt is missing '$field'.") }
    }
    if ($client.ContainsKey('pipeNamespace') -and ([string]$client['pipeNamespace'] -cne $ownedNamespace)) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-SUBSTITUTED: client pipe namespace is foreign to this run.') }
    $handshakeValid = $false
    if ([bool]$client['peerAuthenticated']) {
        $peerId = [string]$client['peerId']
        if ([string]::IsNullOrWhiteSpace($peerId)) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-SUBSTITUTED: authenticated peer carries no identity.') }
        if ($peerId -ceq $ownedSession) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-SUBSTITUTED: peer identity reuses the session handle.') }
        [void](Test-RuntimeDigestFormat -Digest ([string]$client['handshakeDigest']))
        $handshakeValid = $true
    }
    $peerState = 'peer-unknown'
    if ($handshakeValid) { $peerState = 'authenticated-peer-connected' }
    $issuance = $null
    if ($StartReceipt.ContainsKey('ownerIssuance')) { $issuance = $StartReceipt['ownerIssuance'] }
    if ($null -eq $issuance -or ($issuance -isnot [hashtable])) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt carries no owner issuance.') }
    $clientGen = -1
    $clientEpoch = -1
    try { $clientGen = [int]$client['generation']; $clientEpoch = [int]$client['epoch'] } catch { }
    $genFenceOk = (($clientGen -eq [int]$issuance['generation']) -and ([string]$client['fence'] -ceq [string]$issuance['fence']) -and ($clientEpoch -eq [int]$issuance['epoch']))
    $genFenceState = 'generation-fence-accepted'
    if (-not $genFenceOk) { $genFenceState = 'generation-fence-stale' }
    $clientComponents = $client['components']
    if ($null -eq $clientComponents -or ($clientComponents -isnot [hashtable])) { throw [System.InvalidOperationException]::new('RUNTIME-CLIENT-FAILED: client component map is not a hashtable.') }
    $readyMap = @{}
    $components = @{}
    $unknownComponents = New-Object Collections.Generic.List[string]
    $blockedDependents = New-Object Collections.Generic.List[string]
    foreach ($component in $Script:RuntimeComponents) { $readyMap[$component] = $false }
    foreach ($component in $Script:RuntimeLaunchOrder) {
        $ownedPid = [int]$StartReceipt['observed'][$component]['pid']
        $ownedPipe = [string]$StartReceipt['observed'][$component]['pipe']
        $process = (& $ProcessObserver @{ pid = $ownedPid; runId = $runId; component = $component })
        $pipeState = (& $PipeObserver @{ pipe = $ownedPipe; runId = $runId; component = $component })
        if ($null -eq $process -or $null -eq $pipeState) { [void]$unknownComponents.Add($component); continue }
        if ($process -isnot [hashtable] -or -not $process.ContainsKey('alive')) { throw [System.InvalidOperationException]::new("RUNTIME-OBSERVER-FAILED: process observer must return an alive mapping for '$component'.") }
        if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne $ownedPid)) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-FOREIGN: process observer returned a foreign pid for '$component'.") }
        if ($pipeState -isnot [hashtable] -or -not $pipeState.ContainsKey('open')) { throw [System.InvalidOperationException]::new("RUNTIME-OBSERVER-FAILED: pipe observer must return an open mapping for '$component'.") }
        if ($pipeState.ContainsKey('pipe') -and ([string]$pipeState['pipe'] -cne $ownedPipe)) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-FOREIGN: pipe observer returned a foreign pipe for '$component'.") }
        $clientReady = $false
        if ($clientComponents.ContainsKey($component) -and ($clientComponents[$component] -is [hashtable]) -and $clientComponents[$component].ContainsKey('ready')) { $clientReady = [bool]$clientComponents[$component]['ready'] }
        $local = ([bool]$process['alive'] -and [bool]$pipeState['open'] -and $clientReady)
        $depsReady = $true
        foreach ($dep in @($Script:RuntimeComponentDependencies[$component])) { if (-not [bool]$readyMap[$dep]) { $depsReady = $false } }
        $readyMap[$component] = ($local -and $depsReady)
        if ($local -and -not [bool]$readyMap[$component]) { [void]$blockedDependents.Add($component) }
        $components[$component] = @{ alive = [bool]$process['alive']; pipeOpen = [bool]$pipeState['open']; clientReady = $clientReady; ready = [bool]$readyMap[$component] }
    }
    if ($unknownComponents.Count -gt 0) {
        return @{ runId = $runId; readinessState = 'ReconciliationRequired'; ready = $false; wholeTopologyReady = $false; peerState = $peerState; generationFenceState = $genFenceState; unknownComponents = @($unknownComponents); pipeNamespace = $ownedNamespace }
    }
    $allReady = $true
    $anyReady = $false
    foreach ($component in $Script:RuntimeComponents) {
        if (-not [bool]$readyMap[$component]) { $allReady = $false } else { $anyReady = $true }
    }
    $whole = ($allReady -and $handshakeValid -and $genFenceOk)
    $state = 'ObservedProcessReadinessUnknown'
    if ($whole) { $state = 'WholeTopologyReady' }
    elseif ($anyReady) { $state = 'SubsystemReady' }
    return @{ runId = $runId; readinessState = $state; ready = $whole; wholeTopologyReady = $whole; peerState = $peerState; peerAuthenticated = [bool]$client['peerAuthenticated']; generationFenceState = $genFenceState; generationAccepted = $genFenceOk; staleGeneration = (-not $genFenceOk); components = $components; blockedDependents = @($blockedDependents); pipeNamespace = $ownedNamespace }
}
function Invoke-RuntimeResetForTest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Fixture, [Parameter(Mandatory)][hashtable]$ReadinessReceipt, [Parameter(Mandatory)][AllowNull()][scriptblock]$OwnerClient)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($field in @('fixtureName', 'baselineDigest')) {
        if (-not $Fixture.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Fixture[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-FIXTURE: fixture is missing '$field'.") }
    }
    [void](Test-RuntimeDigestFormat -Digest ([string]$Fixture['baselineDigest']))
    $fixtureName = [string]$Fixture['fixtureName']
    if ($fixtureName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-FIXTURE: fixture name has an invalid shape.') }
    if ([string]$ReadinessReceipt['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: readiness receipt run identity is foreign.') }
    if ($null -eq $OwnerClient) { throw [System.ArgumentException]::new('RUNTIME-MISSING-OWNER: an owner-API seam is required; reset never bypasses the owner.') }
    $result = (& $OwnerClient @{ runId = $runId; fixtureName = $fixtureName; baselineDigest = [string]$Fixture['baselineDigest'] })
    if ($null -eq $result -or $result -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-CLIENT-FAILED: owner reset must return a hashtable.') }
    if (-not $result.ContainsKey('resetOk') -or -not $result.ContainsKey('baselineOk') -or -not $result.ContainsKey('owner')) { throw [System.InvalidOperationException]::new('RUNTIME-CLIENT-FAILED: owner reset receipt is missing resetOk/baselineOk/owner.') }
    if ([string]$result['owner'] -cne [string]$Binding['owner']) { throw [System.InvalidOperationException]::new('RUNTIME-RESET-FOREIGN-OWNER: reset was not issued by the run owner.') }
    if ($result.ContainsKey('fixtureName') -and ([string]$result['fixtureName'] -cne $fixtureName)) { throw [System.InvalidOperationException]::new('RUNTIME-FIXTURE-MISMATCH: owner reset receipt fixture does not match the declared fixture.') }
    if ([bool]$result['resetOk'] -and [bool]$result['baselineOk']) {
        return @{ runId = $runId; fixtureName = $fixtureName; baselineVerified = $true; contaminationScope = 'none'; resetState = 'GroupInitialization' }
    }
    return @{ runId = $runId; fixtureName = $fixtureName; baselineVerified = $false; contaminationScope = 'group'; resetState = 'GroupContaminated'; resetOk = [bool]$result['resetOk']; baselineOk = [bool]$result['baselineOk'] }
}
function Invoke-RuntimeCollectEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][AllowEmptyString()][string]$TerminalState, [Parameter(Mandatory)][AllowEmptyString()][string]$LogText, [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$Secrets, [ValidateRange(1, 16777216)][int]$MaxBytes = 65536)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    [void](Test-RuntimeTerminalDisposition -Disposition $TerminalState)
    $redacted = Get-RuntimeRedactedText -Text $LogText -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) {
        return @{ runId = [string]$Binding['runId']; terminalState = $TerminalState; evidenceState = 'EvidenceCollectionFailed'; bytes = 0; truncated = $false; redactionFailed = $true; owner = [string]$Binding['owner'] }
    }
    return @{ runId = [string]$Binding['runId']; testClass = $Script:RuntimeTestClass; providerRevision = $Script:RuntimeProviderRevision; generation = [int]$Binding['generation']; owner = [string]$Binding['owner']; evidenceId = ('ev-' + ([string]$Binding['runId']).Substring(0, 8)); terminalState = $TerminalState; evidenceState = 'TerminalTestEvidence'; bytes = [int]$redacted.bytes; truncated = [bool]$redacted.truncated; text = [string]$redacted.text }
}
function Invoke-RuntimeStop {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$StartReceipt, [Parameter(Mandatory)][AllowNull()][scriptblock]$ProcessController, [Parameter()][AllowNull()][scriptblock]$Clock)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    [void](Resolve-RuntimeDeadline -Binding $Binding -Clock $Clock -Operation 'Stop')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: start receipt run identity is foreign.') }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable])) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt carries no observed pids.') }
    $ownedPids = @{}
    foreach ($component in $Script:RuntimeComponents) {
        $entry = $null
        if ($StartReceipt['observed'].ContainsKey($component)) { $entry = $StartReceipt['observed'][$component] }
        if ($null -eq $entry -or ($entry -isnot [hashtable]) -or -not $entry.ContainsKey('pid')) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-STALE: start receipt has no observed pid for '$component'.") }
        $ownedPid = 0
        try { $ownedPid = [int]$entry['pid'] } catch { throw [System.ArgumentException]::new("RUNTIME-INVALID-PID: owned pid is not an integer for '$component'.") }
        if ($ownedPid -le 0) { throw [System.ArgumentException]::new("RUNTIME-INVALID-PID: owned pid is not positive for '$component'.") }
        $ownedPids[$component] = $ownedPid
    }
    if ($null -eq $ProcessController) { throw [System.ArgumentException]::new('RUNTIME-MISSING-CONTROLLER: a process-controller seam is required.') }
    $stopOrder = New-Object Collections.Generic.List[string]
    $componentStates = @{}
    foreach ($component in $Script:RuntimeComponents) { $componentStates[$component] = 'stop-unknown' }
    $forced = $false
    foreach ($phaseName in @('graceful', 'forced')) {
        if ($phaseName -ceq 'forced' -and -not $forced) {
            $pending = $false
            foreach ($component in $Script:RuntimeComponents) { if ($componentStates[$component] -cne 'process-exited') { $pending = $true } }
            if (-not $pending) { break }
        }
        if ($phaseName -ceq 'forced') { $forced = $true }
        foreach ($component in $Script:RuntimeShutdownOrder) {
            if ($phaseName -ceq 'forced' -and $componentStates[$component] -ceq 'process-exited') { continue }
            $phase = (& $ProcessController @{ phase = $phaseName; component = $component; pid = $ownedPids[$component]; runId = $runId })
            if ($null -eq $phase) {
                return @{ runId = $runId; stopState = 'ReconciliationRequired'; requestedStop = $true; stopOrder = @($stopOrder); forced = $forced; retryPermitted = $false; failure = ("unknown-stop-owned:{0}:{1}" -f $component, $phaseName) }
            }
            if ($phase -isnot [hashtable] -or -not $phase.ContainsKey('exited')) { throw [System.InvalidOperationException]::new("RUNTIME-CONTROLLER-FAILED: $phaseName phase must return an exited mapping for '$component'.") }
            if ($phase.ContainsKey('pid') -and ([int]$phase['pid'] -ne [int]$ownedPids[$component])) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-PROCESS: controller touched a foreign pid for '$component'; PID reuse is rejected.") }
            [void]$stopOrder.Add(($phaseName + ':' + $component))
            if ([bool]$phase['exited']) { $componentStates[$component] = 'process-exited' }
        }
    }
    $phase = 'graceful'
    if ($forced) { $phase = 'forced' }
    return @{ runId = $runId; stopPhase = $phase; stopState = 'ShutdownRequested'; stopOrder = @($stopOrder); componentStates = $componentStates; ownedPids = $ownedPids; forced = $forced }
}
function Invoke-RuntimeVerifyCleanup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][hashtable]$StartReceipt, [Parameter()][AllowNull()][scriptblock]$ProcessObserver, [Parameter()][AllowNull()][scriptblock]$JobObserver, [Parameter()][AllowNull()][scriptblock]$PipeObserver, [Parameter()][AllowNull()][scriptblock]$HandleProbe)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: allocation run identity is foreign.') }
    foreach ($field in @('runRoot', 'installationRoot', 'sessionRoot', 'configRoot', 'dataRoot', 'logRoot', 'tempRoot', 'artifactRoot', 'pipeNamespace')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing '$field'.") }
    }
    $runRoot = [System.IO.Path]::GetFullPath([string]$Allocation['runRoot'])
    $runLeaf = [System.IO.Path]::GetFileName($runRoot)
    if ([string]::IsNullOrWhiteSpace($runLeaf) -or -not $runLeaf.Contains($runId)) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: cleanup run root leaf does not carry the run identity: $runRoot") }
    $runPrefix = $runRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($rootField in @('installationRoot', 'sessionRoot', 'configRoot', 'dataRoot', 'logRoot', 'tempRoot', 'artifactRoot')) {
        $rootFull = [System.IO.Path]::GetFullPath([string]$Allocation[$rootField])
        if ($rootFull -ine $runRoot -and -not $rootFull.StartsWith($runPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: allocation root '$rootField' escapes the owned run root.") }
    }
    [void](Resolve-RuntimeOwnedPath -RunRoot $runRoot -Path $runRoot -ExpectedRunId $runId)
    $failures = New-Object Collections.Generic.List[string]
    $ownedPids = @{}
    if ($null -ne $StartReceipt['observed'] -and $StartReceipt['observed'] -is [hashtable]) {
        foreach ($component in $Script:RuntimeComponents) {
            if ($StartReceipt['observed'].ContainsKey($component) -and ($StartReceipt['observed'][$component] -is [hashtable]) -and $StartReceipt['observed'][$component].ContainsKey('pid')) {
                try { $ownedPids[$component] = [int]$StartReceipt['observed'][$component]['pid'] } catch { }
            }
        }
    }
    if ($null -ne $ProcessObserver) {
        foreach ($component in @($ownedPids.Keys)) {
            $process = (& $ProcessObserver @{ pid = $ownedPids[$component]; runId = $runId; component = $component })
            if ($null -ne $process -and $process -is [hashtable]) {
                if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne [int]$ownedPids[$component])) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-PROCESS: cleanup observer returned a foreign pid for '$component'.") }
                if ($process.ContainsKey('alive') -and [bool]$process['alive']) { [void]$failures.Add(('process-still-alive:' + $component)) }
                if ($process.ContainsKey('descendants') -and $null -ne $process['descendants'] -and @($process['descendants']).Count -gt 0) { [void]$failures.Add(('descendants-remaining:' + $component + ':' + @($process['descendants']).Count)) }
            }
        }
    }
    if ($null -ne $JobObserver) {
        $job = (& $JobObserver @{ runId = $runId; pipeNamespace = [string]$Allocation['pipeNamespace'] })
        if ($null -ne $job -and $job -is [hashtable]) {
            if ($job.ContainsKey('pipeNamespace') -and ([string]$job['pipeNamespace'] -cne [string]$Allocation['pipeNamespace'])) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: cleanup job observer returned a foreign namespace.') }
            if ($job.ContainsKey('jobAlive') -and [bool]$job['jobAlive']) { [void]$failures.Add('job-still-active') }
            if ($job.ContainsKey('members') -and $null -ne $job['members'] -and @($job['members']).Count -gt 0) { [void]$failures.Add(('job-members-remaining:' + @($job['members']).Count)) }
        }
    }
    if ($null -ne $PipeObserver) {
        $pipes = (& $PipeObserver @{ pipeNamespace = [string]$Allocation['pipeNamespace']; runId = $runId })
        if ($null -ne $pipes -and $pipes -is [hashtable]) {
            if ($pipes.ContainsKey('pipeNamespace') -and ([string]$pipes['pipeNamespace'] -cne [string]$Allocation['pipeNamespace'])) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: cleanup pipe observer returned a foreign namespace.') }
            if ($pipes.ContainsKey('pipesOpen') -and [bool]$pipes['pipesOpen']) { [void]$failures.Add('pipes-still-open') }
        }
    }
    if ($null -ne $HandleProbe) {
        $probe = (& $HandleProbe @{ runRoot = $runRoot; runId = $runId })
        if ($null -ne $probe -and $probe -is [hashtable]) {
            if ($probe.ContainsKey('runRoot') -and ([System.IO.Path]::GetFullPath([string]$probe['runRoot']) -ine $runRoot)) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: cleanup handle probe returned a foreign root.') }
            foreach ($flag in @('handlesHeld', 'locksHeld', 'mutexHeld', 'secretsPresent', 'rootsPresent')) {
                if ($probe.ContainsKey($flag) -and [bool]$probe[$flag]) { [void]$failures.Add(($flag -creplace '([A-Z])', '-$1').ToLowerInvariant()) }
            }
            if ($probe.ContainsKey('entries')) {
                foreach ($entry in @($probe['entries'])) {
                    if ([string]$entry -cnotin $Script:RuntimeAllowedRootChildren) { [void]$failures.Add(('foreign-entry-preserved:' + [string]$entry)) }
                }
            }
        }
    } elseif (Test-Path -LiteralPath $runRoot) {
        $entries = @(Get-ChildItem -LiteralPath $runRoot -Force -ErrorAction SilentlyContinue)
        foreach ($entry in $entries) {
            if ($entry.Name -cnotin $Script:RuntimeAllowedRootChildren) { [void]$failures.Add(('foreign-entry-preserved:' + $entry.Name)) }
        }
        if ($entries.Count -gt 0) { [void]$failures.Add('roots-present') }
    }
    if ($failures.Count -gt 0) { return @{ runId = $runId; cleanupState = 'ReconciliationRequired'; cleaned = $false; failures = @($failures); ownedRoot = $runRoot } }
    return @{ runId = $runId; cleanupState = 'AllResourcesReaped'; cleaned = $true; failures = @(); ownedRoot = $runRoot }
}
function Resolve-RuntimeGovernorConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$ConfigReceipt)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    foreach ($field in @('configName', 'version', 'runId', 'channel', 'digest')) {
        if (-not $ConfigReceipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$ConfigReceipt[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-CONFIG: governor config receipt is missing '$field'.") }
    }
    $configSpec = @{ configName = $Script:RuntimeGovernorConfigName; version = $Script:RuntimeGovernorConfigVersion; channel = $Script:RuntimeGovernorConfigChannel }
    foreach ($field in @($configSpec.Keys)) {
        if ([string]$ConfigReceipt[$field] -cne $configSpec[$field]) { throw [System.InvalidOperationException]::new("RUNTIME-CONFIG-PROVENANCE: governor config field '$field' is not the accepted run-local value; ambient, production, and default sources are rejected.") }
    }
    if ([string]$ConfigReceipt['runId'] -cne [string]$Binding['runId']) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-PROVENANCE: governor config receipt run identity is foreign.') }
    [void](Test-RuntimeDigestFormat -Digest ([string]$ConfigReceipt['digest']))
    return @{ runId = [string]$Binding['runId']; configName = $Script:RuntimeGovernorConfigName; version = $Script:RuntimeGovernorConfigVersion; channel = $Script:RuntimeGovernorConfigChannel; digest = [string]$ConfigReceipt['digest']; provenance = 'run-local-config-receipt'; accepted = $true }
}
Export-ModuleMember -Function @('Get-RuntimeProviderIdentity', 'Get-RuntimeLockIdentity', 'Get-RuntimeClosedOperations', 'Get-RuntimeTerminalDispositions', 'Test-RuntimeDigestFormat', 'Test-RuntimeClosedOperation', 'Test-RuntimeTerminalDisposition', 'Resolve-RuntimeDeadline', 'Test-RuntimeBindingShape', 'Test-RuntimeProviderResultClosed', 'Invoke-RuntimeProviderOperation', 'Invoke-RuntimeValidateRequirement', 'Invoke-RuntimePlan', 'Resolve-RuntimeOwnedPath', 'Get-RuntimeChildEnv', 'New-RuntimeEphemeralCredential', 'Test-RuntimePrincipalShape', 'Test-RuntimeProviderReceipt', 'Get-RuntimeRedactedText', 'Invoke-RuntimeAllocate', 'Invoke-RuntimeStart', 'Invoke-RuntimeObserveReadiness', 'Invoke-RuntimeResetForTest', 'Invoke-RuntimeCollectEvidence', 'Invoke-RuntimeStop', 'Invoke-RuntimeVerifyCleanup', 'Resolve-RuntimeGovernorConfig')
