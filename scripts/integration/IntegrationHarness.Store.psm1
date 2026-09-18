# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Store — authenticated isolated SurrealDB 3.1.4 provider for issue #909.
#
# This module holds the Store provider BEHAVIOR behind the closed 9-operation
# provider interface (ValidateRequirement, Plan, Allocate, Start,
# ObserveReadiness, ResetForTest, CollectEvidence, Stop, VerifyCleanup).
# It mirrors the Core.psm1 Invoke pattern: a closed dispatcher validates the
# operation name, the binding shape, and the deadline via an injected clock,
# invokes the operation scriptblock, and validates the result carries no
# forbidden authority (testDenominator/providerChoice/command/argv/executable/
# shellCommand/testPassed/markPassed/verdictOverride).
#
# Fail-closed rules enforced here:
# - Exact Store class (STORE) plus provider revision plus lock identity
#   (surreal.exe 3.1.4 windows-x64 pe 8664 sha
#   13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1).
#   Unsupported class or revision is rejected; there is no fallback provider.
# - Plan is finite and mutation-free: it returns Approve-Plan shaped resources
#   (resourceKey/runId/testClass/providerRevision/owner/generation) and never
#   carries shellCommand/executablePath/rawArgv/url/credential/environmentMap/
#   outputPath. Plan performs no filesystem, process, port, or network action.
# - Allocate mints unique owned data/log/secret roots under the admitted run
#   root with the owner marker eliot-harness-owned-root-v1, derives
#   namespace/database from the run identity, and reserves a loopback endpoint
#   through an ownership-safe reservation protocol (injected reservation only;
#   no bind here).
# - Start verifies the approved executable version/platform/arch/digest plus
#   acquisition provenance before execution, including cached binaries which
#   are re-verified. It rejects latest/missing/caller-hash/wrong version or
#   arch. Invocation is fixed from typed accepted fields only; arbitrary
#   executable/URL/argv/env input is unrepresentable.
# - ObserveReadiness binds exact process/start/endpoint identity plus an
#   authenticated protocol handshake plus namespace/database selection plus
#   schema identity. Process-alive, TCP-open, authenticated, schema-ready, and
#   fixture-ready are separate receipts; liveness without auth is not readiness.
# - ResetForTest requires the exact declared fixture plus baseline
#   revalidation; a reset failure contaminates exactly its group, never the run.
# - CollectEvidence returns bounded redacted handles with truncation; it
#   redacts credential/query/source/data canaries and never emits secrets.
# - Stop performs a bounded graceful phase then exact-owned-tree termination
#   of the observed PID only; never by name, port, or unverified PID.
# - VerifyCleanup checks process descendants, port, locks, secrets, and roots;
#   it is idempotent and never deletes foreign state.
# - Paths are canonicalized under the admitted run root (traversal, reparse,
#   symlink, reserved device names, and foreign owner markers are rejected).
# - Child environments are minimal and allowlisted; ephemeral credentials live
#   in memory and protected channels only, never in display text, receipts, or
#   logs. Run, provider, binary, config, process, start, endpoint, namespace,
#   database, root, and credential-handle identities plus deadlines are bound
#   on every operation. Terminal dispositions follow the closed I07-20 set;
#   this provider never carries testPassed or verdictOverride authority.
#
# Clocks, process/port observers, Store clients, entropy, acquisition,
# launchers, controllers, and file probes are injected; this module never
# downloads anything, never spawns live processes/ports, and never sleeps.
#
# Proof ceiling: STORE-PROVIDER-ISOLATED-ONLY (fake-seam proof; no live
# SurrealDB, no download, no cargo test).

Set-StrictMode -Version Latest

$Script:StoreTestClass = 'STORE'
$Script:StoreProviderName = 'eliot-store-surreal-isolated'
$Script:StoreProviderRevision = 'eliot.integration.store-provider.v1'
$Script:StoreInterfaceVersion = 'eliot.integration.harness-provider.v1'
$Script:StoreArtifact = 'surreal.exe'
$Script:StoreRelativePath = 'runtime/surreal.exe'
$Script:StoreVersion = '3.1.4'
$Script:StoreArchitecture = 'windows-x64'
$Script:StorePlatform = 'windows'
$Script:StoreArch = 'x64'
$Script:StorePeMachine = '8664'
$Script:StoreDigest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
$Script:StoreOwnedRootMarker = 'eliot-harness-owned-root-v1'
$Script:StoreLoopback = '127.0.0.1'

$Script:StoreClosedOperations = @(
    'ValidateRequirement',
    'Plan',
    'Allocate',
    'Start',
    'ObserveReadiness',
    'ResetForTest',
    'CollectEvidence',
    'Stop',
    'VerifyCleanup'
)

$Script:StoreTerminalDispositions = @(
    'Passed',
    'AssertionFailed',
    'TimedOut',
    'ProcessCrashed',
    'InfrastructureBlocked',
    'UnsupportedExternalCredential',
    'HarnessError',
    'Cancelled',
    'NotExecutedDueToPriorContamination'
)

$Script:StoreForbiddenPlanKeys = @(
    'shellCommand',
    'executablePath',
    'rawArgv',
    'url',
    'credential',
    'environmentMap',
    'outputPath'
)

$Script:StoreForbiddenResultKeys = @(
    'testDenominator',
    'providerChoice',
    'chooseProvider',
    'command',
    'argv',
    'executable',
    'shellCommand',
    'testPassed',
    'markPassed',
    'verdictOverride'
)

$Script:StoreAllowedChildEnv = @(
    'PATH',
    'SystemRoot',
    'TEMP',
    'TMP',
    'OS',
    'PATHEXT',
    'COMSPEC'
)

$Script:StoreAllowedRootChildren = @(
    '.eliot-harness-owner.json',
    'data',
    'logs',
    'secrets'
)

$Script:StoreReservedLeafPattern = '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'

function Get-StoreProviderIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        interfaceVersion = $Script:StoreInterfaceVersion
        artifact         = $Script:StoreArtifact
        relativePath     = $Script:StoreRelativePath
        version          = $Script:StoreVersion
        architecture     = $Script:StoreArchitecture
        peMachine        = $Script:StorePeMachine
        digest           = $Script:StoreDigest
    }
}

function Get-StoreLockIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        artifact     = $Script:StoreArtifact
        relativePath = $Script:StoreRelativePath
        version      = $Script:StoreVersion
        architecture = $Script:StoreArchitecture
        peMachine    = $Script:StorePeMachine
        sha256       = $Script:StoreDigest
    }
}

function Get-StoreClosedOperations {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:StoreClosedOperations)
}

function Get-StoreTerminalDispositions {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:StoreTerminalDispositions)
}

function Test-StoreDigestFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Digest
    )
    if ([string]::IsNullOrWhiteSpace($Digest)) {
        throw [System.ArgumentException]::new('STORE-INVALID-DIGEST: digest is empty.')
    }
    if ($Digest -cnotmatch '^[0-9a-f]{64}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-DIGEST: digest must be 64 lowercase hex.')
    }
    return $true
}

function Test-StoreClosedOperation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Operation
    )
    if ([string]::IsNullOrWhiteSpace($Operation)) {
        throw [System.ArgumentException]::new('STORE-UNKNOWN-OPERATION: operation name is empty.')
    }
    foreach ($allowed in $Script:StoreClosedOperations) {
        if ($Operation -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "STORE-UNKNOWN-OPERATION: '$Operation' is not a member of the closed Store provider interface.")
}

function Test-StoreTerminalDisposition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Disposition
    )
    if ([string]::IsNullOrWhiteSpace($Disposition)) {
        throw [System.ArgumentException]::new('STORE-INVALID-DISPOSITION: disposition is empty.')
    }
    foreach ($allowed in $Script:StoreTerminalDispositions) {
        if ($Disposition -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "STORE-INVALID-DISPOSITION: '$Disposition' is not an accepted terminal disposition.")
}

function Resolve-StoreDeadline {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter(Mandatory)]
        [string]$Operation
    )
    if (-not $Binding.ContainsKey('deadlineUtc') -or [string]::IsNullOrWhiteSpace([string]$Binding['deadlineUtc'])) {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: binding is missing deadlineUtc.')
    }
    $deadline = [System.DateTimeOffset]::Parse([string]$Binding['deadlineUtc'])
    $now = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observed = (& $Clock)
        if ($observed -is [System.DateTimeOffset]) {
            $now = $observed
        } elseif ($observed -is [System.DateTime]) {
            $now = [System.DateTimeOffset]::new($observed.ToUniversalTime())
        } else {
            throw [System.ArgumentException]::new('STORE-INVALID-CLOCK: injected clock must return DateTimeOffset.')
        }
    }
    $remaining = [int]($deadline - $now).TotalSeconds
    if ($remaining -le 0) {
        throw [System.TimeoutException]::new("STORE-DEADLINE-EXCEEDED: operation '$Operation' has no remaining bound.")
    }
    return $remaining
}

function Test-StoreBindingShape {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    $runId = [string]$Binding['runId']
    if ($runId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: runId must be 32 lowercase hex.')
    }
    $gen = 0
    try { $gen = [int]$Binding['generation'] } catch {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: generation must be a positive integer.')
    }
    if ($gen -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: generation must be positive.')
    }
    foreach ($key in @($Binding.Keys)) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "STORE-BINDING-FORBIDDEN: binding must not carry '$key'.")
            }
        }
    }
    return $true
}

function Test-StoreProviderResultClosed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in $Script:StoreForbiddenResultKeys) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "STORE-PROVIDER-FORBIDDEN: provider result must not contain '$key'.")
            }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) {
        throw [System.InvalidOperationException]::new('STORE-PROVIDER-FORBIDDEN: provider must not change the run identity.')
    }
    return $true
}

function Invoke-StoreProviderOperation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Operation,
        [Parameter(Mandatory)]
        [hashtable]$Provider,
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter()]
        [hashtable]$Arguments,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    [void](Test-StoreClosedOperation -Operation $Operation)
    if ($null -eq $Provider -or $Provider.Count -eq 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PROVIDER: provider table is empty.')
    }
    if (-not $Provider.ContainsKey($Operation)) {
        throw [System.ArgumentException]::new("STORE-UNKNOWN-OPERATION: provider has no implementation for '$Operation'.")
    }
    $implementation = $Provider[$Operation]
    if ($implementation -isnot [scriptblock]) {
        throw [System.ArgumentException]::new("STORE-INVALID-PROVIDER: operation '$Operation' must map to a scriptblock.")
    }
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation $Operation)
    $context = @{
        operation = $Operation
        binding   = $Binding
        arguments = $Arguments
    }
    $raw = $null
    try {
        $raw = (& $implementation $context)
    } catch {
        throw [System.InvalidOperationException]::new(
            "STORE-PROVIDER-FAILED:$Operation : $($_.Exception.Message)")
    }
    if ($null -eq $raw) {
        throw [System.InvalidOperationException]::new("STORE-PROVIDER-FAILED:$Operation : provider returned no result.")
    }
    $result = @{}
    if ($raw -is [hashtable]) {
        $result = $raw
    } elseif ($raw -is [psobject]) {
        foreach ($prop in $raw.PSObject.Properties) {
            $result[[string]$prop.Name] = $prop.Value
        }
    } else {
        throw [System.InvalidOperationException]::new(
            "STORE-PROVIDER-FAILED:$Operation : provider result must be a hashtable.")
    }
    [void](Test-StoreProviderResultClosed -Result $result -Binding $Binding)
    return $result
}

function Invoke-StoreValidateRequirement {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requirement,
        [Parameter(Mandatory)]
        [hashtable]$Lock
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    foreach ($field in @('testClass', 'providerRevision')) {
        if (-not $Requirement.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Requirement[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-REQUIREMENT: requirement is missing '$field'.")
        }
    }
    $reqClass = [string]$Requirement['testClass']
    if ($reqClass -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new(
            "STORE-UNSUPPORTED-CLASS: requirement class '$reqClass' is not STORE.")
    }
    $reqRev = [string]$Requirement['providerRevision']
    if ($reqRev -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new(
            "STORE-UNSUPPORTED-REVISION: provider revision '$reqRev' is not '$($Script:StoreProviderRevision)'.")
    }
    if ([string]$Binding['testClass'] -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding testClass is not STORE.')
    }
    if ([string]$Binding['providerRevision'] -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding providerRevision mismatch.')
    }
    if ([string]$Binding['providerName'] -cne $Script:StoreProviderName) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding providerName mismatch.')
    }
    foreach ($field in @('version', 'architecture', 'peMachine', 'sha256', 'artifact')) {
        if (-not $Lock.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Lock[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-LOCK: lock is missing '$field'.")
        }
    }
    if ([string]$Lock['version'] -cne $Script:StoreVersion) {
        throw [System.InvalidOperationException]::new(
            "STORE-LOCK-MISMATCH: lock version '$($Lock['version'])' is not '$($Script:StoreVersion)'.")
    }
    if ([string]$Lock['architecture'] -cne $Script:StoreArchitecture) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock architecture mismatch.')
    }
    if ([string]$Lock['peMachine'] -cne $Script:StorePeMachine) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock peMachine mismatch.')
    }
    if ([string]$Lock['artifact'] -cne $Script:StoreArtifact) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock artifact mismatch.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$Lock['sha256']))
    if ([string]$Lock['sha256'] -cne $Script:StoreDigest) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock digest does not match the pinned SurrealDB identity.')
    }
    return @{
        runId            = [string]$Binding['runId']
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        version          = $Script:StoreVersion
        architecture     = $Script:StoreArchitecture
        peMachine        = $Script:StorePeMachine
        digest           = $Script:StoreDigest
        artifact         = $Script:StoreArtifact
        accepted         = $true
    }
}

function Invoke-StorePlan {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requirement
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    if ([string]$Requirement['testClass'] -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new('STORE-UNSUPPORTED-CLASS: plan requirement class is not STORE.')
    }
    if ([string]$Requirement['providerRevision'] -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new('STORE-UNSUPPORTED-REVISION: plan requirement revision mismatch.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $resources = @(
        @{ resourceKey = 'surreal-data'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen },
        @{ resourceKey = 'surreal-logs'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen },
        @{ resourceKey = 'surreal-secrets'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen }
    )
    foreach ($resource in $resources) {
        foreach ($key in @($resource.Keys)) {
            foreach ($forbidden in $Script:StoreForbiddenPlanKeys) {
                if ([string]$key -ieq $forbidden) {
                    throw [System.InvalidOperationException]::new(
                        "STORE-PLAN-FORBIDDEN: plan resource must not carry '$key'.")
                }
            }
        }
    }
    return @{
        runId            = $runId
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        owner            = $owner
        generation       = $gen
        resources        = $resources
        mutationFree     = $true
    }
}

function Resolve-StoreOwnedPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ExpectedRunId
    )
    if ([string]::IsNullOrWhiteSpace($RunRoot)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: RunRoot is empty.')
    }
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: Path is empty.')
    }
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.')
    }
    $rootFull = [System.IO.Path]::GetFullPath($RunRoot)
    $candidate = $Path
    if (-not [System.IO.Path]::IsPathFullyQualified($candidate)) {
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $candidate))
    } else {
        $candidate = [System.IO.Path]::GetFullPath($candidate)
    }
    $prefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ine $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("STORE-PATH-ESCAPE: path escapes the admitted run root: $candidate")
    }
    $leaf = [System.IO.Path]::GetFileName($candidate)
    if (-not [string]::IsNullOrEmpty($leaf) -and $leaf -match $Script:StoreReservedLeafPattern) {
        throw [System.InvalidOperationException]::new("STORE-RESERVED-PATH: reserved device name rejected: $leaf")
    }
    foreach ($segment in ($candidate.Substring($rootFull.Length).Split([System.IO.Path]::DirectorySeparatorChar))) {
        if ($segment -match $Script:StoreReservedLeafPattern) {
            throw [System.InvalidOperationException]::new("STORE-RESERVED-PATH: reserved device segment rejected: $segment")
        }
    }
    $probe = $candidate
    while ($null -ne $probe -and $probe.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw [System.InvalidOperationException]::new("STORE-REPARSE-ESCAPE: path crosses a reparse point: $($entry.FullName)")
            }
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
                if ($recorded.run_id -cne $ExpectedRunId) {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker belongs to another run: $cursor")
                }
            } catch [System.InvalidOperationException] {
                throw
            } catch {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker unreadable at: $cursor")
            }
            break
        }
        if ($cursor -ieq $rootFull) { break }
        $next = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($next) -or $next -eq $cursor) { break }
        $cursor = $next
    }
    return $candidate
}

function Get-StoreChildEnv {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Ambient
    )
    $filtered = @{}
    foreach ($key in @($Ambient.Keys)) {
        if ($key -cnotin $Script:StoreAllowedChildEnv) { continue }
        $upper = ([string]$key).ToUpperInvariant()
        if ($upper.Contains('TOKEN') -or $upper.Contains('SECRET') -or $upper.Contains('CREDENTIAL') -or $upper.Contains('PASSWORD') -or $upper.Contains('KEY')) {
            continue
        }
        $value = [string]$Ambient[$key]
        $bytes = [System.Text.Encoding]::UTF8.GetByteCount($value)
        if ($bytes -gt 4096) {
            throw [System.InvalidOperationException]::new("STORE-ENV-BOUND: child env value exceeds byte cap: $key")
        }
        $filtered[$key] = $value
    }
    return $filtered
}

function New-StoreEphemeralCredential {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$CredentialId,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy
    )
    if ([string]::IsNullOrWhiteSpace($CredentialId)) {
        throw [System.ArgumentException]::new('STORE-INVALID-CREDENTIAL: credential id is empty.')
    }
    if ($CredentialId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-CREDENTIAL: credential id has an invalid shape.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or [string]::IsNullOrWhiteSpace($nonce)) {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return nonempty text.')
        }
    } else {
        $bytes = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $nonce = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    }
    if ($nonce -cnotmatch '^[0-9a-f]{16,128}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy nonce must be lowercase hex.')
    }
    $secret = ('store-ephemeral-' + $nonce)
    return @{
        credentialId     = $CredentialId
        credentialHandle = ('handle:' + $CredentialId + ':' + $nonce.Substring(0, 8))
        secret           = $secret
        ephemeral        = $true
    }
}

function Get-StoreRedactedText {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secrets,
        [ValidateRange(1, 16777216)]
        [int]$MaxBytes = 65536
    )
    $redacted = $Text
    try {
        if ($null -ne $Secrets) {
            foreach ($secret in $Secrets) {
                if ([string]::IsNullOrEmpty($secret)) { continue }
                $redacted = $redacted.Replace($secret, '[redacted-store-secret]')
            }
        }
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring)\s*[:=]\s*\S+',
            '$1=[redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)surreal_[a-z_]*(pass|secret|token|key)[a-z_]*\s*=\s*\S+',
            '[redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)CONTENT\s*\{[^}]{0,4096}\}',
            'CONTENT [redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)[A-Za-z]:\\Users\\[^\\/:*?"<>|]+',
            '[redacted-user-path]')
    } catch {
        return [pscustomobject]@{
            text      = ''
            bytes     = 0
            truncated = $false
            failed    = $true
        }
    }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($redacted)
    } catch {
        return [pscustomobject]@{
            text      = ''
            bytes     = 0
            truncated = $false
            failed    = $true
        }
    }
    $truncated = $bytes.Length -gt $MaxBytes
    $output = $redacted
    if ($truncated) {
        try {
            $output = [System.Text.Encoding]::UTF8.GetString($bytes, $bytes.Length - $MaxBytes, $MaxBytes)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
        } catch {
            return [pscustomobject]@{
                text      = ''
                bytes     = 0
                truncated = $true
                failed    = $true
            }
        }
    }
    return [pscustomobject]@{
        text      = $output
        bytes     = $bytes.Length
        truncated = $truncated
        failed    = $false
    }
}

function Invoke-StoreAllocate {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Plan,
        [Parameter(Mandatory)]
        [string]$BaseTemp,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortReservation
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    if ([string]$Plan['runId'] -cne [string]$Binding['runId']) {
        throw [System.InvalidOperationException]::new('STORE-ALLOCATION-MISMATCH: plan run identity does not match binding.')
    }
    if ([string]::IsNullOrWhiteSpace($BaseTemp)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: BaseTemp is empty.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $baseFull = [System.IO.Path]::GetFullPath($BaseTemp)
    $lower = $baseFull.ToLowerInvariant()
    if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) {
        throw [System.InvalidOperationException]::new('STORE-FORBIDDEN-ROOT: allocation base crossed a forbidden host boundary.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return lowercase hex.')
        }
    } else {
        $nonce = $runId.Substring(0, 8)
    }
    $runRoot = [System.IO.Path]::GetFullPath((Join-Path $baseFull ("eliot-store-{0}-{1}" -f $runId, $nonce)))
    $prefix = $baseFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $runRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("STORE-PATH-ESCAPE: allocated run root escaped its base: $runRoot")
    }
    $dataRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'data'))
    $logRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'logs'))
    $secretRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'secrets'))
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $dataRoot -ExpectedRunId $runId)
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $logRoot -ExpectedRunId $runId)
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $secretRoot -ExpectedRunId $runId)
    $namespace = ('eliot_ns_' + $runId.Substring(0, 8))
    $database = ('eliot_db_' + $runId.Substring(8, 8))
    if ($namespace -cnotmatch '^[A-Za-z0-9_]{1,64}$' -or $database -cnotmatch '^[A-Za-z0-9_]{1,64}$') {
        throw [System.InvalidOperationException]::new('STORE-ALLOCATION-MISMATCH: derived namespace/database has an invalid shape.')
    }
    if ($null -eq $PortReservation) {
        throw [System.ArgumentException]::new('STORE-MISSING-RESERVATION: a port-reservation seam is required; no implicit bind is performed.')
    }
    $reservation = $null
    try {
        $reservation = (& $PortReservation @{ runId = $runId; namespace = $namespace; database = $database })
    } catch {
        throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: reservation failed: $($_.Exception.Message)")
    }
    $port = 0
    if ($reservation -is [hashtable] -and $reservation.ContainsKey('port')) {
        try { $port = [int]$reservation['port'] } catch {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: reservation port is not an integer.')
        }
    } elseif ($reservation -is [int]) {
        $port = $reservation
    } else {
        throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: reservation must return a port mapping.')
    }
    if ($port -lt 1024 -or $port -gt 65535) {
        throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: reserved port '$port' is outside the ephemeral bound.")
    }
    $host_ = $Script:StoreLoopback
    if ($reservation -is [hashtable] -and $reservation.ContainsKey('host')) {
        $host_ = [string]$reservation['host']
    }
    if ($host_ -cne $Script:StoreLoopback) {
        throw [System.InvalidOperationException]::new("STORE-ENDPOINT-FORBIDDEN: endpoint host '$host_' is not loopback.")
    }
    $endpoint = ('{0}:{1}' -f $host_, $port)
    return @{
        runId          = $runId
        runRoot        = $runRoot
        dataRoot       = $dataRoot
        logRoot        = $logRoot
        secretRoot     = $secretRoot
        ownerMarker    = $Script:StoreOwnedRootMarker
        namespace      = $namespace
        database       = $database
        endpoint       = $endpoint
        host           = $host_
        port           = $port
        owner          = $owner
        generation     = $gen
        allocationSeed = $nonce
    }
}

function Invoke-StoreStart {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Acquisition,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Launcher,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-START-MISMATCH: allocation run identity does not match binding.')
    }
    foreach ($field in @('endpoint', 'namespace', 'database', 'dataRoot', 'runRoot')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-ALLOCATION: allocation is missing '$field'.")
        }
    }
    if ($null -eq $Acquisition) {
        throw [System.ArgumentException]::new('STORE-MISSING-ACQUISITION: an acquisition seam is required; no download is performed here.')
    }
    $receipt = $null
    try {
        $receipt = (& $Acquisition @{ runId = $runId; artifact = $Script:StoreArtifact })
    } catch {
        throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: $($_.Exception.Message)")
    }
    if ($null -eq $receipt -or $receipt -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-ACQUISITION-FAILED: acquisition must return a hashtable receipt.')
    }
    foreach ($field in @('version', 'architecture', 'peMachine', 'digest', 'provenance', 'storePath')) {
        if (-not $receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$receipt[$field])) {
            throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: receipt is missing '$field'.")
        }
    }
    $version = [string]$receipt['version']
    if ($version -ieq 'latest') {
        throw [System.InvalidOperationException]::new('STORE-LATEST-REJECTED: floating latest tag is never accepted.')
    }
    if ($version -cne $Script:StoreVersion) {
        throw [System.InvalidOperationException]::new("STORE-VERSION-MISMATCH: version '$version' is not '$($Script:StoreVersion)'.")
    }
    if ([string]$receipt['architecture'] -cne $Script:StoreArchitecture) {
        throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: architecture mismatch.')
    }
    if ([string]$receipt['peMachine'] -cne $Script:StorePeMachine) {
        throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: peMachine mismatch.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$receipt['digest']))
    if ([string]$receipt['digest'] -cne $Script:StoreDigest) {
        throw [System.InvalidOperationException]::new('STORE-DIGEST-MISMATCH: binary digest does not match the pinned SurrealDB identity.')
    }
    $provenance = [string]$receipt['provenance']
    if ($provenance -cne 'acquired-verified' -and $provenance -cne 'cached-reverified') {
        if ($provenance -ieq 'caller-hash' -or $provenance -ieq 'caller-supplied') {
            throw [System.InvalidOperationException]::new('STORE-CALLER-HASH-REJECTED: caller-supplied hashes never establish provenance.')
        }
        throw [System.InvalidOperationException]::new("STORE-PROVENANCE-MISSING: provenance '$provenance' is not an accepted verified acquisition.")
    }
    $storePath = [string]$receipt['storePath']
    if (-not $storePath.EndsWith($Script:StoreArtifact, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new('STORE-ACQUISITION-FAILED: store path does not name the approved artifact.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return lowercase hex.')
        }
    } else {
        $nonce = $runId.Substring(16, 8)
    }
    $fixedArgv = @(
        $storePath,
        'start',
        '--bind', ([string]$Allocation['endpoint']),
        '--ns', ([string]$Allocation['namespace']),
        '--db', ([string]$Allocation['database']),
        '--data-dir', ([string]$Allocation['dataRoot'])
    )
    $childEnv = Get-StoreChildEnv -Ambient @{
        PATH = [string]$receipt['storePath']
        TEMP = ([string]$Allocation['runRoot'])
    }
    if ($null -eq $Launcher) {
        throw [System.ArgumentException]::new('STORE-MISSING-LAUNCHER: a process-launcher seam is required; no live spawn is performed here.')
    }
    $launchInput = @{
        runId      = $runId
        argv       = $fixedArgv
        endpoint   = [string]$Allocation['endpoint']
        namespace  = [string]$Allocation['namespace']
        database   = [string]$Allocation['database']
        childEnv   = $childEnv
        requestKey = ('req-' + $nonce)
    }
    $observed = $null
    try {
        $observed = (& $Launcher $launchInput)
    } catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)lost-response|timeout|unknown') {
            return @{
                runId            = $runId
                startState       = 'ReconciliationRequired'
                requested        = @{ requestKey = $launchInput['requestKey']; endpoint = $launchInput['endpoint'] }
                observed         = $null
                invocation       = @{ argvCount = $fixedArgv.Count; bindEndpoint = $launchInput['endpoint'] }
                binary           = @{ version = $version; digest = [string]$receipt['digest']; provenance = $provenance }
                retryPermitted   = $false
                failure          = ('lost-response-owned:' + $message)
            }
        }
        throw [System.InvalidOperationException]::new("STORE-LAUNCH-FAILED: $message")
    }
    if ($null -eq $observed -or $observed -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launcher must return a hashtable observation.')
    }
    if (-not $observed.ContainsKey('observedPid') -or -not $observed.ContainsKey('observedNonce')) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launcher observation is missing pid/nonce.')
    }
    $observedPid = 0
    try { $observedPid = [int]$observed['observedPid'] } catch {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: observed pid is not an integer.')
    }
    if ($observedPid -le 0) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: observed pid is not positive.')
    }
    $observedNonce = [string]$observed['observedNonce']
    if ($observedNonce -ceq $nonce) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: requested and observed nonces must be distinct handles.')
    }
    return @{
        runId      = $runId
        startState = 'StartRequested'
        requested  = @{ requestKey = $launchInput['requestKey']; endpoint = $launchInput['endpoint']; nonce = $nonce }
        observed   = @{ pid = $observedPid; nonce = $observedNonce; endpoint = $launchInput['endpoint'] }
        invocation = @{ argvCount = $fixedArgv.Count; bindEndpoint = $launchInput['endpoint']; artifact = $Script:StoreArtifact }
        binary     = @{ version = $version; architecture = $Script:StoreArchitecture; peMachine = $Script:StorePeMachine; digest = [string]$receipt['digest']; provenance = $provenance }
    }
}

function Invoke-StoreObserveReadiness {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$PortObserver,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$StoreClient,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation 'ObserveReadiness')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: start receipt run identity is foreign.')
    }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable])) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no observed process handle.')
    }
    $observed = $StartReceipt['observed']
    if (-not $observed.ContainsKey('pid') -or -not $observed.ContainsKey('endpoint')) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt observation is incomplete.')
    }
    $ownedPid = [int]$observed['pid']
    $ownedEndpoint = [string]$observed['endpoint']
    if ($null -eq $ProcessObserver -or $null -eq $PortObserver -or $null -eq $StoreClient) {
        throw [System.ArgumentException]::new('STORE-MISSING-OBSERVER: process, port, and Store-client seams are all required.')
    }
    $process = (& $ProcessObserver @{ pid = $ownedPid; runId = $runId })
    $port = (& $PortObserver @{ endpoint = $ownedEndpoint; runId = $runId })
    if ($null -eq $process -or $process -isnot [hashtable] -or -not $process.ContainsKey('alive')) {
        throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: process observer must return an alive mapping.')
    }
    if ($null -eq $port -or $port -isnot [hashtable] -or -not $port.ContainsKey('open')) {
        throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: port observer must return an open mapping.')
    }
    $alive = [bool]$process['alive']
    $open = [bool]$port['open']
    if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne $ownedPid)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: process observer returned a foreign pid.')
    }
    if ($port.ContainsKey('endpoint') -and ([string]$port['endpoint'] -cne $ownedEndpoint)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: port observer returned a foreign endpoint.')
    }
    $client = (& $StoreClient @{ runId = $runId; endpoint = $ownedEndpoint; pid = $ownedPid })
    if ($null -eq $client -or $client -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: Store client must return a hashtable.')
    }
    foreach ($field in @('authenticated', 'namespace', 'database', 'schemaDigest')) {
        if (-not $client.ContainsKey($field)) {
            throw [System.InvalidOperationException]::new("STORE-CLIENT-FAILED: client receipt is missing '$field'.")
        }
    }
    $authenticated = [bool]$client['authenticated']
    [void](Test-StoreDigestFormat -Digest ([string]$client['schemaDigest']))
    if ($client.ContainsKey('endpoint') -and ([string]$client['endpoint'] -cne $ownedEndpoint)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client receipt endpoint is foreign.')
    }
    $expectedNs = $null
    $expectedDb = $null
    if ($StartReceipt.ContainsKey('requested') -and $StartReceipt['requested'] -is [hashtable]) {
        $expectedNs = $StartReceipt['requested']['namespace']
        $expectedDb = $StartReceipt['requested']['database']
    }
    if ($null -eq $expectedNs -and $StartReceipt.ContainsKey('namespace')) { $expectedNs = $StartReceipt['namespace'] }
    if ($null -eq $expectedDb -and $StartReceipt.ContainsKey('database')) { $expectedDb = $StartReceipt['database'] }
    if ($null -ne $expectedNs -and ([string]$client['namespace'] -cne [string]$expectedNs)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client namespace selection is foreign.')
    }
    if ($null -ne $expectedDb -and ([string]$client['database'] -cne [string]$expectedDb)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client database selection is foreign.')
    }
    $fixtureReady = $false
    if ($client.ContainsKey('fixtureReady')) { $fixtureReady = [bool]$client['fixtureReady'] }
    $schemaReady = ($authenticated -and $alive -and $open)
    $ready = ($alive -and $open -and $authenticated -and $schemaReady)
    $state = 'ObservedProcessReadinessUnknown'
    if ($ready) { $state = 'AcceptedSemanticReadiness' }
    return @{
        runId          = $runId
        readinessState = $state
        processAlive   = $alive
        tcpOpen        = $open
        authenticated  = $authenticated
        schemaReady    = $schemaReady
        fixtureReady   = $fixtureReady
        schemaDigest   = [string]$client['schemaDigest']
        endpoint       = $ownedEndpoint
        pid            = $ownedPid
        ready          = $ready
    }
}

function Invoke-StoreResetForTest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Fixture,
        [Parameter(Mandatory)]
        [hashtable]$ReadinessReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$StoreClient
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($field in @('fixtureName', 'baselineDigest')) {
        if (-not $Fixture.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Fixture[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-FIXTURE: fixture is missing '$field'.")
        }
    }
    [void](Test-StoreDigestFormat -Digest ([string]$Fixture['baselineDigest']))
    $fixtureName = [string]$Fixture['fixtureName']
    if ($fixtureName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-FIXTURE: fixture name has an invalid shape.')
    }
    if ([string]$ReadinessReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: readiness receipt run identity is foreign.')
    }
    if ($null -eq $StoreClient) {
        throw [System.ArgumentException]::new('STORE-MISSING-CLIENT: a Store-client seam is required.')
    }
    $result = (& $StoreClient @{ runId = $runId; fixtureName = $fixtureName; baselineDigest = [string]$Fixture['baselineDigest'] })
    if ($null -eq $result -or $result -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: reset client must return a hashtable.')
    }
    if (-not $result.ContainsKey('resetOk') -or -not $result.ContainsKey('baselineOk')) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: reset receipt is missing resetOk/baselineOk.')
    }
    if ($result.ContainsKey('fixtureName') -and ([string]$result['fixtureName'] -cne $fixtureName)) {
        throw [System.InvalidOperationException]::new('STORE-FIXTURE-MISMATCH: reset receipt fixture does not match the declared fixture.')
    }
    $resetOk = [bool]$result['resetOk']
    $baselineOk = [bool]$result['baselineOk']
    if ($resetOk -and $baselineOk) {
        return @{
            runId              = $runId
            fixtureName        = $fixtureName
            baselineVerified   = $true
            contaminationScope = 'none'
            resetState         = 'GroupInitialization'
        }
    }
    return @{
        runId              = $runId
        fixtureName        = $fixtureName
        baselineVerified   = $false
        contaminationScope = 'group'
        resetState         = 'GroupContaminated'
        resetOk            = $resetOk
        baselineOk         = $baselineOk
    }
}

function Invoke-StoreCollectEvidence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$TerminalState,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$LogText,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secrets,
        [ValidateRange(1, 16777216)]
        [int]$MaxBytes = 65536
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Test-StoreTerminalDisposition -Disposition $TerminalState)
    $redacted = Get-StoreRedactedText -Text $LogText -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) {
        return @{
            runId          = [string]$Binding['runId']
            terminalState  = $TerminalState
            evidenceState  = 'EvidenceCollectionFailed'
            bytes          = 0
            truncated      = $false
            redactionFailed = $true
            owner          = [string]$Binding['owner']
        }
    }
    return @{
        runId          = [string]$Binding['runId']
        terminalState  = $TerminalState
        evidenceState  = 'TerminalTestEvidence'
        bytes          = [int]$redacted.bytes
        truncated      = [bool]$redacted.truncated
        text           = [string]$redacted.text
        owner          = [string]$Binding['owner']
    }
}

function Invoke-StoreStop {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ProcessController,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation 'Stop')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: start receipt run identity is foreign.')
    }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable]) -or -not $StartReceipt['observed'].ContainsKey('pid')) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no observed pid.')
    }
    $ownedPid = [int]$StartReceipt['observed']['pid']
    if ($ownedPid -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PID: owned pid is not positive.')
    }
    if ($null -eq $ProcessController) {
        throw [System.ArgumentException]::new('STORE-MISSING-CONTROLLER: a process-controller seam is required.')
    }
    $graceful = (& $ProcessController @{ phase = 'graceful'; pid = $ownedPid; runId = $runId })
    if ($null -eq $graceful -or $graceful -isnot [hashtable] -or -not $graceful.ContainsKey('exited')) {
        throw [System.InvalidOperationException]::new('STORE-CONTROLLER-FAILED: graceful phase must return an exited mapping.')
    }
    if ($graceful.ContainsKey('pid') -and ([int]$graceful['pid'] -ne $ownedPid)) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: controller touched a foreign pid.')
    }
    if ([bool]$graceful['exited']) {
        return @{
            runId     = $runId
            stopPhase = 'graceful'
            ownedPid  = $ownedPid
            stopState = 'OwnedResourcesStopped'
            forced    = $false
        }
    }
    $forced = (& $ProcessController @{ phase = 'forced'; pid = $ownedPid; runId = $runId })
    if ($null -eq $forced -or $forced -isnot [hashtable] -or -not $forced.ContainsKey('exited')) {
        throw [System.InvalidOperationException]::new('STORE-CONTROLLER-FAILED: forced phase must return an exited mapping.')
    }
    if ($forced.ContainsKey('pid') -and ([int]$forced['pid'] -ne $ownedPid)) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: controller touched a foreign pid.')
    }
    return @{
        runId     = $runId
        stopPhase = 'forced'
        ownedPid  = $ownedPid
        stopState = 'OwnedResourcesStopped'
        forced    = $true
        exited    = [bool]$forced['exited']
    }
}

function Invoke-StoreVerifyCleanup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: allocation run identity is foreign.')
    }
    foreach ($field in @('runRoot', 'dataRoot', 'logRoot', 'secretRoot', 'endpoint', 'port')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-ALLOCATION: allocation is missing '$field'.")
        }
    }
    $runRoot = [System.IO.Path]::GetFullPath([string]$Allocation['runRoot'])
    $runLeaf = [System.IO.Path]::GetFileName($runRoot)
    if ([string]::IsNullOrWhiteSpace($runLeaf) -or -not $runLeaf.Contains($runId)) {
        throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: cleanup run root leaf does not carry the run identity: $runRoot")
    }
    $runPrefix = $runRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($rootField in @('dataRoot', 'logRoot', 'secretRoot')) {
        $rootFull = [System.IO.Path]::GetFullPath([string]$Allocation[$rootField])
        if ($rootFull -ine $runRoot -and -not $rootFull.StartsWith($runPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: allocation root '$rootField' escapes the owned run root.")
        }
    }
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $runRoot -ExpectedRunId $runId)
    $failures = New-Object Collections.Generic.List[string]
    $ownedPid = 0
    if ($null -ne $StartReceipt['observed'] -and $StartReceipt['observed'] -is [hashtable] -and $StartReceipt['observed'].ContainsKey('pid')) {
        try { $ownedPid = [int]$StartReceipt['observed']['pid'] } catch { $ownedPid = 0 }
    }
    if ($null -ne $ProcessObserver -and $ownedPid -gt 0) {
        $process = (& $ProcessObserver @{ pid = $ownedPid; runId = $runId })
        if ($null -ne $process -and $process -is [hashtable]) {
            if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne $ownedPid)) {
                throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup observer returned a foreign pid.')
            }
            if ($process.ContainsKey('alive') -and [bool]$process['alive']) {
                [void]$failures.Add('process-still-alive')
            }
            if ($process.ContainsKey('descendants') -and $null -ne $process['descendants']) {
                $descendants = @($process['descendants'])
                if ($descendants.Count -gt 0) {
                    [void]$failures.Add(('descendants-remaining:' + $descendants.Count))
                }
            }
        }
    }
    if ($null -ne $PortObserver) {
        $port = (& $PortObserver @{ endpoint = [string]$Allocation['endpoint']; runId = $runId })
        if ($null -ne $port -and $port -is [hashtable]) {
            if ($port.ContainsKey('endpoint') -and ([string]$port['endpoint'] -cne [string]$Allocation['endpoint'])) {
                throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup port observer returned a foreign endpoint.')
            }
            if ($port.ContainsKey('open') -and [bool]$port['open']) {
                [void]$failures.Add('port-still-open')
            }
        }
    }
    if ($null -ne $FileProbe) {
        $probe = (& $FileProbe @{ runRoot = $runRoot; runId = $runId })
        if ($null -ne $probe -and $probe -is [hashtable]) {
            if ($probe.ContainsKey('runRoot') -and ([System.IO.Path]::GetFullPath([string]$probe['runRoot']) -ine $runRoot)) {
                throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup file probe returned a foreign root.')
            }
            if ($probe.ContainsKey('locksHeld') -and [bool]$probe['locksHeld']) {
                [void]$failures.Add('locks-held')
            }
            if ($probe.ContainsKey('secretsPresent') -and [bool]$probe['secretsPresent']) {
                [void]$failures.Add('secrets-present')
            }
            if ($probe.ContainsKey('rootsPresent') -and [bool]$probe['rootsPresent']) {
                [void]$failures.Add('roots-present')
            }
            if ($probe.ContainsKey('entries')) {
                foreach ($entry in @($probe['entries'])) {
                    if ([string]$entry -cnotin $Script:StoreAllowedRootChildren) {
                        [void]$failures.Add(('foreign-entry-preserved:' + [string]$entry))
                    }
                }
            }
        }
    } else {
        if (Test-Path -LiteralPath $runRoot) {
            $entries = @(Get-ChildItem -LiteralPath $runRoot -Force -ErrorAction SilentlyContinue)
            foreach ($entry in $entries) {
                if ($entry.Name -cnotin $Script:StoreAllowedRootChildren) {
                    [void]$failures.Add(('foreign-entry-preserved:' + $entry.Name))
                }
            }
            if ($entries.Count -gt 0) {
                [void]$failures.Add('roots-present')
            }
        }
    }
    if ($failures.Count -gt 0) {
        return @{
            runId     = $runId
            cleanupState = 'ReconciliationRequired'
            cleaned   = $false
            failures  = @($failures)
            ownedRoot = $runRoot
        }
    }
    return @{
        runId     = $runId
        cleanupState = 'CleanupVerified'
        cleaned   = $true
        failures  = @()
        ownedRoot = $runRoot
    }
}

Export-ModuleMember -Function @(
    'Get-StoreProviderIdentity',
    'Get-StoreLockIdentity',
    'Get-StoreClosedOperations',
    'Get-StoreTerminalDispositions',
    'Test-StoreDigestFormat',
    'Test-StoreClosedOperation',
    'Test-StoreTerminalDisposition',
    'Resolve-StoreDeadline',
    'Test-StoreBindingShape',
    'Test-StoreProviderResultClosed',
    'Invoke-StoreProviderOperation',
    'Invoke-StoreValidateRequirement',
    'Invoke-StorePlan',
    'Resolve-StoreOwnedPath',
    'Get-StoreChildEnv',
    'New-StoreEphemeralCredential',
    'Get-StoreRedactedText',
    'Invoke-StoreAllocate',
    'Invoke-StoreStart',
    'Invoke-StoreObserveReadiness',
    'Invoke-StoreResetForTest',
    'Invoke-StoreCollectEvidence',
    'Invoke-StoreStop',
    'Invoke-StoreVerifyCleanup'
)
