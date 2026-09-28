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
# plus Store/Git receipt requirements plus the exact planned target closure
# (plannedComponents, dependency-closed, launch-ordered); Allocate consumes the
# required Store/Git receipts via explicit -ProviderReceipts (validated, lane-matched,
# run-bound, propagated Allocate -> Start -> readiness) and always echoes the
# requirement; Start launches only the Plan scope when a Plan is supplied and the
# full topology otherwise (recorded default, never silent); unique run-owned
# installation/session/config/
# data/log/temp/artifact identities + canonical F-PIPE namespace held by a real
# exclusive single-instance named-pipe server claim (registered in the owner
# table, re-proven by live handle identity, squatted/foreign/released claims
# rejected; a name echo is never a claim) + user-scoped
# isolated-foreground principal; per-executable digest + PE target/profile before
# launch; Job Object (or accepted equivalent) containment before descendants escape;
# request/observed handle separation; owner-issued generation/fence/epoch (never
# minted); authenticated peer handshake; liveness never proves subsystem readiness;
# stale/foreign/expired receipts never restore readiness; unknown launches require
# reconciliation without retry/reuse; owner-only reset; reverse-order shutdown +
# owned-tree-only termination (never by label/pipe/PID alone) re-proven live from
# this run's own launch claim before every termination request, an unproven
# component left running and reported instead of terminated, and every diagnostic
# emission (typed error detail, receipt failure text) passing caller- and
# seam-derived text through one total redactor that removes the value and can
# never throw; full descendant/job/pipe/mutex/handle/lock/root verification;
# idempotent cleanup preserving the primary
# failure; bounded redacted evidence; ELIOT_GOVERNOR_CONFIG only as a versioned
# run-local receipt via the Core-protected channel, dispatched from Allocate and
# bound (relative path + digest) into the Allocate and provider-readiness receipts
# with #909 Store handle references (namespace/endpoint/credentialHandle, names only;
# created-file digests are computed from the exact written bytes and re-verified at
# launch, never caller-declared). Local file verification (stream hash + PE machine
# + reparse rejection), structured containment proofs (exact run-owned Job Object
# name + observed image + observed start, never PID alone), strict owner-handshake
# validation (fixed issuer + fence format + handshake digest + issued/expiry
# freshness), expiry enforcement whenever bound, port observations, and a strict
# cleanup lane (every observer required, unknowns preserved) are explicit recorded
# verification lanes: seam-attested operation is never silent and never mistaken
# for verified operation. All clocks/seams injected; reads, hashes, PE/ACL/identity
# observations and the single owned config-file write are local and bounded; no
# download, spawn, or sleep here.
# Seams stay injected; only bounded local verification runs here.
# Proof ceiling: RUNTIME-PROVIDER-ISOLATED-ONLY.
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
$Script:RuntimeGovernorConfigRelativePath = 'config/governor-config-v1.json'
$Script:RuntimeStoreNamespacePrefix = 'eliot_ns_'
$Script:RuntimeStoreLoopback = '127.0.0.1'
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
$Script:RuntimeFencePattern = '^fence-[0-9a-f]{8,64}$'
$Script:RuntimeOwnerHandshakeIssuer = 'runtime-provider-owner'
$Script:RuntimeJobObjectPrefix = 'eliot-job-'
$Script:RuntimeMaxArtifactBytes = 134217728
$Script:RuntimeMaxConfigBytes = 65536
$Script:RuntimeMaxPriorFailureChars = 2000
# Namespace reservation (#911). The canonical F-PIPE namespace is a mutable
# namespace: one exclusive server instance per namespace, exactly as the loopback
# port is one bind per endpoint. The count is part of the namespace's identity,
# so the claim is what reserves, never the name.
$Script:RuntimeNamespaceReservations = @{}
$Script:RuntimeReservationServerInstances = 1
$Script:RuntimeReservationPipeBufferBytes = 65536
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
function Get-RuntimeTargetClosure {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Target)
    if ([string]$Target -cnotin $Script:RuntimeComponents) { throw [System.InvalidOperationException]::new("RUNTIME-UNKNOWN-TARGET: closure target '$Target' is not a topology component.") }
    $closed = @{}
    $stack = New-Object Collections.Generic.List[string]
    [void]$stack.Add($Target)
    while ($stack.Count -gt 0) {
        $next = $stack[$stack.Count - 1]
        [void]$stack.RemoveAt($stack.Count - 1)
        if ($closed.ContainsKey($next)) { continue }
        $closed[$next] = $true
        foreach ($dep in @($Script:RuntimeComponentDependencies[$next])) {
            if (-not $closed.ContainsKey([string]$dep)) { [void]$stack.Add([string]$dep) }
        }
    }
    return @($Script:RuntimeLaunchOrder | Where-Object { $closed.ContainsKey($_) })
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
    catch { throw [System.InvalidOperationException]::new("RUNTIME-PROVIDER-FAILED:$Operation : $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
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
    $plannedTarget = [string]$Requirement['target']
    $plannedComponents = @(Get-RuntimeTargetClosure -Target $plannedTarget)
    return @{ runId = $runId; testClass = $Script:RuntimeTestClass; target = $plannedTarget; plannedTarget = $plannedTarget; plannedComponents = $plannedComponents; providerName = $Script:RuntimeProviderName; providerRevision = $Script:RuntimeProviderRevision; owner = $owner; generation = $gen; resources = $resources; requiredReceipts = $requiredReceipts; mutationFree = $true }
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
    if ($candidate -ine $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-PATH-ESCAPE: path escapes the admitted run root: $(Get-RuntimeSafeDiagnosticText -Text $candidate)") }
    if (-not [string]::IsNullOrEmpty([System.IO.Path]::GetFileName($candidate)) -and ([System.IO.Path]::GetFileName($candidate) -match $Script:RuntimeReservedLeafPattern)) { throw [System.InvalidOperationException]::new("RUNTIME-RESERVED-PATH: reserved device name rejected: $(Get-RuntimeSafeDiagnosticText -Text $candidate)") }
    foreach ($segment in ($candidate.Substring($rootFull.Length).Split([System.IO.Path]::DirectorySeparatorChar))) {
        if ($segment -match $Script:RuntimeReservedLeafPattern) { throw [System.InvalidOperationException]::new("RUNTIME-RESERVED-PATH: reserved device segment rejected: $(Get-RuntimeSafeDiagnosticText -Text $segment)") }
    }
    $probe = $candidate
    while ($null -ne $probe -and $probe.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw [System.InvalidOperationException]::new("RUNTIME-REPARSE-ESCAPE: path crosses a reparse point: $(Get-RuntimeSafeDiagnosticText -Text $entry.FullName)") }
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
                if ($recorded.run_id -cne $ExpectedRunId) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: owner marker belongs to another run: $(Get-RuntimeSafeDiagnosticText -Text $cursor)") }
            } catch [System.InvalidOperationException] { throw }
            catch { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: owner marker unreadable at: $(Get-RuntimeSafeDiagnosticText -Text $cursor)") }
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
# Caller-side minter for the Allocate -PeerCredential explicit input: the caller mints
# and keeps the secret, and only the handle crosses into the provider (Allocate
# validates and binds it, Start forwards it to the launcher/peer channel).
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
function Resolve-RuntimePeerCredential {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Credential)
    if ($Credential.ContainsKey('secret')) { throw [System.InvalidOperationException]::new('RUNTIME-PEER-CREDENTIAL-VALUE: peer credential must report names/handles, never values.') }
    foreach ($field in @('credentialId', 'credentialHandle')) {
        if (-not $Credential.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Credential[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-PEER-CREDENTIAL: peer credential is missing '$field'.") }
    }
    $peerId = [string]$Credential['credentialId']
    if ($peerId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-PEER-CREDENTIAL: credential id has an invalid shape.') }
    if ([string]$Credential['credentialHandle'] -cnotmatch '^handle:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[0-9a-f]{8}$') { throw [System.InvalidOperationException]::new('RUNTIME-PEER-CREDENTIAL-SHAPE: peer credentialHandle is not an ephemeral-handle shape.') }
    $expectedPrefix = ('handle:' + $peerId + ':')
    if (-not ([string]$Credential['credentialHandle']).StartsWith($expectedPrefix, [System.StringComparison]::Ordinal)) { throw [System.InvalidOperationException]::new('RUNTIME-PEER-CREDENTIAL-SHAPE: peer credentialHandle does not belong to the declared credential id.') }
    return @{ credentialId = $peerId; credentialHandle = [string]$Credential['credentialHandle'] }
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
        # A quoted value is removed whole; an unquoted value runs to the next
        # separator. Matching only the first token would leave the tail of a
        # payload ("model = "claude opus 5"") recoverable from the diagnostic.
        $redacted = [regex]::Replace($redacted, '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring|governorconfig)\s*[:=]\s*("[^"]*"|''[^'']*''|\S+)', '$1=[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)ELIOT_GOVERNOR_CONFIG\s*=\s*("[^"]*"|''[^'']*''|\S+)', 'ELIOT_GOVERNOR_CONFIG=[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)runtime_[a-z_]*(pass|secret|token|key)[a-z_]*\s*=\s*("[^"]*"|''[^'']*''|\S+)', '[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)(frame|payload|memory|command|argv|environment|environ|protocol|source|model|user)\s*\{[^}]{0,4096}\}', '$1 [redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)(frame|payload|memory|command|argv|environment|environ|protocol|source|model|user|trace|commit|branch|tag|repo|repository)\s*[:=]\s*("[^"]*"|''[^'']*''|\S+)', '$1=[redacted-runtime-secret]')
        $redacted = [regex]::Replace($redacted, '(?i)([A-Za-z]:\\(?:[^\\/:*?"<>|\s]+\\)*private(?:\\[^\\/:*?"<>|\s]*)*|/(?:[^\\/:*?"<>|\s]+/)*private(?:/[^\\/:*?"<>|\s]*)*)', '[redacted-private-path]')
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
# W7 redaction lane: every diagnostic-adjacent emission (typed error detail, receipt
# failure text) sends caller- and seam-derived text through this one entry point, so
# no emitting path is left unredacted. The emitted copy loses the value; control flow
# keeps reading the raw text, so a diagnostic never decides behaviour. Total by
# construction: a redaction failure degrades to an empty detail instead of throwing,
# so a diagnostic can never introduce a failure of its own.
function Get-RuntimeSafeDiagnosticText {
    [CmdletBinding()]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Text, [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$Secrets, [Parameter()][ValidateRange(1, 16777216)][int]$MaxBytes = 2048)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $redacted = Get-RuntimeRedactedText -Text $Text -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) { return '' }
    return [string]$redacted.text
}
# Namespace-reservation owner table (#911 W1, namespace half). This is the same
# shape the Store lane uses for its loopback bind: a length-delimited identity
# key, an exclusive create, a registration that refuses a duplicate, and a
# claim that is re-proven live before anyone may act on it. Nothing here
# recognises a reservation by its name, and nothing deletes or replaces a
# directory, file or handle it has not proven it owns.
function Get-RuntimeNamespaceReservationId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][int]$Generation,
        [Parameter(Mandatory)][string]$AllocationSeed,
        [Parameter(Mandatory)][string]$PipeNamespace
    )
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @($RunId, $Owner, [string]$Generation, $AllocationSeed, $PipeNamespace)) {
        [void]$builder.Append($part.Length).Append(':').Append($part)
    }
    return $builder.ToString()
}
function Register-RuntimeNamespaceReservation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][hashtable]$Reservation,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][int]$Generation,
        [Parameter(Mandatory)][string]$AllocationSeed,
        [Parameter(Mandatory)][string]$PipeNamespace,
        [Parameter()][AllowNull()][object]$Claim
    )
    $id = Get-RuntimeNamespaceReservationId -RunId $RunId -Owner $Owner -Generation $Generation `
        -AllocationSeed $AllocationSeed -PipeNamespace $PipeNamespace
    if ($Script:RuntimeNamespaceReservations.ContainsKey($id)) {
        throw [System.InvalidOperationException]::new('RUNTIME-NAMESPACE-CONFLICT: namespace reservation identity has already been used for this namespace.')
    }
    $handle = $null
    if ($null -ne $Claim -and ($Claim -is [System.IO.Pipes.NamedPipeServerStream])) {
        try { $handle = $Claim.SafePipeHandle } catch { $handle = $null }
    }
    $record = @{
        reservationId  = $id
        runId          = $RunId
        owner          = $Owner
        generation     = $Generation
        allocationSeed = $AllocationSeed
        pipeNamespace  = $PipeNamespace
        claim          = $Claim
        handle         = $handle
        state          = 'Pending'
    }
    $Script:RuntimeNamespaceReservations[$id] = $record
    return $record
}
function Close-RuntimeSuppliedReservationClaim {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()]$Reservation)
    if ($null -eq $Reservation) { return $true }
    $claim = $null
    if ($Reservation -is [System.IO.Pipes.NamedPipeServerStream]) { $claim = $Reservation }
    elseif (($Reservation -is [hashtable]) -and $Reservation.ContainsKey('claim')) { $claim = $Reservation['claim'] }
    else { return $true }
    if ($null -eq $claim) { return $true }
    if ($claim -isnot [System.IO.Pipes.NamedPipeServerStream]) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-CLEANUP-UNKNOWN: supplied namespace claim has an unsupported type.')
    }
    try { $claim.Dispose() }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-RESERVATION-CLEANUP-UNKNOWN: supplied namespace claim release failed: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
    return $true
}
function Complete-RuntimeNamespaceReservation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][hashtable]$Identity,
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$Owner,
        [Parameter(Mandatory)][int]$Generation,
        [Parameter(Mandatory)][string]$PipeNamespace
    )
    foreach ($field in @('reservationId', 'runId', 'owner', 'generation', 'allocationSeed', 'pipeNamespace')) {
        if (-not $Identity.ContainsKey($field)) {
            throw [System.InvalidOperationException]::new("RUNTIME-RESERVATION-FOREIGN: namespace reservation identity is missing '$field'.")
        }
    }
    if ([string]$Identity['runId'] -cne $RunId -or [string]$Identity['owner'] -cne $Owner -or
        [int]$Identity['generation'] -ne $Generation -or [string]$Identity['pipeNamespace'] -cne $PipeNamespace) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-FOREIGN: namespace reservation identity does not match its binding.')
    }
    $expectedId = Get-RuntimeNamespaceReservationId -RunId $RunId -Owner $Owner -Generation $Generation `
        -AllocationSeed ([string]$Identity['allocationSeed']) -PipeNamespace $PipeNamespace
    $id = [string]$Identity['reservationId']
    if ($id -cne $expectedId -or -not $Script:RuntimeNamespaceReservations.ContainsKey($id)) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-UNKNOWN: pending namespace reservation owner is unavailable.')
    }
    $registered = $Script:RuntimeNamespaceReservations[$id]
    if ([string]$registered['runId'] -cne $RunId -or [string]$registered['owner'] -cne $Owner -or
        [int]$registered['generation'] -ne $Generation -or [string]$registered['pipeNamespace'] -cne $PipeNamespace -or
        [string]$registered['allocationSeed'] -cne [string]$Identity['allocationSeed']) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-FOREIGN: namespace reservation identity does not match its registered owner.')
    }
    if ([string]$registered['state'] -ceq 'Released') {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-REUSED: released namespace reservation cannot authorize another launch.')
    }
    if (-not $Identity.ContainsKey('claim') -or -not [object]::ReferenceEquals($registered['claim'], $Identity['claim'])) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-FOREIGN: pending namespace reservation handle does not match its registered claim.')
    }
    # The ownership gate. A namespace with no live exclusive claim was never
    # reserved by this run; a name alone can never authorize a launch, and the
    # claim must still be the exact registered object.
    if ($null -eq $registered['claim'] -or ($registered['claim'] -isnot [System.IO.Pipes.NamedPipeServerStream])) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-UNKNOWN: namespace reservation carries no live exclusive claim.')
    }
    $liveHandle = $null
    try { $liveHandle = $registered['claim'].SafePipeHandle } catch { $liveHandle = $null }
    if ($null -eq $liveHandle -or $liveHandle.IsInvalid -or $liveHandle.IsClosed) {
        throw [System.InvalidOperationException]::new('RUNTIME-RESERVATION-UNKNOWN: namespace reservation claim is no longer live.')
    }
    try { $registered['claim'].Dispose() }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-RESERVATION-CLEANUP-FAILED: owned namespace claim release failed: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
    $registered['state'] = 'Released'
    $registered['claim'] = $null
    $Identity['state'] = 'Released'
    $Identity['claim'] = $null
    return $true
}
function Get-RuntimeNamespaceReservationReceipt {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][hashtable]$Identity)
    return @{
        reservationId  = [string]$Identity['reservationId']
        runId          = [string]$Identity['runId']
        owner          = [string]$Identity['owner']
        generation     = [int]$Identity['generation']
        allocationSeed = [string]$Identity['allocationSeed']
        pipeNamespace  = [string]$Identity['pipeNamespace']
        state          = [string]$Identity['state']
    }
}
# Real namespace reservation: win the exclusive create of the canonical F-PIPE
# namespace and return the live single-instance server claim. The count is part
# of what the namespace is, so a namespace already taken by a live instance
# fails the create here instead of being announced and contended later. A held
# server instance never accepts a connection, so holding the namespace does not
# consume a pipe, a thread or a peer.
# The same seam this seam substitutes for is the hook a caller may pass to supply
# its own claim source, exactly as New-StoreProviderOperationTable does for the
# port reservation; with no hook the exclusive create below is the claim source.
# In: {runId,pipeNamespace,sessionId}. Out: {pipeNamespace,claim}.
function New-RuntimeDefaultNamespaceReservation {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param([Parameter()][AllowNull()][scriptblock]$Reservation)
    $source = $Reservation
    if ($null -eq $source) {
        # The counts are read from the script scope at call time, not captured
        # into a closure, so the namespace identity cannot drift from the
        # module's own constant.
        $source = {
            param($Context)
            [System.IO.Pipes.NamedPipeServerStream]::new(
                [string]$Context['pipeNamespace'],
                [System.IO.Pipes.PipeDirection]::InOut,
                $Script:RuntimeReservationServerInstances,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::None,
                $Script:RuntimeReservationPipeBufferBytes,
                $Script:RuntimeReservationPipeBufferBytes)
        }
    }
    $reserve = {
        param($Context)
        $namespace = [string]$Context['pipeNamespace']
        $claim = $null
        try {
            $claim = (& $source @{ runId = [string]$Context['runId']; pipeNamespace = $namespace; sessionId = [string]$Context['sessionId'] })
        }
        catch {
            $primary = $_.Exception.Message
            if ($primary -match '^RUNTIME-[A-Z0-9-]+:') { throw [System.InvalidOperationException]::new($primary) }
            # Losing the exclusive create IS the squatting / foreign-ownership
            # signal: some live holder already owns this mutable namespace. It is
            # never downgraded to a reusable name.
            throw [System.InvalidOperationException]::new(
                "RUNTIME-NAMESPACE-CONFLICT: exclusive namespace create failed for the canonical namespace: $(Get-RuntimeSafeDiagnosticText -Text $primary)")
        }
        return @{ pipeNamespace = $namespace; claim = $claim }
    }
    return $reserve.GetNewClosure()
}
function Invoke-RuntimeAllocate {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][string]$BaseTemp, [Parameter()][AllowNull()][scriptblock]$Entropy, [Parameter()][AllowNull()][scriptblock]$NamespaceReservation, [Parameter()][AllowNull()][hashtable]$GovernorConfigReceipt, [Parameter()][AllowNull()][AllowEmptyCollection()][hashtable[]]$ProviderReceipts, [Parameter()][AllowNull()][hashtable]$PeerCredential, [Parameter()][AllowNull()][hashtable]$GovernorConfigContent, [Parameter()][AllowNull()][hashtable]$GovernorConfigStoreHandles, [Parameter()][switch]$VerifyPrincipal)
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
    if (-not $runRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-PATH-ESCAPE: allocated run root escaped its base: $(Get-RuntimeSafeDiagnosticText -Text $runRoot)") }
    $roots = @{}
    foreach ($leaf in @('installation', 'session', 'config', 'data', 'logs', 'temp', 'artifacts')) {
        $full = [System.IO.Path]::GetFullPath((Join-Path $runRoot $leaf))
        [void](Resolve-RuntimeOwnedPath -RunRoot $runRoot -Path $full -ExpectedRunId $runId)
        $roots[$leaf] = $full
    }
    # Every MUTABLE identity below is derived from the FULL 128-bit run identity.
    # The previous first-8-hex form mapped distinct run identities onto one pipe
    # namespace, one job object and one session, which is the cross-run mutable
    # sharing this operation exists to prevent. No hash, seed or counter replaces
    # the discarded bits. The canonical prefixes are 12 and 10 characters, so a
    # 32-hex run identity yields 44 and 42 characters and both 64-character shape
    # guards below still hold without a second truncation.
    #
    # $nonce is deliberately NOT used for any of the three: it stays the path
    # suffix and the allocation seed, where the full $runId already present in the
    # same leaf keeps distinct runs distinct, and where a caller-supplied -Entropy
    # value of up to 64 hex characters would otherwise push 'sess-' past the
    # 64-character principal shape and fail as RUNTIME-INVALID-PRINCIPAL rather
    # than the RUNTIME-INVALID-ENTROPY the bad entropy actually is.
    $pipeNamespace = ($Script:RuntimePipePrefix + $runId)
    if ($pipeNamespace -cnotmatch '^[A-Za-z0-9_.-]{1,64}$') { throw [System.InvalidOperationException]::new('RUNTIME-ALLOCATION-MISMATCH: derived pipe namespace has an invalid shape.') }
    $jobObjectName = ($Script:RuntimeJobObjectPrefix + $runId)
    if ($jobObjectName -cnotmatch '^[A-Za-z0-9_.-]{1,64}$') { throw [System.InvalidOperationException]::new('RUNTIME-ALLOCATION-MISMATCH: derived job-object identity has an invalid shape.') }
    $sessionId = ('sess-' + $runId)
    $principal = @{ principal = [string]$Binding['owner']; sessionId = $sessionId; scope = $Script:RuntimePrincipalScope }
    [void](Test-RuntimePrincipalShape -Principal $principal)
    $principalLane = 'shape-only'
    if ($VerifyPrincipal) {
        [void](Test-RuntimePrincipalBinding -Principal $principal)
        $principalLane = 'identity-verified'
    }
    if ($null -eq $NamespaceReservation) { throw [System.ArgumentException]::new('RUNTIME-MISSING-RESERVATION: a namespace-reservation seam is required; no pipe is created here.') }
    $reservation = $null
    try { $reservation = (& $NamespaceReservation @{ runId = $runId; pipeNamespace = $pipeNamespace; sessionId = $sessionId }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-NAMESPACE-CONFLICT: reservation failed: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
    $reserved = ''
    $claimed = $null
    if ($reservation -is [hashtable] -and $reservation.ContainsKey('pipeNamespace')) {
        $reserved = [string]$reservation['pipeNamespace']
        if ($reservation.ContainsKey('claim')) { $claimed = $reservation['claim'] }
    }
    elseif ($reservation -is [string]) { $reserved = $reservation }
    else { throw [System.InvalidOperationException]::new('RUNTIME-NAMESPACE-CONFLICT: reservation must return a pipe-namespace mapping.') }
    if ($reserved -cne $pipeNamespace) { throw [System.InvalidOperationException]::new('RUNTIME-NAMESPACE-CONFLICT: reserved namespace does not match the derived canonical namespace.') }
    $reservationIdentity = $null
    try {
        $reservationIdentity = Register-RuntimeNamespaceReservation -Reservation $reservation `
            -RunId $runId -Owner ([string]$Binding['owner']) -Generation ([int]$Binding['generation']) `
            -AllocationSeed $nonce -PipeNamespace $pipeNamespace -Claim $claimed
    }
    catch {
        $primary = $_.Exception.Message
        if ($null -ne $primary -and $primary -cmatch '^RUNTIME-[A-Z0-9-]+:') { throw [System.InvalidOperationException]::new($primary) }
        throw [System.InvalidOperationException]::new("RUNTIME-NAMESPACE-CONFLICT: namespace reservation could not be registered: $(Get-RuntimeSafeDiagnosticText -Text $primary)")
    }
    $allocation = @{ runId = $runId; runRoot = $runRoot; installationRoot = $roots['installation']; sessionRoot = $roots['session']; configRoot = $roots['config']; dataRoot = $roots['data']; logRoot = $roots['logs']; tempRoot = $roots['temp']; artifactRoot = $roots['artifacts']; ownerMarker = $Script:RuntimeOwnedRootMarker; pipeNamespace = $pipeNamespace; jobObjectName = $jobObjectName; sessionId = $sessionId; principal = $principal; owner = [string]$Binding['owner']; generation = [int]$Binding['generation']; allocationSeed = $nonce }
    $requiredLanes = @()
    if ($Plan.ContainsKey('requiredReceipts') -and $null -ne $Plan['requiredReceipts']) { $requiredLanes = @($Plan['requiredReceipts']) }
    $allocation['requiredReceipts'] = $requiredLanes
    $acceptedReceipts = @()
    $storeReceiptForConfig = $null
    $suppliedReceipts = @()
    if ($null -ne $ProviderReceipts) { $suppliedReceipts = @($ProviderReceipts) }
    if ($suppliedReceipts.Count -gt 0) {
        $coveredLanes = @{}
        foreach ($receipt in $suppliedReceipts) {
            if ($receipt -isnot [hashtable]) { throw [System.ArgumentException]::new('RUNTIME-INVALID-RECEIPT: provider receipt must be a hashtable.') }
            [void](Test-RuntimeProviderReceipt -Receipt $receipt)
            if ([string]$receipt['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: provider receipt run identity is foreign to this binding.') }
            $laneKind = 'store-receipt'
            if ([string]$receipt['testClass'] -ceq 'GIT') { $laneKind = 'git-receipt' }
            $matched = $false
            foreach ($lane in $requiredLanes) {
                if (($lane -is [hashtable]) -and ([string]$lane['kind'] -ceq $laneKind) -and ([string]$lane['providerRevision'] -ceq [string]$receipt['providerRevision'])) { $matched = $true }
            }
            if (-not $matched) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-LANE: provider receipt lane '$laneKind' is not required by this plan.") }
            $coveredLanes[$laneKind] = $true
            $acceptedReceipts += @{ testClass = [string]$receipt['testClass']; providerRevision = [string]$receipt['providerRevision']; digest = [string]$receipt['digest']; issuer = [string]$receipt['issuer']; runId = $runId }
        }
        foreach ($lane in $requiredLanes) {
            if (($lane -is [hashtable]) -and (-not $coveredLanes.ContainsKey([string]$lane['kind']))) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-MISSING: required lane '$($lane['kind'])' has no accepted provider receipt.") }
        }
        foreach ($accepted in $acceptedReceipts) { if ([string]$accepted['testClass'] -ceq 'STORE') { $storeReceiptForConfig = $accepted } }
    }
    $allocation['providerReceipts'] = $acceptedReceipts
    # The namespace stays held: the identity carries the run's own live claim, so
    # the reservation is re-proven by handle identity before anything acts on it
    # and a released or substituted handle can never authorize a later launch.
    $allocation['namespaceReservation'] = $reservationIdentity
    $governorConfigLane = 'none'
    if ($null -ne $PeerCredential) {
        $allocation['peerCredential'] = (Resolve-RuntimePeerCredential -Credential $PeerCredential)
    }
    if ($null -ne $GovernorConfigReceipt) {
        $allocation['governorConfig'] = (Resolve-RuntimeGovernorConfig -Binding $Binding -ConfigReceipt $GovernorConfigReceipt -RunRoot $runRoot -AcceptedStoreReceipt $storeReceiptForConfig)
        $governorConfigLane = 'receipt-declared'
    }
    if ($null -ne $GovernorConfigContent) {
        if ($null -ne $GovernorConfigReceipt) { throw [System.ArgumentException]::new('RUNTIME-CONFIG-AMBIGUOUS: governor config content and a config receipt are mutually exclusive; provenance must be unambiguous.') }
        $storeProofForFile = $null
        if ($null -ne $GovernorConfigStoreHandles) { $storeProofForFile = $storeReceiptForConfig }
        $allocation['governorConfig'] = (New-RuntimeGovernorConfigFile -Binding $Binding -RunRoot $runRoot -Content $GovernorConfigContent -StoreHandles $GovernorConfigStoreHandles -AcceptedStoreReceipt $storeProofForFile)
        $governorConfigLane = 'created-file'
    }
    $allocation['governorConfigLane'] = $governorConfigLane
    $allocation['principalLane'] = $principalLane
    return $allocation
}
function Invoke-RuntimeStart {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][AllowNull()][scriptblock]$Acquisition, [Parameter(Mandatory)][AllowNull()][scriptblock]$Launcher, [Parameter(Mandatory)][AllowNull()][scriptblock]$OwnerIssuance, [Parameter()][AllowNull()][scriptblock]$Entropy, [Parameter()][AllowNull()][hashtable]$Plan, [Parameter()][switch]$VerifyArtifactFile, [Parameter()][AllowNull()][hashtable]$OwnerHandshake, [Parameter()][AllowNull()][scriptblock]$Clock)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-START-MISMATCH: allocation run identity does not match binding.') }
    if (-not $Allocation.ContainsKey('principal') -or ($Allocation['principal'] -isnot [hashtable])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing 'principal'.") }
    [void](Test-RuntimePrincipalShape -Principal $Allocation['principal'])
    if (-not $Allocation.ContainsKey('jobObjectName') -or [string]::IsNullOrWhiteSpace([string]$Allocation['jobObjectName'])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing 'jobObjectName'.") }
    $jobObjectName = [string]$Allocation['jobObjectName']
    foreach ($field in @('runRoot', 'installationRoot', 'sessionRoot', 'configRoot', 'pipeNamespace', 'sessionId')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing '$field'.") }
    }
    $governorBinding = $null
    if ($Allocation.ContainsKey('governorConfig') -and $null -ne $Allocation['governorConfig']) {
        $candidate = $Allocation['governorConfig']
        if ($candidate -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-INVALID-ALLOCATION: allocation governorConfig must be a hashtable receipt.') }
        foreach ($field in @('relativePath', 'digest')) {
            if (-not $candidate.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$candidate[$field])) { throw [System.InvalidOperationException]::new("RUNTIME-INVALID-ALLOCATION: allocation governorConfig is missing '$field'.") }
        }
        if ($candidate.ContainsKey('runId') -and ([string]$candidate['runId'] -cne $runId)) { throw [System.InvalidOperationException]::new('RUNTIME-START-MISMATCH: allocation governorConfig run identity does not match binding.') }
        $governorBinding = $candidate
    }
    $launchScope = @($Script:RuntimeLaunchOrder)
    $launchScopeSource = 'full-topology-default'
    if ($null -ne $Plan) {
        if (-not $Plan.ContainsKey('runId') -or ([string]$Plan['runId'] -cne $runId)) { throw [System.InvalidOperationException]::new('RUNTIME-START-MISMATCH: plan run identity does not match binding.') }
        if (-not $Plan.ContainsKey('plannedComponents') -or $null -eq $Plan['plannedComponents']) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PLAN: plan carries no derived target closure.') }
        $claimedScope = @($Plan['plannedComponents'])
        if ($claimedScope.Count -eq 0) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PLAN: planned target closure is empty.') }
        foreach ($scoped in $claimedScope) {
            if ([string]$scoped -cnotin $Script:RuntimeComponents) { throw [System.InvalidOperationException]::new("RUNTIME-UNKNOWN-TARGET: planned scope '$scoped' is not a topology component.") }
        }
        foreach ($scoped in $claimedScope) {
            foreach ($dep in @($Script:RuntimeComponentDependencies[[string]$scoped])) {
                if ([string]$dep -cnotin $claimedScope) { throw [System.InvalidOperationException]::new("RUNTIME-PLAN-SCOPE-UNCLOSED: planned scope omits dependency '$dep' of '$scoped'.") }
            }
        }
        $launchScope = @($Script:RuntimeLaunchOrder | Where-Object { $claimedScope -ccontains $_ })
        $launchScopeSource = 'plan'
    }
    $peerCredentialBinding = $null
    if ($Allocation.ContainsKey('peerCredential') -and $null -ne $Allocation['peerCredential']) {
        $peerCandidate = $Allocation['peerCredential']
        if ($peerCandidate -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-INVALID-ALLOCATION: allocation peerCredential must be a hashtable receipt.') }
        $peerCredentialBinding = (Resolve-RuntimePeerCredential -Credential $peerCandidate)
    }
    if ($null -eq $Acquisition) { throw [System.ArgumentException]::new('RUNTIME-MISSING-ACQUISITION: an acquisition seam is required; no download is performed here.') }
    if ($null -eq $Launcher) { throw [System.ArgumentException]::new('RUNTIME-MISSING-LAUNCHER: a process-launcher seam is required; no live spawn is performed here.') }
    if ($null -eq $OwnerIssuance) { throw [System.ArgumentException]::new('RUNTIME-MISSING-ISSUANCE: an owner-issuance seam is required; generation/fence/epoch are never locally minted.') }
    $receipt = $null
    try { $receipt = (& $Acquisition @{ runId = $runId; artifact = $Script:RuntimeArtifact }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ACQUISITION-FAILED: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
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
    $artifactLane = 'seam-attested'
    $artifactProof = $null
    if ($VerifyArtifactFile) {
        $artifactProof = Test-RuntimeArtifactFile -RuntimePath $runtimePath -ExpectedDigest $Script:RuntimeDigest -ExpectedPeMachine $Script:RuntimePeMachine
        if ([string]$artifactProof['digest'] -cne [string]$receipt['digest']) { throw [System.InvalidOperationException]::new('RUNTIME-DIGEST-MISMATCH: verified file digest diverges from the acquisition receipt digest.') }
        $artifactLane = 'local-file-verified'
    }
    $issuance = $null
    try { $issuance = (& $OwnerIssuance @{ runId = $runId }) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ISSUANCE-FAILED: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
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
    if ([string]$issuance['fence'] -cnotmatch $Script:RuntimeFencePattern) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issued fence is not a well-formed State Fence.') }
    $startNow = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $clockObserved = (& $Clock)
        if ($clockObserved -is [System.DateTimeOffset]) { $startNow = $clockObserved }
        elseif ($clockObserved -is [System.DateTime]) { $startNow = [System.DateTimeOffset]::new($clockObserved.ToUniversalTime()) }
        else { throw [System.ArgumentException]::new('RUNTIME-INVALID-CLOCK: injected clock must return DateTimeOffset.') }
    }
    $issuanceIssuedAt = ''
    $issuanceExpiresAt = ''
    if ($issuance.ContainsKey('issuedAtUtc') -or $issuance.ContainsKey('expiresUtc')) {
        if (-not $issuance.ContainsKey('issuedAtUtc') -or -not $issuance.ContainsKey('expiresUtc')) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: owner issuance carries a partial freshness window; issued and expiry are required together.') }
        $parsedIssued = [System.DateTimeOffset]::MinValue
        $parsedExpiry = [System.DateTimeOffset]::MinValue
        try { $parsedIssued = [System.DateTimeOffset]::Parse([string]$issuance['issuedAtUtc']) }
        catch { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issuance issuedAtUtc is not a timestamp.') }
        try { $parsedExpiry = [System.DateTimeOffset]::Parse([string]$issuance['expiresUtc']) }
        catch { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issuance expiresUtc is not a timestamp.') }
        if ($parsedExpiry -le $parsedIssued) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issuance expiry does not follow issuance.') }
        if ($parsedIssued -gt $startNow) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-FAILED: issuance was issued in the future.') }
        if ($parsedExpiry -le $startNow) { throw [System.InvalidOperationException]::new('RUNTIME-ISSUANCE-EXPIRED: owner issuance is expired; stale receipts never authorize launch.') }
        $issuanceIssuedAt = $parsedIssued.ToString('o')
        $issuanceExpiresAt = $parsedExpiry.ToString('o')
    }
    $issuanceLane = 'seam-issuance-only'
    $ownerHandshakeBinding = $null
    if ($null -ne $OwnerHandshake) {
        $ownerHandshakeBinding = Test-RuntimeOwnerHandshake -Binding $Binding -Handshake $OwnerHandshake -Clock $Clock
        if ([int]$ownerHandshakeBinding['generation'] -ne $issuedGen) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-MISMATCH: handshake generation disagrees with owner issuance.') }
        if ([string]$ownerHandshakeBinding['fence'] -cne [string]$issuance['fence']) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-MISMATCH: handshake fence disagrees with owner issuance.') }
        if ([int]$ownerHandshakeBinding['epoch'] -ne $issuedEpoch) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-MISMATCH: handshake epoch disagrees with owner issuance.') }
        if ($issuanceExpiresAt -ne '' -and ([string]$ownerHandshakeBinding['expiresUtc'] -cne $issuanceExpiresAt)) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-MISMATCH: handshake expiry disagrees with owner issuance.') }
        $issuanceLane = 'owner-handshake'
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-ENTROPY: entropy must return lowercase hex.') }
    } else { $nonce = $runId.Substring(16, 8) }
    $pipeNamespace = [string]$Allocation['pipeNamespace']
    $sessionId = [string]$Allocation['sessionId']
    $childEnv = Get-RuntimeChildEnv -Ambient @{ PATH = $runtimePath; TEMP = ([string]$Allocation['runRoot']) }
    $governorConfigFullPath = $null
    if ($null -ne $governorBinding) {
        if ($governorBinding.ContainsKey('provenance') -and ([string]$governorBinding['provenance'] -ceq 'run-local-config-created')) {
            foreach ($field in @('fullPath', 'digest')) {
                if (-not $governorBinding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$governorBinding[$field])) { throw [System.InvalidOperationException]::new("RUNTIME-INVALID-ALLOCATION: created governor config is missing '$field'.") }
            }
            $createdFull = [System.IO.Path]::GetFullPath([string]$governorBinding['fullPath'])
            [void](Resolve-RuntimeOwnedPath -RunRoot ([string]$Allocation['runRoot']) -Path $createdFull -ExpectedRunId $runId)
            if (-not (Test-Path -LiteralPath $createdFull -PathType Leaf)) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-MISSING: created governor config is absent at launch; refusing to start.') }
            $createdInfo = Get-Item -LiteralPath $createdFull -Force -ErrorAction Stop
            if ($createdInfo.Length -gt $Script:RuntimeMaxConfigBytes) { throw [System.InvalidOperationException]::new("RUNTIME-CONFIG-BOUND: created governor config exceeds byte bound ($($Script:RuntimeMaxConfigBytes)).") }
            $createdBytes = [System.IO.File]::ReadAllBytes($createdFull)
            $launchHasher = [System.Security.Cryptography.SHA256]::Create()
            $launchDigestBytes = $null
            try { $launchDigestBytes = $launchHasher.ComputeHash($createdBytes) }
            finally { $launchHasher.Dispose() }
            $launchDigest = (($launchDigestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
            if ($launchDigest -cne [string]$governorBinding['digest']) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-DIGEST-MISMATCH: created governor config digest changed after allocation; refusing to start.') }
            $governorConfigFullPath = $createdFull
        } else {
            $governorConfigFullPath = [System.IO.Path]::GetFullPath((Join-Path ([string]$Allocation['runRoot']) ([string]$governorBinding['relativePath'])))
        }
        [void](Resolve-RuntimeOwnedPath -RunRoot ([string]$Allocation['runRoot']) -Path $governorConfigFullPath -ExpectedRunId $runId)
        # Core-owned protected channel: the only ELIOT_GOVERNOR_CONFIG the child can see
        # is this explicit owned-root assignment after ambient filtering (ambient values
        # never survive Get-RuntimeChildEnv, and the path never enters argv).
        $childEnv['ELIOT_GOVERNOR_CONFIG'] = $governorConfigFullPath
    }
    $observed = @{}
    $proofBoundCount = 0
    $requestKeys = @{}
    foreach ($component in $Script:RuntimeLaunchOrder) {
        if ($launchScope -cnotcontains $component) { continue }
        $requestKey = ('req-' + $component + '-' + $nonce)
        $pipe = ($Script:RuntimePipeDevicePrefix + $pipeNamespace + '-' + $component)
        $fixedArgv = @($runtimePath, 'run', '--component', $component, '--pipe', $pipe, '--session', $sessionId)
        $single = $null
        $launchInput = @{ runId = $runId; component = $component; argv = $fixedArgv; pipe = $pipe; sessionId = $sessionId; childEnv = $childEnv; requestKey = $requestKey; jobObjectName = $jobObjectName }
        if ($null -ne $peerCredentialBinding) { $launchInput['peerCredentialHandle'] = [string]$peerCredentialBinding['credentialHandle'] }
        $registeredAt = $startNow.ToString('o')
        try { $single = (& $Launcher $launchInput) }
        catch {
            $message = $_.Exception.Message
            if ($message -match '(?i)lost-response|timeout|unknown') {
                return @{ runId = $runId; launchState = 'ReconciliationRequired'; requested = @{ component = $component; requestKey = $requestKey; pipe = $pipe }; observed = $null; invocation = @{ argvCount = $fixedArgv.Count; pipe = $pipe; component = $component }; binary = @{ version = $Script:RuntimeVersion; digest = [string]$receipt['digest']; provenance = $provenance }; retryPermitted = $false; failure = ('lost-response-owned:' + (Get-RuntimeSafeDiagnosticText -Text $message)) }
            }
            throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: $(Get-RuntimeSafeDiagnosticText -Text $message)")
        }
        if ($null -eq $single -or $single -isnot [hashtable]) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: launcher must return a hashtable observation for '$component'.") }
        if (-not $single.ContainsKey('observedPid') -or -not $single.ContainsKey('observedNonce') -or -not $single.ContainsKey('containment')) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: launcher observation is missing pid/nonce/containment for '$component'.") }
        $observedPid = 0
        try { $observedPid = [int]$single['observedPid'] } catch { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: observed pid is not an integer for '$component'.") }
        if ($observedPid -le 0) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: observed pid is not positive for '$component'.") }
        if ([string]$single['observedNonce'] -ceq $nonce) { throw [System.InvalidOperationException]::new("RUNTIME-LAUNCH-FAILED: requested and observed nonces must be distinct handles for '$component'.") }
        if ([string]$single['containment'] -cnotin $Script:RuntimeAcceptedContainments) { throw [System.InvalidOperationException]::new("RUNTIME-CONTAINMENT-MISSING: component '$component' entered without Job Object containment proof; execution is not recognized.") }
        $proofKeysPresent = @(@('jobObjectName', 'observedImage', 'observedStartUtc') | Where-Object { $single.ContainsKey($_) })
        $componentProof = $null
        if ($proofKeysPresent.Count -gt 0) {
            if ($proofKeysPresent.Count -ne 3) { throw [System.InvalidOperationException]::new("RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: partial containment proof rejected for '$component'.") }
            $componentProof = Test-RuntimeContainmentProof -Allocation $Allocation -RuntimePath $runtimePath -Proof @{ jobObjectName = [string]$single['jobObjectName']; method = [string]$single['containment']; observedImage = [string]$single['observedImage']; observedStartUtc = [string]$single['observedStartUtc']; observedPid = $observedPid } -RegisteredAtUtc $registeredAt -Clock $Clock
        }
        $observed[$component] = @{ pid = $observedPid; nonce = [string]$single['observedNonce']; containment = [string]$single['containment']; pipe = $pipe; requestKey = $requestKey }
        if ($null -ne $componentProof) {
            $observed[$component]['jobObjectName'] = [string]$componentProof['jobObjectName']
            $observed[$component]['observedImage'] = [string]$componentProof['observedImage']
            $observed[$component]['observedStartUtc'] = [string]$componentProof['observedStartUtc']
            $proofBoundCount++
        }
        $requestKeys[$component] = $requestKey
    }
    $ownerIssuanceOut = @{ generation = $issuedGen; fence = [string]$issuance['fence']; epoch = $issuedEpoch; owner = [string]$issuance['owner'] }
    if ($issuanceIssuedAt -ne '') { $ownerIssuanceOut['issuedAtUtc'] = $issuanceIssuedAt; $ownerIssuanceOut['expiresUtc'] = $issuanceExpiresAt }
    if ($null -ne $ownerHandshakeBinding) {
        $ownerIssuanceOut['issuer'] = [string]$ownerHandshakeBinding['issuer']
        $ownerIssuanceOut['handshakeDigest'] = [string]$ownerHandshakeBinding['handshakeDigest']
        $ownerIssuanceOut['issuedAtUtc'] = [string]$ownerHandshakeBinding['issuedAtUtc']
        $ownerIssuanceOut['expiresUtc'] = [string]$ownerHandshakeBinding['expiresUtc']
        $ownerIssuanceOut['currentExpiry'] = [string]$ownerHandshakeBinding['currentExpiry']
    } elseif ($issuanceExpiresAt -ne '') { $ownerIssuanceOut['currentExpiry'] = $issuanceExpiresAt }
    $containmentLane = 'launcher-asserted'
    if ($proofBoundCount -eq @($launchScope).Count) { $containmentLane = 'proof-bound' }
    $governorStartLane = 'none'
    if ($null -ne $governorBinding) {
        $governorStartLane = 'receipt-declared'
        if ($governorBinding.ContainsKey('provenance') -and ([string]$governorBinding['provenance'] -ceq 'run-local-config-created')) { $governorStartLane = 'created-file' }
    }
    $startResult = @{ runId = $runId; launchState = 'launch-registered'; containedObserved = $true; requested = @{ requestKeys = $requestKeys; pipeNamespace = $pipeNamespace; sessionId = $sessionId }; observed = $observed; invocation = @{ argvCount = 8; artifact = $Script:RuntimeArtifact }; binary = @{ version = $Script:RuntimeVersion; architecture = $Script:RuntimeArchitecture; peMachine = $Script:RuntimePeMachine; peProfile = $Script:RuntimePeProfile; digest = [string]$receipt['digest']; provenance = $provenance; runtimePath = $runtimePath }; ownerIssuance = $ownerIssuanceOut; pipeNamespace = $pipeNamespace; sessionId = $sessionId }
    if ($null -ne $governorBinding) { $startResult['governorConfig'] = $governorBinding }
    if ($null -ne $governorConfigFullPath) { $startResult['governorConfigPath'] = $governorConfigFullPath }
    $startResult['principal'] = $Allocation['principal']
    $startResult['verificationLanes'] = @{ artifact = $artifactLane; issuance = $issuanceLane; containment = $containmentLane; governorConfig = $governorStartLane }
    if ($null -ne $artifactProof) { $startResult['binary']['artifactVerification'] = $artifactProof }
    $startResult['launchScope'] = @($launchScope)
    $startResult['launchScopeSource'] = $launchScopeSource
    if ($null -ne $peerCredentialBinding) { $startResult['peerCredential'] = $peerCredentialBinding }
    if ($Allocation.ContainsKey('providerReceipts') -and $null -ne $Allocation['providerReceipts'] -and @($Allocation['providerReceipts']).Count -gt 0) { $startResult['providerReceipts'] = @($Allocation['providerReceipts']) }
    if ($Allocation.ContainsKey('requiredReceipts') -and $null -ne $Allocation['requiredReceipts']) { $startResult['requiredReceipts'] = @($Allocation['requiredReceipts']) }
    return $startResult
}
function Invoke-RuntimeObserveReadiness {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$StartReceipt, [Parameter(Mandatory)][AllowNull()][scriptblock]$ProcessObserver, [Parameter(Mandatory)][AllowNull()][scriptblock]$PipeObserver, [Parameter(Mandatory)][AllowNull()][scriptblock]$TopologyClient, [Parameter()][AllowNull()][scriptblock]$Clock, [Parameter()][switch]$LiveProcessProbe)
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
    $currentExpiry = ''
    $expiryLane = 'no-expiry-bound'
    $observeNow = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observeClock = (& $Clock)
        if ($observeClock -is [System.DateTimeOffset]) { $observeNow = $observeClock }
        elseif ($observeClock -is [System.DateTime]) { $observeNow = [System.DateTimeOffset]::new($observeClock.ToUniversalTime()) }
        else { throw [System.ArgumentException]::new('RUNTIME-INVALID-CLOCK: injected clock must return DateTimeOffset.') }
    }
    if ($issuance.ContainsKey('expiresUtc') -and -not [string]::IsNullOrWhiteSpace([string]$issuance['expiresUtc'])) {
        $issuanceExpiry = [System.DateTimeOffset]::MinValue
        try { $issuanceExpiry = [System.DateTimeOffset]::Parse([string]$issuance['expiresUtc']) }
        catch { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt issuance expiry is not a timestamp.') }
        $currentExpiry = $issuanceExpiry.ToString('o')
        $expiryLane = 'expiry-enforced'
        if ($issuanceExpiry -le $observeNow) { $genFenceOk = $false; $genFenceState = 'generation-fence-expired' }
    }
    if ($client.ContainsKey('expiresUtc') -and -not [string]::IsNullOrWhiteSpace([string]$client['expiresUtc'])) {
        $clientExpiry = [System.DateTimeOffset]::MinValue
        try { $clientExpiry = [System.DateTimeOffset]::Parse([string]$client['expiresUtc']) }
        catch { throw [System.InvalidOperationException]::new('RUNTIME-CLIENT-FAILED: client receipt expiry is not a timestamp.') }
        $expiryLane = 'expiry-enforced'
        if ($currentExpiry -eq '') { $currentExpiry = $clientExpiry.ToString('o') }
        if ($clientExpiry -le $observeNow) { $genFenceOk = $false; $genFenceState = 'generation-fence-expired' }
    }
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
        if ($LiveProcessProbe -and $StartReceipt['observed'][$component].ContainsKey('observedImage')) {
            $recordedStart = $null
            if ($StartReceipt['observed'][$component].ContainsKey('observedStartUtc')) { $recordedStart = [string]$StartReceipt['observed'][$component]['observedStartUtc'] }
            try { [void](Get-RuntimeProcessBinding -ProcessId $ownedPid -ExpectedImagePath ([string]$StartReceipt['observed'][$component]['observedImage']) -ExpectedStartUtc $recordedStart) }
            catch {
                $probeDetail = $_.Exception.Message
                if (($probeDetail -match 'RUNTIME-PROCESS-ABSENT') -and (-not [bool]$process['alive'])) { }
                else { throw }
            }
        }
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
    $governorBinding = $null
    if ($StartReceipt.ContainsKey('governorConfig') -and $null -ne $StartReceipt['governorConfig']) {
        $candidate = $StartReceipt['governorConfig']
        if ($candidate -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt governorConfig is not a hashtable receipt.') }
        foreach ($field in @('relativePath', 'digest')) {
            if (-not $candidate.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$candidate[$field])) { throw [System.InvalidOperationException]::new("RUNTIME-RECEIPT-STALE: start receipt governorConfig is missing '$field'.") }
        }
        if ($candidate.ContainsKey('runId') -and ([string]$candidate['runId'] -cne $runId)) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: start receipt governorConfig run identity is foreign.') }
        $governorBinding = $candidate
    }
    $artifactBinding = @{}
    if ($StartReceipt.ContainsKey('binary') -and ($StartReceipt['binary'] -is [hashtable])) {
        foreach ($field in @('version', 'architecture', 'peMachine', 'peProfile', 'digest', 'provenance', 'runtimePath')) {
            if ($StartReceipt['binary'].ContainsKey($field)) { $artifactBinding[$field] = [string]$StartReceipt['binary'][$field] }
        }
    }
    $processBindings = @{}
    foreach ($component in $Script:RuntimeLaunchOrder) {
        $processBindings[$component] = @{ pid = [int]$StartReceipt['observed'][$component]['pid']; pipe = [string]$StartReceipt['observed'][$component]['pipe']; containment = [string]$StartReceipt['observed'][$component]['containment'] }
        if ($StartReceipt['observed'][$component].ContainsKey('observedImage')) {
            $processBindings[$component]['observedImage'] = [string]$StartReceipt['observed'][$component]['observedImage']
            $processBindings[$component]['jobObjectName'] = [string]$StartReceipt['observed'][$component]['jobObjectName']
        }
        if ($StartReceipt['observed'][$component].ContainsKey('observedStartUtc')) { $processBindings[$component]['observedStartUtc'] = [string]$StartReceipt['observed'][$component]['observedStartUtc'] }
    }
    $dependencyBindings = @{}
    foreach ($component in $Script:RuntimeComponents) { $dependencyBindings[$component] = @($Script:RuntimeComponentDependencies[$component]) }
    $observationLane = 'seam-observation'
    if ($LiveProcessProbe) { $observationLane = 'live-probe-attested' }
    $readinessLanes = @{ observation = $observationLane; expiry = $expiryLane }
    if ($StartReceipt.ContainsKey('verificationLanes') -and ($StartReceipt['verificationLanes'] -is [hashtable])) {
        foreach ($laneKey in @($StartReceipt['verificationLanes'].Keys)) { $readinessLanes[('start-' + $laneKey)] = [string]$StartReceipt['verificationLanes'][$laneKey] }
    }
    $readinessResult = @{ runId = $runId; readinessState = $state; ready = $whole; wholeTopologyReady = $whole; peerState = $peerState; peerAuthenticated = [bool]$client['peerAuthenticated']; generationFenceState = $genFenceState; generationAccepted = $genFenceOk; staleGeneration = (-not $genFenceOk); components = $components; blockedDependents = @($blockedDependents); pipeNamespace = $ownedNamespace; artifact = $artifactBinding; processes = $processBindings; sessionId = $ownedSession; currentExpiry = $currentExpiry; dependencies = $dependencyBindings; verificationLanes = $readinessLanes }
    if ($StartReceipt.ContainsKey('principal') -and ($StartReceipt['principal'] -is [hashtable])) { $readinessResult['principal'] = $StartReceipt['principal'] }
    if ($null -ne $governorBinding) { $readinessResult['governorConfig'] = $governorBinding }
    if ($StartReceipt.ContainsKey('providerReceipts') -and $null -ne $StartReceipt['providerReceipts'] -and @($StartReceipt['providerReceipts']).Count -gt 0) {
        foreach ($accepted in @($StartReceipt['providerReceipts'])) {
            if (($accepted -isnot [hashtable]) -or (-not $accepted.ContainsKey('testClass')) -or (-not $accepted.ContainsKey('providerRevision')) -or (-not $accepted.ContainsKey('digest'))) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-STALE: start receipt provider receipt is not an accepted lane binding.') }
            [void](Test-RuntimeDigestFormat -Digest ([string]$accepted['digest']))
            if ($accepted.ContainsKey('runId') -and ([string]$accepted['runId'] -cne $runId)) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: start receipt provider receipt run identity is foreign.') }
        }
        $readinessResult['providerReceipts'] = @($StartReceipt['providerReceipts'])
    }
    return $readinessResult
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
    $secretCount = 0
    if ($null -ne $Secrets) { $secretCount = @($Secrets).Count }
    $redacted = Get-RuntimeRedactedText -Text $LogText -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) {
        return @{ runId = [string]$Binding['runId']; terminalState = $TerminalState; evidenceState = 'EvidenceCollectionFailed'; bytes = 0; truncated = $false; redactionFailed = $true; owner = [string]$Binding['owner']; secretCount = $secretCount; maxBytes = $MaxBytes }
    }
    return @{ runId = [string]$Binding['runId']; testClass = $Script:RuntimeTestClass; providerRevision = $Script:RuntimeProviderRevision; generation = [int]$Binding['generation']; owner = [string]$Binding['owner']; evidenceId = ('ev-' + ([string]$Binding['runId']).Substring(0, 8)); terminalState = $TerminalState; evidenceState = 'TerminalTestEvidence'; bytes = [int]$redacted.bytes; truncated = [bool]$redacted.truncated; text = [string]$redacted.text; secretCount = $secretCount; maxBytes = $MaxBytes }
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
    # Teardown never acts on a component label, a pipe name or a PID alone. Each
    # component carries this run's own launch claim (the pid the run asked the
    # launcher to bind, the image the run asked to launch, and the observed start
    # when the containment proof recorded one), and that claim is re-proven live
    # before any termination request. An unproven claim is never handed to the
    # controller: the process is left running and reported instead.
    $ownedIdentities = @{}
    foreach ($component in $Script:RuntimeComponents) {
        $observedEntry = $StartReceipt['observed'][$component]
        $expectedImage = ''
        if ($observedEntry.ContainsKey('observedImage')) { $expectedImage = [string]$observedEntry['observedImage'] }
        if ([string]::IsNullOrWhiteSpace($expectedImage) -and $StartReceipt.ContainsKey('binary') -and ($StartReceipt['binary'] -is [hashtable]) -and $StartReceipt['binary'].ContainsKey('runtimePath')) { $expectedImage = [string]$StartReceipt['binary']['runtimePath'] }
        $expectedStart = ''
        if ($observedEntry.ContainsKey('observedStartUtc')) { $expectedStart = [string]$observedEntry['observedStartUtc'] }
        $ownedIdentities[$component] = @{ pid = [int]$ownedPids[$component]; expectedImage = $expectedImage; expectedStartUtc = $expectedStart }
    }
    if ($null -eq $ProcessController) { throw [System.ArgumentException]::new('RUNTIME-MISSING-CONTROLLER: a process-controller seam is required.') }
    $stopOrder = New-Object Collections.Generic.List[string]
    $componentStates = @{}
    $unprovenOwnership = New-Object Collections.Generic.List[string]
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
            $identity = $ownedIdentities[$component]
            $owned = $null
            $ownershipFailure = ''
            try { $owned = Get-RuntimeProcessBinding -ProcessId ([int]$identity['pid']) -ExpectedImagePath ([string]$identity['expectedImage']) -ExpectedStartUtc ([string]$identity['expectedStartUtc']) }
            catch { $ownershipFailure = [string]$_.Exception.Message }
            if ($null -eq $owned) {
                # Already gone: there is nothing to terminate and nothing to delete,
                # so the controller is never handed a pid that could be recycled.
                if ($ownershipFailure -match 'RUNTIME-PROCESS-ABSENT') {
                    $componentStates[$component] = 'process-exited'
                    [void]$stopOrder.Add(($phaseName + ':' + $component))
                    continue
                }
                # Ownership unproven (foreign image, recycled pid, unreadable identity
                # or no launch claim): left alone and reported, never terminated.
                $componentStates[$component] = 'ownership-unproven'
                [void]$unprovenOwnership.Add(('{0}:{1}:{2}' -f $component, $phaseName, (Get-RuntimeSafeDiagnosticText -Text $ownershipFailure)))
                continue
            }
            $phase = (& $ProcessController @{ phase = $phaseName; component = $component; pid = [int]$identity['pid']; runId = $runId; expectedImage = [string]$identity['expectedImage']; expectedStartUtc = [string]$identity['expectedStartUtc'] })
            if ($null -eq $phase) {
                return @{ runId = $runId; stopState = 'ReconciliationRequired'; requestedStop = $true; stopOrder = @($stopOrder); forced = $forced; retryPermitted = $false; failure = ("unknown-stop-owned:{0}:{1}" -f $component, $phaseName); unprovenOwnership = @($unprovenOwnership) }
            }
            if ($phase -isnot [hashtable] -or -not $phase.ContainsKey('exited')) { throw [System.InvalidOperationException]::new("RUNTIME-CONTROLLER-FAILED: $phaseName phase must return an exited mapping for '$component'.") }
            if ($phase.ContainsKey('pid') -and ([int]$phase['pid'] -ne [int]$ownedPids[$component])) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-PROCESS: controller touched a foreign pid for '$component'; PID reuse is rejected.") }
            [void]$stopOrder.Add(($phaseName + ':' + $component))
            if ([bool]$phase['exited']) { $componentStates[$component] = 'process-exited' }
        }
    }
    $phase = 'graceful'
    if ($forced) { $phase = 'forced' }
    $stopResult = @{ runId = $runId; stopPhase = $phase; stopState = 'ShutdownRequested'; stopOrder = @($stopOrder); componentStates = $componentStates; ownedPids = $ownedPids; forced = $forced }
    if ($unprovenOwnership.Count -gt 0) { $stopResult['unprovenOwnership'] = @($unprovenOwnership) }
    return $stopResult
}
function Invoke-RuntimeVerifyCleanup {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][hashtable]$StartReceipt, [Parameter()][AllowNull()][scriptblock]$ProcessObserver, [Parameter()][AllowNull()][scriptblock]$JobObserver, [Parameter()][AllowNull()][scriptblock]$PipeObserver, [Parameter()][AllowNull()][scriptblock]$HandleProbe, [Parameter()][AllowNull()][scriptblock]$PortObserver, [Parameter()][switch]$Strict, [Parameter()][AllowNull()][AllowEmptyString()][string]$PriorFailure)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-RECEIPT-FOREIGN: allocation run identity is foreign.') }
    foreach ($field in @('runRoot', 'installationRoot', 'sessionRoot', 'configRoot', 'dataRoot', 'logRoot', 'tempRoot', 'artifactRoot', 'pipeNamespace')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-ALLOCATION: allocation is missing '$field'.") }
    }
    $runRoot = [System.IO.Path]::GetFullPath([string]$Allocation['runRoot'])
    $runLeaf = [System.IO.Path]::GetFileName($runRoot)
    if ([string]::IsNullOrWhiteSpace($runLeaf) -or -not $runLeaf.Contains($runId)) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: cleanup run root leaf does not carry the run identity: $(Get-RuntimeSafeDiagnosticText -Text $runRoot)") }
    $runPrefix = $runRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($rootField in @('installationRoot', 'sessionRoot', 'configRoot', 'dataRoot', 'logRoot', 'tempRoot', 'artifactRoot')) {
        $rootFull = [System.IO.Path]::GetFullPath([string]$Allocation[$rootField])
        if ($rootFull -ine $runRoot -and -not $rootFull.StartsWith($runPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-ROOT: allocation root '$rootField' escapes the owned run root.") }
    }
    [void](Resolve-RuntimeOwnedPath -RunRoot $runRoot -Path $runRoot -ExpectedRunId $runId)
    $failures = New-Object Collections.Generic.List[string]
    $unknowns = New-Object Collections.Generic.List[string]
    $priorFailureText = ''
    if (-not [string]::IsNullOrWhiteSpace($PriorFailure)) {
        if ($PriorFailure.Length -gt $Script:RuntimeMaxPriorFailureChars) { throw [System.ArgumentException]::new("RUNTIME-FAILURE-BOUND: prior failure exceeds char bound ($($Script:RuntimeMaxPriorFailureChars)).") }
        $redactedPrior = Get-RuntimeRedactedText -Text $PriorFailure -Secrets @() -MaxBytes 65536
        if ([bool]$redactedPrior.failed) { $priorFailureText = '[prior-failure-redaction-failed]' }
        else { $priorFailureText = [string]$redactedPrior.text }
    }
    $seamPresence = @{ process = ($null -ne $ProcessObserver); job = ($null -ne $JobObserver); pipe = ($null -ne $PipeObserver); handle = ($null -ne $HandleProbe); port = ($null -ne $PortObserver) }
    if ($Strict) {
        $missingSeams = @($seamPresence.Keys | Where-Object { -not $seamPresence[$_] })
        if ($missingSeams.Count -gt 0) { throw [System.ArgumentException]::new("RUNTIME-MISSING-OBSERVER: strict cleanup verification requires every observer seam; missing: $($missingSeams -join ', ').") }
    } else {
        foreach ($area in @('process', 'job', 'pipe', 'handle', 'port')) {
            if (-not $seamPresence[$area]) { [void]$unknowns.Add(('unverified-' + $area + '-seam-omitted')) }
        }
    }
    $verificationLane = 'seam-optional'
    if ($Strict) { $verificationLane = 'strict' }
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
            if ($null -eq $process) {
                if ($Strict) { [void]$unknowns.Add(('unknown-process:' + $component)) }
                else { [void]$unknowns.Add(('unverified-process:' + $component)) }
            }
            if ($null -ne $process -and $process -is [hashtable]) {
                if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne [int]$ownedPids[$component])) { throw [System.InvalidOperationException]::new("RUNTIME-FOREIGN-PROCESS: cleanup observer returned a foreign pid for '$component'.") }
                if ($process.ContainsKey('alive') -and [bool]$process['alive']) { [void]$failures.Add(('process-still-alive:' + $component)) }
                if ($process.ContainsKey('descendants') -and $null -ne $process['descendants'] -and @($process['descendants']).Count -gt 0) { [void]$failures.Add(('descendants-remaining:' + $component + ':' + @($process['descendants']).Count)) }
            }
        }
    }
    if ($null -ne $JobObserver) {
        $job = (& $JobObserver @{ runId = $runId; pipeNamespace = [string]$Allocation['pipeNamespace'] })
        if ($null -eq $job) {
            if ($Strict) { [void]$unknowns.Add('unknown-job') }
            else { [void]$unknowns.Add('unverified-job') }
        }
        if ($null -ne $job -and $job -is [hashtable]) {
            if ($job.ContainsKey('pipeNamespace') -and ([string]$job['pipeNamespace'] -cne [string]$Allocation['pipeNamespace'])) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: cleanup job observer returned a foreign namespace.') }
            if ($job.ContainsKey('jobAlive') -and [bool]$job['jobAlive']) { [void]$failures.Add('job-still-active') }
            if ($job.ContainsKey('members') -and $null -ne $job['members'] -and @($job['members']).Count -gt 0) { [void]$failures.Add(('job-members-remaining:' + @($job['members']).Count)) }
        }
    }
    if ($null -ne $PipeObserver) {
        $pipes = (& $PipeObserver @{ pipeNamespace = [string]$Allocation['pipeNamespace']; runId = $runId })
        if ($null -eq $pipes) {
            if ($Strict) { [void]$unknowns.Add('unknown-pipes') }
            else { [void]$unknowns.Add('unverified-pipes') }
        }
        if ($null -ne $pipes -and $pipes -is [hashtable]) {
            if ($pipes.ContainsKey('pipeNamespace') -and ([string]$pipes['pipeNamespace'] -cne [string]$Allocation['pipeNamespace'])) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: cleanup pipe observer returned a foreign namespace.') }
            if ($pipes.ContainsKey('pipesOpen') -and [bool]$pipes['pipesOpen']) { [void]$failures.Add('pipes-still-open') }
        }
    }
    if ($null -ne $HandleProbe) {
        $probe = (& $HandleProbe @{ runRoot = $runRoot; runId = $runId })
        if ($null -eq $probe) {
            if ($Strict) { [void]$unknowns.Add('unknown-handles') }
            else { [void]$unknowns.Add('unverified-handles') }
        }
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
    if ($null -ne $PortObserver) {
        $portObservation = (& $PortObserver @{ runId = $runId; pipeNamespace = [string]$Allocation['pipeNamespace'] })
        if ($null -eq $portObservation) {
            if ($Strict) { [void]$unknowns.Add('unknown-ports') }
            else { [void]$unknowns.Add('unverified-ports') }
        } else {
            if ($portObservation -isnot [hashtable]) { throw [System.InvalidOperationException]::new('RUNTIME-OBSERVER-FAILED: port observer must return a hashtable.') }
            $portCheck = Test-RuntimePortObservation -Allocation $Allocation -Observation $portObservation
            foreach ($portFailure in @($portCheck['failures'])) { [void]$failures.Add($portFailure) }
        }
    }
    if ($failures.Count -gt 0 -or ($Strict -and $unknowns.Count -gt 0)) {
        $cleanupResult = @{ runId = $runId; cleanupState = 'ReconciliationRequired'; cleaned = $false; failures = @($failures); unknowns = @($unknowns); ownedRoot = $runRoot; verificationLane = $verificationLane }
        if ($priorFailureText -ne '') { $cleanupResult['priorFailure'] = $priorFailureText }
        return $cleanupResult
    }
    $cleanResult = @{ runId = $runId; cleanupState = 'AllResourcesReaped'; cleaned = $true; failures = @(); unknowns = @($unknowns); ownedRoot = $runRoot; verificationLane = $verificationLane }
    if ($priorFailureText -ne '') { $cleanResult['priorFailure'] = $priorFailureText }
    return $cleanResult
}
function Test-RuntimeStoreHandleReference {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$StoreHandles)
    # Scope: shape + run-consistency only (forms mirrored from
    # IntegrationHarness.Store.psm1: namespace derivation :1004, loopback :135,
    # ephemeral port bound :1029, handle shape :761). This check never proves #909
    # issuance by itself; issuance is proven by the consumed STORE provider receipt
    # (Allocate -ProviderReceipts, threaded as Resolve -AcceptedStoreReceipt).
    # Validates a reference to the #909 Store provisioner handle triple as issued by
    # Invoke-StoreAllocate (:941; namespace/endpoint :1004/:1032-:1039) and New-StoreEphemeralCredential (:728)
    # (credentialHandle). This module only references Store-issued handles; it never
    # mints them. Shapes mirror scripts/integration/IntegrationHarness.Store.psm1
    # (namespace derivation, loopback endpoint bound, credential-handle shape).
    foreach ($field in @('namespace', 'endpoint', 'credentialHandle')) {
        if (-not $StoreHandles.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$StoreHandles[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-STORE-HANDLE: store handle reference is missing '$field'.") }
    }
    if ($StoreHandles.ContainsKey('secret')) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-VALUE: store handle reference must report names/handles, never values.') }
    $runId = [string]$Binding['runId']
    $expectedNamespace = ($Script:RuntimeStoreNamespacePrefix + $runId.Substring(0, 8))
    if ([string]$StoreHandles['namespace'] -cne $expectedNamespace) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-FOREIGN: store namespace is not the run-owned #909 namespace for this run.') }
    $endpoint = [string]$StoreHandles['endpoint']
    $separator = $endpoint.LastIndexOf(':')
    if ($separator -le 0) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-ENDPOINT: store endpoint must be a host:port pair.') }
    $host_ = $endpoint.Substring(0, $separator)
    $portText = $endpoint.Substring($separator + 1)
    if ($host_ -cne $Script:RuntimeStoreLoopback) { throw [System.InvalidOperationException]::new("RUNTIME-STORE-HANDLE-ENDPOINT: store endpoint host '$host_' is not loopback.") }
    $port = 0
    try { $port = [int]$portText } catch { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-ENDPOINT: store endpoint port is not an integer.') }
    if ($port -lt 1024 -or $port -gt 65535) { throw [System.InvalidOperationException]::new("RUNTIME-STORE-HANDLE-ENDPOINT: store endpoint port '$port' is outside the ephemeral bound.") }
    if ([string]$StoreHandles['credentialHandle'] -cnotmatch '^handle:[A-Za-z0-9][A-Za-z0-9._-]{0,63}:[0-9a-f]{8}$') { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-SHAPE: store credentialHandle is not a #909-issued handle shape.') }
    return $true
}
function Resolve-RuntimeGovernorConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$ConfigReceipt, [Parameter()][AllowNull()][AllowEmptyString()][string]$RunRoot, [Parameter()][AllowNull()][hashtable]$AcceptedStoreReceipt)
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
    if ($ConfigReceipt.ContainsKey('relativePath') -and ([string]$ConfigReceipt['relativePath'] -cne $Script:RuntimeGovernorConfigRelativePath)) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-PROVENANCE: declared governor config path is not the exact versioned run-local location.') }
    $relativePath = $Script:RuntimeGovernorConfigRelativePath
    if (-not [string]::IsNullOrWhiteSpace($RunRoot)) {
        [void](Resolve-RuntimeOwnedPath -RunRoot $RunRoot -Path (Join-Path $RunRoot $relativePath) -ExpectedRunId ([string]$Binding['runId']))
    }
    $storeHandles = $null
    $storeKeys = @('storeNamespace', 'storeEndpoint', 'storeCredentialHandle')
    $declaredStoreKeys = @($storeKeys | Where-Object { $ConfigReceipt.ContainsKey($_) })
    if ($declaredStoreKeys.Count -gt 0) {
        if ($declaredStoreKeys.Count -ne $storeKeys.Count) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: partial #909 store-handle reference; namespace, endpoint, and credentialHandle are required together.') }
        if ($null -eq $AcceptedStoreReceipt) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-UNPROVEN: store handle reference requires the accepted STORE provider receipt; shape alone never proves #909 issuance.') }
        [void](Test-RuntimeProviderReceipt -Receipt $AcceptedStoreReceipt)
        if ([string]$AcceptedStoreReceipt['testClass'] -cne 'STORE') { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-UNPROVEN: accepted receipt is not the STORE lane.') }
        if ([string]$AcceptedStoreReceipt['runId'] -cne [string]$Binding['runId']) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-UNPROVEN: accepted STORE receipt run identity is foreign.') }
        $candidate = @{ namespace = [string]$ConfigReceipt['storeNamespace']; endpoint = [string]$ConfigReceipt['storeEndpoint']; credentialHandle = [string]$ConfigReceipt['storeCredentialHandle'] }
        [void](Test-RuntimeStoreHandleReference -Binding $Binding -StoreHandles $candidate)
        $candidate['receiptDigest'] = [string]$AcceptedStoreReceipt['digest']
        $storeHandles = $candidate
    }
    $resolved = @{ runId = [string]$Binding['runId']; configName = $Script:RuntimeGovernorConfigName; version = $Script:RuntimeGovernorConfigVersion; channel = $Script:RuntimeGovernorConfigChannel; relativePath = $relativePath; digest = [string]$ConfigReceipt['digest']; provenance = 'run-local-config-receipt'; accepted = $true }
    if ($null -ne $storeHandles) { $resolved['storeHandles'] = $storeHandles }
    return $resolved
}
function Test-RuntimeArtifactFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RuntimePath, [Parameter(Mandatory)][string]$ExpectedDigest, [Parameter(Mandatory)][string]$ExpectedPeMachine, [ValidateRange(4096, 268435456)][int]$MaxBytes = 134217728)
    if ([string]::IsNullOrWhiteSpace($RuntimePath)) { throw [System.ArgumentException]::new('RUNTIME-ARTIFACT-MISSING: runtime path is empty.') }
    [void](Test-RuntimeDigestFormat -Digest $ExpectedDigest)
    if ([string]::IsNullOrWhiteSpace($ExpectedPeMachine) -or ($ExpectedPeMachine -cnotmatch '^[0-9a-fA-F]{4}$')) { throw [System.ArgumentException]::new('RUNTIME-ARTIFACT-PE-MISMATCH: expected PE machine must be 4 hex digits.') }
    $full = $null
    try { $full = [System.IO.Path]::GetFullPath($RuntimePath) }
    catch { throw [System.ArgumentException]::new('RUNTIME-ARTIFACT-MISSING: runtime path is not usable.') }
    $leaf = $null
    try { $leaf = Get-Item -LiteralPath $full -Force -ErrorAction Stop }
    catch { throw [System.IO.FileNotFoundException]::new("RUNTIME-ARTIFACT-MISSING: runtime file is absent: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    if ($leaf -isnot [System.IO.FileInfo]) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-MISSING: runtime path is not a file: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    if (($leaf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-REPARSE: runtime file is a reparse point: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    $cursor = Split-Path -Parent $full
    $depth = 0
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and $depth -lt 64) {
        $depth++
        $entry = $null
        try { $entry = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry -and (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-REPARSE: runtime path crosses a reparse point: $(Get-RuntimeSafeDiagnosticText -Text $entry.FullName)") }
        $next = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($next) -or $next -ceq $cursor) { break }
        $cursor = $next
    }
    if ($leaf.Length -le 0) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-MISSING: runtime file is empty: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    if ($leaf.Length -gt $MaxBytes) { throw [System.ArgumentException]::new("RUNTIME-ARTIFACT-BOUND: runtime file exceeds byte bound ($MaxBytes): $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    $header = [byte[]]::new(65536)
    $headerCount = 0
    $machineHex = ''
    $digestBytes = $null
    $stream = $null
    try {
        $stream = [System.IO.File]::OpenRead($full)
        while ($headerCount -lt $header.Length) {
            $read = $stream.Read($header, $headerCount, $header.Length - $headerCount)
            if ($read -le 0) { break }
            $headerCount += $read
        }
        if ($headerCount -lt 64) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-NOT-PE: file too small for headers: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
        if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-NOT-PE: missing MZ signature: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
        $peOffset = [System.BitConverter]::ToInt32($header, 0x3C)
        if ($peOffset -lt 0 -or ($peOffset + 6) -gt $headerCount) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-NOT-PE: PE offset outside header window: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
        if ($header[$peOffset] -ne 0x50 -or $header[$peOffset + 1] -ne 0x45 -or $header[$peOffset + 2] -ne 0x00 -or $header[$peOffset + 3] -ne 0x00) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-NOT-PE: missing PE signature: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
        $machine = [System.BitConverter]::ToUInt16($header, $peOffset + 4)
        $machineHex = ('{0:x4}' -f $machine)
        if ($machineHex -cne $ExpectedPeMachine.ToLowerInvariant()) { throw [System.InvalidOperationException]::new("RUNTIME-ARTIFACT-PE-MISMATCH: PE machine '$machineHex' is not the accepted '$ExpectedPeMachine'.") }
        $stream.Position = 0
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try { $digestBytes = $hasher.ComputeHash($stream) }
        finally { $hasher.Dispose() }
    }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
    $actual = (($digestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    if ($actual -cne $ExpectedDigest) { throw [System.InvalidOperationException]::new('RUNTIME-ARTIFACT-DIGEST-MISMATCH: file digest does not match the accepted artifact identity.') }
    return @{ path = $full; bytesHashed = [long]$leaf.Length; digest = $actual; peMachine = $machineHex; method = 'local-file-hash-pe'; verifiedAtUtc = ([System.DateTimeOffset]::UtcNow.ToString('o')) }
}
function Test-RuntimeOwnerHandshake {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][hashtable]$Handshake, [Parameter()][AllowNull()][scriptblock]$Clock)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    foreach ($field in @('owner', 'issuer', 'generation', 'fence', 'epoch', 'handshakeDigest', 'issuedAtUtc', 'expiresUtc')) {
        if (-not $Handshake.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Handshake[$field])) { throw [System.ArgumentException]::new("RUNTIME-HANDSHAKE-INCOMPLETE: owner handshake is missing '$field'.") }
    }
    if ([string]$Handshake['owner'] -cne [string]$Binding['owner']) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-FOREIGN: handshake owner does not match the binding owner.') }
    if ([string]$Handshake['issuer'] -cne $Script:RuntimeOwnerHandshakeIssuer) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-UNPROVEN: handshake issuer is not the runtime owner authority; self-minted handshakes are rejected.') }
    $gen = 0
    $epoch = 0
    try { $gen = [int]$Handshake['generation']; $epoch = [int]$Handshake['epoch'] }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-INCOMPLETE: handshake generation/epoch are not integers.') }
    if ($gen -le 0 -or $epoch -le 0) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-INCOMPLETE: handshake generation/epoch must be positive.') }
    if ($gen -ne [int]$Binding['generation']) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-STALE: handshake generation does not match the binding generation.') }
    if ([string]$Handshake['fence'] -cnotmatch $Script:RuntimeFencePattern) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-FENCE: handshake fence is not a well-formed State Fence.') }
    [void](Test-RuntimeDigestFormat -Digest ([string]$Handshake['handshakeDigest']))
    $issued = [System.DateTimeOffset]::MinValue
    $expires = [System.DateTimeOffset]::MinValue
    try { $issued = [System.DateTimeOffset]::Parse([string]$Handshake['issuedAtUtc']) }
    catch { throw [System.ArgumentException]::new('RUNTIME-HANDSHAKE-INCOMPLETE: issuedAtUtc is not a timestamp.') }
    try { $expires = [System.DateTimeOffset]::Parse([string]$Handshake['expiresUtc']) }
    catch { throw [System.ArgumentException]::new('RUNTIME-HANDSHAKE-INCOMPLETE: expiresUtc is not a timestamp.') }
    if ($expires -le $issued) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-INCOMPLETE: handshake expiry does not follow issuance.') }
    $now = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observed = (& $Clock)
        if ($observed -is [System.DateTimeOffset]) { $now = $observed }
        elseif ($observed -is [System.DateTime]) { $now = [System.DateTimeOffset]::new($observed.ToUniversalTime()) }
        else { throw [System.ArgumentException]::new('RUNTIME-INVALID-CLOCK: injected clock must return DateTimeOffset.') }
    }
    if ($issued -gt $now) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-FUTURE: handshake was issued in the future.') }
    if ($expires -le $now) { throw [System.InvalidOperationException]::new('RUNTIME-HANDSHAKE-EXPIRED: owner handshake is expired; stale receipts never restore authority.') }
    return @{ owner = [string]$Handshake['owner']; issuer = $Script:RuntimeOwnerHandshakeIssuer; generation = $gen; fence = [string]$Handshake['fence']; epoch = $epoch; handshakeDigest = [string]$Handshake['handshakeDigest']; issuedAtUtc = $issued.ToString('o'); expiresUtc = $expires.ToString('o'); currentExpiry = $expires.ToString('o') }
}
function Test-RuntimeContainmentProof {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][string]$RuntimePath, [Parameter(Mandatory)][hashtable]$Proof, [Parameter(Mandatory)][string]$RegisteredAtUtc, [Parameter()][AllowNull()][scriptblock]$Clock)
    foreach ($field in @('jobObjectName', 'method', 'observedImage', 'observedStartUtc', 'observedPid')) {
        if (-not $Proof.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Proof[$field])) { throw [System.ArgumentException]::new("RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: containment proof is missing '$field'.") }
    }
    if (-not $Allocation.ContainsKey('jobObjectName') -or [string]::IsNullOrWhiteSpace([string]$Allocation['jobObjectName'])) { throw [System.ArgumentException]::new('RUNTIME-INVALID-ALLOCATION: allocation carries no canonical job-object identity.') }
    if ([string]$Proof['jobObjectName'] -cne [string]$Allocation['jobObjectName']) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-FOREIGN: proof job object is not the exact run-owned containment identity.') }
    if ([string]$Proof['method'] -cnotin $Script:RuntimeAcceptedContainments) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-MISSING: proof method is not an accepted containment.') }
    $expectedImage = $null
    try { $expectedImage = [System.IO.Path]::GetFullPath($RuntimePath) }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-FOREIGN: runtime path is not usable.') }
    $observedImage = $null
    try { $observedImage = [System.IO.Path]::GetFullPath([string]$Proof['observedImage']) }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-FOREIGN: proof image path is not usable.') }
    if ($observedImage -ine $expectedImage) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-FOREIGN: proof image is not the verified runtime image; PID alone never binds identity.') }
    $registered = [System.DateTimeOffset]::MinValue
    $started = [System.DateTimeOffset]::MinValue
    try { $registered = [System.DateTimeOffset]::Parse($RegisteredAtUtc) }
    catch { throw [System.ArgumentException]::new('RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: registeredAtUtc is not a timestamp.') }
    try { $started = [System.DateTimeOffset]::Parse([string]$Proof['observedStartUtc']) }
    catch { throw [System.ArgumentException]::new('RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: observedStartUtc is not a timestamp.') }
    if ($started -lt $registered.AddSeconds(-2)) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-FOREIGN: proof start predates launch registration; reused or foreign process rejected.') }
    $now = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observed = (& $Clock)
        if ($observed -is [System.DateTimeOffset]) { $now = $observed }
        elseif ($observed -is [System.DateTime]) { $now = [System.DateTimeOffset]::new($observed.ToUniversalTime()) }
        else { throw [System.ArgumentException]::new('RUNTIME-INVALID-CLOCK: injected clock must return DateTimeOffset.') }
    }
    if ($started -gt $now.AddMinutes(5)) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-PROOF-FUTURE: proof start is absurdly future-dated.') }
    $proofPid = 0
    try { $proofPid = [int]$Proof['observedPid'] }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: proof pid is not an integer.') }
    if ($proofPid -le 0) { throw [System.InvalidOperationException]::new('RUNTIME-CONTAINMENT-PROOF-INCOMPLETE: proof pid is not positive.') }
    return @{ jobObjectName = [string]$Proof['jobObjectName']; method = [string]$Proof['method']; observedImage = $observedImage; observedStartUtc = $started.ToString('o'); observedPid = $proofPid }
}
function Get-RuntimeProcessBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId, [Parameter(Mandatory)][string]$ExpectedImagePath, [Parameter()][AllowNull()][AllowEmptyString()][string]$ExpectedStartUtc)
    if ($ProcessId -le 0) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PID: process id is not positive.') }
    if ([string]::IsNullOrWhiteSpace($ExpectedImagePath)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: expected image path is empty.') }
    $proc = $null
    try { $proc = Get-Process -Id $ProcessId -ErrorAction Stop }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-ABSENT: no live process binds pid '$ProcessId'.") }
    if ($proc.HasExited) { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-ABSENT: pid '$ProcessId' is not a live process.") }
    $actualImage = $null
    try { $actualImage = $proc.Path }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-UNREADABLE: live process image is not observable for pid '$ProcessId'.") }
    if ([string]::IsNullOrWhiteSpace($actualImage)) { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-UNREADABLE: live process image is empty for pid '$ProcessId'.") }
    $expectedFull = [System.IO.Path]::GetFullPath($ExpectedImagePath)
    $actualFull = [System.IO.Path]::GetFullPath($actualImage)
    if ($actualFull -ine $expectedFull) { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-FOREIGN: live image for pid '$ProcessId' is not the bound runtime image; PID reuse is rejected.") }
    $actualStart = [System.DateTimeOffset]::MinValue
    try { $actualStart = [System.DateTimeOffset]::new($proc.StartTime.ToUniversalTime()) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-UNREADABLE: live process start is not observable for pid '$ProcessId'.") }
    if (-not [string]::IsNullOrWhiteSpace($ExpectedStartUtc)) {
        $expectedStart = [System.DateTimeOffset]::MinValue
        try { $expectedStart = [System.DateTimeOffset]::Parse($ExpectedStartUtc) }
        catch { throw [System.ArgumentException]::new('RUNTIME-PROCESS-UNREADABLE: expected start is not a timestamp.') }
        if (($actualStart - $expectedStart).Duration().TotalSeconds -gt 2) { throw [System.InvalidOperationException]::new("RUNTIME-PROCESS-FOREIGN: live start for pid '$ProcessId' does not match the bound start; PID reuse is rejected.") }
    }
    return @{ pid = $ProcessId; imagePath = $actualFull; startUtc = $actualStart.ToString('o'); alive = (-not $proc.HasExited) }
}
function Test-RuntimePrincipalBinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Principal)
    [void](Test-RuntimePrincipalShape -Principal $Principal)
    $current = $null
    try { $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-PRINCIPAL-UNREADABLE: current test principal is not observable.') }
    if ([string]::IsNullOrWhiteSpace($current)) { throw [System.InvalidOperationException]::new('RUNTIME-PRINCIPAL-UNREADABLE: current test principal is empty.') }
    if ([string]$Principal['principal'] -ine $current) { throw [System.InvalidOperationException]::new('RUNTIME-PRINCIPAL-SUBSTITUTED: bound principal is not the current test principal.') }
    return @{ principal = [string]$Principal['principal']; currentIdentity = $current; sessionId = [string]$Principal['sessionId']; scope = $Script:RuntimePrincipalScope; verified = $true }
}
function Test-RuntimeOwnedRootAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: path is empty.') }
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full)) { throw [System.IO.DirectoryNotFoundException]::new("RUNTIME-ACL-ABSENT: owned path is absent: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    $acl = $null
    try { $acl = Get-Acl -LiteralPath $full -ErrorAction Stop }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ACL-UNREADABLE: ACL is not observable: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    $me = $null
    try { $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
    catch { throw [System.InvalidOperationException]::new('RUNTIME-ACL-UNREADABLE: current test principal SID is not observable.') }
    $ownerSid = $null
    try { $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-ACL-UNREADABLE: owner SID is not resolvable: $(Get-RuntimeSafeDiagnosticText -Text $full)") }
    if ($ownerSid -cne $me) { throw [System.InvalidOperationException]::new('RUNTIME-ACL-FOREIGN-OWNER: owned path is not owned by the current test principal.') }
    $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')
    $allowedMask = [int]([System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
    $explicit = 0
    foreach ($rule in $acl.Access) {
        if ($rule -isnot [System.Security.AccessControl.FileSystemAccessRule]) { continue }
        if ($rule.IsInherited) { continue }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        $explicit++
        $sid = $null
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($sid -cin $broadSids) {
            $excess = ([int]$rule.FileSystemRights) -band (-bnot $allowedMask)
            if ($excess -ne 0) { throw [System.InvalidOperationException]::new("RUNTIME-ACL-BROAD-ACCESS: explicit broad access granted to '$sid' on the owned path.") }
        }
    }
    return @{ path = $full; ownerSid = $ownerSid; explicitAllowRules = $explicit; broadAccess = $false }
}
function New-RuntimeGovernorConfigFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Binding, [Parameter(Mandatory)][string]$RunRoot, [Parameter(Mandatory)][hashtable]$Content, [Parameter()][AllowNull()][hashtable]$StoreHandles, [Parameter()][AllowNull()][hashtable]$AcceptedStoreReceipt, [ValidateRange(1024, 1048576)][int]$MaxBytes = 65536)
    [void](Test-RuntimeBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]::IsNullOrWhiteSpace($RunRoot)) { throw [System.ArgumentException]::new('RUNTIME-INVALID-PATH: RunRoot is empty.') }
    $configFull = [System.IO.Path]::GetFullPath((Join-Path $RunRoot $Script:RuntimeGovernorConfigRelativePath))
    [void](Resolve-RuntimeOwnedPath -RunRoot $RunRoot -Path $configFull -ExpectedRunId $runId)
    foreach ($field in @('scope_id', 'settings')) {
        if (-not $Content.ContainsKey($field)) { throw [System.ArgumentException]::new("RUNTIME-INVALID-CONFIG: governor config content is missing '$field'.") }
    }
    if (@($Content.Keys).Count -ne 2) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-PROVENANCE: governor config content carries unknown top-level fields; scope plus references only.') }
    if ([string]::IsNullOrWhiteSpace([string]$Content['scope_id'])) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config scope_id is empty.') }
    if ([string]$Content['scope_id'] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config scope_id has an invalid shape.') }
    $settings = @($Content['settings'])
    if ($settings.Count -eq 0 -or $settings.Count -gt 128) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config settings must list 1..128 references.') }
    $forbiddenValueKeys = @('secret', 'password', 'passwd', 'token', 'credential', 'apikey', 'api_key', 'connectionstring', 'value')
    $seen = @{}
    $canonicalSettings = @()
    foreach ($setting in $settings) {
        if ($setting -isnot [hashtable]) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config settings must be hashtables.') }
        foreach ($field in @('key', 'value_ref', 'owner_ref')) {
            if (-not $setting.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$setting[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-CONFIG: governor config setting is missing '$field'.") }
        }
        if (@($setting.Keys).Count -ne 3) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-PROVENANCE: governor config setting carries unknown fields; references only.') }
        foreach ($present in @($setting.Keys)) {
            if ([string]$present -cin $forbiddenValueKeys) { throw [System.InvalidOperationException]::new("RUNTIME-CONFIG-SECRET-VALUE: governor config setting must carry references, never values: '$present'.") }
        }
        $settingKey = [string]$setting['key']
        if ($settingKey -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config setting key has an invalid shape.') }
        if ($seen.ContainsKey($settingKey)) { throw [System.ArgumentException]::new("RUNTIME-INVALID-CONFIG: duplicate governor config setting key: '$settingKey'.") }
        $seen[$settingKey] = $true
        if ([string]$setting['value_ref'] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config value_ref has an invalid shape.') }
        if ([string]$setting['owner_ref'] -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: governor config owner_ref has an invalid shape.') }
        $canonicalSettings += [ordered]@{ key = $settingKey; value_ref = [string]$setting['value_ref']; owner_ref = [string]$setting['owner_ref'] }
    }
    $storeTriple = $null
    if ($null -ne $StoreHandles -or $null -ne $AcceptedStoreReceipt) {
        if ($null -eq $StoreHandles -or $null -eq $AcceptedStoreReceipt) { throw [System.ArgumentException]::new('RUNTIME-INVALID-CONFIG: store handles and the accepted STORE receipt are required together.') }
        [void](Test-RuntimeProviderReceipt -Receipt $AcceptedStoreReceipt)
        if ([string]$AcceptedStoreReceipt['testClass'] -cne 'STORE') { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-UNPROVEN: accepted receipt is not the STORE lane.') }
        if ([string]$AcceptedStoreReceipt['runId'] -cne $runId) { throw [System.InvalidOperationException]::new('RUNTIME-STORE-HANDLE-UNPROVEN: accepted STORE receipt run identity is foreign.') }
        foreach ($field in @('storeNamespace', 'storeEndpoint', 'storeCredentialHandle')) {
            if (-not $StoreHandles.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$StoreHandles[$field])) { throw [System.ArgumentException]::new("RUNTIME-INVALID-CONFIG: store handle reference is missing '$field'.") }
        }
        $candidate = @{ namespace = [string]$StoreHandles['storeNamespace']; endpoint = [string]$StoreHandles['storeEndpoint']; credentialHandle = [string]$StoreHandles['storeCredentialHandle'] }
        [void](Test-RuntimeStoreHandleReference -Binding $Binding -StoreHandles $candidate)
        $candidate['receiptDigest'] = [string]$AcceptedStoreReceipt['digest']
        $storeTriple = $candidate
    }
    $document = [ordered]@{ configName = $Script:RuntimeGovernorConfigName; version = $Script:RuntimeGovernorConfigVersion; runId = $runId; channel = $Script:RuntimeGovernorConfigChannel; relativePath = $Script:RuntimeGovernorConfigRelativePath; scope_id = [string]$Content['scope_id']; settings = $canonicalSettings }
    if ($null -ne $storeTriple) { $document['storeHandles'] = [ordered]@{ namespace = $storeTriple['namespace']; endpoint = $storeTriple['endpoint']; credentialHandle = $storeTriple['credentialHandle']; receiptDigest = $storeTriple['receiptDigest'] } }
    $json = ($document | ConvertTo-Json -Depth 8 -Compress)
    if ([string]::IsNullOrWhiteSpace($json)) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-CREATE-FAILED: governor config document did not render.') }
    $encoded = [System.Text.Encoding]::UTF8.GetBytes($json)
    if ($encoded.Length -gt $MaxBytes) { throw [System.ArgumentException]::new("RUNTIME-CONFIG-BOUND: governor config exceeds byte bound ($MaxBytes).") }
    $parent = Split-Path -Parent $configFull
    [void](Resolve-RuntimeOwnedPath -RunRoot $RunRoot -Path $parent -ExpectedRunId $runId)
    try { [void][System.IO.Directory]::CreateDirectory($parent) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-CONFIG-CREATE-FAILED: cannot create owned config dir: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
    if (Test-Path -LiteralPath $configFull) { throw [System.InvalidOperationException]::new('RUNTIME-CONFIG-SQUAT: governor config path is already occupied; refusing to overwrite.') }
    try { [System.IO.File]::WriteAllText($configFull, $json, [System.Text.Encoding]::UTF8) }
    catch { throw [System.InvalidOperationException]::new("RUNTIME-CONFIG-CREATE-FAILED: cannot write owned config file: $(Get-RuntimeSafeDiagnosticText -Text $_.Exception.Message)") }
    try { [void](Test-RuntimeOwnedRootAcl -Path $configFull) }
    catch {
        Remove-Item -LiteralPath $configFull -Force -ErrorAction SilentlyContinue
        throw
    }
    $written = [System.IO.File]::ReadAllBytes($configFull)
    $configHasher = [System.Security.Cryptography.SHA256]::Create()
    $configDigestBytes = $null
    try { $configDigestBytes = $configHasher.ComputeHash($written) }
    finally { $configHasher.Dispose() }
    $digest = (($configDigestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    $resolved = @{ runId = $runId; configName = $Script:RuntimeGovernorConfigName; version = $Script:RuntimeGovernorConfigVersion; channel = $Script:RuntimeGovernorConfigChannel; relativePath = $Script:RuntimeGovernorConfigRelativePath; fullPath = $configFull; digest = $digest; bytes = $written.Length; provenance = 'run-local-config-created'; accepted = $true }
    if ($null -ne $storeTriple) { $resolved['storeHandles'] = $storeTriple }
    return $resolved
}
function Test-RuntimePortObservation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Allocation, [Parameter(Mandatory)][hashtable]$Observation)
    if (-not $Observation.ContainsKey('runId') -or ([string]$Observation['runId'] -cne [string]$Allocation['runId'])) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: port observation run identity is foreign.') }
    if (-not $Observation.ContainsKey('portsOpen')) { throw [System.ArgumentException]::new('RUNTIME-OBSERVER-FAILED: port observation must return a portsOpen mapping.') }
    $ports = @()
    if ($Observation.ContainsKey('ports') -and $null -ne $Observation['ports']) { $ports = @($Observation['ports']) }
    foreach ($entry in $ports) {
        if ($entry -isnot [hashtable] -or -not $entry.ContainsKey('host') -or -not $entry.ContainsKey('port')) { throw [System.InvalidOperationException]::new('RUNTIME-OBSERVER-FAILED: port entries must be host/port mappings.') }
        if ([string]$entry['host'] -cne $Script:RuntimeStoreLoopback) { throw [System.InvalidOperationException]::new('RUNTIME-FOREIGN-PROCESS: port observation reports a non-loopback endpoint.') }
        $observedPort = 0
        try { $observedPort = [int]$entry['port'] }
        catch { throw [System.InvalidOperationException]::new('RUNTIME-OBSERVER-FAILED: observed port is not an integer.') }
        if ($observedPort -lt 1 -or $observedPort -gt 65535) { throw [System.InvalidOperationException]::new('RUNTIME-OBSERVER-FAILED: observed port is out of range.') }
    }
    $portFailures = @()
    if ([bool]$Observation['portsOpen'] -or $ports.Count -gt 0) { $portFailures += 'ports-still-open' }
    return @{ runId = [string]$Allocation['runId']; portsObserved = $ports.Count; failures = $portFailures }
}
Export-ModuleMember -Function @('Get-RuntimeProviderIdentity', 'Get-RuntimeLockIdentity', 'Get-RuntimeClosedOperations', 'Get-RuntimeTerminalDispositions', 'Test-RuntimeDigestFormat', 'Test-RuntimeClosedOperation', 'Test-RuntimeTerminalDisposition', 'Resolve-RuntimeDeadline', 'Test-RuntimeBindingShape', 'Test-RuntimeProviderResultClosed', 'Invoke-RuntimeProviderOperation', 'Invoke-RuntimeValidateRequirement', 'Invoke-RuntimePlan', 'Resolve-RuntimeOwnedPath', 'Get-RuntimeChildEnv', 'New-RuntimeEphemeralCredential', 'Test-RuntimePrincipalShape', 'Test-RuntimeProviderReceipt', 'Get-RuntimeRedactedText', 'Get-RuntimeSafeDiagnosticText', 'Get-RuntimeNamespaceReservationId', 'Register-RuntimeNamespaceReservation', 'Close-RuntimeSuppliedReservationClaim', 'Complete-RuntimeNamespaceReservation', 'Get-RuntimeNamespaceReservationReceipt', 'New-RuntimeDefaultNamespaceReservation', 'Invoke-RuntimeAllocate', 'Invoke-RuntimeStart', 'Invoke-RuntimeObserveReadiness', 'Invoke-RuntimeResetForTest', 'Invoke-RuntimeCollectEvidence', 'Invoke-RuntimeStop', 'Invoke-RuntimeVerifyCleanup', 'Resolve-RuntimeGovernorConfig', 'Test-RuntimeStoreHandleReference', 'Test-RuntimeArtifactFile', 'Test-RuntimeOwnerHandshake', 'Test-RuntimeContainmentProof', 'Get-RuntimeProcessBinding', 'Test-RuntimePrincipalBinding', 'Test-RuntimeOwnedRootAcl', 'New-RuntimeGovernorConfigFile', 'Test-RuntimePortObservation')
