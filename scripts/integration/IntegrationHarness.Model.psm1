# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Model — closed versioned data shapes for issue #907.
#
# This module holds DATA SHAPES ONLY: interface version, state order, terminal
# sets, bounds, bindings, digests, grouping keys, arithmetic and evidence
# validators. It performs no process/port/pipe/worktree/data allocation and
# starts no external action. Behavior lives in IntegrationHarness.Core.psm1.
#
# Proof ceiling: INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY. Fake-provider
# proof is sufficient for core behavior; real Store/Runtime/Git readiness and
# full tier execution belong to their owners and #915, not this issue.

Set-StrictMode -Version Latest

$Script:HarnessModelVersion = 'eliot.integration.harness-model.v1'
$Script:ProviderInterfaceVersion = 'eliot.integration.harness-provider.v1'
$Script:ProofCeiling = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'

$Script:ProviderOperations = @(
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

$Script:RunStateOrder = @(
    'InventoryConfigAccepted',
    'OwnedRunRoot',
    'AcceptedProviderPlans',
    'Allocation',
    'StartRequested',
    'ObservedProcessReadinessUnknown',
    'AcceptedSemanticReadiness',
    'GroupInitialization',
    'ExactTestExecution',
    'TerminalTestEvidence',
    'EvidenceCollection',
    'CleanupRequested',
    'OwnedResourcesStopped',
    'CleanupVerified',
    'ReconciliationRequired',
    'Complete',
    'Failed',
    'Incomplete',
    'Cancelled'
)

$Script:TerminalTestStates = @(
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

$Script:RunOutcomes = @(
    'Complete',
    'Failed',
    'Incomplete',
    'Cancelled'
)

$Script:ClockFieldNames = @(
    'durationMs',
    'durationObservationMs',
    'observedAt',
    'observedAtUtc',
    'wallClockMs',
    'monotonicMs',
    'elapsedMs',
    'timestampUtc',
    'clockSkewMs',
    'waitedMs'
)

$Script:ForbiddenProviderResultKeys = @(
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

function Get-IntegrationHarnessModelVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $Script:HarnessModelVersion
}

function Get-IntegrationHarnessProviderInterfaceVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $Script:ProviderInterfaceVersion
}

function Get-IntegrationHarnessProviderOperations {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:ProviderOperations)
}

function Get-IntegrationHarnessStateOrder {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:RunStateOrder)
}

function Get-IntegrationHarnessTerminalTestStates {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:TerminalTestStates)
}

function Get-IntegrationHarnessRunOutcomes {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:RunOutcomes)
}

function Get-IntegrationHarnessProofCeiling {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $Script:ProofCeiling
}

function Get-IntegrationHarnessDefaultBounds {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        overallSeconds     = 3600
        startSeconds       = 300
        readinessSeconds   = 300
        groupSeconds       = 1800
        testWallSeconds    = 600
        testIdleSeconds    = 120
        evidenceSeconds    = 300
        gracefulStopMs     = 2000
        forcedStopMs       = 10000
        maxOutputBytes     = 65536
        maxLines           = 2000
        maxArtifactBytes   = 1048576
        maxResources       = 64
        maxDescendants     = 128
    }
}

function Test-IntegrationHarnessDigestFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Digest
    )
    if ([string]::IsNullOrWhiteSpace($Digest)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-DIGEST: digest is empty.')
    }
    if ($Digest -cnotmatch '^[0-9a-f]{64}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-DIGEST: digest must be 64 lowercase hex.')
    }
    return $true
}

function Test-IntegrationHarnessProviderOperation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Operation
    )
    if ([string]::IsNullOrWhiteSpace($Operation)) {
        throw [System.ArgumentException]::new('HARNESS-UNKNOWN-OPERATION: operation name is empty.')
    }
    foreach ($allowed in $Script:ProviderOperations) {
        if ($Operation -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "HARNESS-UNKNOWN-OPERATION: '$Operation' is not a member of the closed provider interface.")
}

function Test-IntegrationHarnessTerminalTestState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$State
    )
    if ([string]::IsNullOrWhiteSpace($State)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-TERMINAL-STATE: state is empty.')
    }
    foreach ($allowed in $Script:TerminalTestStates) {
        if ($State -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "HARNESS-INVALID-TERMINAL-STATE: '$State' is not an accepted terminal disposition.")
}

function Get-IntegrationHarnessStateRank {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [string]$State
    )
    switch ($State) {
        'InventoryConfigAccepted' { return 0 }
        'OwnedRunRoot' { return 1 }
        'AcceptedProviderPlans' { return 2 }
        'Allocation' { return 3 }
        'StartRequested' { return 4 }
        'ObservedProcessReadinessUnknown' { return 5 }
        'AcceptedSemanticReadiness' { return 6 }
        'GroupInitialization' { return 7 }
        'ExactTestExecution' { return 8 }
        'TerminalTestEvidence' { return 9 }
        'EvidenceCollection' { return 10 }
        'CleanupRequested' { return 11 }
        'OwnedResourcesStopped' { return 12 }
        'CleanupVerified' { return 13 }
        'ReconciliationRequired' { return 13 }
        'Complete' { return 14 }
        'Failed' { return 14 }
        'Incomplete' { return 14 }
        'Cancelled' { return 14 }
        default {
            throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STATE: '$State'.")
        }
    }
    return -1
}

function Test-IntegrationHarnessStateTransition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$FromState,
        [Parameter(Mandatory)]
        [string]$ToState
    )
    $fromRank = Get-IntegrationHarnessStateRank -State $FromState
    $toRank = Get-IntegrationHarnessStateRank -State $ToState
    if ($FromState -ceq $ToState) {
        if ($FromState -ceq 'CleanupRequested' -or
            $FromState -ceq 'OwnedResourcesStopped' -or
            $FromState -ceq 'CleanupVerified' -or
            $FromState -ceq 'ReconciliationRequired') {
            return $true
        }
        throw [System.InvalidOperationException]::new(
            "HARNESS-ILLEGAL-TRANSITION: self-transition only allowed for idempotent cleanup states; '$FromState'.")
    }
    if ($toRank -eq ($fromRank + 1)) {
        if ($fromRank -eq 12) {
            if ($ToState -ceq 'CleanupVerified' -or $ToState -ceq 'ReconciliationRequired') {
                return $true
            }
            throw [System.InvalidOperationException]::new(
                "HARNESS-ILLEGAL-TRANSITION: '$FromState' may only advance to CleanupVerified or ReconciliationRequired.")
        }
        if ($fromRank -eq 13) {
            foreach ($outcome in $Script:RunOutcomes) {
                if ($ToState -ceq $outcome) {
                    return $true
                }
            }
            throw [System.InvalidOperationException]::new(
                "HARNESS-ILLEGAL-TRANSITION: cleanup outcome '$FromState' may only advance to a run outcome.")
        }
        return $true
    }
    throw [System.InvalidOperationException]::new(
        "HARNESS-ILLEGAL-TRANSITION: '$FromState' -> '$ToState' skips or reverses the closed state order.")
}

function ConvertTo-IntegrationHarnessEscapedString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )
    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int]$ch
        switch ($code) {
            34 { [void]$builder.Append('\"'); continue }
            92 { [void]$builder.Append('\\'); continue }
            8 { [void]$builder.Append('\b'); continue }
            9 { [void]$builder.Append('\t'); continue }
            10 { [void]$builder.Append('\n'); continue }
            12 { [void]$builder.Append('\f'); continue }
            13 { [void]$builder.Append('\r'); continue }
            default {
                if ($code -lt 32) {
                    [void]$builder.Append(('\u{0:x4}' -f $code))
                } else {
                    [void]$builder.Append($ch)
                }
            }
        }
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Get-IntegrationHarnessCanonicalJson {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        $Value
    )
    if ($null -eq $Value) {
        return 'null'
    }
    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or
        $Value -is [decimal] -or $Value -is [byte] -or $Value -is [int16] -or
        $Value -is [int64] -or $Value -is [single]) {
        return [string]$Value
    }
    if ($Value -is [string]) {
        return (ConvertTo-IntegrationHarnessEscapedString -Value $Value)
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = @($Value.Keys | ForEach-Object { [string]$_ } | Sort-Object -Culture '' -CaseSensitive)
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($key in $keys) {
            $encodedKey = ConvertTo-IntegrationHarnessEscapedString -Value $key
            $encodedValue = Get-IntegrationHarnessCanonicalJson -Value $Value[$key]
            $parts.Add(('{0}:{1}' -f $encodedKey, $encodedValue))
        }
        return ('{' + ($parts -join ',') + '}')
    }
    if ($Value -is [psobject] -and $Value -isnot [string]) {
        $table = @{}
        foreach ($prop in $Value.PSObject.Properties) {
            $table[[string]$prop.Name] = $prop.Value
        }
        return (Get-IntegrationHarnessCanonicalJson -Value $table)
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $Value) {
            $parts.Add((Get-IntegrationHarnessCanonicalJson -Value $item))
        }
        return ('[' + ($parts -join ',') + ']')
    }
    throw [System.ArgumentException]::new(
        "HARNESS-UNCANONICAL-VALUE: unsupported value type '$($Value.GetType().FullName)'.")
}

function Get-IntegrationHarnessSha256Hex {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $hasher.ComputeHash($bytes)
    } finally {
        $hasher.Dispose()
    }
    return (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-IntegrationHarnessSemanticIdentity {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Evidence
    )
    $filtered = @{}
    foreach ($key in $Evidence.Keys) {
        $name = [string]$key
        if ($Script:ClockFieldNames -ccontains $name) {
            continue
        }
        if ($name -cmatch '^(?i)(duration|clock|elapsed|observed|waited).*') {
            continue
        }
        $filtered[$name] = $Evidence[$key]
    }
    $canonical = Get-IntegrationHarnessCanonicalJson -Value $filtered
    return (Get-IntegrationHarnessSha256Hex -Text $canonical)
}

function Get-IntegrationHarnessFailureFingerprint {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$LoadBearingEvidence
    )
    $ordered = [ordered]@{}
    $ordered['inventoryDigest'] = $LoadBearingEvidence['inventoryDigest']
    $selected = @($LoadBearingEvidence['selectedRowDigests'])
    $ordered['selectedRowDigests'] = @($selected | Sort-Object -Culture '' -CaseSensitive)
    $ordered['providerRevision'] = $LoadBearingEvidence['providerRevision']
    $ordered['harnessVersion'] = $LoadBearingEvidence['harnessVersion']
    $terminals = @()
    foreach ($entry in @($LoadBearingEvidence['terminalDispositions'])) {
        $terminals += ('{0}={1}' -f $entry['testIdentity'], $entry['disposition'])
    }
    $ordered['terminalDispositions'] = @($terminals | Sort-Object -Culture '' -CaseSensitive)
    $ordered['cleanupStates'] = @($LoadBearingEvidence['cleanupStates'] | Sort-Object -Culture '' -CaseSensitive)
    $ordered['selectedCount'] = $LoadBearingEvidence['selectedCount']
    $ordered['executedCount'] = $LoadBearingEvidence['executedCount']
    $ordered['evidenceCount'] = $LoadBearingEvidence['evidenceCount']
    $canonical = Get-IntegrationHarnessCanonicalJson -Value $ordered
    return (Get-IntegrationHarnessSha256Hex -Text $canonical)
}

function Get-IntegrationHarnessGroupKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Row
    )
    foreach ($field in @('providerClass', 'isolationClass', 'targetClass', 'resetClass', 'serializationClass')) {
        if (-not $Row.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Row[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-GROUP-ROW: missing '$field'.")
        }
        if ([string]$Row[$field] -cmatch '[|]') {
            throw [System.ArgumentException]::new("HARNESS-INVALID-GROUP-ROW: field '$field' contains a separator.")
        }
    }
    return ('{0}|{1}|{2}|{3}|{4}' -f
        $Row['providerClass'], $Row['isolationClass'], $Row['targetClass'],
        $Row['resetClass'], $Row['serializationClass'])
}

function New-IntegrationHarnessRunBinding {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$TestClass,
        [Parameter(Mandatory)]
        [string]$ProviderName,
        [Parameter(Mandatory)]
        [string]$ProviderRevision,
        [Parameter(Mandatory)]
        [string]$Owner,
        [Parameter(Mandatory)]
        [int]$Generation,
        [Parameter(Mandatory)]
        [System.DateTimeOffset]$DeadlineUtc,
        [Parameter(Mandatory)]
        [string]$InventoryDigest
    )
    [void](Test-IntegrationHarnessRunBinding -RunId $RunId -TestClass $TestClass `
        -ProviderName $ProviderName -ProviderRevision $ProviderRevision -Owner $Owner `
        -Generation $Generation -DeadlineUtc $DeadlineUtc -InventoryDigest $InventoryDigest)
    return @{
        runId             = $RunId
        testClass         = $TestClass
        providerName      = $ProviderName
        providerRevision  = $ProviderRevision
        owner             = $Owner
        generation        = $Generation
        deadlineUtc       = $DeadlineUtc.ToString('o')
        inventoryDigest   = $InventoryDigest
        interfaceVersion  = $Script:ProviderInterfaceVersion
    }
}

function Test-IntegrationHarnessRunBinding {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunId,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$TestClass,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ProviderName,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ProviderRevision,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Owner,
        [Parameter(Mandatory)]
        [int]$Generation,
        [Parameter(Mandatory)]
        [System.DateTimeOffset]$DeadlineUtc,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InventoryDigest
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    if ([string]::IsNullOrWhiteSpace($TestClass) -or $TestClass.Length -gt 256) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: TestClass is empty or too long.')
    }
    if ($TestClass -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: TestClass has an illegal shape.')
    }
    if ([string]::IsNullOrWhiteSpace($ProviderName) -or $ProviderName.Length -gt 128) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: ProviderName is empty or too long.')
    }
    if ([string]::IsNullOrWhiteSpace($ProviderRevision) -or $ProviderRevision.Length -gt 128) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: ProviderRevision is empty or too long.')
    }
    if ($ProviderRevision -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: ProviderRevision has an illegal shape.')
    }
    if ([string]::IsNullOrWhiteSpace($Owner) -or $Owner.Length -gt 128) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: Owner receipt is empty or too long.')
    }
    if ($Generation -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: Generation must be a positive integer.')
    }
    [void](Test-IntegrationHarnessDigestFormat -Digest $InventoryDigest)
    $now = [System.DateTimeOffset]::UtcNow
    if ($DeadlineUtc -le $now.AddSeconds(-1)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: DeadlineUtc is already expired.')
    }
    return $true
}

function New-IntegrationHarnessBounds {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateRange(1, 86400)]
        [int]$OverallSeconds = 3600,
        [ValidateRange(1, 7200)]
        [int]$StartSeconds = 300,
        [ValidateRange(1, 7200)]
        [int]$ReadinessSeconds = 300,
        [ValidateRange(1, 7200)]
        [int]$GroupSeconds = 1800,
        [ValidateRange(1, 7200)]
        [int]$TestWallSeconds = 600,
        [ValidateRange(1, 3600)]
        [int]$TestIdleSeconds = 120,
        [ValidateRange(1, 3600)]
        [int]$EvidenceSeconds = 300,
        [ValidateRange(100, 60000)]
        [int]$GracefulStopMs = 2000,
        [ValidateRange(1000, 120000)]
        [int]$ForcedStopMs = 10000,
        [ValidateRange(1024, 16777216)]
        [int]$MaxOutputBytes = 65536,
        [ValidateRange(10, 100000)]
        [int]$MaxLines = 2000,
        [ValidateRange(1024, 67108864)]
        [int]$MaxArtifactBytes = 1048576,
        [ValidateRange(1, 1024)]
        [int]$MaxResources = 64,
        [ValidateRange(1, 4096)]
        [int]$MaxDescendants = 128
    )
    $bounds = @{
        overallSeconds   = $OverallSeconds
        startSeconds     = $StartSeconds
        readinessSeconds = $ReadinessSeconds
        groupSeconds     = $GroupSeconds
        testWallSeconds  = $TestWallSeconds
        testIdleSeconds  = $TestIdleSeconds
        evidenceSeconds  = $EvidenceSeconds
        gracefulStopMs   = $GracefulStopMs
        forcedStopMs     = $ForcedStopMs
        maxOutputBytes   = $MaxOutputBytes
        maxLines          = $MaxLines
        maxArtifactBytes = $MaxArtifactBytes
        maxResources     = $MaxResources
        maxDescendants   = $MaxDescendants
    }
    [void](Test-IntegrationHarnessBounds -Bounds $bounds)
    return $bounds
}

function Test-IntegrationHarnessBounds {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Bounds
    )
    foreach ($field in @(
        'overallSeconds', 'startSeconds', 'readinessSeconds', 'groupSeconds',
        'testWallSeconds', 'testIdleSeconds', 'evidenceSeconds', 'gracefulStopMs',
        'forcedStopMs', 'maxOutputBytes', 'maxLines', 'maxArtifactBytes',
        'maxResources', 'maxDescendants')) {
        if (-not $Bounds.ContainsKey($field)) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-BOUNDS: missing '$field'.")
        }
        $value = $Bounds[$field]
        if ($value -isnot [int] -or $value -le 0) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-BOUNDS: '$field' must be a positive integer.")
        }
    }
    if ($Bounds['testIdleSeconds'] -gt $Bounds['testWallSeconds']) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BOUNDS: idle bound must not exceed wall bound.')
    }
    if ($Bounds['gracefulStopMs'] -ge $Bounds['forcedStopMs']) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BOUNDS: graceful stop must be shorter than forced stop.')
    }
    if ($Bounds['startSeconds'] + $Bounds['readinessSeconds'] + $Bounds['evidenceSeconds'] -gt $Bounds['overallSeconds']) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BOUNDS: phase bounds exceed the overall bound.')
    }
    return $true
}

function Test-IntegrationHarnessInventoryRow {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Row
    )
    foreach ($field in @('packageId', 'targetKind', 'targetName', 'testName', 'rowDigest')) {
        if (-not $Row.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Row[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: missing '$field'.")
        }
    }
    $identity = ('{0}::{1}::{2}::{3}' -f $Row['packageId'], $Row['targetKind'], $Row['targetName'], $Row['testName'])
    if ($identity -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,511}$') {
        throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: identity '$identity' has an illegal shape.")
    }
    [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$Row['rowDigest']))
    foreach ($field in @('providerClass', 'isolationClass', 'targetClass', 'resetClass', 'serializationClass')) {
        if (-not $Row.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Row[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: missing class field '$field'.")
        }
    }
    return $true
}

function Test-IntegrationHarnessSelectedSet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$SelectedRows
    )
    if ($SelectedRows.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: an empty selection is never success.')
    }
    if ($SelectedRows.Count -gt 100000) {
        throw [System.ArgumentException]::new('HARNESS-SELECTION-BOUND: selection exceeds the finite denominator bound.')
    }
    $seenIdentities = @{}
    $seenDigests = @{}
    foreach ($row in $SelectedRows) {
        if ($row -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-SELECTION: selected row must be a hashtable.')
        }
        [void](Test-IntegrationHarnessInventoryRow -Row $row)
        $identity = ('{0}::{1}::{2}::{3}' -f $row['packageId'], $row['targetKind'], $row['targetName'], $row['testName'])
        if ($identity -eq '*' -or $identity -eq 'all' -or $identity.Contains('*')) {
            throw [System.ArgumentException]::new('HARNESS-WILDCARD-SELECTION: implicit wildcard selection is forbidden.')
        }
        if ($seenIdentities.ContainsKey($identity)) {
            throw [System.ArgumentException]::new("HARNESS-DUPLICATE-SELECTION: duplicate test identity '$identity'.")
        }
        $seenIdentities[$identity] = $true
        $digest = [string]$row['rowDigest']
        if ($seenDigests.ContainsKey($digest)) {
            throw [System.ArgumentException]::new('HARNESS-DUPLICATE-SELECTION: duplicate selected-row digest.')
        }
        $seenDigests[$digest] = $true
    }
    return $true
}

function Test-IntegrationHarnessArithmetic {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [int]$SelectedCount,
        [Parameter(Mandatory)]
        [int]$ExecutedCount,
        [Parameter(Mandatory)]
        [int]$EvidenceCount,
        [Parameter(Mandatory)]
        [int]$ResourceCount,
        [Parameter(Mandatory)]
        [int]$CleanedCount
    )
    if ($SelectedCount -le 0) {
        throw [System.ArgumentException]::new('HARNESS-ARITHMETIC: selected count must be positive; zero execution is not success.')
    }
    if ($ExecutedCount -lt 0 -or $EvidenceCount -lt 0 -or $ResourceCount -lt 0 -or $CleanedCount -lt 0) {
        throw [System.ArgumentException]::new('HARNESS-ARITHMETIC: counts must not be negative.')
    }
    if ($EvidenceCount -ne $SelectedCount) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-ARITHMETIC: evidence count $EvidenceCount does not equal selected count $SelectedCount.")
    }
    if ($ExecutedCount -gt $SelectedCount) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-ARITHMETIC: executed count $ExecutedCount exceeds selected count $SelectedCount.")
    }
    $notExecuted = $SelectedCount - $ExecutedCount
    if ($notExecuted -lt 0) {
        throw [System.InvalidOperationException]::new('HARNESS-ARITHMETIC: negative non-executed remainder.')
    }
    if ($CleanedCount -gt $ResourceCount) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-ARITHMETIC: cleaned count $CleanedCount exceeds resource count $ResourceCount.")
    }
    return $true
}

function Test-IntegrationHarnessProviderResult {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in $Script:ForbiddenProviderResultKeys) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-PROVIDER-FORBIDDEN: provider result must not contain '$key'.")
            }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) {
        throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: provider must not change the run identity.')
    }
    if ($Result.ContainsKey('providerName') -and ([string]$Result['providerName'] -cne [string]$Binding['providerName'])) {
        throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: provider must not choose another provider.')
    }
    if ($Result.ContainsKey('providerRevision') -and ([string]$Result['providerRevision'] -cne [string]$Binding['providerRevision'])) {
        throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: provider must not change its revision.')
    }
    return $true
}

function Test-IntegrationHarnessTerminalEvidenceSet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$TerminalRecords,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$SelectedIdentities
    )
    if ($SelectedIdentities.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: terminal evidence requires a non-empty selection.')
    }
    if ($TerminalRecords.Count -ne $SelectedIdentities.Count) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-EVIDENCE-COUNT: terminal record count $($TerminalRecords.Count) does not equal selected count $($SelectedIdentities.Count).")
    }
    $selected = @($SelectedIdentities | Sort-Object -Culture '' -CaseSensitive)
    $seen = @{}
    $recorded = [System.Collections.Generic.List[string]]::new()
    foreach ($record in $TerminalRecords) {
        if ($record -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-TERMINAL: record must be a hashtable.')
        }
        foreach ($field in @('testIdentity', 'disposition')) {
            if (-not $record.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$record[$field])) {
                throw [System.ArgumentException]::new("HARNESS-INVALID-TERMINAL: missing '$field'.")
            }
        }
        $identity = [string]$record['testIdentity']
        [void](Test-IntegrationHarnessTerminalTestState -State ([string]$record['disposition']))
        if ($seen.ContainsKey($identity)) {
            throw [System.InvalidOperationException]::new("HARNESS-DUPLICATE-EVIDENCE: duplicate terminal identity '$identity'.")
        }
        $seen[$identity] = $true
        [void]$recorded.Add($identity)
        if ([string]$record['disposition'] -ceq 'Passed') {
            if (-not $record.ContainsKey('executedReceipt') -or $null -eq $record['executedReceipt']) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-PASS-WITHOUT-RECEIPT: '$identity' is Passed without an exact executed-test receipt.")
            }
            $receipt = $record['executedReceipt']
            if ($receipt -isnot [hashtable]) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-PASS-WITHOUT-RECEIPT: '$identity' executed receipt must be a hashtable.")
            }
            foreach ($field in @('testIdentity', 'binaryDigest', 'discoveryDigest')) {
                if (-not $receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$receipt[$field])) {
                    throw [System.InvalidOperationException]::new(
                        "HARNESS-PASS-WITHOUT-RECEIPT: '$identity' executed receipt is missing '$field'.")
                }
            }
            if ([string]$receipt['testIdentity'] -cne $identity) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-CONTRADICTORY-EVIDENCE: '$identity' executed receipt identity mismatch.")
            }
            [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$receipt['binaryDigest']))
            [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$receipt['discoveryDigest']))
        }
        if ($record.ContainsKey('attempts') -and $null -ne $record['attempts']) {
            $attempts = @($record['attempts'])
            if ($attempts.Count -eq 0) {
                throw [System.InvalidOperationException]::new("HARNESS-RETRY-EVIDENCE: '$identity' has an empty attempts list.")
            }
            if ($attempts.Count -gt 1 -and -not $record.ContainsKey('recurrenceRequested')) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-RETRY-EVIDENCE: '$identity' has multiple attempts without explicit recurrence request.")
            }
        }
    }
    $sortedRecorded = @($recorded | Sort-Object -Culture '' -CaseSensitive)
    if (($sortedRecorded -join "`n") -cne ($selected -join "`n")) {
        throw [System.InvalidOperationException]::new(
            'HARNESS-EVIDENCE-COUNT: terminal identities do not exactly equal the selected identities.')
    }
    return $true
}

function Test-IntegrationHarnessRunEvidence {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Evidence
    )
    foreach ($field in @(
        'sourceIdentity', 'worktreeIdentity', 'inventoryDigest', 'selectedRowDigests',
        'harnessVersion', 'providerIdentity', 'toolIdentities', 'runBinding',
        'resourceRecords', 'planRecords', 'readinessRecords', 'perTestDiscovery',
        'perTestExecution', 'perTestTerminal', 'artifactHandles', 'failureFingerprint',
        'cleanupRecords', 'arithmetic', 'proofCeiling')) {
        if (-not $Evidence.ContainsKey($field) -or $null -eq $Evidence[$field]) {
            throw [System.InvalidOperationException]::new("HARNESS-MISSING-EVIDENCE: missing '$field'.")
        }
    }
    if ([string]$Evidence['proofCeiling'] -cne $Script:ProofCeiling) {
        throw [System.InvalidOperationException]::new('HARNESS-PROOF-CEILING: unexpected proof ceiling.')
    }
    [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$Evidence['inventoryDigest']))
    [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$Evidence['failureFingerprint']))
    $digests = @($Evidence['selectedRowDigests'])
    if ($digests.Count -eq 0) {
        throw [System.InvalidOperationException]::new('HARNESS-MISSING-EVIDENCE: zero selected-row digests.')
    }
    $unique = @($digests | Sort-Object -Culture '' -CaseSensitive -Unique)
    if ($unique.Count -ne $digests.Count) {
        throw [System.InvalidOperationException]::new('HARNESS-DUPLICATE-EVIDENCE: duplicate selected-row digest.')
    }
    foreach ($digest in $digests) {
        [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$digest))
    }
    $arithmetic = $Evidence['arithmetic']
    if ($arithmetic -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('HARNESS-MISSING-EVIDENCE: arithmetic must be a hashtable.')
    }
    [void](Test-IntegrationHarnessArithmetic `
        -SelectedCount ([int]$arithmetic['selectedCount']) `
        -ExecutedCount ([int]$arithmetic['executedCount']) `
        -EvidenceCount ([int]$arithmetic['evidenceCount']) `
        -ResourceCount ([int]$arithmetic['resourceCount']) `
        -CleanedCount ([int]$arithmetic['cleanedCount']))
    $terminals = @($Evidence['perTestTerminal'])
    if ($terminals.Count -ne $digests.Count) {
        throw [System.InvalidOperationException]::new('HARNESS-CONTRADICTORY-EVIDENCE: terminal count contradicts selection count.')
    }
    $cleanups = @($Evidence['cleanupRecords'])
    if ($cleanups.Count -eq 0) {
        throw [System.InvalidOperationException]::new('HARNESS-MISSING-EVIDENCE: every cleanup state must be recorded.')
    }
    $artifacts = @($Evidence['artifactHandles'])
    foreach ($handle in $artifacts) {
        if ($handle -isnot [hashtable]) {
            throw [System.InvalidOperationException]::new('HARNESS-INVALID-ARTIFACT: handle must be a hashtable.')
        }
        foreach ($field in @('name', 'bytes', 'truncated')) {
            if (-not $handle.ContainsKey($field)) {
                throw [System.InvalidOperationException]::new("HARNESS-INVALID-ARTIFACT: missing '$field'.")
            }
        }
        if (([int]$handle['bytes']) -lt 0) {
            throw [System.InvalidOperationException]::new('HARNESS-INVALID-ARTIFACT: negative byte count.')
        }
    }
    return $true
}

Export-ModuleMember -Function @(
    'Get-IntegrationHarnessModelVersion',
    'Get-IntegrationHarnessProviderInterfaceVersion',
    'Get-IntegrationHarnessProviderOperations',
    'Get-IntegrationHarnessStateOrder',
    'Get-IntegrationHarnessTerminalTestStates',
    'Get-IntegrationHarnessRunOutcomes',
    'Get-IntegrationHarnessProofCeiling',
    'Get-IntegrationHarnessDefaultBounds',
    'Get-IntegrationHarnessCanonicalJson',
    'Get-IntegrationHarnessSha256Hex',
    'Get-IntegrationHarnessSemanticIdentity',
    'Get-IntegrationHarnessFailureFingerprint',
    'Get-IntegrationHarnessGroupKey',
    'Get-IntegrationHarnessStateRank',
    'ConvertTo-IntegrationHarnessEscapedString',
    'New-IntegrationHarnessRunBinding',
    'Test-IntegrationHarnessRunBinding',
    'New-IntegrationHarnessBounds',
    'Test-IntegrationHarnessBounds',
    'Test-IntegrationHarnessDigestFormat',
    'Test-IntegrationHarnessProviderOperation',
    'Test-IntegrationHarnessTerminalTestState',
    'Test-IntegrationHarnessStateTransition',
    'Test-IntegrationHarnessInventoryRow',
    'Test-IntegrationHarnessSelectedSet',
    'Test-IntegrationHarnessArithmetic',
    'Test-IntegrationHarnessProviderResult',
    'Test-IntegrationHarnessTerminalEvidenceSet',
    'Test-IntegrationHarnessRunEvidence'
)
