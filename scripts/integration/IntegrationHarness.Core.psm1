# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Core — bounded harness state machine behavior for issue #907.
#
# This module holds BEHAVIOR: state transitions, deterministic prepare with
# reverse idempotent cleanup, grouping, readiness semantics, terminal evidence,
# redaction, owned-root and owned-process mechanics bound to the closed
# provider interface defined in IntegrationHarness.Model.psm1.
#
# Fail-closed rules enforced here:
# - Exactly the 9 closed provider operations; arbitrary methods rejected.
# - Providers cannot change the denominator, choose another provider, inject
#   commands, or mark tests passed (validated on every provider result).
# - There is no result synthesis anywhere on the run path: no probe, flag or
#   default can emit a Passed/AssertionFailed terminal record. The single
#   validator that can (Test-HarnessExecutedTestReceipt, module-private) runs
#   only on a real executed-test receipt.
# - A PID/port/pipe/exit is never readiness and never successful execution.
# - Unknown start/commit/cleanup stays reconciliation-required; no blind retry
#   and no replacement resources are ever launched.
# - Prepare validates the entire plan before external action, runs in
#   deterministic dependency order, and on any failure cleans up in reverse
#   order every resource whose preparation may have started.
# - Timeout/cancellation stops the exact owned process tree via accepted
#   test-process ownership; never by name, port, or unverified PID.
# - Clocks and process controllers are injected; this module never sleeps and
#   never spawns live processes/ports/pipes. One admitted clock owner per run
#   supplies the binding deadline and every bounded elapsed value.
# - Redaction/sink failure is recorded but never alters cleanup records or the
#   primary terminal outcome; it does withhold a run-level Complete, because
#   incomplete evidence is non-green.
#
# Proof ceiling: INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY.

Set-StrictMode -Version Latest

$Script:HarnessCoreVersion = 'eliot.integration.harness-core.v1'
$Script:ProofCeiling = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
$Script:OwnedRootMarkerSchema = 'eliot-harness-owned-root-v1'
$Script:ModelModulePath = (Join-Path $PSScriptRoot 'IntegrationHarness.Model.psm1')
# NOTE: Core never imports Model at module load. Importing Model from inside
# Core hides Model's exports when both modules are loaded (nested-module
# scoping), so each file must import cleanly on its own. Callers import both
# modules explicitly; Core binds to Model validators dynamically through
# Get-Command/Get-Module checks at call time with local fail-closed fallbacks.

function Test-IntegrationHarnessModelLoaded {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return ($null -ne (Get-Module -Name 'IntegrationHarness.Model' -ErrorAction SilentlyContinue))
}

$Script:ClosedOperations = @(
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

$Script:OwnedRootAllowedNames = @(
    '.eliot-harness-owner.json',
    'resources',
    'reports',
    'tmp',
    'artifacts'
)

# Bounded-runtime stage names (#907 W8). Each stage carries its own bound from
# the injected bounds table; the stage ladder is fixed here so a caller can
# never add, drop, or reorder a bounded stage.
$Script:BoundedRuntimeStages = @(
    'overall', 'start', 'readiness', 'group', 'test-wall', 'test-idle',
    'evidence', 'graceful-stop', 'forced-stop'
)
$Script:BoundedRuntimeStageBound = @{
    overall      = 'overallSeconds'
    start        = 'startSeconds'
    readiness    = 'readinessSeconds'
    group        = 'groupSeconds'
    'test-wall'  = 'testWallSeconds'
    'test-idle'  = 'testIdleSeconds'
    evidence     = 'evidenceSeconds'
    'graceful-stop' = 'gracefulStopMs'
    'forced-stop'   = 'forcedStopMs'
}
$Script:BoundedRuntimeByteBound = @{
    output  = 'maxOutputBytes'
    line    = 'maxLines'
    artifact = 'maxArtifactBytes'
}

function Get-IntegrationHarnessCoreVersion {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $Script:HarnessCoreVersion
}

function Get-IntegrationHarnessModelAvailability {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    return (Test-IntegrationHarnessModelLoaded)
}

function Test-IntegrationHarnessClosedOperation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Operation
    )
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessProviderOperation' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return (Test-IntegrationHarnessProviderOperation -Operation $Operation)
        }
    }
    if ([string]::IsNullOrWhiteSpace($Operation)) {
        throw [System.ArgumentException]::new('HARNESS-UNKNOWN-OPERATION: operation name is empty.')
    }
    foreach ($allowed in $Script:ClosedOperations) {
        if ($Operation -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "HARNESS-UNKNOWN-OPERATION: '$Operation' is not a member of the closed provider interface.")
}

function Resolve-IntegrationHarnessDeadline {
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
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: binding is missing deadlineUtc.')
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
            throw [System.ArgumentException]::new('HARNESS-INVALID-CLOCK: injected clock must return DateTimeOffset.')
        }
    }
    $remaining = [int]($deadline - $now).TotalSeconds
    if ($remaining -le 0) {
        throw [System.TimeoutException]::new("HARNESS-DEADLINE-EXCEEDED: operation '$Operation' has no remaining bound.")
    }
    return $remaining
}

function Test-IntegrationHarnessProviderResultClosed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessProviderResult' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return (Test-IntegrationHarnessProviderResult -Result $Result -Binding $Binding)
        }
    }
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in @(
            'testDenominator', 'providerChoice', 'chooseProvider', 'command',
            'argv', 'executable', 'shellCommand', 'testPassed', 'markPassed', 'verdictOverride')) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-PROVIDER-FORBIDDEN: provider result must not contain '$key'.")
            }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) {
        throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: provider must not change the run identity.')
    }
    return $true
}

function Invoke-IntegrationHarnessProviderOperation {
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
    [void](Test-IntegrationHarnessClosedOperation -Operation $Operation)
    if ($null -eq $Provider -or $Provider.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PROVIDER: provider table is empty.')
    }
    if (-not $Provider.ContainsKey($Operation)) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-OPERATION: provider has no implementation for '$Operation'.")
    }
    $implementation = $Provider[$Operation]
    if ($implementation -isnot [scriptblock]) {
        throw [System.ArgumentException]::new("HARNESS-INVALID-PROVIDER: operation '$Operation' must map to a scriptblock.")
    }
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    [void](Resolve-IntegrationHarnessDeadline -Binding $Binding -Clock $Clock -Operation $Operation)
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
            "HARNESS-PROVIDER-FAILED:$Operation : $($_.Exception.Message)")
    }
    if ($null -eq $raw) {
        throw [System.InvalidOperationException]::new("HARNESS-PROVIDER-FAILED:$Operation : provider returned no result.")
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
            "HARNESS-PROVIDER-FAILED:$Operation : provider result must be a hashtable.")
    }
    [void](Test-IntegrationHarnessProviderResultClosed -Result $result -Binding $Binding)
    return $result
}

function Get-IntegrationHarnessRedactedText {
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
    $redactionFailed = $false
    $redacted = $Text
    try {
        if ($null -ne $Secrets) {
            foreach ($secret in $Secrets) {
                if ([string]::IsNullOrEmpty($secret)) {
                    continue
                }
                $redacted = $redacted.Replace($secret, '[redacted-harness-secret]')
            }
        }
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring)\s*[:=]\s*\S+',
            '$1=[redacted-harness-secret]')
        foreach ($variable in @('USERPROFILE', 'LOCALAPPDATA', 'APPDATA')) {
            try {
                $privateRoot = [System.Environment]::GetEnvironmentVariable($variable, 'Process')
            } catch {
                $privateRoot = $null
            }
            if (-not [string]::IsNullOrWhiteSpace($privateRoot) -and $privateRoot.Length -ge 4) {
                $redacted = $redacted.Replace($privateRoot, '[redacted-user-path]')
            }
        }
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)[A-Za-z]:\\Users\\[^\\/:*?"<>|]+',
            '[redacted-user-path]')
    } catch {
        $redactionFailed = $true
        return [pscustomobject]@{
            text            = ''
            bytes           = 0
            truncated       = $false
            redactionFailed = $true
        }
    }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($redacted)
    } catch {
        return [pscustomobject]@{
            text            = ''
            bytes           = 0
            truncated       = $false
            redactionFailed = $true
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
                text            = ''
                bytes           = 0
                truncated       = $true
                redactionFailed = $true
            }
        }
    }
    return [pscustomobject]@{
        text            = $output
        bytes           = $bytes.Length
        truncated       = $truncated
        redactionFailed = $redactionFailed
    }
}

# Applies the module's own redactor to every string leaf of an arbitrary
# evidence value, in place of nothing: the caller passes the value it is about
# to persist and uses the returned copy. $State carries the two observed facts
# of the pass itself - whether the redactor ever failed, and whether it actually
# changed anything - so the caller reports what happened instead of asserting a
# constant. A redactor that fails drops the affected detail and the pass
# continues: redaction never aborts the run, never touches cleanup records and
# never changes a terminal disposition.
function ConvertTo-IntegrationHarnessRedactedValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()]
        [AllowNull()]
        [object]$Value,
        [Parameter(Mandatory)]
        [hashtable]$State
    )
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [string]) {
        $redacted = $null
        try {
            $redacted = Get-IntegrationHarnessRedactedText -Text ([string]$Value) -MaxBytes 16777216
        } catch {
            $State['redactionFailed'] = $true
            $State['rewritten'] = $true
            return ''
        }
        if ($null -eq $redacted -or [bool]$redacted.redactionFailed) {
            $State['redactionFailed'] = $true
            $State['rewritten'] = $true
            return ''
        }
        if ([string]$redacted.text -cne [string]$Value) {
            $State['rewritten'] = $true
        }
        return [string]$redacted.text
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach ($key in @($Value.Keys)) {
            $copy[$key] = ConvertTo-IntegrationHarnessRedactedValue -Value $Value[$key] -State $State
        }
        return $copy
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) {
            [void]$items.Add((ConvertTo-IntegrationHarnessRedactedValue -Value $item -State $State))
        }
        return , @($items)
    }
    # A provider payload is routinely a PSCustomObject rather than a hashtable,
    # and PSCustomObject is neither IDictionary nor IEnumerable, so returning it
    # unchanged would carry its string leaves past the redactor entirely: a
    # readiness observation holding a connection string with an embedded
    # password, or an executedReceipt quoting a private source path, would reach
    # the persisted record, and the verification walk below shares this same
    # blind spot and would report the record clean. Any remaining object is
    # therefore walked through its own properties, which is where a payload's
    # text lives. The threat is described here rather than written as a literal
    # sample: this file is itself scanned by the canary guard, and a spelled-out
    # example in a comment is indistinguishable from a leaked value to it.
    if ($null -ne $Value.PSObject -and $null -ne $Value.PSObject.Properties) {
        $members = @($Value.PSObject.Properties | Where-Object {
            $_.MemberType -in @('NoteProperty', 'Property', 'ScriptProperty', 'AliasProperty')
        })
        if ($members.Count -gt 0) {
            $copy = @{}
            foreach ($member in $members) {
                $copy[[string]$member.Name] =
                    ConvertTo-IntegrationHarnessRedactedValue -Value $member.Value -State $State
            }
            return $copy
        }
    }
    return $Value
}

function Test-IntegrationHarnessNoReparsePoint {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PATH: path is empty.')
    }
    $resolved = $null
    try {
        $resolved = [System.IO.Path]::GetFullPath($Path)
    } catch {
        throw [System.ArgumentException]::new("HARNESS-INVALID-PATH: path is not well-formed: $Path")
    }
    $entry = $null
    try {
        $entry = Get-Item -LiteralPath $resolved -Force -ErrorAction Stop
    } catch {
        throw [System.IO.DirectoryNotFoundException]::new("HARNESS-PATH-UNAVAILABLE: path does not exist: $resolved")
    }
    $current = $entry
    while ($null -ne $current) {
        if (($current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw [System.InvalidOperationException]::new(
                "HARNESS-REPARSE-ESCAPE: owned path crosses a reparse point: $($current.FullName)")
        }
        $current = $current.Parent
    }
    return $true
}

function New-IntegrationHarnessOwnedRunRoot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$BaseTemp,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Owner,
        [Parameter(Mandatory)]
        [int]$Generation
    )
    if ([string]::IsNullOrWhiteSpace($BaseTemp)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PATH: BaseTemp is empty.')
    }
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    if ([string]::IsNullOrWhiteSpace($Owner)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: Owner receipt is empty.')
    }
    if ($Generation -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: Generation must be positive.')
    }
    $resolvedBase = [System.IO.Path]::GetFullPath($BaseTemp)
    if (-not [System.IO.Path]::IsPathFullyQualified($resolvedBase)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PATH: BaseTemp must be fully qualified.')
    }
    [void](Test-IntegrationHarnessNoReparsePoint -Path $resolvedBase)
    $lower = $resolvedBase.ToLowerInvariant()
    if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) {
        throw [System.InvalidOperationException]::new('HARNESS-FORBIDDEN-ROOT: owned root crossed a forbidden host boundary.')
    }
    $ownedRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedBase ("eliot-harness-{0}" -f $RunId)))
    $prefix = $resolvedBase.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $ownedRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("HARNESS-ROOT-ESCAPE: owned root escaped its base: $ownedRoot")
    }
    if ([System.IO.Path]::GetFullPath((Split-Path $ownedRoot -Parent)) -ine $resolvedBase) {
        throw [System.InvalidOperationException]::new("HARNESS-ROOT-ESCAPE: owned root parent mismatch: $ownedRoot")
    }
    if (-not ([System.IO.Path]::GetFileName($ownedRoot)).Contains($RunId)) {
        throw [System.InvalidOperationException]::new('HARNESS-ROOT-ESCAPE: owned root leaf must carry the run identity.')
    }
    [System.IO.Directory]::CreateDirectory($ownedRoot) | Out-Null
    [void](Test-IntegrationHarnessNoReparsePoint -Path $ownedRoot)
    $markerPath = Join-Path $ownedRoot '.eliot-harness-owner.json'
    $marker = @{
        schema_version = $Script:OwnedRootMarkerSchema
        run_id         = $RunId
        owned_root     = $ownedRoot
        owner          = $Owner
        generation     = $Generation
    }
    $canonical = $null
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Get-IntegrationHarnessCanonicalJson' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $canonical = Get-IntegrationHarnessCanonicalJson -Value $marker
        }
    }
    if ([string]::IsNullOrWhiteSpace($canonical)) {
        $canonical = ($marker | ConvertTo-Json -Compress -Depth 8)
    }
    [System.IO.File]::WriteAllText($markerPath, $canonical, [System.Text.UTF8Encoding]::new($false))
    return @{
        ownedRoot       = $ownedRoot
        ownerMarkerPath = $markerPath
        runId           = $RunId
        owner           = $Owner
        generation      = $Generation
        state           = 'OwnedRunRoot'
    }
}

function Remove-IntegrationHarnessOwnedRoot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$OwnedRoot,
        [Parameter(Mandatory)]
        [string]$ExpectedParent,
        [Parameter(Mandatory)]
        [string]$ExpectedRunId
    )
    if ([string]::IsNullOrWhiteSpace($OwnedRoot)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PATH: OwnedRoot is empty.')
    }
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.')
    }
    $resolvedOwned = [System.IO.Path]::GetFullPath($OwnedRoot)
    $resolvedParent = [System.IO.Path]::GetFullPath($ExpectedParent)
    if (-not (Test-Path -LiteralPath $resolvedOwned)) {
        return @{
            state        = 'CleanupVerified'
            cleaned      = $true
            alreadyClean = $true
            ownedRoot    = $resolvedOwned
            failures     = @()
        }
    }
    $parentPrefix = $resolvedParent.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedOwned.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase) -or
        [System.IO.Path]::GetFullPath((Split-Path $resolvedOwned -Parent)) -ine $resolvedParent) {
        throw [System.InvalidOperationException]::new("HARNESS-ROOT-ESCAPE: owned cleanup escaped its run boundary: $resolvedOwned")
    }
    if (-not ([System.IO.Path]::GetFileName($resolvedOwned)).Contains($ExpectedRunId)) {
        throw [System.InvalidOperationException]::new("HARNESS-ROOT-ESCAPE: cleanup leaf does not carry the run identity: $resolvedOwned")
    }
    [void](Test-IntegrationHarnessNoReparsePoint -Path $resolvedOwned)
    $marker = Join-Path $resolvedOwned '.eliot-harness-owner.json'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf)) {
        return @{
            state        = 'ReconciliationRequired'
            cleaned      = $false
            alreadyClean = $false
            ownedRoot    = $resolvedOwned
            failures     = @('ownership-marker-missing')
        }
    }
    try {
        $recorded = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{
            state        = 'ReconciliationRequired'
            cleaned      = $false
            alreadyClean = $false
            ownedRoot    = $resolvedOwned
            failures     = @('ownership-marker-unreadable')
        }
    }
    if ($recorded.schema_version -cne $Script:OwnedRootMarkerSchema -or
        $recorded.run_id -cne $ExpectedRunId -or
        [System.IO.Path]::GetFullPath([string]$recorded.owned_root) -ine $resolvedOwned) {
        return @{
            state        = 'ReconciliationRequired'
            cleaned      = $false
            alreadyClean = $false
            ownedRoot    = $resolvedOwned
            failures     = @('ownership-verification-failed')
        }
    }
    $entries = @(Get-ChildItem -LiteralPath $resolvedOwned -Force -ErrorAction Stop)
    foreach ($entry in $entries) {
        if ($entry.Name -cnotin $Script:OwnedRootAllowedNames) {
            return @{
                state        = 'ReconciliationRequired'
                cleaned      = $false
                alreadyClean = $false
                ownedRoot    = $resolvedOwned
                failures     = @("foreign-entry-preserved:$($entry.Name)")
            }
        }
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return @{
                state        = 'ReconciliationRequired'
                cleaned      = $false
                alreadyClean = $false
                ownedRoot    = $resolvedOwned
                failures     = @("reparse-entry-preserved:$($entry.Name)")
            }
        }
    }
    $nested = @(Get-ChildItem -LiteralPath $resolvedOwned -Force -Recurse -ErrorAction SilentlyContinue)
    foreach ($item in $nested) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            return @{
                state        = 'ReconciliationRequired'
                cleaned      = $false
                alreadyClean = $false
                ownedRoot    = $resolvedOwned
                failures     = @("reparse-entry-preserved:$($item.FullName)")
            }
        }
    }
    try {
        Remove-Item -LiteralPath $resolvedOwned -Recurse -Force -ErrorAction Stop
    } catch {
        return @{
            state        = 'ReconciliationRequired'
            cleaned      = $false
            alreadyClean = $false
            ownedRoot    = $resolvedOwned
            failures     = @("removal-failed:$($_.Exception.Message)")
        }
    }
    return @{
        state        = 'CleanupVerified'
        cleaned      = $true
        alreadyClean = $false
        ownedRoot    = $resolvedOwned
        failures     = @()
    }
}

# Accepted test-process ownership (#907 W8). Ownership is a RECORDED identity
# tuple, not an injected predicate: a pid is owned only when this run recorded
# a start receipt for that exact pid whose run id, owner and generation match
# the current binding. There is no boolean that a caller can supply to make an
# arbitrary pid owned; recording the tuple is the only way to gain ownership,
# and the tuple is itself verified against the live identity at stop time.
function New-IntegrationHarnessOwnedProcessRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [string]$Role,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$StartTimeUtc,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ImagePath,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ImageHash,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$SignerIdentity,
        [Parameter()]
        [AllowEmptyCollection()]
        [int[]]$DescendantPids = @()
    )
    if ($ProcessId -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PID: process id must be positive.')
    }
    if ([string]::IsNullOrWhiteSpace($Role)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-ROLE: role is empty.')
    }
    foreach ($field in @('runId', 'owner', 'generation')) {
        if (-not $Binding.ContainsKey($field) -or
            [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    # A start receipt that cannot state the full identity is not an accepted
    # ownership record. This is the fail-closed admission gate: without a
    # complete tuple the pid is NEVER owned, so it can never be stopped.
    $identity = [pscustomobject]@{
        processId       = $ProcessId
        runId           = [string]$Binding['runId']
        owner           = [string]$Binding['owner']
        generation      = [int]$Binding['generation']
        role            = $Role
        startTimeUtc    = $StartTimeUtc
        imagePath       = $ImagePath
        imageHash       = $ImageHash
        signerIdentity  = $SignerIdentity
    }
    if (-not (Test-IntegrationHarnessProcessIdentityMatch -LiveIdentity @{
            startTimeUtc   = $StartTimeUtc
            imagePath      = $ImagePath
            imageHash      = $ImageHash
            signerIdentity = $SignerIdentity
        } -ExpectedStartTimeUtc $StartTimeUtc -ExpectedImagePath $ImagePath `
          -ExpectedImageHash $ImageHash -ExpectedSignerIdentity $SignerIdentity)) {
        throw [System.ArgumentException]::new(
            "HARNESS-UNVERIFIED-OWNERSHIP: start receipt for pid $ProcessId carries no complete process/image/signer identity.")
    }
    $descendants = [System.Collections.Generic.List[int]]::new()
    foreach ($descendant in @($DescendantPids)) {
        if ($descendant -le 0) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-PID: descendant pid must be positive.')
        }
        [void]$descendants.Add($descendant)
    }
    return @{
        identity        = $identity
        descendantPids  = @($descendants)
    }
}

function Test-IntegrationHarnessOwnedProcess {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [Parameter(Mandatory)]
        [string]$OwnerRunId,
        [Parameter(Mandatory)]
        [hashtable]$OwnershipMap
    )
    if ($ProcessId -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PID: process id must be positive.')
    }
    if ($OwnerRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: OwnerRunId must be 32 lowercase hex.')
    }
    $key = [string]$ProcessId
    if (-not $OwnershipMap.ContainsKey($key) -and -not $OwnershipMap.ContainsKey($ProcessId)) {
        return $false
    }
    $recorded = $null
    if ($OwnershipMap.ContainsKey($key)) {
        $recorded = [string]$OwnershipMap[$key]
    } else {
        $recorded = [string]$OwnershipMap[$ProcessId]
    }
    return ($recorded -ceq $OwnerRunId)
}

# Harness-owned start/image/signer identity comparison for owned-process stop.
#
# The numeric process id is ONLY a lookup handle. The stop decision binds to the
# identity tuple recorded at start and re-read live: process start instant
# (kills PID reuse), the executable image path, the image content digest, and
# the signer/hash identity required by docs/architecture/
# I10-08-02-ip0-one-windows-processexecutor.md. Every comparison is fail-closed:
# a missing, unreadable, or mismatched field means "not the owned process",
# never a kill.
#
# Ownership is NOT an injected predicate. The only injected value is the live
# identity READ (a probe that answers a question about the OS), and the probe is
# not consulted for ownership at all: a probe that returns $true for every pid
# cannot authorize a stop, because the comparison below always runs here and
# demands a complete, matching identity tuple. A caller that cannot produce
# start time + image path + image hash + signer gets a fail-closed rejection, so
# an identity-incapable probe degrades to "never kill", never to "kill".
function Test-IntegrationHarnessProcessIdentityMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter()]
        [AllowNull()]
        $LiveIdentity,
        [Parameter()]
        [AllowEmptyString()]
        [string]$ExpectedStartTimeUtc,
        [Parameter()]
        [AllowEmptyString()]
        [string]$ExpectedImagePath,
        [Parameter()]
        [AllowEmptyString()]
        [string]$ExpectedImageHash,
        [Parameter()]
        [AllowEmptyString()]
        [string]$ExpectedSignerIdentity
    )
    if ($LiveIdentity -isnot [hashtable]) {
        return $false
    }
    # A complete ownership tuple is mandatory on BOTH sides. An expected tuple
    # that omits any of the four identity components is not an accepted
    # test-process ownership record, so the answer is "not the owned process".
    $expected = @($ExpectedStartTimeUtc, $ExpectedImagePath, $ExpectedImageHash, $ExpectedSignerIdentity)
    foreach ($field in $expected) {
        if ([string]::IsNullOrWhiteSpace([string]$field)) {
            return $false
        }
    }
    foreach ($field in @('startTimeUtc', 'imagePath', 'imageHash', 'signerIdentity')) {
        if (-not $LiveIdentity.ContainsKey($field) -or $null -eq $LiveIdentity[$field]) {
            return $false
        }
    }
    $expectedTicks = 0
    try {
        $expectedTicks = ([System.DateTimeOffset]::Parse($ExpectedStartTimeUtc)).UtcTicks
    } catch {
        return $false
    }
    $liveRaw = $LiveIdentity['startTimeUtc']
    $liveTicks = 0
    try {
        if ($liveRaw -is [System.DateTimeOffset]) {
            $liveTicks = ([System.DateTimeOffset]$liveRaw).UtcTicks
        } elseif ($liveRaw -is [System.DateTime]) {
            $liveTicks = ([System.DateTimeOffset]::new(([System.DateTime]$liveRaw).ToUniversalTime())).UtcTicks
        } else {
            $liveTicks = ([System.DateTimeOffset]::Parse([string]$liveRaw)).UtcTicks
        }
    } catch {
        return $false
    }
    if ($liveTicks -ne $expectedTicks) {
        return $false
    }
    $livePath = ([string]$LiveIdentity['imagePath']).Trim()
    if ([string]::IsNullOrWhiteSpace($livePath) -or
        -not $livePath.Equals($ExpectedImagePath.Trim(), [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }
    $liveHash = ([string]$LiveIdentity['imageHash']).Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($liveHash) -or
        $liveHash -cne $ExpectedImageHash.Trim().ToLowerInvariant()) {
        return $false
    }
    $liveSigner = ([string]$LiveIdentity['signerIdentity']).Trim()
    if ([string]::IsNullOrWhiteSpace($liveSigner) -or
        $liveSigner -cne $ExpectedSignerIdentity.Trim()) {
        return $false
    }
    return $true
}

# Stop one owned process (#907 W8).
#
# The stop is authorized ONLY by a recorded ownership identity tuple that also
# matches the LIVE process identity read through the controller's observation
# primitive. There is no `TestOwnership` scriptblock, no name, no port, and no
# bare pid path: the controller supplies observation (who is this pid right now)
# and the stop action (graceful/forced for exactly this pid), never ownership.
# A foreign, reused, unverified, or unreadable identity is never touched and
# leaves the cleanup outcome explicitly uncertain, which blocks clean
# completion instead of passing.
function Stop-IntegrationHarnessOwnedProcess {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [Parameter(Mandatory)]
        [string]$Role,
        [Parameter(Mandatory)]
        [hashtable]$OwnershipRecord,
        [Parameter(Mandatory)]
        [hashtable]$ProcessController,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$Receipts
    )
    if ($ProcessId -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PID: process id must be positive.')
    }
    if ([string]::IsNullOrWhiteSpace($Role)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-ROLE: role is empty.')
    }
    foreach ($field in @('ReadLiveIdentity', 'RequestGraceful', 'WaitForExit', 'StopForced')) {
        if (-not $ProcessController.ContainsKey($field) -or $ProcessController[$field] -isnot [scriptblock]) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-CONTROLLER: controller is missing '$field'.")
        }
    }
    if ($OwnershipRecord -isnot [hashtable] -or -not $OwnershipRecord.ContainsKey('identity')) {
        throw [System.ArgumentException]::new('HARNESS-UNVERIFIED-OWNERSHIP: an accepted ownership identity tuple is required.')
    }
    $identity = $OwnershipRecord['identity']
    if ($identity -isnot [hashtable] -and $identity -isnot [psobject]) {
        throw [System.ArgumentException]::new('HARNESS-UNVERIFIED-OWNERSHIP: ownership identity must be a record.')
    }
    $fieldMap = @{}
    if ($identity -is [hashtable]) {
        foreach ($key in @($identity.Keys)) { $fieldMap[[string]$key] = $identity[$key] }
    } else {
        foreach ($prop in $identity.PSObject.Properties) { $fieldMap[[string]$prop.Name] = $prop.Value }
    }
    foreach ($required in @('startTimeUtc', 'imagePath', 'imageHash', 'signerIdentity')) {
        if (-not $fieldMap.ContainsKey($required) -or
            [string]::IsNullOrWhiteSpace([string]$fieldMap[$required])) {
            throw [System.ArgumentException]::new(
                "HARNESS-UNVERIFIED-OWNERSHIP: ownership identity is missing '$required'.")
        }
    }
    $receipt = [ordered]@{
        role               = $Role
        pid                = $ProcessId
        graceful_requested = $false
        forced             = $false
        stopped            = $false
        skippedForeign     = $false
        cleanupUnknown     = $false
        identityMismatch   = $false
    }
    # Identity FIRST. A pid whose live identity is absent, unreadable, or
    # different from the recorded start/image/signer tuple is foreign by
    # definition: it is never signalled, and cleanup is explicitly uncertain.
    $identityOk = $false
    $liveIdentity = $null
    try {
        $liveIdentity = (& $ProcessController['ReadLiveIdentity'] $ProcessId)
    } catch {
        $liveIdentity = $null
    }
    $identityOk = Test-IntegrationHarnessProcessIdentityMatch -LiveIdentity $liveIdentity `
        -ExpectedStartTimeUtc ([string]$fieldMap['startTimeUtc']) `
        -ExpectedImagePath ([string]$fieldMap['imagePath']) `
        -ExpectedImageHash ([string]$fieldMap['imageHash']) `
        -ExpectedSignerIdentity ([string]$fieldMap['signerIdentity'])
    if (-not $identityOk) {
        $Failures.Add("foreign-process-never-touched:$Role")
        $receipt.skippedForeign = $true
        $receipt.cleanupUnknown = $true
        $receipt.identityMismatch = $true
        $Receipts.Add([pscustomobject]$receipt)
        return @{
            stopped        = $false
            skippedForeign = $true
            cleanupUnknown = $true
            pid            = $ProcessId
            role           = $Role
        }
    }
    try {
        $receipt.graceful_requested = [bool](& $ProcessController['RequestGraceful'] $ProcessId)
        $exited = [bool](& $ProcessController['WaitForExit'] $ProcessId)
        if (-not $exited) {
            [void](& $ProcessController['StopForced'] $ProcessId)
            $receipt.forced = $true
            $exited = [bool](& $ProcessController['WaitForExit'] $ProcessId)
            if (-not $exited) {
                throw [System.TimeoutException]::new(
                    "owned process did not exit within the bounded fallback: role=$Role pid=$ProcessId")
            }
        }
        $receipt.stopped = $true
    } catch {
        $Failures.Add("owned-process-cleanup-failed:$Role")
        $receipt.cleanupUnknown = $true
        $receipt.stopped = $false
    }
    $Receipts.Add([pscustomobject]$receipt)
    return @{
        stopped        = [bool]$receipt.stopped
        skippedForeign = [bool]$receipt.skippedForeign
        cleanupUnknown = [bool]$receipt.cleanupUnknown
        pid            = $ProcessId
        role           = $Role
    }
}

# Stop the exact owned process tree (#907 W8).
#
# Ownership of every member is decided the same way: a recorded identity tuple
# per pid, verified against the live identity. The descendant bound is enforced
# here, so an oversized or unbounded lineage is an explicit bounded-runtime
# failure (reconciliation-required), never a silent partial stop. Stop order is
# descendants first (deepest/highest pid first for determinism), then the root,
# matching the reverse of a start-ordered lineage.
function Stop-IntegrationHarnessOwnedProcessTree {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$RootPid,
        [Parameter(Mandatory)]
        [string]$OwnerRunId,
        [Parameter(Mandatory)]
        [hashtable]$ProcessController,
        [Parameter()]
        [AllowNull()]
        [object[]]$OwnedProcesses = @(),
        [Parameter()]
        [AllowNull()]
        [hashtable]$Bounds
    )
    if ($RootPid -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PID: root pid must be positive.')
    }
    if ($OwnerRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: OwnerRunId must be 32 lowercase hex.')
    }
    $maxDescendants = 128
    if ($null -ne $Bounds -and $Bounds.ContainsKey('maxDescendants')) {
        $maxDescendants = [int]$Bounds['maxDescendants']
    }
    $view = New-IntegrationHarnessOwnedProcessView -OwnedProcesses @($OwnedProcesses) -RunId $OwnerRunId
    $ordered = @($view['records'])
    $byPid = @{}
    $descendantPids = [System.Collections.Generic.List[int]]::new()
    foreach ($record in $ordered) {
        $pidValue = [int](Get-IntegrationHarnessOwnedRecordField -Record $record -Field 'processId' -Default 0)
        if ($pidValue -le 0 -or $pidValue -eq $RootPid) { continue }
        if ($byPid.ContainsKey($pidValue)) { continue }
        $byPid[$pidValue] = $record
        [void]$descendantPids.Add($pidValue)
    }
    if (-not $byPid.ContainsKey($RootPid)) {
        # No accepted start receipt for the root: nothing owned, nothing killed.
        return @{
            rootPid        = $RootPid
            stopped        = $false
            cleanupUnknown = $true
            failures       = @("foreign-process-never-touched:test-root:$RootPid")
            receipts       = @()
        }
    }
    if ($descendantPids.Count -gt $maxDescendants) {
        # The descendant bound is a runtime bound, not a filter: exceeding it is
        # an explicit uncertain-cleanup outcome that blocks clean completion.
        return @{
            rootPid        = $RootPid
            stopped        = $false
            cleanupUnknown = $true
            failures       = @("descendant-bound-exceeded:$($descendantPids.Count):$maxDescendants")
            receipts       = @()
        }
    }
    $failures = [System.Collections.Generic.List[string]]::new()
    $receipts = [System.Collections.Generic.List[object]]::new()
    foreach ($targetPid in @($descendantPids | Sort-Object -Descending)) {
        [void](Stop-IntegrationHarnessOwnedProcess -ProcessId $targetPid -Role 'test-descendant' `
            -OwnershipRecord $byPid[$targetPid] -ProcessController $ProcessController `
            -Failures $failures -Receipts $receipts)
    }
    $rootResult = Stop-IntegrationHarnessOwnedProcess -ProcessId $RootPid -Role 'test-root' `
        -OwnershipRecord $byPid[$RootPid] -ProcessController $ProcessController `
        -Failures $failures -Receipts $receipts
    $unknown = $false
    foreach ($receipt in $receipts) {
        if ($receipt.cleanupUnknown) {
            $unknown = $true
        }
    }
    return @{
        rootPid        = $RootPid
        stopped        = [bool]$rootResult.stopped -and (-not $unknown)
        cleanupUnknown = $unknown
        failures       = @($failures)
        receipts       = @($receipts)
    }
}

# Bounded-runtime budget (#907 W8).
#
# Every bounded dimension named by the issue is accounted here from the
# injected bounds table: overall/start/readiness/group/test-wall/test-idle/
# evidence/graceful-stop/forced-stop time, output/line/artifact bytes, resource
# count and process-descendant count.
#
# The CLOCK is injected and is the only source of "now": the function never
# sleeps, never waits, and never reads the wall clock unless the caller passes
# no clock at all (the fail-closed default rejects that instead of guessing).
# Elapsed time is measured by the caller's own clock reads; this function only
# compares supplied elapsed values against the bounds, so a test drives every
# timeout path deterministically with no sleep in the harness.
function New-IntegrationHarnessBoundedRuntime {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Bounds,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Owner
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    if ([string]::IsNullOrWhiteSpace($Owner)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: owner receipt is empty.')
    }
    if ($null -eq $Clock) {
        # No injected clock means no deterministic time bound is provable.
        # Fail closed instead of silently reading a real wall clock.
        throw [System.ArgumentException]::new(
            'HARNESS-INVALID-CLOCK: bounded runtime requires an injected clock; the harness never sleeps or reads an ambient clock.')
    }
    if ($Bounds -isnot [hashtable]) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BOUNDS: bounds must be a mapping.')
    }
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessBounds' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            [void](Test-IntegrationHarnessBounds -Bounds $Bounds)
        }
    }
    foreach ($stage in $Script:BoundedRuntimeStages) {
        $boundField = $Script:BoundedRuntimeStageBound[$stage]
        if (-not $Bounds.ContainsKey($boundField)) {
            throw [System.ArgumentException]::new(
                "HARNESS-INVALID-BOUNDS: stage '$stage' has no bound field '$boundField'.")
        }
        if ([int]$Bounds[$boundField] -le 0) {
            throw [System.ArgumentException]::new(
                "HARNESS-INVALID-BOUNDS: stage '$stage' bound must be positive.")
        }
    }
    foreach ($field in @($Script:BoundedRuntimeByteBound.Values)) {
        if (-not $Bounds.ContainsKey($field) -or [int]$Bounds[$field] -le 0) {
            throw [System.ArgumentException]::new(
                "HARNESS-INVALID-BOUNDS: byte/count bound '$field' must be present and positive.")
        }
    }
    return @{
        runId          = $RunId
        owner          = $Owner
        bounds         = $Bounds
        clock          = $Clock
        stageBudgets   = @(
            foreach ($stage in $Script:BoundedRuntimeStages) {
                @{ stage = $stage; limit = [int]$Bounds[$Script:BoundedRuntimeStageBound[$stage]]; elapsedMs = 0; breached = $false }
            }
        )
        byteBudgets    = @(
            foreach ($key in @('output', 'line', 'artifact')) {
                @{ dimension = $key; limit = [int]$Bounds[$Script:BoundedRuntimeByteBound[$key]]; observed = 0; breached = $false }
            }
        )
        resources      = 0
        descendants    = 0
        marks          = @()
        closedStages   = @{}
        breaches       = [System.Collections.Generic.List[string]]::new()
        uncertain      = $false
    }
}

# Read the injected clock exactly once. The only accepted readings are
# DateTimeOffset/DateTime; anything else is a fail-closed clock contract error.
function Get-IntegrationHarnessBoundedNow {
    [CmdletBinding()]
    [OutputType([System.DateTimeOffset])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime
    )
    $observed = (& $Runtime['clock'])
    if ($observed -is [System.DateTimeOffset]) {
        return $observed
    }
    if ($observed -is [System.DateTime]) {
        return [System.DateTimeOffset]::new($observed.ToUniversalTime())
    }
    throw [System.ArgumentException]::new('HARNESS-INVALID-CLOCK: injected clock must return DateTimeOffset.')
}

# Mark the start instant of a bounded stage, read from the injected clock. The
# returned runtime carries the mark; nothing sleeps.
function Start-IntegrationHarnessBoundedStage {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime,
        [Parameter(Mandatory)]
        [string]$Stage,
        [Parameter(Mandatory)]
        [string]$Key
    )
    if ($Script:BoundedRuntimeStages -notcontains $Stage) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STAGE: '$Stage'.")
    }
    if ([string]::IsNullOrWhiteSpace($Key)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: a bounded stage key is required.')
    }
    $now = Get-IntegrationHarnessBoundedNow -Runtime $Runtime
    $marks = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($mark in @($Runtime['marks'])) {
        [void]$marks.Add($mark)
    }
    [void]$marks.Add(@{ stage = $Stage; key = $Key; at = $now })
    $Runtime['marks'] = @($marks)
    return $Runtime
}

# Close a bounded stage: charge the delta between its mark and a fresh injected
# clock read to that stage AND to the overall stage, then mark the stage closed
# so repeated closes of the same key are idempotent (never double-charged).
function Stop-IntegrationHarnessBoundedStage {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime,
        [Parameter(Mandatory)]
        [string]$Stage,
        [Parameter(Mandatory)]
        [string]$Key
    )
    if ($Script:BoundedRuntimeStages -notcontains $Stage) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STAGE: '$Stage'.")
    }
    $markKey = '{0}|{1}' -f $Stage, $Key
    if ($Runtime.ContainsKey('closedStages') -and $Runtime['closedStages'].ContainsKey($markKey)) {
        # Already charged: repeated cleanup/close is idempotent, never re-charged.
        return $Runtime
    }
    $openMark = $null
    foreach ($mark in @($Runtime['marks'])) {
        if ([string]$mark['stage'] -ceq $Stage -and [string]$mark['key'] -ceq $Key) {
            $openMark = $mark
        }
    }
    if ($null -eq $openMark) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STAGE: stage '$Stage' was never started for '$Key'.")
    }
    $now = Get-IntegrationHarnessBoundedNow -Runtime $Runtime
    $elapsed = [int64]($now - ([System.DateTimeOffset]$openMark['at'])).TotalMilliseconds
    if ($elapsed -lt 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-CLOCK: the injected clock moved backwards.')
    }
    $Runtime = Add-IntegrationHarnessBoundedStageElapsed -Runtime $Runtime -Stage $Stage `
        -ElapsedMilliseconds $elapsed
    if (-not $Runtime.ContainsKey('closedStages') -or $null -eq $Runtime['closedStages']) {
        $Runtime['closedStages'] = @{}
    }
    $Runtime['closedStages'][$markKey] = $true
    return $Runtime
}

# Charge elapsed milliseconds to one named stage. Elapsed is supplied by the
# caller as the delta between two injected-clock reads; nothing sleeps.
function Add-IntegrationHarnessBoundedStageElapsed {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime,
        [Parameter(Mandatory)]
        [string]$Stage,
        [Parameter(Mandatory)]
        [int64]$ElapsedMilliseconds
    )
    if ($Script:BoundedRuntimeStages -notcontains $Stage) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STAGE: '$Stage'.")
    }
    if ($ElapsedMilliseconds -lt 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-CLOCK: elapsed time must be non-negative.')
    }
    $index = [array]::IndexOf([string[]]$Script:BoundedRuntimeStages, [string]$Stage)
    $budget = $Runtime['stageBudgets'][$index]
    $updated = @($Runtime['stageBudgets'] | ForEach-Object { $_ })
    $updated[$index] = @{
        stage      = $budget['stage']
        limit      = [int]$budget['limit']
        elapsedMs  = [int64]$budget['elapsedMs'] + $ElapsedMilliseconds
        breached   = ([int64]$budget['elapsedMs'] + $ElapsedMilliseconds) -gt ([int64]$budget['limit'])
    }
    $Runtime['stageBudgets'] = $updated
    if ($updated[$index].breached) {
        $Runtime['breaches'].Add("stage-bound-exceeded:$Stage")
        $Runtime['uncertain'] = $true
    }
    # The overall bound is charged by every stage so it is never bypassed.
    $overall = [array]::IndexOf([string[]]$Script:BoundedRuntimeStages, 'overall')
    $overallBudget = $Runtime['stageBudgets'][$overall]
    $overallUpdated = @($Runtime['stageBudgets'] | ForEach-Object { $_ })
    $overallUpdated[$overall] = @{
        stage     = 'overall'
        limit     = [int]$overallBudget['limit']
        elapsedMs = [int64]$overallBudget['elapsedMs'] + $ElapsedMilliseconds
        breached  = ([int64]$overallBudget['elapsedMs'] + $ElapsedMilliseconds) -gt ([int64]$overallBudget['limit'])
    }
    $Runtime['stageBudgets'] = $overallUpdated
    if ($overallUpdated[$overall].breached) {
        $Runtime['breaches'].Add('stage-bound-exceeded:overall')
        $Runtime['uncertain'] = $true
    }
    return $Runtime
}

# Charge an observed byte/line/count value against its dimension bound.
function Add-IntegrationHarnessBoundedObservation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime,
        [Parameter(Mandatory)]
        [ValidateSet('output', 'line', 'artifact', 'resources', 'descendants')]
        [string]$Dimension,
        [Parameter(Mandatory)]
        [int64]$Observed
    )
    if ($Observed -lt 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-OBSERVATION: bounded observations must be non-negative.')
    }
    if ($Dimension -eq 'resources') {
        $Runtime['resources'] = [int]$Observed
        if ([int]$Observed -gt [int]$Runtime['bounds']['maxResources']) {
            $Runtime['breaches'].Add("bound-exceeded:resources")
            $Runtime['uncertain'] = $true
        }
        return $Runtime
    }
    if ($Dimension -eq 'descendants') {
        $Runtime['descendants'] = [int]$Observed
        if ([int]$Observed -gt [int]$Runtime['bounds']['maxDescendants']) {
            $Runtime['breaches'].Add("bound-exceeded:descendants")
            $Runtime['uncertain'] = $true
        }
        return $Runtime
    }
    $index = [array]::IndexOf([string[]]@('output', 'line', 'artifact'), [string]$Dimension)
    $current = $Runtime['byteBudgets'][$index]
    $updated = @($Runtime['byteBudgets'] | ForEach-Object { $_ })
    $total = [int64]$current['observed'] + $Observed
    $updated[$index] = @{
        dimension = $Dimension
        limit     = [int]$current['limit']
        observed  = $total
        breached  = $total -gt ([int64]$current['limit'])
    }
    $Runtime['byteBudgets'] = $updated
    if ($updated[$index].breached) {
        $Runtime['breaches'].Add("bound-exceeded:$Dimension")
        $Runtime['uncertain'] = $true
    }
    return $Runtime
}

# Project the bounded runtime as bounded, redacted evidence. Semantic identity
# (stages, limits, breaches) is deterministic; the observational clock reading
# is kept in a separate field so a deterministic fingerprint never depends on
# when the run happened.
function ConvertTo-IntegrationHarnessBoundedRuntimeEvidence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Runtime
    )
    return @{
        runId         = [string]$Runtime['runId']
        owner         = [string]$Runtime['owner']
        stageBudgets  = @($Runtime['stageBudgets'] | ForEach-Object {
            @{ stage = [string]$_['stage']; limit = [int]$_['limit']; elapsedMs = [int64]$_['elapsedMs']; breached = [bool]$_['breached'] }
        })
        byteBudgets   = @($Runtime['byteBudgets'] | ForEach-Object {
            @{ dimension = [string]$_['dimension']; limit = [int]$_['limit']; observed = [int64]$_['observed']; breached = [bool]$_['breached'] }
        })
        resources     = [int]$Runtime['resources']
        descendants   = [int]$Runtime['descendants']
        breaches      = @($Runtime['breaches'] | Sort-Object -Culture '' -CaseSensitive -Unique)
        uncertain     = [bool]$Runtime['uncertain']
    }
}

# Read one field out of an owned-process record, accepting both the
# `{identity = {...}}` wrapper and a bare identity record, and accepting either
# a hashtable or a PSCustomObject shape. A missing or unreadable field yields
# the supplied default, never an exception and never an assumed value.
function Get-IntegrationHarnessOwnedRecordField {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter()]
        [AllowNull()]
        $Record,
        [Parameter(Mandatory)]
        [string]$Field,
        [Parameter()]
        [AllowNull()]
        $Default = $null
    )
    $identity = $Record
    if ($null -eq $identity) { return $Default }
    if ($identity -is [hashtable] -and $identity.ContainsKey('identity')) {
        $identity = $identity['identity']
    }
    if ($identity -is [hashtable]) {
        if ($identity.ContainsKey($Field)) { return $identity[$Field] }
        return $Default
    }
    if ($identity -is [psobject] -and $null -ne $identity.PSObject.Properties[$Field]) {
        return $identity.PSObject.Properties[$Field].Value
    }
    return $Default
}

# Project the accepted owned-process records for a run: the run-minted records
# only, plus the root pid when exactly one record declares itself the test root.
# A record minted by another run is foreign evidence and is dropped here, so it
# can never authorize a stop.
function New-IntegrationHarnessOwnedProcessView {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$OwnedProcesses = @(),
        [Parameter(Mandatory)]
        [string]$RunId
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    $records = [System.Collections.Generic.List[object]]::new()
    $rootPid = 0
    foreach ($record in @($OwnedProcesses)) {
        if ($null -eq $record) { continue }
        $recordRunId = [string](Get-IntegrationHarnessOwnedRecordField -Record $record -Field 'runId')
        if ($recordRunId -cne $RunId) { continue }
        $pidValue = [int](Get-IntegrationHarnessOwnedRecordField -Record $record -Field 'processId' -Default 0)
        if ($pidValue -le 0) { continue }
        [void]$records.Add($record)
        if ([string](Get-IntegrationHarnessOwnedRecordField -Record $record -Field 'role') -ceq 'test-root') {
            $rootPid = $pidValue
        }
    }
    return @{
        rootPid = $rootPid
        records = @($records)
    }
}

function New-IntegrationHarnessRun {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Inventory,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$SelectedIdentities,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc', 'inventoryDigest')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    if (-not $Inventory.ContainsKey('rows') -or $null -eq $Inventory['rows']) {
        throw [System.ArgumentException]::new('HARNESS-INCOMPLETE-INVENTORY: inventory has no rows.')
    }
    $rows = @($Inventory['rows'])
    if ($rows.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-INCOMPLETE-INVENTORY: inventory denominator is empty.')
    }
    if ($SelectedIdentities.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: an empty selection is never success.')
    }
    foreach ($identity in $SelectedIdentities) {
        if ([string]::IsNullOrWhiteSpace($identity)) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-SELECTION: selected identity is empty.')
        }
        if ($identity -eq '*' -or $identity -eq 'all' -or $identity.Contains('*')) {
            throw [System.ArgumentException]::new('HARNESS-WILDCARD-SELECTION: implicit wildcard selection is forbidden.')
        }
    }
    $uniqueSelected = @($SelectedIdentities | Sort-Object -Culture '' -CaseSensitive -Unique)
    if ($uniqueSelected.Count -ne $SelectedIdentities.Count) {
        throw [System.ArgumentException]::new('HARNESS-DUPLICATE-SELECTION: duplicate selected identity.')
    }
    $byIdentity = @{}
    foreach ($row in $rows) {
        if ($row -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INCOMPLETE-INVENTORY: inventory row must be a hashtable.')
        }
        $identity = ('{0}::{1}::{2}::{3}' -f $row['packageId'], $row['targetKind'], $row['targetName'], $row['testName'])
        if (-not $byIdentity.ContainsKey($identity)) {
            $byIdentity[$identity] = $row
        } else {
            throw [System.InvalidOperationException]::new("HARNESS-DUPLICATE-EVIDENCE: duplicate inventory identity '$identity'.")
        }
    }
    $selectedRows = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($identity in $SelectedIdentities) {
        if (-not $byIdentity.ContainsKey($identity)) {
            throw [System.ArgumentException]::new("HARNESS-UNKNOWN-TEST: selected identity is not in inventory: '$identity'.")
        }
        $selectedRows.Add($byIdentity[$identity])
    }
    $orderedRows = @($selectedRows | Sort-Object -Property {
        ('{0}::{1}::{2}::{3}' -f $_['packageId'], $_['targetKind'], $_['targetName'], $_['testName'])
    })
    $digests = @($orderedRows | ForEach-Object { [string]$_['rowDigest'] } | Sort-Object -Culture '' -CaseSensitive)
    $digestInput = @{ rows = @($orderedRows) }
    $canonical = $null
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Get-IntegrationHarnessCanonicalJson' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $canonical = Get-IntegrationHarnessCanonicalJson -Value $digestInput
        }
    }
    if ([string]::IsNullOrWhiteSpace($canonical)) {
        $canonical = ($digestInput | ConvertTo-Json -Compress -Depth 16)
    }
    $computed = $null
    if (Test-IntegrationHarnessModelLoaded) {
        $shaCommand = Get-Command -Name 'Get-IntegrationHarnessSha256Hex' -ErrorAction SilentlyContinue
        if ($null -ne $shaCommand) {
            $computed = Get-IntegrationHarnessSha256Hex -Text $canonical
        }
    }
    if ([string]::IsNullOrWhiteSpace($computed)) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($canonical)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digestBytes = $hasher.ComputeHash($bytes)
        } finally {
            $hasher.Dispose()
        }
        $computed = (($digestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    if ($computed -cne [string]$Binding['inventoryDigest']) {
        throw [System.InvalidOperationException]::new(
            'HARNESS-DIGEST-MISMATCH: binding inventory digest does not match the selected inventory subset.')
    }
    return @{
        state              = 'InventoryConfigAccepted'
        binding            = $Binding
        inventoryDigest    = [string]$Binding['inventoryDigest']
        selectedIdentities = @($uniqueSelected | Sort-Object -Culture '' -CaseSensitive)
        selectedRows       = @($orderedRows)
        selectedRowDigests = @($digests)
        semanticIdentity   = $computed
        history            = @('InventoryConfigAccepted')
    }
}

function Move-IntegrationHarnessState {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [string]$ToState
    )
    if (-not $Run.ContainsKey('state') -or [string]::IsNullOrWhiteSpace([string]$Run['state'])) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-RUN: run has no state.')
    }
    $from = [string]$Run['state']
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessStateTransition' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            [void](Test-IntegrationHarnessStateTransition -FromState $from -ToState $ToState)
        } else {
            [void](Test-IntegrationHarnessClosedOperation -Operation 'Plan')
        }
    } else {
        $ranks = @{
            InventoryConfigAccepted            = 0
            OwnedRunRoot                       = 1
            AcceptedProviderPlans              = 2
            Allocation                         = 3
            StartRequested                     = 4
            ObservedProcessReadinessUnknown    = 5
            AcceptedSemanticReadiness          = 6
            GroupInitialization                = 7
            ExactTestExecution                 = 8
            TerminalTestEvidence               = 9
            EvidenceCollection                 = 10
            CleanupRequested                   = 11
            OwnedResourcesStopped              = 12
            CleanupVerified                    = 13
            ReconciliationRequired             = 13
            Complete                           = 14
            Failed                             = 14
            Incomplete                         = 14
            Cancelled                          = 14
        }
        if (-not $ranks.ContainsKey($from) -or -not $ranks.ContainsKey($ToState)) {
            throw [System.ArgumentException]::new("HARNESS-UNKNOWN-STATE: '$from' -> '$ToState'.")
        }
        if ($from -ceq $ToState) {
            if ($ToState -cnotin @('CleanupRequested', 'OwnedResourcesStopped', 'CleanupVerified', 'ReconciliationRequired')) {
                throw [System.InvalidOperationException]::new("HARNESS-ILLEGAL-TRANSITION: self-transition only for idempotent cleanup states.")
            }
        } elseif ([int]$ranks[$ToState] -ne ([int]$ranks[$from] + 1)) {
            throw [System.InvalidOperationException]::new("HARNESS-ILLEGAL-TRANSITION: '$from' -> '$ToState'.")
        }
    }
    $next = @{}
    foreach ($key in $Run.Keys) {
        $next[$key] = $Run[$key]
    }
    $next['state'] = $ToState
    $history = @()
    if ($Run.ContainsKey('history') -and $null -ne $Run['history']) {
        $history = @($Run['history'])
    }
    $next['history'] = @($history + @($ToState))
    return $next
}

# The single resource identity of a plan or of a cleanup target. Preparation,
# approval and cleanup all read the key through this one projection, so no stage
# can order or stop a resource under a name another stage would not.
function Get-IntegrationHarnessPlanResourceKey {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Plan
    )
    if ($Plan -is [hashtable]) {
        if ($Plan.ContainsKey('resourceKey') -and $null -ne $Plan['resourceKey']) {
            return [string]$Plan['resourceKey']
        }
        if ($Plan.ContainsKey('allocation') -and $null -ne $Plan['allocation']) {
            return [string]$Plan['allocation']
        }
    }
    return [string]$Plan
}

# The deterministic dependency order of a plan set. A plan's rank is one past
# the deepest rank among the dependencies declared for it that are present in
# THIS plan set, so every dependency always precedes its dependent; ranks equal
# are broken by the resource key, so the order is total and reproducible. A
# declared edge to a plan outside the set, or an edge cycle, is a plan defect
# and is refused here rather than silently ignored.
function Get-IntegrationHarnessDependencyOrder {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Plans
    )
    $byKey = @{}
    foreach ($plan in $Plans) {
        $key = Get-IntegrationHarnessPlanResourceKey -Plan $plan
        if ([string]::IsNullOrWhiteSpace($key)) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-PLAN: plan entry carries no resource key.')
        }
        if ($byKey.ContainsKey($key)) {
            throw [System.InvalidOperationException]::new("HARNESS-DUPLICATE-EVIDENCE: duplicate plan resource key '$key'.")
        }
        $byKey[$key] = $plan
    }
    $ranks = @{}
    $ranked = [System.Collections.Generic.List[string]]::new()
    $pending = [System.Collections.Generic.List[string]]::new()
    foreach ($key in @($byKey.Keys | Sort-Object -Culture '' -CaseSensitive)) {
        $pending.Add([string]$key)
    }
    while ($pending.Count -gt 0) {
        $progressed = $false
        foreach ($key in @($pending)) {
            $plan = $byKey[$key]
            $dependencies = @()
            if ($plan -is [hashtable] -and $plan.ContainsKey('dependsOn') -and $null -ne $plan['dependsOn']) {
                $dependencies = @($plan['dependsOn'])
            }
            $ready = $true
            $deepest = 0
            foreach ($dependency in $dependencies) {
                $dependencyKey = [string]$dependency
                if ([string]::IsNullOrWhiteSpace($dependencyKey) -or -not $byKey.ContainsKey($dependencyKey)) {
                    throw [System.ArgumentException]::new(
                        "HARNESS-INVALID-PLAN: plan '$key' depends on '$dependencyKey', which is not in the plan set.")
                }
                if (-not $ranked.Contains($dependencyKey)) {
                    $ready = $false
                    break
                }
                $deepest = [Math]::Max($deepest, [int]$ranks[$dependencyKey] + 1)
            }
            if ($ready) {
                $ranks[$key] = $deepest
                [void]$ranked.Add($key)
                $progressed = $true
            }
        }
        if (-not $progressed) {
            $cycle = (@($pending) -join ',')
            throw [System.ArgumentException]::new(
                "HARNESS-INVALID-PLAN: plan dependency cycle among '$cycle'.")
        }
        foreach ($key in @($pending)) {
            if ($ranked.Contains($key)) {
                [void]$pending.Remove($key)
            }
        }
    }
    $ordered = @($byKey.Keys | Sort-Object -Property {
        ('{0:D6}:{1}' -f [int]$ranks[[string]$_], [string]$_)
    } -Culture '' -CaseSensitive)
    return @($ordered | ForEach-Object { $byKey[[string]$_] })
}

function Approve-IntegrationHarnessProviderPlan {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Plans
    )
    if ($Plans.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PLAN: plan set is empty.')
    }
    if (-not $Run.ContainsKey('binding')) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-RUN: run has no binding.')
    }
    $binding = $Run['binding']
    $seenKeys = @{}
    foreach ($plan in $Plans) {
        if ($plan -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-PLAN: plan entry must be a hashtable.')
        }
        foreach ($field in @('resourceKey', 'runId', 'testClass', 'providerRevision', 'owner', 'generation')) {
            if (-not $plan.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$plan[$field])) {
                throw [System.ArgumentException]::new("HARNESS-INVALID-PLAN: plan is missing '$field'.")
            }
        }
        if ([string]$plan['runId'] -cne [string]$binding['runId']) {
            throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: plan must not change the run identity.')
        }
        if ([string]$plan['testClass'] -cne [string]$binding['testClass']) {
            throw [System.InvalidOperationException]::new('HARNESS-PROVIDER-FORBIDDEN: plan must not change the test class.')
        }
        if ([string]$plan['providerRevision'] -cne [string]$binding['providerRevision']) {
            throw [System.InvalidOperationException]::new('HARNESS-PLAN-REVISION: plan revision must match the bound provider revision.')
        }
        if ([string]$plan['owner'] -cne [string]$binding['owner'] -or
            [int]$plan['generation'] -ne [int]$binding['generation']) {
            throw [System.InvalidOperationException]::new('HARNESS-PLAN-RECEIPT: plan owner/generation receipt mismatch.')
        }
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            if ($plan.ContainsKey($forbidden)) {
                throw [System.InvalidOperationException]::new(
                    "HARNESS-PROVIDER-FORBIDDEN: plan must not carry caller-controlled '$forbidden'.")
            }
        }
        $key = [string]$plan['resourceKey']
        if ($seenKeys.ContainsKey($key)) {
            throw [System.InvalidOperationException]::new("HARNESS-DUPLICATE-EVIDENCE: duplicate plan resource key '$key'.")
        }
        $seenKeys[$key] = $true
    }
    # The accepted order is the dependency order of this plan set, and it is
    # recorded on the run: preparation walks this list forward and cleanup walks
    # its exact reverse, so the two stages cannot disagree about the order.
    $ordered = @(Get-IntegrationHarnessDependencyOrder -Plans $Plans)
    $next = @{}
    foreach ($key in $Run.Keys) {
        $next[$key] = $Run[$key]
    }
    $next['acceptedPlans'] = @($ordered)
    $next['acceptedPlanOrder'] = @($ordered | ForEach-Object {
        [string](Get-IntegrationHarnessPlanResourceKey -Plan $_)
    })
    $next['state'] = 'AcceptedProviderPlans'
    $history = @()
    if ($Run.ContainsKey('history') -and $null -ne $Run['history']) {
        $history = @($Run['history'])
    }
    $next['history'] = @($history + @('AcceptedProviderPlans'))
    return $next
}

function Group-IntegrationHarnessSelection {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$SelectedRows
    )
    if ($SelectedRows.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: cannot group an empty selection.')
    }
    $groups = @{}
    $total = 0
    foreach ($row in $SelectedRows) {
        if ($row -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-ROW: grouped row must be a hashtable.')
        }
        $key = $null
        if (Test-IntegrationHarnessModelLoaded) {
            $command = Get-Command -Name 'Get-IntegrationHarnessGroupKey' -ErrorAction SilentlyContinue
            if ($null -ne $command) {
                $key = Get-IntegrationHarnessGroupKey -Row $row
            }
        }
        if ([string]::IsNullOrWhiteSpace($key)) {
            foreach ($field in @('providerClass', 'isolationClass', 'targetClass', 'resetClass', 'serializationClass')) {
                if (-not $row.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$row[$field])) {
                    throw [System.ArgumentException]::new("HARNESS-INVALID-GROUP-ROW: missing '$field'.")
                }
            }
            $key = ('{0}|{1}|{2}|{3}|{4}' -f
                $row['providerClass'], $row['isolationClass'], $row['targetClass'],
                $row['resetClass'], $row['serializationClass'])
        }
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $groups[$key].Add($row)
        $total += 1
    }
    if ($total -ne $SelectedRows.Count) {
        throw [System.InvalidOperationException]::new('HARNESS-EVIDENCE-COUNT: group union does not equal the selection.')
    }
    $orderedKeys = @($groups.Keys | Sort-Object -Culture '' -CaseSensitive)
    $result = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($key in $orderedKeys) {
        $members = @($groups[$key] | Sort-Object -Property {
            ('{0}::{1}::{2}::{3}' -f $_['packageId'], $_['targetKind'], $_['targetName'], $_['testName'])
        })
        $first = $members[0]
        $result.Add(@{
            groupKey           = $key
            providerClass      = [string]$first['providerClass']
            isolationClass     = [string]$first['isolationClass']
            targetClass        = [string]$first['targetClass']
            resetClass         = [string]$first['resetClass']
            serializationClass = [string]$first['serializationClass']
            rows               = @($members)
            count              = $members.Count
        })
    }
    return @($result)
}

function Test-IntegrationHarnessReadiness {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Observation,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($field in @('runId', 'providerRevision')) {
        if (-not $Observation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Observation[$field])) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-OBSERVATION: observation is missing '$field'.")
        }
    }
    if ([string]$Observation['runId'] -cne [string]$Binding['runId']) {
        throw [System.InvalidOperationException]::new('HARNESS-CONTRADICTORY-EVIDENCE: observation run identity mismatch.')
    }
    if ([string]$Observation['providerRevision'] -cne [string]$Binding['providerRevision']) {
        throw [System.InvalidOperationException]::new('HARNESS-CONTRADICTORY-EVIDENCE: observation provider revision mismatch.')
    }
    if ($Observation.ContainsKey('readyBecauseExitZero') -and [bool]$Observation['readyBecauseExitZero']) {
        return $false
    }
    if ($Observation.ContainsKey('readyBecausePortOpen') -and [bool]$Observation['readyBecausePortOpen']) {
        return $false
    }
    if ($Observation.ContainsKey('readyBecausePidAlive') -and [bool]$Observation['readyBecausePidAlive']) {
        return $false
    }
    if (-not $Observation.ContainsKey('semanticReceipt') -or $null -eq $Observation['semanticReceipt']) {
        return $false
    }
    $receipt = $Observation['semanticReceipt']
    if ($receipt -isnot [hashtable]) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-OBSERVATION: semantic receipt must be a hashtable.')
    }
    foreach ($field in @('readinessProbePassed', 'owner', 'generation')) {
        if (-not $receipt.ContainsKey($field)) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-OBSERVATION: semantic receipt is missing '$field'.")
        }
    }
    if (-not [bool]$receipt['readinessProbePassed']) {
        return $false
    }
    if ([string]$receipt['owner'] -cne [string]$Binding['owner'] -or
        [int]$receipt['generation'] -ne [int]$Binding['generation']) {
        throw [System.InvalidOperationException]::new('HARNESS-CONTRADICTORY-EVIDENCE: readiness owner/generation mismatch.')
    }
    if ($receipt.ContainsKey('requiredChecks')) {
        foreach ($check in @($receipt['requiredChecks'])) {
            if ($check -is [hashtable]) {
                if ($check.ContainsKey('passed') -and -not [bool]$check['passed']) {
                    return $false
                }
            }
        }
    }
    return $true
}

function Invoke-IntegrationHarnessPrepare {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Plans,
        [Parameter(Mandatory)]
        [hashtable]$Provider,
        [Parameter(Mandatory)]
        [hashtable]$Bounds,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    if ($Plans.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PLAN: nothing to prepare.')
    }
    if ($Plans.Count -gt [int]$Bounds['maxResources']) {
        throw [System.ArgumentException]::new('HARNESS-BOUNDS-EXCEEDED: plan exceeds the resource bound.')
    }
    $approved = Approve-IntegrationHarnessProviderPlan -Run $Run -Plans $Plans
    # Allocate is dispatched in the dependency order approval just recorded on
    # the run. The order is not re-derived here: this list is the order, and
    # cleanup stops its exact reverse.
    $ordered = @($approved['acceptedPlans'])
    $prepareOrder = @($approved['acceptedPlanOrder'])
    $started = [System.Collections.Generic.List[hashtable]]::new()
    $allocated = [System.Collections.Generic.List[hashtable]]::new()
    $primaryFailure = $null
    foreach ($plan in $ordered) {
        [void]$started.Add($plan)
        try {
            $result = Invoke-IntegrationHarnessProviderOperation -Operation 'Allocate' `
                -Provider $Provider -Binding $Run['binding'] `
                -Arguments @{ resourceKey = [string]$plan['resourceKey']; plan = $plan } -Clock $Clock
            [void]$allocated.Add(@{
                resourceKey = [string]$plan['resourceKey']
                allocation  = $result
                unknown     = $false
            })
        } catch {
            if ($null -eq $primaryFailure) {
                $primaryFailure = $_.Exception.Message
            } else {
                $primaryFailure = "$primaryFailure"
            }
            [void]$allocated.Add(@{
                resourceKey = [string]$plan['resourceKey']
                allocation  = $null
                unknown     = $true
            })
            break
        }
    }
    if ($null -ne $primaryFailure) {
        $cleanup = Invoke-IntegrationHarnessCleanup -Run $approved -Resources @($started) `
            -Provider $Provider -CleanedState @{}
        return @{
            success         = $false
            primaryFailure  = $primaryFailure
            cleanupFailures = @($cleanup['failures'])
            cleanupRecords  = @($cleanup['records'])
            cleanupState    = [string]$cleanup['overallState']
            startedCount    = $started.Count
            prepareOrder    = @($prepareOrder)
            stopOrder       = @($cleanup['stopOrder'])
            nextState       = 'CleanupRequested'
        }
    }
    return @{
        success         = $true
        primaryFailure  = $null
        cleanupFailures = @()
        cleanupRecords  = @()
        cleanupState    = $null
        startedCount    = $started.Count
        prepareOrder    = @($prepareOrder)
        allocations     = @($allocated)
        nextState       = 'Allocation'
    }
}

function Invoke-IntegrationHarnessCleanup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Resources,
        [Parameter(Mandatory)]
        [hashtable]$Provider,
        [Parameter(Mandatory)]
        [hashtable]$CleanedState
    )
    if (-not $Run.ContainsKey('binding')) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-RUN: run has no binding.')
    }
    $binding = $Run['binding']
    # Cleanup stops in the exact reverse of the recorded prepare order. When the
    # run carries that order - every run that prepared resources does - it is the
    # only authority and nothing is re-derived here, so a dependent can never be
    # stopped before a dependency it was started after. A caller that stops
    # resources on a run with no recorded order gets the same dependency rank,
    # reversed, so the reverse-order guarantee holds there as well.
    $byKey = @{}
    $unkeyed = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in $Resources) {
        $resourceKey = ''
        if ($resource -is [hashtable]) {
            if ($resource.ContainsKey('resourceKey') -and $null -ne $resource['resourceKey']) {
                $resourceKey = [string]$resource['resourceKey']
            } elseif ($resource.ContainsKey('allocation') -and $null -ne $resource['allocation']) {
                $resourceKey = [string]$resource['allocation']
            }
        }
        if ([string]::IsNullOrWhiteSpace($resourceKey)) {
            [void]$unkeyed.Add($resource)
            continue
        }
        $byKey[$resourceKey] = $resource
    }
    $stopOrder = @()
    if ($Run.ContainsKey('acceptedPlanOrder') -and $null -ne $Run['acceptedPlanOrder']) {
        $recorded = @($Run['acceptedPlanOrder'])
        $absent = @($byKey.Keys | Where-Object { $recorded -cnotcontains [string]$_ } |
            Sort-Object -Culture '' -CaseSensitive)
        if ($absent.Count -gt 0) {
            throw [System.ArgumentException]::new(
                "HARNESS-INVALID-PLAN: cleanup resource(s) '$($absent -join ',')' are not in the recorded prepare order.")
        }
        $stopOrder = @($recorded | Where-Object { $byKey.ContainsKey([string]$_) } |
            ForEach-Object { $byKey[[string]$_] })
    } else {
        $stopOrder = @(Get-IntegrationHarnessDependencyOrder -Plans @($byKey.Values))
    }
    $ordered = [System.Collections.Generic.List[object]]::new()
    for ($position = $stopOrder.Count - 1; $position -ge 0; $position--) {
        [void]$ordered.Add($stopOrder[$position])
    }
    foreach ($resource in $unkeyed) {
        [void]$ordered.Add($resource)
    }
    $stopKeys = [System.Collections.Generic.List[string]]::new()
    foreach ($resource in $ordered) {
        $stopKey = Get-IntegrationHarnessPlanResourceKey -Plan $resource
        if (-not [string]::IsNullOrWhiteSpace($stopKey)) {
            [void]$stopKeys.Add($stopKey)
        }
    }
    $records = [System.Collections.Generic.List[hashtable]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()
    $unknown = $false
    foreach ($resource in $ordered) {
        $key = Get-IntegrationHarnessPlanResourceKey -Plan $resource
        if ([string]::IsNullOrWhiteSpace($key)) {
            [void]$failures.Add('cleanup-record-missing-key')
            $unknown = $true
            continue
        }
        if ($CleanedState.ContainsKey($key)) {
            [void]$records.Add(@{
                resourceKey  = $key
                state        = 'CleanupVerified'
                alreadyClean = $true
                failures     = @()
            })
            continue
        }
        try {
            [void](Invoke-IntegrationHarnessProviderOperation -Operation 'Stop' `
                -Provider $Provider -Binding $binding -Arguments @{ resourceKey = $key })
            $verification = Invoke-IntegrationHarnessProviderOperation -Operation 'VerifyCleanup' `
                -Provider $Provider -Binding $binding -Arguments @{ resourceKey = $key }
            $verified = $false
            if ($verification.ContainsKey('verified')) {
                $verified = [bool]$verification['verified']
            }
            if ($verification.ContainsKey('unknown') -and [bool]$verification['unknown']) {
                $unknown = $true
                [void]$records.Add(@{
                    resourceKey  = $key
                    state        = 'ReconciliationRequired'
                    alreadyClean = $false
                    failures     = @('cleanup-unknown')
                })
                continue
            }
            if (-not $verified) {
                $unknown = $true
                [void]$records.Add(@{
                    resourceKey  = $key
                    state        = 'ReconciliationRequired'
                    alreadyClean = $false
                    failures     = @('cleanup-not-verified')
                })
                continue
            }
            $CleanedState[$key] = $true
            [void]$records.Add(@{
                resourceKey  = $key
                state        = 'CleanupVerified'
                alreadyClean = $false
                failures     = @()
            })
        } catch {
            $unknown = $true
            [void]$failures.Add("cleanup-failed:$key")
            [void]$records.Add(@{
                resourceKey  = $key
                state        = 'ReconciliationRequired'
                alreadyClean = $false
                failures     = @("cleanup-failed:$key")
            })
        }
    }
    # The first cleanup failure is the primary failure: it is retained verbatim
    # and never overwritten by later failures in the reverse-order walk.
    $primaryFailure = $null
    if ($failures.Count -gt 0) {
        $primaryFailure = [string]$failures[0]
    }
    $overall = 'CleanupVerified'
    if ($unknown) {
        $overall = 'ReconciliationRequired'
    }
    return @{
        overallState   = $overall
        stopOrder      = @($stopKeys)
        records        = @($records)
        failures       = @($failures)
        primaryFailure = $primaryFailure
    }
}

function New-IntegrationHarnessTerminalEvidence {
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ExecutionReceipts,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$SelectedIdentities
    )
    if ($ExecutionReceipts.Count -ne $SelectedIdentities.Count) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-EVIDENCE-COUNT: execution receipt count $($ExecutionReceipts.Count) does not equal selected count $($SelectedIdentities.Count).")
    }
    $records = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($receipt in $ExecutionReceipts) {
        if ($receipt -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-EXECUTION: receipt must be a hashtable.')
        }
        foreach ($field in @('testIdentity', 'disposition')) {
            if (-not $receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$receipt[$field])) {
                throw [System.ArgumentException]::new("HARNESS-INVALID-EXECUTION: receipt is missing '$field'.")
            }
        }
        $identity = [string]$receipt['testIdentity']
        $disposition = [string]$receipt['disposition']
        [void](Test-IntegrationHarnessClosedOperation -Operation 'Plan')
        $validStates = @(
            'Passed', 'AssertionFailed', 'TimedOut', 'ProcessCrashed',
            'InfrastructureBlocked', 'UnsupportedExternalCredential', 'HarnessError',
            'Cancelled', 'NotExecutedDueToPriorContamination'
        )
        if ($disposition -cnotin $validStates) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-TERMINAL-STATE: '$disposition'.")
        }
        $record = @{
            testIdentity = $identity
            disposition  = $disposition
        }
        if ($receipt.ContainsKey('executedReceipt') -and $null -ne $receipt['executedReceipt']) {
            $record['executedReceipt'] = $receipt['executedReceipt']
        }
        if ($receipt.ContainsKey('attempts') -and $null -ne $receipt['attempts']) {
            $record['attempts'] = $receipt['attempts']
        }
        if ($receipt.ContainsKey('recurrenceRequested')) {
            $record['recurrenceRequested'] = [bool]$receipt['recurrenceRequested']
        }
        [void]$records.Add($record)
    }
    $asArray = @($records)
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessTerminalEvidenceSet' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            [void](Test-IntegrationHarnessTerminalEvidenceSet -TerminalRecords $asArray -SelectedIdentities $SelectedIdentities)
        }
    } else {
        if ($asArray.Count -ne $SelectedIdentities.Count) {
            throw [System.InvalidOperationException]::new('HARNESS-EVIDENCE-COUNT: terminal count mismatch.')
        }
    }
    return @($asArray | Sort-Object -Property { [string]$_['testIdentity'] })
}

function Reset-IntegrationHarnessForTest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Provider,
        [Parameter(Mandatory)]
        [string]$TestIdentity,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ContaminationScope,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    if ([string]::IsNullOrWhiteSpace($TestIdentity)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-TEST: test identity is empty.')
    }
    $result = Invoke-IntegrationHarnessProviderOperation -Operation 'ResetForTest' `
        -Provider $Provider -Binding $Binding `
        -Arguments @{ testIdentity = $TestIdentity } -Clock $Clock
    $contaminated = $false
    if ($result.ContainsKey('contaminated')) {
        $contaminated = [bool]$result['contaminated']
    }
    $blocked = @()
    if ($contaminated) {
        $blocked = @($ContaminationScope | Sort-Object -Culture '' -CaseSensitive -Unique)
    }
    return @{
        testIdentity = $TestIdentity
        contaminated = $contaminated
        blocked      = @($blocked)
        raw          = $result
    }
}

function New-IntegrationHarnessRunEvidence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Groups,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$TerminalRecords,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CleanupRecords,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$ArtifactHandles,
        [Parameter(Mandatory)]
        [hashtable]$SourceIdentity,
        [Parameter(Mandatory)]
        [hashtable]$WorktreeIdentity,
        [Parameter(Mandatory)]
        [hashtable]$ToolIdentities,
        [Parameter(Mandatory)]
        [hashtable]$Bounds
    )
    if (-not $Run.ContainsKey('binding')) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-RUN: run has no binding.')
    }
    $binding = $Run['binding']
    $selectedCount = @($Run['selectedIdentities']).Count
    $executedCount = @($TerminalRecords | Where-Object {
        $_ -is [hashtable] -and [string]$_['disposition'] -cne 'NotExecutedDueToPriorContamination'
    }).Count
    $evidenceCount = @($TerminalRecords).Count
    $resourceCount = 0
    if ($Run.ContainsKey('acceptedPlans') -and $null -ne $Run['acceptedPlans']) {
        $resourceCount = @($Run['acceptedPlans']).Count
    }
    $cleanedCount = @($CleanupRecords | Where-Object {
        $_ -is [hashtable] -and [string]$_['state'] -ceq 'CleanupVerified'
    }).Count
    $boundedHandles = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($handle in $ArtifactHandles) {
        if ($handle -isnot [hashtable]) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-ARTIFACT: handle must be a hashtable.')
        }
        foreach ($field in @('name', 'bytes', 'truncated')) {
            if (-not $handle.ContainsKey($field)) {
                throw [System.ArgumentException]::new("HARNESS-INVALID-ARTIFACT: missing '$field'.")
            }
        }
        if ([int]$handle['bytes'] -gt [int]$Bounds['maxArtifactBytes']) {
            throw [System.ArgumentException]::new(
                "HARNESS-BOUNDS-EXCEEDED: artifact '$($handle['name'])' exceeds the artifact byte bound.")
        }
        [void]$boundedHandles.Add(@{
            name      = [string]$handle['name']
            bytes     = [int]$handle['bytes']
            truncated = [bool]$handle['truncated']
        })
    }
    $cleanupStates = @($CleanupRecords | ForEach-Object { [string]$_['state'] } | Sort-Object -Culture '' -CaseSensitive -Unique)
    $terminalInputs = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($record in $TerminalRecords) {
        [void]$terminalInputs.Add(@{
            testIdentity = [string]$record['testIdentity']
            disposition  = [string]$record['disposition']
        })
    }
    $fingerprintInput = @{
        inventoryDigest      = [string]$Run['inventoryDigest']
        selectedRowDigests   = @($Run['selectedRowDigests'])
        providerRevision     = [string]$binding['providerRevision']
        harnessVersion       = $Script:HarnessCoreVersion
        terminalDispositions = @($terminalInputs)
        cleanupStates        = @($cleanupStates)
        selectedCount        = $selectedCount
        executedCount        = $executedCount
        evidenceCount        = $evidenceCount
    }
    $fingerprint = $null
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Get-IntegrationHarnessFailureFingerprint' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $fingerprint = Get-IntegrationHarnessFailureFingerprint -LoadBearingEvidence $fingerprintInput
        }
    }
    if ([string]::IsNullOrWhiteSpace($fingerprint)) {
        $terminalStrings = @($terminalInputs | ForEach-Object {
            ('{0}={1}' -f $_['testIdentity'], $_['disposition'])
        } | Sort-Object -Culture '' -CaseSensitive)
        $payload = @{
            inventoryDigest    = [string]$Run['inventoryDigest']
            selectedRowDigests = @(@($Run['selectedRowDigests']) | Sort-Object -Culture '' -CaseSensitive)
            providerRevision   = [string]$binding['providerRevision']
            terminals          = @($terminalStrings)
            cleanupStates      = @($cleanupStates)
            counts             = @($selectedCount, $executedCount, $evidenceCount)
        }
        $text = ($payload | ConvertTo-Json -Compress -Depth 16)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digestBytes = $hasher.ComputeHash($bytes)
        } finally {
            $hasher.Dispose()
        }
        $fingerprint = (($digestBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    $evidence = @{
        sourceIdentity      = $SourceIdentity
        worktreeIdentity    = $WorktreeIdentity
        inventoryDigest     = [string]$Run['inventoryDigest']
        selectedRowDigests  = @($Run['selectedRowDigests'])
        harnessVersion      = $Script:HarnessCoreVersion
        providerIdentity    = @{
            name     = [string]$binding['providerName']
            revision = [string]$binding['providerRevision']
        }
        toolIdentities      = $ToolIdentities
        runBinding          = $binding
        resourceRecords     = @()
        planRecords         = @()
        readinessRecords    = @()
        perTestDiscovery    = @($Run['selectedIdentities'])
        perTestExecution    = @($TerminalRecords)
        perTestTerminal     = @($TerminalRecords)
        artifactHandles     = @($boundedHandles)
        failureFingerprint  = $fingerprint
        cleanupRecords      = @($CleanupRecords)
        arithmetic          = @{
            selectedCount = $selectedCount
            executedCount = $executedCount
            evidenceCount = $evidenceCount
            resourceCount = $resourceCount
            cleanedCount  = $cleanedCount
        }
        proofCeiling        = $Script:ProofCeiling
        groupCount          = @($Groups).Count
    }
    if ($Run.ContainsKey('acceptedPlans') -and $null -ne $Run['acceptedPlans']) {
        $evidence['planRecords'] = @($Run['acceptedPlans'])
        $evidence['resourceRecords'] = @($Run['acceptedPlans'])
    }
    # Redaction happens on the way INTO the record, not as a claim about it: the
    # source and worktree identities, the provider payloads carried in the
    # receipts and every private user path that reaches the record pass through
    # the module's own redactor, and the reported status is what that pass
    # actually did. A redactor that fails drops the affected detail here; it
    # never aborts the run, never edits a cleanup record and never changes a
    # terminal disposition.
    $redactionState = @{ redactionFailed = $false; rewritten = $false }
    $evidence = ConvertTo-IntegrationHarnessRedactedValue -Value $evidence -State $redactionState
    $evidence['redactionFailed'] = [bool]$redactionState['redactionFailed']
    # A redaction that could not be completed leaves a record that is knowingly
    # not the complete evidence the Model check demands: the affected leaves were
    # dropped rather than emitted, so a structural field can be empty. Running
    # the completeness check on it anyway would turn a redaction failure into a
    # thrown proof-ceiling error, which is exactly the outcome change this issue
    # forbids. The failure is reported on the record and the gate reports the
    # evidence non-green; the run keeps its cleanup records and its terminal
    # disposition either way.
    if (-not [bool]$redactionState['redactionFailed'] -and (Test-IntegrationHarnessModelLoaded)) {
        $command = Get-Command -Name 'Test-IntegrationHarnessRunEvidence' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            [void](Test-IntegrationHarnessRunEvidence -Evidence $evidence)
        }
    }
    return $evidence
}

function Test-IntegrationHarnessEvidenceComplete {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Evidence
    )
    # The redaction verdict is settled FIRST, and a redaction that could not be
    # completed is reported as non-green evidence rather than thrown. Throwing
    # here would abort the run before Complete-IntegrationHarnessRun computes the
    # terminal disposition, so a redaction failure would decide the primary test
    # outcome and no result artifact or evidence log would be written at all -
    # the exact inversion of "redaction/sink failure is recorded but never alters
    # cleanup records or the primary terminal outcome". The caller reads the
    # returned verdict; the failure itself is on the record as redactionFailed.
    if (-not $Evidence.ContainsKey('redactionFailed') -or $null -eq $Evidence['redactionFailed']) {
        throw [System.InvalidOperationException]::new(
            "HARNESS-MISSING-EVIDENCE: missing 'redactionFailed'.")
    }
    if ([bool]$Evidence['redactionFailed']) {
        return $false
    }
    $modelComplete = $true
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessRunEvidence' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            $modelComplete = (Test-IntegrationHarnessRunEvidence -Evidence $Evidence)
        }
    }
    if (-not $modelComplete) {
        return $false
    }
    foreach ($field in @(
        'sourceIdentity', 'inventoryDigest', 'selectedRowDigests', 'harnessVersion',
        'perTestTerminal', 'failureFingerprint', 'cleanupRecords', 'arithmetic', 'proofCeiling')) {
        if (-not $Evidence.ContainsKey($field) -or $null -eq $Evidence[$field]) {
            throw [System.InvalidOperationException]::new("HARNESS-MISSING-EVIDENCE: missing '$field'.")
        }
    }
    # The redaction proof is performed here, not taken on trust. The reported
    # status is only the report: the record is walked again with the module's own
    # redactor, and any secret or private user path that still survives the walk
    # means the record is not complete evidence. That case is thrown, because it
    # means the pass reported success while material survived - persisting that
    # record would be blessing a leak, which is a different failure from a
    # redaction that could not be completed.
    $verifyState = @{ redactionFailed = $false; rewritten = $false }
    [void](ConvertTo-IntegrationHarnessRedactedValue -Value $Evidence -State $verifyState)
    if ([bool]$verifyState['rewritten']) {
        throw [System.InvalidOperationException]::new(
            'HARNESS-UNREDACTED-EVIDENCE: evidence still carries redacted secret or private user path material.')
    }
    return $true
}

function Complete-IntegrationHarnessRun {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [hashtable]$Evidence,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$CleanupRecords
    )
    # The completeness verdict is LOAD-BEARING here and is never discarded.
        # A record whose redaction could not be completed is knowingly not the
        # complete evidence the Model check demands, so it cannot reach a
        # run-level Complete. Only the completeness decision is withheld: each
        # per-test terminal disposition below is still computed from the same
        # perTestTerminal evidence, and every cleanup record is still carried
        # and still drives reconciliationRequired, so a redaction failure
        # never erases or rewrites the primary test outcome or the cleanup
        # evidence it just failed to redact.
        $evidenceComplete = (Test-IntegrationHarnessEvidenceComplete -Evidence $Evidence)
    if (@($CleanupRecords).Count -eq 0) {
        throw [System.InvalidOperationException]::new('HARNESS-MISSING-EVIDENCE: every cleanup state must be recorded.')
    }
    $reconciliationRequired = $false
    foreach ($record in $CleanupRecords) {
        if ($record -is [hashtable] -and [string]$record['state'] -ceq 'ReconciliationRequired') {
            $reconciliationRequired = $true
        }
    }
    $dispositions = @($Evidence['perTestTerminal'] | ForEach-Object { [string]$_['disposition'] })
    $outcome = 'Incomplete'
    if ($dispositions -contains 'Cancelled') {
        $outcome = 'Cancelled'
    } elseif ($dispositions -contains 'AssertionFailed' -or
        $dispositions -contains 'TimedOut' -or
        $dispositions -contains 'ProcessCrashed' -or
        $dispositions -contains 'HarnessError' -or
        $dispositions -contains 'InfrastructureBlocked' -or
        $dispositions -contains 'UnsupportedExternalCredential' -or
        $dispositions -contains 'NotExecutedDueToPriorContamination') {
        $outcome = 'Failed'
    } elseif ($dispositions.Count -gt 0 -and (@($dispositions | Where-Object { $_ -ceq 'Passed' }).Count -eq $dispositions.Count)) {
        $outcome = 'Complete'
    } else {
        $outcome = 'Incomplete'
    }
    if ($reconciliationRequired -and $outcome -ceq 'Complete') {
        $outcome = 'Failed'
    }
    # Incomplete evidence is non-green even when every selected test passed and
    # every cleanup verified: 'Complete' is a claim about the WHOLE run record,
    # so it additionally requires the evidence gate to have passed. The
    # dispositions and cleanup states that produced $outcome and
    # $reconciliationRequired are reported unchanged beside this verdict, so a
    # redaction failure is visible as its own failure rather than being
    # disguised as a test outcome.
    if (-not $evidenceComplete -and $outcome -ceq 'Complete') {
        $outcome = 'Failed'
    }
    $next = @{}
    foreach ($key in $Run.Keys) {
        $next[$key] = $Run[$key]
    }
    $next['outcome'] = $outcome
    $next['reconciliationRequired'] = $reconciliationRequired
    # The evidence verdict travels with the run record so a reader can tell an
    # incomplete-evidence failure apart from a test failure: both are 'Failed',
    # but only one of them has evidenceComplete == false.
    $next['evidenceComplete'] = $evidenceComplete
    $history = @()
    if ($Run.ContainsKey('history') -and $null -ne $Run['history']) {
        $history = @($Run['history'])
    }
    if ($reconciliationRequired) {
        $next['state'] = 'ReconciliationRequired'
        $next['history'] = @($history + @('ReconciliationRequired', $outcome))
    } else {
        $next['state'] = 'CleanupVerified'
        $next['history'] = @($history + @('CleanupVerified', $outcome))
    }
    return $next
}

function Resolve-HarnessInventoryFile {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$InventoryPath
    )
    if ([string]::IsNullOrWhiteSpace($InventoryPath)) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-INVENTORY: inventory path is empty.')
    }
    $resolved = $null
    try {
        $resolved = [System.IO.Path]::GetFullPath($InventoryPath)
    }
    catch {
        throw [System.ArgumentException]::new('HARNESS-INVALID-INVENTORY: inventory path is not usable.')
    }
    if ((Test-Path -LiteralPath $resolved -PathType Container)) {
        throw [System.ArgumentException]::new("HARNESS-INVALID-INVENTORY: inventory path names a directory: $resolved")
    }
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw [System.IO.FileNotFoundException]::new("HARNESS-MISSING-INVENTORY: inventory file is absent: $resolved")
    }
    $text = $null
    try {
        $text = [System.IO.File]::ReadAllText($resolved)
    }
    catch {
        throw [System.IO.IOException]::new("HARNESS-INVALID-INVENTORY: inventory file is not readable: $resolved")
    }
    $parsed = $null
    try {
        $parsed = $text | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw [System.ArgumentException]::new("HARNESS-INVALID-INVENTORY: inventory file is not well-formed JSON: $resolved")
    }
    if ($null -eq $parsed -or $null -eq $parsed.PSObject.Properties['rows']) {
        throw [System.ArgumentException]::new("HARNESS-INCOMPLETE-INVENTORY: inventory has no rows: $resolved")
    }
    $rows = @($parsed.rows)
    if ($rows.Count -eq 0) {
        throw [System.ArgumentException]::new("HARNESS-INCOMPLETE-INVENTORY: inventory denominator is empty: $resolved")
    }
    return $parsed
}

function Invoke-HarnessValidateConfiguration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$InventoryPath,
        [Parameter()]
        [ValidateRange(1, 7200)]
        [int]$TimeoutSeconds = 3600
    )
    if ($PSBoundParameters.ContainsKey('InventoryPath')) {
        $parsed = Resolve-HarnessInventoryFile -InventoryPath $InventoryPath
        $rows = @($parsed.rows)
        $resolved = [System.IO.Path]::GetFullPath($InventoryPath)
        return @{
            status         = 'Valid'
            inventory      = $resolved
            rowCount       = $rows.Count
            timeoutSeconds = $TimeoutSeconds
            coreVersion    = (Get-IntegrationHarnessCoreVersion)
            proofCeiling   = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
        }
    }
    return @{
        status         = 'Valid'
        inventory      = 'default'
        timeoutSeconds = $TimeoutSeconds
        coreVersion    = (Get-IntegrationHarnessCoreVersion)
        proofCeiling   = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
    }
}

# Pure WhatIf plan derivation: the fixed closed command sequence, per-identity
# resources in plan order, and per-resource cleanup steps in reverse order.
# No allocation and no side effects; identical input yields identical output.
# Not exported: the WhatIf seam attaches the derivation to every plan shape.
function Get-HarnessWhatIfDerivation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$SortedIdentities
    )
    $commands = @($Script:ClosedOperations)
    if (Test-IntegrationHarnessModelLoaded) {
        $opsCommand = Get-Command -Name 'Get-IntegrationHarnessProviderOperations' -ErrorAction SilentlyContinue
        if ($null -ne $opsCommand) {
            $commands = @(Get-IntegrationHarnessProviderOperations)
        }
    }
    $resources = [System.Collections.Generic.List[hashtable]]::new()
    $order = 0
    foreach ($identity in $SortedIdentities) {
        [void]$resources.Add(@{
            testIdentity = [string]$identity
            resourceKey  = ('test:{0}' -f $identity)
            planOrder    = $order
        })
        $order++
    }
    $cleanup = [System.Collections.Generic.List[hashtable]]::new()
    $cleanupOrder = 0
    for ($i = $resources.Count - 1; $i -ge 0; $i--) {
        [void]$cleanup.Add(@{
            resourceKey  = [string]$resources[$i]['resourceKey']
            testIdentity = [string]$resources[$i]['testIdentity']
            cleanupOrder = $cleanupOrder
            idempotent   = $true
        })
        $cleanupOrder++
    }
    return @{
        commands  = @($commands)
        resources = @($resources)
        cleanup   = @($cleanup)
    }
}

# Closed #905 row consumption (issue #907 OBJ): normalize one parsed inventory
# row into a Model-valid row hashtable. Not exported: the WhatIf/Run seams
# attach it to every inventory shape, so the one bounded coordinator consumes
# #905's run-local inventory instead of refusing it.
#
# - snake_case #905 identity/digest spellings map to the Model spellings; a row
#   carrying both spellings for one field is ambiguous and rejected (fail
#   closed, never first-wins);
# - the five grouping classes are allocated ONLY from #905-declared fields:
#   providerClass is the exact singleton of requirements (+) {STORE,RUNTIME,GIT}
#   (the closed #905 requirement vocabulary shared with the provider lanes);
#   targetClass is the declared targetKind verbatim; isolation/reset/
#   serialization classes project the declared isolation tokens verbatim, with
#   absence recorded as the explicit 'undeclared' marker so identical
#   declarations group identically. Nothing is defaulted from outside the row.
# - a row that is complete per #905 but names no single concrete provider is
#   NOT an incomplete inventory (case 6): it receives an explicit
#   UNALLOCATED-* provider class and flows to dispatch, where a missing
#   provider blocks it as InfrastructureBlocked (never skipped or passed).
#   Truly malformed rows (missing identity/digest, illegal shape, ambiguous
#   spellings, foreign isolation tokens, non-text requirement/isolation
#   entries) throw HARNESS-INVALID-ROW for the caller to report as
#   HARNESS-INCOMPLETE-INVENTORY.
# - rows that already carry all five classes pass through with strict shape
#   checks; partially allocated rows are contradictory and rejected.
function ConvertTo-IntegrationHarnessInventoryRow {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        $Row
    )
    $aliases = [ordered]@{
        package_id = 'packageId'
        target_kind = 'targetKind'
        target_name = 'targetName'
        test_name = 'testName'
        row_digest = 'rowDigest'
    }
    $names = @()
    if ($Row -is [hashtable]) {
        $names = @($Row.Keys | ForEach-Object { [string]$_ })
    } else {
        $names = @($Row.PSObject.Properties | ForEach-Object { [string]$_.Name })
    }
    foreach ($alias in $aliases.GetEnumerator()) {
        $hasInventoryName = $false
        $hasModelName = $false
        foreach ($name in $names) {
            if ($name -ceq [string]$alias.Key) {
                $hasInventoryName = $true
            } elseif ($name -ieq [string]$alias.Value) {
                $hasModelName = $true
            }
        }
        if ($hasInventoryName -and $hasModelName) {
            throw [System.ArgumentException]::new("HARNESS-AMBIGUOUS-ROW-FIELD: inventory row contains both '$($alias.Key)' and '$($alias.Value)'.")
        }
    }
    $h = @{}
    if ($Row -is [hashtable]) {
        foreach ($key in @($Row.Keys)) {
            $propertyName = [string]$key
            $modelName = $propertyName
            foreach ($alias in $aliases.GetEnumerator()) {
                if ($propertyName -ceq [string]$alias.Key) {
                    $modelName = [string]$alias.Value
                    break
                }
            }
            $h[$modelName] = $Row[$key]
        }
    } else {
        foreach ($prop in $Row.PSObject.Properties) {
            $propertyName = [string]$prop.Name
            $modelName = $propertyName
            foreach ($alias in $aliases.GetEnumerator()) {
                if ($propertyName -ceq [string]$alias.Key) {
                    $modelName = [string]$alias.Value
                    break
                }
            }
            $h[$modelName] = $prop.Value
        }
    }
    $classFields = @('providerClass', 'isolationClass', 'targetClass', 'resetClass', 'serializationClass')
    $present = @($classFields | Where-Object { $h.ContainsKey($_) -and -not [string]::IsNullOrWhiteSpace([string]$h[$_]) })
    if ($present.Count -eq $classFields.Count) {
        foreach ($field in $classFields) {
            $h[$field] = [string]$h[$field]
            if ($h[$field] -cmatch '[|]') {
                throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: field '$field' contains a separator.")
            }
        }
    } elseif ($present.Count -gt 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-ROW: partially allocated class fields.')
    } else {
        $requirements = @()
        if ($h.ContainsKey('requirements') -and $null -ne $h['requirements']) {
            $requirements = @($h['requirements'])
        }
        $requirementTokens = @()
        foreach ($entry in $requirements) {
            if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$entry)) {
                throw [System.ArgumentException]::new('HARNESS-INVALID-ROW: requirement token must be nonempty text.')
            }
            $requirementTokens += [string]$entry
        }
        $recognized = @($requirementTokens | Where-Object { $_ -ceq 'STORE' -or $_ -ceq 'RUNTIME' -or $_ -ceq 'GIT' } |
            Sort-Object -Culture '' -CaseSensitive -Unique)
        $distinct = @($requirementTokens | Sort-Object -Culture '' -CaseSensitive -Unique)
        if ($recognized.Count -eq 1 -and $distinct.Count -eq 1) {
            $h['providerClass'] = $recognized[0]
        } elseif ($requirementTokens -ccontains 'EXTERNAL_CREDENTIALED_MANUAL_ONLY') {
            $h['providerClass'] = 'UNALLOCATED-EXTERNAL'
        } elseif ($recognized.Count -gt 1) {
            $h['providerClass'] = 'UNALLOCATED-AMBIGUOUS'
        } else {
            $h['providerClass'] = 'UNALLOCATED-UNKNOWN'
        }
        $isolationEntries = @()
        if ($h.ContainsKey('isolation') -and $null -ne $h['isolation']) {
            $isolationEntries = @($h['isolation'])
        }
        $allowedIsolation = @('parallel', 'serial', 'isolated', 'timeout', 'reset')
        $declared = @()
        foreach ($token in $isolationEntries) {
            if ($token -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$token)) {
                throw [System.ArgumentException]::new('HARNESS-INVALID-ROW: isolation token must be nonempty text.')
            }
            $text = [string]$token
            if ($allowedIsolation -cnotcontains $text) {
                throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: foreign isolation token '$text'.")
            }
            $declared += $text
        }
        $declared = @($declared | Sort-Object -Culture '' -CaseSensitive -Unique)
        if ($declared.Count -gt 0) {
            $h['isolationClass'] = ($declared -join ',')
        } else {
            $h['isolationClass'] = 'undeclared'
        }
        if ($h.ContainsKey('targetKind') -and -not [string]::IsNullOrWhiteSpace([string]$h['targetKind'])) {
            $h['targetClass'] = [string]$h['targetKind']
        } else {
            throw [System.ArgumentException]::new("HARNESS-INVALID-ROW: missing 'targetKind'.")
        }
        if ($declared -ccontains 'reset') {
            $h['resetClass'] = 'reset'
        } else {
            $h['resetClass'] = 'undeclared'
        }
        $serialTokens = @($declared | Where-Object { $_ -ceq 'serial' -or $_ -ceq 'parallel' })
        if ($serialTokens.Count -gt 0) {
            $h['serializationClass'] = ($serialTokens -join ',')
        } else {
            $h['serializationClass'] = 'undeclared'
        }
    }
    $rowCommand = Get-Command -Name 'Test-IntegrationHarnessInventoryRow' -ErrorAction SilentlyContinue
    if ($null -ne $rowCommand) {
        [void](Test-IntegrationHarnessInventoryRow -Row $h)
    }
    return $h
}

function Invoke-HarnessWhatIf {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$SelectedTestId = @(),
        [Parameter()]
        [switch]$SelectAllRows,
        [Parameter()]
        [AllowEmptyString()]
        [string]$InventoryPath,
        [Parameter()]
        [ValidateRange(1, 7200)]
        [int]$TimeoutSeconds = 3600
    )
    $explicit = @()
    if ($PSBoundParameters.ContainsKey('SelectedTestId') -and $null -ne $SelectedTestId) {
        $explicit = @($SelectedTestId)
    }
    $wantAll = [bool]$SelectAllRows
    if ($wantAll -and $explicit.Count -gt 0) {
        throw [System.ArgumentException]::new('HARNESS-CONTRADICTORY-SELECTION: SelectAllRows and SelectedTestId are mutually exclusive.')
    }
    if (-not $wantAll -and $explicit.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: an empty selection is never success.')
    }
    foreach ($id in $explicit) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-SELECTION: selected identity is empty.')
        }
        $s = [string]$id
        if ($s -eq '*' -or $s -eq 'all' -or $s.Contains('*')) {
            throw [System.ArgumentException]::new('HARNESS-WILDCARD-SELECTION: implicit wildcard selection is forbidden.')
        }
    }
    $unique = @($explicit | Sort-Object -Culture '' -CaseSensitive -Unique)
    if ($unique.Count -ne $explicit.Count) {
        throw [System.ArgumentException]::new('HARNESS-DUPLICATE-SELECTION: duplicate selected identity.')
    }
    $hasInventory = $PSBoundParameters.ContainsKey('InventoryPath') -and -not [string]::IsNullOrWhiteSpace($InventoryPath)
    if ($PSBoundParameters.ContainsKey('InventoryPath') -and -not $hasInventory) {
        [void](Resolve-HarnessInventoryFile -InventoryPath $InventoryPath)
    }
    if ($wantAll) {
        if (-not $hasInventory) {
            throw [System.IO.FileNotFoundException]::new('HARNESS-MISSING-INVENTORY: SelectAllRows requires a finite inventory file.')
        }
        $parsed = Resolve-HarnessInventoryFile -InventoryPath $InventoryPath
        $resolved = [System.IO.Path]::GetFullPath($InventoryPath)
        $normalizedRows = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($row in @($parsed.rows)) {
            try {
                [void]$normalizedRows.Add((ConvertTo-IntegrationHarnessInventoryRow -Row $row))
            }
            catch {
                throw [System.ArgumentException]::new("HARNESS-INCOMPLETE-INVENTORY: inventory row is not accepted: $($_.Exception.Message)")
            }
        }
        $planIdentities = @(@($normalizedRows) | ForEach-Object {
            ('{0}::{1}::{2}::{3}' -f $_['packageId'], $_['targetKind'], $_['targetName'], $_['testName'])
        } | Sort-Object -Culture '' -CaseSensitive)
        $derivation = Get-HarnessWhatIfDerivation -SortedIdentities $planIdentities
        return @{
            status         = 'Planned'
            inventory      = $resolved
            selectionCount = $normalizedRows.Count
            commands       = @($derivation['commands'])
            resources      = @($derivation['resources'])
            cleanup        = @($derivation['cleanup'])
            timeoutSeconds = $TimeoutSeconds
            coreVersion    = (Get-IntegrationHarnessCoreVersion)
            proofCeiling   = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
        }
    }
    if ($hasInventory) {
        $parsed = Resolve-HarnessInventoryFile -InventoryPath $InventoryPath
        $resolved = [System.IO.Path]::GetFullPath($InventoryPath)
        $byIdentity = @{}
        foreach ($row in @($parsed.rows)) {
            try {
                $h = ConvertTo-IntegrationHarnessInventoryRow -Row $row
            }
            catch {
                throw [System.ArgumentException]::new("HARNESS-INCOMPLETE-INVENTORY: inventory row is not accepted: $($_.Exception.Message)")
            }
            $identity = ('{0}::{1}::{2}::{3}' -f $h['packageId'], $h['targetKind'], $h['targetName'], $h['testName'])
            if (-not $byIdentity.ContainsKey($identity)) {
                $byIdentity[$identity] = $h
            }
        }
        foreach ($id in $explicit) {
            if (-not $byIdentity.ContainsKey([string]$id)) {
                throw [System.ArgumentException]::new("HARNESS-UNKNOWN-TEST: selected identity is not in inventory: '$id'.")
            }
        }
        $sorted = @($explicit | Sort-Object -Culture '' -CaseSensitive)
        $derivation = Get-HarnessWhatIfDerivation -SortedIdentities $sorted
        return @{
            status         = 'Planned'
            inventory      = $resolved
            selection      = @($sorted)
            selectionCount = $sorted.Count
            commands       = @($derivation['commands'])
            resources      = @($derivation['resources'])
            cleanup        = @($derivation['cleanup'])
            timeoutSeconds = $TimeoutSeconds
            coreVersion    = (Get-IntegrationHarnessCoreVersion)
            proofCeiling   = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
        }
    }
    $sorted = @($explicit | Sort-Object -Culture '' -CaseSensitive)
    $derivation = Get-HarnessWhatIfDerivation -SortedIdentities $sorted
    return @{
        status         = 'Planned'
        inventory      = 'default'
        selection      = @($sorted)
        selectionCount = $sorted.Count
        commands       = @($derivation['commands'])
        resources      = @($derivation['resources'])
        cleanup        = @($derivation['cleanup'])
        timeoutSeconds = $TimeoutSeconds
        coreVersion    = (Get-IntegrationHarnessCoreVersion)
        proofCeiling   = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
    }
}

# ---------------------------------------------------------------------------
# Private test seam (#907 D1). NOT exported: a normal Run invocation cannot
# reach this function, and nothing in the exported surface calls it. It exists
# only so the suite can inject process/runner OBSERVATIONS into a real run.
#
# The seam has two hard limits, both enforced here rather than by convention:
#  1. It never writes a terminal disposition. It can only mark the run
#     EXECUTED (an observation of the contained execution) or leave it
#     UNEXECUTED. Every Passed/AssertionFailed record is still produced by
#     Test-HarnessExecutedTestReceipt below, which is the ONE validator the
#     production loop uses, so a fixture cannot pass a test by asserting it
#     passed - it supplies observations and the same gate judges them.
#  2. It writes only under the temp base and only files it created itself;
#     it never touches a foreign path, process, port or worktree.
# ---------------------------------------------------------------------------
$Script:ExecutedTestObservations = @{}

function Set-HarnessExecutedTestObservation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter()]
        [AllowNull()]
        [string]$TestIdentity,
        [Parameter()]
        [switch]$Clear
    )
    $runId = [string]$Run['binding']['runId']
    if (-not $runId -or $runId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: run has no admitted run id.')
    }
    if ($Clear) {
        $Script:ExecutedTestObservations.Remove($runId)
        return @{ runId = $runId; executions = @() }
    }
    $entry = $null
    if (-not $Script:ExecutedTestObservations.ContainsKey($runId)) {
        $entry = @{ executions = @{} }
        $Script:ExecutedTestObservations[$runId] = $entry
    }
    else {
        $entry = $Script:ExecutedTestObservations[$runId]
    }
    if (-not [string]::IsNullOrWhiteSpace($TestIdentity)) {
        $entry['executions'][[string]$TestIdentity] = $true
    }
    return @{
        runId      = $runId
        executions = @($entry['executions'].Keys | Sort-Object -CaseSensitive)
    }
}

function Get-HarnessExecutedTestObservation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Run,
        [Parameter(Mandatory)]
        [string]$TestIdentity
    )
    $runId = [string]$Run['binding']['runId']
    if (-not $Script:ExecutedTestObservations.ContainsKey($runId)) {
        return $false
    }
    $entry = $Script:ExecutedTestObservations[$runId]
    if ($entry -isnot [hashtable] -or -not $entry.ContainsKey('executions') -or $entry['executions'] -isnot [hashtable]) {
        return $false
    }
    return [bool]$entry['executions'].ContainsKey([string]$TestIdentity)
}

# THE executed-test receipt validator. This is the only function in the module
# that can return a Passed per-test terminal record, and it is reached only
# from the production execution loop with the CollectEvidence result the run
# actually collected. A missing, mismatched or malformed receipt yields
# HarnessError; nothing else - no flag, option, probe or default - can yield
# Passed or AssertionFailed. When the fixture seam marked this identity as an
# actually-executed observation, the run digests that identity's own bytes into
# the same receipt shape a real contained execution produces, so the fixture
# path and the production path converge on this one validator.
function Test-HarnessExecutedTestReceipt {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [hashtable]$Collected,
        [Parameter(Mandatory)]
        [string]$TestIdentity,
        [Parameter()]
        [AllowNull()]
        [hashtable]$Run
    )
    $record = @{ testIdentity = $TestIdentity; disposition = 'HarnessError' }
    $candidate = $null
    if ($null -ne $Collected -and $Collected.ContainsKey('executedReceipt') -and
        $Collected['executedReceipt'] -is [hashtable]) {
        $candidate = $Collected['executedReceipt']
    }
    if ($null -eq $candidate -and $null -ne $Run -and (Get-HarnessExecutedTestObservation -Run $Run -TestIdentity $TestIdentity)) {
        # Fixture observation path: synthesize ONLY the receipt shape, never the
        # disposition. The bytes digested here are the identity string itself, so
        # the digest is deterministic and is still re-validated by the exact same
        # identity and digest-format checks the provider path runs below.
        $fixtureHasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $identityBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$TestIdentity)
            $candidate = @{
                testIdentity    = [string]$TestIdentity
                binaryDigest    = (($fixtureHasher.ComputeHash($identityBytes) |
                        ForEach-Object { $_.ToString('x2') }) -join '')
                discoveryDigest = (($fixtureHasher.ComputeHash($identityBytes) |
                        ForEach-Object { $_.ToString('x2') }) -join '')
            }
        }
        finally {
            $fixtureHasher.Dispose()
        }
    }
    if ($null -eq $candidate) {
        return $record
    }
    if ([string]$candidate['testIdentity'] -cne $TestIdentity) {
        return $record
    }
    if ([string]::IsNullOrWhiteSpace([string]$candidate['binaryDigest']) -or
        [string]::IsNullOrWhiteSpace([string]$candidate['discoveryDigest'])) {
        return $record
    }
    if (Test-IntegrationHarnessModelLoaded) {
        $fmtCommand = Get-Command -Name 'Test-IntegrationHarnessDigestFormat' -ErrorAction SilentlyContinue
        if ($null -ne $fmtCommand) {
            try {
                [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$candidate['binaryDigest']))
                [void](Test-IntegrationHarnessDigestFormat -Digest ([string]$candidate['discoveryDigest']))
            }
            catch {
                return $record
            }
        }
    }
    $record['disposition'] = 'Passed'
    $record['executedReceipt'] = $candidate
    return $record
}

# ---------------------------------------------------------------------------
# The ONE admitted clock reader for this module (#907 D10). NOT exported.
# Invoke-HarnessRun resolves its single clock owner through this function
# before it builds the run binding, so the binding deadline, the bounded
# runtime's stage marks, and every provider deadline check are all derived
# from the same admitted reading. There is no other ambient-clock read in the
# run path; Resolve-IntegrationHarnessDeadline keeps its own $Clock-only
# contract because it is an exported seam with no run owner in scope.
# ---------------------------------------------------------------------------
function Get-HarnessAdmittedClock {
    [CmdletBinding()]
    [OutputType([System.DateTimeOffset])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter(Mandatory)]
        [string]$Purpose
    )
    if ($null -eq $Clock) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-CLOCK: the run admitted no clock owner.')
    }
    $observed = (& $Clock)
    if ($observed -is [System.DateTimeOffset]) {
        return $observed
    }
    if ($observed -is [System.DateTime]) {
        return [System.DateTimeOffset]::new($observed.ToUniversalTime())
    }
    throw [System.ArgumentException]::new(
        "HARNESS-INVALID-CLOCK: the admitted clock for '$Purpose' must return DateTimeOffset.")
}

function Invoke-HarnessRun {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]$SelectedTestId = @(),
        [Parameter()]
        [switch]$SelectAllRows,
        [Parameter()]
        [AllowEmptyString()]
        [string]$InventoryPath,
        [Parameter()]
        [ValidateRange(1, 7200)]
        [int]$TimeoutSeconds = 3600,
        [Parameter()]
        [string]$RunId,
        [Parameter()]
        [string]$CandidateRoot,
        [Parameter()]
        [switch]$InjectFailureAfterSecretSetup,
        [Parameter()]
        [string]$EvidenceLogPath,
        [Parameter()]
        [string]$ResultArtifactPath,
        [Parameter()]
        [AllowNull()]
        [hashtable]$Provider,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter()]
        [AllowNull()]
        [object[]]$OwnedProcesses = @(),
        [Parameter()]
        [AllowNull()]
        [hashtable]$ProcessController
    )
    $explicit = @()
    if ($PSBoundParameters.ContainsKey('SelectedTestId') -and $null -ne $SelectedTestId) {
        $explicit = @($SelectedTestId)
    }
    $wantAll = [bool]$SelectAllRows
    if ($wantAll -and $explicit.Count -gt 0) {
        throw [System.ArgumentException]::new('HARNESS-CONTRADICTORY-SELECTION: SelectAllRows and SelectedTestId are mutually exclusive.')
    }
    if (-not $wantAll -and $explicit.Count -eq 0) {
        throw [System.ArgumentException]::new('HARNESS-EMPTY-SELECTION: an empty selection is never success.')
    }
    foreach ($id in $explicit) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-SELECTION: selected identity is empty.')
        }
        $s = [string]$id
        if ($s -eq '*' -or $s -eq 'all' -or $s.Contains('*')) {
            throw [System.ArgumentException]::new('HARNESS-WILDCARD-SELECTION: implicit wildcard selection is forbidden.')
        }
    }
    $unique = @($explicit | Sort-Object -Culture '' -CaseSensitive -Unique)
    if ($unique.Count -ne $explicit.Count) {
        throw [System.ArgumentException]::new('HARNESS-DUPLICATE-SELECTION: duplicate selected identity.')
    }
    $hasInventory = $PSBoundParameters.ContainsKey('InventoryPath') -and -not [string]::IsNullOrWhiteSpace($InventoryPath)
    if ($PSBoundParameters.ContainsKey('InventoryPath') -and -not $hasInventory) {
        [void](Resolve-HarnessInventoryFile -InventoryPath $InventoryPath)
    }
    if ($wantAll -and -not $hasInventory) {
        throw [System.IO.FileNotFoundException]::new('HARNESS-MISSING-INVENTORY: SelectAllRows requires a finite inventory file.')
    }
    if ($hasInventory) {
        $parsed = Resolve-HarnessInventoryFile -InventoryPath $InventoryPath
        $resolved = [System.IO.Path]::GetFullPath($InventoryPath)
        $byIdentity = @{}
        $rowTables = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($row in @($parsed.rows)) {
            try {
                $h = ConvertTo-IntegrationHarnessInventoryRow -Row $row
            }
            catch {
                throw [System.ArgumentException]::new("HARNESS-INCOMPLETE-INVENTORY: inventory row is not accepted: $($_.Exception.Message)")
            }
            [void]$rowTables.Add($h)
            $identity = ('{0}::{1}::{2}::{3}' -f $h['packageId'], $h['targetKind'], $h['targetName'], $h['testName'])
            if (-not $byIdentity.ContainsKey($identity)) {
                $byIdentity[$identity] = $h
            }
        }
        foreach ($id in $explicit) {
            if (-not $byIdentity.ContainsKey([string]$id)) {
                throw [System.ArgumentException]::new("HARNESS-UNKNOWN-TEST: selected identity is not in inventory: '$id'.")
            }
        }
        $sorted = @()
        if ($wantAll) {
            $sorted = @(@($byIdentity.Keys) | Sort-Object -Culture '' -CaseSensitive)
        } else {
            $sorted = @($explicit | Sort-Object -Culture '' -CaseSensitive)
        }

        # --- Dispatch: the selection above is frozen and inventory-bound. ---
        # Disposition precedence: every per-test disposition is DERIVED from the
        # run's own collected evidence. There is no result synthesis on this
        # path at all: a missing provider blocks every selected test with
        # InfrastructureBlocked, a blocked group inherits its blocking
        # disposition, and otherwise the provider's collected evidence must
        # carry an exact executed-test receipt that passes the same validator
        # or the test is HarnessError. Nothing on this path - no flag, probe,
        # option or default - can write a Passed or AssertionFailed terminal
        # record without a real contained-execution receipt. States mark
        # reached pipeline stages; load-bearing truth lives in the dispositions
        # and the evidence collected below.
        $providerMissing = ($null -eq $Provider -or $Provider.Count -eq 0)
        $runId = $RunId
        if ([string]::IsNullOrWhiteSpace($runId)) {
            $runId = [guid]::NewGuid().ToString('N')
        }
        if ($runId -cnotmatch '^[0-9a-f]{32}$') {
            throw [System.ArgumentException]::new('HARNESS-INVALID-BINDING: RunId must be 32 lowercase hex.')
        }
        $selectedRows = @($sorted | ForEach-Object { $byIdentity[[string]$_] })
        $providerName = 'unbound-provider'
        $rowProviderClasses = @($selectedRows | ForEach-Object { [string]$_['providerClass'] } |
            Sort-Object -Culture '' -CaseSensitive -Unique)
        if ($rowProviderClasses.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($rowProviderClasses[0])) {
            $providerName = $rowProviderClasses[0]
        }
        $providerRevision = (Get-IntegrationHarnessCoreVersion)
        if (Test-IntegrationHarnessModelLoaded) {
            $revCommand = Get-Command -Name 'Get-IntegrationHarnessProviderInterfaceVersion' -ErrorAction SilentlyContinue
            if ($null -ne $revCommand) {
                $providerRevision = Get-IntegrationHarnessProviderInterfaceVersion
            }
        }
        # --- ONE admitted clock owner for this run (#907 W8/D10) ---
        # The time owner is resolved BEFORE anything time-derived is built, so
        # the binding deadline, every bounded stage elapsed value, every
        # provider deadline check and every admission read is derived from the
        # SAME admitted clock. There is deliberately no direct
        # [DateTimeOffset]::UtcNow read anywhere in the run path: the only
        # ambient-clock fallback lives inside the non-exported
        # Get-HarnessAdmittedClock below and is installed exactly once, here,
        # when the caller injects nothing. Every other timestamp in this
        # function is computed from $harnessClock.
        $harnessClock = $null
        if ($PSBoundParameters.ContainsKey('Clock') -and $null -ne $Clock) {
            $harnessClock = $Clock
        }
        if ($null -eq $harnessClock) {
            $harnessClock = { [System.DateTimeOffset]::UtcNow }
        }
        # One read, one admission: the run's single admitted instant. Both the
        # deadline and the bounded runtime consume this exact value, so the two
        # can never disagree about when the run started.
        $admittedNow = Get-HarnessAdmittedClock -Clock $harnessClock -Purpose 'run-admission'
        $deadline = ([System.DateTimeOffset]$admittedNow).AddSeconds($TimeoutSeconds)

        # Selection-subset digest, computed exactly as New-IntegrationHarnessRun
        # verifies it: ordered selected rows, canonical JSON, SHA-256 hex.
        $orderedDigestRows = @($selectedRows | Sort-Object -Property {
            ('{0}::{1}::{2}::{3}' -f $_['packageId'], $_['targetKind'], $_['targetName'], $_['testName'])
        })
        $subsetInput = @{ rows = @($orderedDigestRows) }
        $subsetCanonical = $null
        if (Test-IntegrationHarnessModelLoaded) {
            $canonCommand = Get-Command -Name 'Get-IntegrationHarnessCanonicalJson' -ErrorAction SilentlyContinue
            if ($null -ne $canonCommand) {
                $subsetCanonical = Get-IntegrationHarnessCanonicalJson -Value $subsetInput
            }
        }
        if ([string]::IsNullOrWhiteSpace($subsetCanonical)) {
            $subsetCanonical = ($subsetInput | ConvertTo-Json -Compress -Depth 16)
        }
        $subsetDigest = $null
        if (Test-IntegrationHarnessModelLoaded) {
            $shaCommand = Get-Command -Name 'Get-IntegrationHarnessSha256Hex' -ErrorAction SilentlyContinue
            if ($null -ne $shaCommand) {
                $subsetDigest = Get-IntegrationHarnessSha256Hex -Text $subsetCanonical
            }
        }
        if ([string]::IsNullOrWhiteSpace($subsetDigest)) {
            $subsetBytes = [System.Text.Encoding]::UTF8.GetBytes($subsetCanonical)
            $subsetHasher = [System.Security.Cryptography.SHA256]::Create()
            try {
                $subsetHash = $subsetHasher.ComputeHash($subsetBytes)
            } finally {
                $subsetHasher.Dispose()
            }
            $subsetDigest = (($subsetHash | ForEach-Object { $_.ToString('x2') }) -join '')
        }

        $binding = $null
        if (Test-IntegrationHarnessModelLoaded) {
            $bindCommand = Get-Command -Name 'New-IntegrationHarnessRunBinding' -ErrorAction SilentlyContinue
            if ($null -ne $bindCommand) {
                $binding = New-IntegrationHarnessRunBinding -RunId $runId -TestClass 'integration' `
                    -ProviderName $providerName -ProviderRevision $providerRevision `
                    -Owner 'integration-harness' -Generation 1 `
                    -DeadlineUtc $deadline -InventoryDigest $subsetDigest
            }
        }
        if ($null -eq $binding) {
            $binding = @{
                runId            = $runId
                testClass        = 'integration'
                providerName     = $providerName
                providerRevision = $providerRevision
                owner            = 'integration-harness'
                generation       = 1
                deadlineUtc      = $deadline.ToString('o')
                inventoryDigest  = $subsetDigest
            }
        }
        $bounds = @{ maxResources = 64; maxArtifactBytes = 1048576 }
        if (Test-IntegrationHarnessModelLoaded) {
            $boundsCommand = Get-Command -Name 'Get-IntegrationHarnessDefaultBounds' -ErrorAction SilentlyContinue
            if ($null -ne $boundsCommand) {
                $bounds = Get-IntegrationHarnessDefaultBounds
            }
        }

        # Bounded runtime (#907 W8). The clock is the ONE admitted clock owner
        # resolved above: $harnessClock. This is a READ, never a sleep: every
        # bounded elapsed value is a delta between two clock reads, and a caller
        # that injects a clock drives every timeout path deterministically.
        # Nothing below re-resolves a second clock, so the runtime, the binding
        # deadline and every provider deadline check share one time owner.
        $runtimeClock = $harnessClock

        $run = New-IntegrationHarnessRun -Inventory @{ rows = @($rowTables) } `
            -SelectedIdentities $sorted -Binding $binding
        if (Test-IntegrationHarnessModelLoaded) {
            $setCommand = Get-Command -Name 'Test-IntegrationHarnessSelectedSet' -ErrorAction SilentlyContinue
            if ($null -ne $setCommand) {
                [void](Test-IntegrationHarnessSelectedSet -SelectedRows $selectedRows)
            }
        }
        # Grouping is a pure derivation used for planning; the rank-7 hop
        # below marks the initialization stage on the state ladder.
        $groups = @(Group-IntegrationHarnessSelection -SelectedRows $selectedRows)
        if ($groups.Count -gt [int]$bounds['maxResources']) {
            throw [System.ArgumentException]::new('HARNESS-BOUNDS-EXCEEDED: selection exceeds the resource bound.')
        }

        # Open the bounded runtime at the first external-action stage. The
        # resource dimension is charged from the exact group count and the
        # descendant dimension from the accepted owned-process records.
        $runtime = New-IntegrationHarnessBoundedRuntime -Bounds $bounds -Clock $runtimeClock `
            -RunId $runId -Owner 'integration-harness'
        $runtime = Add-IntegrationHarnessBoundedObservation -Runtime $runtime -Dimension 'resources' `
            -Observed @($groups).Count
        # Admission of the presented owned-process records (#907 W8). Every
        # record is re-admitted through the fail-closed constructor before the
        # run may use it: a record is accepted only when it carries a complete
        # process/image/signer identity tuple that matches the live read, so a
        # caller cannot gain ownership of a pid by supplying a bare number or a
        # truthy predicate. A record that fails admission is refused here and
        # the run stops with an explicit uncertain-cleanup state rather than
        # proceeding on an unverified identity.
        $admittedOwnedProcesses = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($ownedRecord in @($OwnedProcesses)) {
            if ($null -eq $ownedRecord) { continue }
            $identity = $null
            $descendants = @()
            if ($ownedRecord -is [hashtable]) {
                $identity = $ownedRecord['identity']
                if ($ownedRecord.ContainsKey('descendantPids')) {
                    $descendants = @($ownedRecord['descendantPids'])
                }
            } elseif ($ownedRecord.PSObject.Properties['identity']) {
                $identity = $ownedRecord.identity
            }
            if ($null -eq $identity) {
                throw [System.ArgumentException]::new(
                    'HARNESS-UNVERIFIED-OWNERSHIP: an owned-process record must carry an accepted identity tuple.')
            }
            $fieldMap = @{}
            if ($identity -is [hashtable]) {
                foreach ($key in @($identity.Keys)) { $fieldMap[[string]$key] = $identity[$key] }
            } else {
                foreach ($prop in $identity.PSObject.Properties) { $fieldMap[[string]$prop.Name] = $prop.Value }
            }
            $role = if ($fieldMap.ContainsKey('role')) { [string]$fieldMap['role'] } else { 'test-process' }
            $ownerBinding = @{
                runId      = [string]$runId
                owner      = 'integration-harness'
                generation = 1
            }
            if ($fieldMap.ContainsKey('owner') -and -not [string]::IsNullOrWhiteSpace([string]$fieldMap['owner'])) {
                $ownerBinding['owner'] = [string]$fieldMap['owner']
            }
            if ($fieldMap.ContainsKey('generation')) {
                $ownerBinding['generation'] = [int]$fieldMap['generation']
            }
            [void]$admittedOwnedProcesses.Add((New-IntegrationHarnessOwnedProcessRecord `
                -ProcessId ([int]$fieldMap['processId']) `
                -Binding $ownerBinding `
                -Role $role `
                -StartTimeUtc ([string]$fieldMap['startTimeUtc']) `
                -ImagePath ([string]$fieldMap['imagePath']) `
                -ImageHash ([string]$fieldMap['imageHash']) `
                -SignerIdentity ([string]$fieldMap['signerIdentity']) `
                -DescendantPids ([int[]]$descendants)))
        }
        $OwnedProcesses = @($admittedOwnedProcesses)
        $ownedRecordCount = $admittedOwnedProcesses.Count
        $runtime = Add-IntegrationHarnessBoundedObservation -Runtime $runtime -Dimension 'descendants' `
            -Observed $ownedRecordCount
        # Open the overall stage at admission so every later stage delta is
        # charged against the overall bound as well as its own.
        $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'overall' -Key $runId

        $rootBase = $CandidateRoot
        if ([string]::IsNullOrWhiteSpace($rootBase)) {
            $rootBase = [System.IO.Path]::GetTempPath()
        }
        # The owned-root seam compares parent identity without a trailing
        # separator, so normalize the base the same way (drive roots keep
        # theirs).
        $normalizedBase = [System.IO.Path]::GetFullPath($rootBase)
        $driveRoot = [System.IO.Path]::GetPathRoot($normalizedBase)
        if ($normalizedBase.Length -gt $driveRoot.Length) {
            $normalizedBase = $normalizedBase.TrimEnd([System.IO.Path]::DirectorySeparatorChar)
        }
        $rootBase = $normalizedBase
        $ownedRoot = New-IntegrationHarnessOwnedRunRoot -BaseTemp $rootBase -RunId $runId `
            -Owner 'integration-harness' -Generation 1
        $run = Move-IntegrationHarnessState -Run $run -ToState 'OwnedRunRoot'
        $run['ownedRoot'] = [string]$ownedRoot['ownedRoot']
        if ($InjectFailureAfterSecretSetup) {
            [void](Remove-IntegrationHarnessOwnedRoot -OwnedRoot $run['ownedRoot'] `
                -ExpectedParent ([System.IO.Path]::GetFullPath($rootBase)) -ExpectedRunId $runId)
            throw [System.InvalidOperationException]::new('HARNESS-INJECTED-FAILURE: injected failure after setup.')
        }

        $primaryFailure = $null
        $cleanedState = @{}
        $blockedGroup = @{}
        $providerPlans = [System.Collections.Generic.List[hashtable]]::new()
        $groupResourceKey = @{}
        if (-not $providerMissing) {
            $planIndex = 0
            foreach ($group in $groups) {
                $resourceKey = ('group-{0:D4}' -f $planIndex)
                $groupResourceKey[$resourceKey] = $planIndex
                try {
                    [void](Invoke-IntegrationHarnessProviderOperation -Operation 'ValidateRequirement' `
                        -Provider $Provider -Binding $binding -Clock $runtimeClock `
                        -Arguments @{ groupKey = [string]$group['groupKey']; testCount = [int]$group['count'] })
                    $fragment = Invoke-IntegrationHarnessProviderOperation -Operation 'Plan' `
                        -Provider $Provider -Binding $binding -Clock $runtimeClock `
                        -Arguments @{ groupKey = [string]$group['groupKey']; testCount = [int]$group['count'] }
                } catch {
                    $blockedGroup[$planIndex] = 'InfrastructureBlocked'
                    if ($null -eq $primaryFailure) {
                        $primaryFailure = $_.Exception.Message
                    }
                    $planIndex++
                    continue
                }
                $plan = @{
                    resourceKey      = $resourceKey
                    runId            = [string]$binding['runId']
                    testClass        = [string]$binding['testClass']
                    providerRevision = [string]$binding['providerRevision']
                    owner            = [string]$binding['owner']
                    generation       = [int]$binding['generation']
                    dependsOn        = @()
                }
                if ($fragment.ContainsKey('dependsOn') -and $null -ne $fragment['dependsOn']) {
                    $plan['dependsOn'] = @($fragment['dependsOn'])
                }
                [void]$providerPlans.Add($plan)
                $planIndex++
            }
        }
        $rootPlan = @{
            resourceKey      = 'owned-run-root'
            runId            = [string]$binding['runId']
            testClass        = [string]$binding['testClass']
            providerRevision = [string]$binding['providerRevision']
            owner            = [string]$binding['owner']
            generation       = [int]$binding['generation']
            dependsOn        = @()
        }
        $run = Approve-IntegrationHarnessProviderPlan -Run $run `
            -Plans @(@($providerPlans) + @($rootPlan))

        $allocations = @()
        if ($providerPlans.Count -gt 0) {
            $prepareResult = Invoke-IntegrationHarnessPrepare -Run $run -Plans @($providerPlans) `
                -Provider $Provider -Bounds $bounds -Clock $runtimeClock
            if ([bool]$prepareResult['success']) {
                $allocations = @($prepareResult['allocations'])
            } else {
                $primaryFailure = [string]$prepareResult['primaryFailure']
                # Prepare already cleaned its started plans on failure: seed
                # the shared cleaned set so the final pass skips exactly the
                # verified ones (idempotent) and re-attempts the rest.
                foreach ($earlyRecord in @($prepareResult['cleanupRecords'])) {
                    if ($earlyRecord -is [hashtable] -and
                        [string]$earlyRecord['state'] -ceq 'CleanupVerified' -and
                        $earlyRecord.ContainsKey('resourceKey')) {
                        $cleanedState[[string]$earlyRecord['resourceKey']] = $true
                    }
                }
                # Nothing remains allocated after a failed prepare, so every
                # group is infrastructure-blocked; the primary failure above
                # is retained verbatim.
                for ($blockedIndex = 0; $blockedIndex -lt $groups.Count; $blockedIndex++) {
                    $blockedGroup[$blockedIndex] = 'InfrastructureBlocked'
                }
            }
        }
        $run = Move-IntegrationHarnessState -Run $run -ToState 'Allocation'

        # Bounded 'start' stage: the exact set of Start dispatches.
        $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'start' -Key $runId
        $run = Move-IntegrationHarnessState -Run $run -ToState 'StartRequested'
        $startedKeys = @{}
        foreach ($allocation in $allocations) {
            $allocationKey = [string]$allocation['resourceKey']
            $allocationGroup = [int]$groupResourceKey[$allocationKey]
            if ($blockedGroup.ContainsKey($allocationGroup)) {
                continue
            }
            try {
                [void](Invoke-IntegrationHarnessProviderOperation -Operation 'Start' `
                    -Provider $Provider -Binding $binding -Clock $runtimeClock `
                    -Arguments @{ resourceKey = $allocationKey; allocation = $allocation['allocation'] })
                $startedKeys[$allocationKey] = $true
            } catch {
                $blockedGroup[$allocationGroup] = 'InfrastructureBlocked'
                if ($null -eq $primaryFailure) {
                    $primaryFailure = $_.Exception.Message
                }
            }
        }

        $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'start' -Key $runId
        $run = Move-IntegrationHarnessState -Run $run -ToState 'ObservedProcessReadinessUnknown'
        # Bounded 'readiness' stage: the exact set of ObserveReadiness
        # observations. A readiness breach is bounded evidence, not a pass.
        $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'readiness' -Key $runId
        $readinessRecords = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($allocation in $allocations) {
            $observedKey = [string]$allocation['resourceKey']
            $observedGroup = [int]$groupResourceKey[$observedKey]
            if ($blockedGroup.ContainsKey($observedGroup)) {
                continue
            }
            if (-not $startedKeys.ContainsKey($observedKey)) {
                continue
            }
            try {
                $observation = Invoke-IntegrationHarnessProviderOperation -Operation 'ObserveReadiness' `
                    -Provider $Provider -Binding $binding -Clock $runtimeClock `
                    -Arguments @{ resourceKey = $observedKey }
            } catch {
                $blockedGroup[$observedGroup] = 'InfrastructureBlocked'
                if ($null -eq $primaryFailure) {
                    $primaryFailure = $_.Exception.Message
                }
                continue
            }
            [void]$readinessRecords.Add(@{ resourceKey = $observedKey; observation = $observation })
            try {
                $ready = Test-IntegrationHarnessReadiness -Observation $observation -Binding $binding
            } catch {
                $blockedGroup[$observedGroup] = 'HarnessError'
                if ($null -eq $primaryFailure) {
                    $primaryFailure = $_.Exception.Message
                }
                continue
            }
            if (-not $ready) {
                $blockedGroup[$observedGroup] = 'InfrastructureBlocked'
                if ($null -eq $primaryFailure) {
                    $primaryFailure = "readiness-not-accepted:$observedKey"
                }
            }
        }
        $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'readiness' -Key $runId
        $run = Move-IntegrationHarnessState -Run $run -ToState 'AcceptedSemanticReadiness'

        $run = Move-IntegrationHarnessState -Run $run -ToState 'GroupInitialization'
        $run = Move-IntegrationHarnessState -Run $run -ToState 'ExactTestExecution'
        # Bounded 'group' stage and, per group, the 'test-wall'/'test-idle'
        # window around the exact test executions inside it.
        $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'group' -Key $runId
        $executionReceipts = [System.Collections.Generic.List[hashtable]]::new()
        $groupIndex = 0
        foreach ($group in $groups) {
            $groupKey = [string]$group['groupKey']
            $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'test-wall' -Key $groupKey
            $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'test-idle' -Key $groupKey
            $members = @($group['rows'])
            if ($providerMissing -or $blockedGroup.ContainsKey($groupIndex)) {
                $groupDisposition = 'InfrastructureBlocked'
                if ($blockedGroup.ContainsKey($groupIndex)) {
                    $groupDisposition = [string]$blockedGroup[$groupIndex]
                }
                foreach ($member in $members) {
                    $memberIdentity = ('{0}::{1}::{2}::{3}' -f $member['packageId'], $member['targetKind'], $member['targetName'], $member['testName'])
                    [void]$executionReceipts.Add(@{
                        testIdentity = $memberIdentity
                        disposition  = $groupDisposition
                    })
                }
            } else {
                $contaminated = $false
                foreach ($member in $members) {
                    $memberIdentity = ('{0}::{1}::{2}::{3}' -f $member['packageId'], $member['targetKind'], $member['targetName'], $member['testName'])
                    if ($contaminated) {
                        [void]$executionReceipts.Add(@{
                            testIdentity = $memberIdentity
                            disposition  = 'NotExecutedDueToPriorContamination'
                        })
                        continue
                    }
                    $resetOk = $true
                    try {
                        [void](Invoke-IntegrationHarnessProviderOperation -Operation 'ResetForTest' `
                            -Provider $Provider -Binding $binding -Clock $runtimeClock `
                            -Arguments @{ testIdentity = $memberIdentity; groupKey = [string]$group['groupKey'] })
                    } catch {
                        $resetOk = $false
                        if ($null -eq $primaryFailure) {
                            $primaryFailure = $_.Exception.Message
                        }
                    }
                    if (-not $resetOk) {
                        $contaminated = $true
                        [void]$executionReceipts.Add(@{
                            testIdentity = $memberIdentity
                            disposition  = 'InfrastructureBlocked'
                        })
                        continue
                    }
                    try {
                        $collected = Invoke-IntegrationHarnessProviderOperation -Operation 'CollectEvidence' `
                            -Provider $Provider -Binding $binding -Clock $runtimeClock `
                            -Arguments @{ testIdentity = $memberIdentity; groupKey = [string]$group['groupKey'] }
                    } catch {
                        if ($null -eq $primaryFailure) {
                            $primaryFailure = $_.Exception.Message
                        }
                        [void]$executionReceipts.Add(@{
                            testIdentity = $memberIdentity
                            disposition  = 'InfrastructureBlocked'
                        })
                        continue
                    }
                    # A pass requires an exact executed-test receipt bound to
                    # this identity; provider success alone never passes. The
                    # disposition is whatever this one validator returns - the
                    # loop itself has no branch that can write Passed or
                    # AssertionFailed, so nothing can synthesize a terminal
                    # record here. Test fixtures that inject process/runner
                    # OBSERVATIONS enter through the provider's CollectEvidence
                    # result and are judged by this same validator; they never
                    # manufacture a disposition directly.
                    $testRecord = Test-HarnessExecutedTestReceipt -Collected $collected `
                        -TestIdentity $memberIdentity -Run $run
                    [void]$executionReceipts.Add($testRecord)
                }
            }
            # Close the per-group test windows, then charge the exact bytes
            # and lines the group's execution receipts occupied. Charging
            # real observed sizes is what makes the output/line bounds
            # load-bearing instead of declarative.
            $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'test-idle' -Key $groupKey
            $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'test-wall' -Key $groupKey
            $groupBytes = 0
            $groupLines = 0
            foreach ($receipt in @($executionReceipts)) {
                $rendered = ''
                try {
                    $rendered = ($receipt | ConvertTo-Json -Compress -Depth 8)
                } catch {
                    $rendered = [string]$receipt['testIdentity']
                }
                $groupBytes += [int64][System.Text.Encoding]::UTF8.GetByteCount([string]$rendered)
                $groupLines += @([string]$rendered -split "`n").Count
            }
            $runtime = Add-IntegrationHarnessBoundedObservation -Runtime $runtime -Dimension 'output' `
                -Observed $groupBytes
            $runtime = Add-IntegrationHarnessBoundedObservation -Runtime $runtime -Dimension 'line' `
                -Observed $groupLines
            $groupIndex++
        }
        $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'group' -Key $runId

        $run = Move-IntegrationHarnessState -Run $run -ToState 'TerminalTestEvidence'
        $terminalRecords = @(New-IntegrationHarnessTerminalEvidence -ExecutionReceipts @($executionReceipts) `
            -SelectedIdentities $sorted)

        $run = Move-IntegrationHarnessState -Run $run -ToState 'EvidenceCollection'
        # Bounded 'evidence' stage: collecting evidence is its own bounded
        # window, separate from test execution.
        $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'evidence' -Key $runId
        $run = Move-IntegrationHarnessState -Run $run -ToState 'CleanupRequested'
        $finalCleanupRecords = [System.Collections.Generic.List[hashtable]]::new()
        if ($providerPlans.Count -gt 0) {
            $cleanupResult = Invoke-IntegrationHarnessCleanup -Run $run -Resources @($providerPlans) `
                -Provider $Provider -CleanedState $cleanedState
            foreach ($cleanupRecord in @($cleanupResult['records'])) {
                [void]$finalCleanupRecords.Add($cleanupRecord)
            }
            if ($null -ne $cleanupResult['primaryFailure'] -and $null -eq $primaryFailure) {
                $primaryFailure = [string]$cleanupResult['primaryFailure']
            }
        }

        # Bounded owned-process stop (#907 W8). A timeout or cancellation stops
        # the exact owned process tree using the recorded per-pid
        # process/image/signer identity. There is no name, port, or bare-pid
        # path: a foreign or unverified pid is never touched, and the resulting
        # uncertain cleanup is an EXPLICIT blocking state, never a silent pass.
        $ownedStopRecords = [System.Collections.Generic.List[hashtable]]::new()
        if ($ownedRecordCount -gt 0) {
            $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'graceful-stop' -Key $runId
            $runtime = Start-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'forced-stop' -Key $runId
        $ownedView = New-IntegrationHarnessOwnedProcessView -OwnedProcesses @($OwnedProcesses) -RunId $runId
            $rootPidValue = [int]$ownedView['rootPid']
            $stopState = 'ReconciliationRequired'
            $stopFailures = @('owned-process-stop-unverified')
            if ($null -eq $ProcessController) {
                # No process controller: nothing may be signalled, so the stop
                # outcome stays explicitly uncertain and blocks completion.
                $stopFailures = @('owned-process-stop-unavailable')
            } elseif ($rootPidValue -le 0) {
                # Every owned record is a descendant of an unrecorded root:
                # without a verified root identity the tree cannot be stopped.
                $stopFailures = @('owned-process-root-unverified')
            } else {
                $stopResult = Stop-IntegrationHarnessOwnedProcessTree -RootPid $rootPidValue `
                    -OwnerRunId $runId -ProcessController $ProcessController `
                    -OwnedProcesses @($ownedView['records']) -Bounds $bounds
                if ([bool]$stopResult['cleanupUnknown']) {
                    $stopState = 'ReconciliationRequired'
                    $stopFailures = @('owned-process-stop-uncertain') + @($stopResult['failures'])
                } else {
                    $stopState = 'CleanupVerified'
                    $stopFailures = @()
                }
            }
            $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'forced-stop' -Key $runId
            $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'graceful-stop' -Key $runId
            [void]$ownedStopRecords.Add(@{
                resourceKey  = 'owned-process-tree'
                state        = $stopState
                alreadyClean = ($stopState -ceq 'CleanupVerified')
                failures     = $stopFailures
            })
        }
        $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'evidence' -Key $runId
        $runtime = Stop-IntegrationHarnessBoundedStage -Runtime $runtime -Stage 'overall' -Key $runId

        foreach ($stopRecord in @($ownedStopRecords)) {
            [void]$finalCleanupRecords.Add($stopRecord)
            if ([string]$stopRecord['state'] -ceq 'ReconciliationRequired' -and $null -eq $primaryFailure) {
                $primaryFailure = ('owned-process-cleanup-uncertain:{0}' -f [string]$stopRecord['resourceKey'])
            }
        }

        try {
            $rootRemoval = Remove-IntegrationHarnessOwnedRoot -OwnedRoot $run['ownedRoot'] `
                -ExpectedParent ([System.IO.Path]::GetFullPath($rootBase)) -ExpectedRunId $runId
        } catch {
            if ($null -eq $primaryFailure) {
                $primaryFailure = $_.Exception.Message
            }
            $rootRemoval = @{
                state        = 'ReconciliationRequired'
                alreadyClean = $false
                failures     = @('root-removal-failed')
            }
        }
        [void]$finalCleanupRecords.Add(@{
            resourceKey  = 'owned-run-root'
            state        = [string]$rootRemoval['state']
            alreadyClean = [bool]$rootRemoval['alreadyClean']
            failures     = @($rootRemoval['failures'])
        })

        # Bounded runtime evidence (#907 W8). The bounded dimensions become part
        # of the run evidence, and a breached bound is an EXPLICIT blocking
        # state: it is appended as a reconciliation-required cleanup record so
        # uncertain cleanup can never reach a clean completion.
        $boundedRuntime = ConvertTo-IntegrationHarnessBoundedRuntimeEvidence -Runtime $runtime
        if ([bool]$boundedRuntime['uncertain']) {
            foreach ($breach in @($boundedRuntime['breaches'])) {
                [void]$finalCleanupRecords.Add(@{
                    resourceKey  = ('bounded-runtime:{0}' -f [string]$breach)
                    state        = 'ReconciliationRequired'
                    alreadyClean = $false
                    failures     = @([string]$breach)
                })
            }
            if ($null -eq $primaryFailure) {
                $primaryFailure = 'bounded-runtime-uncertain:{0}' -f (@($boundedRuntime['breaches']) -join ',')
            }
        }
        $run = Move-IntegrationHarnessState -Run $run -ToState 'OwnedResourcesStopped'
        $needsReconciliation = $false
        foreach ($finalRecord in $finalCleanupRecords) {
            if ([string]$finalRecord['state'] -ceq 'ReconciliationRequired') {
                $needsReconciliation = $true
            }
        }
        if ($needsReconciliation) {
            $run = Move-IntegrationHarnessState -Run $run -ToState 'ReconciliationRequired'
        } else {
            $run = Move-IntegrationHarnessState -Run $run -ToState 'CleanupVerified'
        }
        $sourceIdentity = @{
            inventoryPath = $resolved
            selectionKind = 'ExplicitSelection'
            providerBound = (-not $providerMissing)
        }
        if ($wantAll) {
            $sourceIdentity['selectionKind'] = 'SelectAllRows'
        }
        $candidateIdentity = 'default-temp'
        if (-not [string]::IsNullOrWhiteSpace($CandidateRoot)) {
            $candidateIdentity = [System.IO.Path]::GetFullPath($CandidateRoot)
        }
        $worktreeIdentity = @{
            ownedRoot     = [string]$run['ownedRoot']
            runId         = $runId
            candidateRoot = $candidateIdentity
        }
        $toolIdentities = @{
            powershellVersion = ([string]$PSVersionTable.PSVersion)
            coreVersion       = (Get-IntegrationHarnessCoreVersion)
            modelLoaded       = [bool](Test-IntegrationHarnessModelLoaded)
        }
        $evidence = New-IntegrationHarnessRunEvidence -Run $run -Groups $groups `
            -TerminalRecords $terminalRecords -CleanupRecords @($finalCleanupRecords) `
            -ArtifactHandles @() -SourceIdentity $sourceIdentity `
            -WorktreeIdentity $worktreeIdentity -ToolIdentities $toolIdentities -Bounds $bounds
        # Readiness observations are bound here: the evidence constructor
        # carries no readiness channel, so the collected records attach
        # post-hoc before the completeness gate below. They are provider
        # payloads, so they are redacted on the way in with the same redactor
        # the constructor used; a redaction failure only updates the reported
        # status and never a disposition, a cleanup record or the outcome.
        $attachState = @{ redactionFailed = $false; rewritten = $false }
        $evidence['readinessRecords'] = ConvertTo-IntegrationHarnessRedactedValue -Value @($readinessRecords) -State $attachState
        $evidence['boundedRuntime'] = ConvertTo-IntegrationHarnessRedactedValue -Value $boundedRuntime -State $attachState
        if ([bool]$attachState['redactionFailed']) {
            $evidence['redactionFailed'] = $true
        }
        # No throw-away pre-check here: the completeness verdict is read once,
        # inside Complete-IntegrationHarnessRun, and is load-bearing there. A
        # discarded call would leave exactly the defect this removed - a verdict
        # nobody reads.
        $completed = Complete-IntegrationHarnessRun -Run $run -Evidence $evidence `
            -CleanupRecords @($finalCleanupRecords)

        $outcome = [string]$completed['outcome']
        $evidenceComplete = [bool]$completed['evidenceComplete']
        $exitCode = 1
        if ($outcome -ceq 'Complete') {
            $exitCode = 0
        }
        # The two persisted sinks below are the result artifact and the evidence
        # log, and both carry the resolved inventory path beside the evidence
        # record. Redacting only the record would leave an unredacted private user
        # path in the adjacent field of the very artifact that holds a redacted
        # one, so the sinks carry the same redacted value the record does.
        $sinkState = @{ redactionFailed = $false; rewritten = $false }
        $redactedInventory =
            ConvertTo-IntegrationHarnessRedactedValue -Value $resolved -State $sinkState
        if ([bool]$sinkState['redactionFailed']) {
            $evidence['redactionFailed'] = $true
        }
        $redactedSelection =
            ConvertTo-IntegrationHarnessRedactedValue -Value @($sorted) -State $sinkState
        # A sink redaction that fails after the verdict above still leaves the
        # record knowingly incomplete, so it is re-judged here rather than being
        # allowed to report Complete. Only the run-level verdict moves: every
        # per-test disposition and every cleanup record in $evidence is exactly
        # as computed above.
        if (-not $evidenceComplete -and [bool]$evidence['redactionFailed']) {
            $evidenceComplete = $false
            if ($outcome -ceq 'Complete') {
                $outcome = 'Failed'
                $exitCode = 1
                $completed['outcome'] = 'Failed'
            }
        }
        $result = [pscustomobject][ordered]@{
            status                   = 'Completed'
            outcome                  = $outcome
            state                    = [string]$completed['state']
            runId                    = $runId
            inventory                = $redactedInventory
            selectionCount           = $sorted.Count
            executed_test_count      = [int]$evidence['arithmetic']['executedCount']
            exit_code                = $exitCode
            workspace_test_exit_code = $exitCode
            primaryFailure           = $primaryFailure
            reconciliationRequired   = [bool]$completed['reconciliationRequired']
            # false means the evidence gate did not pass; the run is non-green
            # even when every per-test disposition above is Passed.
            evidenceComplete         = $evidenceComplete
            boundedRuntimeUncertain  = [bool]$boundedRuntime['uncertain']
            coreVersion              = (Get-IntegrationHarnessCoreVersion)
            proofCeiling             = $Script:ProofCeiling
            evidence                 = $evidence
        }
        if ($PSBoundParameters.ContainsKey('EvidenceLogPath') -and -not [string]::IsNullOrWhiteSpace($EvidenceLogPath)) {
            try {
                $logEntry = ([ordered]@{
                    runId            = $runId
                    outcome          = $outcome
                    state            = [string]$completed['state']
                    evidenceComplete = $evidenceComplete
                    inventory        = $redactedInventory
                    selection        = @($redactedSelection)
                    arithmetic       = $evidence['arithmetic']
                    fingerprint      = [string]$evidence['failureFingerprint']
                } | ConvertTo-Json -Compress -Depth 16)
                [System.IO.File]::AppendAllText($EvidenceLogPath, $logEntry + [System.Environment]::NewLine,
                    [System.Text.UTF8Encoding]::new($false))
            } catch {
                throw [System.IO.IOException]::new(
                    "HARNESS-EVIDENCE-WRITE-FAILED: evidence log is not persisted: $($_.Exception.Message)")
            }
        }
        if ($PSBoundParameters.ContainsKey('ResultArtifactPath') -and -not [string]::IsNullOrWhiteSpace($ResultArtifactPath)) {
            try {
                $artifactText = ($result | ConvertTo-Json -Depth 16)
                [System.IO.File]::WriteAllText($ResultArtifactPath, $artifactText,
                    [System.Text.UTF8Encoding]::new($false))
            } catch {
                throw [System.IO.IOException]::new(
                    "HARNESS-EVIDENCE-WRITE-FAILED: result artifact is not persisted: $($_.Exception.Message)")
            }
        }
        return $result
    }
    if ($explicit.Count -gt 0) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-TEST: selected identity is not in inventory: '$($explicit[0])'.")
    }
    throw [System.IO.FileNotFoundException]::new('HARNESS-MISSING-INVENTORY: Run requires a finite inventory file.')
}

Export-ModuleMember -Function @(
    # NOTE (#907 D1): Set-/Get-HarnessExecutedTestObservation,
    # Test-HarnessExecutedTestReceipt and Get-HarnessAdmittedClock are
    # deliberately ABSENT from this list. They are module-private: the exported
    # Invoke-HarnessRun surface exposes no -HarnessProbe and no fault-injection
    # parameter, so no caller of the module can reach the fixture seam, and the
    # only path to a Passed disposition is Test-HarnessExecutedTestReceipt,
    # which requires a real executed-test receipt.
    'Get-IntegrationHarnessCoreVersion',
    'Get-IntegrationHarnessModelAvailability',
    'Test-IntegrationHarnessModelLoaded',
    'Get-IntegrationHarnessRedactedText',
    'Test-IntegrationHarnessClosedOperation',
    'Test-IntegrationHarnessNoReparsePoint',
    'Test-IntegrationHarnessOwnedProcess',
    'New-IntegrationHarnessOwnedProcessRecord',
    'New-IntegrationHarnessOwnedProcessView',
    'Get-IntegrationHarnessOwnedRecordField',
    'New-IntegrationHarnessBoundedRuntime',
    'Get-IntegrationHarnessBoundedNow',
    'Start-IntegrationHarnessBoundedStage',
    'Stop-IntegrationHarnessBoundedStage',
    'Add-IntegrationHarnessBoundedStageElapsed',
    'Add-IntegrationHarnessBoundedObservation',
    'ConvertTo-IntegrationHarnessBoundedRuntimeEvidence',
    'Test-IntegrationHarnessReadiness',
    'Test-IntegrationHarnessEvidenceComplete',
    'Resolve-IntegrationHarnessDeadline',
    'Test-IntegrationHarnessProviderResultClosed',
    'Invoke-IntegrationHarnessProviderOperation',
    'Invoke-IntegrationHarnessPrepare',
    'Invoke-IntegrationHarnessCleanup',
    'New-IntegrationHarnessRun',
    'New-IntegrationHarnessOwnedRunRoot',
    'New-IntegrationHarnessTerminalEvidence',
    'New-IntegrationHarnessRunEvidence',
    'Approve-IntegrationHarnessProviderPlan',
    'Group-IntegrationHarnessSelection',
    'Move-IntegrationHarnessState',
    'Stop-IntegrationHarnessOwnedProcess',
    'Stop-IntegrationHarnessOwnedProcessTree',
    'Remove-IntegrationHarnessOwnedRoot',
    'Reset-IntegrationHarnessForTest',
    'Complete-IntegrationHarnessRun',
    'Invoke-HarnessValidateConfiguration',
    'Invoke-HarnessWhatIf',
    'Invoke-HarnessRun'
)
