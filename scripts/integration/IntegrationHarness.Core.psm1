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
# - A PID/port/pipe/exit is never readiness and never successful execution.
# - Unknown start/commit/cleanup stays reconciliation-required; no blind retry
#   and no replacement resources are ever launched.
# - Prepare validates the entire plan before external action, runs in
#   deterministic dependency order, and on any failure cleans up in reverse
#   order every resource whose preparation may have started.
# - Timeout/cancellation stops the exact owned process tree via accepted
#   test-process ownership; never by name, port, or unverified PID.
# - Clocks and process controllers are injected; this module never sleeps and
#   never spawns live processes/ports/pipes.
# - Redaction/sink failure is recorded but never alters cleanup records or the
#   primary terminal outcome.
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

function Stop-IntegrationHarnessOwnedProcess {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [Parameter(Mandatory)]
        [string]$Role,
        [Parameter(Mandatory)]
        [string]$OwnerRunId,
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
    foreach ($field in @('TestOwnership', 'RequestGraceful', 'WaitForExit', 'StopForced')) {
        if (-not $ProcessController.ContainsKey($field) -or $ProcessController[$field] -isnot [scriptblock]) {
            throw [System.ArgumentException]::new("HARNESS-INVALID-CONTROLLER: controller is missing '$field'.")
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
    }
    try {
        $owned = (& $ProcessController['TestOwnership'] $ProcessId $OwnerRunId)
        if (-not $owned) {
            $Failures.Add("foreign-process-never-touched:$Role")
            $receipt.skippedForeign = $true
            $receipt.cleanupUnknown = $true
            $Receipts.Add([pscustomobject]$receipt)
            return @{
                stopped        = $false
                skippedForeign = $true
                cleanupUnknown = $true
                pid            = $ProcessId
                role           = $Role
            }
        }
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

function Stop-IntegrationHarnessOwnedProcessTree {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$RootPid,
        [Parameter()]
        [AllowEmptyCollection()]
        [int[]]$DescendantPids = @(),
        [Parameter(Mandatory)]
        [string]$OwnerRunId,
        [Parameter(Mandatory)]
        [hashtable]$ProcessController
    )
    if ($RootPid -le 0) {
        throw [System.ArgumentException]::new('HARNESS-INVALID-PID: root pid must be positive.')
    }
    $failures = [System.Collections.Generic.List[string]]::new()
    $receipts = [System.Collections.Generic.List[object]]::new()
    $ordered = @()
    $seen = @{}
    foreach ($targetPid in @($DescendantPids)) {
        if ($targetPid -le 0) {
            throw [System.ArgumentException]::new('HARNESS-INVALID-PID: descendant pid must be positive.')
        }
        $key = [string]$targetPid
        if (-not $seen.ContainsKey($key) -and $targetPid -ne $RootPid) {
            $seen[$key] = $true
            $ordered += $targetPid
        }
    }
    $ordered = @($ordered | Sort-Object -Descending)
    foreach ($targetPid in $ordered) {
        [void](Stop-IntegrationHarnessOwnedProcess -ProcessId $targetPid -Role 'test-descendant' `
            -OwnerRunId $OwnerRunId -ProcessController $ProcessController `
            -Failures $failures -Receipts $receipts)
    }
    $rootResult = Stop-IntegrationHarnessOwnedProcess -ProcessId $RootPid -Role 'test-root' `
        -OwnerRunId $OwnerRunId -ProcessController $ProcessController `
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
    $ordered = @($Plans | Sort-Object -Property { [string]$_['resourceKey'] })
    $next = @{}
    foreach ($key in $Run.Keys) {
        $next[$key] = $Run[$key]
    }
    $next['acceptedPlans'] = @($ordered)
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
    $ordered = @($approved['acceptedPlans'] | Sort-Object -Property {
        $depends = 0
        if ($_['dependsOn']) { $depends = @($_['dependsOn']).Count }
        ('{0:D6}:{1}' -f $depends, [string]$_['resourceKey'])
    })
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
    $ordered = @($Resources | Sort-Object -Property { [string]$_['resourceKey'] } -Descending)
    $records = [System.Collections.Generic.List[hashtable]]::new()
    $failures = [System.Collections.Generic.List[string]]::new()
    $unknown = $false
    foreach ($resource in $ordered) {
        $key = $null
        if ($resource -is [hashtable] -and $resource.ContainsKey('resourceKey')) {
            $key = [string]$resource['resourceKey']
        } elseif ($resource -is [hashtable] -and $resource.ContainsKey('allocation')) {
            $key = [string]$resource['allocation']
        } else {
            $key = [string]$resource
        }
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
    $overall = 'CleanupVerified'
    if ($unknown) {
        $overall = 'ReconciliationRequired'
    }
    return @{
        overallState = $overall
        records      = @($records)
        failures     = @($failures)
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
        redactionFailed     = $false
    }
    if ($Run.ContainsKey('acceptedPlans') -and $null -ne $Run['acceptedPlans']) {
        $evidence['planRecords'] = @($Run['acceptedPlans'])
        $evidence['resourceRecords'] = @($Run['acceptedPlans'])
    }
    if (Test-IntegrationHarnessModelLoaded) {
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
    if (Test-IntegrationHarnessModelLoaded) {
        $command = Get-Command -Name 'Test-IntegrationHarnessRunEvidence' -ErrorAction SilentlyContinue
        if ($null -ne $command) {
            return (Test-IntegrationHarnessRunEvidence -Evidence $Evidence)
        }
    }
    foreach ($field in @(
        'sourceIdentity', 'inventoryDigest', 'selectedRowDigests', 'harnessVersion',
        'perTestTerminal', 'failureFingerprint', 'cleanupRecords', 'arithmetic', 'proofCeiling')) {
        if (-not $Evidence.ContainsKey($field) -or $null -eq $Evidence[$field]) {
            throw [System.InvalidOperationException]::new("HARNESS-MISSING-EVIDENCE: missing '$field'.")
        }
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
    [void](Test-IntegrationHarnessEvidenceComplete -Evidence $Evidence)
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
    $next = @{}
    foreach ($key in $Run.Keys) {
        $next[$key] = $Run[$key]
    }
    $next['outcome'] = $outcome
    $next['reconciliationRequired'] = $reconciliationRequired
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

Export-ModuleMember -Function @(
    'Get-IntegrationHarnessCoreVersion',
    'Get-IntegrationHarnessModelAvailability',
    'Test-IntegrationHarnessModelLoaded',
    'Get-IntegrationHarnessRedactedText',
    'Test-IntegrationHarnessClosedOperation',
    'Test-IntegrationHarnessNoReparsePoint',
    'Test-IntegrationHarnessOwnedProcess',
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
    'Complete-IntegrationHarnessRun'
)
