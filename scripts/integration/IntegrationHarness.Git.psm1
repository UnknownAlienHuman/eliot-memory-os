# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Git — deterministic isolated Git repository/ref/worktree provider for issue #913.
#
# This module holds the Git provider BEHAVIOR behind the closed 9-operation
# provider interface (ValidateRequirement, Plan, Allocate, Start,
# ObserveReadiness, ResetForTest, CollectEvidence, Stop, VerifyCleanup).
# It mirrors the Core.psm1 Invoke pattern: a closed dispatcher validates the
# operation name, the binding shape, and the deadline via an injected clock,
# invokes the operation scriptblock, and validates the result carries no
# forbidden authority (testDenominator/providerChoice/command/argv/executable/
# shellCommand/testPassed/markPassed/verdictOverride).
#
# Fail-closed rules enforced here:
# - Exact GIT class plus provider revision eliot.integration.git-provider.v1
#   plus approved tool identity (git.exe, >= 2.40, no caller executable).
#   Unsupported class/revision, remote/network/provider/production-SCM
#   requirements stay explicit unsupported/external dispositions; they are
#   never converted to local fixture success.
# - Plan is finite and mutation-free: it returns Approve-Plan shaped resources
#   (resourceKey/runId/testClass/providerRevision/owner/generation) and never
#   carries shellCommand/executablePath/rawArgv/url/credential/environmentMap/
#   outputPath. Plan performs no filesystem, process, or network action.
# - Allocate mints a canonical owner-marked run-local repository path under the
#   admitted run root with the owner marker eliot-harness-owned-root-v1. It
#   never adopts the source checkout, another run's repository, or a foreign
#   marker; allocation is pure path computation (no mkdir here).
# - Start executes a closed fixed Git command set through an injected GitRunner
#   seam only (shell always disabled): git init --initial-branch, config --local
#   of an allowlisted key set, add/commit of frozen fixture bytes with
#   deterministic author/committer/timestamps, then independent verification of
#   objects/trees/commits/refs beyond the exit code. Arbitrary subcommand,
#   executable, shell, config key, URL, refspec, or argv is unrepresentable.
# - Global/system/user config inheritance is disabled per command
#   (GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=<owned null>, HOME=<owned temp>
#   without changing the real HOME), hooks/templates/aliases/filters/signing/
#   credential helpers/protocol paths are disabled through command/fixture-local
#   settings only.
# - ObserveReadiness binds owner marker plus scoped config plus fixture digest
#   plus exact object/tree/commit/ref/registered/materialized-worktree identity.
#   Init success or clean status alone is not readiness.
# - Exact operation/fixture replay returns the same verified owned topology
#   without duplicate commits/refs/worktrees; a changed fixture/config under one
#   identity is a typed conflict. A lost (uncertain) mutation response requires
#   exact object/ref reconciliation before retry.
# - ResetForTest restores only the declared owned baseline under an explicit
#   disposable-fixture policy; unexpected dirty/foreign state is preserved as
#   contamination evidence, never destroyed. The source checkout is never reset,
#   cleaned, pruned, or deleted.
# - CollectEvidence returns bounded redacted identities with truncation; it
#   redacts secrets/config/content/credential/private-path canaries and never
#   emits raw file contents, commands, config, credentials, or home paths.
# - Stop is a no-op lock release for a daemonless provider; sinks cannot change
#   Git or cleanup semantics.
# - VerifyCleanup checks the exact owned topology, registrations, locks, and
#   roots; it is idempotent, preserves foreign state, and reports uncertain
#   residue as non-green reconciliation-required instead of passing.
# - Paths are canonicalized under the admitted run root (traversal, reparse,
#   symlink, reserved device names, nested foreign repositories, and foreign
#   owner markers are rejected). Worktree paths are verified independently via
#   rev-parse --git-dir plus worktree list --porcelain owner checks.
# - Child environments are minimal and allowlisted. Run, provider, tool, config,
#   fixture, source, test-group, repository, and operation identities are bound
#   on every operation. Terminal dispositions follow the closed I07-20 set;
#   this provider never carries testPassed or verdictOverride authority.
#
# Clocks, git runners, file writers/probes, and entropy are injected; this
# module never spawns a process, never touches the network, never reads user
# Git secrets/config contents, and never sleeps.
#
# Proof ceiling: GIT-PROVIDER-ISOLATED-ONLY (fake-seam proof; no live git, no
# network, no run-isolated-tests.ps1 here — the real fixture smoke belongs to
# the controller track, not this work unit).

Set-StrictMode -Version Latest

$Script:GitTestClass = 'GIT'
$Script:GitProviderName = 'git-provider-owner'
$Script:GitProviderRevision = 'eliot.integration.git-provider.v1'
$Script:GitInterfaceVersion = 'eliot.integration.harness-provider.v1'
$Script:GitOwnedRootMarker = 'eliot-harness-owned-root-v1'
$Script:GitOwnerMarkerFile = '.eliot-harness-owner.json'
$Script:GitFixtureProfile = 'git-fixture-topology-v1'
$Script:GitTopology = 'single-repo'

$Script:GitInitialBranch = 'main'
$Script:GitObjectFormat = 'sha1'
$Script:GitHeadRef = 'refs/heads/main'
$Script:GitFixtureFileName = 'fixture.txt'
$Script:GitFixtureFileText = "eliot-git-fixture-v1`n"
$Script:GitFixtureDigest = 'c534928527968880e7989b782a683a08b9de304d64209af25fa875ad40b612a4'
$Script:GitFixtureMessage = 'eliot git-provider fixture commit'
$Script:GitFixtureAuthorName = 'eliot-fixture-author'
$Script:GitFixtureAuthorEmail = 'fixture-author@example.invalid'
$Script:GitFixtureCommitterName = 'eliot-fixture-author'
$Script:GitFixtureCommitterEmail = 'fixture-author@example.invalid'
$Script:GitFixtureAuthorDate = '2026-01-01T00:00:00+00:00'
$Script:GitFixtureCommitterDate = '2026-01-01T00:00:00+00:00'

$Script:GitMinimumMajor = 2
$Script:GitMinimumMinor = 40

$Script:GitClosedOperations = @(
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

$Script:GitTerminalDispositions = @(
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

$Script:GitForbiddenPlanKeys = @(
    'shellCommand', 'executablePath', 'rawArgv', 'url', 'credential',
    'environmentMap', 'outputPath'
)

$Script:GitForbiddenResultKeys = @(
    'testDenominator', 'providerChoice', 'chooseProvider', 'command', 'argv',
    'executable', 'shellCommand', 'testPassed', 'markPassed', 'verdictOverride'
)

$Script:GitAllowedChildEnv = @(
    'PATH', 'SystemRoot', 'TEMP', 'TMP', 'OS', 'PATHEXT', 'COMSPEC'
)

$Script:GitAllowedRootChildren = @(
    '.eliot-harness-owner.json', 'repo', 'worktrees', 'logs', 'temp'
)

$Script:GitReservedLeafPattern = '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'

$Script:GitAllowedCommands = @(
    'init', 'config', 'add', 'commit', 'rev-parse', 'cat-file',
    'hash-object', 'show-ref', 'status', 'worktree', 'log', 'reset'
)

$Script:GitAllowedConfigKeys = @(
    'user.name', 'user.email', 'commit.gpgsign', 'core.autocrlf',
    'core.hooksPath', 'core.repositoryformatversion', 'init.defaultBranch'
)

$Script:GitNetworkSubcommands = @(
    'clone', 'fetch', 'pull', 'push', 'remote', 'submodule', 'ls-remote',
    'upload-pack', 'receive-pack', 'upload-archive', 'archive'
)

function Get-GitProviderIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        testClass        = $Script:GitTestClass
        providerName     = $Script:GitProviderName
        providerRevision = $Script:GitProviderRevision
        interfaceVersion = $Script:GitInterfaceVersion
        artifact         = 'git.exe'
        objectFormat     = $Script:GitObjectFormat
        initialBranch    = $Script:GitInitialBranch
        fixtureProfile   = $Script:GitFixtureProfile
    }
}

function Get-GitLockIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        artifact       = 'git.exe'
        objectFormat   = $Script:GitObjectFormat
        initialBranch  = $Script:GitInitialBranch
        minimumVersion = ('{0}.{1}.0' -f $Script:GitMinimumMajor, $Script:GitMinimumMinor)
    }
}

function Get-GitClosedOperations {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:GitClosedOperations)
}

function Get-GitTerminalDispositions {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:GitTerminalDispositions)
}

function Test-GitDigestFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Digest
    )
    if ([string]::IsNullOrWhiteSpace($Digest)) {
        throw [System.ArgumentException]::new('GIT-INVALID-DIGEST: digest is empty.')
    }
    if ($Digest -cnotmatch '^[0-9a-f]{64}$') {
        throw [System.ArgumentException]::new('GIT-INVALID-DIGEST: digest must be 64 lowercase hex.')
    }
    return $true
}

function Test-GitObjectFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ObjectId
    )
    if ([string]::IsNullOrWhiteSpace($ObjectId)) {
        throw [System.ArgumentException]::new('GIT-INVALID-OBJECT: object id is empty.')
    }
    if ($ObjectId -cnotmatch '^[0-9a-f]{40}$') {
        throw [System.ArgumentException]::new('GIT-INVALID-OBJECT: object id must be 40 lowercase hex (sha1).')
    }
    return $true
}

function Test-GitClosedOperation {
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
    foreach ($allowed in $Script:GitClosedOperations) {
        if ($Operation -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "HARNESS-UNKNOWN-OPERATION: '$Operation' is not a member of the closed Git provider interface.")
}

function Test-GitTerminalDisposition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Disposition
    )
    if ([string]::IsNullOrWhiteSpace($Disposition)) {
        throw [System.ArgumentException]::new('GIT-INVALID-DISPOSITION: disposition is empty.')
    }
    foreach ($allowed in $Script:GitTerminalDispositions) {
        if ($Disposition -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "GIT-INVALID-DISPOSITION: '$Disposition' is not an accepted terminal disposition.")
}

function Resolve-GitDeadline {
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
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: binding is missing deadlineUtc.')
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
            throw [System.ArgumentException]::new('GIT-INVALID-CLOCK: injected clock must return DateTimeOffset.')
        }
    }
    $remaining = [int]($deadline - $now).TotalSeconds
    if ($remaining -le 0) {
        throw [System.TimeoutException]::new("GIT-DEADLINE-EXCEEDED: operation '$Operation' has no remaining bound.")
    }
    return $remaining
}

function Test-GitBindingShape {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("GIT-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    $runId = [string]$Binding['runId']
    if ($runId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: runId must be 32 lowercase hex.')
    }
    $gen = 0
    try { $gen = [int]$Binding['generation'] } catch {
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: generation must be a positive integer.')
    }
    if ($gen -le 0) {
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: generation must be positive.')
    }
    foreach ($key in @($Binding.Keys)) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "GIT-BINDING-FORBIDDEN: binding must not carry '$key'.")
            }
        }
    }
    return $true
}

function Test-GitProviderResultClosed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in $Script:GitForbiddenResultKeys) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "GIT-PROVIDER-FORBIDDEN: provider result must not contain '$key'.")
            }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) {
        throw [System.InvalidOperationException]::new('GIT-PROVIDER-FORBIDDEN: provider must not change the run identity.')
    }
    return $true
}

function Invoke-GitProviderOperation {
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
    [void](Test-GitClosedOperation -Operation $Operation)
    if ($null -eq $Provider -or $Provider.Count -eq 0) {
        throw [System.ArgumentException]::new('GIT-INVALID-PROVIDER: provider table is empty.')
    }
    if (-not $Provider.ContainsKey($Operation)) {
        throw [System.ArgumentException]::new("HARNESS-UNKNOWN-OPERATION: provider has no implementation for '$Operation'.")
    }
    $implementation = $Provider[$Operation]
    if ($implementation -isnot [scriptblock]) {
        throw [System.ArgumentException]::new("GIT-INVALID-PROVIDER: operation '$Operation' must map to a scriptblock.")
    }
    [void](Test-GitBindingShape -Binding $Binding)
    [void](Resolve-GitDeadline -Binding $Binding -Clock $Clock -Operation $Operation)
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
            "GIT-PROVIDER-FAILED:$Operation : $($_.Exception.Message)")
    }
    if ($null -eq $raw) {
        throw [System.InvalidOperationException]::new("GIT-PROVIDER-FAILED:$Operation : provider returned no result.")
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
            "GIT-PROVIDER-FAILED:$Operation : provider result must be a hashtable.")
    }
    [void](Test-GitProviderResultClosed -Result $result -Binding $Binding)
    return $result
}

function Test-GitCommandShape {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Command,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Argv
    )
    if ([string]::IsNullOrWhiteSpace($Command)) {
        throw [System.ArgumentException]::new('GIT-INVALID-COMMAND: command is empty.')
    }
    foreach ($network in $Script:GitNetworkSubcommands) {
        if ($Command -ieq $network) {
            throw [System.InvalidOperationException]::new(
                "GIT-NETWORK-FORBIDDEN: network subcommand '$Command' is not in the closed command set.")
        }
    }
    $known = $false
    foreach ($allowed in $Script:GitAllowedCommands) {
        if ($Command -ceq $allowed) { $known = $true; break }
    }
    if (-not $known) {
        throw [System.InvalidOperationException]::new(
            "GIT-UNKNOWN-COMMAND: subcommand '$Command' is not in the closed command set.")
    }
    $args = @()
    if ($null -ne $Argv) { $args = @($Argv) }
    foreach ($arg in $args) {
        if ($null -eq $arg -or $arg -isnot [string]) {
            throw [System.ArgumentException]::new('GIT-INVALID-ARGV: argv carries non-text.')
        }
        if ($arg -match '[\|\;&\$``]') {
            throw [System.InvalidOperationException]::new('GIT-SHELL-FORBIDDEN: argv carries shell metacharacters.')
        }
        if ($arg -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') {
            throw [System.InvalidOperationException]::new('GIT-URL-FORBIDDEN: argv carries a URL.')
        }
        if ($arg -match '@' -and $arg -match ':') {
            throw [System.InvalidOperationException]::new('GIT-URL-FORBIDDEN: argv carries an scp-like remote target.')
        }
        if ($arg -ceq '-c' -or $arg.StartsWith('--upload-pack') -or $arg.StartsWith('--receive-pack') -or $arg.StartsWith('--exec=')) {
            throw [System.InvalidOperationException]::new("GIT-CONFIG-FORBIDDEN: argv carries an unscoped override: $arg")
        }
        if ($arg -ceq '-C' -or $arg.StartsWith('--git-dir=') -or $arg.StartsWith('--work-tree=')) {
            throw [System.InvalidOperationException]::new("GIT-DISCOVERY-FORBIDDEN: argv overrides repository discovery: $arg")
        }
        if ($arg -match 'credential\.' -or $arg -match 'helper') {
            throw [System.InvalidOperationException]::new('GIT-CREDENTIAL-FORBIDDEN: argv touches credential helpers.')
        }
        if ($arg -match '[^a-zA-Z0-9_.:/\\+=@%~,\-]' -and $arg -match ':') {
            throw [System.InvalidOperationException]::new("GIT-REFSPEC-FORBIDDEN: argv carries a refspec: $arg")
        }
    }
    return $true
}

function Test-GitConfigKey {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key
    )
    if ([string]::IsNullOrWhiteSpace($Key)) {
        throw [System.ArgumentException]::new('GIT-INVALID-CONFIG: config key is empty.')
    }
    foreach ($allowed in $Script:GitAllowedConfigKeys) {
        if ($Key -ceq $allowed) { return $true }
    }
    throw [System.InvalidOperationException]::new(
        "GIT-CONFIG-FORBIDDEN: config key '$Key' is not in the scoped allowlist.")
}

function Resolve-GitOwnedPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ExpectedRunId,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe
    )
    if ([string]::IsNullOrWhiteSpace($RunRoot)) {
        throw [System.ArgumentException]::new('GIT-INVALID-PATH: RunRoot is empty.')
    }
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new('GIT-INVALID-PATH: Path is empty.')
    }
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.')
    }
    foreach ($rawSegment in ([string]$Path -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($rawSegment)) { continue }
        if ($rawSegment -match $Script:GitReservedLeafPattern) {
            throw [System.InvalidOperationException]::new("GIT-RESERVED-PATH: reserved device name rejected: $rawSegment")
        }
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
        throw [System.InvalidOperationException]::new("GIT-PATH-ESCAPE: path escapes the admitted run root: $candidate")
    }
    $leaf = [System.IO.Path]::GetFileName($candidate)
    if (-not [string]::IsNullOrEmpty($leaf) -and $leaf -match $Script:GitReservedLeafPattern) {
        throw [System.InvalidOperationException]::new("GIT-RESERVED-PATH: reserved device name rejected: $leaf")
    }
    $relative = ''
    if ($candidate.Length -gt $rootFull.Length) {
        $relative = $candidate.Substring($rootFull.Length)
    }
    foreach ($segment in ($relative.Split([System.IO.Path]::DirectorySeparatorChar))) {
        if ([string]::IsNullOrEmpty($segment)) { continue }
        if ($segment -match $Script:GitReservedLeafPattern) {
            throw [System.InvalidOperationException]::new("GIT-RESERVED-PATH: reserved device segment rejected: $segment")
        }
    }
    if ($null -ne $FileProbe) {
        $report = (& $FileProbe @{ runRoot = $rootFull; path = $candidate; expectedRunId = $ExpectedRunId })
        if ($null -eq $report -or $report -isnot [hashtable]) {
            throw [System.InvalidOperationException]::new('GIT-PROBE-INVALID: file probe must return a hashtable.')
        }
        if ([bool]$report['reparse']) {
            throw [System.InvalidOperationException]::new("GIT-REPARSE-ESCAPE: path crosses a reparse point: $candidate")
        }
        if ([bool]$report['foreignMarker']) {
            throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: owner marker belongs to another run near: $candidate")
        }
        if ([bool]$report['nestedForeignRepo']) {
            throw [System.InvalidOperationException]::new("GIT-FOREIGN-REPO: nested foreign repository rejected: $candidate")
        }
        return $candidate
    }
    $probe = $candidate
    while ($null -ne $probe -and $probe.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw [System.InvalidOperationException]::new("GIT-REPARSE-ESCAPE: path crosses a reparse point: $($entry.FullName)")
            }
            break
        }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    $cursor = Split-Path -Parent $candidate
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and $cursor.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $marker = Join-Path $cursor $Script:GitOwnerMarkerFile
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            try {
                $recorded = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($recorded.run_id -cne $ExpectedRunId) {
                    throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: owner marker belongs to another run: $cursor")
                }
            } catch [System.InvalidOperationException] {
                throw
            } catch {
                throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: owner marker unreadable at: $cursor")
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

function Test-GitRunRootShape {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$ExpectedRunId
    )
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('GIT-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.')
    }
    $rootFull = [System.IO.Path]::GetFullPath($RunRoot)
    $leaf = Split-Path -Leaf $rootFull
    $expected = ('eliot-git-{0}-' -f $ExpectedRunId)
    if (-not $leaf.StartsWith($expected, [System.StringComparison]::Ordinal)) {
        throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: run root '$rootFull' is not the canonical owned root for this run; source checkouts and foreign runs are never adopted.")
    }
    $suffix = $leaf.Substring($expected.Length)
    if ($suffix -cnotmatch '^[0-9a-f]{8,64}$') {
        throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: run root '$rootFull' carries an invalid allocation seed.")
    }
    return $true
}

function Get-GitChildEnv {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Ambient,
        [Parameter(Mandatory)]
        [string]$OwnedHome,
        [Parameter(Mandatory)]
        [string]$OwnedGlobalConfig
    )
    if ([string]::IsNullOrWhiteSpace($OwnedHome)) {
        throw [System.ArgumentException]::new('GIT-INVALID-PATH: OwnedHome is empty.')
    }
    if ([string]::IsNullOrWhiteSpace($OwnedGlobalConfig)) {
        throw [System.ArgumentException]::new('GIT-INVALID-PATH: OwnedGlobalConfig is empty.')
    }
    $filtered = @{}
    foreach ($key in @($Ambient.Keys)) {
        if ($key -cnotin $Script:GitAllowedChildEnv) { continue }
        $upper = ([string]$key).ToUpperInvariant()
        if ($upper.Contains('TOKEN') -or $upper.Contains('SECRET') -or $upper.Contains('CREDENTIAL') -or $upper.Contains('PASSWORD') -or $upper.Contains('KEY')) {
            continue
        }
        $value = [string]$Ambient[$key]
        $bytes = [System.Text.Encoding]::UTF8.GetByteCount($value)
        if ($bytes -gt 4096) {
            throw [System.InvalidOperationException]::new("GIT-ENV-BOUND: child env value exceeds byte cap: $key")
        }
        $filtered[$key] = $value
    }
    $filtered['GIT_CONFIG_NOSYSTEM'] = '1'
    $filtered['GIT_CONFIG_GLOBAL'] = $OwnedGlobalConfig
    $filtered['HOME'] = $OwnedHome
    $filtered['GIT_TERMINAL_PROMPT'] = '0'
    $filtered['GIT_AUTHOR_NAME'] = $Script:GitFixtureAuthorName
    $filtered['GIT_AUTHOR_EMAIL'] = $Script:GitFixtureAuthorEmail
    $filtered['GIT_AUTHOR_DATE'] = $Script:GitFixtureAuthorDate
    $filtered['GIT_COMMITTER_NAME'] = $Script:GitFixtureCommitterName
    $filtered['GIT_COMMITTER_EMAIL'] = $Script:GitFixtureCommitterEmail
    $filtered['GIT_COMMITTER_DATE'] = $Script:GitFixtureCommitterDate
    return $filtered
}

function Get-GitFixtureBytes {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param()
    return [System.Text.Encoding]::UTF8.GetBytes($Script:GitFixtureFileText)
}

function Test-GitFixtureDigest {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes
    )
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)
    $actual = ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
    if ($actual -cne $Script:GitFixtureDigest) {
        throw [System.InvalidOperationException]::new('GIT-FIXTURE-MISMATCH: fixture bytes digest is not the frozen fixture identity.')
    }
    return $true
}

function Get-GitRedactedText {
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
                $redacted = $redacted.Replace($secret, '[redacted-git-secret]')
            }
        }
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring|credential)\s*[:=]\s*\S+',
            '$1=[redacted-git-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)(user\.email|user\.name|commit\.gpgsign|core\.hooksPath|core\.autocrlf)\s*[=:]+\s*\S+',
            '$1=[redacted-git-config]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)CONTENT\s*\{[^}]{0,4096}\}',
            'CONTENT [redacted-git-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)[A-Za-z]:\\Users\\[^\\/:*?"<>|]+',
            '[redacted-user-path]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)/home/[^/:*?"<>|\s]+',
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

function Test-GitToolVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Version
    )
    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw [System.ArgumentException]::new('GIT-TOOL-UNAVAILABLE: tool version is empty; the approved git executable is unavailable.')
    }
    $m = [regex]::Match($Version, '^\s*(\d+)\.(\d+)(?:\.(\d+))?')
    if (-not $m.Success) {
        throw [System.InvalidOperationException]::new("GIT-LOCK-MISMATCH: tool version '$Version' is not a dotted version.")
    }
    $major = [int]$m.Groups[1].Value
    $minor = [int]$m.Groups[2].Value
    if ($major -lt $Script:GitMinimumMajor -or ($major -eq $Script:GitMinimumMajor -and $minor -lt $Script:GitMinimumMinor)) {
        throw [System.InvalidOperationException]::new(
            "GIT-LOCK-MISMATCH: tool version '$Version' is below the approved minimum '$($Script:GitMinimumMajor).$($Script:GitMinimumMinor)'.")
    }
    return $true
}

function Invoke-GitValidateRequirement {
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
    [void](Test-GitBindingShape -Binding $Binding)
    foreach ($field in @('testClass', 'providerRevision')) {
        if (-not $Requirement.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Requirement[$field])) {
            throw [System.ArgumentException]::new("GIT-INVALID-REQUIREMENT: requirement is missing '$field'.")
        }
    }
    foreach ($external in @('url', 'remote', 'remoteUrl', 'provider', 'productionScm', 'production-scm')) {
        if ($Requirement.ContainsKey($external) -and -not [string]::IsNullOrWhiteSpace([string]$Requirement[$external])) {
            throw [System.InvalidOperationException]::new(
                "GIT-UNSUPPORTED-EXTERNAL: requirement carries '$external'; remote/provider/production-SCM stays explicit unsupported/external.")
        }
    }
    $reqClass = [string]$Requirement['testClass']
    if ($reqClass -cne $Script:GitTestClass) {
        throw [System.InvalidOperationException]::new(
            "GIT-UNSUPPORTED-EXTERNAL: requirement class '$reqClass' is not GIT; disposition unsupported-external.")
    }
    $reqRev = [string]$Requirement['providerRevision']
    if ($reqRev -cne $Script:GitProviderRevision) {
        throw [System.InvalidOperationException]::new(
            "GIT-UNSUPPORTED-REVISION: provider revision '$reqRev' is not '$($Script:GitProviderRevision)'.")
    }
    if ($Requirement.ContainsKey('fixtureProfile') -and -not [string]::IsNullOrWhiteSpace([string]$Requirement['fixtureProfile'])) {
        if ([string]$Requirement['fixtureProfile'] -cne $Script:GitFixtureProfile) {
            throw [System.InvalidOperationException]::new(
                "GIT-UNSUPPORTED-PROFILE: fixture profile '$($Requirement['fixtureProfile'])' is not '$($Script:GitFixtureProfile)'.")
        }
    }
    if ($Requirement.ContainsKey('topology') -and -not [string]::IsNullOrWhiteSpace([string]$Requirement['topology'])) {
        if ([string]$Requirement['topology'] -cne $Script:GitTopology) {
            throw [System.InvalidOperationException]::new(
                "GIT-UNSUPPORTED-TOPOLOGY: topology '$($Requirement['topology'])' is not '$($Script:GitTopology)'.")
        }
    }
    if ([string]$Binding['testClass'] -cne $Script:GitTestClass) {
        throw [System.InvalidOperationException]::new('GIT-BINDING-MISMATCH: binding testClass is not GIT.')
    }
    if ([string]$Binding['providerRevision'] -cne $Script:GitProviderRevision) {
        throw [System.InvalidOperationException]::new('GIT-BINDING-MISMATCH: binding providerRevision mismatch.')
    }
    if ([string]$Binding['providerName'] -cne $Script:GitProviderName) {
        throw [System.InvalidOperationException]::new('GIT-BINDING-MISMATCH: binding providerName mismatch.')
    }
    foreach ($field in @('artifact', 'version')) {
        if (-not $Lock.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Lock[$field])) {
            throw [System.InvalidOperationException]::new("GIT-TOOL-UNAVAILABLE: lock is missing '$field'; the approved git executable is unavailable.")
        }
    }
    $artifact = [string]$Lock['artifact']
    if ($artifact -ine 'git.exe' -and $artifact -ine 'git') {
        throw [System.InvalidOperationException]::new("GIT-LOCK-MISMATCH: lock artifact '$artifact' is not the approved git executable.")
    }
    [void](Test-GitToolVersion -Version ([string]$Lock['version']))
    if ($Lock.ContainsKey('objectFormat') -and -not [string]::IsNullOrWhiteSpace([string]$Lock['objectFormat'])) {
        if ([string]$Lock['objectFormat'] -cne $Script:GitObjectFormat) {
            throw [System.InvalidOperationException]::new('GIT-LOCK-MISMATCH: lock object format is not sha1.')
        }
    }
    return @{
        runId            = [string]$Binding['runId']
        testClass        = $Script:GitTestClass
        providerName     = $Script:GitProviderName
        providerRevision = $Script:GitProviderRevision
        artifact         = 'git.exe'
        version          = [string]$Lock['version']
        objectFormat     = $Script:GitObjectFormat
        initialBranch    = $Script:GitInitialBranch
        fixtureProfile   = $Script:GitFixtureProfile
        disposition      = 'accepted-local'
        accepted         = $true
    }
}

function Invoke-GitPlan {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requirement
    )
    [void](Test-GitBindingShape -Binding $Binding)
    if ([string]$Requirement['testClass'] -cne $Script:GitTestClass) {
        throw [System.InvalidOperationException]::new('GIT-UNSUPPORTED-CLASS: plan requirement class is not GIT.')
    }
    if ([string]$Requirement['providerRevision'] -cne $Script:GitProviderRevision) {
        throw [System.InvalidOperationException]::new('GIT-UNSUPPORTED-REVISION: plan requirement revision mismatch.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $resources = @(
        @{ resourceKey = 'git-repo'; testClass = $Script:GitTestClass; providerRevision = $Script:GitProviderRevision; runId = $runId; owner = $owner; generation = $gen; objectFormat = $Script:GitObjectFormat; initialBranch = $Script:GitInitialBranch; fixtureProfile = $Script:GitFixtureProfile },
        @{ resourceKey = 'git-worktree'; testClass = $Script:GitTestClass; providerRevision = $Script:GitProviderRevision; runId = $runId; owner = $owner; generation = $gen; objectFormat = $Script:GitObjectFormat; initialBranch = $Script:GitInitialBranch; fixtureProfile = $Script:GitFixtureProfile }
    )
    foreach ($resource in $resources) {
        foreach ($key in @($resource.Keys)) {
            foreach ($forbidden in $Script:GitForbiddenPlanKeys) {
                if ([string]$key -ieq $forbidden) {
                    throw [System.InvalidOperationException]::new(
                        "GIT-PLAN-FORBIDDEN: plan resource must not carry '$key'.")
                }
            }
        }
    }
    return @{
        runId            = $runId
        testClass        = $Script:GitTestClass
        providerName     = $Script:GitProviderName
        providerRevision = $Script:GitProviderRevision
        owner            = $owner
        generation       = $gen
        topology         = $Script:GitTopology
        fixtureDigest    = $Script:GitFixtureDigest
        resources        = $resources
        mutationFree     = $true
    }
}

function Invoke-GitAllocate {
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
        [scriptblock]$FileProbe
    )
    [void](Test-GitBindingShape -Binding $Binding)
    if ([string]$Plan['runId'] -cne [string]$Binding['runId']) {
        throw [System.InvalidOperationException]::new('GIT-ALLOCATION-MISMATCH: plan run identity does not match binding.')
    }
    if ([string]::IsNullOrWhiteSpace($BaseTemp)) {
        throw [System.ArgumentException]::new('GIT-INVALID-PATH: BaseTemp is empty.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $baseFull = [System.IO.Path]::GetFullPath($BaseTemp)
    $lower = $baseFull.ToLowerInvariant()
    if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) {
        throw [System.InvalidOperationException]::new('GIT-FORBIDDEN-ROOT: allocation base crossed a forbidden host boundary.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') {
            throw [System.ArgumentException]::new('GIT-INVALID-ENTROPY: entropy must return lowercase hex.')
        }
    } else {
        $nonce = $runId.Substring(0, 8)
    }
    $runRoot = [System.IO.Path]::GetFullPath((Join-Path $baseFull ("eliot-git-{0}-{1}" -f $runId, $nonce)))
    $prefix = $baseFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $runRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("GIT-PATH-ESCAPE: allocated run root escaped its base: $runRoot")
    }
    $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'repo'))
    $worktreeRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'worktrees'))
    $logRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'logs'))
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $repoRoot -ExpectedRunId $runId -FileProbe $FileProbe)
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $worktreeRoot -ExpectedRunId $runId -FileProbe $FileProbe)
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $logRoot -ExpectedRunId $runId -FileProbe $FileProbe)
    $markerPath = Join-Path $runRoot $Script:GitOwnerMarkerFile
    return @{
        runId          = $runId
        runRoot        = $runRoot
        repoRoot       = $repoRoot
        worktreeRoot   = $worktreeRoot
        logRoot        = $logRoot
        ownerMarker    = $Script:GitOwnedRootMarker
        ownerMarkerFile = $markerPath
        topology       = $Script:GitTopology
        objectFormat   = $Script:GitObjectFormat
        initialBranch  = $Script:GitInitialBranch
        fixtureDigest  = $Script:GitFixtureDigest
        owner          = $owner
        generation     = $gen
        allocationSeed = $nonce
    }
}

function Invoke-GitRunnerCall {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GitRunner,
        [Parameter(Mandatory)]
        [string]$Command,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Argv,
        [Parameter(Mandatory)]
        [string]$WorkDir,
        [Parameter(Mandatory)]
        [hashtable]$Env
    )
    if ($null -eq $GitRunner) {
        throw [System.ArgumentException]::new('GIT-MISSING-RUNNER: a GitRunner seam is required; no implicit git execution is performed.')
    }
    $args = @()
    if ($null -ne $Argv) { $args = @($Argv) }
    [void](Test-GitCommandShape -Command $Command -Argv $args)
    $call = @{
        command = $Command
        argv    = $args
        workDir = $WorkDir
        env     = $Env
    }
    $result = $null
    try {
        $result = (& $GitRunner $call)
    } catch {
        throw [System.InvalidOperationException]::new("GIT-RUNNER-FAILED: git runner failed for '$Command': $($_.Exception.Message)")
    }
    if ($null -eq $result -or $result -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new("GIT-RUNNER-INVALID: git runner must return a hashtable for '$Command'.")
    }
    if ($result.ContainsKey('uncertain') -and [bool]$result['uncertain']) {
        throw [System.InvalidOperationException]::new("GIT-RECONCILIATION-REQUIRED: lost '$Command' response; reconcile exact object/ref state before retry.")
    }
    if (-not $result.ContainsKey('exit')) {
        throw [System.InvalidOperationException]::new("GIT-RUNNER-INVALID: git runner result is missing 'exit' for '$Command'.")
    }
    $exit = 0
    try { $exit = [int]$result['exit'] } catch {
        throw [System.InvalidOperationException]::new("GIT-RUNNER-INVALID: git runner exit is not an integer for '$Command'.")
    }
    if ($exit -ne 0) {
        throw [System.InvalidOperationException]::new("GIT-START-FAILED: git '$Command' exited $exit.")
    }
    return $result
}

function Invoke-GitStart {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GitRunner,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileWriter,
        [Parameter()]
        [AllowNull()]
        [hashtable]$PriorReceipt,
        [Parameter()]
        [AllowNull()]
        [hashtable]$AmbientEnv
    )
    [void](Test-GitBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('GIT-START-MISMATCH: allocation run identity does not match binding.')
    }
    if ([string]$Allocation['fixtureDigest'] -cne $Script:GitFixtureDigest) {
        throw [System.InvalidOperationException]::new('GIT-PROFILE-CONFLICT: allocation fixture digest is not the frozen fixture identity.')
    }
    if ($null -ne $PriorReceipt) {
        if ([string]$PriorReceipt['runId'] -cne $runId) {
            throw [System.InvalidOperationException]::new('GIT-START-MISMATCH: prior receipt run identity does not match binding.')
        }
        if ([string]$PriorReceipt['fixtureDigest'] -cne $Script:GitFixtureDigest) {
            throw [System.InvalidOperationException]::new('GIT-PROFILE-CONFLICT: changed fixture under one identity conflicts; no duplicate topology is created.')
        }
        if ([bool]$PriorReceipt['verified'] -and -not [string]::IsNullOrWhiteSpace([string]$PriorReceipt['commitId'])) {
            [void](Test-GitObjectFormat -ObjectId ([string]$PriorReceipt['commitId']))
            return $PriorReceipt
        }
    }
    if ($null -eq $GitRunner) {
        throw [System.ArgumentException]::new('GIT-MISSING-RUNNER: a GitRunner seam is required; no implicit git execution is performed.')
    }
    if ($null -eq $FileWriter) {
        throw [System.ArgumentException]::new('GIT-MISSING-WRITER: a FileWriter seam is required; no implicit file mutation is performed.')
    }
    $runRoot = [string]$Allocation['runRoot']
    $repoRoot = [string]$Allocation['repoRoot']
    [void](Test-GitRunRootShape -RunRoot $runRoot -ExpectedRunId $runId)
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $repoRoot -ExpectedRunId $runId)
    $ownedHome = Join-Path $runRoot 'temp'
    $ownedGlobal = Join-Path $runRoot 'temp'
    if ([System.IO.Path]::DirectorySeparatorChar -eq '\') { $ownedGlobal = 'NUL' } else { $ownedGlobal = '/dev/null' }
    $ambient = @{}
    if ($null -ne $AmbientEnv) { $ambient = $AmbientEnv }
    $childEnv = Get-GitChildEnv -Ambient $ambient -OwnedHome $ownedHome -OwnedGlobalConfig $ownedGlobal
    [void](Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'init' -Argv @('--initial-branch=main', $repoRoot) -WorkDir $runRoot -Env $childEnv)
    foreach ($pair in @(@('user.name', $Script:GitFixtureAuthorName), @('user.email', $Script:GitFixtureAuthorEmail), @('commit.gpgsign', 'false'), @('core.autocrlf', 'false'), @('core.hooksPath', ''))) {
        [void](Test-GitConfigKey -Key $pair[0])
        [void](Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'config' -Argv @('--local', $pair[0], $pair[1]) -WorkDir $repoRoot -Env $childEnv)
    }
    $fixturePath = Join-Path $repoRoot $Script:GitFixtureFileName
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $fixturePath -ExpectedRunId $runId)
    $written = $null
    try {
        $written = (& $FileWriter @{ path = $fixturePath; bytes = (Get-GitFixtureBytes) })
    } catch {
        throw [System.InvalidOperationException]::new("GIT-WRITE-FAILED: fixture writer failed: $($_.Exception.Message)")
    }
    if ($null -eq $written -or $written -isnot [hashtable] -or -not $written.ContainsKey('digest')) {
        throw [System.InvalidOperationException]::new('GIT-WRITE-INVALID: fixture writer must return a digest receipt.')
    }
    [void](Test-GitDigestFormat -Digest ([string]$written['digest']))
    if ([string]$written['digest'] -cne $Script:GitFixtureDigest) {
        throw [System.InvalidOperationException]::new('GIT-FIXTURE-MISMATCH: materialized fixture bytes digest is not the frozen fixture identity.')
    }
    [void](Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'add' -Argv @('--', $Script:GitFixtureFileName) -WorkDir $repoRoot -Env $childEnv)
    [void](Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'commit' -Argv @('-m', $Script:GitFixtureMessage, '--no-gpg-sign', '--no-verify') -WorkDir $repoRoot -Env $childEnv)
    $verifyHead = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('--verify', 'HEAD') -WorkDir $repoRoot -Env $childEnv
    $commitId = ([string]$verifyHead['stdout']).Trim()
    [void](Test-GitObjectFormat -ObjectId $commitId)
    $catCommit = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'cat-file' -Argv @('-t', $commitId) -WorkDir $repoRoot -Env $childEnv
    if (([string]$catCommit['stdout']).Trim() -cne 'commit') {
        throw [System.InvalidOperationException]::new('GIT-START-FAILED: HEAD does not resolve to a commit object.')
    }
    $verifyTree = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('HEAD^{tree}') -WorkDir $repoRoot -Env $childEnv
    $treeId = ([string]$verifyTree['stdout']).Trim()
    [void](Test-GitObjectFormat -ObjectId $treeId)
    $catTree = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'cat-file' -Argv @('-t', $treeId) -WorkDir $repoRoot -Env $childEnv
    if (([string]$catTree['stdout']).Trim() -cne 'tree') {
        throw [System.InvalidOperationException]::new('GIT-START-FAILED: HEAD tree does not resolve to a tree object.')
    }
    return @{
        runId          = $runId
        repoRoot       = $repoRoot
        commitId       = $commitId
        treeId         = $treeId
        refName        = $Script:GitHeadRef
        fixtureDigest  = $Script:GitFixtureDigest
        toolEnv        = 'scoped-child'
        owner          = [string]$Binding['owner']
        generation     = [int]$Binding['generation']
        verified       = $true
    }
}

function Invoke-GitObserveReadiness {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GitRunner,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe
    )
    [void](Test-GitBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($table in @($Allocation, $StartReceipt)) {
        if ([string]$table['runId'] -cne $runId) {
            throw [System.InvalidOperationException]::new('GIT-READINESS-MISMATCH: allocation/start run identity does not match binding.')
        }
    }
    if ($null -eq $GitRunner) {
        throw [System.ArgumentException]::new('GIT-MISSING-RUNNER: a GitRunner seam is required; init/status exit alone is not readiness.')
    }
    $runRoot = [string]$Allocation['runRoot']
    $repoRoot = [string]$Allocation['repoRoot']
    [void](Test-GitRunRootShape -RunRoot $runRoot -ExpectedRunId $runId)
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $repoRoot -ExpectedRunId $runId -FileProbe $FileProbe)
    if ($null -eq $FileProbe) {
        throw [System.ArgumentException]::new('GIT-MISSING-PROBE: a FileProbe seam is required; owner/config/fixture evidence is mandatory.')
    }
    $ownerReport = (& $FileProbe @{ runRoot = $runRoot; path = (Join-Path $runRoot $Script:GitOwnerMarkerFile); expectedRunId = $runId; kind = 'owner-marker' })
    if ($null -eq $ownerReport -or $ownerReport -isnot [hashtable] -or -not [bool]$ownerReport['markerValid']) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: owner marker evidence is missing or foreign.')
    }
    $ambient = @{}
    $childEnv = Get-GitChildEnv -Ambient $ambient -OwnedHome (Join-Path $runRoot 'temp') -OwnedGlobalConfig 'NUL'
    $configResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'config' -Argv @('--local', '--list') -WorkDir $repoRoot -Env $childEnv
    $configLines = @((([string]$configResult['stdout']) -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($configLines.Count -eq 0) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: scoped config evidence is empty.')
    }
    $seen = @{}
    foreach ($line in $configLines) {
        $eq = $line.IndexOf('=')
        if ($eq -le 0) {
            throw [System.InvalidOperationException]::new("GIT-NOT-READY: scoped config line is malformed: $line")
        }
        $key = $line.Substring(0, $eq)
        [void](Test-GitConfigKey -Key $key)
        $seen[$key] = $true
    }
    foreach ($required in @('user.name', 'user.email')) {
        if (-not $seen.ContainsKey($required)) {
            throw [System.InvalidOperationException]::new("GIT-NOT-READY: scoped config is missing '$required'.")
        }
    }
    $fixtureReport = (& $FileProbe @{ runRoot = $runRoot; path = (Join-Path $repoRoot $Script:GitFixtureFileName); expectedRunId = $runId; kind = 'fixture-bytes' })
    if ($null -eq $fixtureReport -or $fixtureReport -isnot [hashtable] -or -not $fixtureReport.ContainsKey('digest')) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: fixture bytes evidence is missing.')
    }
    [void](Test-GitDigestFormat -Digest ([string]$fixtureReport['digest']))
    if ([string]$fixtureReport['digest'] -cne $Script:GitFixtureDigest) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: fixture bytes digest is not the frozen fixture identity.')
    }
    $headResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('--verify', 'HEAD') -WorkDir $repoRoot -Env $childEnv
    $commitId = ([string]$headResult['stdout']).Trim()
    [void](Test-GitObjectFormat -ObjectId $commitId)
    if ($commitId -cne [string]$StartReceipt['commitId']) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: HEAD commit identity does not match the start receipt.')
    }
    $treeResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('HEAD^{tree}') -WorkDir $repoRoot -Env $childEnv
    $treeId = ([string]$treeResult['stdout']).Trim()
    [void](Test-GitObjectFormat -ObjectId $treeId)
    if ($treeId -cne [string]$StartReceipt['treeId']) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: HEAD tree identity does not match the start receipt.')
    }
    $refResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'show-ref' -Argv @('--head') -WorkDir $repoRoot -Env $childEnv
    $refLines = @((([string]$refResult['stdout']) -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    $headSeen = $false
    foreach ($refLine in $refLines) {
        $parts = @($refLine -split '\s+')
        if ($parts.Count -ne 2) {
            throw [System.InvalidOperationException]::new("GIT-NOT-READY: ref line is malformed: $refLine")
        }
        [void](Test-GitObjectFormat -ObjectId $parts[0])
        $refName = $parts[1]
        if ($refName -cne 'HEAD' -and $refName -cne $Script:GitHeadRef) {
            throw [System.InvalidOperationException]::new("GIT-FOREIGN-REF: unowned ref rejected without adoption: $refName")
        }
        if (($refName -ceq $Script:GitHeadRef -or $refName -ceq 'HEAD') -and $parts[0] -ceq $commitId) {
            $headSeen = $true
        }
    }
    if (-not $headSeen) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: head ref identity is absent from show-ref evidence.')
    }
    $wtResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'worktree' -Argv @('list', '--porcelain') -WorkDir $repoRoot -Env $childEnv
    $wtPaths = @()
    foreach ($wtLine in (([string]$wtResult['stdout']) -split "`n")) {
        $trimmed = $wtLine.Trim()
        if ($trimmed.StartsWith('worktree ')) {
            $wtPaths += $trimmed.Substring('worktree '.Length).Trim()
        }
    }
    if ($wtPaths.Count -eq 0) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: registered worktree evidence is empty.')
    }
    foreach ($wtPath in $wtPaths) {
        [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $wtPath -ExpectedRunId $runId -FileProbe $FileProbe)
    }
    $gitDirResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('--git-dir') -WorkDir $repoRoot -Env $childEnv
    $gitDir = ([string]$gitDirResult['stdout']).Trim()
    if ([string]::IsNullOrWhiteSpace($gitDir)) {
        throw [System.InvalidOperationException]::new('GIT-NOT-READY: git-dir evidence is empty.')
    }
    return @{
        runId        = $runId
        ready        = $true
        commitId     = $commitId
        treeId       = $treeId
        refName      = $Script:GitHeadRef
        worktrees    = @($wtPaths)
        gitDir       = $gitDir
        owner        = [string]$Binding['owner']
        evidenceIds  = @('owner-marker', 'scoped-config', 'fixture-digest', 'commit', 'tree', 'ref', 'worktree-list', 'git-dir')
    }
}

function Invoke-GitResetForTest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$GitRunner,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileWriter,
        [Parameter(Mandatory)]
        [string]$Disposition,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe
    )
    [void](Test-GitBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($table in @($Allocation, $StartReceipt)) {
        if ([string]$table['runId'] -cne $runId) {
            throw [System.InvalidOperationException]::new('GIT-RESET-MISMATCH: allocation/start run identity does not match binding.')
        }
    }
    if ($null -eq $GitRunner) {
        throw [System.ArgumentException]::new('GIT-MISSING-RUNNER: a GitRunner seam is required; no implicit reset is performed.')
    }
    if ($Disposition -cne 'disposable-fixture' -and $Disposition -cne 'baseline-verify') {
        throw [System.ArgumentException]::new("GIT-INVALID-DISPOSITION: reset disposition '$Disposition' is not disposable-fixture or baseline-verify.")
    }
    $runRoot = [string]$Allocation['runRoot']
    $repoRoot = [string]$Allocation['repoRoot']
    [void](Test-GitRunRootShape -RunRoot $runRoot -ExpectedRunId $runId)
    [void](Resolve-GitOwnedPath -RunRoot $runRoot -Path $repoRoot -ExpectedRunId $runId -FileProbe $FileProbe)
    $ambient = @{}
    $childEnv = Get-GitChildEnv -Ambient $ambient -OwnedHome (Join-Path $runRoot 'temp') -OwnedGlobalConfig 'NUL'
    if ($null -ne $FileProbe) {
        $foreignReport = (& $FileProbe @{ runRoot = $runRoot; path = $repoRoot; expectedRunId = $runId; kind = 'foreign-scan' })
        if ($null -ne $foreignReport -and $foreignReport -is [hashtable] -and [bool]$foreignReport['foreignPresent']) {
            return @{
                runId          = $runId
                reset          = $false
                contaminated   = $true
                evidenceIds    = @('foreign-preserved')
                detail         = 'GIT-CONTAMINATION: foreign state preserved as reconciliation evidence; no destructive reset performed.'
            }
        }
    }
    $statusResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'status' -Argv @('--porcelain=v1') -WorkDir $repoRoot -Env $childEnv
    $statusText = ([string]$statusResult['stdout']).Trim()
    if ($statusText -eq '') {
        $headResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('--verify', 'HEAD') -WorkDir $repoRoot -Env $childEnv
        $commitId = ([string]$headResult['stdout']).Trim()
        [void](Test-GitObjectFormat -ObjectId $commitId)
        if ($commitId -cne [string]$StartReceipt['commitId']) {
            throw [System.InvalidOperationException]::new('GIT-RESET-MISMATCH: clean HEAD identity drifted from the start receipt.')
        }
        return @{
            runId        = $runId
            reset        = $true
            baseline     = 'already-clean'
            commitId     = $commitId
            owner        = [string]$Binding['owner']
            evidenceIds  = @('status-clean', 'head-verified')
        }
    }
    if ($Disposition -cne 'disposable-fixture') {
        return @{
            runId          = $runId
            reset          = $false
            contaminated   = $true
            evidenceIds    = @('dirty-preserved')
            detail         = 'GIT-CONTAMINATION: unexpected dirty state without disposable-fixture policy; preserved as evidence.'
        }
    }
    [void](Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'reset' -Argv @('--hard', 'HEAD') -WorkDir $repoRoot -Env $childEnv)
    $postResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'status' -Argv @('--porcelain=v1') -WorkDir $repoRoot -Env $childEnv
    if (([string]$postResult['stdout']).Trim() -ne '') {
        throw [System.InvalidOperationException]::new('GIT-RESET-FAILED: post-reset worktree is not clean.')
    }
    $headResult = Invoke-GitRunnerCall -GitRunner $GitRunner -Command 'rev-parse' -Argv @('--verify', 'HEAD') -WorkDir $repoRoot -Env $childEnv
    $commitId = ([string]$headResult['stdout']).Trim()
    [void](Test-GitObjectFormat -ObjectId $commitId)
    if ($commitId -cne [string]$StartReceipt['commitId']) {
        throw [System.InvalidOperationException]::new('GIT-RESET-MISMATCH: post-reset HEAD identity drifted from the start receipt.')
    }
    return @{
        runId        = $runId
        reset        = $true
        baseline     = 'restored-disposable'
        commitId     = $commitId
        owner        = [string]$Binding['owner']
        evidenceIds  = @('reset-hard', 'status-clean', 'head-verified')
    }
}

function Invoke-GitCollectEvidence {
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
        [string]$StatusText,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Refs,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secrets,
        [ValidateRange(1, 16777216)]
        [int]$MaxBytes = 65536
    )
    [void](Test-GitBindingShape -Binding $Binding)
    [void](Test-GitTerminalDisposition -Disposition $TerminalState)
    $refIds = @()
    if ($null -ne $Refs) {
        foreach ($ref in @($Refs)) {
            if ($ref -isnot [string] -or [string]::IsNullOrWhiteSpace($ref)) {
                throw [System.ArgumentException]::new('GIT-INVALID-EVIDENCE: ref identity must be nonempty text.')
            }
            if ($ref.Length -gt 256) {
                throw [System.InvalidOperationException]::new('GIT-EVIDENCE-BOUND: ref identity exceeds the bound.')
            }
            $refIds += $ref
        }
    }
    if ($refIds.Count -gt 64) {
        throw [System.InvalidOperationException]::new('GIT-EVIDENCE-BOUND: ref identity count exceeds the bound.')
    }
    $redacted = Get-GitRedactedText -Text $StatusText -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) {
        throw [System.InvalidOperationException]::new('GIT-EVIDENCE-FAILED: evidence redaction failed closed.')
    }
    return @{
        runId         = [string]$Binding['runId']
        terminalState = $TerminalState
        owner         = [string]$Binding['owner']
        text          = [string]$redacted.text
        bytes         = [int]$redacted.bytes
        truncated     = [bool]$redacted.truncated
        evidenceIds   = @('run', 'terminal-state', 'status-refs', 'worktree-ids')
        refCount      = $refIds.Count
    }
}

function Invoke-GitStop {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$LockReleaser
    )
    [void](Test-GitBindingShape -Binding $Binding)
    if ([string]$StartReceipt['runId'] -cne [string]$Binding['runId']) {
        throw [System.InvalidOperationException]::new('GIT-STOP-MISMATCH: start run identity does not match binding.')
    }
    $released = $true
    if ($null -ne $LockReleaser) {
        try {
            $sink = (& $LockReleaser @{ runId = [string]$Binding['runId']; repoRoot = [string]$StartReceipt['repoRoot'] })
            if ($null -ne $sink -and $sink -is [hashtable] -and $sink.ContainsKey('released')) {
                $released = [bool]$sink['released']
            }
        } catch {
            throw [System.InvalidOperationException]::new("GIT-STOP-FAILED: lock release failed: $($_.Exception.Message)")
        }
    }
    return @{
        runId     = [string]$Binding['runId']
        stopPhase = 'none-required'
        released  = $released
        owner     = [string]$Binding['owner']
    }
}

function Invoke-GitVerifyCleanup {
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
        [scriptblock]$GitRunner,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe
    )
    [void](Test-GitBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($table in @($Allocation, $StartReceipt)) {
        if ([string]$table['runId'] -cne $runId) {
            throw [System.InvalidOperationException]::new('GIT-CLEANUP-MISMATCH: allocation/start run identity does not match binding.')
        }
    }
    if ($null -eq $FileProbe) {
        throw [System.ArgumentException]::new('GIT-MISSING-PROBE: a FileProbe seam is required; cleanup is verified, never assumed.')
    }
    $runRoot = [string]$Allocation['runRoot']
    $repoRoot = [string]$Allocation['repoRoot']
    [void](Test-GitRunRootShape -RunRoot $runRoot -ExpectedRunId $runId)
    if ($repoRoot -ine $runRoot) {
        $prefix = $runRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $repoRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new("GIT-FOREIGN-ROOT: allocation repo root is outside the owned run root: $repoRoot")
        }
    }
    $report = (& $FileProbe @{ runRoot = $runRoot; path = $runRoot; expectedRunId = $runId; kind = 'cleanup-scan' })
    if ($null -eq $report -or $report -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('GIT-PROBE-INVALID: cleanup probe must return a hashtable.')
    }
    if ([bool]$report['uncertain']) {
        throw [System.InvalidOperationException]::new('GIT-RECONCILIATION-REQUIRED: uncertain cleanup residue; original outcome preserved, cleanup non-green.')
    }
    $foreignPresent = [bool]$report['foreignPresent']
    $ownedPresent = [bool]$report['ownedPresent']
    $locksHeld = [bool]$report['locksHeld']
    if ($ownedPresent -or $locksHeld) {
        return @{
            runId            = $runId
            ownedRoot        = $runRoot
            cleaned          = $false
            cleanupState     = 'ReconciliationRequired'
            preservedForeign = $foreignPresent
            evidenceIds      = @('owned-residue', 'locks')
        }
    }
    return @{
        runId            = $runId
        ownedRoot        = $runRoot
        cleaned          = $true
        cleanupState     = 'CleanupVerified'
        preservedForeign = $foreignPresent
        evidenceIds      = @('roots-absent', 'locks-released', 'foreign-preserved')
    }
}
