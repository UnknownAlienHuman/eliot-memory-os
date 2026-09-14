<#
.SYNOPSIS
    PowerShell self-test suite for the #913 D-INT-GIT isolated provider (cases 1-22).

.DESCRIPTION
    Containment (scripts/tests/test_integration_harness_git.py, WRITER owned):
    invoked as `pwsh -NoProfile -NonInteractive -File <this path> -CaseId <id>`
    with a positive integer 1..22, this file emits EXACTLY ONE bounded versioned
    JSON object to stdout with the closed field set:
      suite, case_id, schema_version, outcome, identity, content_digest,
      truncated_bytes
    outcome is one of Passed | AssertionFailed | TimedOut | ProcessCrashed |
    InfrastructureBlocked | UnsupportedExternalCredential | HarnessError |
    Cancelled | NotExecutedDueToPriorContamination | Skipped. Only Passed with
    process exit 0 verifies green. content_digest is the SHA-256 hex of the exact
    bytes of this file. identity is always "913/<case_id>".

    Without -CaseId this file is a diagnostic entrypoint: it executes all cases
    1..22 in-process and reports each identity plus its outcome.

    Each case asserts ACTUAL Git provider behavior against the real
    scripts/integration/IntegrationHarness.Git.psm1 module (imported
    conditionally) using injected fake seams only (fake GitRunner, FileWriter,
    FileProbe, entropy, clock). Real logic runs over fakes; no live git is
    spawned, no network is touched, and no user config is read. When the Git
    module is absent every case fails closed honestly with HarnessError (never
    a pass). This suite imports IntegrationHarness.Git.psm1 only and never
    mutates Core/Model/Store/Runtime state, inventory, workflows, or Rust.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 22)]
    [int]$CaseId = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SuiteName = 'IntegrationHarness.Git'
$script:SchemaVersion = 'harness-git-case-result-v1'
$script:MinCaseId = 1
$script:MaxCaseId = 22
$script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:GitModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\integration\IntegrationHarness.Git.psm1'))
$script:MaxModuleSourceBytes = 1048576

$script:ModulesAvailable = $false
$script:ImportDetail = 'not-attempted'
try {
    if (Test-Path -LiteralPath $script:GitModulePath -PathType Leaf) {
        Import-Module -Name $script:GitModulePath -ErrorAction Stop
        $script:ModulesAvailable = $true
        $script:ImportDetail = 'imported'
    }
    else {
        $script:ImportDetail = 'module-file-absent'
    }
}
catch {
    $script:ModulesAvailable = $false
    $script:ImportDetail = 'import-failed'
}

$script:FakeCommitId = 'a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4'
$script:FakeTreeId = 'e5f60718e5f60718e5f60718e5f60718e5f60718'
$script:FakeState = @{ statusText = ''; foreignPresent = $false; fixtureDigestOverride = $null }

function Get-GitFileDigest {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

try {
    $script:SuiteDigest = Get-GitFileDigest $PSCommandPath
}
catch {
    $script:SuiteDigest = '0000000000000000000000000000000000000000000000000000000000000000'
}

function New-GitAssertionScope {
    Write-Output -NoEnumerate ([Collections.Generic.List[string]]::new())
}

function Assert-GitTrue {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not $Condition) {
        [void]$Failures.Add($Name)
    }
}

function Test-GitRejects {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Check,
        [string]$MustMatch = $null
    )
    try {
        $null = (& $Check)
        [void]$Failures.Add("$Name-no-throw")
    }
    catch {
        if ($null -ne $MustMatch -and $MustMatch -ne '' -and $_.Exception.Message -cnotmatch $MustMatch) {
            $detail = [string]$_.Exception.Message
            if ($detail.Length -gt 160) { $detail = $detail.Substring(0, 160) }
            [void]$Failures.Add("$Name-wrong-error<$detail>")
        }
    }
}

function Get-GitTestBinding {
    param([string]$RunId = '0123456789abcdef0123456789abcdef')
    $deadline = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
    return @{
        runId            = $RunId
        testClass        = 'GIT'
        providerName     = 'git-provider-owner'
        providerRevision = 'eliot.integration.git-provider.v1'
        owner            = 'git-test-owner'
        generation       = 1
        deadlineUtc      = $deadline
    }
}

function Get-GitTestRequirement {
    return @{
        testClass        = 'GIT'
        providerRevision = 'eliot.integration.git-provider.v1'
        fixtureProfile   = 'git-fixture-topology-v1'
    }
}

function Get-GitTestLock {
    return @{
        artifact = 'git.exe'
        version  = '2.55.0'
    }
}

function New-GitFakeRunner {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Collections.Generic.List[object]]$CallLog = $null,
        [hashtable]$State = $null
    )
    if ($null -eq $State) { $State = $script:FakeState }
    $commit = $script:FakeCommitId
    $tree = $script:FakeTreeId
    $runner = {
        param($call)
        if ($null -ne $CallLog) { [void]$CallLog.Add($call) }
        [void](Test-GitCommandShape -Command ([string]$call['command']) -Argv @($call['argv']))
        $cmd = [string]$call['command']
        $argv = @($call['argv'])
        if ($cmd -ceq 'init') { return @{ exit = 0; stdout = 'Initialized empty Git repository'; uncertain = $false } }
        if ($cmd -ceq 'config') {
            if ($argv.Count -eq 2 -and $argv[0] -ceq '--local' -and $argv[1] -ceq '--list') {
                return @{ exit = 0; stdout = "user.name=eliot-fixture-author`nuser.email=fixture-author@example.invalid`ncommit.gpgsign=false`ncore.autocrlf=false`ncore.hooksPath="; uncertain = $false }
            }
            return @{ exit = 0; stdout = ''; uncertain = $false }
        }
        if ($cmd -ceq 'add') { return @{ exit = 0; stdout = ''; uncertain = $false } }
        if ($cmd -ceq 'commit') { return @{ exit = 0; stdout = "[main $($commit.Substring(0,7))] eliot git-provider fixture commit"; uncertain = $false } }
        if ($cmd -ceq 'rev-parse') {
            if ($argv.Count -eq 2 -and $argv[1] -ceq 'HEAD') { return @{ exit = 0; stdout = $commit; uncertain = $false } }
            if ($argv.Count -eq 1 -and $argv[0] -ceq 'HEAD^{tree}') { return @{ exit = 0; stdout = $tree; uncertain = $false } }
            if ($argv.Count -eq 1 -and $argv[0] -ceq '--git-dir') { return @{ exit = 0; stdout = '.git'; uncertain = $false } }
            return @{ exit = 0; stdout = $commit; uncertain = $false }
        }
        if ($cmd -ceq 'cat-file') {
            if ($argv.Count -eq 2 -and $argv[1] -ceq $commit) { return @{ exit = 0; stdout = 'commit'; uncertain = $false } }
            if ($argv.Count -eq 2 -and $argv[1] -ceq $tree) { return @{ exit = 0; stdout = 'tree'; uncertain = $false } }
            return @{ exit = 0; stdout = 'commit'; uncertain = $false }
        }
        if ($cmd -ceq 'show-ref') { return @{ exit = 0; stdout = "$commit HEAD`n$commit refs/heads/main"; uncertain = $false } }
        if ($cmd -ceq 'worktree') { return @{ exit = 0; stdout = "worktree $RepoRoot`nHEAD $commit`nbranch refs/heads/main`n"; uncertain = $false } }
        if ($cmd -ceq 'status') { return @{ exit = 0; stdout = [string]$State.statusText; uncertain = $false } }
        if ($cmd -ceq 'reset') {
            $State.statusText = ''
            return @{ exit = 0; stdout = ''; uncertain = $false }
        }
        if ($cmd -ceq 'log' -or $cmd -ceq 'hash-object') { return @{ exit = 0; stdout = $commit; uncertain = $false } }
        return @{ exit = 0; stdout = ''; uncertain = $false }
    }.GetNewClosure()
    return $runner
}

function New-GitFakeWriter {
    $writer = {
        param($request)
        $bytes = [byte[]]$request['bytes']
        $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
        $digest = ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
        return @{ digest = $digest; path = [string]$request['path'] }
    }.GetNewClosure()
    return $writer
}

function New-GitFakeProbe {
    param([hashtable]$State = $null)
    if ($null -eq $State) { $State = $script:FakeState }
    $probe = {
        param($request)
        $kind = [string]$request['kind']
        if ($kind -ceq 'owner-marker') { return @{ markerValid = $true } }
        if ($kind -ceq 'fixture-bytes') {
            if ($null -ne $State.fixtureDigestOverride) {
                return @{ digest = [string]$State.fixtureDigestOverride }
            }
            return @{ digest = 'c534928527968880e7989b782a683a08b9de304d64209af25fa875ad40b612a4' }
        }
        if ($kind -ceq 'cleanup-scan') {
            return @{ ownedPresent = $false; foreignPresent = [bool]$State.foreignPresent; locksHeld = $false; uncertain = $false }
        }
        if ($kind -ceq 'foreign-scan') { return @{ foreignPresent = [bool]$State.foreignPresent } }
        return @{ reparse = $false; foreignMarker = $false; nestedForeignRepo = $false }
    }.GetNewClosure()
    return $probe
}

function Get-GitTestAllocation {
    param([hashtable]$Binding)
    if ($null -eq $Binding) { $Binding = Get-GitTestBinding }
    $plan = Invoke-GitPlan -Binding $Binding -Requirement (Get-GitTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $entropy = { return 'abcdef01' }
    return (Invoke-GitAllocate -Binding $Binding -Plan $plan -BaseTemp $base -Entropy $entropy)
}

function Get-GitTestStartReceipt {
    param([hashtable]$Binding, [hashtable]$Allocation)
    if ($null -eq $Binding) { $Binding = Get-GitTestBinding }
    if ($null -eq $Allocation) { $Allocation = Get-GitTestAllocation $Binding }
    $runner = New-GitFakeRunner -RepoRoot $Allocation['repoRoot']
    $writer = New-GitFakeWriter
    return (Invoke-GitStart -Binding $Binding -Allocation $Allocation -GitRunner $runner -FileWriter $writer)
}

# ---------------------------------------------------------------------------
# Case 1: exact provider/schema/revision/Git requirement.
# ---------------------------------------------------------------------------
function Test-GitCase1 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $receipt = Invoke-GitValidateRequirement -Binding $binding -Requirement (Get-GitTestRequirement) -Lock (Get-GitTestLock)
    Assert-GitTrue $Failures ([bool]$receipt['accepted']) '1-accepted'
    Assert-GitTrue $Failures ($receipt['testClass'] -ceq 'GIT') '1-class'
    Assert-GitTrue $Failures ($receipt['providerRevision'] -ceq 'eliot.integration.git-provider.v1') '1-revision'
    Assert-GitTrue $Failures ($receipt['providerName'] -ceq 'git-provider-owner') '1-provider'
    Assert-GitTrue $Failures ($receipt['disposition'] -ceq 'accepted-local') '1-disposition'
    $identity = Get-GitProviderIdentity
    Assert-GitTrue $Failures ($identity['interfaceVersion'] -ceq 'eliot.integration.harness-provider.v1') '1-interface'
    Assert-GitTrue $Failures ($identity['providerRevision'] -ceq 'eliot.integration.git-provider.v1') '1-identity-revision'
}

# ---------------------------------------------------------------------------
# Case 2: unsupported class/network/production-SCM requirement remains explicit.
# ---------------------------------------------------------------------------
function Test-GitCase2 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $lock = Get-GitTestLock
    foreach ($class in @('REMOTE', 'NETWORK', 'STORE', 'RUNTIME', 'PRODUCTION-SCM')) {
        $req = @{ testClass = $class; providerRevision = 'eliot.integration.git-provider.v1' }
        Test-GitRejects $Failures "2-class-$class" { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $lock } 'GIT-UNSUPPORTED-EXTERNAL'
    }
    $netReq = @{ testClass = 'GIT'; providerRevision = 'eliot.integration.git-provider.v1'; remote = 'https://example.invalid/repo.git' }
    Test-GitRejects $Failures '2-remote-url' { Invoke-GitValidateRequirement -Binding $binding -Requirement $netReq -Lock $lock } 'GIT-UNSUPPORTED-EXTERNAL'
    $prodReq = @{ testClass = 'GIT'; providerRevision = 'eliot.integration.git-provider.v1'; provider = 'github-production' }
    Test-GitRejects $Failures '2-production' { Invoke-GitValidateRequirement -Binding $binding -Requirement $prodReq -Lock $lock } 'GIT-UNSUPPORTED-EXTERNAL'
    $badRev = @{ testClass = 'GIT'; providerRevision = 'eliot.integration.git-provider.v9' }
    Test-GitRejects $Failures '2-bad-revision' { Invoke-GitValidateRequirement -Binding $binding -Requirement $badRev -Lock $lock } 'GIT-UNSUPPORTED-REVISION'
}

# ---------------------------------------------------------------------------
# Case 3: deterministic Plan creates no repo/config/ref/worktree.
# ---------------------------------------------------------------------------
function Test-GitCase3 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $req = Get-GitTestRequirement
    $first = Invoke-GitPlan -Binding $binding -Requirement $req
    $second = Invoke-GitPlan -Binding $binding -Requirement $req
    $firstJson = ($first | ConvertTo-Json -Depth 8 -Compress)
    $secondJson = ($second | ConvertTo-Json -Depth 8 -Compress)
    Assert-GitTrue $Failures ($firstJson -ceq $secondJson) '3-deterministic'
    Assert-GitTrue $Failures ([bool]$first['mutationFree']) '3-mutation-free'
    Assert-GitTrue $Failures ($first['resources'].Count -eq 2) '3-two-resources'
    $allocation = Invoke-GitAllocate -Binding $binding -Plan $first -BaseTemp ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) -Entropy { return 'abcdef01' }
    Assert-GitTrue $Failures (-not (Test-Path -LiteralPath $allocation['runRoot'])) '3-no-run-root'
    Assert-GitTrue $Failures (-not (Test-Path -LiteralPath $allocation['repoRoot'])) '3-no-repo'
    Assert-GitTrue $Failures (-not (Test-Path -LiteralPath $allocation['ownerMarkerFile'])) '3-no-marker'
}

# ---------------------------------------------------------------------------
# Case 4: arbitrary subcommand/executable/shell/config/hook/URL/refspec unrepresentable.
# ---------------------------------------------------------------------------
function Test-GitCase4 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    foreach ($network in @('clone', 'fetch', 'pull', 'push', 'remote', 'submodule', 'ls-remote')) {
        Test-GitRejects $Failures "4-network-$network" { Test-GitCommandShape -Command $network -Argv @() } 'GIT-NETWORK-FORBIDDEN'
    }
    Test-GitRejects $Failures '4-unknown-command' { Test-GitCommandShape -Command 'bisect' -Argv @() } 'GIT-UNKNOWN-COMMAND'
    Test-GitRejects $Failures '4-shell-pipe' { Test-GitCommandShape -Command 'status' -Argv @('--porcelain=v1', '|', 'more') } 'GIT-SHELL-FORBIDDEN'
    Test-GitRejects $Failures '4-url' { Test-GitCommandShape -Command 'config' -Argv @('--local', 'remote.origin.url', 'https://example.invalid/x.git') } 'GIT-URL-FORBIDDEN'
    Test-GitRejects $Failures '4-scp' { Test-GitCommandShape -Command 'config' -Argv @('--local', 'x', 'git@example.invalid:y.git') } 'GIT-URL-FORBIDDEN'
    Test-GitRejects $Failures '4-dash-c' { Test-GitCommandShape -Command 'status' -Argv @('-c', 'core.hooksPath=/tmp/x') } 'GIT-CONFIG-FORBIDDEN'
    Test-GitRejects $Failures '4-git-dir' { Test-GitCommandShape -Command 'status' -Argv @('--git-dir=/tmp/other') } 'GIT-DISCOVERY-FORBIDDEN'
    Test-GitRejects $Failures '4-credential' { Test-GitCommandShape -Command 'config' -Argv @('--local', 'credential.helper', 'store') } 'GIT-CREDENTIAL-FORBIDDEN'
    Test-GitRejects $Failures '4-config-key' { Test-GitConfigKey -Key 'core.sshCommand' } 'GIT-CONFIG-FORBIDDEN'
    Test-GitRejects $Failures '4-unknown-op' { Test-GitClosedOperation -Operation 'Clone' } 'HARNESS-UNKNOWN-OPERATION'
    Test-GitRejects $Failures '4-dispatcher-unknown' {
        Invoke-GitProviderOperation -Operation 'Clone' -Provider @{} -Binding (Get-GitTestBinding)
    } 'HARNESS-UNKNOWN-OPERATION'
}

# ---------------------------------------------------------------------------
# Case 5: approved Git identity and unavailable/invalid distinction.
# ---------------------------------------------------------------------------
function Test-GitCase5 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $req = Get-GitTestRequirement
    $lockInfo = Get-GitLockIdentity
    Assert-GitTrue $Failures ($lockInfo['artifact'] -ceq 'git.exe') '5-lock-artifact'
    Assert-GitTrue $Failures ($lockInfo['minimumVersion'] -ceq '2.40.0') '5-lock-minimum'
    $missing = @{ artifact = 'git.exe' }
    Test-GitRejects $Failures '5-missing-version' { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $missing } 'GIT-TOOL-UNAVAILABLE'
    $empty = @{ artifact = ''; version = '' }
    Test-GitRejects $Failures '5-empty-lock' { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $empty } 'GIT-TOOL-UNAVAILABLE'
    $caller = @{ artifact = 'C:\Tools\custom-git.exe'; version = '9.9.9' }
    Test-GitRejects $Failures '5-caller-exe' { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $caller } 'GIT-LOCK-MISMATCH'
    $old = @{ artifact = 'git.exe'; version = '2.30.1' }
    Test-GitRejects $Failures '5-old-version' { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $old } 'GIT-LOCK-MISMATCH'
    $garbage = @{ artifact = 'git.exe'; version = 'not-a-version' }
    Test-GitRejects $Failures '5-garbage-version' { Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock $garbage } 'GIT-LOCK-MISMATCH'
    $good = Invoke-GitValidateRequirement -Binding $binding -Requirement $req -Lock (Get-GitTestLock)
    Assert-GitTrue $Failures ([bool]$good['accepted']) '5-good-accepted'
}

# ---------------------------------------------------------------------------
# Case 6: canonical repo root under exact owned run root.
# ---------------------------------------------------------------------------
function Test-GitCase6 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $leaf = Split-Path -Leaf $allocation['runRoot']
    Assert-GitTrue $Failures ($leaf -ceq ('eliot-git-{0}-abcdef01' -f $binding['runId'])) '6-canonical-leaf'
    Assert-GitTrue $Failures ($allocation['repoRoot'] -ceq (Join-Path $allocation['runRoot'] 'repo')) '6-repo-child'
    Assert-GitTrue $Failures ($allocation['ownerMarker'] -ceq 'eliot-harness-owned-root-v1') '6-owner-marker'
    Assert-GitTrue $Failures ((Split-Path -Leaf $allocation['ownerMarkerFile']) -ceq '.eliot-harness-owner.json') '6-marker-file'
    Assert-GitTrue $Failures ($allocation['topology'] -ceq 'single-repo') '6-topology'
    [void](Test-GitRunRootShape -RunRoot $allocation['runRoot'] -ExpectedRunId $binding['runId'])
    Assert-GitTrue $Failures $true '6-shape-accepted'
    Test-GitRejects $Failures '6-source-root' { Test-GitRunRootShape -RunRoot $script:RepoRoot -ExpectedRunId $binding['runId'] } 'GIT-FOREIGN-ROOT'
}

# ---------------------------------------------------------------------------
# Case 7: path/reparse/symlink/nested foreign repo/owner-marker escape rejected.
# ---------------------------------------------------------------------------
function Test-GitCase7 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $runRoot = $allocation['runRoot']
    $runId = $binding['runId']
    Test-GitRejects $Failures '7-traversal' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot '..\..\Windows\System32') -ExpectedRunId $runId } 'GIT-PATH-ESCAPE'
    Test-GitRejects $Failures '7-absolute-escape' { Resolve-GitOwnedPath -RunRoot $runRoot -Path 'C:\Windows\System32' -ExpectedRunId $runId } 'GIT-PATH-ESCAPE'
    Test-GitRejects $Failures '7-reserved-leaf' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'NUL') -ExpectedRunId $runId } 'GIT-RESERVED-PATH'
    Test-GitRejects $Failures '7-reserved-segment' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'repo\COM1\fixture.txt') -ExpectedRunId $runId } 'GIT-RESERVED-PATH'
    $reparseProbe = { param($request) return @{ reparse = $true; foreignMarker = $false; nestedForeignRepo = $false } }
    Test-GitRejects $Failures '7-reparse' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'repo') -ExpectedRunId $runId -FileProbe $reparseProbe } 'GIT-REPARSE-ESCAPE'
    $foreignProbe = { param($request) return @{ reparse = $false; foreignMarker = $true; nestedForeignRepo = $false } }
    Test-GitRejects $Failures '7-foreign-marker' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'repo') -ExpectedRunId $runId -FileProbe $foreignProbe } 'GIT-FOREIGN-ROOT'
    $nestedProbe = { param($request) return @{ reparse = $false; foreignMarker = $false; nestedForeignRepo = $true } }
    Test-GitRejects $Failures '7-nested-foreign' { Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'repo\other') -ExpectedRunId $runId -FileProbe $nestedProbe } 'GIT-FOREIGN-REPO'
    $okProbe = { param($request) return @{ reparse = $false; foreignMarker = $false; nestedForeignRepo = $false } }
    $resolved = Resolve-GitOwnedPath -RunRoot $runRoot -Path (Join-Path $runRoot 'repo') -ExpectedRunId $runId -FileProbe $okProbe
    Assert-GitTrue $Failures ($resolved -ceq $allocation['repoRoot']) '7-owned-accepted'
}

# ---------------------------------------------------------------------------
# Case 8: source checkout and other run's repository/worktree never mutated.
# ---------------------------------------------------------------------------
function Test-GitCase8 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $runnerCalls = New-Object Collections.Generic.List[object]
    $writerCalls = New-Object Collections.Generic.List[object]
    $runner = New-GitFakeRunner -RepoRoot $script:RepoRoot -CallLog $runnerCalls
    $writer = { param($request) [void]$writerCalls.Add($request); return @{ digest = 'c534928527968880e7989b782a683a08b9de304d64209af25fa875ad40b612a4'; path = [string]$request['path'] } }.GetNewClosure()
    $sourceAllocation = @{
        runId          = $binding['runId']
        runRoot        = $script:RepoRoot
        repoRoot       = $script:RepoRoot
        worktreeRoot   = (Join-Path $script:RepoRoot 'worktrees')
        logRoot        = (Join-Path $script:RepoRoot 'logs')
        fixtureDigest  = 'c534928527968880e7989b782a683a08b9de304d64209af25fa875ad40b612a4'
    }
    Test-GitRejects $Failures '8-source-adoption' { Invoke-GitStart -Binding $binding -Allocation $sourceAllocation -GitRunner $runner -FileWriter $writer } 'GIT-FOREIGN-ROOT'
    Assert-GitTrue $Failures ($runnerCalls.Count -eq 0) '8-no-runner-calls'
    Assert-GitTrue $Failures ($writerCalls.Count -eq 0) '8-no-writer-calls'
    $otherRunId = 'ffffffffffffffffffffffffffffffff'
    $otherBinding = Get-GitTestBinding -RunId $otherRunId
    $ownAllocation = Get-GitTestAllocation $binding
    Test-GitRejects $Failures '8-cross-run' { Invoke-GitStart -Binding $otherBinding -Allocation $ownAllocation -GitRunner $runner -FileWriter $writer } 'GIT-START-MISMATCH'
    Assert-GitTrue $Failures ($runnerCalls.Count -eq 0) '8-cross-run-no-calls'
}

# ---------------------------------------------------------------------------
# Case 9: explicit initial branch/object format and deterministic author/committer/timestamps.
# ---------------------------------------------------------------------------
function Test-GitCase9 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    Assert-GitTrue $Failures ((Get-GitProviderIdentity)['initialBranch'] -ceq 'main') '9-branch'
    Assert-GitTrue $Failures ((Get-GitProviderIdentity)['objectFormat'] -ceq 'sha1') '9-format'
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $calls = New-Object Collections.Generic.List[object]
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot'] -CallLog $calls
    $writer = New-GitFakeWriter
    $receipt = Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter $writer
    $initCall = @($calls | Where-Object { $_['command'] -ceq 'init' })[0]
    Assert-GitTrue $Failures ($initCall['argv'][0] -ceq '--initial-branch=main') '9-init-branch'
    $env = $initCall['env']
    Assert-GitTrue $Failures ($env['GIT_AUTHOR_NAME'] -ceq 'eliot-fixture-author') '9-author-name'
    Assert-GitTrue $Failures ($env['GIT_AUTHOR_EMAIL'] -ceq 'fixture-author@example.invalid') '9-author-email'
    Assert-GitTrue $Failures ($env['GIT_AUTHOR_DATE'] -ceq '2026-01-01T00:00:00+00:00') '9-author-date'
    Assert-GitTrue $Failures ($env['GIT_COMMITTER_NAME'] -ceq 'eliot-fixture-author') '9-committer-name'
    Assert-GitTrue $Failures ($env['GIT_COMMITTER_EMAIL'] -ceq 'fixture-author@example.invalid') '9-committer-email'
    Assert-GitTrue $Failures ($env['GIT_COMMITTER_DATE'] -ceq '2026-01-01T00:00:00+00:00') '9-committer-date'
    Assert-GitTrue $Failures ($receipt['refName'] -ceq 'refs/heads/main') '9-head-ref'
    [void](Test-GitObjectFormat -ObjectId $receipt['commitId'])
    Assert-GitTrue $Failures $true '9-commit-shape'
}

# ---------------------------------------------------------------------------
# Case 10: identity/line-ending/signing/hook/filter/protocol settings scoped.
# ---------------------------------------------------------------------------
function Test-GitCase10 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $calls = New-Object Collections.Generic.List[object]
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot'] -CallLog $calls
    $writer = New-GitFakeWriter
    $null = Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter $writer
    $configCalls = @($calls | Where-Object { $_['command'] -ceq 'config' -and $_['argv'].Count -eq 3 })
    Assert-GitTrue $Failures ($configCalls.Count -eq 5) '10-five-scoped-configs'
    foreach ($call in $configCalls) {
        Assert-GitTrue $Failures ($call['argv'][0] -ceq '--local') '10-local-only'
        [void](Test-GitConfigKey -Key $call['argv'][1])
    }
    $keys = @($configCalls | ForEach-Object { $_['argv'][1] })
    foreach ($required in @('user.name', 'user.email', 'commit.gpgsign', 'core.autocrlf', 'core.hooksPath')) {
        Assert-GitTrue $Failures ($keys -ccontains $required) "10-key-$required"
    }
    $signing = @($configCalls | Where-Object { $_['argv'][1] -ceq 'commit.gpgsign' })[0]
    Assert-GitTrue $Failures ($signing['argv'][2] -ceq 'false') '10-signing-off'
    $hooks = @($configCalls | Where-Object { $_['argv'][1] -ceq 'core.hooksPath' })[0]
    Assert-GitTrue $Failures ($hooks['argv'][2] -ceq '') '10-hooks-empty'
}

# ---------------------------------------------------------------------------
# Case 11: global/system/user config/HOME/credential helpers untouched and unread.
# ---------------------------------------------------------------------------
function Test-GitCase11 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $realHome = $env:HOME
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $calls = New-Object Collections.Generic.List[object]
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot'] -CallLog $calls
    $writer = New-GitFakeWriter
    $null = Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter $writer
    Assert-GitTrue $Failures ($env:HOME -ceq $realHome) '11-real-home-untouched'
    $firstEnv = $calls[0]['env']
    Assert-GitTrue $Failures ($firstEnv['GIT_CONFIG_NOSYSTEM'] -ceq '1') '11-no-system'
    Assert-GitTrue $Failures ([string]$firstEnv['GIT_CONFIG_GLOBAL'] -cne '') '11-global-owned'
    Assert-GitTrue $Failures ([string]$firstEnv['HOME'] -cne [string]$realHome -or [string]$realHome -ceq '') '11-home-overridden'
    Assert-GitTrue $Failures ($firstEnv['HOME'] -ceq (Join-Path $allocation['runRoot'] 'temp')) '11-home-owned-temp'
    Assert-GitTrue $Failures ($firstEnv['GIT_TERMINAL_PROMPT'] -ceq '0') '11-no-prompt'
    $source = [IO.File]::ReadAllText($script:GitModulePath)
    Assert-GitTrue $Failures ($source -cnotmatch 'credential\.helper') '11-no-credential-helper'
    Assert-GitTrue $Failures ($source -cnotmatch '\$env:HOME\s*=') '11-no-home-write'
    Assert-GitTrue $Failures ($source -cnotmatch 'Set-Content.*\.gitconfig') '11-no-gitconfig-write'
}

# ---------------------------------------------------------------------------
# Case 12: only declared fixture bytes materialized and digest is load-bearing.
# ---------------------------------------------------------------------------
function Test-GitCase12 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $bytes = Get-GitFixtureBytes
    Assert-GitTrue $Failures ($bytes.Length -eq 21) '12-fixture-length'
    [void](Test-GitFixtureDigest -Bytes $bytes)
    Assert-GitTrue $Failures $true '12-digest-accepted'
    Test-GitRejects $Failures '12-tampered-bytes' { Test-GitFixtureDigest -Bytes ([Text.Encoding]::UTF8.GetBytes("tampered`n")) } 'GIT-FIXTURE-MISMATCH'
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $lyingWriter = { param($request) return @{ digest = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'; path = [string]$request['path'] } }.GetNewClosure()
    Test-GitRejects $Failures '12-lying-writer' { Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter $lyingWriter } 'GIT-FIXTURE-MISMATCH'
    $script:FakeState.fixtureDigestOverride = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    try {
        $receipt = Get-GitTestStartReceipt $binding $allocation
        $probe = New-GitFakeProbe
        Test-GitRejects $Failures '12-tampered-readiness' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileProbe $probe } 'GIT-NOT-READY'
    }
    finally {
        $script:FakeState.fixtureDigestOverride = $null
    }
}

# ---------------------------------------------------------------------------
# Case 13: exact object/tree/commit/ref/registered/materialized worktree identities verified.
# ---------------------------------------------------------------------------
function Test-GitCase13 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $probe = New-GitFakeProbe
    $readiness = Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$readiness['ready']) '13-ready'
    Assert-GitTrue $Failures ($readiness['commitId'] -ceq $receipt['commitId']) '13-commit-bound'
    Assert-GitTrue $Failures ($readiness['treeId'] -ceq $receipt['treeId']) '13-tree-bound'
    Assert-GitTrue $Failures ($readiness['evidenceIds'].Count -eq 8) '13-eight-evidence'
    $wrongCommitRunner = {
        param($call)
        if ([string]$call['command'] -ceq 'rev-parse') { return @{ exit = 0; stdout = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'; uncertain = $false } }
        $inner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
        return (& $inner $call)
    }.GetNewClosure()
    Test-GitRejects $Failures '13-exit-zero-wrong-id' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $wrongCommitRunner -FileProbe $probe } 'GIT-NOT-READY'
}

# ---------------------------------------------------------------------------
# Case 14: foreign/preexisting unowned refs/worktrees rejected without adoption.
# ---------------------------------------------------------------------------
function Test-GitCase14 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $probe = New-GitFakeProbe
    $refCommitId = $script:FakeCommitId
    $foreignRefRunner = {
        param($call)
        if ([string]$call['command'] -ceq 'show-ref') {
            return @{ exit = 0; stdout = "$refCommitId HEAD`n$refCommitId refs/heads/main`n$refCommitId refs/heads/foreign-takeover"; uncertain = $false }
        }
        $inner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
        return (& $inner $call)
    }.GetNewClosure()
    Test-GitRejects $Failures '14-foreign-ref' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $foreignRefRunner -FileProbe $probe } 'GIT-FOREIGN-REF'
    $foreignWtRunner = {
        param($call)
        if ([string]$call['command'] -ceq 'worktree') {
            return @{ exit = 0; stdout = "worktree $($allocation['repoRoot'])`nHEAD $refCommitId`nbranch refs/heads/main`n`nworktree C:\Windows\Temp\foreign-wt`nHEAD $refCommitId`nbranch refs/heads/main`n"; uncertain = $false }
        }
        $inner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
        return (& $inner $call)
    }.GetNewClosure()
    Test-GitRejects $Failures '14-foreign-worktree' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $foreignWtRunner -FileProbe $probe } 'GIT-PATH-ESCAPE'
}

# ---------------------------------------------------------------------------
# Case 15: readiness requires owner/config/fixture/topology evidence, not init/status.
# ---------------------------------------------------------------------------
function Test-GitCase15 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $noMarkerProbe = {
        param($request)
        if ([string]$request['kind'] -ceq 'owner-marker') { return @{ markerValid = $false } }
        $inner = New-GitFakeProbe
        return (& $inner $request)
    }.GetNewClosure()
    Test-GitRejects $Failures '15-no-owner' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileProbe $noMarkerProbe } 'GIT-NOT-READY'
    $emptyConfigRunner = {
        param($call)
        if ([string]$call['command'] -ceq 'config') { return @{ exit = 0; stdout = ''; uncertain = $false } }
        $inner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
        return (& $inner $call)
    }.GetNewClosure()
    $probe = New-GitFakeProbe
    Test-GitRejects $Failures '15-empty-config' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $emptyConfigRunner -FileProbe $probe } 'GIT-NOT-READY'
    Test-GitRejects $Failures '15-no-probe' { Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner } 'GIT-MISSING-PROBE'
}

# ---------------------------------------------------------------------------
# Case 16: reset restores exact allowed baseline or marks contamination.
# ---------------------------------------------------------------------------
function Test-GitCase16 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $script:FakeState.statusText = ''
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $probe = New-GitFakeProbe
    $clean = Invoke-GitResetForTest -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileWriter (New-GitFakeWriter) -Disposition 'baseline-verify' -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$clean['reset']) '16-clean-reset'
    Assert-GitTrue $Failures ($clean['baseline'] -ceq 'already-clean') '16-already-clean'
    $script:FakeState.statusText = ' M fixture.txt'
    $dirtyBlocked = Invoke-GitResetForTest -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileWriter (New-GitFakeWriter) -Disposition 'baseline-verify' -FileProbe $probe
    Assert-GitTrue $Failures (-not [bool]$dirtyBlocked['reset']) '16-dirty-blocked'
    Assert-GitTrue $Failures ([bool]$dirtyBlocked['contaminated']) '16-dirty-contaminated'
    $restored = Invoke-GitResetForTest -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileWriter (New-GitFakeWriter) -Disposition 'disposable-fixture' -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$restored['reset']) '16-disposable-restored'
    Assert-GitTrue $Failures ($restored['baseline'] -ceq 'restored-disposable') '16-restored-label'
    Assert-GitTrue $Failures ($restored['commitId'] -ceq $receipt['commitId']) '16-head-stable'
    $script:FakeState.statusText = ''
    $script:FakeState.foreignPresent = $true
    try {
        $foreign = Invoke-GitResetForTest -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileWriter (New-GitFakeWriter) -Disposition 'disposable-fixture' -FileProbe $probe
        Assert-GitTrue $Failures (-not [bool]$foreign['reset']) '16-foreign-blocked'
        Assert-GitTrue $Failures ([bool]$foreign['contaminated']) '16-foreign-contaminated'
    }
    finally {
        $script:FakeState.foreignPresent = $false
    }
}

# ---------------------------------------------------------------------------
# Case 17: timeout/lost mutation response requires reconciliation before retry.
# ---------------------------------------------------------------------------
function Test-GitCase17 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $uncertainRunner = { param($call) return @{ exit = 0; stdout = ''; uncertain = $true } }.GetNewClosure()
    Test-GitRejects $Failures '17-uncertain-init' { Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $uncertainRunner -FileWriter (New-GitFakeWriter) } 'GIT-RECONCILIATION-REQUIRED'
    $reconciled = Get-GitTestStartReceipt $binding $allocation
    Assert-GitTrue $Failures ([bool]$reconciled['verified']) '17-reconciled-verified'
    $probe = New-GitFakeProbe
    $steadyRunner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $readiness = Invoke-GitObserveReadiness -Binding $binding -Allocation $allocation -StartReceipt $reconciled -GitRunner $steadyRunner -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$readiness['ready']) '17-ready-after-reconcile'
}

# ---------------------------------------------------------------------------
# Case 18: bounded evidence retains IDs without config/content/credential/private-path canaries.
# ---------------------------------------------------------------------------
function Test-GitCase18 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $secret = 'hunter2-secret-token'
    $statusText = "M fixture.txt user.email=fixture-author@example.invalid token=hunter2-secret-token path=C:\Users\someone\repo"
    $evidence = Invoke-GitCollectEvidence -Binding $binding -TerminalState 'Passed' -StatusText $statusText -Refs @('refs/heads/main') -Secrets @($secret)
    Assert-GitTrue $Failures ($evidence['text'] -cnotmatch 'hunter2') '18-canary-absent'
    Assert-GitTrue $Failures ($evidence['text'] -match 'redacted-git-secret') '18-redacted'
    Assert-GitTrue $Failures ($evidence['text'] -cnotmatch 'someone') '18-user-path-absent'
    Assert-GitTrue $Failures ($evidence['refCount'] -eq 1) '18-ref-count'
    Assert-GitTrue $Failures (-not [bool]$evidence['truncated']) '18-not-truncated'
    $longText = ('head-secret=hunter2-secret-token; tail-padding=' + ('x' * 5000) + '; tail-secret=hunter2-secret-token')
    $long = Invoke-GitCollectEvidence -Binding $binding -TerminalState 'Passed' -StatusText $longText -Secrets @($secret) -MaxBytes 1024
    Assert-GitTrue $Failures ([bool]$long['truncated']) '18-truncated'
    Assert-GitTrue $Failures ([int]$long['bytes'] -le 1024) '18-bounded'
    Assert-GitTrue $Failures ($long['text'] -cnotmatch 'hunter2') '18-long-canary-absent'
    Test-GitRejects $Failures '18-bad-disposition' { Invoke-GitCollectEvidence -Binding $binding -TerminalState 'Green' -StatusText 'x' } 'GIT-INVALID-DISPOSITION'
}

# ---------------------------------------------------------------------------
# Case 19: cleanup targets exact owned topology, verifies registry/locks/roots, preserves foreign.
# ---------------------------------------------------------------------------
function Test-GitCase19 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $probe = New-GitFakeProbe
    $script:FakeState.foreignPresent = $false
    $clean = Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$clean['cleaned']) '19-cleaned'
    Assert-GitTrue $Failures ($clean['cleanupState'] -ceq 'CleanupVerified') '19-verified'
    Assert-GitTrue $Failures ($clean['ownedRoot'] -ceq $allocation['runRoot']) '19-owned-root'
    $script:FakeState.foreignPresent = $true
    try {
        $withForeign = Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $probe
        Assert-GitTrue $Failures ([bool]$withForeign['cleaned']) '19-foreign-cleaned'
        Assert-GitTrue $Failures ([bool]$withForeign['preservedForeign']) '19-foreign-preserved'
    }
    finally {
        $script:FakeState.foreignPresent = $false
    }
    $residueProbe = { param($request) return @{ ownedPresent = $true; foreignPresent = $false; locksHeld = $false; uncertain = $false } }.GetNewClosure()
    $residue = Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $residueProbe
    Assert-GitTrue $Failures (-not [bool]$residue['cleaned']) '19-residue-not-clean'
    Assert-GitTrue $Failures ($residue['cleanupState'] -ceq 'ReconciliationRequired') '19-residue-reconcile'
    $foreignAllocation = @{
        runId         = $binding['runId']
        runRoot       = 'C:\Windows\System32'
        repoRoot      = 'C:\Windows\System32'
        fixtureDigest = 'c534928527968880e7989b782a683a08b9de304d64209af25fa875ad40b612a4'
    }
    Test-GitRejects $Failures '19-foreign-root' { Invoke-GitVerifyCleanup -Binding $binding -Allocation $foreignAllocation -StartReceipt $receipt -FileProbe $probe } 'GIT-FOREIGN-ROOT'
}

# ---------------------------------------------------------------------------
# Case 20: no Core/inventory/Store/Runtime/workflow/Rust/source-repo/global/network mutation or test-pass authority.
# ---------------------------------------------------------------------------
function Test-GitCase20 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $source = [IO.File]::ReadAllText($script:GitModulePath)
    Assert-GitTrue $Failures ($source -cnotmatch 'todo!') '20-no-todo'
    Assert-GitTrue $Failures ($source -cnotmatch 'unimplemented!') '20-no-unimplemented'
    Assert-GitTrue $Failures ($source -cnotmatch 'run_case') '20-no-bridge-run-case'
    Assert-GitTrue $Failures ($source -cnotmatch 'verify_result_bytes') '20-no-bridge-verify'
    Assert-GitTrue $Failures ($source -cnotmatch 'IntegrationHarness\.Core') '20-no-core-import'
    Assert-GitTrue $Failures ($source -cnotmatch 'IntegrationHarness\.Store') '20-no-store-import'
    Assert-GitTrue $Failures ($source -cnotmatch 'IntegrationHarness\.Runtime') '20-no-runtime-import'
    Assert-GitTrue $Failures ($source -cnotmatch 'IntegrationHarness\.Model') '20-no-model-import'
    Assert-GitTrue $Failures ($source -cnotmatch 'Start-Process') '20-no-start-process'
    Assert-GitTrue $Failures ($source -cnotmatch 'Invoke-Expression') '20-no-invoke-expression'
    Assert-GitTrue $Failures ($source -cnotmatch 'Invoke-RestMethod') '20-no-rest-method'
    Assert-GitTrue $Failures ($source -cnotmatch 'Net\.WebClient') '20-no-webclient'
    $ops = Get-GitClosedOperations
    Assert-GitTrue $Failures ($ops.Count -eq 9) '20-nine-ops'
    foreach ($op in @('ValidateRequirement', 'Plan', 'Allocate', 'Start', 'ObserveReadiness', 'ResetForTest', 'CollectEvidence', 'Stop', 'VerifyCleanup')) {
        Assert-GitTrue $Failures ($ops -ccontains $op) ("20-op-$op")
    }
    $exported = @(Get-Command -Module 'IntegrationHarness.Git' -CommandType Function -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Assert-GitTrue $Failures ($exported -contains 'Invoke-GitValidateRequirement') '20-exports-validate'
    Assert-GitTrue $Failures ($exported -contains 'Invoke-GitVerifyCleanup') '20-exports-cleanup'
    $selfSource = [IO.File]::ReadAllText($PSCommandPath)
    Assert-GitTrue $Failures ($selfSource -cnotmatch 'IntegrationHarness\.Core\.psm1') '20-tests-no-core-module'
    $stop = Invoke-GitStop -Binding (Get-GitTestBinding) -StartReceipt (Get-GitTestStartReceipt)
    Assert-GitTrue $Failures ($stop['stopPhase'] -ceq 'none-required') '20-stop-noop'
}

# ---------------------------------------------------------------------------
# Case 21: same-operation exact replay creates no duplicate object/ref/worktree; changed profile/config conflicts.
# ---------------------------------------------------------------------------
function Test-GitCase21 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $first = Get-GitTestStartReceipt $binding $allocation
    $calls = New-Object Collections.Generic.List[object]
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot'] -CallLog $calls
    $second = Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter (New-GitFakeWriter) -PriorReceipt $first
    Assert-GitTrue $Failures ($calls.Count -eq 0) '21-no-duplicate-calls'
    Assert-GitTrue $Failures ($second['commitId'] -ceq $first['commitId']) '21-same-commit'
    Assert-GitTrue $Failures ($second['treeId'] -ceq $first['treeId']) '21-same-tree'
    $changed = @{} + $first
    $changed['fixtureDigest'] = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    Test-GitRejects $Failures '21-changed-profile' { Invoke-GitStart -Binding $binding -Allocation $allocation -GitRunner $runner -FileWriter (New-GitFakeWriter) -PriorReceipt $changed } 'GIT-PROFILE-CONFLICT'
    Assert-GitTrue $Failures ($calls.Count -eq 0) '21-conflict-no-calls'
}

# ---------------------------------------------------------------------------
# Case 22: unexpected dirty/foreign state blocks destructive cleanup; disposable policy; idempotent cleanup; uncertain non-green.
# ---------------------------------------------------------------------------
function Test-GitCase22 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-GitTestBinding
    $allocation = Get-GitTestAllocation $binding
    $receipt = Get-GitTestStartReceipt $binding $allocation
    $runner = New-GitFakeRunner -RepoRoot $allocation['repoRoot']
    $probe = New-GitFakeProbe
    $script:FakeState.statusText = ' M fixture.txt'
    $blocked = Invoke-GitResetForTest -Binding $binding -Allocation $allocation -StartReceipt $receipt -GitRunner $runner -FileWriter (New-GitFakeWriter) -Disposition 'baseline-verify' -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$blocked['contaminated']) '22-dirty-blocks-destructive'
    $script:FakeState.statusText = ''
    $first = Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $probe
    $second = Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $probe
    Assert-GitTrue $Failures ([bool]$second['cleaned']) '22-cleaned'
    Assert-GitTrue $Failures ($first['ownedRoot'] -ceq $second['ownedRoot']) '22-idempotent-root'
    Assert-GitTrue $Failures ($first['cleanupState'] -ceq $second['cleanupState']) '22-idempotent-state'
    $uncertainProbe = { param($request) return @{ ownedPresent = $false; foreignPresent = $false; locksHeld = $false; uncertain = $true } }.GetNewClosure()
    Test-GitRejects $Failures '22-uncertain-non-green' { Invoke-GitVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $receipt -FileProbe $uncertainProbe } 'GIT-RECONCILIATION-REQUIRED'
}

$script:CaseTitles = @{
    1  = 'exact provider/schema/revision/Git requirement'
    2  = 'unsupported class/network/production-SCM requirement remains explicit'
    3  = 'deterministic Plan creates no repo/config/ref/worktree'
    4  = 'arbitrary subcommand/executable/shell/config/hook/URL/refspec unrepresentable'
    5  = 'approved Git identity and unavailable/invalid distinction'
    6  = 'canonical repo root under exact owned run root'
    7  = 'path/reparse/symlink/nested foreign repo/owner-marker escape rejected'
    8  = 'source checkout and other run repository/worktree never mutated'
    9  = 'explicit initial branch/object format and deterministic author/committer/timestamps'
    10 = 'identity/line-ending/signing/hook/filter/protocol settings scoped to commands/fixture repo'
    11 = 'global/system/user config/HOME/credential helpers remain untouched and unread as payload'
    12 = 'only declared fixture bytes materialized and digest is load-bearing'
    13 = 'exact object/tree/commit/ref/registered/materialized worktree identities verified beyond exit code'
    14 = 'foreign/preexisting unowned refs/worktrees rejected without adoption'
    15 = 'readiness requires owner/config/fixture/topology evidence, not init/status success'
    16 = 'reset restores exact allowed baseline or marks contamination'
    17 = 'timeout/lost mutation response requires reconciliation before retry'
    18 = 'bounded evidence retains IDs without config/content/credential/private-path canaries'
    19 = 'cleanup targets exact owned topology, verifies registry/locks/roots and preserves foreign state'
    20 = 'no Core/inventory/Store/Runtime/workflow/Rust/source-repo/global/network mutation or test-pass authority'
    21 = 'same-operation exact replay creates no duplicate object/ref/worktree and changed profile/config conflicts'
    22 = 'unexpected dirty/foreign state blocks destructive cleanup; explicit owned disposable changes follow policy; repeated cleanup is idempotent and uncertain residue remains non-green'
}

function Invoke-GitCaseById {
    param([Parameter(Mandatory)][int]$Id)
    $failures = New-GitAssertionScope
    $outcome = 'HarnessError'
    $note = ''
    try {
        $null = & "Test-GitCase$Id" $failures
        if ($failures.Count -gt 0) {
            $outcome = 'AssertionFailed'
            $note = 'git assertion failures: ' + ($failures -join ' | ')
        }
        elseif (-not $script:ModulesAvailable) {
            $outcome = 'HarnessError'
            $note = 'fail-closed: IntegrationHarness.Git module absent (' + $script:ImportDetail + ')'
        }
        else {
            $outcome = 'Passed'
            $note = 'git assertions held over fake seams'
        }
    }
    catch {
        $outcome = 'HarnessError'
        $note = 'fail-closed harness exception: ' + $_.Exception.Message
        if ($failures.Count -gt 0) {
            $note = $note + '; prior assertion failures: ' + ($failures -join ' | ')
        }
    }
    if ($note.Length -gt 2000) {
        $note = $note.Substring(0, 2000)
    }
    return [pscustomobject]@{
        CaseId   = $Id
        Outcome  = $outcome
        Failures = $failures
        Note     = $note
    }
}

function Write-GitCaseResult {
    param([Parameter(Mandatory)][int]$Id, [Parameter(Mandatory)][string]$Outcome)
    $result = [ordered]@{
        suite           = $script:SuiteName
        case_id         = $Id
        schema_version  = $script:SchemaVersion
        outcome         = $Outcome
        identity        = ("913/{0}" -f $Id)
        content_digest  = $script:SuiteDigest
        truncated_bytes = 0
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
}

if ($CaseId -ne 0) {
    $single = $null
    try {
        $single = Invoke-GitCaseById -Id $CaseId
    }
    catch {
        $single = [pscustomobject]@{
            CaseId   = $CaseId
            Outcome  = 'HarnessError'
            Failures = @()
            Note     = 'fail-closed dispatcher exception'
        }
    }
    Write-GitCaseResult -Id $CaseId -Outcome $single.Outcome
    if ($single.Outcome -eq 'Passed') { exit 0 } else { exit 1 }
}

$diagnosticResults = @()
foreach ($id in $script:MinCaseId..$script:MaxCaseId) {
    $diagnosticResults += Invoke-GitCaseById -Id $id
}
'IntegrationHarness.Git diagnostic: {0} cases, modules={1}' -f $diagnosticResults.Count, $script:ImportDetail
foreach ($row in $diagnosticResults) {
    '913/{0} {1} entry_failures={2} title={3}' -f $row.CaseId, $row.Outcome, $row.Failures.Count, $script:CaseTitles[$row.CaseId]
    '  note: {0}' -f $row.Note
}
$passed = @($diagnosticResults | Where-Object { $_.Outcome -eq 'Passed' }).Count
'summary: passed={0} failed={1}' -f $passed, ($diagnosticResults.Count - $passed)
if ($passed -eq $diagnosticResults.Count) { exit 0 } else { exit 1 }
