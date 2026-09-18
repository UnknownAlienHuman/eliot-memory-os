<#
.SYNOPSIS
    PowerShell self-test suite for the #911 D-INT-RUNTIME isolated provider (cases 1-29).

.DESCRIPTION
    Containment (scripts/tests/test_integration_harness_runtime.py, WRITER owned):
    invoked as `pwsh -NoProfile -NonInteractive -File <this path> -CaseId <id>`
    with a positive integer 1..29, this file emits EXACTLY ONE bounded versioned
    JSON object to stdout with the closed field set:
      suite, case_id, schema_version, outcome, identity, content_digest,
      truncated_bytes
    outcome is one of Passed | AssertionFailed | TimedOut | ProcessCrashed |
    InfrastructureBlocked | UnsupportedExternalCredential | HarnessError |
    Cancelled | NotExecutedDueToPriorContamination | Skipped. Only Passed with
    process exit 0 verifies green. content_digest is the SHA-256 hex of the exact
    bytes of this file. identity is always "911/<case_id>".

    Without -CaseId this file is a diagnostic entrypoint: it executes all cases
    1..29 in-process and reports each identity plus its outcome.

    Each case asserts ACTUAL Runtime provider behavior against the real
    scripts/integration/IntegrationHarness.Runtime.psm1 module (imported
    conditionally) using injected fake seams only (fake entropy, namespace
    reservation, acquisition, launcher, owner issuance, process/pipe observers,
    topology client, controller, job/pipe/handle probes, clock). Real logic runs
    over fakes; no live topology is started and nothing is downloaded. When the
    Runtime module is absent every case fails closed honestly with HarnessError
    (never a pass). This suite imports IntegrationHarness.Runtime.psm1 only and
    never mutates Core, Store, or Git state.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 29)]
    [int]$CaseId = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SuiteName = 'IntegrationHarness.Runtime'
$script:SchemaVersion = 'harness-runtime-case-result-v1'
$script:MinCaseId = 1
$script:MaxCaseId = 29
$script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:RuntimeModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\integration\IntegrationHarness.Runtime.psm1'))
$script:MaxModuleSourceBytes = 1048576
$script:RuntimeDigest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'

$script:ModulesAvailable = $false
$script:ImportDetail = 'not-attempted'
try {
    if (Test-Path -LiteralPath $script:RuntimeModulePath -PathType Leaf) {
        Import-Module -Name $script:RuntimeModulePath -ErrorAction Stop
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

function Get-RuntimeFileDigest {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

try {
    $script:SuiteDigest = Get-RuntimeFileDigest $PSCommandPath
}
catch {
    $script:SuiteDigest = '0000000000000000000000000000000000000000000000000000000000000000'
}

function New-RuntimeAssertionScope {
    Write-Output -NoEnumerate ([Collections.Generic.List[string]]::new())
}

function Assert-RuntimeTrue {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not $Condition) {
        [void]$Failures.Add($Name)
    }
}

function Get-RuntimeTestBinding {
    param([string]$RunId = '0123456789abcdef0123456789abcdef')
    $deadline = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
    return @{
        runId            = $RunId
        testClass        = 'RUNTIME'
        providerName     = 'eliot-runtime-windows-isolated'
        providerRevision = 'eliot.integration.runtime-provider.v1'
        owner            = 'runtime-test-owner'
        generation       = 1
        deadlineUtc      = $deadline
    }
}

function Get-RuntimeTestRequirement {
    param([string]$Target = 'host')
    return @{
        testClass        = 'RUNTIME'
        target           = $Target
        providerRevision = 'eliot.integration.runtime-provider.v1'
    }
}

function Get-RuntimeTestLock {
    return @{
        version      = '1.0.0'
        architecture = 'windows-x64'
        peMachine    = '8664'
        peProfile    = 'isolated-foreground'
        sha256       = $script:RuntimeDigest
        artifact     = 'eliot-host.exe'
    }
}

function Get-RuntimeTestAcquisition {
    param([string]$Provenance = 'acquired-verified')
    return {
        param($ctx)
        return @{
            version      = '1.0.0'
            architecture = 'windows-x64'
            peMachine    = '8664'
            peProfile    = 'isolated-foreground'
            digest       = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'
            provenance   = $Provenance
            runtimePath  = 'C:\runtime\eliot-host.exe'
        }
    }.GetNewClosure()
}

function Get-RuntimeTestOwnerIssuance {
    param([string]$Owner = 'runtime-test-owner', [int]$Generation = 1, [int]$Epoch = 1, [string]$Fence = 'fence-01234567')
    return {
        param($ctx)
        return @{ generation = $Generation; fence = $Fence; epoch = $Epoch; owner = $Owner }
    }.GetNewClosure()
}

function Get-RuntimeTestAllocation {
    param([hashtable]$Binding)
    if ($null -eq $Binding) { $Binding = Get-RuntimeTestBinding }
    $plan = Invoke-RuntimePlan -Binding $Binding -Requirement (Get-RuntimeTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservation = { param($ctx) return @{ pipeNamespace = $ctx['pipeNamespace'] } }
    $entropy = { return 'abcdef01' }
    return (Invoke-RuntimeAllocate -Binding $Binding -Plan $plan -BaseTemp $base -Entropy $entropy -NamespaceReservation $reservation)
}

function Get-RuntimeTestLauncher {
    $calls = @{ count = 0 }
    $launcher = { param($in_) $calls['count']++; $n = $calls['count']; return @{ observedPid = (4300 + $n); observedNonce = ('feedface{0:00}' -f $n); containment = 'job-object' } }.GetNewClosure()
    return @{ launcher = $launcher; calls = $calls }
}

function Get-RuntimeTestStartReceipt {
    param([hashtable]$Binding, [hashtable]$Allocation)
    if ($null -eq $Binding) { $Binding = Get-RuntimeTestBinding }
    if ($null -eq $Allocation) { $Allocation = Get-RuntimeTestAllocation $Binding }
    $launcher = Get-RuntimeTestLauncher
    $entropy = { return 'cafef00d' }
    return (Invoke-RuntimeStart -Binding $Binding -Allocation $Allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher.launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy $entropy)
}

function Get-RuntimeTestObservers {
    $proc = { param($ctx) return @{ alive = $true; pid = $ctx['pid'] } }
    $pipe = { param($ctx) return @{ open = $true; pipe = $ctx['pipe'] } }
    return @{ process = $proc; pipe = $pipe }
}

function Get-RuntimeTestClient {
    param([string]$Fence = 'fence-01234567', [int]$Generation = 1, [int]$Epoch = 1, [bool]$Authenticated = $true, [string]$PeerId = 'peer-77aa')
    $comps = @{}
    foreach ($c in @('kernel', 'host', 'governor', 'watchdog', 'bridge')) { $comps[$c] = @{ ready = $true } }
    return {
        param($ctx)
        return @{ peerAuthenticated = $Authenticated; peerId = $PeerId; handshakeDigest = ('ab' * 32); generation = $Generation; fence = $Fence; epoch = $Epoch; components = $comps; pipeNamespace = $ctx['pipeNamespace'] }
    }.GetNewClosure()
}

function Read-RuntimeModuleSource {
    param([Parameter(Mandatory)][string]$Path)
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.Length -gt $script:MaxModuleSourceBytes) {
        throw "module source exceeds byte bound: $Path"
    }
    return [IO.File]::ReadAllText($Path)
}

function Test-RuntimeRejects {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Call
    )
    try {
        [void](& $Call)
        [void]$Failures.Add(("{0}: expected fail-closed rejection but the call succeeded" -f $Name))
    }
    catch {
    }
}

# ---------------------------------------------------------------------------
# Case 1: provider schema revision and class accepted.
# ---------------------------------------------------------------------------
function Test-RuntimeCase1 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $accepted = Invoke-RuntimeValidateRequirement -Binding $binding -Requirement (Get-RuntimeTestRequirement) -Lock (Get-RuntimeTestLock)
    Assert-RuntimeTrue $Failures ([bool]$accepted['accepted']) '1-accepted'
    Assert-RuntimeTrue $Failures ($accepted['testClass'] -ceq 'RUNTIME') '1-class'
    Assert-RuntimeTrue $Failures ($accepted['target'] -ceq 'host') '1-target'
    Assert-RuntimeTrue $Failures ($accepted['providerRevision'] -ceq 'eliot.integration.runtime-provider.v1') '1-revision'
    Assert-RuntimeTrue $Failures ($accepted['artifactState'] -ceq 'artifact-accepted') '1-artifact-state'
    Assert-RuntimeTrue $Failures ($accepted['digest'] -ceq $script:RuntimeDigest) '1-digest'
    Assert-RuntimeTrue $Failures ($accepted['peProfile'] -ceq 'isolated-foreground') '1-profile'
    Assert-RuntimeTrue $Failures ($accepted['runId'] -ceq $binding['runId']) '1-run-bound'
    $identity = Get-RuntimeProviderIdentity
    Assert-RuntimeTrue $Failures ($identity['interfaceVersion'] -ceq 'eliot.integration.harness-provider.v1') '1-interface'
}

# ---------------------------------------------------------------------------
# Case 2: unknown class component target and revision rejected.
# ---------------------------------------------------------------------------
function Test-RuntimeCase2 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $lock = Get-RuntimeTestLock
    Test-RuntimeRejects $Failures '2-wrong-class' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement @{ testClass = 'STORE'; target = 'host'; providerRevision = 'eliot.integration.runtime-provider.v1' } -Lock $lock }
    Test-RuntimeRejects $Failures '2-unknown-target' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement @{ testClass = 'RUNTIME'; target = 'daemon'; providerRevision = 'eliot.integration.runtime-provider.v1' } -Lock $lock }
    Test-RuntimeRejects $Failures '2-unknown-component' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement (Get-RuntimeTestRequirement -Target 'scheduler') -Lock $lock }
    Test-RuntimeRejects $Failures '2-wrong-revision' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement @{ testClass = 'RUNTIME'; target = 'host'; providerRevision = 'eliot.integration.runtime-provider.v9' } -Lock $lock }
    Test-RuntimeRejects $Failures '2-wrong-digest' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement (Get-RuntimeTestRequirement) -Lock @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; sha256 = ('0' * 64); artifact = 'eliot-host.exe' } }
    Test-RuntimeRejects $Failures '2-wrong-profile' { Invoke-RuntimeValidateRequirement -Binding $binding -Requirement (Get-RuntimeTestRequirement) -Lock @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'shared-background'; sha256 = $script:RuntimeDigest; artifact = 'eliot-host.exe' } }
    $badBinding = Get-RuntimeTestBinding
    $badBinding['testClass'] = 'STORE'
    Test-RuntimeRejects $Failures '2-binding-class' { Invoke-RuntimeValidateRequirement -Binding $badBinding -Requirement (Get-RuntimeTestRequirement) -Lock $lock }
}

# ---------------------------------------------------------------------------
# Case 3: no unrequested launch without approved registration.
# ---------------------------------------------------------------------------
function Test-RuntimeCase3 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $spy = Get-RuntimeTestLauncher
    $foreignBinding = Get-RuntimeTestBinding -RunId 'ffffffffffffffffffffffffffffffff'
    Test-RuntimeRejects $Failures '3-foreign-allocation' { Invoke-RuntimeStart -Binding $foreignBinding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $spy.launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return '0123abcd' } }
    Assert-RuntimeTrue $Failures ($spy.calls['count'] -eq 0) '3-no-launch-on-foreign'
    Test-RuntimeRejects $Failures '3-no-acquisition' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $null -Launcher $spy.launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return '0123abcd' } }
    Assert-RuntimeTrue $Failures ($spy.calls['count'] -eq 0) '3-no-launch-without-acquisition'
    Test-RuntimeRejects $Failures '3-no-issuance' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $spy.launcher -OwnerIssuance $null -Entropy { return '0123abcd' } }
    Assert-RuntimeTrue $Failures ($spy.calls['count'] -eq 0) '3-no-launch-without-issuance'
    $ok = Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $spy.launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return '0123abcd' }
    Assert-RuntimeTrue $Failures ($spy.calls['count'] -eq 5) '3-five-registered-launches'
    Assert-RuntimeTrue $Failures ($ok['launchState'] -ceq 'launch-registered') '3-registered'
}

# ---------------------------------------------------------------------------
# Case 4: plan is finite and mutation-free.
# ---------------------------------------------------------------------------
function Test-RuntimeCase4 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $req = Get-RuntimeTestRequirement
    $first = Invoke-RuntimePlan -Binding $binding -Requirement $req
    $second = Invoke-RuntimePlan -Binding $binding -Requirement $req
    Assert-RuntimeTrue $Failures ($first['resources'].Count -eq 5) '4-five-resources'
    Assert-RuntimeTrue $Failures ([bool]$first['mutationFree']) '4-mutation-free'
    $firstJson = ($first | ConvertTo-Json -Depth 8 -Compress)
    $secondJson = ($second | ConvertTo-Json -Depth 8 -Compress)
    Assert-RuntimeTrue $Failures ($firstJson -ceq $secondJson) '4-deterministic'
    $graph = @{}
    foreach ($resource in $first['resources']) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            Assert-RuntimeTrue $Failures (-not $resource.ContainsKey($forbidden)) ("4-no-$forbidden")
        }
        Assert-RuntimeTrue $Failures ($resource['runId'] -ceq $binding['runId']) '4-resource-run-bound'
        $graph[$resource['component']] = @($resource['dependsOn'])
    }
    Assert-RuntimeTrue $Failures ((@($graph['kernel'])).Count -eq 0) '4-kernel-root'
    Assert-RuntimeTrue $Failures ((@($graph['bridge']) -contains 'host') -and (@($graph['bridge']) -contains 'governor')) '4-bridge-deps'
    Assert-RuntimeTrue $Failures ((@($graph['watchdog']) -contains 'governor')) '4-watchdog-dep'
    $receipts = @($first['requiredReceipts'])
    Assert-RuntimeTrue $Failures ($receipts.Count -eq 2) '4-two-receipts'
    Assert-RuntimeTrue $Failures ((@($receipts | Where-Object { $_['providerRevision'] -ceq 'eliot.integration.store-provider.v1' })).Count -eq 1) '4-store-receipt'
    Assert-RuntimeTrue $Failures ((@($receipts | Where-Object { $_['providerRevision'] -ceq 'eliot.integration.git-provider.v1' })).Count -eq 1) '4-git-receipt'
    Test-RuntimeRejects $Failures '4-unknown-target' { Invoke-RuntimePlan -Binding $binding -Requirement (Get-RuntimeTestRequirement -Target 'daemon') }
}

# ---------------------------------------------------------------------------
# Case 5: artifact binding to accepted identity.
# ---------------------------------------------------------------------------
function Test-RuntimeCase5 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $accepted = Invoke-RuntimeValidateRequirement -Binding $binding -Requirement (Get-RuntimeTestRequirement -Target 'bridge') -Lock (Get-RuntimeTestLock)
    Assert-RuntimeTrue $Failures ($accepted['target'] -ceq 'bridge') '5-target-bound'
    Assert-RuntimeTrue $Failures ($accepted['version'] -ceq '1.0.0') '5-version'
    Assert-RuntimeTrue $Failures ($accepted['architecture'] -ceq 'windows-x64') '5-arch'
    Assert-RuntimeTrue $Failures ($accepted['peMachine'] -ceq '8664') '5-pe-machine'
    Assert-RuntimeTrue $Failures ($accepted['peProfile'] -ceq 'isolated-foreground') '5-pe-profile'
    Assert-RuntimeTrue $Failures ($accepted['artifact'] -ceq 'eliot-host.exe') '5-artifact'
    $identity = Get-RuntimeProviderIdentity
    $lock = Get-RuntimeLockIdentity
    Assert-RuntimeTrue $Failures ($identity['digest'] -ceq $lock['sha256']) '5-identity-lock-agree'
    Assert-RuntimeTrue $Failures ($identity['digest'] -ceq $script:RuntimeDigest) '5-pinned'
}

# ---------------------------------------------------------------------------
# Case 6: stale mixed missing substituted artifact rejected.
# ---------------------------------------------------------------------------
function Test-RuntimeCase6 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $launcher = (Get-RuntimeTestLauncher).launcher
    $entropy = { return 'cafef00d' }
    $issuance = Get-RuntimeTestOwnerIssuance
    $latest = { param($ctx) return @{ version = 'latest'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'; provenance = 'acquired-verified'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-latest' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $latest -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $missing = { param($ctx) return @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = ''; provenance = 'acquired-verified'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-missing-digest' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $missing -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $callerHash = { param($ctx) return @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'; provenance = 'caller-hash'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-caller-hash' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $callerHash -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $mixed = { param($ctx) return @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = ('1' * 64); provenance = 'acquired-verified'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-mixed-digest' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $mixed -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $substituted = { param($ctx) return @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'; provenance = 'acquired-verified'; runtimePath = 'C:\runtime\other-daemon.exe' } }
    Test-RuntimeRejects $Failures '6-substituted-artifact' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $substituted -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $wrongProfile = { param($ctx) return @{ version = '1.0.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'shared-background'; digest = '6356df0348218c3e68fe045073b102c1ad84adab38158c85ea9cc0374a6ba0fc'; provenance = 'acquired-verified'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-wrong-profile' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $wrongProfile -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
    $staleVersion = { param($ctx) return @{ version = '0.9.0'; architecture = 'windows-x64'; peMachine = '8664'; peProfile = 'isolated-foreground'; digest = ('2' * 64); provenance = 'acquired-verified'; runtimePath = 'C:\runtime\eliot-host.exe' } }
    Test-RuntimeRejects $Failures '6-stale-version' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition $staleVersion -Launcher $launcher -OwnerIssuance $issuance -Entropy $entropy }
}

# ---------------------------------------------------------------------------
# Case 7: arbitrary command authority unrepresentable.
# ---------------------------------------------------------------------------
function Test-RuntimeCase7 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $plan = Invoke-RuntimePlan -Binding $binding -Requirement (Get-RuntimeTestRequirement)
    $planJson = ($plan | ConvertTo-Json -Depth 8 -Compress)
    foreach ($token in @('shellCommand', 'executablePath', 'rawArgv', '"url"', 'credential', 'environmentMap', 'outputPath')) {
        Assert-RuntimeTrue $Failures ($planJson -cnotmatch $token) ("7-plan-no-$token")
    }
    $allocation = Get-RuntimeTestAllocation $binding
    $seen = @{ argv = $null }
    $spyLauncher = { param($in_) $seen['argv'] = $in_['argv']; $n = 1; return @{ observedPid = 6101; observedNonce = 'cc03dd04'; containment = 'job-object' } }.GetNewClosure()
    [void](Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $spyLauncher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return 'abcdef12' })
    Assert-RuntimeTrue $Failures ($null -ne $seen['argv']) '7-launcher-received-argv'
    Assert-RuntimeTrue $Failures ($seen['argv'][0] -like '*eliot-host.exe') '7-fixed-exe'
    Assert-RuntimeTrue $Failures ($seen['argv'] -notcontains '-Command') '7-no-shell'
    Assert-RuntimeTrue $Failures ($seen['argv'] -contains 'run') '7-fixed-verb'
    $startParams = (Get-Command -Name 'Invoke-RuntimeStart').Parameters
    foreach ($bad in @('Executable', 'Url', 'Argv', 'Environment', 'ShellCommand', 'Command')) {
        Assert-RuntimeTrue $Failures (-not $startParams.ContainsKey($bad)) ("7-no-param-$bad")
    }
    $provider = @{ Start = { param($ctx) return @{ runId = $ctx['binding']['runId']; testPassed = $true } } }
    Test-RuntimeRejects $Failures '7-verdict-override' { Invoke-RuntimeProviderOperation -Operation 'Start' -Provider $provider -Binding $binding -Arguments @{} }
}

# ---------------------------------------------------------------------------
# Case 8: unique run-owned identities and pipe namespace.
# ---------------------------------------------------------------------------
function Test-RuntimeCase8 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $bindingA = Get-RuntimeTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $bindingB = Get-RuntimeTestBinding -RunId 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    $planA = Invoke-RuntimePlan -Binding $bindingA -Requirement (Get-RuntimeTestRequirement)
    $planB = Invoke-RuntimePlan -Binding $bindingB -Requirement (Get-RuntimeTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservation = { param($ctx) return @{ pipeNamespace = $ctx['pipeNamespace'] } }
    $allocA = Invoke-RuntimeAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -NamespaceReservation $reservation
    $allocB = Invoke-RuntimeAllocate -Binding $bindingB -Plan $planB -BaseTemp $base -Entropy { return 'e5f60718' } -NamespaceReservation $reservation
    Assert-RuntimeTrue $Failures ($allocA['runRoot'] -cne $allocB['runRoot']) '8-roots-unique'
    Assert-RuntimeTrue $Failures ($allocA['installationRoot'] -cne $allocB['installationRoot']) '8-install-unique'
    Assert-RuntimeTrue $Failures ($allocA['sessionRoot'] -cne $allocB['sessionRoot']) '8-session-unique'
    Assert-RuntimeTrue $Failures ($allocA['configRoot'] -cne $allocB['configRoot']) '8-config-unique'
    Assert-RuntimeTrue $Failures ($allocA['dataRoot'] -cne $allocB['dataRoot']) '8-data-unique'
    Assert-RuntimeTrue $Failures ($allocA['artifactRoot'] -cne $allocB['artifactRoot']) '8-artifact-unique'
    Assert-RuntimeTrue $Failures ($allocA['pipeNamespace'] -cne $allocB['pipeNamespace']) '8-namespace-unique'
    Assert-RuntimeTrue $Failures ($allocA['sessionId'] -cne $allocB['sessionId']) '8-session-id-unique'
    Assert-RuntimeTrue $Failures ($allocA['pipeNamespace'] -ceq 'eliot-fpipe-aaaaaaaa') '8-namespace-shape'
    Assert-RuntimeTrue $Failures ($allocA['ownerMarker'] -ceq 'eliot-harness-owned-root-v1') '8-marker'
    Assert-RuntimeTrue $Failures ($allocA['principal']['scope'] -ceq 'user-isolated-foreground') '8-scope'
    $conflict = { param($ctx) throw 'namespace already reserved' }
    try {
        [void](Invoke-RuntimeAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -NamespaceReservation $conflict)
        [void]$Failures.Add('8-conflict-expected-throw')
    }
    catch {
        Assert-RuntimeTrue $Failures ($_.Exception.Message -match 'RUNTIME-NAMESPACE-CONFLICT') '8-conflict-typed'
    }
}

# ---------------------------------------------------------------------------
# Case 9: path reparse symlink reserved foreign-owner rejected.
# ---------------------------------------------------------------------------
function Test-RuntimeCase9 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $runId = 'cccccccccccccccccccccccccccccccc'
    $root = Join-Path ([IO.Path]::GetTempPath()) ("eliot-runtime-case9-{0}" -f $runId.Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($root)
    try {
        Test-RuntimeRejects $Failures '9-traversal' { Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root '..\outside.txt') -ExpectedRunId $runId }
        Test-RuntimeRejects $Failures '9-absolute-foreign' { Resolve-RuntimeOwnedPath -RunRoot $root -Path 'C:\Windows\System32\evil.dat' -ExpectedRunId $runId }
        Test-RuntimeRejects $Failures '9-reserved' { Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root 'CON') -ExpectedRunId $runId }
        Test-RuntimeRejects $Failures '9-reserved-ext' { Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root 'NUL.txt') -ExpectedRunId $runId }
        $ok = Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root 'config\topology.json') -ExpectedRunId $runId
        Assert-RuntimeTrue $Failures ($ok.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) '9-admitted-descendant'
        $marker = Join-Path $root '.eliot-harness-owner.json'
        '{"run_id":"dddddddddddddddddddddddddddddddd"}' | Set-Content -LiteralPath $marker -NoNewline
        Test-RuntimeRejects $Failures '9-foreign-owner' { Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root 'data\x.dat') -ExpectedRunId $runId }
        '{"run_id":"cccccccccccccccccccccccccccccccc"}' | Set-Content -LiteralPath $marker -NoNewline
        $ok2 = Resolve-RuntimeOwnedPath -RunRoot $root -Path (Join-Path $root 'data\x.dat') -ExpectedRunId $runId
        Assert-RuntimeTrue $Failures ($ok2.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) '9-own-marker-admits'
    }
    finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Case 10: principal and session ACL binding.
# ---------------------------------------------------------------------------
function Test-RuntimeCase10 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    Assert-RuntimeTrue $Failures ($allocation['principal']['principal'] -ceq 'runtime-test-owner') '10-principal-owner'
    Assert-RuntimeTrue $Failures ($allocation['principal']['scope'] -ceq 'user-isolated-foreground') '10-scope'
    Assert-RuntimeTrue $Failures ($allocation['principal']['sessionId'] -ceq $allocation['sessionId']) '10-session-bound'
    [void](Test-RuntimePrincipalShape -Principal $allocation['principal'])
    Test-RuntimeRejects $Failures '10-system-scope' { Test-RuntimePrincipalShape -Principal @{ principal = 'runtime-test-owner'; sessionId = 'sess-abcdef01'; scope = 'system' } }
    Test-RuntimeRejects $Failures '10-missing-session' { Test-RuntimePrincipalShape -Principal @{ principal = 'runtime-test-owner'; scope = 'user-isolated-foreground' } }
    $cred = New-RuntimeEphemeralCredential -CredentialId 'runtime-peer-01' -Entropy { return 'abcdef0123456789' }
    Assert-RuntimeTrue $Failures ([bool]$cred['ephemeral']) '10-ephemeral'
    Assert-RuntimeTrue $Failures ($cred['credentialHandle'] -match '^handle:runtime-peer-01:') '10-handle-shape'
    $secret = [string]$cred['secret']
    $child = Get-RuntimeChildEnv -Ambient @{ PATH = 'C:\x'; SystemRoot = 'C:\Windows'; SECRET_TOKEN = 'shh'; PWSH_EXTRA = 'x'; TEMP = 'C:\t' }
    Assert-RuntimeTrue $Failures (-not $child.ContainsKey('SECRET_TOKEN')) '10-secret-dropped'
    Assert-RuntimeTrue $Failures (-not $child.ContainsKey('PWSH_EXTRA')) '10-unlisted-dropped'
    Assert-RuntimeTrue $Failures ($child.ContainsKey('PATH')) '10-path-kept'
    $display = ("pipe=eliot-fpipe-01234567-host token=$secret ns=eliot")
    $redacted = Get-RuntimeRedactedText -Text $display -Secrets @($secret) -MaxBytes 65536
    Assert-RuntimeTrue $Failures ($redacted.text -cnotmatch [regex]::Escape($secret)) '10-secret-redacted'
    Assert-RuntimeTrue $Failures ($cred['credentialHandle'] -cnotmatch [regex]::Escape($secret)) '10-handle-no-secret'
}

# ---------------------------------------------------------------------------
# Case 11: Store and Git receipts unfabricable.
# ---------------------------------------------------------------------------
function Test-RuntimeCase11 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $runId = '0123456789abcdef0123456789abcdef'
    $storeReceipt = @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1'; runId = $runId; digest = ('aa' * 32); issuer = 'store-provider-owner' }
    Assert-RuntimeTrue $Failures ([bool](Test-RuntimeProviderReceipt -Receipt $storeReceipt)) '11-store-accepted'
    $gitReceipt = @{ testClass = 'GIT'; providerRevision = 'eliot.integration.git-provider.v1'; runId = $runId; digest = ('bb' * 32); issuer = 'git-provider-owner' }
    Assert-RuntimeTrue $Failures ([bool](Test-RuntimeProviderReceipt -Receipt $gitReceipt)) '11-git-accepted'
    Test-RuntimeRejects $Failures '11-self-minted' { Test-RuntimeProviderReceipt -Receipt @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1'; runId = $runId; digest = ('aa' * 32); issuer = 'caller' } }
    Test-RuntimeRejects $Failures '11-cross-issuer' { Test-RuntimeProviderReceipt -Receipt @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1'; runId = $runId; digest = ('aa' * 32); issuer = 'git-provider-owner' } }
    Test-RuntimeRejects $Failures '11-wrong-revision' { Test-RuntimeProviderReceipt -Receipt @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v9'; runId = $runId; digest = ('aa' * 32); issuer = 'store-provider-owner' } }
    Test-RuntimeRejects $Failures '11-unknown-class' { Test-RuntimeProviderReceipt -Receipt @{ testClass = 'RUNTIME'; providerRevision = 'eliot.integration.runtime-provider.v1'; runId = $runId; digest = ('aa' * 32); issuer = 'store-provider-owner' } }
    Test-RuntimeRejects $Failures '11-missing-digest' { Test-RuntimeProviderReceipt -Receipt @{ testClass = 'GIT'; providerRevision = 'eliot.integration.git-provider.v1'; runId = $runId; issuer = 'git-provider-owner' } }
}

# ---------------------------------------------------------------------------
# Case 12: registration and containment before execution.
# ---------------------------------------------------------------------------
function Test-RuntimeCase12 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $entropy = { return 'deadbeef' }
    $issuance = Get-RuntimeTestOwnerIssuance
    $noContainment = { param($in_) return @{ observedPid = 5001; observedNonce = 'aa01bb02' } }
    Test-RuntimeRejects $Failures '12-no-containment-key' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $noContainment -OwnerIssuance $issuance -Entropy $entropy }
    $bare = { param($in_) return @{ observedPid = 5002; observedNonce = 'bb02cc03'; containment = 'none' } }
    Test-RuntimeRejects $Failures '12-no-containment-proof' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $bare -OwnerIssuance $issuance -Entropy $entropy }
    $noPid = { param($in_) return @{ observedNonce = 'cc03dd04'; containment = 'job-object' } }
    Test-RuntimeRejects $Failures '12-no-pid' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $noPid -OwnerIssuance $issuance -Entropy $entropy }
    $equivalent = { param($in_) return @{ observedPid = 5003; observedNonce = 'dd04ee05'; containment = 'job-object-equivalent' } }
    $accepted = Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $equivalent -OwnerIssuance $issuance -Entropy $entropy
    Assert-RuntimeTrue $Failures ($accepted['launchState'] -ceq 'launch-registered') '12-equivalent-accepted'
    Assert-RuntimeTrue $Failures ([bool]$accepted['containedObserved']) '12-contained-observed'
    $spy = Get-RuntimeTestLauncher
    $receipt = Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $spy.launcher -OwnerIssuance $issuance -Entropy $entropy
    Assert-RuntimeTrue $Failures ($receipt['requested']['requestKeys'].Count -eq 5) '12-five-request-keys'
    Assert-RuntimeTrue $Failures ($receipt['observed']['host']['nonce'] -cne 'deadbeef') '12-nonces-distinct'
    Assert-RuntimeTrue $Failures ($receipt['observed']['host']['pipe'] -ceq $receipt['requested']['pipeNamespace'].Replace('eliot-fpipe-', '\\.\pipe\eliot-fpipe-') + '-host') '12-pipe-bound'
}

# ---------------------------------------------------------------------------
# Case 13: observed process is not readiness.
# ---------------------------------------------------------------------------
function Test-RuntimeCase13 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $observers = Get-RuntimeTestObservers
    $noAuth = Get-RuntimeTestClient -Authenticated $false
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $noAuth
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['ready']) '13-not-ready'
    Assert-RuntimeTrue $Failures ($receipt['readinessState'] -cne 'WholeTopologyReady') '13-never-whole'
    Assert-RuntimeTrue $Failures ([bool]$receipt['components']['kernel']['alive']) '13-alive-recorded'
    Assert-RuntimeTrue $Failures ([bool]$receipt['components']['host']['pipeOpen']) '13-pipe-recorded'
    Assert-RuntimeTrue $Failures ($receipt['peerState'] -ceq 'peer-unknown') '13-peer-unknown'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['peerAuthenticated']) '13-auth-false'
}

# ---------------------------------------------------------------------------
# Case 14: handshake substitution rejected.
# ---------------------------------------------------------------------------
function Test-RuntimeCase14 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $observers = Get-RuntimeTestObservers
    $reuseSession = Get-RuntimeTestClient -PeerId $start['sessionId']
    Test-RuntimeRejects $Failures '14-session-reuse' { Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $reuseSession }
    $foreignNs = { param($ctx) return @{ peerAuthenticated = $true; peerId = 'peer-99bb'; handshakeDigest = ('ab' * 32); generation = 1; fence = 'fence-01234567'; epoch = 1; components = @{ kernel = @{ ready = $true }; host = @{ ready = $true }; governor = @{ ready = $true }; watchdog = @{ ready = $true }; bridge = @{ ready = $true } }; pipeNamespace = 'eliot-fpipe-deadbeef' } }
    Test-RuntimeRejects $Failures '14-foreign-namespace' { Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $foreignNs }
    $noDigest = { param($ctx) return @{ peerAuthenticated = $true; peerId = 'peer-77aa'; handshakeDigest = ''; generation = 1; fence = 'fence-01234567'; epoch = 1; components = @{ kernel = @{ ready = $true }; host = @{ ready = $true }; governor = @{ ready = $true }; watchdog = @{ ready = $true }; bridge = @{ ready = $true } }; pipeNamespace = $ctx['pipeNamespace'] } }
    Test-RuntimeRejects $Failures '14-empty-digest' { Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $noDigest }
    $valid = Get-RuntimeTestClient
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $valid
    Assert-RuntimeTrue $Failures ($receipt['peerState'] -ceq 'authenticated-peer-connected') '14-peer-connected'
    Assert-RuntimeTrue $Failures ([bool]$receipt['ready']) '14-whole-ready'
}

# ---------------------------------------------------------------------------
# Case 15: generation fence and epoch from owner only.
# ---------------------------------------------------------------------------
function Test-RuntimeCase15 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $launcher = (Get-RuntimeTestLauncher).launcher
    $entropy = { return '1234abcd' }
    $foreignOwner = Get-RuntimeTestOwnerIssuance -Owner 'someone-else'
    Test-RuntimeRejects $Failures '15-foreign-owner' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher -OwnerIssuance $foreignOwner -Entropy $entropy }
    $wrongGen = Get-RuntimeTestOwnerIssuance -Generation 7
    Test-RuntimeRejects $Failures '15-wrong-generation' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher -OwnerIssuance $wrongGen -Entropy $entropy }
    Test-RuntimeRejects $Failures '15-no-issuance' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher -OwnerIssuance $null -Entropy $entropy }
    $thin = { param($ctx) return @{ generation = 1; owner = 'runtime-test-owner' } }
    Test-RuntimeRejects $Failures '15-thin-issuance' { Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher -OwnerIssuance $thin -Entropy $entropy }
    $receipt = Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy $entropy
    Assert-RuntimeTrue $Failures ($receipt['ownerIssuance']['generation'] -eq 1) '15-generation-recorded'
    Assert-RuntimeTrue $Failures ($receipt['ownerIssuance']['fence'] -ceq 'fence-01234567') '15-fence-recorded'
    Assert-RuntimeTrue $Failures ($receipt['ownerIssuance']['epoch'] -eq 1) '15-epoch-recorded'
    Assert-RuntimeTrue $Failures ($receipt['ownerIssuance']['owner'] -ceq 'runtime-test-owner') '15-owner-recorded'
}

# ---------------------------------------------------------------------------
# Case 16: stale generation and fence never restore readiness.
# ---------------------------------------------------------------------------
function Test-RuntimeCase16 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $observers = Get-RuntimeTestObservers
    $staleGen = Get-RuntimeTestClient -Generation 0
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $staleGen
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['ready']) '16-stale-gen-not-ready'
    Assert-RuntimeTrue $Failures ($receipt['generationFenceState'] -ceq 'generation-fence-stale') '16-stale-state'
    Assert-RuntimeTrue $Failures ([bool]$receipt['staleGeneration']) '16-stale-flag'
    Assert-RuntimeTrue $Failures ($receipt['readinessState'] -cne 'WholeTopologyReady') '16-never-whole'
    $staleFence = Get-RuntimeTestClient -Fence 'fence-aaaaaaaa'
    $receipt2 = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $staleFence
    Assert-RuntimeTrue $Failures (-not [bool]$receipt2['ready']) '16-stale-fence-not-ready'
    $staleEpoch = Get-RuntimeTestClient -Epoch 9
    $receipt3 = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $staleEpoch
    Assert-RuntimeTrue $Failures (-not [bool]$receipt3['ready']) '16-stale-epoch-not-ready'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt3['generationAccepted']) '16-not-accepted'
}

# ---------------------------------------------------------------------------
# Case 17: full readiness denominator binds topology.
# ---------------------------------------------------------------------------
function Test-RuntimeCase17 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $observers = Get-RuntimeTestObservers
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient (Get-RuntimeTestClient)
    Assert-RuntimeTrue $Failures ([bool]$receipt['ready']) '17-ready'
    Assert-RuntimeTrue $Failures ($receipt['readinessState'] -ceq 'WholeTopologyReady') '17-whole-state'
    Assert-RuntimeTrue $Failures ([bool]$receipt['wholeTopologyReady']) '17-whole-flag'
    Assert-RuntimeTrue $Failures ($receipt['pipeNamespace'] -ceq $start['pipeNamespace']) '17-namespace-bound'
    Assert-RuntimeTrue $Failures ((@($receipt['blockedDependents'])).Count -eq 0) '17-no-blocked'
    foreach ($component in @('kernel', 'host', 'governor', 'watchdog', 'bridge')) {
        Assert-RuntimeTrue $Failures ([bool]$receipt['components'][$component]['ready']) ("17-ready-$component")
    }
    $partialComps = @{ kernel = @{ ready = $true }; host = @{ ready = $true }; governor = @{ ready = $true }; watchdog = @{ ready = $true }; bridge = @{ ready = $false } }
    $partial = { param($ctx) return @{ peerAuthenticated = $true; peerId = 'peer-77aa'; handshakeDigest = ('ab' * 32); generation = 1; fence = 'fence-01234567'; epoch = 1; components = $partialComps; pipeNamespace = $ctx['pipeNamespace'] } }.GetNewClosure()
    $receipt2 = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $partial
    Assert-RuntimeTrue $Failures (-not [bool]$receipt2['ready']) '17-partial-not-whole'
    Assert-RuntimeTrue $Failures ($receipt2['readinessState'] -ceq 'SubsystemReady') '17-subsystem-state'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt2['components']['bridge']['ready']) '17-bridge-not-ready'
}

# ---------------------------------------------------------------------------
# Case 18: crash and timeout block dependents.
# ---------------------------------------------------------------------------
function Test-RuntimeCase18 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $crashedKernel = { param($ctx) if ($ctx['component'] -ceq 'kernel') { return @{ alive = $false; pid = $ctx['pid'] } } else { return @{ alive = $true; pid = $ctx['pid'] } } }
    $pipe = (Get-RuntimeTestObservers).pipe
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $crashedKernel -PipeObserver $pipe -TopologyClient (Get-RuntimeTestClient)
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['ready']) '18-not-ready'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['components']['kernel']['ready']) '18-kernel-down'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['components']['host']['ready']) '18-host-blocked'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['components']['bridge']['ready']) '18-bridge-blocked'
    Assert-RuntimeTrue $Failures ((@($receipt['blockedDependents']) -contains 'host')) '18-host-listed'
    $closedPipe = { param($ctx) if ($ctx['component'] -ceq 'governor') { return @{ open = $false; pipe = $ctx['pipe'] } } else { return @{ open = $true; pipe = $ctx['pipe'] } } }
    $proc = (Get-RuntimeTestObservers).process
    $receipt2 = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PipeObserver $closedPipe -TopologyClient (Get-RuntimeTestClient)
    Assert-RuntimeTrue $Failures (-not [bool]$receipt2['ready']) '18-pipe-block-not-ready'
    Assert-RuntimeTrue $Failures ((@($receipt2['blockedDependents']) -contains 'watchdog')) '18-watchdog-listed'
}

# ---------------------------------------------------------------------------
# Case 19: unknown launch and state change require reconciliation.
# ---------------------------------------------------------------------------
function Test-RuntimeCase19 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $calls = @{ count = 0 }
    $losing = { param($in_) $calls['count']++; throw 'unknown-commit: pipe closed before ack' }.GetNewClosure()
    $result = Invoke-RuntimeStart -Binding $binding -Allocation $allocation -Acquisition (Get-RuntimeTestAcquisition) -Launcher $losing -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return '0123abcd' }
    Assert-RuntimeTrue $Failures ($result['launchState'] -ceq 'ReconciliationRequired') '19-reconciliation'
    Assert-RuntimeTrue $Failures (-not [bool]$result['retryPermitted']) '19-no-retry'
    Assert-RuntimeTrue $Failures ($calls['count'] -eq 1) '19-single-attempt'
    Assert-RuntimeTrue $Failures ($null -eq $result['observed']) '19-no-observed'
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $unknownProc = { param($ctx) if ($ctx['component'] -ceq 'watchdog') { return $null } else { return @{ alive = $true; pid = $ctx['pid'] } } }
    $pipe = (Get-RuntimeTestObservers).pipe
    $receipt = Invoke-RuntimeObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $unknownProc -PipeObserver $pipe -TopologyClient (Get-RuntimeTestClient)
    Assert-RuntimeTrue $Failures ($receipt['readinessState'] -ceq 'ReconciliationRequired') '19-unknown-reconciles'
    Assert-RuntimeTrue $Failures (-not [bool]$receipt['ready']) '19-unknown-not-ready'
    Assert-RuntimeTrue $Failures ((@($receipt['unknownComponents']) -contains 'watchdog')) '19-unknown-listed'
}

# ---------------------------------------------------------------------------
# Case 20: owner-only reset with group contamination.
# ---------------------------------------------------------------------------
function Test-RuntimeCase20 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $readiness = @{ runId = $binding['runId'] }
    $fixture = @{ fixtureName = 'runtime-baseline-v1'; baselineDigest = ('34' * 32) }
    $ownerClient = { param($ctx) return @{ resetOk = $true; baselineOk = $true; owner = 'runtime-test-owner'; fixtureName = 'runtime-baseline-v1' } }
    $reset = Invoke-RuntimeResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -OwnerClient $ownerClient
    Assert-RuntimeTrue $Failures ([bool]$reset['baselineVerified']) '20-baseline-verified'
    Assert-RuntimeTrue $Failures ($reset['contaminationScope'] -ceq 'none') '20-no-contamination'
    Assert-RuntimeTrue $Failures ($reset['resetState'] -ceq 'GroupInitialization') '20-group-init'
    $foreignClient = { param($ctx) return @{ resetOk = $true; baselineOk = $true; owner = 'someone-else'; fixtureName = 'runtime-baseline-v1' } }
    Test-RuntimeRejects $Failures '20-foreign-owner' { Invoke-RuntimeResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -OwnerClient $foreignClient }
    $wrongClient = { param($ctx) return @{ resetOk = $true; baselineOk = $true; owner = 'runtime-test-owner'; fixtureName = 'other-fixture' } }
    Test-RuntimeRejects $Failures '20-fixture-mismatch' { Invoke-RuntimeResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -OwnerClient $wrongClient }
    Test-RuntimeRejects $Failures '20-no-owner-api' { Invoke-RuntimeResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -OwnerClient $null }
    $failing = { param($ctx) return @{ resetOk = $false; baselineOk = $false; owner = 'runtime-test-owner'; fixtureName = 'runtime-baseline-v1' } }
    $failed = Invoke-RuntimeResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -OwnerClient $failing
    Assert-RuntimeTrue $Failures ($failed['contaminationScope'] -ceq 'group') '20-group-scope'
    Assert-RuntimeTrue $Failures ($failed['resetState'] -ceq 'GroupContaminated') '20-group-state'
}

# ---------------------------------------------------------------------------
# Case 21: bounded evidence with run identity.
# ---------------------------------------------------------------------------
function Test-RuntimeCase21 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $secret = 'runtime-ephemeral-abcdef0123456789'
    $short = Invoke-RuntimeCollectEvidence -Binding $binding -TerminalState 'Passed' -LogText 'topology ready' -Secrets @($secret) -MaxBytes 65536
    Assert-RuntimeTrue $Failures ($short['terminalState'] -ceq 'Passed') '21-terminal'
    Assert-RuntimeTrue $Failures ($short['runId'] -ceq $binding['runId']) '21-run-bound'
    Assert-RuntimeTrue $Failures ($short['owner'] -ceq $binding['owner']) '21-owner-bound'
    Assert-RuntimeTrue $Failures ($short['generation'] -eq 1) '21-generation-bound'
    Assert-RuntimeTrue $Failures ($short['evidenceId'] -ceq 'ev-01234567') '21-evidence-id'
    Assert-RuntimeTrue $Failures (-not [bool]$short['truncated']) '21-short-not-truncated'
    $long = Invoke-RuntimeCollectEvidence -Binding $binding -TerminalState 'TimedOut' -LogText ('pad=' + ('x' * 5000)) -Secrets @() -MaxBytes 1024
    Assert-RuntimeTrue $Failures ([bool]$long['truncated']) '21-truncated'
    Assert-RuntimeTrue $Failures ([int]$long['bytes'] -le 1024) '21-bounded'
    Assert-RuntimeTrue $Failures ($long['terminalState'] -ceq 'TimedOut') '21-timeout-preserved'
    Test-RuntimeRejects $Failures '21-bad-disposition' { Invoke-RuntimeCollectEvidence -Binding $binding -TerminalState 'Green' -LogText 'x' -Secrets @() }
}

# ---------------------------------------------------------------------------
# Case 22: canary absence across redacted evidence.
# ---------------------------------------------------------------------------
function Test-RuntimeCase22 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $secret = 'runtime-ephemeral-abcdef0123456789'
    $canary = 'canary-9f8e7d6c5b4a'
    $log = ("connected ok; password=hunter2; token=$canary; ELIOT_GOVERNOR_CONFIG=$canary; frame-topology {pipe:open};" +
        ' payload {session:abc}; memory {bytes:12}; query=START HOST CONTENT {x:1}; path=C:\Users\operator\run; peer secret is ' + $secret)
    $evidence = Invoke-RuntimeCollectEvidence -Binding $binding -TerminalState 'Passed' -LogText $log -Secrets @($secret, $canary, 'hunter2') -MaxBytes 65536
    Assert-RuntimeTrue $Failures ($evidence['text'] -cnotmatch [regex]::Escape($canary)) '22-canary-absent'
    Assert-RuntimeTrue $Failures ($evidence['text'] -cnotmatch 'hunter2') '22-password-absent'
    Assert-RuntimeTrue $Failures ($evidence['text'] -cnotmatch [regex]::Escape($secret)) '22-secret-absent'
    Assert-RuntimeTrue $Failures ($evidence['text'] -match 'redacted-runtime-secret') '22-redacted'
    Assert-RuntimeTrue $Failures ($evidence['text'] -match 'redacted-user-path') '22-user-path-redacted'
    $longLog = ('head-secret=' + $canary + '; tail-padding=' + ('x' * 5000) + '; tail-secret=' + $canary)
    $long = Invoke-RuntimeCollectEvidence -Binding $binding -TerminalState 'Passed' -LogText $longLog -Secrets @($canary) -MaxBytes 1024
    Assert-RuntimeTrue $Failures ([bool]$long['truncated']) '22-long-truncated'
    Assert-RuntimeTrue $Failures ($long['text'] -cnotmatch [regex]::Escape($canary)) '22-long-canary-absent'
}

# ---------------------------------------------------------------------------
# Case 23: reverse-dependency-order shutdown.
# ---------------------------------------------------------------------------
function Test-RuntimeCase23 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $order = New-Object Collections.Generic.List[string]
    $controller = { param($ctx) [void]$order.Add(($ctx['phase'] + ':' + $ctx['component'])); return @{ exited = $true; pid = $ctx['pid'] } }.GetNewClosure()
    $stop = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $controller
    Assert-RuntimeTrue $Failures ($stop['stopState'] -ceq 'ShutdownRequested') '23-requested'
    Assert-RuntimeTrue $Failures ($stop['stopPhase'] -ceq 'graceful') '23-graceful-phase'
    Assert-RuntimeTrue $Failures (-not [bool]$stop['forced']) '23-not-forced'
    $expected = @('graceful:bridge', 'graceful:watchdog', 'graceful:governor', 'graceful:host', 'graceful:kernel')
    Assert-RuntimeTrue $Failures ((@($stop['stopOrder']) -join ',') -ceq ($expected -join ',')) '23-reverse-order'
    foreach ($component in @('kernel', 'host', 'governor', 'watchdog', 'bridge')) {
        Assert-RuntimeTrue $Failures ($stop['componentStates'][$component] -ceq 'process-exited') ("23-exited-$component")
    }
    Assert-RuntimeTrue $Failures ($stop['ownedPids']['bridge'] -eq $start['observed']['bridge']['pid']) '23-owned-pid'
}

# ---------------------------------------------------------------------------
# Case 24: parent exit is not cleanup.
# ---------------------------------------------------------------------------
function Test-RuntimeCase24 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $controller = { param($ctx) return @{ exited = $true; pid = $ctx['pid'] } }
    $stop = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $controller
    Assert-RuntimeTrue $Failures (-not $stop.ContainsKey('cleaned')) '24-no-cleaned-key'
    Assert-RuntimeTrue $Failures (-not $stop.ContainsKey('cleanupState')) '24-no-cleanup-state'
    $cleanProcess = { param($ctx) return @{ pid = $ctx['pid']; alive = $false; descendants = @() } }
    $dirtyProbe = { param($ctx) return @{ runRoot = $ctx['runRoot']; handlesHeld = $false; locksHeld = $false; mutexHeld = $false; secretsPresent = $false; rootsPresent = $true; entries = @() } }
    $dirty = Invoke-RuntimeVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $start -ProcessObserver $cleanProcess -JobObserver { param($ctx) return @{ pipeNamespace = $ctx['pipeNamespace']; jobAlive = $false; members = @() } } -PipeObserver { param($ctx) return @{ pipeNamespace = $ctx['pipeNamespace']; pipesOpen = $false } } -HandleProbe $dirtyProbe
    Assert-RuntimeTrue $Failures ($dirty['cleanupState'] -ceq 'ReconciliationRequired') '24-cleanup-still-required'
    Assert-RuntimeTrue $Failures (-not [bool]$dirty['cleaned']) '24-not-cleaned'
}

# ---------------------------------------------------------------------------
# Case 25: owned-tree-only forced stop with PID-reuse negative.
# ---------------------------------------------------------------------------
function Test-RuntimeCase25 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $forcedFor = New-Object Collections.Generic.List[string]
    $controller = { param($ctx) if ($ctx['phase'] -ceq 'graceful' -and $ctx['component'] -cne 'host') { return @{ exited = $true; pid = $ctx['pid'] } } elseif ($ctx['phase'] -ceq 'graceful') { return @{ exited = $false; pid = $ctx['pid'] } } else { [void]$forcedFor.Add($ctx['component']); return @{ exited = $true; pid = $ctx['pid'] } } }.GetNewClosure()
    $stop = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $controller
    Assert-RuntimeTrue $Failures ($stop['stopPhase'] -ceq 'forced') '25-forced-phase'
    Assert-RuntimeTrue $Failures ([bool]$stop['forced']) '25-forced-flag'
    Assert-RuntimeTrue $Failures ((@($forcedFor)).Count -eq 1 -and (@($forcedFor) -contains 'host')) '25-forced-host-only'
    Assert-RuntimeTrue $Failures ($stop['stopState'] -ceq 'ShutdownRequested') '25-requested'
    $reusedPid = { param($ctx) return @{ exited = $true; pid = 999999 } }
    Test-RuntimeRejects $Failures '25-pid-reuse' { Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $reusedPid }
    $byLabel = { param($ctx) return @{ exited = $true } }
    $unlabeled = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $byLabel
    Assert-RuntimeTrue $Failures ($unlabeled['stopState'] -ceq 'ShutdownRequested') '25-no-label-kill'
}

# ---------------------------------------------------------------------------
# Case 26: unknown stop preserves failure and is idempotent.
# ---------------------------------------------------------------------------
function Test-RuntimeCase26 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    $unknown = { param($ctx) if ($ctx['component'] -ceq 'kernel' -and $ctx['phase'] -ceq 'graceful') { return $null } else { return @{ exited = $true; pid = $ctx['pid'] } } }
    $first = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $unknown
    Assert-RuntimeTrue $Failures ($first['stopState'] -ceq 'ReconciliationRequired') '26-reconciliation'
    Assert-RuntimeTrue $Failures ([bool]$first['requestedStop']) '26-requested-preserved'
    Assert-RuntimeTrue $Failures (-not [bool]$first['retryPermitted']) '26-no-retry'
    Assert-RuntimeTrue $Failures ($first['failure'] -match 'kernel') '26-failure-names-component'
    Assert-RuntimeTrue $Failures ($first['failure'] -match 'graceful') '26-failure-names-phase'
    $second = Invoke-RuntimeStop -Binding $binding -StartReceipt $start -ProcessController $unknown
    Assert-RuntimeTrue $Failures ($second['stopState'] -ceq $first['stopState']) '26-idempotent-state'
    Assert-RuntimeTrue $Failures ($second['failure'] -ceq $first['failure']) '26-failure-preserved'
    Assert-RuntimeTrue $Failures ((@($second['stopOrder']) -join ',') -ceq ((@($first['stopOrder']) -join ','))) '26-order-stable'
}

# ---------------------------------------------------------------------------
# Case 27: concurrent-run isolation.
# ---------------------------------------------------------------------------
function Test-RuntimeCase27 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $bindingA = Get-RuntimeTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $bindingB = Get-RuntimeTestBinding -RunId 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    $allocA = Get-RuntimeTestAllocation $bindingA
    $allocB = Get-RuntimeTestAllocation $bindingB
    Test-RuntimeRejects $Failures '27-cross-start' { Invoke-RuntimeStart -Binding $bindingA -Allocation $allocB -Acquisition (Get-RuntimeTestAcquisition) -Launcher (Get-RuntimeTestLauncher).launcher -OwnerIssuance (Get-RuntimeTestOwnerIssuance) -Entropy { return 'abcdef01' } }
    $startA = Get-RuntimeTestStartReceipt $bindingA $allocA
    $observers = Get-RuntimeTestObservers
    $clientB = Get-RuntimeTestClient
    Test-RuntimeRejects $Failures '27-cross-observe' { Invoke-RuntimeObserveReadiness -Binding $bindingB -StartReceipt $startA -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient $clientB }
    $controller = { param($ctx) return @{ exited = $true; pid = $ctx['pid'] } }
    Test-RuntimeRejects $Failures '27-cross-stop' { Invoke-RuntimeStop -Binding $bindingB -StartReceipt $startA -ProcessController $controller }
    $cleanProcess = { param($ctx) return @{ pid = $ctx['pid']; alive = $false; descendants = @() } }
    Test-RuntimeRejects $Failures '27-cross-cleanup' { Invoke-RuntimeVerifyCleanup -Binding $bindingB -Allocation $allocA -StartReceipt $startA -ProcessObserver $cleanProcess }
    $own = Invoke-RuntimeObserveReadiness -Binding $bindingA -StartReceipt $startA -ProcessObserver $observers.process -PipeObserver $observers.pipe -TopologyClient (Get-RuntimeTestClient)
    Assert-RuntimeTrue $Failures ([bool]$own['ready']) '27-own-run-unaffected'
}

# ---------------------------------------------------------------------------
# Case 28: no foreign mutation or test-pass authority.
# ---------------------------------------------------------------------------
function Test-RuntimeCase28 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $allocation = Get-RuntimeTestAllocation $binding
    $start = Get-RuntimeTestStartReceipt $binding $allocation
    foreach ($bad in @('testPassed', 'markPassed', 'verdictOverride', 'providerChoice', 'command', 'argv', 'executable', 'shellCommand')) {
        $provider = @{ ObserveReadiness = { param($ctx) return @{ runId = $ctx['binding']['runId']; ready = $true; ($bad) = $true } } }
        Test-RuntimeRejects $Failures ("28-no-$bad") { Invoke-RuntimeProviderOperation -Operation 'ObserveReadiness' -Provider $provider -Binding $binding -Arguments @{} }
    }
    Test-RuntimeRejects $Failures '28-empty-provider' { Invoke-RuntimeProviderOperation -Operation 'Stop' -Provider @{} -Binding $binding -Arguments @{} }
    Test-RuntimeRejects $Failures '28-unknown-op' { Invoke-RuntimeProviderOperation -Operation 'Launch' -Provider @{ Launch = { param($ctx) return @{ runId = $ctx['binding']['runId'] } } } -Binding $binding -Arguments @{} }
    $mutatedBinding = Get-RuntimeTestBinding
    $mutatedBinding['shellCommand'] = 'evil'
    Test-RuntimeRejects $Failures '28-binding-command' { Invoke-RuntimeProviderOperation -Operation 'Plan' -Provider @{ Plan = { param($ctx) return @{ runId = $ctx['binding']['runId'] } } } -Binding $mutatedBinding -Arguments @{} }
    $foreignAllocation = @{ runId = $binding['runId']; runRoot = 'C:\Windows\System32'; installationRoot = 'C:\Windows\System32'; sessionRoot = 'C:\Windows\System32'; configRoot = 'C:\Windows\System32'; dataRoot = 'C:\Windows\System32'; logRoot = 'C:\Windows\System32'; tempRoot = 'C:\Windows\System32'; artifactRoot = 'C:\Windows\System32'; pipeNamespace = 'eliot-fpipe-01234567' }
    Test-RuntimeRejects $Failures '28-foreign-root' { Invoke-RuntimeVerifyCleanup -Binding $binding -Allocation $foreignAllocation -StartReceipt $start -ProcessObserver { param($ctx) return @{ pid = $ctx['pid']; alive = $false } } }
    $stopParams = (Get-Command -Name 'Invoke-RuntimeStop').Parameters
    foreach ($bad in @('TestPassed', 'MarkPassed', 'Verdict', 'VerdictOverride')) {
        Assert-RuntimeTrue $Failures (-not $stopParams.ContainsKey($bad)) ("28-no-stop-param-$bad")
    }
}

# ---------------------------------------------------------------------------
# Case 29: governor-config provenance and Store separation.
# ---------------------------------------------------------------------------
function Test-RuntimeCase29 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-RuntimeTestBinding
    $good = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v1'; runId = $binding['runId']; channel = 'core-protected'; digest = ('cd' * 32) }
    $accepted = Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $good
    Assert-RuntimeTrue $Failures ([bool]$accepted['accepted']) '29-accepted'
    Assert-RuntimeTrue $Failures ($accepted['provenance'] -ceq 'run-local-config-receipt') '29-provenance'
    Assert-RuntimeTrue $Failures ($accepted['runId'] -ceq $binding['runId']) '29-run-bound'
    $ambient = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v1'; runId = $binding['runId']; channel = 'ambient'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-ambient' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $ambient }
    $production = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v1'; runId = $binding['runId']; channel = 'production'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-production' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $production }
    $default = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v1'; runId = $binding['runId']; channel = 'default'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-default' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $default }
    $oldVersion = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v0'; runId = $binding['runId']; channel = 'core-protected'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-old-version' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $oldVersion }
    $foreignRun = @{ configName = 'ELIOT_GOVERNOR_CONFIG'; version = 'governor-config-v1'; runId = ('f' * 32); channel = 'core-protected'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-foreign-run' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $foreignRun }
    $storeShaped = @{ configName = 'STORE-CONFIG'; version = 'governor-config-v1'; runId = $binding['runId']; channel = 'core-protected'; digest = ('cd' * 32) }
    Test-RuntimeRejects $Failures '29-store-shaped' { Resolve-RuntimeGovernorConfig -Binding $binding -ConfigReceipt $storeShaped }
    Assert-RuntimeTrue $Failures ('eliot.integration.runtime-provider.v1' -cne 'eliot.integration.store-provider.v1') '29-revision-separation'
    $identity = Get-RuntimeProviderIdentity
    Assert-RuntimeTrue $Failures ($identity['providerRevision'] -cne 'eliot.integration.store-provider.v1') '29-provider-separation'
}

$script:CaseTitles = @{
    1  = 'provider schema revision and class accepted'
    2  = 'unknown class component target and revision rejected'
    3  = 'no unrequested launch without approved registration'
    4  = 'plan is finite and mutation-free'
    5  = 'artifact binding to accepted identity'
    6  = 'stale mixed missing substituted artifact rejected'
    7  = 'arbitrary command authority unrepresentable'
    8  = 'unique run-owned identities and pipe namespace'
    9  = 'path reparse symlink reserved foreign-owner rejected'
    10 = 'principal and session ACL binding'
    11 = 'store and git receipts unfabricable'
    12 = 'registration and containment before execution'
    13 = 'observed process is not readiness'
    14 = 'handshake substitution rejected'
    15 = 'generation fence and epoch from owner only'
    16 = 'stale generation and fence never restore readiness'
    17 = 'full readiness denominator binds topology'
    18 = 'crash and timeout block dependents'
    19 = 'unknown launch and state change require reconciliation'
    20 = 'owner-only reset with group contamination'
    21 = 'bounded evidence with run identity'
    22 = 'canary absence across redacted evidence'
    23 = 'reverse-dependency-order shutdown'
    24 = 'parent exit is not cleanup'
    25 = 'owned-tree-only forced stop with pid-reuse negative'
    26 = 'unknown stop preserves failure and is idempotent'
    27 = 'concurrent-run isolation'
    28 = 'no foreign mutation or test-pass authority'
    29 = 'governor-config provenance and store separation'
}

function Invoke-RuntimeCaseById {
    param([Parameter(Mandatory)][int]$Id)
    $failures = New-RuntimeAssertionScope
    $outcome = 'HarnessError'
    $note = ''
    try {
        $null = & "Test-RuntimeCase$Id" $failures
        if ($failures.Count -gt 0) {
            $outcome = 'AssertionFailed'
            $note = 'runtime assertion failures: ' + ($failures -join ' | ')
        }
        elseif (-not $script:ModulesAvailable) {
            $outcome = 'HarnessError'
            $note = 'fail-closed: IntegrationHarness.Runtime module absent (' + $script:ImportDetail + ')'
        }
        else {
            $outcome = 'Passed'
            $note = 'runtime assertions held over fake seams'
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

function Write-RuntimeCaseResult {
    param([Parameter(Mandatory)][int]$Id, [Parameter(Mandatory)][string]$Outcome)
    $result = [ordered]@{
        suite           = $script:SuiteName
        case_id         = $Id
        schema_version  = $script:SchemaVersion
        outcome         = $Outcome
        identity        = ("911/{0}" -f $Id)
        content_digest  = $script:SuiteDigest
        truncated_bytes = 0
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
}

if ($CaseId -ne 0) {
    $single = $null
    try {
        $single = Invoke-RuntimeCaseById -Id $CaseId
    }
    catch {
        $single = [pscustomobject]@{
            CaseId   = $CaseId
            Outcome  = 'HarnessError'
            Failures = @()
            Note     = 'fail-closed dispatcher exception'
        }
    }
    Write-RuntimeCaseResult -Id $CaseId -Outcome $single.Outcome
    if ($single.Outcome -eq 'Passed') { exit 0 } else { exit 1 }
}

$diagnosticResults = @()
foreach ($id in $script:MinCaseId..$script:MaxCaseId) {
    $diagnosticResults += Invoke-RuntimeCaseById -Id $id
}
'IntegrationHarness.Runtime diagnostic: {0} cases, modules={1}' -f $diagnosticResults.Count, $script:ImportDetail
foreach ($row in $diagnosticResults) {
    '911/{0} {1} entry_failures={2} title={3}' -f $row.CaseId, $row.Outcome, $row.Failures.Count, $script:CaseTitles[$row.CaseId]
    '  note: {0}' -f $row.Note
}
$passed = @($diagnosticResults | Where-Object { $_.Outcome -eq 'Passed' }).Count
'summary: passed={0} failed={1}' -f $passed, ($diagnosticResults.Count - $passed)
if ($passed -eq $diagnosticResults.Count) { exit 0 } else { exit 1 }
