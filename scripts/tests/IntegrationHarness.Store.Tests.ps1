<#
.SYNOPSIS
    PowerShell self-test suite for the #909 D-INT-STORE isolated provider (cases 1-22).

.DESCRIPTION
    Containment (scripts/tests/test_integration_harness_store.py, WRITER owned):
    invoked as `pwsh -NoProfile -NonInteractive -File <this path> -CaseId <id>`
    with a positive integer 1..22, this file emits EXACTLY ONE bounded versioned
    JSON object to stdout with the closed field set:
      suite, case_id, schema_version, outcome, identity, content_digest,
      truncated_bytes
    outcome is one of Passed | AssertionFailed | TimedOut | ProcessCrashed |
    InfrastructureBlocked | UnsupportedExternalCredential | HarnessError |
    Cancelled | NotExecutedDueToPriorContamination | Skipped. Only Passed with
    process exit 0 verifies green. content_digest is the SHA-256 hex of the exact
    bytes of this file. identity is always "909/<case_id>".

    Without -CaseId this file is a diagnostic entrypoint: it executes all cases
    1..22 in-process and reports each identity plus its outcome.

    Each case asserts ACTUAL Store provider behavior against the real
    scripts/integration/IntegrationHarness.Store.psm1 module (imported
    conditionally) using injected fake seams only (fake entropy, port
    reservation, acquisition, launcher, process/port observers, Store client,
    controller, file probe, clock). Real logic runs over fakes; no live
    SurrealDB is started and nothing is downloaded. When the Store module is
    absent every case fails closed honestly with HarnessError (never a pass).
    This suite imports IntegrationHarness.Store.psm1 only and never mutates
    Core state.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 22)]
    [int]$CaseId = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SuiteName = 'IntegrationHarness.Store'
$script:SchemaVersion = 'harness-store-case-result-v1'
$script:MinCaseId = 1
$script:MaxCaseId = 22
$script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:StoreModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\integration\IntegrationHarness.Store.psm1'))
$script:MaxModuleSourceBytes = 1048576

$script:ModulesAvailable = $false
$script:ImportDetail = 'not-attempted'
try {
    if (Test-Path -LiteralPath $script:StoreModulePath -PathType Leaf) {
        Import-Module -Name $script:StoreModulePath -ErrorAction Stop
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

function Get-StoreFileDigest {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

try {
    $script:SuiteDigest = Get-StoreFileDigest $PSCommandPath
}
catch {
    $script:SuiteDigest = '0000000000000000000000000000000000000000000000000000000000000000'
}

function New-StoreAssertionScope {
    Write-Output -NoEnumerate ([Collections.Generic.List[string]]::new())
}

function Assert-StoreTrue {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Name
    )
    if (-not $Condition) {
        [void]$Failures.Add($Name)
    }
}

function Get-StoreTestBinding {
    param([string]$RunId = '0123456789abcdef0123456789abcdef')
    $deadline = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
    return @{
        runId            = $RunId
        testClass        = 'STORE'
        providerName     = 'eliot-store-surreal-isolated'
        providerRevision = 'eliot.integration.store-provider.v1'
        owner            = 'store-test-owner'
        generation       = 1
        deadlineUtc      = $deadline
    }
}

function Get-StoreTestRequirement {
    return @{
        testClass        = 'STORE'
        providerRevision = 'eliot.integration.store-provider.v1'
    }
}

function Get-StoreTestLock {
    return @{
        version      = '3.1.4'
        architecture = 'windows-x64'
        peMachine    = '8664'
        sha256       = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
        artifact     = 'surreal.exe'
    }
}

function Get-StoreTestAcquisition {
    param([string]$Provenance = 'acquired-verified')
    $receipt = (Get-StoreTestLock)
    $acq = {
        param($ctx)
        return @{
            version      = '3.1.4'
            architecture = 'windows-x64'
            peMachine    = '8664'
            digest       = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
            provenance   = $Provenance
            storePath    = 'C:\runtime\surreal.exe'
        }
    }.GetNewClosure()
    return $acq
}

$script:TestReservationListeners = [Collections.Generic.List[System.Net.Sockets.TcpListener]]::new()
$script:TestObservedImagePath = 'C:\runtime\surreal.exe'
$script:TestObservedStartTimeUtc = '2026-09-27T12:00:00.0000000Z'

function New-StoreTestReservation {
    param([Parameter(Mandatory)][int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start()
    [void]$script:TestReservationListeners.Add($listener)
    return @{ port = $Port; host = '127.0.0.1'; listener = $listener }
}

function Close-StoreTestReservations {
    foreach ($live in $script:TestReservationListeners) {
        try { $live.Stop() } catch { }
    }
    $script:TestReservationListeners.Clear()
}

function New-StoreTestLauncher {
    param([int]$ObservedPid = 4242, [string]$Nonce = 'feedface01')
    $image = $script:TestObservedImagePath
    $started = $script:TestObservedStartTimeUtc
    return ({ param($input_) return @{ observedPid = $ObservedPid; observedNonce = $Nonce; imagePath = $image; startTimeUtc = $started } }).GetNewClosure()
}

$script:TestAllocationSerial = 0
function Get-StoreTestAllocation {
    param([hashtable]$Binding, [int]$Port = 0, [string]$EntropySeed = '')
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    $script:TestAllocationSerial++
    if ($Port -le 0) { $Port = 18020 + $script:TestAllocationSerial }
    if ([string]::IsNullOrWhiteSpace($EntropySeed)) { $EntropySeed = ('{0:x8}' -f $script:TestAllocationSerial) }
    $plan = Invoke-StorePlan -Binding $Binding -Requirement (Get-StoreTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservation = { param($ctx) return (New-StoreTestReservation -Port $Port) }.GetNewClosure()
    $entropy = { return $EntropySeed }.GetNewClosure()
    return (Invoke-StoreAllocate -Binding $Binding -Plan $plan -BaseTemp $base -Entropy $entropy -PortReservation $reservation)
}

function Get-StoreTestStartReceipt {
    param([hashtable]$Binding, [hashtable]$Allocation)
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    if ($null -eq $Allocation) { $Allocation = Get-StoreTestAllocation $Binding }
    $launcher = New-StoreTestLauncher
    $entropy = { return 'cafef00d' }
    return (Invoke-StoreStart -Binding $Binding -Allocation $Allocation -Acquisition (Get-StoreTestAcquisition) -Launcher $launcher -Entropy $entropy)
}

function Read-StoreModuleSource {
    param([Parameter(Mandatory)][string]$Path)
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.Length -gt $script:MaxModuleSourceBytes) {
        throw "module source exceeds byte bound: $Path"
    }
    return [IO.File]::ReadAllText($Path)
}

function Test-StoreRejects {
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
# Case 1: exact Store requirement and provider revision accepted.
# ---------------------------------------------------------------------------
function Test-StoreCase1 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $accepted = Invoke-StoreValidateRequirement -Binding $binding -Requirement (Get-StoreTestRequirement) -Lock (Get-StoreTestLock)
    Assert-StoreTrue $Failures ([bool]$accepted['accepted']) '1-accepted'
    Assert-StoreTrue $Failures ($accepted['testClass'] -ceq 'STORE') '1-class'
    Assert-StoreTrue $Failures ($accepted['providerRevision'] -ceq 'eliot.integration.store-provider.v1') '1-revision'
    Assert-StoreTrue $Failures ($accepted['version'] -ceq '3.1.4') '1-version'
    Assert-StoreTrue $Failures ($accepted['digest'] -ceq '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1') '1-digest'
    Assert-StoreTrue $Failures ($accepted['runId'] -ceq $binding['runId']) '1-run-bound'
}

# ---------------------------------------------------------------------------
# Case 2: unsupported requirement class and revision rejected.
# ---------------------------------------------------------------------------
function Test-StoreCase2 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $lock = Get-StoreTestLock
    Test-StoreRejects $Failures '2-wrong-class' { Invoke-StoreValidateRequirement -Binding $binding -Requirement @{ testClass = 'RUNTIME'; providerRevision = 'eliot.integration.store-provider.v1' } -Lock $lock }
    Test-StoreRejects $Failures '2-wrong-revision' { Invoke-StoreValidateRequirement -Binding $binding -Requirement @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v9' } -Lock $lock }
    Test-StoreRejects $Failures '2-wrong-digest' { Invoke-StoreValidateRequirement -Binding $binding -Requirement (Get-StoreTestRequirement) -Lock @{ version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'; sha256 = ('0' * 64); artifact = 'surreal.exe' } }
    Test-StoreRejects $Failures '2-wrong-version' { Invoke-StoreValidateRequirement -Binding $binding -Requirement (Get-StoreTestRequirement) -Lock @{ version = '3.1.5'; architecture = 'windows-x64'; peMachine = '8664'; sha256 = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'; artifact = 'surreal.exe' } }
    $badBinding = Get-StoreTestBinding
    $badBinding['testClass'] = 'GIT'
    Test-StoreRejects $Failures '2-binding-class' { Invoke-StoreValidateRequirement -Binding $badBinding -Requirement (Get-StoreTestRequirement) -Lock $lock }
}

# ---------------------------------------------------------------------------
# Case 3: plan is finite and mutation-free.
# ---------------------------------------------------------------------------
function Test-StoreCase3 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $req = Get-StoreTestRequirement
    $first = Invoke-StorePlan -Binding $binding -Requirement $req
    $second = Invoke-StorePlan -Binding $binding -Requirement $req
    Assert-StoreTrue $Failures ($first['resources'].Count -eq 3) '3-three-resources'
    Assert-StoreTrue $Failures ([bool]$first['mutationFree']) '3-mutation-free'
    $firstJson = ($first | ConvertTo-Json -Depth 8 -Compress)
    $secondJson = ($second | ConvertTo-Json -Depth 8 -Compress)
    Assert-StoreTrue $Failures ($firstJson -ceq $secondJson) '3-deterministic'
    foreach ($resource in $first['resources']) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            Assert-StoreTrue $Failures (-not $resource.ContainsKey($forbidden)) ("3-no-$forbidden")
        }
        Assert-StoreTrue $Failures ($resource['runId'] -ceq $binding['runId']) '3-resource-run-bound'
        Assert-StoreTrue $Failures ($resource['testClass'] -ceq 'STORE') '3-resource-class'
    }
}

# ---------------------------------------------------------------------------
# Case 4: exact 3.1.4 provenance and digest reverified including cache.
# ---------------------------------------------------------------------------
function Test-StoreCase4 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $attempts = @(
        @{ provenance = 'acquired-verified'; port = 18011; entropySeed = 'deadbeef' },
        @{ provenance = 'cached-reverified'; port = 18012; entropySeed = 'deadbee0' }
    )
    foreach ($attempt in $attempts) {
        $provenance = [string]$attempt['provenance']
        $allocation = Get-StoreTestAllocation $binding -Port ([int]$attempt['port']) -EntropySeed ([string]$attempt['entropySeed'])
        $launcher = New-StoreTestLauncher -ObservedPid 5001 -Nonce 'aa01bb02'
        $entropy = { return 'deadbeef' }
        $receipt = Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition (Get-StoreTestAcquisition -Provenance $provenance) -Launcher $launcher -Entropy $entropy
        Assert-StoreTrue $Failures ($receipt['startState'] -ceq 'StartRequested') ("4-started-$provenance")
        Assert-StoreTrue $Failures ($receipt['binary']['version'] -ceq '3.1.4') ("4-version-$provenance")
        Assert-StoreTrue $Failures ($receipt['binary']['digest'] -ceq '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1') ("4-digest-$provenance")
        Assert-StoreTrue $Failures ($receipt['binary']['provenance'] -ceq $provenance) ("4-provenance-$provenance")
    }
}

# ---------------------------------------------------------------------------
# Case 5: latest/missing/caller-hash/wrong version-arch rejected.
# ---------------------------------------------------------------------------
function Test-StoreCase5 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $launcher = New-StoreTestLauncher -ObservedPid 5002 -Nonce 'bb02cc03'
    $entropy = { return 'cafef00d' }
    $latest = { param($ctx) return @{ version = 'latest'; architecture = 'windows-x64'; peMachine = '8664'; digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'; provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } }
    Test-StoreRejects $Failures '5-latest' { Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition $latest -Launcher $launcher -Entropy $entropy }
    $missing = { param($ctx) return @{ version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'; digest = ''; provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } }
    Test-StoreRejects $Failures '5-missing-digest' { Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition $missing -Launcher $launcher -Entropy $entropy }
    $callerHash = { param($ctx) return @{ version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'; digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'; provenance = 'caller-hash'; storePath = 'C:\runtime\surreal.exe' } }
    Test-StoreRejects $Failures '5-caller-hash' { Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition $callerHash -Launcher $launcher -Entropy $entropy }
    $wrongVer = { param($ctx) return @{ version = '2.9.0'; architecture = 'windows-x64'; peMachine = '8664'; digest = ('1' * 64); provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } }
    Test-StoreRejects $Failures '5-wrong-version' { Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition $wrongVer -Launcher $launcher -Entropy $entropy }
    $wrongArch = { param($ctx) return @{ version = '3.1.4'; architecture = 'linux-x64'; peMachine = '8664'; digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'; provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } }
    Test-StoreRejects $Failures '5-wrong-arch' { Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition $wrongArch -Launcher $launcher -Entropy $entropy }
}

# ---------------------------------------------------------------------------
# Case 6: arbitrary executable/URL/argv/env authority unrepresentable.
# ---------------------------------------------------------------------------
function Test-StoreCase6 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $plan = Invoke-StorePlan -Binding $binding -Requirement (Get-StoreTestRequirement)
    $planJson = ($plan | ConvertTo-Json -Depth 8 -Compress)
    foreach ($token in @('shellCommand', 'executablePath', 'rawArgv', '"url"', 'credential', 'environmentMap', 'outputPath')) {
        Assert-StoreTrue $Failures ($planJson -cnotmatch $token) ("6-plan-no-$token")
    }
    $allocation = Get-StoreTestAllocation $binding
    $seen = @{ argv = $null }
    $spyImage = $script:TestObservedImagePath
    $spyStarted = $script:TestObservedStartTimeUtc
    $spyLauncher = { param($input_) $seen['argv'] = $input_['argv']; return @{ observedPid = 6001; observedNonce = 'cc03dd04'; imagePath = $spyImage; startTimeUtc = $spyStarted } }.GetNewClosure()
    $entropy = { return 'abcdef12' }
    [void](Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition (Get-StoreTestAcquisition) -Launcher $spyLauncher -Entropy $entropy)
    Assert-StoreTrue $Failures ($null -ne $seen['argv']) '6-launcher-received-argv'
    Assert-StoreTrue $Failures ($seen['argv'][0] -like '*surreal.exe') '6-fixed-exe'
    Assert-StoreTrue $Failures ($seen['argv'] -notcontains '-Command') '6-no-shell'
    $startParams = (Get-Command -Name 'Invoke-StoreStart').Parameters
    foreach ($bad in @('Executable', 'Url', 'Argv', 'Environment', 'ShellCommand')) {
        Assert-StoreTrue $Failures (-not $startParams.ContainsKey($bad)) ("6-no-param-$bad")
    }
    $provider = @{ Start = { param($ctx) return @{ runId = $ctx['binding']['runId']; testPassed = $true } } }
    Test-StoreRejects $Failures '6-verdict-override' { Invoke-StoreProviderOperation -Operation 'Start' -Provider $provider -Binding $binding -Arguments @{} }
}

# ---------------------------------------------------------------------------
# Case 7: unique owned roots/namespace/database with race-safe endpoint.
# ---------------------------------------------------------------------------
function Test-StoreCase7 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $bindingA = Get-StoreTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $bindingB = Get-StoreTestBinding -RunId 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
    # A third run that shares its FIRST 8 hex chars with run A. runId-prefix-only
    # naming makes these two runs indistinguishable, so this run exists to prove
    # the namespace/database derivation does not stop there.
    $bindingPrefixTwin = Get-StoreTestBinding -RunId 'aaaaaaaa123456781234567812345678'
    $planA = Invoke-StorePlan -Binding $bindingA -Requirement (Get-StoreTestRequirement)
    $planB = Invoke-StorePlan -Binding $bindingB -Requirement (Get-StoreTestRequirement)
    $planPrefixTwin = Invoke-StorePlan -Binding $bindingPrefixTwin -Requirement (Get-StoreTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservationA = { param($ctx) return (New-StoreTestReservation -Port 18101) }
    $reservationB = { param($ctx) return (New-StoreTestReservation -Port 18102) }
    $reservationPrefixTwin = { param($ctx) return (New-StoreTestReservation -Port 18103) }
    $allocA = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -PortReservation $reservationA
    $allocB = Invoke-StoreAllocate -Binding $bindingB -Plan $planB -BaseTemp $base -Entropy { return 'e5f60718' } -PortReservation $reservationB
    $allocPrefixTwin = Invoke-StoreAllocate -Binding $bindingPrefixTwin -Plan $planPrefixTwin -BaseTemp $base -Entropy { return 'c3d4e5f6' } -PortReservation $reservationPrefixTwin
    Assert-StoreTrue $Failures ($allocA['runRoot'] -cne $allocB['runRoot']) '7-roots-unique'
    Assert-StoreTrue $Failures ($allocA['dataRoot'] -cne $allocB['dataRoot']) '7-data-unique'
    Assert-StoreTrue $Failures ($allocA['logRoot'] -cne $allocB['logRoot']) '7-log-unique'
    Assert-StoreTrue $Failures ($allocA['secretRoot'] -cne $allocB['secretRoot']) '7-secret-unique'
    Assert-StoreTrue $Failures ($allocA['namespace'] -cne $allocB['namespace']) '7-ns-unique'
    Assert-StoreTrue $Failures ($allocA['database'] -cne $allocB['database']) '7-db-unique'
    Assert-StoreTrue $Failures ($allocA['port'] -ne $allocB['port']) '7-ports-distinct'
    Assert-StoreTrue $Failures ($allocA['host'] -ceq '127.0.0.1') '7-loopback'
    Assert-StoreTrue $Failures ($allocA['endpoint'] -ceq '127.0.0.1:18101') '7-endpoint-shape'
    Assert-StoreTrue $Failures ($allocA['ownerMarker'] -ceq 'eliot-harness-owned-root-v1') '7-marker'
    Assert-StoreTrue $Failures ($allocA['reservationIdentity']['endpoint'] -ceq $allocA['endpoint']) '7-reservation-endpoint-bound'

    # --- Names are per-allocation, not per-run-prefix. ------------------------
    # The only case that decides this is a SECOND ALLOCATION OF THE SAME RUN: a
    # different run proves nothing, because a runId-prefix derivation separates
    # two runs trivially. These two allocations differ only in their allocation
    # seed, which is exactly the per-allocation entropy the module already uses
    # for the run root, and they must still not share either name.
    $allocA1 = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port 18111) }
    $allocA2 = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return '5f6e7d8c' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port 18112) }
    Assert-StoreTrue $Failures ([string]$allocA1['runId'] -ceq [string]$allocA2['runId']) '7-same-run-allocation-a'
    Assert-StoreTrue $Failures ([string]$allocA1['runRoot'] -cne [string]$allocA2['runRoot']) '7-same-run-roots-unique'
    Assert-StoreTrue $Failures ([string]$allocA1['namespace'] -cne [string]$allocA2['namespace']) ('7-same-run-ns-unique: ' + [string]$allocA1['namespace'] + ' vs ' + [string]$allocA2['namespace'])
    Assert-StoreTrue $Failures ([string]$allocA1['database'] -cne [string]$allocA2['database']) ('7-same-run-db-unique: ' + [string]$allocA1['database'] + ' vs ' + [string]$allocA2['database'])
    Assert-StoreTrue $Failures ([string]$allocA1['namespace'] -ceq 'eliot_ns_aaaaaaaa_a1b2c3d4') ('7-same-run-ns-shape: ' + [string]$allocA1['namespace'])
    Assert-StoreTrue $Failures ([string]$allocA1['database'] -ceq 'eliot_db_aaaaaaaa_a1b2c3d4') ('7-same-run-db-shape: ' + [string]$allocA1['database'])
    Assert-StoreTrue $Failures ([string]$allocA2['namespace'] -ceq 'eliot_ns_aaaaaaaa_5f6e7d8c') ('7-same-run-ns-shape-2: ' + [string]$allocA2['namespace'])
    Assert-StoreTrue $Failures ([string]$allocA2['database'] -ceq 'eliot_db_aaaaaaaa_5f6e7d8c') ('7-same-run-db-shape-2: ' + [string]$allocA2['database'])
    # Deterministic for a given (runId, seed): the same allocation re-derives the
    # identical pair instead of minting a new name each time it is replayed.
    $allocA1Replay = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port 18113) }
    Assert-StoreTrue $Failures ([string]$allocA1Replay['namespace'] -ceq [string]$allocA1['namespace']) '7-ns-deterministic-for-seed'
    Assert-StoreTrue $Failures ([string]$allocA1Replay['database'] -ceq [string]$allocA1['database']) '7-db-deterministic-for-seed'
    # A DIFFERENT run that shares run A's first 8 hex chars must also not share
    # the name: the run prefix alone is not an identity.
    Assert-StoreTrue $Failures ([string]$allocA['namespace'] -cne [string]$allocPrefixTwin['namespace']) '7-ns-distinct-prefix-twin-run'
    Assert-StoreTrue $Failures ([string]$allocA['database'] -cne [string]$allocPrefixTwin['database']) '7-db-distinct-prefix-twin-run'

    # --- Ownership is a per-allocation identity, not a name prediction. --------
    # The reserved endpoint is claimed by a registry identity built from this
    # allocation's own run/owner/generation/seed/endpoint, so two allocations can
    # never share one reservation record and a record cannot be re-registered
    # while it is still live.
    $identityA = $allocA['reservationIdentity']
    $identityB = $allocB['reservationIdentity']
    Assert-StoreTrue $Failures ($identityA -is [hashtable]) '7-identity-is-record'
    Assert-StoreTrue $Failures ($identityB -is [hashtable]) '7-identity-b-record'
    Assert-StoreTrue $Failures ([string]$identityA['reservationId'] -cne [string]$identityB['reservationId']) '7-identity-distinct'
    Assert-StoreTrue $Failures ([string]$identityA['runId'] -ceq 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') '7-identity-run-bound'
    Assert-StoreTrue $Failures ([string]$identityA['owner'] -ceq $bindingA['owner']) '7-identity-owner-bound'
    Assert-StoreTrue $Failures ([int]$identityA['generation'] -eq [int]$bindingA['generation']) '7-identity-generation-bound'
    Assert-StoreTrue $Failures ([string]$identityA['allocationSeed'] -ceq 'a1b2c3d4') '7-identity-seed-bound'
    Assert-StoreTrue $Failures ([string]$identityA['state'] -ceq 'Pending') '7-identity-pending'
    # The hold is proven, not asserted by shape: the module re-read the bound
    # socket and classified the proof itself.
    Assert-StoreTrue $Failures ([string]$identityA['reservationProof'] -ceq 'held-socket') '7-proof-held-socket'

    # --- The atomic claim is the bind, proven on this host. -------------------
    # While allocation A's reservation is live its exclusive loopback bind is
    # still held, so a second exclusive bind of the same endpoint must be refused
    # by the OS. That refusal is what makes the endpoint race-safe across runs;
    # it is measured here rather than claimed.
    $contender = $null
    $refusal = ''
    try {
        $contender = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, [int]$allocA['port'])
        $contender.ExclusiveAddressUse = $true
        $contender.Start()
    }
    catch { $refusal = [string]$_.Exception.Message }
    finally {
        if ($null -ne $contender) { try { $contender.Stop() } catch { } }
    }
    Assert-StoreTrue $Failures (-not [string]::IsNullOrWhiteSpace($refusal)) '7-live-reservation-refuses-second-bind'

    # --- A HOSTILE racer is refused on the endpoint, not on its identity. -----
    # The arms below differ from the identity-equal cases above in exactly the
    # ways a real racer differs: a DIFFERENT run, NO listener of its own, and A's
    # endpoint while A still physically holds it. None of them matches A's
    # runId/owner/generation/seed tuple, so a guard keyed on that tuple passes
    # all three -- which is precisely why these arms exist.
    $hostileRacers = @(
        @{ name = 'foreign-run'; binding = $bindingB; generation = 1 },
        @{ name = 'foreign-owner'; binding = (Get-StoreTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' | ForEach-Object { $_.owner = 'someone-else'; $_ }); generation = 1 },
        @{ name = 'foreign-generation'; binding = (Get-StoreTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'); generation = 7 }
    )
    foreach ($racerCase in $hostileRacers) {
        $racerBinding = $racerCase['binding']
        $racerBinding['generation'] = $racerCase['generation']
        $racerPlan = Invoke-StorePlan -Binding $racerBinding -Requirement (Get-StoreTestRequirement)
        $hostileAllocation = $null
        $hostileRefusal = ''
        try {
            # No listener: the racer owns nothing, it merely NAMES A's endpoint.
            $hostileAllocation = Invoke-StoreAllocate -Binding $racerBinding -Plan $racerPlan -BaseTemp $base `
                -Entropy { return '7d6e5f4c' } -PortReservation { param($ctx) return @{ port = [int]$allocA['port']; host = '127.0.0.1' } }
        }
        catch { $hostileRefusal = [string]$_.Exception.Message }
        $label = [string]$racerCase['name']
        Assert-StoreTrue $Failures ($null -eq $hostileAllocation) ("7-hostile-racer-refused-${label}: " + $hostileRefusal)
        # A cross-run racer for a physically held endpoint is a genuine conflict,
        # not this run's reused reservation; the refusal says so in its code.
        Assert-StoreTrue $Failures ($hostileRefusal -match '^STORE-PORT-CONFLICT:') ("7-hostile-racer-typed-${label}: " + $hostileRefusal)
        $afterHostile = [hashtable]$allocA['reservationIdentity']
        Assert-StoreTrue $Failures ([string]$afterHostile['state'] -ceq 'Pending') "7-hostile-racer-left-winner-holding-$label"
        Assert-StoreTrue $Failures ([string]$afterHostile['endpoint'] -ceq [string]$allocA['endpoint']) "7-hostile-racer-endpoint-intact-$label"
    }

    # An END-TO-END hostile racer: the loser above produced NO allocation, so the
    # only thing it could reach Start with would be an endpoint it NAMED while
    # A still physically held it. This arm gives that loser a real allocation of
    # its own, starts it on its own endpoint, and only then points that same
    # allocation at A's held endpoint. Nothing the module can hand out on A's
    # endpoint authorizes a launch, the refusal is typed rather than a bare
    # string, and A's hold survives the attempt.
    $racerPlanB = Invoke-StorePlan -Binding $bindingB -Requirement (Get-StoreTestRequirement)
    $racerAlloc = $null
    $racerAllocRefusal = ''
    try {
        $racerAlloc = Invoke-StoreAllocate -Binding $bindingB -Plan $racerPlanB -BaseTemp $base `
            -Entropy { return '0b0c0d0e' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port 18108) }
    }
    catch { $racerAllocRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -ne $racerAlloc) ('7-hostile-owns-own-endpoint: ' + $racerAllocRefusal)
    # The racer's OWN endpoint, once started, IS released by the handoff, so it
    # is no longer a live claim; it could never be the raced endpoint anyway,
    # because it is not A's endpoint.
    $racerLaunch = $null
    $racerLaunchRefusal = ''
    try {
        $racerLaunch = Invoke-StoreStart -Binding $bindingB -Allocation $racerAlloc -Acquisition (Get-StoreTestAcquisition) `
            -Launcher (New-StoreTestLauncher -ObservedPid 7301 -Nonce '2a2b3c3d') -Entropy { return 'e5f60718' }
    }
    catch { $racerLaunchRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ([string]$racerLaunch['startState'] -ceq 'StartRequested') ('7-hostile-own-launch-succeeds: ' + $racerLaunchRefusal)
    Assert-StoreTrue $Failures ([string]$racerLaunch['reservationIdentity']['state'] -ceq 'Released') '7-hostile-own-launch-released'
    $racerEndpoint = [string]$racerAlloc['endpoint']
    $racerForged = @{}
    foreach ($key in $racerAlloc.Keys) { $racerForged[$key] = $racerAlloc[$key] }
    $racerForged['endpoint'] = $allocA['endpoint']
    $racerForged['port'] = $allocA['port']
    $racerForgedRefusal = ''
    $racerForgedLaunched = $false
    try {
        $racerForgedReceipt = Invoke-StoreStart -Binding $bindingB -Allocation $racerForged `
            -Acquisition (Get-StoreTestAcquisition) -Launcher (New-StoreTestLauncher -ObservedPid 7303 -Nonce '4a4b5c5d') `
            -Entropy { return 'e5f60718' }
        $racerForgedLaunched = ([string]$racerForgedReceipt['startState'] -ceq 'StartRequested')
    }
    catch { $racerForgedRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures (-not $racerForgedLaunched) ('7-hostile-launch-refused: ' + $racerForgedRefusal)
    Assert-StoreTrue $Failures ($racerForgedRefusal -match '^STORE-RESERVATION-FOREIGN:') ('7-hostile-launch-typed: ' + $racerForgedRefusal)
    # The refusal above happened before any child, so A's own hold is untouched.
    $afterHostileStart = [hashtable]$allocA['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$afterHostileStart['state'] -ceq 'Pending') '7-hostile-launch-left-winner-holding'
    Assert-StoreTrue $Failures ([string]$afterHostileStart['endpoint'] -ceq [string]$allocA['endpoint']) '7-hostile-launch-endpoint-intact'
    # The forged endpoint did not survive onto the racer's own record, so nothing
    # later in this case can read A's endpoint off the loser's allocation.
    $racerIdentityAfter = [hashtable]$racerAlloc['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$racerIdentityAfter['endpoint'] -ceq $racerEndpoint) '7-hostile-own-endpoint-not-repointed'

    # --- Ownership proof classes are not interchangeable at launch. -----------
    # 'held-socket' is a bind this module re-reads and can re-prove; it reaches
    # Start (A's own handoff below proves it). 'seam-asserted' is a seam's word
    # with no handle behind it, so the handoff refuses it with a typed code
    # instead of releasing a claim it cannot verify. The two records differ only
    # because the proof differs.
    $bindingUnproven = Get-StoreTestBinding -RunId 'cccccccccccccccccccccccccccccccc'
    $seamAsserted = Invoke-StoreAllocate -Binding $bindingUnproven `
        -Plan (Invoke-StorePlan -Binding $bindingUnproven -Requirement (Get-StoreTestRequirement)) `
        -BaseTemp $base -Entropy { return 'c0ffee01' } -PortReservation { param($ctx) return @{ port = 18107; host = '127.0.0.1' } }
    Assert-StoreTrue $Failures ([string]$seamAsserted['reservationIdentity']['reservationProof'] -ceq 'seam-asserted') '7-seam-asserted-classified'
    $seamStart = $null
    $seamStartRefusal = ''
    try {
        $seamStart = Invoke-StoreStart -Binding $bindingUnproven `
            -Allocation $seamAsserted -Acquisition (Get-StoreTestAcquisition) `
            -Launcher (New-StoreTestLauncher -ObservedPid 7302 -Nonce '3b3c4d3e') -Entropy { return 'c0ffee01' }
    }
    catch { $seamStartRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -eq $seamStart) ('7-seam-asserted-start-refused: ' + $seamStartRefusal)
    Assert-StoreTrue $Failures ($seamStartRefusal -match '^STORE-RESERVATION-UNPROVEN:') ('7-seam-asserted-start-typed: ' + $seamStartRefusal)

    # --- The registry, not just the OS, refuses to re-issue a live claim. -----
    # A seam that hands allocation A's OWN still-held endpoint back to a second
    # Allocate of the same run identity never gets to rebind it, so the module's
    # own registry is what must refuse. Same seed => same reservation identity,
    # so this is the reused-identity refusal.
    $heldA = $null
    if ($identityA.ContainsKey('listener')) { $heldA = $identityA['listener'] }
    $heldShape = ($null -ne $heldA -and $heldA -is [System.Net.Sockets.TcpListener])
    Assert-StoreTrue $Failures $heldShape '7-held-listener-in-identity'
    $sameIdentity = $null
    $sameIdentityRefusal = ''
    try {
        $sameIdentity = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base `
            -Entropy { return 'a1b2c3d4' } -PortReservation {
            param($ctx) return @{ port = [int]$allocA['port']; host = '127.0.0.1'; listener = $heldA }
        }.GetNewClosure()
    }
    catch { $sameIdentityRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -eq $sameIdentity) '7-live-identity-not-reissued'
    Assert-StoreTrue $Failures ($sameIdentityRefusal -match 'STORE-RESERVATION-REUSED') ('7-live-identity-typed: ' + $sameIdentityRefusal)
    $afterSame = [hashtable]$allocA['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$afterSame['state'] -ceq 'Pending') '7-live-identity-left-winner-holding'

    # A different seed makes a DIFFERENT reservation identity for the very same
    # run, owner, generation and endpoint. This run already holds that endpoint,
    # so it is the reused-reservation refusal -- the second identity is never
    # issued, and the hold A still owns is untouched.
    $otherIdentity = $null
    $otherIdentityRefusal = ''
    try {
        $otherIdentity = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base `
            -Entropy { return '9f8e7d6c' } -PortReservation {
            param($ctx) return @{ port = [int]$allocA['port']; host = '127.0.0.1'; listener = $heldA }
        }.GetNewClosure()
    }
    catch { $otherIdentityRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -eq $otherIdentity) '7-second-identity-same-endpoint-refused'
    Assert-StoreTrue $Failures ($otherIdentityRefusal -match '^STORE-RESERVATION-REUSED:') ('7-second-identity-typed: ' + $otherIdentityRefusal)
    $afterOther = [hashtable]$allocA['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$afterOther['state'] -ceq 'Pending') '7-second-identity-left-winner-holding'

    # A reservation handle that carries no live bind at all is refused as a
    # genuine port conflict rather than adopted, so a name alone can never stand
    # in for the hold. This is the exact shape a losing racer would present: the
    # right endpoint string and no ownership of it.
    $planB = Invoke-StorePlan -Binding $bindingB -Requirement (Get-StoreTestRequirement)
    $unowned = $null
    $unownedRefusal = ''
    try {
        $unowned = Invoke-StoreAllocate -Binding $bindingB -Plan $planB -BaseTemp $base `
            -Entropy { return '5a6b7c8d' } -PortReservation { param($ctx) return @{ port = 18105; host = '127.0.0.1' } }
    }
    catch { $unownedRefusal = [string]$_.Exception.Message }
    # Either the allocation proceeds on its own owned endpoint, or it is refused.
    # What must never happen is a second registry record for a live-held endpoint.
    if ($null -ne $unowned) {
        $unownedIdentity = [hashtable]$unowned['reservationIdentity']
        Assert-StoreTrue $Failures ([string]$unownedIdentity['reservationProof'] -ceq 'seam-asserted') '7-unowned-no-live-bind'
        Assert-StoreTrue $Failures ([string]$unownedIdentity['endpoint'] -cne [string]$allocA['endpoint']) '7-unowned-endpoint-distinct'
    }
    else {
        Assert-StoreTrue $Failures ($unownedRefusal -match 'STORE-PORT-CONFLICT') '7-unowned-endpoint-typed'
    }

    # --- Losing racers cannot touch the winner's owned roots. -----------------
    # Allocation A's run root is refused for a different owner even though its
    # path is perfectly predictable, because ownership is read back from marker
    # CONTENT and never inferred from the name.
    $markerPath = [string]$allocA['markerPath']
    $markerText = Get-Content -LiteralPath $markerPath -Raw
    $marker = $markerText | ConvertFrom-Json
    Assert-StoreTrue $Failures ([string]$marker.marker -ceq 'eliot-harness-owned-root-v1') '7-marker-content-value'
    Assert-StoreTrue $Failures ([string]$marker.run_id -ceq 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa') '7-marker-content-run'
    Assert-StoreTrue $Failures ([string]$marker.owner -ceq $bindingA['owner']) '7-marker-content-owner'
    Assert-StoreTrue $Failures ([int]$marker.generation -eq [int]$bindingA['generation']) '7-marker-content-generation'
    $claimOwner = Test-StoreOwnedRootClaim -Recorded $marker -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
        -Owner $bindingA['owner'] -Generation ([int]$bindingA['generation'])
    $claimOtherRun = Test-StoreOwnedRootClaim -Recorded $marker -RunId 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' `
        -Owner $bindingA['owner'] -Generation ([int]$bindingA['generation'])
    $claimOtherOwner = Test-StoreOwnedRootClaim -Recorded $marker -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
        -Owner 'someone-else' -Generation ([int]$bindingA['generation'])
    $claimOtherGeneration = Test-StoreOwnedRootClaim -Recorded $marker -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' `
        -Owner $bindingA['owner'] -Generation 99
    Assert-StoreTrue $Failures ([bool]$claimOwner) '7-claim-true-for-owner'
    Assert-StoreTrue $Failures (-not [bool]$claimOtherRun) '7-claim-false-other-run'
    Assert-StoreTrue $Failures (-not [bool]$claimOtherOwner) '7-claim-false-other-owner'
    Assert-StoreTrue $Failures (-not [bool]$claimOtherGeneration) '7-claim-false-other-generation'

    # Re-allocating A's own roots under a foreign owner is refused, and the
    # refusal must not have released the endpoint A still owns.
    $foreignBinding = Get-StoreTestBinding -RunId 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    $foreignBinding['owner'] = 'someone-else'
    $foreignPlan = Invoke-StorePlan -Binding $foreignBinding -Requirement (Get-StoreTestRequirement)
    $foreign = $null
    $foreignRefusal = ''
    try {
        $foreign = Invoke-StoreAllocate -Binding $foreignBinding -Plan $foreignPlan -BaseTemp $base `
            -Entropy { return 'a1b2c3d4' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port 18104) }
    }
    catch { $foreignRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -eq $foreign) '7-foreign-root-refused'
    Assert-StoreTrue $Failures ($foreignRefusal -match 'STORE-FOREIGN-ROOT') '7-foreign-root-typed'
    $afterForeign = [hashtable]$allocA['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$afterForeign['state'] -ceq 'Pending') '7-foreign-root-left-winner-holding'
    Assert-StoreTrue $Failures ([string]$afterForeign['endpoint'] -ceq [string]$allocA['endpoint']) '7-foreign-root-endpoint-intact'

    # --- The winner's endpoint is released exactly once, by reference. ---------
    # The handoff re-proves the held socket still owns the loopback endpoint, then
    # releases it and records the exact identity it released. A reservation that
    # was lost cannot hand anything off.
    $startA = Invoke-StoreStart -Binding $bindingA -Allocation $allocA -Acquisition (Get-StoreTestAcquisition) `
        -Launcher (New-StoreTestLauncher -ObservedPid 7101 -Nonce '0a0b0c0d') -Entropy { return 'a1b2c3d4' }
    Assert-StoreTrue $Failures ([string]$startA['startState'] -ceq 'StartRequested') '7-handoff-started'
    $receiptA = $startA['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$receiptA['reservationId'] -ceq [string]$identityA['reservationId']) '7-handoff-same-identity'
    Assert-StoreTrue $Failures ([string]$receiptA['endpoint'] -ceq [string]$allocA['endpoint']) '7-handoff-endpoint'
    Assert-StoreTrue $Failures ([string]$receiptA['state'] -ceq 'Released') '7-handoff-released-once'
    Assert-StoreTrue $Failures ([string]$receiptA['reservationProof'] -ceq 'held-socket') '7-handoff-proof-retained'

    # The endpoint is now free, so a competing run can take it: a released
    # reservation is not an eternal claim, and the module does not refuse a
    # legitimate new owner of a freed port.
    $reused = $null
    $reusedRefusal = ''
    try {
        $reused = Invoke-StoreAllocate -Binding $bindingB -Plan $planB -BaseTemp $base `
            -Entropy { return '5a6b7c8d' } -PortReservation { param($ctx) return (New-StoreTestReservation -Port ([int]$allocA['port'])) }
    }
    catch { $reusedRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($null -ne $reused) ('7-released-endpoint-reusable: ' + $reusedRefusal)

    # B still holds its own distinct endpoint while A's handoff runs: the winner
    # releasing a port it won never releases or re-points a competitor's claim.
    # This is asserted HERE, before the positive control below deliberately starts
    # B -- the launch is the only thing in this case that releases B, and reading
    # the state afterwards would prove nothing about A's handoff.
    $identityB2 = [hashtable]$allocB['reservationIdentity']
    Assert-StoreTrue $Failures ([string]$identityB2['state'] -ceq 'Pending') '7-competitor-unaffected'
    Assert-StoreTrue $Failures ([string]$identityB2['endpoint'] -ceq [string]$allocB['endpoint']) '7-competitor-endpoint-intact'
    Assert-StoreTrue $Failures ([string]$identityB2['reservationId'] -cne [string]$receiptA['reservationId']) '7-competitor-identity-distinct'

    # B's own endpoint is a bind B really holds, so it is authorized -- this is the
    # positive control for the proof classes above: the launch succeeds only
    # because the ownership proof is re-verifiable, and only on B's own endpoint,
    # which is not the endpoint A held a moment ago.
    $startB = Invoke-StoreStart -Binding $bindingB -Allocation $allocB -Acquisition (Get-StoreTestAcquisition) `
        -Launcher (New-StoreTestLauncher -ObservedPid 7401 -Nonce '4c4d5e5f') -Entropy { return 'e5f60718' }
    Assert-StoreTrue $Failures ([string]$startB['startState'] -ceq 'StartRequested') '7-owned-holdsocket-launch-authorized'
    Assert-StoreTrue $Failures ([string]$startB['invocation']['bindEndpoint'] -ceq [string]$allocB['endpoint']) '7-owned-holdsocket-binds-own-endpoint'
    Assert-StoreTrue $Failures ([string]$startB['invocation']['bindEndpoint'] -cne [string]$allocA['endpoint']) '7-owned-holdsocket-not-winners-endpoint'
    # A and B reached the same launch authority for the same stated reason -- a
    # re-verifiable held-socket proof on each allocation's OWN endpoint -- and B's
    # handoff released exactly B's identity, never A's already-released one.
    Assert-StoreTrue $Failures ([string]$startB['reservationIdentity']['reservationProof'] -ceq 'held-socket') '7-owned-holdsocket-proof-retained'
    Assert-StoreTrue $Failures ([string]$startB['reservationIdentity']['state'] -ceq 'Released') '7-owned-holdsocket-released-once'
    Assert-StoreTrue $Failures ([string]$startB['reservationIdentity']['reservationId'] -ceq [string]$identityB['reservationId']) '7-owned-holdsocket-same-identity'

    # A handoff identity whose binding no longer matches its allocation cannot
    # authorize a launch: the reservation is proven against the allocation's own
    # run/owner/generation/endpoint, so a foreign identity for the same endpoint
    # is refused before any process exists.
    $forged = @{}
    foreach ($key in $allocA.Keys) { $forged[$key] = $allocA[$key] }
    $forged['reservationIdentity'] = @{
        reservationId   = [string]$identityA['reservationId']
        runId           = 'cccccccccccccccccccccccccccccccc'
        owner           = 'someone-else'
        generation      = 7
        allocationSeed  = 'cafebabe'
        endpoint        = [string]$allocA['endpoint']
        reservationProof = 'held-socket'
        state           = 'Pending'
        listener        = $null
    }
    $forgedRefusal = ''
    $forgedLaunched = $false
    try {
        $forgedReceipt = Invoke-StoreStart -Binding $bindingA -Allocation $forged `
            -Acquisition (Get-StoreTestAcquisition) -Launcher (New-StoreTestLauncher -ObservedPid 7202 -Nonce '1e1f2a2b') `
            -Entropy { return 'a1b2c3d4' }
        $forgedLaunched = ([string]$forgedReceipt['startState'] -ceq 'StartRequested')
    }
    catch { $forgedRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures (-not $forgedLaunched) '7-forged-identity-refused'
    Assert-StoreTrue $Failures ($forgedRefusal -match '^STORE-RESERVATION-FOREIGN:') ('7-forged-identity-typed: ' + $forgedRefusal)
}

# ---------------------------------------------------------------------------
# Case 8: path traversal/reparse/symlink/reserved/foreign rejected.
# ---------------------------------------------------------------------------
function Test-StoreCase8 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $runId = 'cccccccccccccccccccccccccccccccc'
    $root = Join-Path ([IO.Path]::GetTempPath()) ("eliot-store-case8-{0}" -f $runId.Substring(0, 8))
    [void][IO.Directory]::CreateDirectory($root)
    try {
        Test-StoreRejects $Failures '8-traversal' { Resolve-StoreOwnedPath -RunRoot $root -Path (Join-Path $root '..\outside.txt') -ExpectedRunId $runId }
        Test-StoreRejects $Failures '8-absolute-foreign' { Resolve-StoreOwnedPath -RunRoot $root -Path 'C:\Windows\System32\evil.dat' -ExpectedRunId $runId }
        Test-StoreRejects $Failures '8-reserved' { Resolve-StoreOwnedPath -RunRoot $root -Path (Join-Path $root 'CON') -ExpectedRunId $runId }
        Test-StoreRejects $Failures '8-reserved-ext' { Resolve-StoreOwnedPath -RunRoot $root -Path (Join-Path $root 'NUL.txt') -ExpectedRunId $runId }
        $ok = Resolve-StoreOwnedPath -RunRoot $root -Path (Join-Path $root 'data\store.db') -ExpectedRunId $runId
        Assert-StoreTrue $Failures ($ok.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) '8-admitted-descendant'
    }
    finally {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------------------
# Case 9: loopback-only endpoint with typed port conflict.
# ---------------------------------------------------------------------------
function Test-StoreCase9 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $plan = Invoke-StorePlan -Binding $binding -Requirement (Get-StoreTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $nonLoopback = { param($ctx) return @{ port = 18201; host = '0.0.0.0' } }
    Test-StoreRejects $Failures '9-non-loopback' { Invoke-StoreAllocate -Binding $binding -Plan $plan -BaseTemp $base -Entropy { return '1234abcd' } -PortReservation $nonLoopback }
    $badPort = { param($ctx) return @{ port = 80; host = '127.0.0.1' } }
    Test-StoreRejects $Failures '9-privileged-port' { Invoke-StoreAllocate -Binding $binding -Plan $plan -BaseTemp $base -Entropy { return '1234abcd' } -PortReservation $badPort }
    $conflict = { param($ctx) throw 'address already in use' }
    try {
        [void](Invoke-StoreAllocate -Binding $binding -Plan $plan -BaseTemp $base -Entropy { return '1234abcd' } -PortReservation $conflict)
        [void]$Failures.Add('9-conflict-expected-throw')
    }
    catch {
        # A reservation that cannot be taken is a typed port conflict. The
        # module wraps an untyped seam exception as STORE-PORT-CONFLICT and
        # re-throws an already-typed STORE-* refusal unchanged, so this covers
        # both the seam that failed opaquely and one that refused for itself.
        Assert-StoreTrue $Failures ($_.Exception.Message -match '^STORE-(PORT-CONFLICT|PORT-RESERVATION-UNKNOWN|RESERVATION-REUSED)') '9-conflict-typed'
    }
}

# ---------------------------------------------------------------------------
# Case 10: ephemeral credentials and minimal env never in output.
# ---------------------------------------------------------------------------
function Test-StoreCase10 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $cred = New-StoreEphemeralCredential -CredentialId 'store-user-01' -Entropy { return 'abcdef0123456789' }
    Assert-StoreTrue $Failures ([bool]$cred['ephemeral']) '10-ephemeral'
    Assert-StoreTrue $Failures ($cred['credentialHandle'] -match '^handle:store-user-01:') '10-handle-shape'
    $secret = [string]$cred['secret']
    Assert-StoreTrue $Failures (-not [string]::IsNullOrWhiteSpace($secret)) '10-secret-nonempty'
    $child = Get-StoreChildEnv -Ambient @{ PATH = 'C:\x'; SystemRoot = 'C:\Windows'; SECRET_TOKEN = 'shh'; PWSH_EXTRA = 'x'; TEMP = 'C:\t' }
    Assert-StoreTrue $Failures (-not $child.ContainsKey('SECRET_TOKEN')) '10-secret-dropped'
    Assert-StoreTrue $Failures (-not $child.ContainsKey('PWSH_EXTRA')) '10-unlisted-dropped'
    Assert-StoreTrue $Failures ($child.ContainsKey('PATH')) '10-path-kept'
    $display = ("endpoint=127.0.0.1:18301 user=root pass=$secret ns=eliot")
    $redacted = Get-StoreRedactedText -Text $display -Secrets @($secret) -MaxBytes 65536
    Assert-StoreTrue $Failures ($redacted.text -cnotmatch [regex]::Escape($secret)) '10-secret-redacted'
    Assert-StoreTrue $Failures ($redacted.text -match 'redacted-store-secret') '10-redaction-marker'
    Assert-StoreTrue $Failures ($cred['credentialHandle'] -cnotmatch [regex]::Escape($secret)) '10-handle-no-secret'
}

# ---------------------------------------------------------------------------
# Case 11: requested versus observed process identity distinct.
# ---------------------------------------------------------------------------
function Test-StoreCase11 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $receipt = Get-StoreTestStartReceipt $binding $allocation
    Assert-StoreTrue $Failures ($null -ne $receipt['requested']) '11-requested-present'
    Assert-StoreTrue $Failures ($null -ne $receipt['observed']) '11-observed-present'
    Assert-StoreTrue $Failures ($receipt['requested']['nonce'] -cne $receipt['observed']['nonce']) '11-nonces-distinct'
    Assert-StoreTrue $Failures ($receipt['requested']['endpoint'] -ceq $receipt['observed']['endpoint']) '11-endpoint-bound'
    Assert-StoreTrue $Failures ([int]$receipt['observed']['pid'] -gt 0) '11-pid-positive'
}

# ---------------------------------------------------------------------------
# Case 12: lost start response stays owned without retry.
# ---------------------------------------------------------------------------
function Test-StoreCase12 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $calls = @{ count = 0 }
    $losing = { param($input_) $calls['count']++; throw 'lost-response: pipe closed before ack' }.GetNewClosure()
    $result = Invoke-StoreStart -Binding $binding -Allocation $allocation -Acquisition (Get-StoreTestAcquisition) -Launcher $losing -Entropy { return '0123abcd' }
    Assert-StoreTrue $Failures ($result['startState'] -ceq 'ReconciliationRequired') '12-reconciliation'
    Assert-StoreTrue $Failures (-not [bool]$result['retryPermitted']) '12-no-retry'
    Assert-StoreTrue $Failures ($calls['count'] -eq 1) '12-single-attempt'
    Assert-StoreTrue $Failures ($null -eq $result['observed']) '12-no-observed'
}

# ---------------------------------------------------------------------------
# Case 13: liveness without auth is not readiness.
# ---------------------------------------------------------------------------
function Test-StoreCase13 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $ownedPid = [int]$start['observed']['pid']
    $ownedImage = [string]$start['observed']['imagePath']
    $ownedStarted = [string]$start['observed']['startTimeUtc']
    $proc = { param($ctx) return @{ alive = $true; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted } }.GetNewClosure()
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint']; ownerPid = $ownedPid } }.GetNewClosure()
    # The client must select the NAMES THIS ALLOCATION reserved. A hard-coded
    # name would pass here only while namespace derivation ignored the
    # allocation seed, so the fixture echoes the allocation under test.
    $ns = [string]$allocation['namespace']
    $db = [string]$allocation['database']
    $noAuth = { param($ctx) return @{ authenticated = $false; namespace = $ns; database = $db; schemaDigest = ('ab' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $receipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $noAuth
    Assert-StoreTrue $Failures (-not [bool]$receipt['ready']) '13-not-ready'
    Assert-StoreTrue $Failures ($receipt['readinessState'] -ceq 'ObservedProcessReadinessUnknown') '13-unknown-state'
    Assert-StoreTrue $Failures ([bool]$receipt['processAlive']) '13-alive-recorded'
    Assert-StoreTrue $Failures (-not [bool]$receipt['authenticated']) '13-auth-false'
}

# ---------------------------------------------------------------------------
# Case 14: authenticated handshake distinct from fixture readiness.
# ---------------------------------------------------------------------------
function Test-StoreCase14 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $start['namespace'] = $allocation['namespace']
    $start['database'] = $allocation['database']
    $ownedPid = [int]$start['observed']['pid']
    $ownedImage = [string]$start['observed']['imagePath']
    $ownedStarted = [string]$start['observed']['startTimeUtc']
    $proc = { param($ctx) return @{ alive = $true; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted } }.GetNewClosure()
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint']; ownerPid = $ownedPid } }.GetNewClosure()
    # The handshake reports the names THIS ALLOCATION reserved; readiness must
    # accept exactly those and refuse any other pair. The schemaDigest is the
    # MATCHING canary taken from the start receipt's own declared expected
    # schema identity -- a hard-coded one would be compared against a pinned
    # production digest this suite does not and must not restate.
    $ns = [string]$allocation['namespace']
    $db = [string]$allocation['database']
    $schema = [string]$start['requested']['schemaDigest']
    Assert-StoreTrue $Failures ($schema -cmatch '^[0-9a-f]{64}$') ('14-expected-schema-pinned: ' + $schema)
    $authNoFixture = { param($ctx) return @{ authenticated = $true; namespace = $ns; database = $db; schemaDigest = $schema; fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $receipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $authNoFixture
    Assert-StoreTrue $Failures ([bool]$receipt['authenticated']) '14-auth-true'
    Assert-StoreTrue $Failures ([bool]$receipt['schemaReady']) '14-schema-ready'
    Assert-StoreTrue $Failures (-not [bool]$receipt['fixtureReady']) '14-fixture-false'
    Assert-StoreTrue $Failures ([bool]$receipt['ready']) '14-ready-despite-fixture'
    # The handshake was ready ONLY because it carried the receipt's own declared
    # expected schema identity: the receipt reports that exact digest back and
    # no other one flips schemaReady. The mismatch arm reuses the matching
    # process identity, endpoint, authentication and this allocation's own names,
    # so schemaReady is the single field that differs.
    Assert-StoreTrue $Failures ([string]$receipt['schemaDigest'] -ceq $schema) '14-schema-echoes-receipt-identity'
    $wrongSchema = 'ff' + $schema.Substring(2)
    if ($wrongSchema -ceq $schema) { $wrongSchema = 'ee' + $schema.Substring(2) }
    Assert-StoreTrue $Failures ($wrongSchema -cne $schema) '14-wrong-schema-is-distinct'
    $wrongSchemaClient = { param($ctx) return @{ authenticated = $true; namespace = $ns; database = $db; schemaDigest = $wrongSchema; fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $wrongSchemaReceipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $wrongSchemaClient
    Assert-StoreTrue $Failures ([bool]$wrongSchemaReceipt['authenticated']) '14-wrong-schema-still-authenticated'
    Assert-StoreTrue $Failures (-not [bool]$wrongSchemaReceipt['schemaReady']) '14-wrong-schema-not-schema-ready'
    Assert-StoreTrue $Failures (-not [bool]$wrongSchemaReceipt['ready']) '14-wrong-schema-not-ready'
    Assert-StoreTrue $Failures ([string]$wrongSchemaReceipt['failureClass'] -ceq 'schema-mismatch') '14-wrong-schema-failure-class'
    # What the handshake is compared against is the RECEIPT's own declaration,
    # not a digest this test invented and not one recomputed here: a receipt that
    # declares a different expected identity makes that one -- and only that one --
    # the schema-ready canary, on the same authenticated process/endpoint/names.
    $declaredSchema = ('ab' * 32)
    $declaredStart = @{}
    foreach ($key in $start.Keys) { $declaredStart[$key] = $start[$key] }
    $declaredRequested = @{}
    foreach ($key in $start['requested'].Keys) { $declaredRequested[$key] = $start['requested'][$key] }
    $declaredRequested['schemaDigest'] = $declaredSchema
    $declaredStart['requested'] = $declaredRequested
    $declaredClient = { param($ctx) return @{ authenticated = $true; namespace = $ns; database = $db; schemaDigest = $declaredSchema; fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $declaredReceipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $declaredStart -ProcessObserver $proc -PortObserver $port -StoreClient $declaredClient
    Assert-StoreTrue $Failures ([bool]$declaredReceipt['schemaReady']) '14-declared-identity-is-the-canary'
    Assert-StoreTrue $Failures ([bool]$declaredReceipt['ready']) '14-declared-identity-ready'
    Assert-StoreTrue $Failures ([string]$declaredReceipt['schemaDigest'] -ceq $declaredSchema) '14-declared-identity-reported'
    # ...and under that receipt the ORIGINAL pinned identity is no longer ready:
    # the comparison follows the receipt, so it cannot be a hard-coded value.
    $pinnedUnderDeclared = { param($ctx) return @{ authenticated = $true; namespace = $ns; database = $db; schemaDigest = $schema; fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $pinnedDeclaredReceipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $declaredStart -ProcessObserver $proc -PortObserver $port -StoreClient $pinnedUnderDeclared
    Assert-StoreTrue $Failures (-not [bool]$pinnedDeclaredReceipt['schemaReady']) '14-pinned-not-ready-under-other-declaration'
    Assert-StoreTrue $Failures ([string]$pinnedDeclaredReceipt['failureClass'] -ceq 'schema-mismatch') '14-pinned-failure-class-under-other-declaration'
    # A receipt with no declared expected schema identity at all is refused, so the
    # readiness comparison always has something of its OWN to compare against.
    $noSchemaStart = @{}
    foreach ($key in $start.Keys) { $noSchemaStart[$key] = $start[$key] }
    $noSchemaRequested = @{}
    foreach ($key in $start['requested'].Keys) { $noSchemaRequested[$key] = $start['requested'][$key] }
    $noSchemaRequested.Remove('schemaDigest')
    $noSchemaStart['requested'] = $noSchemaRequested
    $noSchemaRefusal = ''
    try { [void](Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $noSchemaStart -ProcessObserver $proc -PortObserver $port -StoreClient $authNoFixture) }
    catch { $noSchemaRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures (-not [string]::IsNullOrWhiteSpace($noSchemaRefusal)) '14-no-declared-schema-refused'
    Assert-StoreTrue $Failures ($noSchemaRefusal -match '^STORE-RECEIPT-STALE:') ('14-no-declared-schema-typed: ' + $noSchemaRefusal)
    $authWithFixture = { param($ctx) return @{ authenticated = $true; namespace = $ns; database = $db; schemaDigest = $schema; fixtureReady = $true; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $receipt2 = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $authWithFixture
    Assert-StoreTrue $Failures ([bool]$receipt2['fixtureReady']) '14-fixture-true-separate'
    Assert-StoreTrue $Failures ($receipt['schemaDigest'] -ceq $receipt2['schemaDigest']) '14-schema-stable'
    Assert-StoreTrue $Failures ($receipt2['schemaDigest'] -ceq $schema) '14-fixture-receipt-same-declared-identity'
}

# ---------------------------------------------------------------------------
# Case 15: stale and foreign receipts rejected.
# ---------------------------------------------------------------------------
function Test-StoreCase15 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $proc = { param($ctx) return @{ alive = $true; pid = $ctx['pid'] } }
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint'] } }
    $client = { param($ctx) return @{ authenticated = $true; namespace = 'eliot_ns_01234567'; database = 'eliot_db_89abcdef'; schemaDigest = ('ef' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }
    $foreignStart = @{ runId = ('f' * 32); observed = $start['observed'] }
    Test-StoreRejects $Failures '15-foreign-run' { Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $foreignStart -ProcessObserver $proc -PortObserver $port -StoreClient $client }
    $staleStart = @{ runId = $binding['runId'] }
    Test-StoreRejects $Failures '15-stale-no-observed' { Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $staleStart -ProcessObserver $proc -PortObserver $port -StoreClient $client }
    $expired = Get-StoreTestBinding
    $expired['deadlineUtc'] = ([DateTimeOffset]::UtcNow.AddMinutes(-5)).ToString('o')
    Test-StoreRejects $Failures '15-expired-deadline' { Invoke-StoreObserveReadiness -Binding $expired -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $client -Clock { return [DateTimeOffset]::UtcNow } }

    # A receipt that is THIS run's own, with the right process and endpoint, is
    # still refused when the authenticated handshake selects somebody else's
    # namespace. This is the typed receipt-level guard the per-allocation naming
    # in case 7 exists to protect, so it is asserted with the real owned process
    # identity rather than left implicit.
    $ownedPid = [int]$start['observed']['pid']
    $ownedImage = [string]$start['observed']['imagePath']
    $ownedStarted = [string]$start['observed']['startTimeUtc']
    $liveProc = { param($ctx) return @{ alive = $true; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted } }.GetNewClosure()
    $ownedPort = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint']; ownerPid = $ownedPid } }.GetNewClosure()
    $foreignNs = { param($ctx) return @{ authenticated = $true; namespace = 'eliot_ns_someoneelse'; database = [string]$allocation['database']; schemaDigest = ('ef' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $foreignDb = { param($ctx) return @{ authenticated = $true; namespace = [string]$allocation['namespace']; database = 'eliot_db_someoneelse'; schemaDigest = ('ef' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $foreignNsRefusal = ''
    $foreignDbRefusal = ''
    try { [void](Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $liveProc -PortObserver $ownedPort -StoreClient $foreignNs) }
    catch { $foreignNsRefusal = [string]$_.Exception.Message }
    try { [void](Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $liveProc -PortObserver $ownedPort -StoreClient $foreignDb) }
    catch { $foreignDbRefusal = [string]$_.Exception.Message }
    Assert-StoreTrue $Failures ($foreignNsRefusal -match '^STORE-RECEIPT-FOREIGN:') ('15-foreign-namespace-typed: ' + $foreignNsRefusal)
    Assert-StoreTrue $Failures ($foreignDbRefusal -match '^STORE-RECEIPT-FOREIGN:') ('15-foreign-database-typed: ' + $foreignDbRefusal)
}

# ---------------------------------------------------------------------------
# Case 16: exact fixture declaration with baseline revalidation.
# ---------------------------------------------------------------------------
function Test-StoreCase16 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $ownedPid = [int]$start['observed']['pid']
    $ownedImage = [string]$start['observed']['imagePath']
    $ownedStarted = [string]$start['observed']['startTimeUtc']
    $proc = { param($ctx) return @{ alive = $true; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted } }.GetNewClosure()
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint']; ownerPid = $ownedPid } }.GetNewClosure()
    # Same rule as cases 13/14: the authenticated handshake reports the names
    # THIS ALLOCATION reserved.
    $client = { param($ctx) return @{ authenticated = $true; namespace = [string]$allocation['namespace']; database = [string]$allocation['database']; schemaDigest = ('12' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }.GetNewClosure()
    $start['namespace'] = $allocation['namespace']
    $start['database'] = $allocation['database']
    $readiness = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $client
    $fixture = @{ fixtureName = 'store-baseline-v1'; baselineDigest = ('34' * 32) }
    $resetClient = { param($ctx) return @{ resetOk = $true; baselineOk = $true; fixtureName = 'store-baseline-v1' } }
    $reset = Invoke-StoreResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -StoreClient $resetClient
    Assert-StoreTrue $Failures ([bool]$reset['baselineVerified']) '16-baseline-verified'
    Assert-StoreTrue $Failures ($reset['contaminationScope'] -ceq 'none') '16-no-contamination'
    $wrongClient = { param($ctx) return @{ resetOk = $true; baselineOk = $true; fixtureName = 'other-fixture' } }
    Test-StoreRejects $Failures '16-fixture-mismatch' { Invoke-StoreResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -StoreClient $wrongClient }
}

# ---------------------------------------------------------------------------
# Case 17: reset failure contaminates only its group.
# ---------------------------------------------------------------------------
function Test-StoreCase17 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $readiness = @{ runId = $binding['runId'] }
    $fixture = @{ fixtureName = 'store-group-a'; baselineDigest = ('56' * 32) }
    $failing = { param($ctx) return @{ resetOk = $false; baselineOk = $false; fixtureName = 'store-group-a' } }
    $result = Invoke-StoreResetForTest -Binding $binding -Fixture $fixture -ReadinessReceipt $readiness -StoreClient $failing
    Assert-StoreTrue $Failures ($result['contaminationScope'] -ceq 'group') '17-group-scope'
    Assert-StoreTrue $Failures ($result['resetState'] -ceq 'GroupContaminated') '17-group-state'
    Assert-StoreTrue $Failures (-not [bool]$result['baselineVerified']) '17-no-baseline'
}

# ---------------------------------------------------------------------------
# Case 18: bounded redacted evidence handles with truncation.
# ---------------------------------------------------------------------------
function Test-StoreCase18 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $secret = 'store-ephemeral-abcdef0123456789'
    $shortLog = 'connected ok; password=hunter2; surreal_user_pass=hunter2; query=DEFINE TABLE t CONTENT {x:1}'
    $short = Invoke-StoreCollectEvidence -Binding $binding -TerminalState 'Passed' -LogText $shortLog -Secrets @($secret, 'hunter2') -MaxBytes 65536
    Assert-StoreTrue $Failures ($short['terminalState'] -ceq 'Passed') '18-terminal'
    Assert-StoreTrue $Failures (-not [bool]$short['truncated']) '18-short-not-truncated'
    Assert-StoreTrue $Failures ($short['text'] -cnotmatch 'hunter2') '18-canary-absent'
    Assert-StoreTrue $Failures ($short['text'] -match 'redacted-store-secret') '18-redacted'
    $longLog = ('head-secret=hunter2; tail-padding=' + ('x' * 5000) + '; tail-secret=hunter2')
    $long = Invoke-StoreCollectEvidence -Binding $binding -TerminalState 'Passed' -LogText $longLog -Secrets @($secret, 'hunter2') -MaxBytes 1024
    Assert-StoreTrue $Failures ([bool]$long['truncated']) '18-truncated'
    Assert-StoreTrue $Failures ([int]$long['bytes'] -le 1024) '18-bounded'
    Assert-StoreTrue $Failures ($long['text'] -cnotmatch 'hunter2') '18-long-canary-absent'
    Assert-StoreTrue $Failures ($long['text'] -match 'redacted-store-secret') '18-long-redacted'
    Test-StoreRejects $Failures '18-bad-disposition' { Invoke-StoreCollectEvidence -Binding $binding -TerminalState 'Green' -LogText 'x' -Secrets @() }
}

# ---------------------------------------------------------------------------
# Case 19: graceful versus forced stop distinct and bounded.
# ---------------------------------------------------------------------------
function Test-StoreCase19 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    # Stop proves the owned root's live state BEFORE and AFTER the graceful phase
    # and refuses a forced fallback unless the owned descendant closure is
    # complete, so this case injects a process observer that answers both probes
    # with a COMPLETE tree. Leaving it unbound would fall through to the real
    # observer, which cannot describe this fake process -- the case would then
    # prove a reconciliation refusal, not the graceful/forced distinction.
    $ownedPid = [int]$start['observed']['pid']
    $ownedImage = [string]$start['observed']['imagePath']
    $ownedStarted = [string]$start['observed']['startTimeUtc']
    $closing = [Collections.Generic.List[bool]]::new([bool[]]@($true, $false))
    $observer = {
        param($ctx)
        $alive = $true
        if ($closing.Count -gt 0) { $alive = $closing[0]; $closing.RemoveAt(0) }
        return @{ alive = $alive; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted; descendants = @(); treeComplete = $true }
    }.GetNewClosure()
    $gracefulController = { param($ctx) return @{ exited = $true; pid = $ctx['pid'] } }
    $graceful = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $gracefulController -ProcessObserver $observer
    Assert-StoreTrue $Failures ($graceful['stopPhase'] -ceq 'graceful') '19-graceful-phase'
    Assert-StoreTrue $Failures (-not [bool]$graceful['forced']) '19-graceful-not-forced'
    Assert-StoreTrue $Failures ($graceful['stopState'] -ceq 'OwnedResourcesStopped') '19-graceful-state'
    Assert-StoreTrue $Failures ($graceful['ownedPid'] -eq $ownedPid) '19-graceful-owned-pid'
    $forcedCalls = @{ count = 0 }
    $closingForced = [Collections.Generic.List[bool]]::new([bool[]]@($true, $true))
    $forcedObserver = {
        param($ctx)
        $alive = $true
        if ($closingForced.Count -gt 0) { $alive = $closingForced[0]; $closingForced.RemoveAt(0) }
        return @{ alive = $alive; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted; descendants = @(); treeComplete = $true }
    }.GetNewClosure()
    # The root is STILL live after the graceful phase, so the exact-owned-tree
    # forced fallback runs -- and the controller is asked for it exactly once.
    $forcedController = { param($ctx) if ($ctx['phase'] -ceq 'graceful') { return @{ exited = $false; pid = $ctx['pid'] } } else { $forcedCalls['count']++; return @{ exited = $true; pid = $ctx['pid'] } } }.GetNewClosure()
    $forced = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $forcedController -ProcessObserver $forcedObserver
    Assert-StoreTrue $Failures ($forced['stopPhase'] -ceq 'forced') '19-forced-phase'
    Assert-StoreTrue $Failures ([bool]$forced['forced']) '19-forced-flag'
    Assert-StoreTrue $Failures ($forced['stopState'] -ceq 'OwnedResourcesStopped') '19-forced-state'
    Assert-StoreTrue $Failures ($forcedCalls['count'] -eq 1) '19-forced-single'
    # The two phases are DISTINCT outcomes of one operation, not two spellings of
    # one: identical input, different observed root liveness, different phase.
    Assert-StoreTrue $Failures ([string]$graceful['stopPhase'] -cne [string]$forced['stopPhase']) '19-phases-distinct'

    # An INCOMPLETE descendant closure is a different outcome again, and it is a
    # typed refusal with retained owner identity rather than a clean stop.
    $incompleteCalls = @{ count = 0 }
    $incompleteObserver = {
        param($ctx)
        return @{ alive = $true; pid = $ownedPid; imagePath = $ownedImage; startTimeUtc = $ownedStarted; descendants = @(); treeComplete = $false }
    }.GetNewClosure()
    $incompleteController = { param($ctx) if ($ctx['phase'] -ceq 'graceful') { return @{ exited = $false; pid = $ctx['pid'] } } else { $incompleteCalls['count']++; return @{ exited = $true; pid = $ctx['pid'] } } }.GetNewClosure()
    $incomplete = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $incompleteController -ProcessObserver $incompleteObserver
    Assert-StoreTrue $Failures ($incomplete['stopState'] -ceq 'ReconciliationRequired') '19-incomplete-closure-reconciles'
    # The stop receipt keeps its typed refusal verbatim behind the
    # stop-ownership-unproven prefix, so the refusal is asserted as the code it
    # actually carries rather than by prose.
    Assert-StoreTrue $Failures ([string]$incomplete['failure'] -match '^stop-ownership-unproven:STORE-DESCENDANT-CLOSURE-INCOMPLETE:') ('19-incomplete-closure-typed: ' + [string]$incomplete['failure'])
    Assert-StoreTrue $Failures ([int]$incomplete['ownedPid'] -eq $ownedPid) '19-incomplete-closure-keeps-owner'
    Assert-StoreTrue $Failures ($incompleteCalls['count'] -eq 0) '19-incomplete-closure-no-forced-kill'
}

# ---------------------------------------------------------------------------
# Case 20: timeout/stop/sink preserve outcome and owner.
# ---------------------------------------------------------------------------
function Test-StoreCase20 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $controller = { param($ctx) return @{ exited = $true; pid = $ctx['pid'] } }
    $stop = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $controller
    Assert-StoreTrue $Failures ($stop['ownedPid'] -eq $start['observed']['pid']) '20-owner-pid'
    Assert-StoreTrue $Failures ($stop['runId'] -ceq $binding['runId']) '20-owner-run'
    $evidence = Invoke-StoreCollectEvidence -Binding $binding -TerminalState 'TimedOut' -LogText 'timed out waiting' -Secrets @()
    Assert-StoreTrue $Failures ($evidence['terminalState'] -ceq 'TimedOut') '20-timeout-preserved'
    Assert-StoreTrue $Failures ($evidence['owner'] -ceq $binding['owner']) '20-owner-preserved'
    $provider = @{
        Stop = { param($ctx) return @{ runId = $ctx['binding']['runId']; stopPhase = 'graceful' } }
    }
    $dispatched = Invoke-StoreProviderOperation -Operation 'Stop' -Provider $provider -Binding $binding -Arguments @{ startReceipt = $start }
    Assert-StoreTrue $Failures ($dispatched['stopPhase'] -ceq 'graceful') '20-dispatch-preserves'
}

# ---------------------------------------------------------------------------
# Case 21: idempotent cleanup verifies without foreign delete.
# ---------------------------------------------------------------------------
function Test-StoreCase21 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $binding = Get-StoreTestBinding
    $allocation = Get-StoreTestAllocation $binding
    $start = Get-StoreTestStartReceipt $binding $allocation
    $cleanProcess = { param($ctx) return @{ pid = $ctx['pid']; alive = $false; descendants = @() } }
    $cleanPort = { param($ctx) return @{ endpoint = $ctx['endpoint']; open = $false } }
    $cleanFiles = { param($ctx) return @{ runRoot = $ctx['runId']; runId = $ctx['runId'] } }
    $outerRoot = [string]$allocation['runRoot']
    $firstProbe = { param($ctx) return @{ runRoot = $outerRoot; locksHeld = $false; secretsPresent = $false; rootsPresent = $false; entries = @() } }.GetNewClosure()
    $first = Invoke-StoreVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $start -ProcessObserver $cleanProcess -PortObserver $cleanPort -FileProbe $firstProbe
    $secondProbe = { param($ctx) return @{ runRoot = $first['ownedRoot']; locksHeld = $false; secretsPresent = $false; rootsPresent = $false; entries = @() } }.GetNewClosure()
    $second = Invoke-StoreVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $start -ProcessObserver $cleanProcess -PortObserver $cleanPort -FileProbe $secondProbe
    Assert-StoreTrue $Failures ([bool]$second['cleaned']) '21-cleaned'
    Assert-StoreTrue $Failures ($second['cleanupState'] -ceq 'CleanupVerified') '21-verified'
    Assert-StoreTrue $Failures ($first['ownedRoot'] -ceq $second['ownedRoot']) '21-idempotent-root'
    $foreignAllocation = @{ runId = $binding['runId']; runRoot = 'C:\Windows\System32'; dataRoot = 'C:\Windows\System32'; logRoot = 'C:\Windows\System32'; secretRoot = 'C:\Windows\System32'; endpoint = '127.0.0.1:18401'; port = 18401 }
    Test-StoreRejects $Failures '21-foreign-root' { Invoke-StoreVerifyCleanup -Binding $binding -Allocation $foreignAllocation -StartReceipt $start -ProcessObserver $cleanProcess -PortObserver $cleanPort }
}

# ---------------------------------------------------------------------------
# Case 22: source and API guard with no bridge or Core mutation.
# ---------------------------------------------------------------------------
function Test-StoreCase22 {
    param([Collections.Generic.List[string]]$Failures)
    if (-not $script:ModulesAvailable) { return }
    $source = Read-StoreModuleSource $script:StoreModulePath
    Assert-StoreTrue $Failures ($source -cnotmatch 'todo!') '22-no-todo'
    Assert-StoreTrue $Failures ($source -cnotmatch 'unimplemented!') '22-no-unimplemented'
    Assert-StoreTrue $Failures ($source -cnotmatch 'run_case') '22-no-bridge-run-case'
    Assert-StoreTrue $Failures ($source -cnotmatch 'verify_result_bytes') '22-no-bridge-verify'
    Assert-StoreTrue $Failures ($source -cnotmatch 'IntegrationHarness\.Core') '22-no-core-import'
    $ops = Get-StoreClosedOperations
    Assert-StoreTrue $Failures ($ops.Count -eq 9) '22-nine-ops'
    foreach ($op in @('ValidateRequirement', 'Plan', 'Allocate', 'Start', 'ObserveReadiness', 'ResetForTest', 'CollectEvidence', 'Stop', 'VerifyCleanup')) {
        Assert-StoreTrue $Failures ($ops -ccontains $op) ("22-op-$op")
    }
    $exported = @(Get-Command -Module 'IntegrationHarness.Store' -CommandType Function -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    Assert-StoreTrue $Failures ($exported -contains 'Invoke-StoreValidateRequirement') '22-exports-validate'
    Assert-StoreTrue $Failures ($exported -contains 'Invoke-StoreVerifyCleanup') '22-exports-cleanup'
    $selfSource = [IO.File]::ReadAllText($PSCommandPath)
    Assert-StoreTrue $Failures ($selfSource -cnotmatch 'IntegrationHarness\.Core\.psm1') '22-tests-no-core-module'
}

$script:CaseTitles = @{
    1  = 'exact Store requirement and provider revision accepted'
    2  = 'unsupported requirement class and revision rejected'
    3  = 'plan is finite and mutation-free'
    4  = 'exact 3.1.4 provenance and digest reverified including cache'
    5  = 'latest missing caller-hash wrong version-arch rejected'
    6  = 'arbitrary executable URL argv env authority unrepresentable'
    7  = 'unique owned roots namespace database with race-safe endpoint'
    8  = 'path traversal reparse symlink reserved foreign rejected'
    9  = 'loopback-only endpoint with typed port conflict'
    10 = 'ephemeral credentials and minimal env never in output'
    11 = 'requested versus observed process identity distinct'
    12 = 'lost start response stays owned without retry'
    13 = 'liveness without auth is not readiness'
    14 = 'authenticated handshake distinct from fixture readiness'
    15 = 'stale and foreign receipts rejected'
    16 = 'exact fixture declaration with baseline revalidation'
    17 = 'reset failure contaminates only its group'
    18 = 'bounded redacted evidence handles with truncation'
    19 = 'graceful versus forced stop distinct and bounded'
    20 = 'timeout stop and sink preserve outcome and owner'
    21 = 'idempotent cleanup verifies without foreign delete'
    22 = 'source and API guard with no bridge or Core mutation'
}

function Invoke-StoreCaseById {
    param([Parameter(Mandatory)][int]$Id)
    $failures = New-StoreAssertionScope
    $outcome = 'HarnessError'
    $note = ''
    try {
        $null = & "Test-StoreCase$Id" $failures
        if ($failures.Count -gt 0) {
            $outcome = 'AssertionFailed'
            $note = 'store assertion failures: ' + ($failures -join ' | ')
        }
        elseif (-not $script:ModulesAvailable) {
            $outcome = 'HarnessError'
            $note = 'fail-closed: IntegrationHarness.Store module absent (' + $script:ImportDetail + ')'
        }
        else {
            $outcome = 'Passed'
            $note = 'store assertions held over fake seams'
        }
    }
    catch {
        $outcome = 'HarnessError'
        $note = 'fail-closed harness exception: ' + $_.Exception.Message
        if ($failures.Count -gt 0) {
            $note = $note + '; prior assertion failures: ' + ($failures -join ' | ')
        }
    }
    finally {
        Close-StoreTestReservations
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

function Write-StoreCaseResult {
    param([Parameter(Mandatory)][int]$Id, [Parameter(Mandatory)][string]$Outcome)
    $result = [ordered]@{
        suite           = $script:SuiteName
        case_id         = $Id
        schema_version  = $script:SchemaVersion
        outcome         = $Outcome
        identity        = ("909/{0}" -f $Id)
        content_digest  = $script:SuiteDigest
        truncated_bytes = 0
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
}

if ($CaseId -ne 0) {
    $single = $null
    try {
        $single = Invoke-StoreCaseById -Id $CaseId
    }
    catch {
        $single = [pscustomobject]@{
            CaseId   = $CaseId
            Outcome  = 'HarnessError'
            Failures = @()
            Note     = 'fail-closed dispatcher exception'
        }
    }
    Write-StoreCaseResult -Id $CaseId -Outcome $single.Outcome
    if ($single.Outcome -eq 'Passed') { exit 0 } else { exit 1 }
}

$diagnosticResults = @()
foreach ($id in $script:MinCaseId..$script:MaxCaseId) {
    $diagnosticResults += Invoke-StoreCaseById -Id $id
}
'IntegrationHarness.Store diagnostic: {0} cases, modules={1}' -f $diagnosticResults.Count, $script:ImportDetail
foreach ($row in $diagnosticResults) {
    '909/{0} {1} entry_failures={2} title={3}' -f $row.CaseId, $row.Outcome, $row.Failures.Count, $script:CaseTitles[$row.CaseId]
    '  note: {0}' -f $row.Note
}
$passed = @($diagnosticResults | Where-Object { $_.Outcome -eq 'Passed' }).Count
'summary: passed={0} failed={1}' -f $passed, ($diagnosticResults.Count - $passed)
if ($passed -eq $diagnosticResults.Count) { exit 0 } else { exit 1 }
