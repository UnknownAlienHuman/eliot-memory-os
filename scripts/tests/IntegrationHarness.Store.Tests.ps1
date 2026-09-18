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

function Get-StoreTestAllocation {
    param([hashtable]$Binding)
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    $plan = Invoke-StorePlan -Binding $Binding -Requirement (Get-StoreTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservation = { param($ctx) return @{ port = 18001; host = '127.0.0.1' } }
    $entropy = { return 'abcdef01' }
    return (Invoke-StoreAllocate -Binding $Binding -Plan $plan -BaseTemp $base -Entropy $entropy -PortReservation $reservation)
}

function Get-StoreTestStartReceipt {
    param([hashtable]$Binding, [hashtable]$Allocation)
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    if ($null -eq $Allocation) { $Allocation = Get-StoreTestAllocation $Binding }
    $launcher = { param($input_) return @{ observedPid = 4242; observedNonce = 'feedface01' } }
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
    $allocation = Get-StoreTestAllocation $binding
    foreach ($provenance in @('acquired-verified', 'cached-reverified')) {
        $launcher = { param($input_) return @{ observedPid = 5001; observedNonce = 'aa01bb02' } }
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
    $launcher = { param($input_) return @{ observedPid = 5002; observedNonce = 'bb02cc03' } }
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
    $spyLauncher = { param($input_) $seen['argv'] = $input_['argv']; return @{ observedPid = 6001; observedNonce = 'cc03dd04' } }.GetNewClosure()
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
    $planA = Invoke-StorePlan -Binding $bindingA -Requirement (Get-StoreTestRequirement)
    $planB = Invoke-StorePlan -Binding $bindingB -Requirement (Get-StoreTestRequirement)
    $base = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $reservationA = { param($ctx) return @{ port = 18101; host = '127.0.0.1' } }
    $reservationB = { param($ctx) return @{ port = 18102; host = '127.0.0.1' } }
    $allocA = Invoke-StoreAllocate -Binding $bindingA -Plan $planA -BaseTemp $base -Entropy { return 'a1b2c3d4' } -PortReservation $reservationA
    $allocB = Invoke-StoreAllocate -Binding $bindingB -Plan $planB -BaseTemp $base -Entropy { return 'e5f60718' } -PortReservation $reservationB
    Assert-StoreTrue $Failures ($allocA['runRoot'] -cne $allocB['runRoot']) '7-roots-unique'
    Assert-StoreTrue $Failures ($allocA['dataRoot'] -cne $allocB['dataRoot']) '7-data-unique'
    Assert-StoreTrue $Failures ($allocA['namespace'] -cne $allocB['namespace']) '7-ns-unique'
    Assert-StoreTrue $Failures ($allocA['database'] -cne $allocB['database']) '7-db-unique'
    Assert-StoreTrue $Failures ($allocA['port'] -ne $allocB['port']) '7-ports-distinct'
    Assert-StoreTrue $Failures ($allocA['host'] -ceq '127.0.0.1') '7-loopback'
    Assert-StoreTrue $Failures ($allocA['endpoint'] -ceq '127.0.0.1:18101') '7-endpoint-shape'
    Assert-StoreTrue $Failures ($allocA['ownerMarker'] -ceq 'eliot-harness-owned-root-v1') '7-marker'
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
        Assert-StoreTrue $Failures ($_.Exception.Message -match 'STORE-PORT-CONFLICT') '9-conflict-typed'
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
    $proc = { param($ctx) return @{ alive = $true; pid = $ctx['pid'] } }
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint'] } }
    $noAuth = { param($ctx) return @{ authenticated = $false; namespace = 'eliot_ns_01234567'; database = 'eliot_db_89abcdef'; schemaDigest = ('ab' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }
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
    $proc = { param($ctx) return @{ alive = $true; pid = $ctx['pid'] } }
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint'] } }
    $authNoFixture = { param($ctx) return @{ authenticated = $true; namespace = 'eliot_ns_01234567'; database = 'eliot_db_89abcdef'; schemaDigest = ('cd' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }
    $receipt = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $authNoFixture
    Assert-StoreTrue $Failures ([bool]$receipt['authenticated']) '14-auth-true'
    Assert-StoreTrue $Failures ([bool]$receipt['schemaReady']) '14-schema-ready'
    Assert-StoreTrue $Failures (-not [bool]$receipt['fixtureReady']) '14-fixture-false'
    Assert-StoreTrue $Failures ([bool]$receipt['ready']) '14-ready-despite-fixture'
    $authWithFixture = { param($ctx) return @{ authenticated = $true; namespace = 'eliot_ns_01234567'; database = 'eliot_db_89abcdef'; schemaDigest = ('cd' * 32); fixtureReady = $true; endpoint = $ctx['endpoint'] } }
    $receipt2 = Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $start -ProcessObserver $proc -PortObserver $port -StoreClient $authWithFixture
    Assert-StoreTrue $Failures ([bool]$receipt2['fixtureReady']) '14-fixture-true-separate'
    Assert-StoreTrue $Failures ($receipt['schemaDigest'] -ceq $receipt2['schemaDigest']) '14-schema-stable'
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
    $proc = { param($ctx) return @{ alive = $true; pid = $ctx['pid'] } }
    $port = { param($ctx) return @{ open = $true; endpoint = $ctx['endpoint'] } }
    $client = { param($ctx) return @{ authenticated = $true; namespace = 'eliot_ns_01234567'; database = 'eliot_db_89abcdef'; schemaDigest = ('12' * 32); fixtureReady = $false; endpoint = $ctx['endpoint'] } }
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
    $gracefulController = { param($ctx) return @{ exited = $true; pid = $ctx['pid'] } }
    $graceful = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $gracefulController
    Assert-StoreTrue $Failures ($graceful['stopPhase'] -ceq 'graceful') '19-graceful-phase'
    Assert-StoreTrue $Failures (-not [bool]$graceful['forced']) '19-graceful-not-forced'
    $calls = @{ count = 0 }
    $forcedController = { param($ctx) if ($ctx['phase'] -ceq 'graceful') { return @{ exited = $false; pid = $ctx['pid'] } } else { $calls['count']++; return @{ exited = $true; pid = $ctx['pid'] } } }.GetNewClosure()
    $forced = Invoke-StoreStop -Binding $binding -StartReceipt $start -ProcessController $forcedController
    Assert-StoreTrue $Failures ($forced['stopPhase'] -ceq 'forced') '19-forced-phase'
    Assert-StoreTrue $Failures ([bool]$forced['forced']) '19-forced-flag'
    Assert-StoreTrue $Failures ($calls['count'] -eq 1) '19-forced-single'
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
    $first = Invoke-StoreVerifyCleanup -Binding $binding -Allocation $allocation -StartReceipt $start -ProcessObserver $cleanProcess -PortObserver $cleanPort -FileProbe {
        param($ctx) return @{ runRoot = (Get-StoreTestAllocation (Get-StoreTestBinding))['runRoot']; locksHeld = $false; secretsPresent = $false; rootsPresent = $false; entries = @() }
    }
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
