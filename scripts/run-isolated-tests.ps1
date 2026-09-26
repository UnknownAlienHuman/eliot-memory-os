<#
.SYNOPSIS
    Bounded coordinator for isolated integration-test execution (issue #907 D-INT-CORE).

.DESCRIPTION
    Public entrypoint path preserved. Exactly one of -WhatIf, -ValidateConfiguration,
    or -Run is required; the three profiles are mutually exclusive. A default
    invocation (no profile) or a conflicting invocation (more than one profile)
    launches NOTHING and fails usage validation with exit code 2. There is no
    second -Mode API.

    Profiles:
      -WhatIf                 Validate inventory/configuration plus a finite explicitly
                              selected row set, derive the fixed commands/resources/
                              cleanup, and write at most an explicitly requested plan
                              file under the admitted run root. No process, port, pipe,
                              worktree, or data allocation.
      -ValidateConfiguration  Read-only validation/plan seams only. No dependency or
                              test launch, no file writes.
      -Run                    Require explicit selection and start exactly those frozen
                              identities via the Core/Model seams. An explicit
                              -SelectAllRows resolves to a finite current list inside
                              the seam; there is no implicit wildcard run-all and no
                              package exclusion. Empty selection, or zero discovered
                              execution, is NOT success (fail-closed).

    Selection is explicit and finite: -SelectedTestId <id...> or -SelectAllRows,
    never both, never neither (for -WhatIf/-Run). Duplicate or blank identities
    prevent start (usage validation failure, exit 2).

    Caller inputs cannot provide shell/executable/raw argv/URL/credential/
    environment-map or unrestricted output-path values. The monolith's
    caller-supplied -TestPackage/-TestBinary/-BinTarget/-LibTarget/-TestName/
    -TestFilterExpression/-SurrealExecutable launch path is removed: the parameters
    remain in the signature only for compatibility and any explicit use of them
    fails closed with a usage error. -McpOnly and -RunIgnored encode implicit
    selection/exclusion and are likewise rejected. Fixed recipes derive from
    accepted inventory identities plus the committed toolchain inside the
    IntegrationHarness.Core/Model modules. -HarnessProbe, -EvidenceLogPath,
    -ResultArtifactPath, and -InjectFailureAfterSecretSetup are execution knobs
    valid only with -Run. -PlanOutputPath is valid only with -WhatIf and must
    descend from the admitted run root. -EvidenceLogPath/-ResultArtifactPath must
    remain OUTSIDE the run-owned cleanup roots (preserved monolith check).

    Real work is delegated to scripts/integration/IntegrationHarness.Core.psm1 and
    scripts/integration/IntegrationHarness.Model.psm1 through this closed seam
    contract (resolved dynamically; a missing seam fails closed, never passes):
      Invoke-HarnessValidateConfiguration [-InventoryPath <file>] [-TimeoutSeconds <n>]
      Invoke-HarnessWhatIf -SelectedTestId <ids>|-SelectAllRows [-InventoryPath <file>]
        [-TimeoutSeconds <n>]  -> returns the finite plan object (never $null)
      Invoke-HarnessRun -SelectedTestId <ids>|-SelectAllRows [-InventoryPath <file>]
        [-RunId <id>] [-CandidateRoot <path>] [-TimeoutSeconds <n>]
        [-HarnessProbe <name>] [-InjectFailureAfterSecretSetup]
        [-EvidenceLogPath <path>] [-ResultArtifactPath <path>]
        -> returns the run result object, or throws on any failure. A result that
           reports zero executed tests is NOT success even without a throw.
    This coordinator owns profile arbitration, selection binding, run-root
    admission, and output-path admission only. It never duplicates the provider
    state machine, never launches processes/ports/pipes/worktrees/data, and never
    mutates process-global environment. Resource cleanup of run-owned state is
    module-owned; the coordinator cleans up only its own explicitly requested
    plan file (reverse order, idempotent) and retains the original failure
    alongside any cleanup failure.

    Exit codes: 2 = usage validation failure (nothing launched); 97 = harness
    delegation failure (modules/seam missing, seam threw, empty plan, or zero
    execution); 98 = coordinator-owned cleanup failure (original failure retained
    in stderr). Exit 2 is reserved for usage validation: delegation outcomes are
    never reported as 2.
#>
[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$ValidateConfiguration,
    [switch]$Run,
    [AllowEmptyCollection()][string[]]$SelectedTestId = @(),
    [switch]$SelectAllRows,
    [string]$InventoryPath,
    [string]$PlanOutputPath,
    [switch]$McpOnly,
    [string]$TestPackage = 'eliot-app',
    [string]$TestBinary,
    [string]$BinTarget,
    [switch]$LibTarget,
    [string]$TestName,
    [string]$TestFilterExpression,
    [switch]$RunIgnored,
    [ValidateRange(1, 7200)]
    [int]$TestTimeoutSeconds = 3600,
    [ValidateSet('none', 'success', 'failure', 'retained_handle')]
    [string]$HarnessProbe = 'none',
    [switch]$InjectFailureAfterSecretSetup,
    [string]$EvidenceLogPath,
    [string]$ResultArtifactPath,
    [string]$SurrealExecutable = $env:ELIOT_SURREAL_EXE
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:UsageExitCode = 2
$script:DelegationFailureExitCode = 97
$script:CleanupFailureExitCode = 98
$script:MaxSelectedIds = 100000
$script:MaxSelectedIdLength = 1024
$script:MaxStderrDetailChars = 4096

function Write-HarnessUsageError {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("run-isolated-tests usage error: $Message")
    [Console]::Error.WriteLine('usage: run-isolated-tests.ps1 -WhatIf|-ValidateConfiguration|-Run -SelectedTestId <id...>|-SelectAllRows [-InventoryPath <file>] [-PlanOutputPath <under-run-root>]')
    [Console]::Error.WriteLine('profiles are mutually exclusive; default or conflicting invocation launches nothing.')
    exit $script:UsageExitCode
}

function Write-HarnessInternalError {
    param([Parameter(Mandatory)][string]$Message)

    [Console]::Error.WriteLine("run-isolated-tests harness error: $Message")
    exit $script:DelegationFailureExitCode
}

function Get-BoundedErrorDetail {
    param([Parameter(Mandatory)][string]$Text)

    if ($Text.Length -gt $script:MaxStderrDetailChars) {
        return $Text.Substring(0, $script:MaxStderrDetailChars) + '...[truncated]'
    }
    return $Text
}

function Get-FileSha256Hex {
    param([Parameter(Mandatory)][string]$Path)

    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
# Profile arbitration (#907 W1): exactly one of -WhatIf, -ValidateConfiguration,
# -Run. Default or conflicting invocation launches nothing (usage error, exit 2).
# Called once from the main flow before any allocation, import, or data touch.
function Resolve-HarnessActiveProfile {
    param([switch]$WhatIf, [switch]$ValidateConfiguration, [switch]$Run)

    $profileCount = 0
    $activeProfile = $null
    if ($WhatIf) { $profileCount++; $activeProfile = 'WhatIf' }
    if ($ValidateConfiguration) { $profileCount++; $activeProfile = 'ValidateConfiguration' }
    if ($Run) { $profileCount++; $activeProfile = 'Run' }
    if ($profileCount -eq 0) {
        Write-HarnessUsageError 'exactly one profile (-WhatIf, -ValidateConfiguration, or -Run) is required; default invocation launches nothing.'
    }
    if ($profileCount -gt 1) {
        Write-HarnessUsageError 'profiles -WhatIf, -ValidateConfiguration, and -Run are mutually exclusive; conflicting invocation launches nothing.'
    }
    return $activeProfile
}

# Raw-launch guard (#907 W3): reject caller-controlled execution inputs before
# anything launches. Takes the script's bound parameter names explicitly because
# $PSBoundParameters inside a function would be the function's own.
function Test-HarnessLaunchInput {
    param(
        [AllowEmptyCollection()][string[]]$BoundParameterNames = @(),
        [switch]$McpOnly,
        [switch]$RunIgnored
    )

    $removedLaunchParams = @(
        'TestPackage', 'TestBinary', 'BinTarget', 'LibTarget',
        'TestName', 'TestFilterExpression', 'SurrealExecutable'
    )
    foreach ($name in $removedLaunchParams) {
        if ($BoundParameterNames -contains $name) {
            Write-HarnessUsageError ("parameter -{0} no longer drives execution; fixed recipes derive from accepted inventory identities via -SelectedTestId/-SelectAllRows. Raw execution input is rejected and nothing launches." -f $name)
        }
    }
    if ($McpOnly) {
        Write-HarnessUsageError '-McpOnly encodes an implicit package/test selection; use explicit -SelectedTestId/-SelectAllRows. Nothing launches.'
    }
    if ($RunIgnored) {
        Write-HarnessUsageError '-RunIgnored encodes an implicit selection/exclusion; use explicit -SelectedTestId/-SelectAllRows. Nothing launches.'
    }
    return $true
}

# -WhatIf profile dispatch (#907 W2/W10 seam edge): invoke the WhatIf seam for
# the frozen selection, publish at most the explicitly requested plan file under
# the admitted run root (reverse-order idempotent coordinator cleanup, original
# failure retained), then emit the terminal receipt. Reads script-scope
# admission/identity state; writes only the function-local plan flag.
function Invoke-HarnessWhatIfProfile {
    param([Parameter(Mandatory)][hashtable]$SeamArgs)

    $planFileWritten = $false
    $seamResult = Invoke-HarnessWhatIf @SeamArgs

    if ($null -eq $seamResult) {
        throw 'the WhatIf seam returned an empty plan; an empty plan is not success.'
    }
    $planJson = $seamResult | ConvertTo-Json -Depth 16 -Compress
    $planDigest = [BitConverter]::ToString(
        [Security.Cryptography.SHA256]::Create().ComputeHash(
            [Text.Encoding]::UTF8.GetBytes($planJson))).Replace('-', '').ToLowerInvariant()
    if ($null -ne $resolvedPlanPath) {
        $planParent = Split-Path -Parent $resolvedPlanPath
        $planParentFull = [IO.Path]::GetFullPath($planParent)
        $planParentPrefix = $planParentFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $planParentPrefix.StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            $planParentFull -ine $candidateRoot) {
            throw 'the requested plan path escapes the admitted run root on re-admission.'
        }
        [IO.Directory]::CreateDirectory($planParentFull) | Out-Null
        try {
            [IO.File]::WriteAllText($resolvedPlanPath, $planJson, [Text.UTF8Encoding]::new($false))
            $planFileWritten = $true
        }
        catch {
            $writeError = $_.Exception.Message
            $cleanupError = $null
            try {
                if (Test-Path -LiteralPath $resolvedPlanPath -PathType Leaf) {
                    Remove-Item -LiteralPath $resolvedPlanPath -Force -ErrorAction Stop
                }
            }
            catch {
                $cleanupError = Get-BoundedErrorDetail $_.Exception.Message
            }
            if ($null -ne $cleanupError) {
                throw ("plan publication failed ({0}); coordinator-owned partial cleanup also failed ({1}); original failure retained." -f $writeError, $cleanupError)
            }
            throw
        }
    }
    $receipt = [ordered]@{
        component = 'run-isolated-tests'
        profile = $activeProfile
        operation_status = 'OPERATION_COMPLETED'
        run_id = $runId
        admitted_root = $candidateRoot.Replace('\', '/')
        selection_count = $explicitIds.Count
        select_all_rows = [bool]$SelectAllRows
        inventory = if ($null -eq $resolvedInventoryPath) { 'default' } else { $resolvedInventoryPath.Replace('\', '/') }
        plan_digest = $planDigest
        plan_file = if ($null -eq $resolvedPlanPath) { $null } else { $resolvedPlanPath.Replace('\', '/') }
        plan_file_written = $planFileWritten
        seam = $seamName
        entrypoint_sha256 = (Get-FileSha256Hex $PSCommandPath)
        core_module_sha256 = (Get-FileSha256Hex $coreModulePath)
        model_module_sha256 = (Get-FileSha256Hex $modelModulePath)
        workspace_test_exit_code = 0
    }
    $receipt | ConvertTo-Json -Compress
    exit 0
}

# -ValidateConfiguration profile dispatch: invoke the read-only validation seam
# and emit the terminal receipt. No plan file, no execution artifacts.
function Invoke-HarnessValidateConfigurationProfile {
    param([Parameter(Mandatory)][hashtable]$SeamArgs)

    $seamResult = Invoke-HarnessValidateConfiguration @SeamArgs
    $receipt = [ordered]@{
        component = 'run-isolated-tests'
        profile = $activeProfile
        operation_status = 'OPERATION_COMPLETED'
        run_id = $runId
        inventory = if ($null -eq $resolvedInventoryPath) { 'default' } else { $resolvedInventoryPath.Replace('\', '/') }
        seam = $seamName
        entrypoint_sha256 = (Get-FileSha256Hex $PSCommandPath)
        core_module_sha256 = (Get-FileSha256Hex $coreModulePath)
        model_module_sha256 = (Get-FileSha256Hex $modelModulePath)
        workspace_test_exit_code = 0
    }
    $receipt | ConvertTo-Json -Compress
    exit 0
}

# #907 OBJ provider dispatch: the Run profile binds the closed 9-operation
# provider table from the real Store/Runtime mechanics. Binding is by EXACT
# native-identity triple match only (testClass/providerName/providerRevision
# against each loaded provider module's self-declared identity): never
# translated, never guessed. Anything else throws a typed no-bound-provider
# error that the Run seam turns into per-test InfrastructureBlocked -- a
# producing branch, never skip/pass. Operations whose inputs have no explicit
# source (runtime target, launch binary, execution client/outcome) throw typed
# missing-input errors for the same treatment; the #909/#911 provider inputs
# fill those seams without reshaping this table.
function Resolve-HarnessBoundProviderClass {
    param([Parameter(Mandatory)][hashtable]$Binding)

    $testClass = [string]$Binding['testClass']
    $providerName = [string]$Binding['providerName']
    $providerRevision = [string]$Binding['providerRevision']
    $storeIdentity = Get-StoreProviderIdentity
    if ($testClass -ceq [string]$storeIdentity['testClass'] -and
        $providerName -ceq [string]$storeIdentity['providerName'] -and
        $providerRevision -ceq [string]$storeIdentity['providerRevision']) {
        return 'STORE'
    }
    $runtimeIdentity = Get-RuntimeProviderIdentity
    if ($testClass -ceq [string]$runtimeIdentity['testClass'] -and
        $providerName -ceq [string]$runtimeIdentity['providerName'] -and
        $providerRevision -ceq [string]$runtimeIdentity['providerRevision']) {
        return 'RUNTIME'
    }
    throw ("HARNESS-NO-BOUND-PROVIDER: no loaded real provider matches binding '{0}' / '{1}' / '{2}'; refusing to translate or guess a provider." -f $testClass, $providerName, $providerRevision)
}

function New-HarnessRunProviderTable {
    param(
        [Parameter(Mandatory)][string]$BaseTemp,
        [Parameter(Mandatory)][hashtable]$RunState,
        [Parameter(Mandatory)][scriptblock]$Entropy,
        [Parameter(Mandatory)][scriptblock]$PortReservation
    )

    $table = @{
        ValidateRequirement = {
            param($context)
            $binding = $context.binding
            $class = Resolve-HarnessBoundProviderClass -Binding $binding
            if ($class -ceq 'RUNTIME') {
                throw 'HARNESS-NO-EXPLICIT-RUNTIME-TARGET: runtime validation needs a topology target and Run arguments carry none; the row targetClass is not threaded through.'
            }
            $requirement = @{ testClass = [string]$binding['testClass']; providerRevision = [string]$binding['providerRevision'] }
            return Invoke-StoreValidateRequirement -Binding $binding -Requirement $requirement -Lock (Get-StoreLockIdentity)
        }.GetNewClosure()
        Plan = {
            param($context)
            $binding = $context.binding
            $class = Resolve-HarnessBoundProviderClass -Binding $binding
            if ($class -ceq 'RUNTIME') {
                throw 'HARNESS-NO-EXPLICIT-RUNTIME-TARGET: runtime planning needs a topology target and Run arguments carry none; the row targetClass is not threaded through.'
            }
            $requirement = @{ testClass = [string]$binding['testClass']; providerRevision = [string]$binding['providerRevision'] }
            return Invoke-StorePlan -Binding $binding -Requirement $requirement
        }.GetNewClosure()
        Allocate = {
            param($context)
            $binding = $context.binding
            $class = Resolve-HarnessBoundProviderClass -Binding $binding
            $key = [string]$context.arguments['resourceKey']
            if ($class -ceq 'RUNTIME') {
                $result = Invoke-RuntimeAllocate -Binding $binding -Plan $context.arguments['plan'] -BaseTemp $BaseTemp -Entropy $Entropy
            } else {
                $result = Invoke-StoreAllocate -Binding $binding -Plan $context.arguments['plan'] -BaseTemp $BaseTemp -Entropy $Entropy -PortReservation $PortReservation
            }
            $RunState['allocations'][$key] = $result
            return $result
        }.GetNewClosure()
        Start = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            throw 'HARNESS-NO-EXPLICIT-LAUNCH-TARGET: no tool input selects a launch binary, so nothing is launched; the acquisition/launcher seam stays empty for the #909/#911 provider inputs.'
        }.GetNewClosure()
        ObserveReadiness = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            throw 'HARNESS-NO-START-RECEIPT: Start never proceeds without an explicit launch target, so there is nothing to observe.'
        }.GetNewClosure()
        ResetForTest = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            throw 'HARNESS-NO-EXECUTION-CLIENT: fixture reset needs a store/topology client and fixture inputs that no explicit input binds.'
        }.GetNewClosure()
        CollectEvidence = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            throw 'HARNESS-NO-EXECUTION-INPUT: evidence collection needs a test-binary locator and outcome inputs that no explicit input binds; provider success alone never passes.'
        }.GetNewClosure()
        Stop = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            $key = [string]$context.arguments['resourceKey']
            if (-not $RunState['startReceipts'].ContainsKey($key)) {
                return @{ stopped = $true; reason = 'never-started' }
            }
            throw 'HARNESS-NO-PROCESS-CONTROLLER: a start receipt exists but no identity-bound process controller is constructed yet.'
        }.GetNewClosure()
        VerifyCleanup = {
            param($context)
            [void](Resolve-HarnessBoundProviderClass -Binding $context.binding)
            $key = [string]$context.arguments['resourceKey']
            if (-not $RunState['allocations'].ContainsKey($key)) {
                throw ("HARNESS-NO-ALLOCATION: no allocation is recorded for '{0}'; nothing to verify." -f $key)
            }
            throw 'HARNESS-NO-START-RECEIPT: verification needs a start receipt and Start never proceeds without an explicit launch target.'
        }.GetNewClosure()
    }
    return $table
}

 
# -Run profile dispatch (#907 OBJ edge): invoke the Run seam for exactly the
# frozen selection, probe the result shape defensively, and emit the terminal
# receipt. Zero executed tests is NOT success (fail-closed throw).
function Invoke-HarnessRunProfile {
    param([Parameter(Mandatory)][hashtable]$SeamArgs)

    # -Run: the seam result carries the outcome. Probe its shape defensively
    # (documented precedence) without second-guessing a successful seam, except
    # for the load-bearing invariant: zero executed tests is NOT success.
    $seamResult = Invoke-HarnessRun @SeamArgs
    $runExit = 0
    $executedCount = $null
    if ($null -eq $seamResult) {
        throw 'the Run seam returned no result; an empty result is not success.'
    }
    foreach ($prop in @('workspace_test_exit_code', 'exit_code', 'exitCode')) {
        if ($null -ne $seamResult.PSObject -and $null -ne $seamResult.PSObject.Properties[$prop]) {
            $candidate = $seamResult.PSObject.Properties[$prop].Value
            if ($candidate -is [int] -and $candidate -ge 0 -and $candidate -le 255) { $runExit = $candidate }
            elseif ($candidate -is [int]) { $runExit = 1 }
            break
        }
    }
    foreach ($prop in @('executed_test_count', 'tests_executed', 'tests_run')) {
        if ($null -ne $seamResult.PSObject -and $null -ne $seamResult.PSObject.Properties[$prop]) {
            $candidate = $seamResult.PSObject.Properties[$prop].Value
            if ($candidate -is [int]) { $executedCount = $candidate }
            break
        }
    }
    if ($null -ne $executedCount -and $executedCount -eq 0) {
        throw 'the Run seam reported zero executed tests; zero discovered execution is not success.'
    }
    $receipt = [ordered]@{
        component = 'run-isolated-tests'
        profile = $activeProfile
        operation_status = if ($runExit -eq 0) { 'OPERATION_COMPLETED' } else { 'FAILED' }
        run_id = $runId
        admitted_root = $candidateRoot.Replace('\', '/')
        selection_count = $explicitIds.Count
        select_all_rows = [bool]$SelectAllRows
        inventory = if ($null -eq $resolvedInventoryPath) { 'default' } else { $resolvedInventoryPath.Replace('\', '/') }
        executed_test_count = $executedCount
        seam = $seamName
        entrypoint_sha256 = (Get-FileSha256Hex $PSCommandPath)
        core_module_sha256 = (Get-FileSha256Hex $coreModulePath)
        model_module_sha256 = (Get-FileSha256Hex $modelModulePath)
        store_module_sha256 = (Get-FileSha256Hex $storeModulePath)
        runtime_module_sha256 = (Get-FileSha256Hex $runtimeModulePath)
        workspace_test_exit_code = $runExit
    }
    $receipt | ConvertTo-Json -Compress
    exit $runExit
}


# ---------------------------------------------------------------------------
# 1. Profile arbitration. This runs before ANY allocation, import, process,
#    port, pipe, worktree, or data touch. Nothing above this point has side
#    effects (function definitions and pure assignments only). The arbitration
#    logic lives in Resolve-HarnessActiveProfile; the call below is the edge.
# ---------------------------------------------------------------------------
$activeProfile = Resolve-HarnessActiveProfile -WhatIf:$WhatIf -ValidateConfiguration:$ValidateConfiguration -Run:$Run

# ---------------------------------------------------------------------------
# 2. Raw-launch guard. The monolith let callers steer execution with package/
#    binary/target/name/filter/executable inputs. That path is removed: the
#    parameters stay in the signature for compatibility, but any explicit use
#    fails closed here, before anything launches. The guard logic lives in
#    Test-HarnessLaunchInput; the call below passes the script's own bound
#    parameter names explicitly and is the production edge.
# ---------------------------------------------------------------------------
[void](Test-HarnessLaunchInput -BoundParameterNames @($PSBoundParameters.Keys) -McpOnly:$McpOnly -RunIgnored:$RunIgnored)

# ---------------------------------------------------------------------------
# 3. Explicit finite selection. -Run and -WhatIf require exactly one selection
#    form with at least one usable, non-duplicate identity. Empty selection is
#    NOT success. -ValidateConfiguration accepts an optional selection for its
#    read-only plan seams but still rejects contradictory/duplicate input.
# ---------------------------------------------------------------------------
$explicitIds = @()
if ($PSBoundParameters.ContainsKey('SelectedTestId') -and $null -ne $SelectedTestId) {
    $explicitIds = @($SelectedTestId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
}
if ($PSBoundParameters.ContainsKey('SelectedTestId') -and $explicitIds.Count -eq 0) {
    Write-HarnessUsageError '-SelectedTestId was provided but contains no usable identity; empty selection is not success and launches nothing.'
}
$duplicateIds = @($explicitIds | Group-Object -NoElement | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
if ($duplicateIds.Count -gt 0) {
    Write-HarnessUsageError ("duplicate test identities prevent start: {0}" -f ($duplicateIds -join ', '))
}
foreach ($id in $explicitIds) {
    if ($id.Length -gt $script:MaxSelectedIdLength) {
        Write-HarnessUsageError 'a selected test identity exceeds the bounded length; selection rejected and nothing launches.'
    }
}
if ($explicitIds.Count -gt $script:MaxSelectedIds) {
    Write-HarnessUsageError 'selection exceeds the bounded row cap; selection rejected and nothing launches.'
}
if ($SelectAllRows -and $explicitIds.Count -gt 0) {
    Write-HarnessUsageError '-SelectAllRows and -SelectedTestId are mutually exclusive; contradictory selection launches nothing.'
}
$hasSelection = ($explicitIds.Count -gt 0) -or [bool]$SelectAllRows
if (($activeProfile -eq 'Run' -or $activeProfile -eq 'WhatIf') -and -not $hasSelection) {
    Write-HarnessUsageError ("-{0} requires explicit finite selection (-SelectedTestId or -SelectAllRows); empty selection is not success and launches nothing." -f $activeProfile)
}

# ---------------------------------------------------------------------------
# 4. Profile-gated knobs. Execution probes/artifacts belong to -Run; plan
#    output belongs to -WhatIf; -ValidateConfiguration takes none of them.
# ---------------------------------------------------------------------------
if ($activeProfile -ne 'Run') {
    if ($HarnessProbe -ne 'none') {
        Write-HarnessUsageError ("-HarnessProbe is an execution probe and is valid only with -Run, not -{0}. Nothing launches." -f $activeProfile)
    }
    if ($InjectFailureAfterSecretSetup) {
        Write-HarnessUsageError ("-InjectFailureAfterSecretSetup is an execution failure-injection knob and is valid only with -Run, not -{0}. Nothing launches." -f $activeProfile)
    }
    if ($PSBoundParameters.ContainsKey('EvidenceLogPath')) {
        Write-HarnessUsageError ("-EvidenceLogPath is an execution artifact path and is valid only with -Run, not -{0}. Nothing launches." -f $activeProfile)
    }
    if ($PSBoundParameters.ContainsKey('ResultArtifactPath')) {
        Write-HarnessUsageError ("-ResultArtifactPath is an execution artifact path and is valid only with -Run, not -{0}. Nothing launches." -f $activeProfile)
    }
}
if ($PSBoundParameters.ContainsKey('PlanOutputPath') -and $activeProfile -ne 'WhatIf') {
    Write-HarnessUsageError '-PlanOutputPath is valid only with -WhatIf. Nothing launches.'
}

# ---------------------------------------------------------------------------
# 5. Admitted run-root derivation (plus the empty root itself for -Run). The candidate root is unique
#    per invocation, must descend from TEMP, and must not cross a forbidden
#    host boundary. The seam admits (creates + writes the owner receipt for)
#    the final run root; the coordinator never creates worktree/data state.
# ---------------------------------------------------------------------------
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$runId = [guid]::NewGuid().ToString('N')
$candidateRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ("eliot-harness-{0}-{1}" -f $PID, $runId)))
$ownedPrefix = $candidateRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $ownedPrefix.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    Write-HarnessInternalError 'admitted run-root derivation escaped TEMP.'
}
$lowerRoot = $candidateRoot.ToLowerInvariant()
if ($lowerRoot.Contains('onedrive') -or $lowerRoot.Contains('programdata')) {
    Write-HarnessUsageError 'admitted run root crossed a forbidden host boundary; nothing launches.'
}
# The Run coordinator admits (creates) exactly this empty root: the owned-run-root
# seam requires an existing, reparse-walked base and creates everything under
# it. All run-owned state (processes, ports, pipes, worktrees, data, secrets)
# stays module-owned; the coordinator creates nothing else. Other profiles
# create nothing (WhatIf self-creates its plan parents).
if ($activeProfile -eq 'Run') {
    try {
        [IO.Directory]::CreateDirectory($candidateRoot) | Out-Null
    }
    catch {
        Write-HarnessInternalError ('admitted run-root creation failed: ' + (Get-BoundedErrorDetail $_.Exception.Message))
    }
}

# ---------------------------------------------------------------------------
# 6. Path admission. Inventory (when given) must be an existing file. The
#    WhatIf plan file, when requested, must descend from the admitted run
#    root. Execution artifacts must remain OUTSIDE the run-owned cleanup
#    roots (preserved monolith check).
# ---------------------------------------------------------------------------
$resolvedInventoryPath = $null
if ($PSBoundParameters.ContainsKey('InventoryPath')) {
    if ([string]::IsNullOrWhiteSpace($InventoryPath)) {
        Write-HarnessUsageError '-InventoryPath must be a nonempty path to an existing inventory file.'
    }
    try {
        $resolvedInventoryPath = [IO.Path]::GetFullPath($InventoryPath)
    }
    catch {
        Write-HarnessUsageError 'the -InventoryPath value is not a usable path.'
    }
    if (-not (Test-Path -LiteralPath $resolvedInventoryPath -PathType Leaf)) {
        Write-HarnessUsageError ("inventory file is absent: {0}" -f $resolvedInventoryPath)
    }
}

$resolvedPlanPath = $null
if ($PSBoundParameters.ContainsKey('PlanOutputPath')) {
    if ([string]::IsNullOrWhiteSpace($PlanOutputPath)) {
        Write-HarnessUsageError '-PlanOutputPath must be a nonempty path under the admitted run root.'
    }
    try {
        $resolvedPlanPath = [IO.Path]::GetFullPath($PlanOutputPath)
    }
    catch {
        Write-HarnessUsageError 'the -PlanOutputPath value is not a usable path.'
    }
    if (-not $resolvedPlanPath.StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Write-HarnessUsageError 'the requested plan path escapes the admitted run root; path-escape and foreign-root output are rejected and nothing launches.'
    }
    if ((Test-Path -LiteralPath $resolvedPlanPath -PathType Container)) {
        Write-HarnessUsageError 'the requested plan path names an existing directory, not a plan file.'
    }
}

$resolvedEvidenceLogPath = $null
$resolvedResultArtifactPath = $null
if ($PSBoundParameters.ContainsKey('EvidenceLogPath') -and -not [string]::IsNullOrWhiteSpace($EvidenceLogPath)) {
    $resolvedEvidenceLogPath = [IO.Path]::GetFullPath($EvidenceLogPath)
    if ($resolvedEvidenceLogPath.StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedEvidenceLogPath -ieq $candidateRoot) {
        Write-HarnessUsageError 'evidence log path must remain outside the run-owned cleanup root.'
    }
}
if ($PSBoundParameters.ContainsKey('ResultArtifactPath') -and -not [string]::IsNullOrWhiteSpace($ResultArtifactPath)) {
    $resolvedResultArtifactPath = [IO.Path]::GetFullPath($ResultArtifactPath)
    if ($resolvedResultArtifactPath.StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        $resolvedResultArtifactPath -ieq $candidateRoot) {
        Write-HarnessUsageError 'result artifact path must remain outside the run-owned cleanup root.'
    }
}

# ---------------------------------------------------------------------------
# 7. Delegation. Import the real Core/Model modules (no duplicated state
#    machine) and dispatch to the closed profile seam. Import happens only
#    AFTER usage validation, so default/conflicting/contradictory invocations
#    always report usage error (exit 2), never a delegation failure.
#    Per-profile invocation plus terminal receipts live in the
#    Invoke-HarnessWhatIfProfile / Invoke-HarnessValidateConfigurationProfile /
#    Invoke-HarnessRunProfile functions; the dispatch below is the edge.
# ---------------------------------------------------------------------------
$coreModulePath = Join-Path $PSScriptRoot 'integration\IntegrationHarness.Core.psm1'
$modelModulePath = Join-Path $PSScriptRoot 'integration\IntegrationHarness.Model.psm1'
try {
    Import-Module -Name $coreModulePath -ErrorAction Stop
    Import-Module -Name $modelModulePath -ErrorAction Stop
}
catch {
    [Console]::Error.WriteLine(
        ("run-isolated-tests harness error: IntegrationHarness.Core/Model modules unavailable; cannot delegate -{0}. Missing file or import failure: {1}" -f
            $activeProfile, (Get-BoundedErrorDetail $_.Exception.Message)))
    exit $script:DelegationFailureExitCode
}

# #907 OBJ: the Run profile additionally binds the real provider mechanics.
# Other profiles stay dependency-light and never touch these modules.
$storeModulePath = $null
$runtimeModulePath = $null
if ($activeProfile -eq 'Run') {
    $storeModulePath = Join-Path $PSScriptRoot 'integration\IntegrationHarness.Store.psm1'
    $runtimeModulePath = Join-Path $PSScriptRoot 'integration\IntegrationHarness.Runtime.psm1'
    try {
        Import-Module -Name $storeModulePath -ErrorAction Stop
        Import-Module -Name $runtimeModulePath -ErrorAction Stop
    }
    catch {
        [Console]::Error.WriteLine(
            ("run-isolated-tests harness error: IntegrationHarness.Store/Runtime provider modules unavailable; cannot delegate -Run. Missing file or import failure: {0}" -f
                (Get-BoundedErrorDetail $_.Exception.Message)))
        exit $script:DelegationFailureExitCode
    }
}

$seamName = $null
if ($activeProfile -eq 'WhatIf') { $seamName = 'Invoke-HarnessWhatIf' }
elseif ($activeProfile -eq 'ValidateConfiguration') { $seamName = 'Invoke-HarnessValidateConfiguration' }
else { $seamName = 'Invoke-HarnessRun' }
$seam = Get-Command -Name $seamName -CommandType Function -ErrorAction SilentlyContinue
if ($null -eq $seam) {
    [Console]::Error.WriteLine(
        ("run-isolated-tests harness error: required profile seam '{0}' is not exported by the IntegrationHarness modules; cannot delegate -{1}." -f
            $seamName, $activeProfile))
    exit $script:DelegationFailureExitCode
}

$seamArgs = @{ TimeoutSeconds = $TestTimeoutSeconds }
if ($activeProfile -eq 'WhatIf' -or $activeProfile -eq 'Run') {
    $seamArgs['SelectedTestId'] = [string[]]$explicitIds
    if ($SelectAllRows) { $seamArgs['SelectAllRows'] = $true }
}
if ($null -ne $resolvedInventoryPath) { $seamArgs['InventoryPath'] = $resolvedInventoryPath }
if ($activeProfile -eq 'Run') {
    $seamArgs['RunId'] = $runId
    $seamArgs['CandidateRoot'] = $candidateRoot
    # #907 OBJ: bind the closed provider table. Cross-op state (allocations,
    # start receipts) lives in this coordinator-closed hashtable, keyed by
    # resource key; adapters snapshot it via .GetNewClosure().
    $providerRunState = @{ allocations = @{}; startReceipts = @{} }
    $providerEntropy = {
        $bytes = New-Object byte[] 8
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }.GetNewClosure()
    $providerPortReservation = {
        param($request)
        # Ephemeral loopback port pick: bind :0, read the port, release.
        # Documented pick-vs-bind race window (test-harness scope only);
        # never a privileged or non-loopback endpoint.
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        try {
            $listener.Start()
            $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        } finally {
            $listener.Stop()
        }
        if ($port -lt 1024 -or $port -gt 65535) {
            throw ("HARNESS-PORT-RESERVATION: picked port '{0}' is outside the ephemeral bound." -f $port)
        }
        return @{ host = '127.0.0.1'; port = $port }
    }.GetNewClosure()
    $seamArgs['Provider'] = New-HarnessRunProviderTable -BaseTemp $candidateRoot `
        -RunState $providerRunState -Entropy $providerEntropy -PortReservation $providerPortReservation
    if ($HarnessProbe -ne 'none') { $seamArgs['HarnessProbe'] = $HarnessProbe }
    if ($InjectFailureAfterSecretSetup) { $seamArgs['InjectFailureAfterSecretSetup'] = $true }
    if ($null -ne $resolvedEvidenceLogPath) { $seamArgs['EvidenceLogPath'] = $resolvedEvidenceLogPath }
    if ($null -ne $resolvedResultArtifactPath) { $seamArgs['ResultArtifactPath'] = $resolvedResultArtifactPath }
}

# Coordinator-owned state: at most the explicitly requested WhatIf plan file.
# Everything run-owned (processes, ports, pipes, worktrees, data, secrets) is
# module-owned and cleaned up by the seam in reverse order, idempotently.
$terminalError = $null
try {
    if ($activeProfile -eq 'WhatIf') {
        Invoke-HarnessWhatIfProfile -SeamArgs $seamArgs
    }
    elseif ($activeProfile -eq 'ValidateConfiguration') {
        Invoke-HarnessValidateConfigurationProfile -SeamArgs $seamArgs
    }
    else {
        Invoke-HarnessRunProfile -SeamArgs $seamArgs
    }
}
catch {
    $terminalError = Get-BoundedErrorDetail $_.Exception.Message
    # The -f expression must be parenthesized: WriteLine(...) parses commas as
    # argument separators, so an unparenthesized -f formats with one argument
    # and throws instead of reporting the delegation failure (exit 97).
    [Console]::Error.WriteLine(("run-isolated-tests harness error: -{0} delegation failed: {1}" -f $activeProfile, $terminalError))
    exit $script:DelegationFailureExitCode
}
