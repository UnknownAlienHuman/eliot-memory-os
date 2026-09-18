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

# ---------------------------------------------------------------------------
# 1. Profile arbitration. This runs before ANY allocation, import, process,
#    port, pipe, worktree, or data touch. Nothing above this point has side
#    effects (function definitions and pure assignments only).
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 2. Raw-launch guard. The monolith let callers steer execution with package/
#    binary/target/name/filter/executable inputs. That path is removed: the
#    parameters stay in the signature for compatibility, but any explicit use
#    fails closed here, before anything launches.
# ---------------------------------------------------------------------------
$removedLaunchParams = @(
    'TestPackage', 'TestBinary', 'BinTarget', 'LibTarget',
    'TestName', 'TestFilterExpression', 'SurrealExecutable'
)
foreach ($name in $removedLaunchParams) {
    if ($PSBoundParameters.ContainsKey($name)) {
        Write-HarnessUsageError ("parameter -{0} no longer drives execution; fixed recipes derive from accepted inventory identities via -SelectedTestId/-SelectAllRows. Raw execution input is rejected and nothing launches." -f $name)
    }
}
if ($McpOnly) {
    Write-HarnessUsageError '-McpOnly encodes an implicit package/test selection; use explicit -SelectedTestId/-SelectAllRows. Nothing launches.'
}
if ($RunIgnored) {
    Write-HarnessUsageError '-RunIgnored encodes an implicit selection/exclusion; use explicit -SelectedTestId/-SelectAllRows. Nothing launches.'
}

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
# 5. Admitted run-root derivation (no creation). The candidate root is unique
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
    if ($HarnessProbe -ne 'none') { $seamArgs['HarnessProbe'] = $HarnessProbe }
    if ($InjectFailureAfterSecretSetup) { $seamArgs['InjectFailureAfterSecretSetup'] = $true }
    if ($null -ne $resolvedEvidenceLogPath) { $seamArgs['EvidenceLogPath'] = $resolvedEvidenceLogPath }
    if ($null -ne $resolvedResultArtifactPath) { $seamArgs['ResultArtifactPath'] = $resolvedResultArtifactPath }
}

# Coordinator-owned state: at most the explicitly requested WhatIf plan file.
# Everything run-owned (processes, ports, pipes, worktrees, data, secrets) is
# module-owned and cleaned up by the seam in reverse order, idempotently.
$planFileWritten = $false
$terminalError = $null
$seamResult = $null
try {
    $seamResult = & $seamName @seamArgs

    if ($activeProfile -eq 'WhatIf') {
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

    if ($activeProfile -eq 'ValidateConfiguration') {
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

    # -Run: the seam result carries the outcome. Probe its shape defensively
    # (documented precedence) without second-guessing a successful seam, except
    # for the load-bearing invariant: zero executed tests is NOT success.
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
        workspace_test_exit_code = $runExit
    }
    $receipt | ConvertTo-Json -Compress
    exit $runExit
}
catch {
    $terminalError = Get-BoundedErrorDetail $_.Exception.Message
    [Console]::Error.WriteLine("run-isolated-tests harness error: -{0} delegation failed: {1}" -f $activeProfile, $terminalError)
    exit $script:DelegationFailureExitCode
}
