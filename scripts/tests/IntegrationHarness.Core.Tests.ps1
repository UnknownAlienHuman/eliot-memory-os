<#
.SYNOPSIS
    PowerShell self-test suite for the #907 D-INT-CORE harness core (cases 1-32).

.DESCRIPTION
    Bridge contract (scripts/integration/powershell_case_bridge.py, WRITER-B owned):
    invoked as `pwsh -NoProfile -NonInteractive -File <this path> -CaseId <id>`
    with a positive integer 1..32, this file emits EXACTLY ONE bounded versioned
    JSON object to stdout with the closed field set:
      suite, case_id, schema_version, outcome, identity, content_digest,
      truncated_bytes
    outcome is one of Passed | AssertionFailed | TimedOut | ProcessCrashed |
    InfrastructureBlocked | UnsupportedExternalCredential | HarnessError |
    Cancelled | NotExecutedDueToPriorContamination | Skipped. Only Passed with
    process exit 0 verifies green. content_digest is the SHA-256 hex of the exact
    bytes of this file. identity is always "907/<case_id>".

    Without -CaseId this file is a diagnostic entrypoint: it executes all cases
    1..32 in-process and reports each identity plus its outcome.

    Each case asserts ACTUAL behavior:
      (a) entrypoint-level assertions against the real scripts/run-isolated-tests.ps1
          coordinator, executed as a child pwsh process with ProcessStartInfo
          (shell disabled, fixed argv, bounded time/output). Child shapes are
          restricted to invocations that fail closed BEFORE module import in EVERY
          environment (usage-validation rejections exit 2, parameter-binding
          errors exit non-zero), plus the two delegating shapes the issue
          guarantees fail fast without launching (read-only ValidateConfiguration,
          and Run with a guaranteed-unknown identity). Tests NEVER invoke -Run or
          -WhatIf with a satisfiable selection, which would really execute.
      (b) module-level assertions against the real
          scripts/integration/IntegrationHarness.Core.psm1 and Model.psm1 modules
          (imported conditionally; discovery-, behavior-, and source-based checks
          with no fixtures and no launched services).

    Issue #907 D1: -HarnessProbe was removed from both the entrypoint and the
    Core Run seam, because it fabricated Passed dispositions with no contained
    execution behind them. Case 19 is the mandatory negative test: it invokes
    the PUBLIC entrypoint with every former probe value and proves no green
    run, no stdout receipt and no exit code that could be read as success.
    Cases 24 and 31 assert the injected-clock and redaction-completeness
    contracts respectively.

    The expected module seam names below are the single reconciliation point
    shared with WRITER-A/WRITER-B. If a seam is absent, the affected cases fail
    closed with HarnessError (never a pass, never a fabricated green).

    When the Core/Model modules are absent (parallel WRITER-A work), every case
    fails closed honestly with HarnessError after still executing its
    entrypoint-level assertions. No case ever reports Passed without the real
    modules present.
#>
[CmdletBinding()]
param(
    [ValidateRange(0, 32)]
    [int]$CaseId = 0
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:SuiteName = 'IntegrationHarness.Core'
$script:SchemaVersion = 'harness-core-case-result-v1'
$script:MinCaseId = 1
$script:MaxCaseId = 32
$script:RepoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$script:EntrypointPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\run-isolated-tests.ps1'))
$script:CoreModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\integration\IntegrationHarness.Core.psm1'))
$script:ModelModulePath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\integration\IntegrationHarness.Model.psm1'))
$script:ChildTimeoutMilliseconds = 60000
$script:MaxChildOutputChars = 65536
$script:MaxModuleSourceBytes = 1048576

# Single reconciliation point for the expected module seam surface (WRITER-A).
$script:ExpectedSeams = @{
    ValidateConfiguration = 'Invoke-HarnessValidateConfiguration'
    WhatIf                = 'Invoke-HarnessWhatIf'
    Run                   = 'Invoke-HarnessRun'
}
$script:TerminalOutcomes = @(
    'Passed', 'AssertionFailed', 'TimedOut', 'ProcessCrashed',
    'InfrastructureBlocked', 'UnsupportedExternalCredential', 'HarnessError',
    'Cancelled', 'NotExecutedDueToPriorContamination'
)
$script:RemovedRawParams = @(
    'TestBinary', 'BinTarget', 'LibTarget', 'TestName',
    'TestFilterExpression', 'SurrealExecutable'
)

$script:ModulesAvailable = $false
$script:ImportDetail = 'not-attempted'
try {
    if ((Test-Path -LiteralPath $script:CoreModulePath -PathType Leaf) -and
        (Test-Path -LiteralPath $script:ModelModulePath -PathType Leaf)) {
        Import-Module -Name $script:CoreModulePath -ErrorAction Stop
        Import-Module -Name $script:ModelModulePath -ErrorAction Stop
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

try {
    $script:PwshPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
}
catch {
    $script:PwshPath = (Get-Command pwsh -ErrorAction Stop).Source
}

function Get-HarnessFileDigest {
    param([Parameter(Mandatory)][string]$Path)

    $bytes = [IO.File]::ReadAllBytes($Path)
    $hash = [Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace('-', '').ToLowerInvariant()
}

try {
    $script:SuiteDigest = Get-HarnessFileDigest $PSCommandPath
}
catch {
    $script:SuiteDigest = '0000000000000000000000000000000000000000000000000000000000000000'
}

function New-HarnessAssertionScope {
    Write-Output -NoEnumerate ([Collections.Generic.List[string]]::new())
}

function Assert-HarnessTrue {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Name
    )

    if (-not $Condition) {
        [void]$Failures.Add($Name)
    }
}

function Invoke-HarnessChild {
    param(
        [string[]]$Arguments = @(),
        [int]$TimeoutMilliseconds = $script:ChildTimeoutMilliseconds
    )

    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $script:PwshPath
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    foreach ($a in $Arguments) {
        [void]$psi.ArgumentList.Add($a)
    }
    $psi.WorkingDirectory = $script:RepoRoot
    $proc = New-Object Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $timedOut = -not $proc.WaitForExit($TimeoutMilliseconds)
    if ($timedOut) {
        try { $proc.Kill() } catch { }
        [void]$proc.WaitForExit(15000)
    }
    $stdout = ''
    $stderr = ''
    try { $stdout = $proc.StandardOutput.ReadToEnd() } catch { }
    try { $stderr = $proc.StandardError.ReadToEnd() } catch { }
    if ($stdout.Length -gt $script:MaxChildOutputChars) {
        $stdout = $stdout.Substring(0, $script:MaxChildOutputChars)
    }
    if ($stderr.Length -gt $script:MaxChildOutputChars) {
        $stderr = $stderr.Substring(0, $script:MaxChildOutputChars)
    }
    $code = -1
    try { $code = $proc.ExitCode } catch { }
    try { $proc.Dispose() } catch { }
    return [pscustomobject]@{
        ExitCode = $code
        Stdout   = $stdout
        Stderr   = $stderr
        TimedOut = [bool]$timedOut
    }
}

function Invoke-EntrypointFile {
    param([string[]]$ScriptArgs = @())

    $argv = New-Object Collections.Generic.List[string]
    [void]$argv.Add('-NoProfile')
    [void]$argv.Add('-NonInteractive')
    [void]$argv.Add('-File')
    [void]$argv.Add($script:EntrypointPath)
    foreach ($a in $ScriptArgs) {
        [void]$argv.Add($a)
    }
    return Invoke-HarnessChild -Arguments $argv.ToArray()
}

function Invoke-EntrypointCommand {
    param([Parameter(Mandatory)][string]$CommandBody)

    # NOTE: `exit <code>` inside a script function propagates the exact process
    # code under `-File` but degrades to 1 under bare `-Command "& ..."`, so the
    # fixed wrapper re-exports the script exit code at the top level, where
    # `exit` is honored exactly. No shell is involved: the child is still
    # spawned directly with a fixed argv.
    $wrapped = $CommandBody + '; exit $LASTEXITCODE'
    return Invoke-HarnessChild -Arguments @('-NoProfile', '-NonInteractive', '-Command', $wrapped)
}

function Get-OwnedResidueSnapshot {
    $names = New-Object Collections.Generic.List[string]
    try {
        $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        foreach ($d in @(Get-ChildItem -LiteralPath $tempBase -Directory -Force -ErrorAction SilentlyContinue)) {
            if ($d.Name -like 'eliot-harness-*' -or $d.Name -like 'eliot-wt-*') {
                [void]$names.Add('TEMP\' + $d.Name)
            }
        }
    }
    catch { }
    try {
        $localAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
        if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
            $testsRoot = Join-Path $localAppData 'Eliot\tests'
            if (Test-Path -LiteralPath $testsRoot -PathType Container) {
                foreach ($e in @(Get-ChildItem -LiteralPath $testsRoot -Force -ErrorAction SilentlyContinue)) {
                    [void]$names.Add('TESTS\' + $e.Name)
                }
            }
        }
    }
    catch { }
    return ,@($names | Sort-Object)
}

function Assert-HarnessNoNewResidue {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyCollection()][object[]]$Before = @(),
        [AllowEmptyCollection()][object[]]$After = @()
    )

    $known = @($Before)
    $seen = @($After)
    $new = @($seen | Where-Object { $known -notcontains $_ })
    if ($new.Count -gt 0) {
        [void]$Failures.Add(("{0}: new owned residue appeared: {1}" -f $Name, ($new -join ', ')))
    }
}

function Get-HarnessAmbientSnapshot {
    $snap = @{}
    foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME', 'PATH')) {
        $snap[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    return $snap
}

function Assert-HarnessAmbientPreserved {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][hashtable]$Before,
        [Parameter(Mandatory)][hashtable]$After
    )

    foreach ($key in $Before.Keys) {
        if ($After[$key] -cne $Before[$key]) {
            [void]$Failures.Add(("{0}: ambient variable changed: {1}" -f $Name, $key))
        }
    }
}

function Get-ScriptCommandNames {
    param([Parameter(Mandatory)][string]$Path)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        throw "target script has parse errors: $Path"
    }
    $found = $ast.FindAll(
        { param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    $names = New-Object Collections.Generic.List[string]
    foreach ($c in $found) {
        $first = $c.CommandElements[0]
        if ($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            [void]$names.Add($first.Value)
        }
    }
    return ,@($names | Sort-Object -Unique)
}

function Read-HarnessModuleSource {
    param([Parameter(Mandatory)][string]$Path)

    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.Length -gt $script:MaxModuleSourceBytes) {
        throw "module source exceeds byte bound: $Path"
    }
    return [IO.File]::ReadAllText($Path)
}

function Get-HarnessSeamCommand {
    param([Parameter(Mandatory)][string]$Profile)

    $name = $script:ExpectedSeams[$Profile]
    $cmd = Get-Command -Name $name -CommandType Function -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        throw "required profile seam is not exported: $name"
    }
    return $cmd
}

function Test-HarnessContractMismatch {
    param([Parameter(Mandatory)][object]$Record)

    $id = [string]$Record.FullyQualifiedErrorId
    $msg = [string]$Record.Exception.Message
    if ($id -eq 'UnknownParameter' -or $id -eq 'NamedParameterNotFound' -or
        $id -eq 'CommandNotFoundException' -or $msg -match 'is not recognized as the name of a cmdlet|does not contain a parameter') {
        return $true
    }
    return $false
}

function Test-HarnessSeamRejects {
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
        if (Test-HarnessContractMismatch $_) {
            throw
        }
    }
}

function Get-HarnessCanaryPatterns {
    return @(
        '(?i)password\s*[:=]\s*[''"][^''"]+[''"]',
        '(?i)surreal_pass\s*=',
        '(?i)connectionstring\s*[:=]\s*\S',
        '(?i)secret\s*[:=]\s*[''"][^''"]+[''"]',
        'BEGIN [A-Z ]*PRIVATE KEY'
    )
}

function Assert-HarnessNoCanaries {
    param(
        [Collections.Generic.List[string]]$Failures,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Text
    )

    foreach ($pattern in Get-HarnessCanaryPatterns) {
        if ($Text -match $pattern) {
            [void]$Failures.Add(("{0}: canary pattern present: {1}" -f $Name, $pattern))
        }
    }
}

# ---------------------------------------------------------------------------
# Case 1: exactly one profile; default launches nothing.
# ---------------------------------------------------------------------------
function Test-HarnessCase1 {
    param([Collections.Generic.List[string]]$Failures)

    $before = Get-OwnedResidueSnapshot
    $d = Invoke-EntrypointFile -ScriptArgs @()
    Assert-HarnessTrue $Failures ($d.TimedOut -eq $false) '1-default-returns'
    Assert-HarnessTrue $Failures ($d.ExitCode -eq 2) '1-default-usage-exit-2'
    Assert-HarnessTrue $Failures ($d.Stderr -match '(?i)usage error') '1-default-usage-text'
    Assert-HarnessTrue $Failures ([string]::IsNullOrWhiteSpace($d.Stdout)) '1-default-no-stdout-receipt'
    $after = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '1-default-no-residue' $before $after

    $c = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-Run', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($c.ExitCode -eq 2) '1-conflicting-two-profiles-exit-2'
    Assert-HarnessTrue $Failures ($c.Stderr -match '(?i)mutually exclusive') '1-conflicting-text'

    $c3 = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-ValidateConfiguration', '-Run', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($c3.ExitCode -eq 2) '1-conflicting-three-profiles-exit-2'

    if (-not $script:ModulesAvailable) { return }
    [void](Get-HarnessSeamCommand 'WhatIf')
    [void](Get-HarnessSeamCommand 'ValidateConfiguration')
    [void](Get-HarnessSeamCommand 'Run')
    $params = (Get-Command -Name $script:EntrypointPath -ErrorAction Stop).Parameters
    Assert-HarnessTrue $Failures ($params.ContainsKey('WhatIf')) '1-entrypoint-has-whatif'
    Assert-HarnessTrue $Failures ($params.ContainsKey('ValidateConfiguration')) '1-entrypoint-has-validate'
    Assert-HarnessTrue $Failures ($params.ContainsKey('Run')) '1-entrypoint-has-run'
    Assert-HarnessTrue $Failures (-not $params.ContainsKey('Mode')) '1-entrypoint-has-no-mode-api'
}

# ---------------------------------------------------------------------------
# Case 2: WhatIf deterministic finite plan (finite selection required).
# ---------------------------------------------------------------------------
function Test-HarnessCase2 {
    param([Collections.Generic.List[string]]$Failures)

    $w = Invoke-EntrypointFile -ScriptArgs @('-WhatIf')
    Assert-HarnessTrue $Failures ($w.ExitCode -eq 2) '2-whatif-without-selection-exit-2'
    Assert-HarnessTrue $Failures ($w.Stderr -match '(?i)selection') '2-whatif-selection-text'

    $b = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-SelectAllRows', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($b.ExitCode -eq 2) '2-whatif-contradictory-selection-exit-2'

    if (-not $script:ModulesAvailable) { return }
    $seam = Get-HarnessSeamCommand 'WhatIf'
    $missing = Join-Path $script:RepoRoot 'SELFTEST-harness-missing-inventory-907-2.json'
    $first = ''
    $second = ''
    try { [void](& $seam.Name -InventoryPath $missing); $first = 'SUCCEEDED' }
    catch {
        if (Test-HarnessContractMismatch $_) { throw }
        $first = $_.Exception.Message
    }
    try { [void](& $seam.Name -InventoryPath $missing); $second = 'SUCCEEDED' }
    catch {
        if (Test-HarnessContractMismatch $_) { throw }
        $second = $_.Exception.Message
    }
    Assert-HarnessTrue $Failures ($first -ne 'SUCCEEDED') '2-whatif-missing-inventory-rejected'
    Assert-HarnessTrue $Failures ($first -ceq $second) '2-whatif-deterministic-repeat'
}

# ---------------------------------------------------------------------------
# Case 3: WhatIf creates no process/port/pipe/worktree/data resource.
# ---------------------------------------------------------------------------
function Test-HarnessCase3 {
    param([Collections.Generic.List[string]]$Failures)

    $before = Get-OwnedResidueSnapshot
    $envBefore = Get-HarnessAmbientSnapshot
    $w = Invoke-EntrypointFile -ScriptArgs @('-WhatIf')
    $after = Get-OwnedResidueSnapshot
    $envAfter = Get-HarnessAmbientSnapshot
    Assert-HarnessTrue $Failures ($w.ExitCode -eq 2) '3-whatif-gate-exit-2'
    Assert-HarnessNoNewResidue $Failures '3-whatif-no-residue' $before $after
    Assert-HarnessAmbientPreserved $Failures '3-whatif-ambient' $envBefore $envAfter

    if (-not $script:ModulesAvailable) { return }
    [void](Get-HarnessSeamCommand 'WhatIf')
    $vseam = Get-HarnessSeamCommand 'ValidateConfiguration'
    $missing = Join-Path $script:RepoRoot 'SELFTEST-harness-missing-inventory-907-3.json'
    $pre = Get-OwnedResidueSnapshot
    try { [void](& $vseam.Name -InventoryPath $missing) } catch {
        if (Test-HarnessContractMismatch $_) { throw }
    }
    $post = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '3-validation-seam-no-residue' $pre $post
}

# ---------------------------------------------------------------------------
# Case 4: ValidateConfiguration uses validation/plan only.
# ---------------------------------------------------------------------------
function Test-HarnessCase4 {
    param([Collections.Generic.List[string]]$Failures)

    # -HarnessProbe was removed from the entrypoint (#907 D1), so the probe is
    # now an UNKNOWN PARAMETER here, not a profile-gate rejection. Both are
    # non-zero and launch nothing; the assertion tracks the new contract.
    $p = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-HarnessProbe', 'success')
    Assert-HarnessTrue $Failures ($p.ExitCode -ne 0) '4-probe-parameter-removed-in-validate'
    Assert-HarnessTrue $Failures ([string]::IsNullOrWhiteSpace($p.Stdout)) '4-probe-no-stdout-receipt'
    $i = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-InjectFailureAfterSecretSetup')
    Assert-HarnessTrue $Failures ($i.ExitCode -eq 2) '4-inject-rejected-in-validate'
    $o = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-PlanOutputPath', 'plan.json')
    Assert-HarnessTrue $Failures ($o.ExitCode -eq 2) '4-plan-output-rejected-in-validate'
    $e = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-EvidenceLogPath', 'ev.log')
    Assert-HarnessTrue $Failures ($e.ExitCode -eq 2) '4-evidence-rejected-in-validate'

    if (-not $script:ModulesAvailable) { return }
    [void](Get-HarnessSeamCommand 'ValidateConfiguration')
    $names = @((Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue) | ForEach-Object { $_.Name })
    Assert-HarnessTrue $Failures ($names.Count -gt 0) '4-modules-export-seams'
}

# ---------------------------------------------------------------------------
# Case 5: unavailable prerequisite differs from invalid configuration.
# ---------------------------------------------------------------------------
function Test-HarnessCase5 {
    param([Collections.Generic.List[string]]$Failures)

    $missing = Join-Path $script:RepoRoot 'SELFTEST-harness-missing-inventory-907-5.json'
    $bad = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-InventoryPath', $missing)
    Assert-HarnessTrue $Failures ($bad.ExitCode -eq 2) '5-missing-caller-path-is-usage-error'
    Assert-HarnessTrue $Failures ($bad.Stderr -match '(?i)inventory') '5-missing-caller-path-text'
    $plain = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration')
    Assert-HarnessTrue $Failures ($plain.ExitCode -ne 2) '5-delegation-is-not-usage-error'
    Assert-HarnessTrue $Failures ($plain.ExitCode -ne 0 -or $script:ModulesAvailable) '5-delegation-nonzero-when-modules-absent'
    Assert-HarnessTrue $Failures ($bad.Stderr -cne $plain.Stderr) '5-distinct-stderr'

    if (-not $script:ModulesAvailable) { return }
    $seam = Get-HarnessSeamCommand 'ValidateConfiguration'
    $malformed = Join-Path ([IO.Path]::GetTempPath()) 'SELFTEST-harness-malformed-907-5.json'
    [IO.File]::WriteAllText($malformed, '{ "not": "an inventory" }')
    try {
        $errMissing = ''
        $errMalformed = ''
        try { [void](& $seam.Name -InventoryPath $missing) } catch {
            if (Test-HarnessContractMismatch $_) { throw }
            $errMissing = $_.Exception.Message
        }
        try { [void](& $seam.Name -InventoryPath $malformed) } catch {
            if (Test-HarnessContractMismatch $_) { throw }
            $errMalformed = $_.Exception.Message
        }
        Assert-HarnessTrue $Failures (-not [string]::IsNullOrWhiteSpace($errMissing)) '5-missing-inventory-rejected'
        Assert-HarnessTrue $Failures (-not [string]::IsNullOrWhiteSpace($errMalformed)) '5-malformed-inventory-rejected'
        Assert-HarnessTrue $Failures ($errMissing -cne $errMalformed) '5-unavailable-differs-from-invalid'
    }
    finally {
        if (Test-Path -LiteralPath $malformed) {
            Remove-Item -LiteralPath $malformed -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Case 6: incomplete inventory differs from missing provider.
# ---------------------------------------------------------------------------
function Test-HarnessCase6 {
    param([Collections.Generic.List[string]]$Failures)

    $r = Invoke-EntrypointFile -ScriptArgs @('-Run')
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '6-run-without-selection-is-usage-error'
    $u = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/6')
    Assert-HarnessTrue $Failures ($u.ExitCode -ne 0) '6-unknown-identity-run-fails'
    Assert-HarnessTrue $Failures ($u.ExitCode -ne 2) '6-unknown-identity-run-is-not-usage-error'
    Assert-HarnessTrue $Failures ($r.Stderr -cne $u.Stderr) '6-empty-differs-from-delegated'

    if (-not $script:ModulesAvailable) { return }
    $seam = Get-HarnessSeamCommand 'ValidateConfiguration'
    $missing = Join-Path $script:RepoRoot 'SELFTEST-harness-missing-inventory-907-6.json'
    Test-HarnessSeamRejects $Failures '6-missing-inventory-rejected' { & $seam.Name -InventoryPath $missing }
    Test-HarnessSeamRejects $Failures '6-empty-inventory-path-rejected' { & $seam.Name -InventoryPath '' }
    # PROVIDER ARGUMENTS THREADED FROM THE GROUP ROW, observed rather than
    # asserted from field names (norm:
    # docs/architecture/I18-32-stateful-test-environments.md:30 - "stateful
    # isolation is observed, not asserted by a synthetic report").
    # Invoke-IntegrationHarnessProviderOperation
    # (scripts/integration/IntegrationHarness.Core.psm1:253-257) invokes each
    # provider op with a context carrying `.binding` and `.arguments`, and the
    # Run path threads the group row into those arguments
    # (scripts/integration/IntegrationHarness.Core.psm1:3940: groupKey,
    # testCount, providerClass, targetClass, isolationClass, resetClass,
    # serializationClass). The Plan op below CAPTURES those arguments instead of
    # returning a shape: a route that never threaded the row would leave the
    # capture table empty and the threaded asserts below would fail.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case6-arguments-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the receipt gate instead of the missing-provider branch.
        $seen = @{}
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = {
                param($c)
                $seen['planArgs'] = $c.arguments
                return @{}
            }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # The same admitted prebuilt receipt as the Case19 block, so the run
        # reaches the execution contour instead of the missing-receipt branch.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The fixed
        # pid is honest because the validator judges shape and run binding,
        # never liveness.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424260; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
        # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
        # binding against the AMBIENT wall clock, outside Core's injected owner,
        # so a fixed past instant would already be expired; deterministic time
        # behavior is proven by Case24 at the Core seam, not here, and no assert
        # below depends on a time value.
        # WHY no entrypoint child is spawned: the temp inventory plus
        # -CandidateRoot under the temp dir are the only inputs and no
        # scriptblock below launches any process.
        $threaded = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('f0' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures ([string]$seen['planArgs']['targetClass'] -ceq 't1') '6-target-threaded'
        Assert-HarnessTrue $Failures ([string]$seen['planArgs']['providerClass'] -ceq 'STORE') '6-provider-threaded'
        Assert-HarnessTrue $Failures `
            (-not [string]::IsNullOrWhiteSpace([string]$seen['planArgs']['groupKey'])) '6-group-key-threaded'
        Assert-HarnessTrue $Failures `
            ([string]$threaded.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '6-threaded-run-passes'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '6-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 7: provider interface rejects arbitrary methods/command fields.
# ---------------------------------------------------------------------------
function Test-HarnessCase7 {
    param([Collections.Generic.List[string]]$Failures)

    $shapes = @(
        @('-Run', '-SelectedTestId', 'a', '-TestBinary', 'foo'),
        @('-Run', '-SelectedTestId', 'a', '-BinTarget', 'x'),
        @('-Run', '-SelectedTestId', 'a', '-LibTarget'),
        @('-Run', '-SelectedTestId', 'a', '-TestName', 'y'),
        @('-Run', '-SelectedTestId', 'a', '-TestFilterExpression', 'E'),
        @('-Run', '-SelectedTestId', 'a', '-SurrealExecutable', 'C:\nonexistent\s.exe'),
        @('-Run', '-SelectedTestId', 'a', '-TestPackage', 'other'),
        @('-Run', '-SelectedTestId', 'a', '-McpOnly'),
        @('-Run', '-SelectedTestId', 'a', '-RunIgnored')
    )
    $index = 0
    foreach ($shape in $shapes) {
        $index++
        $got = Invoke-EntrypointFile -ScriptArgs $shape
        Assert-HarnessTrue $Failures ($got.ExitCode -eq 2) ("7-raw-shape-{0}-exit-2" -f $index)
        Assert-HarnessTrue $Failures ([string]::IsNullOrWhiteSpace($got.Stdout)) ("7-raw-shape-{0}-no-stdout" -f $index)
    }

    if (-not $script:ModulesAvailable) { return }
    $allParams = New-Object Collections.Generic.List[string]
    foreach ($cmd in @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue)) {
        foreach ($key in $cmd.Parameters.Keys) {
            [void]$allParams.Add($key)
        }
    }
    $shellish = @($allParams | Where-Object { $_ -match '^(Shell|Executable|Argv|Command|ScriptBlock|Url|Credential|Environment|ConnectionString)' })
    Assert-HarnessTrue $Failures ($shellish.Count -eq 0) '7-no-shellish-params-on-seams'

    # CLOSED OPERATIONS SET, ASSERTED AS SET MEMBERSHIP (norm:
    # docs/architecture/I18-32-stateful-test-environments.md:27 - "test success
    # requires both property evidence and cleanup/residue disposition", so only
    # the closed receipt validator mints a disposition and a provider operation
    # never does). The provider interface is EXACTLY the nine closed operations
    # (scripts/integration/IntegrationHarness.Core.psm1:53-63). Execution is NOT
    # one of them: it cannot be invoked through the provider table, only through
    # the Core-owned contour Invoke-HarnessExactTestExecution
    # (scripts/integration/IntegrationHarness.Core.psm1:3157) whose closed runner
    # receipt the validator judges. A tenth provider-side execution op would let a
    # provider mint verdicts, so membership is asked of the real
    # Test-IntegrationHarnessClosedOperation
    # (scripts/integration/IntegrationHarness.Core.psm1:129) rather than
    # re-derived from the seam scan above.
    $nineClosed = @(
        'ValidateRequirement', 'Plan', 'Allocate', 'Start', 'ObserveReadiness',
        'ResetForTest', 'CollectEvidence', 'Stop', 'VerifyCleanup'
    )
    $allNineTrue = $true
    foreach ($op in $nineClosed) {
        if (-not (Test-IntegrationHarnessClosedOperation -Operation $op)) {
            $allNineTrue = $false
        }
    }
    # ONE assert for all nine: the claim is the exact set membership, which the
    # rejections below pin again from the other side.
    Assert-HarnessTrue $Failures $allNineTrue '7-closed-nine'

    # EXECUTION IS NOT A PROVIDER OPERATION. 'Execute' must THROW
    # HARNESS-UNKNOWN-OPERATION, never return $true: if it were admitted as a
    # provider op, the call would return without throwing, $thrown would stay
    # false and the case goes red under this assert instead of being caught and
    # passed over.
    $executeThrown = $false
    $executeMessage = ''
    try { [void](Test-IntegrationHarnessClosedOperation -Operation 'Execute') }
    catch {
        if (Test-HarnessContractMismatch $_) { throw }
        $executeMessage = [string]$_.Exception.Message
        $executeThrown = $true
    }
    Assert-HarnessTrue $Failures `
        ($executeThrown -and ($executeMessage -match 'HARNESS-UNKNOWN-OPERATION')) `
        '7-execute-not-provider-op'

    # Unknown words never mint a provider verdict either - the same closed
    # membership judged by a near-miss name and by an invented one. Both must
    # throw HARNESS-UNKNOWN-OPERATION.
    $unknownAllThrown = $true
    foreach ($op in @('ExecutedTest', 'EvilOp')) {
        $thrown = $false
        $message = ''
        try { [void](Test-IntegrationHarnessClosedOperation -Operation $op) }
        catch {
            if (Test-HarnessContractMismatch $_) { throw }
            $message = [string]$_.Exception.Message
            $thrown = $true
        }
        if (-not ($thrown -and ($message -match 'HARNESS-UNKNOWN-OPERATION'))) {
            $unknownAllThrown = $false
        }
    }
    Assert-HarnessTrue $Failures $unknownAllThrown '7-unknown-op-rejected'
}

# ---------------------------------------------------------------------------
# Case 8: provider revision and inventory digest load-bearing.
# ---------------------------------------------------------------------------
function Test-HarnessCase8 {
    param([Collections.Generic.List[string]]$Failures)

    $d1 = Get-HarnessFileDigest $PSCommandPath
    $d2 = Get-HarnessFileDigest $PSCommandPath
    Assert-HarnessTrue $Failures ($d1 -ceq $d2) '8-suite-digest-deterministic'
    Assert-HarnessTrue $Failures ($d1 -ceq $script:SuiteDigest) '8-suite-digest-binds-executed-file'
    $de = Get-HarnessFileDigest $script:EntrypointPath
    Assert-HarnessTrue $Failures ($de -cne $d1) '8-digest-sensitive-to-content'

    if (-not $script:ModulesAvailable) { return }
    $helpers = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Digest|Hash|Revision' })
    Assert-HarnessTrue $Failures ($helpers.Count -gt 0) '8-digest-helper-exported'
    if ($helpers.Count -gt 0) {
        $probe = Join-Path ([IO.Path]::GetTempPath()) 'SELFTEST-harness-digest-907-8.txt'
        [IO.File]::WriteAllText($probe, 'alpha')
        try {
            $h1 = & $helpers[0].Name $probe
            $h2 = & $helpers[0].Name $probe
            [IO.File]::WriteAllText($probe, 'beta')
            $h3 = & $helpers[0].Name $probe
            Assert-HarnessTrue $Failures (("$h1") -ceq ("$h2")) '8-helper-digest-stable'
            Assert-HarnessTrue $Failures (("$h1") -cne ("$h3")) '8-helper-digest-sensitive'
        }
        finally {
            if (Test-Path -LiteralPath $probe) {
                Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Case 9: unique canonical run root and owner receipt.
# ---------------------------------------------------------------------------
function Test-HarnessCase9 {
    param([Collections.Generic.List[string]]$Failures)

    $text = [IO.File]::ReadAllText($script:EntrypointPath)
    Assert-HarnessTrue $Failures ($text -match 'NewGuid') '9-run-id-unique-guid'
    Assert-HarnessTrue $Failures ($text -match 'GetTempPath') '9-root-descends-from-temp'
    Assert-HarnessTrue $Failures ($text -match 'eliot-harness-') '9-canonical-root-pattern'
    $first = Invoke-EntrypointFile -ScriptArgs @()
    $second = Invoke-EntrypointFile -ScriptArgs @()
    Assert-HarnessTrue $Failures ($first.Stderr -ceq $second.Stderr) '9-usage-errors-canonical-deterministic'

    if (-not $script:ModulesAvailable) { return }
    $found = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'RunRoot|Owner' })
    Assert-HarnessTrue $Failures ($found.Count -gt 0) '9-runroot-owner-seam-exported'
}

# ---------------------------------------------------------------------------
# Case 10: path/reparse escape and foreign owner root rejected.
# ---------------------------------------------------------------------------
function Test-HarnessCase10 {
    param([Collections.Generic.List[string]]$Failures)

    $escape = Join-Path ([IO.Path]::GetTempPath()) '..\SELFTEST-harness-escape-907-10.json'
    $p = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-SelectedTestId', 'a', '-PlanOutputPath', $escape)
    Assert-HarnessTrue $Failures ($p.ExitCode -eq 2) '10-plan-path-escape-rejected'
    $dir = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-InventoryPath', $script:RepoRoot)
    Assert-HarnessTrue $Failures ($dir.ExitCode -eq 2) '10-inventory-directory-rejected'
    $empty = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-InventoryPath', '')
    Assert-HarnessTrue $Failures ($empty.ExitCode -ne 0) '10-empty-inventory-path-rejected'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match 'ReparsePoint') '10-reparse-guard-in-modules'
    $seam = Get-HarnessSeamCommand 'ValidateConfiguration'
    $dotdot = Join-Path $script:RepoRoot '..\..\SELFTEST-harness-foreign-907-10.json'
    Test-HarnessSeamRejects $Failures '10-foreign-inventory-rejected' { & $seam.Name -InventoryPath $dotdot }
}

# ---------------------------------------------------------------------------
# Case 11: exact selected group union equals inventory subset; no implicit/empty.
# ---------------------------------------------------------------------------
function Test-HarnessCase11 {
    param([Collections.Generic.List[string]]$Failures)

    $r = Invoke-EntrypointFile -ScriptArgs @('-Run')
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '11-run-empty-selection-exit-2'
    $w = Invoke-EntrypointFile -ScriptArgs @('-WhatIf')
    Assert-HarnessTrue $Failures ($w.ExitCode -eq 2) '11-whatif-empty-selection-exit-2'
    $b = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectAllRows', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($b.ExitCode -eq 2) '11-contradictory-selection-exit-2'
    $blank = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', '')
    Assert-HarnessTrue $Failures ($blank.ExitCode -eq 2) '11-blank-selection-exit-2'

    if (-not $script:ModulesAvailable) { return }
    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '11-empty-selection-rejected' { & $seam.Name -SelectedTestId @() }

    # BEHAVIORAL PROOF of per-group provider binding, the mirror of the Case19
    # block in this SAME file. Norm
    # docs/architecture/I18-32-stateful-test-environments.md:29 - "parallel
    # tests sharing a declared resource use one serial/conflict group rather
    # than racing" - so each group is the unit of dispatch and gets its OWN
    # binding; and norm
    # docs/architecture/I18-32-stateful-test-environments.md:27 - "test
    # success requires both property evidence and cleanup/residue disposition"
    # - which is why this block asserts observed binding names, observed
    # dispositions AND residue disposition.
    #
    # WHY two rows that differ in providerClass: the group key is exactly the
    # five class fields (scripts/integration/IntegrationHarness.Core.psm1:1850-1855),
    # so these rows form TWO groups, and the run must bind and dispatch each
    # group under its own provider name instead of collapsing the whole run to
    # one 'unbound-provider'. A run collapsed to one unbound provider would show
    # a single binding name and fail the first assert below.
    # WHY distinct row digests: Test-IntegrationHarnessSelectedSet
    # (scripts/integration/IntegrationHarness.Model.psm1:713-717) rejects a
    # repeated rowDigest in the selected set, so two rows need two digests.
    # WHY a shared capture table and not $script: state: a $script: assignment
    # does not propagate into module-invoked closures (probe-measured on #907),
    # so the table must travel as a hashtable the closures capture and mutate.
    # WHY $c.binding['providerName']: the run mints one immutable binding per
    # group from the accepted row's provider class
    # (scripts/integration/IntegrationHarness.Core.psm1:3814-3834), so the
    # names observed by the provider op prove each group dispatched under its
    # own binding.
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant plus 600s would already be expired and the run would
    # die before reaching the gate. Deterministic time behavior is proven by
    # Case24 at the Core seam, not here; here the clock only needs to admit the
    # binding, and no assert below depends on a time value.
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under the temp dir are the only inputs and no scriptblock
    # below launches any process.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case11-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                }, @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test2'
                    providerClass    = 'RUNTIME'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('e' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # Two groups = two concrete provider classes (never
        # 'unbound-provider'), so the binding names are STORE and RUNTIME and
        # the run reaches the receipt gate instead of the missing-provider
        # branch.
        $seen = @{ names = @() }
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = {
                param($c)
                $seen.names += [string]$c.binding['providerName']
                return @{}
            }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = {
                param($c)
                # The provider contributes nothing to the verdict: the
                # Core-owned contour mints the closed receipt from the runner
                # observation below.
                return @{}
            }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipts (#907 W7): bound BEFORE any dispatch, so
        # both groups reach the execution contour instead of the
        # missing-receipt branch. Each rowDigest equals its selected row's
        # digest, and the two digests are distinct.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
            'pkg::kind::name::test2' = @{
                testIdentity      = 'pkg::kind::name::test2'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('e' * 64)
            }
        }
        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The
        # Core-owned contour mints the closed receipt from this observation;
        # the fixed pid is honest because the validator judges shape and run
        # binding, never liveness.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424261; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $multi = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('f1' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        # Order-independent: each group bound and dispatched under its OWN
        # provider name, exactly once. Serving both groups under one binding
        # fails this assert.
        Assert-HarnessTrue $Failures (
            @($seen.names | Where-Object { $_ -ceq 'STORE' }).Count -eq 1 -and
            @($seen.names | Where-Object { $_ -ceq 'RUNTIME' }).Count -eq 1) '11-per-group-bindings'
        $passCount = @($multi.evidence['perTestTerminal'] |
            Where-Object { [string]$_.disposition -ceq 'Passed' }).Count
        Assert-HarnessTrue $Failures ($passCount -eq 2) '11-two-groups-pass'
        Assert-HarnessTrue $Failures ([string]$multi.outcome -ceq 'Complete') '11-multi-complete'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '11-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 12: incompatible provider/isolation/target/reset groups rejected.
# ---------------------------------------------------------------------------
function Test-HarnessCase12 {
    param([Collections.Generic.List[string]]$Failures)

    $quoted = "& '" + ($script:EntrypointPath -replace "'", "''") + "' -Run -SelectedTestId @('dup-907-12','dup-907-12')"
    $d = Invoke-EntrypointCommand -CommandBody $quoted
    Assert-HarnessTrue $Failures ($d.ExitCode -eq 2) '12-duplicate-selection-exit-2'
    $b = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-SelectAllRows', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($b.ExitCode -eq 2) '12-contradictory-selection-exit-2'

    if (-not $script:ModulesAvailable) { return }
    $grouped = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Group' })
    Assert-HarnessTrue $Failures ($grouped.Count -gt 0) '12-grouping-seam-exported'
    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '12-duplicate-ids-rejected' { & $seam.Name -SelectedTestId @('dup-907-12', 'dup-907-12') }

    # WHAT this proves that the duplicate-SELECTION-ID assert above cannot: the
    # assert above rejects a repeated SELECTION ID at the entrypoint/WhatIf
    # surface. Two DISTINCT rows can still carry the SAME row digest into the
    # Run seam, so the assert above says nothing about digest duplication.
    # Test-IntegrationHarnessSelectedSet
    # (scripts/integration/IntegrationHarness.Model.psm1:713-717) rejects a
    # repeated rowDigest in the selected set, and the Run seam throws
    # HARNESS-DUPLICATE-SELECTION before any disposition exists (probe-measured
    # on #907: exit 1, no record minted).
    #
    # WHY the residue pair is part of this block (norm:
    # docs/architecture/I18-32-stateful-test-environments.md:27 - test success
    # requires both property evidence and cleanup/residue disposition; a
    # duplicated selection never reaches a disposition at all, so the residue
    # disposition of this rejection is what the pair observes).
    #
    # WHY the provider table and runner are supplied even though the throw
    # precedes every provider call: -Provider and -Runner are mandatory seam
    # parameters for the Run seam, and -PrebuiltReceipts is passed empty for the
    # same reason - so the rejection under test is the digest one, not a
    # missing-parameter or missing-receipt branch.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired; no assert below depends on
    # a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs and no scriptblock
    # below launches any process.
    $dupRunSeam = Get-HarnessSeamCommand 'Run'
    $dupTag = 'harness-core-case12-dup-' + [guid]::NewGuid().ToString('N')
    $dupTmp = Join-Path ([IO.Path]::GetTempPath()) $dupTag
    $dupResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($dupTmp)
        $dupInv = Join-Path $dupTmp 'inventory.json'
        # Two rows identical except testName ('test' and 'test2'), so both the
        # identities and the selections are distinct - and the SAME rowDigest
        # appears twice on purpose.
        $dupInventoryDocument = @{
            rows = @(
                @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                }
                @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test2'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                }
            )
        }
        [IO.File]::WriteAllText($dupInv, ($dupInventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # The mirror provider table, exactly the Case19 shape: every op is a
        # plain empty result except Allocate (a handle), the accepted
        # ObserveReadiness receipt shape and a verified cleanup. No op here is
        # expected to run - the digest rejection precedes dispatch.
        $dupFake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Injected execution runner: process mechanics only, no process is
        # launched. The fixed pid is honest because the validator judges shape
        # and run binding, never liveness.
        $dupRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424263; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $dupThrew = $false
        try {
            & $dupRunSeam.Name -SelectAllRows -InventoryPath $dupInv `
                -Provider $dupFake -RunId ('f4' * 16) -CandidateRoot $dupTmp -TimeoutSeconds 600 `
                -Clock ({ [DateTimeOffset]::UtcNow }.GetNewClosure()) -PrebuiltReceipts @{} -Runner $dupRunner
            $dupThrew = $false
        }
        catch {
            # An unexpected error still fails the case (the Case5 contract
            # mismatch pattern): only DUPLICATE-SELECTION counts as the
            # rejection under test.
            if (Test-HarnessContractMismatch $_) { throw }
            if ([string]$_.Exception.Message -match 'DUPLICATE-SELECTION') { $dupThrew = $true }
        }
        Assert-HarnessTrue $Failures $dupThrew '12-duplicate-row-digest-rejected'
    }
    finally {
        if (Test-Path -LiteralPath $dupTmp) {
            Remove-Item -LiteralPath $dupTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $dupResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '12-dup-digest-no-residue' $dupResidueBefore $dupResidueAfter
}

# ---------------------------------------------------------------------------
# Case 13: missing/duplicate test identity prevents start.
# ---------------------------------------------------------------------------
function Test-HarnessCase13 {
    param([Collections.Generic.List[string]]$Failures)

    $quoted = "& '" + ($script:EntrypointPath -replace "'", "''") + "' -Run -SelectedTestId @('dup-907-13','dup-907-13')"
    $d = Invoke-EntrypointCommand -CommandBody $quoted
    Assert-HarnessTrue $Failures ($d.ExitCode -eq 2) '13-duplicate-identity-exit-2'
    Assert-HarnessTrue $Failures ($d.Stderr -match '(?i)duplicate') '13-duplicate-text'
    $blank = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', '   ')
    Assert-HarnessTrue $Failures ($blank.ExitCode -eq 2) '13-whitespace-identity-exit-2'

    if (-not $script:ModulesAvailable) { return }
    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '13-missing-identity-rejected' { & $seam.Name -SelectedTestId @() }
    Test-HarnessSeamRejects $Failures '13-duplicate-identity-rejected' { & $seam.Name -SelectedTestId @('dup-907-13', 'dup-907-13') }
}

# ---------------------------------------------------------------------------
# Case 14: exact binary/name invocation and zero-match rejection.
# ---------------------------------------------------------------------------
function Test-HarnessCase14 {
    param([Collections.Generic.List[string]]$Failures)

    foreach ($raw in @('-TestBinary', '-TestName', '-BinTarget', '-LibTarget', '-TestFilterExpression')) {
        $extra = @('-Run', '-SelectedTestId', 'a', $raw)
        if ($raw -ne '-LibTarget') { $extra += 'v' }
        $got = Invoke-EntrypointFile -ScriptArgs $extra
        Assert-HarnessTrue $Failures ($got.ExitCode -eq 2) ("14-raw-{0}-exit-2" -f $raw)
        Assert-HarnessTrue $Failures ($got.Stderr -match '(?i)inventory') ("14-raw-{0}-inventory-text" -f $raw)
    }

    if (-not $script:ModulesAvailable) { return }
    $allParams = New-Object Collections.Generic.List[string]
    foreach ($cmd in @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue)) {
        foreach ($key in $cmd.Parameters.Keys) {
            [void]$allParams.Add($key)
        }
    }
    foreach ($raw in $script:RemovedRawParams) {
        Assert-HarnessTrue $Failures (-not $allParams.Contains($raw)) ("14-no-raw-param-{0}" -f $raw)
    }

    # BEHAVIORAL PROOF THAT THE BOUND RECIPE IS WHAT GETS LAUNCHED, not another
    # parameter-surface scan. The asserts above only prove the former raw knobs
    # (-TestBinary / -TestName / -BinTarget / -LibTarget /
    # -TestFilterExpression) are ABSENT from the exported surface; absence says
    # nothing about what the contour actually hands the executor. So one
    # in-process run of the Run seam over a single-row temp inventory captures,
    # inside the runner Execute scriptblock, the exact contour it received:
    # the recipe (with its contour-minted digest), the test identity and the
    # run id. A contour that launched a raw command instead of the bound recipe
    # would leave recipeDigest empty and fail the first assert.
    #
    # NORMS: docs/architecture/I18-32-stateful-test-environments.md:27 - test
    # success requires both property evidence and cleanup/residue disposition,
    # which is why the residue pair below is part of this block;
    # docs/architecture/I10-08-02-ip0-one-windows-processexecutor.md:8 - the
    # executor receives an explicit executable/argv/env/cwd, here the exact
    # bound recipe rather than a raw command, which is what the capture proves.
    #
    # WHY cross-scriptblock state is a CAPTURED HASHTABLE: the runner Execute
    # scriptblock is invoked from inside the module, so a $script: assignment
    # there does not propagate back into this file's scope (probe-measured on
    # #907). A hashtable the closure captures and mutates travels with the
    # scriptblock, so the captured values are observable here.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired. Deterministic time behavior
    # is proven by Case24 at the Core seam, not here, and no assert below depends
    # on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs, the owned root is
    # created and removed by the run itself, and no scriptblock below launches
    # any process.
    $exactSeamCommand = Get-HarnessSeamCommand 'Run'
    $exactTag = 'harness-core-case14-' + [guid]::NewGuid().ToString('N')
    $exactTmp = Join-Path ([IO.Path]::GetTempPath()) $exactTag
    $exactResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($exactTmp)
        $inv = Join-Path $exactTmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the execution contour instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt: bound before dispatch so the run reaches
        # the execution contour; rowDigest equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only. The capture happens
        # on ENTRY, so a recipe/testIdentity/runId that was never captured stays
        # empty and the asserts below fail. No process is launched: the
        # observation is typed, never a live pid.
        $seen = @{}
        $runner = @{
            Execute = {
                param($c)
                $seen['recipe'] = $c.recipe
                $seen['testIdentity'] = $c.testIdentity
                $seen['runId'] = [string]$c.binding['runId']
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424252; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $exactRun = & $exactSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('e9' * 16) -CandidateRoot $exactTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$seen['recipe']['recipeDigest'] -cmatch '^[0-9a-f]{64}$') '14-exact-recipe-bound'
        Assert-HarnessTrue $Failures ($seen['testIdentity'] -ceq 'pkg::kind::name::test') '14-exact-identity-bound'
        Assert-HarnessTrue $Failures ($seen['runId'] -ceq ('e9' * 16)) '14-exact-run-bound'
        Assert-HarnessTrue $Failures `
            ([string]$exactRun.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '14-exact-launch-passes'
    }
    finally {
        if (Test-Path -LiteralPath $exactTmp) {
            Remove-Item -LiteralPath $exactTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $exactResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '14-no-residue' $exactResidueBefore $exactResidueAfter
}

# ---------------------------------------------------------------------------
# Case 15: prebuilt binary receipt required (no per-test rebuild path).
# ---------------------------------------------------------------------------
function Test-HarnessCase15 {
    param([Collections.Generic.List[string]]$Failures)

    $names = @(Get-ScriptCommandNames $script:EntrypointPath)
    foreach ($banned in @('cargo', 'nextest', 'surreal', 'Start-Process', 'Stop-Process')) {
        Assert-HarnessTrue $Failures ($names -notcontains $banned) ("15-entrypoint-no-{0}" -f $banned)
    }

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)receipt') '15-receipt-concept-in-modules'
    $found = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Receipt|Prebuilt|Toolchain' })
    Assert-HarnessTrue $Failures ($found.Count -gt 0) '15-receipt-seam-exported'

    # BEHAVIORAL PROOF OF PREBUILT ADMISSION, not another source scan. The
    # asserts above only prove the receipt CONCEPT exists on the exported
    # surface; nothing there proves that a member without an admitted receipt
    # is refused BEFORE anything is started or executed. Two in-process runs of
    # the Run seam over the SAME single-row temp inventory, the SAME fake
    # provider table and the SAME injected runner differ in exactly one thing:
    # whether the prebuilt receipt table has the member's admitted receipt. The
    # negative run offers an EMPTY table, so the member has no admitted receipt
    # and the admission path
    # (scripts/integration/IntegrationHarness.Core.psm1:4148-4156) records
    # HARNESS-MISSING-PREBUILT-RECEIPT as InfrastructureBlocked and continues
    # before the execution contour; the positive control offers the identical
    # run with the admitted receipt and reaches the contour exactly once.
    # Since the two runs differ only in admission, the execution counter is
    # what separates "the scaffolding started something" from "the admission
    # decided whether the execution happens".
    #
    # NORMS: docs/architecture/I18-32-stateful-test-environments.md:27 - test
    # success requires both property evidence and cleanup/residue disposition,
    # which is why the residue pair below is part of this block and not a
    # separate concern; :28 - unknown external effect or failed cleanup
    # quarantines the environment and opens Problem State, which is why the
    # blocked leg must not leave an environment behind that a later run could
    # mistake for a clean one.
    #
    # WHY cross-scriptblock state is a CAPTURED HASHTABLE: the runner Execute
    # scriptblock is invoked from inside the module, so a $script: assignment
    # there does not propagate back into this file's scope (probe-measured on
    # #907). A hashtable the closure captures and mutates travels with the
    # scriptblock, so the increments are observable here.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired and the run would die
    # before reaching the admission gate. Deterministic time behavior is proven
    # by Case24 at the Core seam, not here; here the clock only needs to admit
    # the binding, and no assert below depends on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs, the owned root is
    # created and removed by the run itself, and no scriptblock below launches
    # any process. The fixed pid is honest because the receipt validator judges
    # shape and run binding, never liveness.
    $admitSeamCommand = Get-HarnessSeamCommand 'Run'
    $admitTag = 'harness-core-case15-' + [guid]::NewGuid().ToString('N')
    $admitTmp = Join-Path ([IO.Path]::GetTempPath()) $admitTag
    $admitResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($admitTmp)
        $inv = Join-Path $admitTmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the admission gate instead of the missing-provider branch.
        $startCalls = @{ n = 0 }
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) $startCalls.n++; return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Injected execution runner: process mechanics only, and the execution
        # counter this case exists to read. The increment happens on ENTRY, so
        # a zero count means the runner was never called at all - not that it
        # was called and declined. No process is launched: the observation is
        # typed, never a live pid.
        $execCalls = @{ n = 0 }
        $runner = @{
            Execute = {
                param($c)
                $execCalls.n++
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424251; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # NEGATIVE: identical args, empty receipt table, so the member has no
        # admitted receipt. The admission path records
        # HARNESS-MISSING-PREBUILT-RECEIPT and continues before the contour.
        $blocked = & $admitSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('e7' * 16) -CandidateRoot $admitTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts @{} -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$blocked.evidence['perTestTerminal'][0].disposition -ceq 'InfrastructureBlocked') `
            '15-no-receipt-blocked'
        # Nothing starts or executes without the admitted receipt.
        Assert-HarnessTrue $Failures ($execCalls.n -eq 0) '15-no-receipt-no-execution'
        Assert-HarnessTrue $Failures ($startCalls.n -eq 0) '15-no-start-without-receipt'
        Assert-HarnessTrue $Failures ([string]$blocked.outcome -ceq 'Failed') '15-no-receipt-fails-run'

        # POSITIVE CONTROL: the identical run with the admitted receipt table -
        # one entry keyed by the member identity, digests bound to the selected
        # row. Only the admission differs from the blocked leg above, so a
        # passing disposition here is the admission's doing, not the
        # scaffolding's.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }
        $admitted = & $admitSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('e8' * 16) -CandidateRoot $admitTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$admitted.evidence['perTestTerminal'][0].disposition -ceq 'Passed') `
            '15-receipt-admits-execution'
        Assert-HarnessTrue $Failures ($execCalls.n -eq 1) '15-receipt-executes-once'
    }
    finally {
        if (Test-Path -LiteralPath $admitTmp) {
            Remove-Item -LiteralPath $admitTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $admitResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '15-no-residue' $admitResidueBefore $admitResidueAfter
}

# ---------------------------------------------------------------------------
# Case 16: process observed does not mean semantic readiness.
# ---------------------------------------------------------------------------
function Test-HarnessCase16 {
    param([Collections.Generic.List[string]]$Failures)

    # The probe parameter no longer exists on either surface, so it cannot fake
    # readiness in -ValidateConfiguration and cannot select a mode under -Run.
    $p = Invoke-EntrypointFile -ScriptArgs @('-ValidateConfiguration', '-HarnessProbe', 'success')
    Assert-HarnessTrue $Failures ($p.ExitCode -ne 0) '16-probe-cannot-fake-readiness-in-validate'
    Assert-HarnessTrue $Failures ($p.ExitCode -ne 2) '16-probe-removal-is-not-a-usage-profile-rejection'
    $b = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-HarnessProbe', 'bogus-value')
    Assert-HarnessTrue $Failures ($b.ExitCode -ne 0) '16-bogus-probe-value-rejected'

    if (-not $script:ModulesAvailable) { return }
    $runSeam = Get-HarnessSeamCommand 'Run'
    $runParams = (Get-Command -Name $runSeam.Name -ErrorAction Stop).Parameters
    Assert-HarnessTrue $Failures (-not $runParams.ContainsKey('HarnessProbe')) '16-run-seam-has-no-probe-parameter'
    $found = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Readiness|Observe' })
    Assert-HarnessTrue $Failures ($found.Count -gt 0) '16-readiness-seam-exported'
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)readiness') '16-readiness-literal'
    Assert-HarnessTrue $Failures ($sources -match '(?i)unknown') '16-unknown-state-literal'

    # BEHAVIORAL PROOF THAT AN OBSERVED PROCESS IS NOT READINESS, not another
    # surface scan. The asserts above only prove the former probe knob is gone
    # and that a readiness seam is exported; nothing there shows what the run
    # loop DOES with an observation that carries no semantic receipt. So two
    # in-process runs of the Run seam over the SAME single-row temp inventory,
    # the SAME admitted receipts and the SAME injected runner differ in exactly
    # one thing: what ObserveReadiness returns. The alias run returns
    # readyBecausePidAlive with NO semanticReceipt, which
    # Test-IntegrationHarnessReadiness
    # (scripts/integration/IntegrationHarness.Core.psm1:1915-1917) reads NOT
    # READY; the observed loop (:4080-4085) then records the group as
    # InfrastructureBlocked BEFORE any execution contour is entered. The typed
    # control returns the accepted shape - binding-bound runId/providerRevision
    # plus a semantic receipt - and reaches execution and passes. Only the
    # readiness payload differs, so the execution counter and the terminal
    # disposition are what separate "a process was observed" from "readiness was
    # proven".
    #
    # NORMS: docs/architecture/I18-32-stateful-test-environments.md:27 - test
    # success requires both property evidence and cleanup/residue disposition,
    # which is why the residue pair below is part of this block;
    # :30 - stateful isolation is observed, not asserted by a synthetic report,
    # which is why the readiness verdict is read back out of the run loop rather
    # than restated here as a report this file would then take on trust.
    #
    # WHY cross-scriptblock state is a CAPTURED HASHTABLE: the runner Execute
    # scriptblock is invoked from inside the module, so a $script: assignment
    # there does not propagate back into this file's scope (probe-measured on
    # #907). A hashtable the closure captures and mutates travels with the
    # scriptblock, so the execution count is observable here.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired. Deterministic time behavior
    # is proven by Case24 at the Core seam, not here, and no assert below depends
    # on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs, the owned root is
    # created and removed by the run itself, and no scriptblock below launches
    # any process. The fixed pid is honest because the receipt validator judges
    # shape and run binding, never liveness.
    $readySeamCommand = Get-HarnessSeamCommand 'Run'
    $readyTag = 'harness-core-case16-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $readyTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the readiness observation instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt: bound before dispatch so both runs below
        # reach the execution contour instead of the missing-receipt branch.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only, and the execution
        # counter this case exists to read. The increment happens on ENTRY, so
        # a zero count means the runner was never called at all - not that it
        # was called and declined. No process is launched.
        $execCalls = @{ n = 0 }
        $runner = @{
            Execute = {
                param($c)
                $execCalls.n++
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424253; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # NEGATIVE: identical inventory, receipts and runner - only
        # ObserveReadiness differs. A live pid is an ALIAS, not readiness: the
        # alias branch of Test-IntegrationHarnessReadiness reads $false before
        # the semantic receipt is ever consulted, and the group is blocked.
        $fakeAlias = @{}
        foreach ($key in @($fake.Keys)) { $fakeAlias[$key] = $fake[$key] }
        $fakeAlias['ObserveReadiness'] = {
            param($c)
            return @{
                runId                = [string]$c.binding['runId']
                providerRevision     = [string]$c.binding['providerRevision']
                readyBecausePidAlive = $true
            }
        }.GetNewClosure()

        $aliasRun = & $readySeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fakeAlias -RunId ('ea' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$aliasRun.evidence['perTestTerminal'][0].disposition -ceq 'InfrastructureBlocked') `
            '16-alias-blocked'
        Assert-HarnessTrue $Failures ($execCalls.n -eq 0) '16-alias-no-execution'

        # TYPED CONTROL: the identical run whose ObserveReadiness returns the
        # accepted shape. Only the readiness payload changed from the leg above,
        # so a Passed disposition here is the readiness gate's doing.
        $typedRun = & $readySeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('eb' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$typedRun.evidence['perTestTerminal'][0].disposition -ceq 'Passed') `
            '16-typed-passes'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '16-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 17: readiness timeout blocks tests and preserves cleanup ownership.
# ---------------------------------------------------------------------------
function Test-HarnessCase17 {
    param([Collections.Generic.List[string]]$Failures)

    $r = Invoke-EntrypointFile -ScriptArgs @('-Run')
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '17-run-blocked-before-start-without-selection'
    $z = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-TestTimeoutSeconds', '0')
    Assert-HarnessTrue $Failures ($z.ExitCode -ne 0) '17-zero-timeout-rejected'
    $big = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-TestTimeoutSeconds', '7201')
    Assert-HarnessTrue $Failures ($big.ExitCode -ne 0) '17-overbound-timeout-rejected'
    $inj = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-SelectedTestId', 'x', '-InjectFailureAfterSecretSetup')
    Assert-HarnessTrue $Failures ($inj.ExitCode -eq 2) '17-inject-rejected-in-whatif'

    if (-not $script:ModulesAvailable) { return }
    $found = @(Get-Command -Module 'IntegrationHarness.Core', 'IntegrationHarness.Model' -CommandType Function -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'Timeout|Deadline|Readiness|Cleanup' })
    Assert-HarnessTrue $Failures ($found.Count -gt 0) '17-timeout-cleanup-seam-exported'

    # BEHAVIORAL PROOF that a readiness probe which fails never runs the test,
    # and that the same scaffolding with a passing probe does run it. Two
    # in-process runs of the Run seam over the SAME single-row inventory, the
    # SAME fake provider table, the SAME admitted prebuilt receipts and the
    # SAME injected runner differ in exactly one thing: the readiness
    # receipt's readinessProbePassed. The negative leg returns the exact shape
    # Test-IntegrationHarnessReadiness accepts (binding-bound runId /
    # providerRevision plus a semantic receipt carrying owner and generation
    # from the binding) EXCEPT readinessProbePassed = $false, which that
    # function reads NOT READY (scripts/integration/IntegrationHarness.Core.psm1:1930-1932);
    # the observed loop (:4080-4085) then records the group as
    # InfrastructureBlocked BEFORE any execution contour is entered. The ready
    # control returns the identical payload with readinessProbePassed = $true
    # and reaches execution. Only the probe verdict differs, so the terminal
    # disposition and the execution counter are what separate "a provider was
    # allocated and started" from "readiness was proven".
    #
    # NORMS: docs/architecture/I18-32-stateful-test-environments.md:27 - test
    # success requires both property evidence and cleanup/residue disposition,
    # which is why the residue pair below is part of this block;
    # docs/architecture/I14-24-local-failure-containment-matrix.md:35 - the
    # blocked group keeps the stop recipe (bounded stage, then cleanup) and the
    # attempt evidence, so the blocked leg is asserted as a terminal
    # disposition read back out of the run rather than as an exception or an
    # absence of output.
    #
    # WHY cross-scriptblock state is a CAPTURED HASHTABLE: the runner Execute
    # scriptblock is invoked from inside the module, so a $script: assignment
    # there does not propagate back into this file's scope (probe-measured on
    # #907). A hashtable the closure captures and mutates travels with the
    # scriptblock, so the execution count is observable here. The increment
    # happens on ENTRY, so a zero count means the runner was never called at
    # all - not that it was called and declined.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired. Deterministic time
    # behavior is proven by Case24 at the Core seam, not here, and no assert
    # below depends on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs, the owned root is
    # created and removed by the run itself, and no scriptblock below launches
    # any process. The fixed pid is honest because the receipt validator judges
    # shape and run binding, never liveness.
    $readinessSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case17-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the readiness observation instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness. The ONLY difference from the ready control
                # below is the probe verdict itself.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $false
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt: bound before dispatch so both legs below
        # reach the execution contour instead of the missing-receipt branch.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only, and the execution
        # counter this block exists to read. No process is launched here - the
        # observation is typed, never a live pid.
        $execCalls = @{ n = 0 }
        $runner = @{
            Execute = {
                param($c)
                $execCalls.n++
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424254; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # NOT-READY LEG: the group never becomes ready, so it never runs.
        $notReadyRun = & $readinessSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('ec' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$notReadyRun.evidence['perTestTerminal'][0].disposition -ceq 'InfrastructureBlocked') `
            '17-not-ready-blocked'
        Assert-HarnessTrue $Failures ($execCalls.n -eq 0) '17-not-ready-no-execution'

        # READY CONTROL: identical run, identical inventory, identical fake
        # table, identical receipts and runner - only readinessProbePassed is
        # $true now, so a Passed disposition here is the probe's doing.
        $fakeReady = @{}
        foreach ($key in @($fake.Keys)) { $fakeReady[$key] = $fake[$key] }
        $fakeReady['ObserveReadiness'] = {
            param($c)
            return @{
                runId            = [string]$c.binding['runId']
                providerRevision = [string]$c.binding['providerRevision']
                semanticReceipt  = @{
                    readinessProbePassed = $true
                    owner                = [string]$c.binding['owner']
                    generation           = [int]$c.binding['generation']
                }
            }
        }.GetNewClosure()

        $readyRun = & $readinessSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fakeReady -RunId ('ed' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$readyRun.evidence['perTestTerminal'][0].disposition -ceq 'Passed') `
            '17-ready-passes'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '17-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 18: one terminal disposition per selected test.
# ---------------------------------------------------------------------------
function Test-HarnessCase18 {
    param([Collections.Generic.List[string]]$Failures)

    $c = Invoke-EntrypointFile -ScriptArgs @('-Run', '-ValidateConfiguration', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($c.ExitCode -eq 2) '18-conflicting-profiles-exit-2'
    $c2 = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-ValidateConfiguration', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($c2.ExitCode -eq 2) '18-conflicting-profiles-exit-2-again'

    if (-not $script:ModulesAvailable) { return }
    $sources = Read-HarnessModuleSource $script:ModelModulePath
    foreach ($outcome in $script:TerminalOutcomes) {
        Assert-HarnessTrue $Failures ($sources -match [regex]::Escape($outcome)) ("18-outcome-literal-{0}" -f $outcome)
    }

    # BEHAVIORAL PROOF of the one-disposition-per-test mapping. Two selected
    # tests share EVERY class field, so both land in ONE group and run through
    # ONE member loop - the shape where a verdict can be minted per group, per
    # attempt or per execution instead of per selected test. The run must still
    # produce exactly one terminal record per selected test: no merged record
    # for the group, no split records for one test, no dropped member, and each
    # record carries exactly one disposition from the closed vocabulary, here
    # Passed for both (docs/architecture/I18-32-stateful-test-environments.md:27
    # - success requires both property evidence and its cleanup/residue
    # disposition).
    #
    # WHY the two rows keep the SAME five class fields: the group key is
    # providerClass + isolationClass + targetClass + resetClass +
    # serializationClass (scripts/integration/IntegrationHarness.Core.psm1
    # :1850-1855), so identical classes with a different testName is exactly
    # the "several tests of one group" shape whose per-test mapping is at risk.
    #
    # WHY the two row digests differ: Test-IntegrationHarnessSelectedSet
    # (scripts/integration/IntegrationHarness.Model.psm1:713-717) refuses a
    # repeated rowDigest in the selected set, so identical digests would die as
    # HARNESS-DUPLICATE-SELECTION long before any disposition existed and the
    # mapping below would be vacuously true.
    #
    # WHY in-process is safe here: no entrypoint child is spawned, the temp
    # inventory plus a -CandidateRoot under that temp dir are the only inputs,
    # and no scriptblock below launches any process - the statefulness is
    # observed in the recorded per-test dispositions, never asserted from a
    # synthetic report (docs/architecture/I18-32-stateful-test-environments.md
    # :30).
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant plus 600s would already be expired and the run would
    # die before the gate. Deterministic time behavior is proven by Case24 at
    # the Core seam, not here; no assert below depends on a time value.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case18-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                }, @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test2'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('e' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One group = one concrete provider class (never 'unbound-provider'),
        # so the binding names STORE and the run reaches the receipt gate
        # instead of the missing-provider branch. The provider contributes
        # nothing to the verdict: the Core-owned contour receipt alone is judged.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # An admitted prebuilt receipt for EVERY member, each rowDigest equal to
        # its own row's digest, so neither member reaches the missing-receipt
        # branch and the dispositions below are produced by the validator, not
        # by absent evidence.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
            'pkg::kind::name::test2' = @{
                testIdentity      = 'pkg::kind::name::test2'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('e' * 64)
            }
        }

        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The fixed
        # pid is honest because the validator judges shape and run binding,
        # never liveness.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424255; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $result = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('ee' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner

        # ONE record per selected test. A loop that merged the group into one
        # record, split one test into several, or dropped a member fails here.
        $terminal = @($result.evidence['perTestTerminal'])
        Assert-HarnessTrue $Failures ($terminal.Count -eq 2) '18-two-terminal-records'

        # Order-independent: member order inside a group is an implementation
        # detail, so both records are checked on their own terms - exactly one
        # disposition each, drawn from the closed vocabulary, both Passed, and
        # two distinct identities so no two records claim the same test.
        $oneEach = $true
        $passedCount = 0
        $identities = @()
        foreach ($record in $terminal) {
            $dispositionKeys = @(@($record.Keys) | Where-Object { [string]$_ -ceq 'disposition' })
            if ($dispositionKeys.Count -ne 1) { $oneEach = $false; continue }
            $disposition = [string]$record['disposition']
            if ($script:TerminalOutcomes -cnotcontains $disposition) { $oneEach = $false; continue }
            if ($disposition -ceq 'Passed') { $passedCount++ }
            $identities += [string]$record['testIdentity']
        }
        if ($passedCount -ne 2) { $oneEach = $false }
        if (@($identities | Sort-Object -Unique).Count -ne 2) { $oneEach = $false }
        Assert-HarnessTrue $Failures $oneEach '18-one-disposition-each'

        # Two per-test passes, one complete run: the outcome is derived from the
        # dispositions, so it can only be Complete when neither record failed.
        Assert-HarnessTrue $Failures ([string]$result.outcome -ceq 'Complete') '18-two-pass-complete'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '18-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 19: pass requires exact executed-test receipt, not exit zero.
#
# MANDATORY NEGATIVE TEST (#907 D1). The public entrypoint is invoked with
# EVERY former probe value and with no probe at all, and for each invocation
# this case proves the same thing: no green run, no stdout receipt, and no
# exit code that could be read as success. A caller that once passed
# `-HarnessProbe success` got a fabricated Passed for every selected test with
# nothing executed; after the removal the parameter does not exist, so the
# run cannot be steered into a green disposition at all.
# ---------------------------------------------------------------------------
function Test-HarnessCase19 {
    param([Collections.Generic.List[string]]$Failures)

    # Every value the removed ValidateSet accepted, plus a value it never did.
    # 'none' was the former default: it is the shape a caller gets for free.
    $formerProbeValues = @('none', 'success', 'failure', 'retained_handle', 'bogus-value')
    $shapes = @(, @('-HarnessProbe', 'success'))
    foreach ($probe in $formerProbeValues) {
        $shapes += , @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/19', '-HarnessProbe', $probe)
        $shapes += , @('-ValidateConfiguration', '-HarnessProbe', $probe)
    }
    $shapes += , @('-Run', '-SelectAllRows', '-HarnessProbe', 'failure')
    $shapes += , @('-WhatIf', '-SelectedTestId', 'x', '-HarnessProbe', 'success')
    $shapes += , @('-HarnessProbe', 'success')
    foreach ($shape in $shapes) {
        $r = Invoke-EntrypointFile -ScriptArgs $shape
        $label = ($shape -join ' ')
        # No green: every one of these must exit non-zero.
        Assert-HarnessTrue $Failures ($r.ExitCode -ne 0) ("19-no-green-exit:{0}" -f $label)
        Assert-HarnessTrue $Failures ($r.ExitCode -ne 2 -or $shape -notcontains '-Run') ("19-not-usage-only:{0}" -f $label)
        # No success receipt: nothing is printed that a caller could read as a
        # completed, passing run.
        Assert-HarnessTrue $Failures ([string]::IsNullOrWhiteSpace($r.Stdout)) ("19-no-stdout-receipt:{0}" -f $label)
        # The rejection is specifically because the parameter no longer exists.
        Assert-HarnessTrue $Failures ($r.Stderr -match "(?i)HarnessProbe") ("19-unknown-parameter:{0}" -f $label)
        # A dead child is never mistaken for a refusal.
        Assert-HarnessTrue $Failures ($r.TimedOut -eq $false) ("19-child-reaped:{0}" -f $label)
    }
    $u = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/19')
    Assert-HarnessTrue $Failures ($u.ExitCode -ne 0) '19-unknown-identity-never-passes'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)receipt') '19-receipt-literal'

    # The entrypoint parameter surface itself must no longer carry the knob.
    $entryParams = (Get-Command -Name $script:EntrypointPath -ErrorAction Stop).Parameters
    Assert-HarnessTrue $Failures (-not $entryParams.ContainsKey('HarnessProbe')) '19-entrypoint-has-no-probe-parameter'
    $entrySource = [IO.File]::ReadAllText($script:EntrypointPath)
    Assert-HarnessTrue $Failures ($entrySource -notmatch '\$HarnessProbe') '19-entrypoint-source-has-no-probe-variable'
    Assert-HarnessTrue $Failures ($entrySource -notmatch "seamArgs\['HarnessProbe'\]") '19-entrypoint-no-probe-forwarding'

    # The exported Core surface must expose no probe or fault-injection knob
    # and no route to a manufactured disposition.
    $coreNames = @((Get-Command -Module 'IntegrationHarness.Core' -CommandType Function -ErrorAction SilentlyContinue) |
        ForEach-Object { $_.Name })
    Assert-HarnessTrue $Failures (@($coreNames | Where-Object { $_ -match 'Probe' }).Count -eq 0) '19-core-exports-no-probe-seam'
    $runSeam = Get-HarnessSeamCommand 'Run'
    $runParams = (Get-Command -Name $runSeam.Name -ErrorAction Stop).Parameters
    Assert-HarnessTrue $Failures (-not $runParams.ContainsKey('HarnessProbe')) '19-run-seam-has-no-probe-parameter'
    foreach ($banned in @('Test-HarnessExecutedTestReceipt', 'Set-HarnessExecutedTestObservation', 'Get-HarnessAdmittedClock')) {
        Assert-HarnessTrue $Failures ($coreNames -notcontains $banned) ("19-private-seam-not-exported-{0}" -f $banned)
    }

    # Source-level proof that no literal disposition synthesis survives: the
    # removed probe branch was the only place the core wrote a terminal
    # disposition directly rather than through the receipt validator. This is
    # checked against the PARSE TREE rather than the raw text, so it states
    # the real claim - Invoke-HarnessRun contains no disposition assignment at
    # all, and every assignment in the module lives in the validator - without
    # depending on formatting or on unrelated functions added elsewhere.
    $coreSource = Read-HarnessModuleSource $script:CoreModulePath
    Assert-HarnessTrue $Failures ($coreSource -notmatch 'probe-binary') '19-core-no-probe-binary-fabrication'
    Assert-HarnessTrue $Failures ($coreSource -notmatch 'probe-discovery') '19-core-no-probe-discovery-fabrication'
    Assert-HarnessTrue $Failures ($coreSource -notmatch 'probeMode') '19-core-no-probe-mode-variable'

    $parseErrors = $null
    $parseTokens = $null
    $coreAst = [System.Management.Automation.Language.Parser]::ParseInput(
        $coreSource, [ref]$parseTokens, [ref]$parseErrors)
    Assert-HarnessTrue $Failures ($parseErrors.Count -eq 0) '19-core-source-parses'
    $functionAsts = @($coreAst.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
    $runAst = @($functionAsts | Where-Object { $_.Name -eq 'Invoke-HarnessRun' })
    Assert-HarnessTrue $Failures ($runAst.Count -eq 1) '19-run-seam-found-once'
    $validatorAst = @($functionAsts | Where-Object { $_.Name -eq 'Test-HarnessExecutedTestReceipt' })
    Assert-HarnessTrue $Failures ($validatorAst.Count -eq 1) '19-validator-found-once'

    # Every 'Passed'/'AssertionFailed' disposition assignment in the module
    # must be inside the validator. Nothing else - in particular not the run
    # seam - may name either disposition as a literal assignment target.
    #
    # A bare string literal on the right of an assignment parses as a
    # CommandExpressionAst wrapping the StringConstantExpressionAst, so the
    # literal must be unwrapped before it can be compared. Testing the wrapper
    # instead of the literal silently matches nothing, which would make the
    # "exactly one site" claim vacuously true rather than false.
    $assignments = @($coreAst.FindAll({
                param($n)
                if (-not ($n -is [System.Management.Automation.Language.AssignmentStatementAst])) { return $false }
                $right = $n.Right
                while ($right -is [System.Management.Automation.Language.CommandExpressionAst]) {
                    $right = $right.Expression
                }
                if (-not ($right -is [System.Management.Automation.Language.StringConstantExpressionAst])) { return $false }
                return (@('Passed', 'AssertionFailed') -contains $right.Value)
            }, $true))
    Assert-HarnessTrue $Failures ($assignments.Count -ge 1) '19-validator-assigns-passed'
    $outside = 0
    $passedSites = 0
    foreach ($a in $assignments) {
        $aRight = $a.Right
        while ($aRight -is [System.Management.Automation.Language.CommandExpressionAst]) {
            $aRight = $aRight.Expression
        }
        if ($aRight.Value -ceq 'Passed') { $passedSites++ }
        $inValidator = $false
        foreach ($v in $validatorAst) {
            if ($a.Extent.StartOffset -ge $v.Extent.StartOffset -and
                $a.Extent.EndOffset -le $v.Extent.EndOffset) {
                $inValidator = $true
            }
        }
        $inRunSeam = $false
        foreach ($v in $runAst) {
            if ($a.Extent.StartOffset -ge $v.Extent.StartOffset -and
                $a.Extent.EndOffset -le $v.Extent.EndOffset) {
                $inRunSeam = $true
            }
        }
        if (-not $inValidator) { $outside++ }
        Assert-HarnessTrue $Failures (-not $inRunSeam) '19-run-seam-writes-no-disposition-literal'
        Assert-HarnessTrue $Failures ($a.Left -is [System.Management.Automation.Language.IndexExpressionAst] -or
            $a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) '19-assignment-target-is-a-record-field'
    }
    Assert-HarnessTrue $Failures ($outside -eq 0) '19-no-disposition-literal-outside-validator'
    Assert-HarnessTrue $Failures ($passedSites -eq 1) '19-exactly-one-passed-assignment-site'

    # BEHAVIORAL PROOF of the admission/execution/validator chain, not another
    # parse-tree claim. Two in-process runs of the Run seam over the SAME
    # single-row inventory, the SAME fake provider table, the SAME admitted
    # prebuilt receipts and the SAME injected runner differ in exactly one
    # thing: what CollectEvidence returns. The negative run offers the legacy
    # two-digest provider payload whose digests CONTRADICT the admitted
    # receipt; the cross-check turns it into HarnessError. The positive control
    # offers no provider receipt at all, and the Core-owned contour's closed
    # runner receipt passes. Reverting the contour/validator to two-digest
    # acceptance, or breaking the cross-check, fails the first pair of asserts.    # in-process runs of the Run seam over the SAME single-row inventory and
    # the SAME fake provider table differ in exactly one thing: what
    # CollectEvidence returns. The negative run hands the validator the legacy
    # two-digest provider payload (testIdentity + binaryDigest +
    # discoveryDigest) and nothing else; the positive control hands it a
    # complete runner receipt bound to this run, this group, this attempt and
    # this identity. Only the second one may pass, so reverting the validator
    # to two-digest acceptance fails the first pair of asserts.
    #
    # WHY an in-process Invoke-HarnessRun with this fake table is safe here: no
    # entrypoint child is spawned, the temp inventory plus a -CandidateRoot
    # under that temp dir are the only inputs, the owned root is created and
    # removed by the run itself, and no scriptblock below launches any process.
    # The suite header's never-satisfiable-selection rule targets entrypoint
    # children that would really execute; this block executes only fake
    # hashtables.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # any fixed past instant plus 600s would already be expired and the run would
    # die before reaching the gate. Deterministic time behavior is proven by
    # Case24 at the Core seam, not here; here the clock only needs to admit the
    # binding, and no assert below depends on a time value.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case19-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the receipt gate instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = {
                param($c)
                # NEGATIVE: the legacy two-digest provider payload with digests
                # that CONTRADICT the admitted receipt below (same identity, so
                # the HarnessError proves the digests are cross-checked, not
                # just the identity). The contour receipt itself is well-formed,
                # so only this contradiction can fail the run.
                return @{
                    executedReceipt = @{
                        testIdentity   = 'pkg::kind::name::test'
                        binaryDigest   = ('f' * 64)
                        discoveryDigest = ('e' * 64)
                    }
                }
            }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt (#907 W7): bound BEFORE any dispatch, so
        # both runs below reach the execution contour instead of the
        # missing-receipt branch. rowDigest equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }
        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The
        # Core-owned contour mints the closed receipt from this observation;
        # the fixed pid is honest because the validator judges shape and run
        # binding, never liveness.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424242; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $negative = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('e' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$negative.evidence['perTestTerminal'][0].disposition -ceq 'HarnessError') '19-legacy-receipt-no-pass'
        Assert-HarnessTrue $Failures ([string]$negative.outcome -cne 'Complete') '19-legacy-receipt-no-complete'

        # POSITIVE CONTROL: identical run, identical inventory, identical fake
        # table, identical receipts and runner - only CollectEvidence differs,
        # now returning no provider receipt at all. The Core-owned contour
        # mints the closed runner receipt from the runner observation above,
        # and the validator passes it: the provider contributes nothing to the
        # verdict.
        $fakePass = @{}
        foreach ($key in @($fake.Keys)) { $fakePass[$key] = $fake[$key] }
        $fakePass['CollectEvidence'] = { param($c) return @{} }.GetNewClosure()

        $positive = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fakePass -RunId ('e' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$positive.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '19-bound-receipt-passes'
        Assert-HarnessTrue $Failures ([string]$positive.outcome -ceq 'Complete') '19-bound-receipt-completes'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '19-fake-run-no-residue' $residueBefore $residueAfter

    # STAGE ORDER, observed rather than asserted from stage NAMES (norm:
    # docs/architecture/I18-32-stateful-test-environments.md:30 - "stateful
    # isolation is observed, not asserted by a synthetic report"). The block
    # above proves WHAT the receipt validator accepts; this block proves WHEN
    # the execution contour ran, by having reset, the runner and evidence
    # collection record themselves as they are entered. Nothing here scans
    # stage names or counts source sites: the order is an observation of a real
    # pass through the Run seam, so a path that skipped the contour records
    # 'reset,collect' and a path that retried it records a longer sequence.
    #
    # WHY a shared order table and not $script: state: a $script: assignment
    # does not propagate into module-invoked closures (probe-measured on #907),
    # so the table must travel as a hashtable the closures capture and mutate.
    # WHY `+=` on the key rather than a List: the array assigned back to the
    # shared key stays observable through the shared table reference.
    $stages = @{ seq = @() }
    $stageTag = 'harness-core-case19-stages-' + [guid]::NewGuid().ToString('N')
    $stageTmp = Join-Path ([IO.Path]::GetTempPath()) $stageTag
    $stageResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($stageTmp)
        $stageInv = Join-Path $stageTmp 'inventory.json'
        $stageInventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($stageInv, ($stageInventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        $stageFake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = {
                param($c)
                $stages.seq += 'reset'
                return @{}
            }.GetNewClosure()
            CollectEvidence   = {
                param($c)
                $stages.seq += 'collect'
                return @{}
            }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # The same admitted prebuilt receipt as the block above, so the run
        # reaches the execution contour instead of the missing-receipt branch.
        $stageReceipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # The execution stage records itself on entry, before returning the
        # typed observation the contour mints its closed receipt from. No
        # process is launched: the fixed pid is honest because the validator
        # judges shape and run binding, never liveness.
        $stageRunner = @{
            Execute = {
                param($c)
                $stages.seq += 'execute'
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424259; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
        # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
        # binding against the AMBIENT wall clock, outside Core's injected
        # owner, so a fixed past instant would already be expired; deterministic
        # time behavior is proven by Case24 at the Core seam, not here, and no
        # assert below depends on a time value.
        # WHY no entrypoint child is spawned: the temp inventory plus
        # -CandidateRoot under the temp dir are the only inputs and no
        # scriptblock below launches any process.
        $staged = & $runSeamCommand.Name -SelectAllRows -InventoryPath $stageInv `
            -Provider $stageFake -RunId ('ef' * 16) -CandidateRoot $stageTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $stageReceipts -Runner $stageRunner
        Assert-HarnessTrue $Failures (($stages.seq -join ',') -ceq 'reset,execute,collect') '19-stage-order'
        Assert-HarnessTrue $Failures `
            ([string]$staged.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '19-stage-order-passes'
    }
    finally {
        if (Test-Path -LiteralPath $stageTmp) {
            Remove-Item -LiteralPath $stageTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $stageResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '19-stage-no-residue' $stageResidueBefore $stageResidueAfter

    # FORGERY IMMUNITY, observed (norms:
    # docs/architecture/I18-32-stateful-test-environments.md:27 - "test success
    # requires both property evidence and cleanup/residue disposition" - which is
    # why the residue pair below is part of this block and not an afterthought -
    # and :30 - "stateful isolation is observed, not asserted by a synthetic
    # report": the stage block above proved the ORDER of a real pass; this block
    # proves which DIGESTS that pass may be built from, by letting a dishonest
    # producer try to smuggle its own digests into the receipt.
    #
    # Leg 1 hands the contour a runner observation that already carries
    # foreign binary/discovery digests. The receipt must still be stamped from
    # the admitted prebuilt digests (IntegrationHarness.Core.psm1:3342-3343), so
    # the run passes AND the terminal receipt shows the prebuilt digests. Leg 2
    # keeps that receipt honest but has the provider contradict it; the
    # cross-check at IntegrationHarness.Core.psm1:3463-3472 must turn that into
    # HarnessError and fail the run. Letting observation digests reach the
    # receipt fails 19-prebuilt-digests-win; dropping the cross-check fails
    # 19-provider-contradiction-blocked.
    #
    # WHY $seen is created BEFORE the tables that capture it: closures capture
    # only the variables that already exist when .GetNewClosure() runs, and a
    # table built afterwards is invisible inside module-invoked closures
    # (probe-measured on #907) - the same reason the stage block above uses a
    # shared order table instead of $script: state.
    $seen = @{}
    $forgeTag = 'harness-core-case19-forge-' + [guid]::NewGuid().ToString('N')
    $forgeTmp = Join-Path ([IO.Path]::GetTempPath()) $forgeTag
    $forgeResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($forgeTmp)
        $forgeInv = Join-Path $forgeTmp 'inventory.json'
        $forgeInventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($forgeInv, ($forgeInventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # The same one-row STORE inventory shape as the blocks above, so the
        # binding names STORE and the run reaches the receipt gate.
        $forgeFake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # The same admitted prebuilt receipt as the blocks above.
        $forgeReceipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # LEG 1 - FORGED OBSERVATION. The runner observation smuggles foreign
        # digests alongside a well-formed outcome and an owned process tree. No
        # process is launched; the fixed pid is honest because the validator
        # judges shape and run binding, never liveness.
        $forgeRunner = @{
            Execute = {
                param($c)
                $seen['executeRunId'] = [string]$c.binding['runId']
                return @{
                    outcome         = 'passed'
                    binaryDigest    = ('f' * 64)
                    discoveryDigest = ('e' * 64)
                    processTree     = @{ rootPid = 424262; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
        # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
        # binding against the AMBIENT wall clock, outside Core's injected owner,
        # so a fixed past instant would already be expired; deterministic time
        # behavior is proven by Case24 at the Core seam, not here, and no assert
        # below depends on a time value.
        # WHY no entrypoint child is spawned: the temp inventory plus
        # -CandidateRoot under the temp dir are the only inputs and no
        # scriptblock below launches any process.
        $forged = & $runSeamCommand.Name -SelectAllRows -InventoryPath $forgeInv `
            -Provider $forgeFake -RunId ('f2' * 16) -CandidateRoot $forgeTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $forgeReceipts -Runner $forgeRunner
        Assert-HarnessTrue $Failures `
            ([string]$forged.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '19-forged-digests-pass'
        # The verdict is not merely green: the terminal receipt itself carries the
        # prebuilt digests, so the foreign ones never became evidence.
        Assert-HarnessTrue $Failures `
            ([string]$forged.evidence['perTestTerminal'][0].executedReceipt['binaryDigest'] -ceq ('c' * 64)) '19-prebuilt-digests-win'

        # LEG 2 - CONTRADICTING PROVIDER. The identical run, whose runner
        # observation is honest again, but whose CollectEvidence stores its input
        # and then returns a provider copy that disagrees with the runner receipt.
        # A provider is evidence, never the verdict: the cross-check refuses it.
        $contraFake = @{}
        foreach ($key in @($forgeFake.Keys)) { $contraFake[$key] = $forgeFake[$key] }
        $contraFake['CollectEvidence'] = {
            param($c)
            $seen['collectRunId'] = [string]$c.binding['runId']
            return @{
                executedReceipt = @{
                    testIdentity    = 'pkg::kind::name::test'
                    binaryDigest    = ('f' * 64)
                    discoveryDigest = ('e' * 64)
                }
            }
        }.GetNewClosure()

        $honestRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424262; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $contradiction = & $runSeamCommand.Name -SelectAllRows -InventoryPath $forgeInv `
            -Provider $contraFake -RunId ('f3' * 16) -CandidateRoot $forgeTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $forgeReceipts -Runner $honestRunner
        Assert-HarnessTrue $Failures `
            ([string]$contradiction.evidence['perTestTerminal'][0].disposition -ceq 'HarnessError') '19-provider-contradiction-blocked'
        Assert-HarnessTrue $Failures ([string]$contradiction.outcome -ceq 'Failed') '19-provider-contradiction-fails-run'
    }
    finally {
        if (Test-Path -LiteralPath $forgeTmp) {
            Remove-Item -LiteralPath $forgeTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $forgeResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '19-forge-no-residue' $forgeResidueBefore $forgeResidueAfter

    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '19-vacuous-selection-rejected' { & $seam.Name -SelectedTestId @() }
}

# ---------------------------------------------------------------------------
# Case 20: assertion/crash/timeout/cancel/infra outcomes distinct.
# ---------------------------------------------------------------------------
function Test-HarnessCase20 {
    param([Collections.Generic.List[string]]$Failures)

    $usage = Invoke-EntrypointFile -ScriptArgs @()
    $binding = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-TestTimeoutSeconds', '0')
    Assert-HarnessTrue $Failures ($usage.ExitCode -eq 2) '20-usage-family-exit-2'
    Assert-HarnessTrue $Failures ($binding.ExitCode -ne 0) '20-binding-family-nonzero'
    Assert-HarnessTrue $Failures ($binding.ExitCode -ne 2) '20-binding-family-distinct-from-usage'
    Assert-HarnessTrue $Failures ($usage.Stderr -cne $binding.Stderr) '20-families-text-distinct'

    if (-not $script:ModulesAvailable) { return }
    $sources = Read-HarnessModuleSource $script:ModelModulePath
    $seen = New-Object Collections.Generic.List[string]
    foreach ($outcome in $script:TerminalOutcomes) {
        if ($sources -match [regex]::Escape($outcome)) {
            [void]$seen.Add($outcome)
        }
    }
    Assert-HarnessTrue $Failures ($seen.Count -eq $script:TerminalOutcomes.Count) '20-all-nine-outcomes-distinct'

    # DIRECT MAPPER BLOCK: the closed runner-outcome vocabulary is exercised at
    # the mapper itself. The source scan above only proves the nine disposition
    # NAMES occur in the module; it cannot prove that each runner token maps to
    # the RIGHT one, nor that an unknown token is refused instead of being read
    # as a verdict. WHY this level is the right one here: Case19 already proves
    # the production loop routes every disposition through the validator and
    # this same mapper, and that exactly one literal 'Passed' assignment site
    # exists; what remained unproven is the mapping itself, so the mapping is
    # asserted directly and exhaustively instead of re-deriving it indirectly.
    $closedTokens = @(
        @{ token = 'passed'; disposition = 'Passed' },
        @{ token = 'assertion-failed'; disposition = 'AssertionFailed' },
        @{ token = 'timed-out'; disposition = 'TimedOut' },
        @{ token = 'process-crashed'; disposition = 'ProcessCrashed' },
        @{ token = 'infrastructure-blocked'; disposition = 'InfrastructureBlocked' },
        @{ token = 'unsupported-credential'; disposition = 'UnsupportedExternalCredential' },
        @{ token = 'cancelled'; disposition = 'Cancelled' },
        @{ token = 'harness-error'; disposition = 'HarnessError' }
    )
    $closedNames = @(
        '20-map-passed', '20-map-assertion-failed', '20-map-timed-out',
        '20-map-process-crashed', '20-map-infrastructure-blocked',
        '20-map-unsupported-credential', '20-map-cancelled', '20-map-harness-error'
    )
    for ($i = 0; $i -lt $closedTokens.Count; $i++) {
        $entry = $closedTokens[$i]
        Assert-HarnessTrue $Failures `
            ([string](ConvertTo-HarnessTerminalDisposition -Outcome $entry.token) -ceq $entry.disposition) `
            $closedNames[$i]
    }

    # UNKNOWN TOKENS NEVER MINT A VERDICT. A provider (or a runner) that
    # invents, empties or garbles an outcome word must not be able to produce
    # Passed: every unrecognised token reads HarnessError, so an unknown word
    # fails the run loudly instead of silently passing it. Case and whitespace
    # tolerance is deliberate and is the ONLY laxity here: ' PASSED ' is the
    # same closed token as 'passed'.
    Assert-HarnessTrue $Failures `
        ([string](ConvertTo-HarnessTerminalDisposition -Outcome '') -ceq 'HarnessError') '20-map-unknown-empty'
    Assert-HarnessTrue $Failures `
        ([string](ConvertTo-HarnessTerminalDisposition -Outcome '  ') -ceq 'HarnessError') '20-map-unknown-blank'
    Assert-HarnessTrue $Failures `
        ([string](ConvertTo-HarnessTerminalDisposition -Outcome 'bogus-outcome') -ceq 'HarnessError') '20-map-unknown-bogus'
    Assert-HarnessTrue $Failures `
        ([string](ConvertTo-HarnessTerminalDisposition -Outcome 'passed!') -ceq 'HarnessError') '20-map-unknown-suffix'
    Assert-HarnessTrue $Failures `
        ([string](ConvertTo-HarnessTerminalDisposition -Outcome ' PASSED ') -ceq 'Passed') '20-map-tolerant-case'

    # END-TO-END CRASH LEG. The mapper block above proves the table; this leg
    # proves the property the whole case exists for - a crashed child is
    # reported as exactly ProcessCrashed, fails the run, and keeps its receipt
    # on the record, through the REAL Run seam over the SAME single-row
    # inventory, fake provider table, admitted prebuilt receipts and injected
    # runner shape as the Case19 behavioral block. It differs from that block in
    # exactly two places: the runner reports 'process-crashed' instead of
    # 'passed', and CollectEvidence returns no provider receipt, so the
    # Core-owned contour receipt alone is judged. CollectEvidence returning
    # nothing is not a shortcut here - it is the isolation of the claim: the
    # provider contributes nothing to the verdict.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired and the run would die
    # before reaching the gate. Deterministic time behavior is proven by Case24
    # at the Core seam, not here; here the clock only needs to admit the
    # binding, and no assert below depends on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs, the owned root is
    # created and removed by the run itself, and no scriptblock below launches
    # any process. The fixed pid is honest because the validator judges receipt
    # shape and run binding, never liveness.
    $crashSeamCommand = Get-HarnessSeamCommand 'Run'
    $crashTag = 'harness-core-case20-' + [guid]::NewGuid().ToString('N')
    $crashTmp = Join-Path ([IO.Path]::GetTempPath()) $crashTag
    $crashResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($crashTmp)
        $inv = Join-Path $crashTmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        $runner = @{
            Execute = {
                param($c)
                # The crash leg's only difference from the Case19 positive
                # control: the typed outcome is 'process-crashed', not 'passed'.
                return @{
                    outcome     = 'process-crashed'
                    processTree = @{ rootPid = 424243; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $result = & $crashSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('e' * 32) -CandidateRoot $crashTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $runner

        Assert-HarnessTrue $Failures `
            ([string]$result.evidence['perTestTerminal'][0].disposition -ceq 'ProcessCrashed') '20-e2e-crash-maps'
        Assert-HarnessTrue $Failures ([string]$result.outcome -ceq 'Failed') '20-e2e-crash-fails-run'
        # The receipt survives on the record: a crash is still property
        # evidence (disposition) plus a disposition-carrying receipt, so the
        # failure can be diagnosed rather than merely reported.
        Assert-HarnessTrue $Failures `
            ([string]$result.evidence['perTestTerminal'][0].executedReceipt['outcome'] -ceq 'process-crashed') `
            '20-e2e-receipt-preserved'
    $cancelInfraTag = 'harness-core-case20-cancel-infra-' + [guid]::NewGuid().ToString('N')
    $cancelInfraTmp = Join-Path ([IO.Path]::GetTempPath()) $cancelInfraTag
    $cancelInfraResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($cancelInfraTmp)
        $cancelInfraInv = Join-Path $cancelInfraTmp 'inventory.json'
        [IO.File]::WriteAllText($cancelInfraInv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # CANCELLED leg. The outcome ladder
        # (scripts/integration/IntegrationHarness.Core.psm1:2588-2589) reports a cancelled run as
        # 'Cancelled' - never 'Failed', never 'Complete' - so this leg asserts exactly that.
        $cancelRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'cancelled'
                    processTree = @{ rootPid = 424256; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }
        $cancelled = & $crashSeamCommand.Name -SelectAllRows -InventoryPath $cancelInfraInv `
            -Provider $fake -RunId ('ec' * 16) -CandidateRoot $cancelInfraTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $cancelRunner
        Assert-HarnessTrue $Failures `
            ([string]$cancelled.evidence['perTestTerminal'][0].disposition -ceq 'Cancelled') '20-e2e-cancelled-maps'
        Assert-HarnessTrue $Failures ([string]$cancelled.outcome -ceq 'Cancelled') '20-e2e-cancelled-cancels-run'
        Assert-HarnessTrue $Failures `
            ([string]$cancelled.evidence['perTestTerminal'][0].executedReceipt['outcome'] -ceq 'cancelled') `
            '20-e2e-cancelled-receipt-preserved'

        # INFRASTRUCTURE-BLOCKED leg. Same scaffolding, only the typed observation differs.
        $infraRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'infrastructure-blocked'
                    processTree = @{ rootPid = 424257; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }
        $infra = & $crashSeamCommand.Name -SelectAllRows -InventoryPath $cancelInfraInv `
            -Provider $fake -RunId ('ed' * 16) -CandidateRoot $cancelInfraTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $infraRunner
        Assert-HarnessTrue $Failures `
            ([string]$infra.evidence['perTestTerminal'][0].disposition -ceq 'InfrastructureBlocked') '20-e2e-infra-maps'
        Assert-HarnessTrue $Failures ([string]$infra.outcome -ceq 'Failed') '20-e2e-infra-fails-run'
        Assert-HarnessTrue $Failures `
            ([string]$infra.evidence['perTestTerminal'][0].executedReceipt['outcome'] -ceq 'infrastructure-blocked') `
            '20-e2e-infra-receipt-preserved'

        # UNSUPPORTED-CREDENTIAL leg. Same scaffolding, only the typed observation differs.
        $credRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'unsupported-credential'
                    processTree = @{ rootPid = 424258; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }
        $cred = & $crashSeamCommand.Name -SelectAllRows -InventoryPath $cancelInfraInv `
            -Provider $fake -RunId ('ee' * 16) -CandidateRoot $cancelInfraTmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow } -PrebuiltReceipts $receipts -Runner $credRunner
        Assert-HarnessTrue $Failures `
            ([string]$cred.evidence['perTestTerminal'][0].disposition -ceq 'UnsupportedExternalCredential') '20-e2e-cred-maps'
        Assert-HarnessTrue $Failures ([string]$cred.outcome -ceq 'Failed') '20-e2e-cred-fails-run'
        Assert-HarnessTrue $Failures `
            ([string]$cred.evidence['perTestTerminal'][0].executedReceipt['outcome'] -ceq 'unsupported-credential') `
            '20-e2e-cred-receipt-preserved'
    }
    finally {
        if (Test-Path -LiteralPath $cancelInfraTmp) {
            Remove-Item -LiteralPath $cancelInfraTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $cancelInfraResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '20-e2e-cancel-infra-no-residue' $cancelInfraResidueBefore $cancelInfraResidueAfter
    }
    finally {
        if (Test-Path -LiteralPath $crashTmp) {
            Remove-Item -LiteralPath $crashTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $crashResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '20-e2e-no-residue' $crashResidueBefore $crashResidueAfter
}

# ---------------------------------------------------------------------------
# Case 21: no automatic retry; first failure preserved.
# ---------------------------------------------------------------------------
function Test-HarnessCase21 {
    param([Collections.Generic.List[string]]$Failures)

    $first = Invoke-EntrypointFile -ScriptArgs @('-Run')
    $second = Invoke-EntrypointFile -ScriptArgs @('-Run')
    Assert-HarnessTrue $Failures ($first.ExitCode -eq 2) '21-first-fails'
    Assert-HarnessTrue $Failures ($second.ExitCode -eq $first.ExitCode) '21-repeat-identical-exit'
    Assert-HarnessTrue $Failures ($second.Stderr -ceq $first.Stderr) '21-repeat-identical-text'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    $retryHits = @(Select-String -InputObject $sources -Pattern '(?i)\bretry\b' -AllMatches)
    $allowed = $true
    foreach ($hit in $retryHits) {
        $context = [string]$hit.Line
        if ($context -notmatch '(?i)no[ -]?retry|never|without|not\s|fail-closed|prohibit|forbid|none') {
            $allowed = $false
        }
    }
    Assert-HarnessTrue $Failures $allowed '21-no-auto-retry-token'

    # BEHAVIORAL PROOF of the single-attempt rule, not another token scan. The
    # scan above can only show that the word 'retry' is absent from the module
    # sources; it cannot show that the production loop makes exactly ONE attempt
    # when a test fails, which is the property this case exists for. So the Run
    # seam is invoked once over the SAME single-row temp inventory, the SAME
    # fake provider table, the SAME admitted prebuilt receipts and the SAME
    # injected runner shape as the Test-HarnessCase19 behavioral block, with one
    # difference in the runner: the typed observation is 'assertion-failed'
    # instead of 'passed'. A loop that retried the failure would preserve a
    # second attempt on the terminal record and fail '21-single-attempt-no-retry'
    # below; a loop that mistook the failure for success would fail
    # '21-failure-maps' or '21-failure-fails-run'.
    #
    # Norms:
    #   docs/architecture/I18-32-stateful-test-environments.md:27 - test success
    #     requires both property evidence AND cleanup/residue disposition, which
    #     is why the residue snapshot brackets this block and names its verdict.
    #   docs/architecture/I14-24-local-failure-containment-matrix.md:35 - the
    #     stop recipe preserves attempt evidence, which is what the
    #     exactly-one-attempt assert below reads.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired and the run would die before
    # reaching the gate. Deterministic time behavior is proven by Case24 at the
    # Core seam, not here; here the clock only needs to admit the binding, and
    # no assert below depends on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs and no scriptblock
    # below launches any process. The fixed pid is honest because the validator
    # judges receipt shape and run binding, never liveness.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case21-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the execution contour instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            # The Core-owned contour receipt alone is judged here: the provider
            # contributes nothing to the verdict.
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt: bound BEFORE any dispatch, so the run
        # reaches the execution contour instead of the missing-receipt branch.
        # rowDigest equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The one
        # difference from the Case19 positive control is the typed outcome:
        # 'assertion-failed' instead of 'passed'.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'assertion-failed'
                    processTree = @{ rootPid = 424246; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $result = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('d' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner

        Assert-HarnessTrue $Failures `
            ([string]$result.evidence['perTestTerminal'][0].disposition -ceq 'AssertionFailed') '21-failure-maps'
        Assert-HarnessTrue $Failures ([string]$result.outcome -ceq 'Failed') '21-failure-fails-run'
        # Exactly one attempt survives on the terminal record: a second one
        # would prove the automatic retry this case forbids.
        Assert-HarnessTrue $Failures `
            ($result.evidence['perTestTerminal'][0].attempts.Count -eq 1) '21-single-attempt-no-retry'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '21-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 22: recurrence preserves every explicit attempt.
# ---------------------------------------------------------------------------
function Test-HarnessCase22 {
    param([Collections.Generic.List[string]]$Failures)

    $first = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/22')
    $second = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/22')
    Assert-HarnessTrue $Failures ($first.ExitCode -ne 0) '22-first-attempt-fails'
    Assert-HarnessTrue $Failures ($second.ExitCode -eq $first.ExitCode) '22-recurrence-preserves-outcome'
    Assert-HarnessTrue $Failures ($second.Stderr -ceq $first.Stderr) '22-recurrence-no-averaging'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)attempt') '22-attempt-literal'

    # BEHAVIORAL PROOF of recurrence at the Core seam, not another source-level
    # claim. The scan above can only show that the word 'attempt' occurs in the
    # module sources; it cannot show that a REPEATED run over the same
    # environment observes the same explicit attempts instead of averaging them,
    # dropping them or quietly retrying. So the Run seam is invoked TWICE over
    # the SAME single-row temp inventory, the SAME fake provider table, the SAME
    # admitted prebuilt receipts and the SAME injected runner shape as the
    # Test-HarnessCase19 behavioral block, with exactly three differences: the
    # typed runner observation is 'assertion-failed', CollectEvidence returns
    # nothing, and the two runs carry DIFFERENT run ids ('b'*32 then 'c'*32) so
    # no shared state can leak between them and hide a dropped attempt. A loop
    # that averaged or discarded attempts on the repeat run fails the pair of
    # asserts below; a loop that retried would preserve a second attempt and
    # fail '22-recurrence-single-attempt-each'.
    #
    # Norms:
    #   docs/architecture/I18-32-stateful-test-environments.md:27 - test success
    #     requires both property evidence AND cleanup/residue disposition, which
    #     is why the residue snapshot brackets this block and names its verdict.
    #   docs/architecture/I18-32-stateful-test-environments.md:30 - stateful
    #     isolation is OBSERVED, not asserted by a synthetic report: attempts are
    #     the observed evidence, so a repeated run must observe the same attempts.
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired and the run would die before
    # reaching the gate. Deterministic time behavior is proven by Case24 at the
    # Core seam, not here; here the clock only needs to admit the binding, and no
    # assert below depends on a time value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs and no scriptblock
    # below launches any process. The fixed pid is honest because the validator
    # judges receipt shape and run binding, never liveness.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case22-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the receipt gate instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            # The Core-owned contour receipt alone is judged here: the provider
            # contributes nothing to the verdict.
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt (#907 W7): bound BEFORE any dispatch, so
        # both runs below reach the execution contour instead of the
        # missing-receipt branch. rowDigest equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The typed
        # outcome is 'assertion-failed', so both runs carry an explicit failed
        # attempt whose preservation is the property under test.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'assertion-failed'
                    processTree = @{ rootPid = 424247; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        # Otherwise identical args; only the run id differs, so nothing about
        # the environment can be shared between the two observations.
        $first = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('b' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner
        $second = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('c' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner

        # Same disposition on both legs of the recurrence.
        Assert-HarnessTrue $Failures `
            ([string]$first.evidence['perTestTerminal'][0].disposition -ceq 'AssertionFailed') `
            '22-recurrence-same-disposition'
        Assert-HarnessTrue $Failures `
            ([string]$second.evidence['perTestTerminal'][0].disposition -ceq 'AssertionFailed') `
            '22-recurrence-same-disposition'

        # Exactly one preserved attempt per run: the repeat neither retries
        # (a second attempt) nor drops what the first run observed.
        Assert-HarnessTrue $Failures `
            ($first.evidence['perTestTerminal'][0].attempts.Count -eq 1 -and
            $second.evidence['perTestTerminal'][0].attempts.Count -eq 1) `
            '22-recurrence-single-attempt-each'

        # The preserved attempts agree: recurrence preserves every explicit
        # attempt instead of averaging or discarding them.
        Assert-HarnessTrue $Failures `
            ([string]$first.evidence['perTestTerminal'][0].attempts[0].outcome -ceq
            [string]$second.evidence['perTestTerminal'][0].attempts[0].outcome) `
            '22-recurrence-same-attempt-outcome'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '22-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 23: reset contamination blocks exactly the affected remainder.
# ---------------------------------------------------------------------------
function Test-HarnessCase23 {
    param([Collections.Generic.List[string]]$Failures)

    $before = Get-OwnedResidueSnapshot
    $r = Invoke-EntrypointFile -ScriptArgs @('-Run')
    $after = Get-OwnedResidueSnapshot
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '23-start-prevented-without-selection'
    Assert-HarnessNoNewResidue $Failures '23-nothing-started-nothing-contaminated' $before $after

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match 'NotExecutedDueToPriorContamination') '23-contamination-literal'
    Assert-HarnessTrue $Failures ($sources -match '(?i)reset') '23-reset-literal'

    # BEHAVIORAL PROOF of the contamination fence, not another literal scan.
    # The two source asserts above can only show the NAMES
    # 'NotExecutedDueToPriorContamination' and reset survive in the modules;
    # they cannot show that a failed cleanup actually quarantines the
    # environment and opens Problem State
    # (docs/architecture/I18-32-stateful-test-environments.md:28) with the
    # property evidence and cleanup/residue disposition the same norm requires
    # (docs/architecture/I18-32-stateful-test-environments.md:27). So this block
    # runs the Run seam in process over a THREE-row inventory whose rows share
    # the SAME five class fields, and fails the second member's reset.
    #
    # WHY three rows in ONE group: the group key is exactly those five class
    # fields (scripts/integration/IntegrationHarness.Core.psm1:1850-1855), so
    # all three rows land in one group and run through the one member loop where
    # a contamination can fence the remainder. A one-row inventory, or three
    # rows in three groups, has no remainder to fence and would make every
    # assert below vacuous.
    #
    # WHY distinct row digests: Test-IntegrationHarnessSelectedSet
    # (scripts/integration/IntegrationHarness.Model.psm1:713-717) rejects a
    # repeated rowDigest in the selected set, so three identical digests would
    # die as HARNESS-DUPLICATE-SELECTION before any disposition exists and the
    # fence would never be observed. Distinct testName AND distinct rowDigest
    # per row are both load-bearing.
    #
    # WHY a reset CALL COUNTER instead of an identity check: member order is an
    # implementation detail, so which row is 'test2' must not decide the
    # property. A counter makes exactly one reset succeed and the second fail
    # whichever member it belongs to, so the remainder property holds
    # order-independently.
    #
    # WHY a captured hashtable for both counters: cross-scriptblock state MUST
    # travel as a hashtable the closures capture and mutate, never as a `$script:`
    # variable assignment, which does not propagate into module-invoked
    # closures (probe-measured on #907).
    #
    # WHY the clock is ambient here: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, outside Core's injected owner, so
    # a fixed past instant would already be expired and the run would die before
    # reaching the reset contour. Deterministic time behavior is proven by
    # Case24 at the Core seam, not here, and no assert below depends on a time
    # value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs and no scriptblock
    # below launches any process; the fixed pid in the runner observation is
    # honest because the validator judges shape and run binding, never liveness.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case23-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                }, @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test2'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('e' * 64)
                }, @{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test3'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('f' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # Reset-call counter: the first member's reset succeeds, the second
        # fails, so exactly one member executes and the fenced remainder never
        # reaches the runner.
        $resetCalls = @{ n = 0 }

        # Execution counter: the runner that would be dispatched per member. A
        # loop that executed the fenced remainder would push this past 1.
        $execCalls = @{ n = 0 }

        # One group = one concrete provider class (never 'unbound-provider'),
        # so the binding names STORE and the run reaches the reset contour
        # instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = {
                param($c)
                $resetCalls.n++
                if ($resetCalls.n -ge 2) { throw 'HARNESS-SIMULATED-RESET-FAILURE' }
                return @{}
            }.GetNewClosure()
            # The provider contributes nothing to the verdict; the Core-owned
            # contour receipt alone is judged.
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt for EVERY member, each rowDigest equal to
        # its own row's digest, so no member reaches the missing-receipt branch
        # and the dispositions below are produced by the fence, not by absent
        # evidence.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
            'pkg::kind::name::test2' = @{
                testIdentity      = 'pkg::kind::name::test2'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('e' * 64)
            }
            'pkg::kind::name::test3' = @{
                testIdentity      = 'pkg::kind::name::test3'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('f' * 64)
            }
        }

        # Injected execution runner: process mechanics only, counting entries so
        # the "fenced remainder never executes" claim is measured rather than
        # inferred from the disposition list alone.
        $runner = @{
            Execute = {
                param($c)
                $execCalls.n++
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424248; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $r2 = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('a' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner

        # Exactly one member passes, exactly one is blocked by the failed reset,
        # and exactly one is fenced as never executed - in any order, because
        # member order is an implementation detail.
        $terminal = @($r2.evidence['perTestTerminal'])
        $passedCount = @($terminal | Where-Object { [string]$_.disposition -ceq 'Passed' }).Count
        $blockedCount = @($terminal | Where-Object { [string]$_.disposition -ceq 'InfrastructureBlocked' }).Count
        $fencedCount = @($terminal | Where-Object { [string]$_.disposition -ceq 'NotExecutedDueToPriorContamination' }).Count
        Assert-HarnessTrue $Failures `
            ($passedCount -eq 1 -and $blockedCount -eq 1 -and $fencedCount -eq 1) '23-contamination-exact-remainder'

        # The failed cleanup opens Problem State: the run itself fails even
        # though one member passed.
        Assert-HarnessTrue $Failures ([string]$r2.outcome -ceq 'Failed') '23-contamination-fails-run'

        # The remainder never reaches the runner. A loop that executed it fails
        # here, independently of what the disposition list says.
        Assert-HarnessTrue $Failures ($execCalls.n -eq 1) '23-remainder-never-executed'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '23-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 24: wall/idle timeout uses injected clock (bounded time envelope).
# ---------------------------------------------------------------------------
function Test-HarnessCase24 {
    param([Collections.Generic.List[string]]$Failures)

    $z = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-TestTimeoutSeconds', '0')
    Assert-HarnessTrue $Failures ($z.ExitCode -ne 0) '24-zero-wall-rejected'
    $big = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'x', '-TestTimeoutSeconds', '7201')
    Assert-HarnessTrue $Failures ($big.ExitCode -ne 0) '24-overbound-wall-rejected'
    $names = @(Get-ScriptCommandNames $script:EntrypointPath)
    Assert-HarnessTrue $Failures ($names -notcontains 'Start-Sleep') '24-entrypoint-no-sleep'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    $moduleNames = New-Object Collections.Generic.List[string]
    foreach ($path in @($script:CoreModulePath, $script:ModelModulePath)) {
        foreach ($n in @(Get-ScriptCommandNames $path)) {
            [void]$moduleNames.Add($n)
        }
    }
    Assert-HarnessTrue $Failures (-not $moduleNames.Contains('Start-Sleep')) '24-modules-no-sleep'
    Assert-HarnessTrue $Failures ($sources -match '(?i)clock') '24-injected-clock-literal'

    # DEFECT 8 (#907 D10): time is fully injected. The run binding deadline
    # must be derived from the admitted clock, never from a direct ambient
    # read, and every clock read in the run path must route through the one
    # admitted owner.
    $coreSource = Read-HarnessModuleSource $script:CoreModulePath
    Assert-HarnessTrue $Failures ($coreSource -notmatch '\[System\.DateTimeOffset\]::UtcNow\.AddSeconds') '24-deadline-not-from-ambient-clock'
    Assert-HarnessTrue $Failures ($coreSource -match '(?i)admitted') '24-admitted-clock-literal'
    # The single admitted-clock reader is module-private, so a caller cannot
    # supply a second time owner alongside its own -Clock.
    $coreNames = @((Get-Command -Module 'IntegrationHarness.Core' -CommandType Function -ErrorAction SilentlyContinue) |
        ForEach-Object { $_.Name })
    Assert-HarnessTrue $Failures ($coreNames -notcontains 'Get-HarnessAdmittedClock') '24-admitted-clock-not-exported'

    # The deadline resolver is the clock's load-bearing consumer: an injected
    # clock that is behind the deadline must leave a bound, and one that is
    # past it must expire - regardless of the real wall clock.
    $deadlineSeam = Get-Command -Name 'Resolve-IntegrationHarnessDeadline' -CommandType Function -ErrorAction SilentlyContinue
    Assert-HarnessTrue $Failures ($null -ne $deadlineSeam) '24-deadline-seam-exported'
    if ($null -ne $deadlineSeam) {
        $now = [DateTimeOffset]::UtcNow
        # A real-now binding read through a clock 500s in the PAST leaves
        # ~600 + 500 seconds of bound; if the resolver had ignored the
        # injected clock it would have reported only ~600.
        $futureBinding = @{ deadlineUtc = $now.AddSeconds(600).ToString('o') }
        $remaining = & $deadlineSeam.Name -Binding $futureBinding -Clock { $now.AddSeconds(-500) } -Operation 'Plan'
        Assert-HarnessTrue $Failures ([int]$remaining -gt 1000) '24-injected-clock-drives-deadline'
        # The same binding with a clock in the FUTURE is expired, even though
        # the ambient wall clock has not moved.
        $expired = $false
        try {
            [void](& $deadlineSeam.Name -Binding $futureBinding -Clock { $now.AddSeconds(900) } -Operation 'Plan')
        }
        catch {
            if ((Test-HarnessContractMismatch $_)) { throw }
            $expired = ([string]$_.Exception.Message -match 'HARNESS-DEADLINE-EXCEEDED')
        }
        Assert-HarnessTrue $Failures $expired '24-injected-clock-can-expire-deadline'
    }

    # The bounded runtime already refuses an absent clock; assert the run path
    # passes an admitted one rather than constructing its own.
    Assert-HarnessTrue $Failures ($coreSource -match 'Get-HarnessAdmittedClock') '24-run-uses-admitted-clock'

    # BEHAVIORAL PROOF of the wall breach at the Core seam, not another
    # source-level claim. Two in-process runs of the Run seam over the SAME
    # single-row inventory, the SAME fake provider table, the SAME admitted
    # prebuilt receipts and the SAME injected runner differ in exactly one
    # thing: whether the Execute scriptblock arms the captured time state. The
    # breached run arms it on entry, so the contour's execStart read sees the
    # base instant and its execEnd read sees base + 601s - the Execute window
    # measures exactly 601s and breaches the 600s test-wall bound. The control
    # never arms it, so the window measures 0s and the same run completes.
    # Reverting the contour breach branch, or the wall/idle measurement that
    # feeds it, fails the first pair of asserts.
    #
    # WHY a captured hashtable for the time state: cross-scriptblock time
    # state MUST travel as a hashtable the closures capture and mutate
    # ($timeState.armed), never as a `$script:` variable assignment - that does
    # not propagate into module-invoked closures (probe-measured on #907).
    #
    # WHY the base is near-ambient: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the
    # binding against the AMBIENT wall clock, so a fixed past base would already
    # be expired and the run would die before reaching the contour. The default
    # bounds are testWallSeconds = 600 / testIdleSeconds = 120
    # (scripts/integration/IntegrationHarness.Model.psm1:156-157), so the 601s
    # window breaches the wall bound.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus a
    # -CandidateRoot under that temp dir are the only inputs and no scriptblock
    # below launches any process.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case24-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # One row = one group = one concrete provider class (never
        # 'unbound-provider'), so the binding names STORE and the run reaches
        # the execution contour instead of the missing-provider branch.
        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            # The timeout path continues before evidence collection, so this
            # returning nothing is honest: it is never reached on the breach
            # run, and the control's provider contributes nothing to the verdict.
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Admitted prebuilt receipt: bound BEFORE any dispatch, so the run
        # reaches the execution contour instead of the missing-receipt branch.
        # rowDigest equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Time state for the breached run: near-ambient base, armed by the
        # runner's Execute on entry.
        $timeState = @{ base = [DateTimeOffset]::UtcNow; armed = $false }

        # Injected execution runner: process mechanics only. No process is
        # launched here - the observation is typed, never a live pid. The fixed
        # pid is honest because the validator judges shape and run binding,
        # never liveness.
        $runner = @{
            Execute = {
                param($c)
                $timeState.armed = $true
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424244; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $breached = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('f' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { if ($timeState.armed) { $timeState.base.AddSeconds(601) } else { $timeState.base } }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$breached.evidence['perTestTerminal'][0].disposition -ceq 'TimedOut') '24-wall-breach-maps'
        Assert-HarnessTrue $Failures ([string]$breached.outcome -ceq 'Failed') '24-wall-breach-fails-run'
        Assert-HarnessTrue $Failures `
            ([int]$breached.evidence['perTestTerminal'][0].attempts.Count -eq 1) '24-wall-single-attempt'
        Assert-HarnessTrue $Failures `
            ([double]$breached.evidence['perTestTerminal'][0].attempts[0].wallSeconds -ge 601) '24-wall-seconds-prove-breach'

        # CONTROL: identical inventory, candidate root, fake table, receipts
        # and runner, with a second state table that is never armed, so the
        # clock always returns its base and the Execute window measures 0s.
        # Nothing else differs, so the breach - not the scaffolding - is what
        # causes the timeout above.
        $controlTimeState = @{ base = [DateTimeOffset]::UtcNow; armed = $false }
        $controlRunner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424245; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }
        $control = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('f' * 32) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { $controlTimeState.base }.GetNewClosure() `
            -PrebuiltReceipts $receipts -Runner $controlRunner
        Assert-HarnessTrue $Failures `
            ([string]$control.evidence['perTestTerminal'][0].disposition -ceq 'Passed') '24-wall-control-passes'
        Assert-HarnessTrue $Failures ([string]$control.outcome -ceq 'Complete') '24-wall-control-completes'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '24-wall-no-residue' $residueBefore $residueAfter

    # BEHAVIORAL PROOF of the IDLE breach, which the wall leg above structurally
    # cannot reach: with a broken idle computation that leg still times out at
    # the WALL bound, so it cannot prove the idle path is wired at all. This leg
    # runs the same Run seam over the same scaffolding with exactly one
    # difference: the Execute scriptblock arms the state but reports NO
    # 'progressSeconds', and the injected clock then reads base + 200s. The
    # Execute window therefore measures 200s - UNDER the 600s test-wall bound
    # but OVER the 120s test-idle bound
    # (scripts/integration/IntegrationHarness.Model.psm1:156-157), so only the
    # idle computation can produce this timeout.
    # WHY no 'progressSeconds' key: the contour's default idle is the window
    # minus numeric observed progress, i.e. the WHOLE window when the key is
    # absent (scripts/integration/IntegrationHarness.Core.psm1:3252-3280). That
    # is what makes the entire 200s window idle.
    # WHY 200 and not 120: 120 is the bound itself and the comparison is
    # strictly greater-than, so the window must exceed it; 200 keeps the leg
    # far below the 600s wall bound, which is what separates the idle path from
    # the wall path. Setting the jump to 60s puts the window under BOTH bounds,
    # the run completes, and this block fails - the assertion is load-bearing.
    # WHY a fresh state table and temp dir: cross-scriptblock time state must
    # travel as a hashtable the closures capture and mutate (see the wall leg),
    # and a separate tag keeps this leg's inventory and residue independent of
    # the wall leg's.
    # Norms: docs/architecture/I10-08-02-ip0-one-windows-processexecutor.md:13
    # (wall, idle, memory, CPU and process-count limits) and
    # docs/architecture/I18-32-stateful-test-environments.md:27 (test success
    # requires both property evidence and cleanup/residue disposition).
    $idleTag = 'harness-core-case24-idle-' + [guid]::NewGuid().ToString('N')
    $idleTmp = Join-Path ([IO.Path]::GetTempPath()) $idleTag
    $idleResidueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($idleTmp)
        $idleInv = Join-Path $idleTmp 'inventory.json'
        $idleInventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($idleInv, ($idleInventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        # Same single-row shape, same one concrete provider class (STORE), so
        # the run reaches the execution contour.
        $idleFake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # Same admitted prebuilt receipt, so the run reaches the execution
        # contour instead of the missing-receipt branch.
        $idleReceipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }

        # Fresh time state for the idle leg, armed by the runner on entry.
        $idleState = @{ base = [DateTimeOffset]::UtcNow; armed = $false }

        # The one difference from the wall leg: no 'progressSeconds' key, so the
        # contour measures the whole window as idle. The fixed pid is honest
        # because the validator judges shape and run binding, never liveness.
        $idleRunner = @{
            Execute = {
                param($c)
                $idleState.armed = $true
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424245; ownerRunId = [string]$c.binding['runId'] }
                }
            }.GetNewClosure()
        }

        $idleBreached = & $runSeamCommand.Name -SelectAllRows -InventoryPath $idleInv `
            -Provider $idleFake -RunId ('9' * 32) -CandidateRoot $idleTmp -TimeoutSeconds 600 `
            -Clock { if ($idleState.armed) { $idleState.base.AddSeconds(200) } else { $idleState.base } }.GetNewClosure() `
            -PrebuiltReceipts $idleReceipts -Runner $idleRunner
        Assert-HarnessTrue $Failures `
            ([string]$idleBreached.evidence['perTestTerminal'][0].disposition -ceq 'TimedOut') '24-idle-breach-maps'
        Assert-HarnessTrue $Failures ([string]$idleBreached.outcome -ceq 'Failed') '24-idle-breach-fails-run'
        Assert-HarnessTrue $Failures `
            ([int]$idleBreached.evidence['perTestTerminal'][0].attempts.Count -eq 1) '24-idle-single-attempt'
        Assert-HarnessTrue $Failures `
            ([double]$idleBreached.evidence['perTestTerminal'][0].attempts[0].wallSeconds -lt 600) '24-idle-wall-under-bound'
        Assert-HarnessTrue $Failures `
            ([double]$idleBreached.evidence['perTestTerminal'][0].attempts[0].idleSeconds -ge 200) '24-idle-seconds-prove-idle-path'
    }
    finally {
        if (Test-Path -LiteralPath $idleTmp) {
            Remove-Item -LiteralPath $idleTmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $idleResidueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '24-idle-no-residue' $idleResidueBefore $idleResidueAfter
}

# ---------------------------------------------------------------------------
# Case 25: timeout/cancellation stops the exact owned complete process tree.
# ---------------------------------------------------------------------------
function Test-HarnessCase25 {
    param([Collections.Generic.List[string]]$Failures)

    $before = Get-OwnedResidueSnapshot
    $started = [DateTime]::UtcNow
    $r = Invoke-EntrypointFile -ScriptArgs @('-Run')
    $elapsed = ([DateTime]::UtcNow - $started).TotalSeconds
    $after = Get-OwnedResidueSnapshot
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '25-gate-fails-fast'
    Assert-HarnessTrue $Failures ($elapsed -lt 60) '25-no-hang'
    Assert-HarnessTrue $Failures ($r.TimedOut -eq $false) '25-child-reaped'
    Assert-HarnessNoNewResidue $Failures '25-no-residue' $before $after

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -notmatch 'Stop-Process[^`r`n]*-Name') '25-no-name-based-stop'
    Assert-HarnessTrue $Failures ($sources -notmatch 'Get-Process\s+-Name') '25-no-name-based-query'
    Assert-HarnessTrue $Failures ($sources -match '(?i)(taskkill|/T\b|descendant|owned)') '25-owned-tree-stop-literal'

    # BEHAVIORAL PROOF that a foreign owner's tree claim fails the run. Mirrors
    # the Test-HarnessCase19 behavioral block exactly - the same temp-dir
    # inventory with one STORE row, the same $fake provider ops table with the
    # accepted ObserveReadiness shape, the same admitted $receipts table keyed by
    # 'pkg::kind::name::test' and the same $runner shape - and differs in exactly
    # one thing: the runner claims a process tree owned by a FOREIGN run.
    #
    # Norms: I10.08.02:36 (descendants stay inside the admitted envelope and are
    # observed as lineage; an unexpected escape or effect is a failure) and
    # I18.32:27 (test success needs both property evidence and a cleanup/residue
    # disposition).
    #
    # WHY this exact ownerRunId: the contour
    # (scripts/integration/IntegrationHarness.Core.psm1:3331-3334) rejects a
    # runner tree whose ownerRunId contradicts the binding runId with
    # HARNESS-CONTRADICTORY-EVIDENCE. An all-zeros id can never equal the
    # -RunId below, so this leg proves a foreign tree claim fails the run instead
    # of being adopted as ours. The rootPid is a fixed typed observation, never a
    # live pid: the validator judges shape and run binding, never liveness, and
    # the owner check is reached before any liveness question.
    #
    # WHY the clock is ambient: Test-IntegrationHarnessRunBinding
    # (scripts/integration/IntegrationHarness.Model.psm1:562) admits the binding
    # against the AMBIENT wall clock, outside Core's injected owner, so a fixed
    # past instant would already be expired. Deterministic time behavior is proven
    # by Case24 at the Core seam, not here, and no assert below depends on a time
    # value.
    #
    # WHY no entrypoint child is spawned: the temp inventory plus -CandidateRoot
    # under that temp dir are the only inputs and no scriptblock launches a
    # process.
    $runSeamCommand = Get-HarnessSeamCommand 'Run'
    $caseTag = 'harness-core-case25-foreign-' + [guid]::NewGuid().ToString('N')
    $tmp = Join-Path ([IO.Path]::GetTempPath()) $caseTag
    $residueBefore = Get-OwnedResidueSnapshot
    try {
        [void][IO.Directory]::CreateDirectory($tmp)
        $inv = Join-Path $tmp 'inventory.json'
        $inventoryDocument = @{
            rows = @(@{
                    packageId        = 'pkg'
                    targetKind       = 'kind'
                    targetName       = 'name'
                    testName         = 'test'
                    providerClass    = 'STORE'
                    isolationClass   = 'serial'
                    targetClass      = 't1'
                    resetClass       = 'reset'
                    serializationClass = 'serial'
                    rowDigest        = ('c' * 64)
                })
        }
        [IO.File]::WriteAllText($inv, ($inventoryDocument | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))

        $fake = @{
            ValidateRequirement = { param($c) return @{} }.GetNewClosure()
            Plan                = { param($c) return @{} }.GetNewClosure()
            Allocate            = { param($c) return @{ handle = 'fake' } }.GetNewClosure()
            Start               = { param($c) return @{} }.GetNewClosure()
            ObserveReadiness    = {
                param($c)
                # The exact shape Test-IntegrationHarnessReadiness accepts:
                # binding-bound ids plus a passed semantic receipt. No
                # readyBecauseExitZero / readyBecausePortOpen /
                # readyBecausePidAlive alias is returned, because none of those
                # prove readiness.
                return @{
                    runId            = [string]$c.binding['runId']
                    providerRevision = [string]$c.binding['providerRevision']
                    semanticReceipt  = @{
                        readinessProbePassed = $true
                        owner                = [string]$c.binding['owner']
                        generation           = [int]$c.binding['generation']
                    }
                }
            }.GetNewClosure()
            ResetForTest      = { param($c) return @{} }.GetNewClosure()
            # Never reached on this path: the loop maps the harness-error and
            # continues first. The provider contributes nothing to this leg.
            CollectEvidence   = { param($c) return @{} }.GetNewClosure()
            Stop              = { param($c) return @{} }.GetNewClosure()
            VerifyCleanup     = { param($c) return @{ verified = $true } }.GetNewClosure()
        }

        # The admitted receipt bound BEFORE dispatch, so this run reaches the
        # execution contour instead of the missing-receipt branch. rowDigest
        # equals the selected row's digest.
        $receipts = @{
            'pkg::kind::name::test' = @{
                testIdentity      = 'pkg::kind::name::test'
                binaryDigest      = ('c' * 64)
                discoveryDigest   = ('d' * 64)
                sourceDigest      = ('9' * 64)
                toolchainIdentity = 'fake-toolchain-1'
                rowDigest         = ('c' * 64)
            }
        }
        # The single injected difference: the tree is claimed by a FOREIGN run.
        $runner = @{
            Execute = {
                param($c)
                return @{
                    outcome     = 'passed'
                    processTree = @{ rootPid = 424250; ownerRunId = ('0' * 32) }
                }
            }.GetNewClosure()
        }

        $foreign = & $runSeamCommand.Name -SelectAllRows -InventoryPath $inv `
            -Provider $fake -RunId ('b5' * 16) -CandidateRoot $tmp -TimeoutSeconds 600 `
            -Clock { [DateTimeOffset]::UtcNow }.GetNewClosure() -PrebuiltReceipts $receipts -Runner $runner
        Assert-HarnessTrue $Failures `
            ([string]$foreign.evidence['perTestTerminal'][0].disposition -ceq 'HarnessError') '25-foreign-owner-rejected'
        Assert-HarnessTrue $Failures ([string]$foreign.outcome -ceq 'Failed') '25-foreign-owner-fails-run'
    }
    finally {
        if (Test-Path -LiteralPath $tmp) {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    $residueAfter = Get-OwnedResidueSnapshot
    Assert-HarnessNoNewResidue $Failures '25-foreign-no-residue' $residueBefore $residueAfter
}

# ---------------------------------------------------------------------------
# Case 26: foreign PID/name/port/resource never killed/deleted.
# ---------------------------------------------------------------------------
function Test-HarnessCase26 {
    param([Collections.Generic.List[string]]$Failures)

    $tag = 'SELFTEST-foreign-907-26-' + [guid]::NewGuid().ToString('N')
    $foreignDir = Join-Path ([IO.Path]::GetTempPath()) $tag
    $foreignFile = Join-Path $foreignDir 'unrelated.txt'
    $siblingFile = $null
    try {
        [IO.Directory]::CreateDirectory($foreignDir) | Out-Null
        [IO.File]::WriteAllText($foreignFile, 'task-owned foreign sentinel')
        try {
            $localAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
            if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
                $testsRoot = Join-Path $localAppData 'Eliot\tests'
                if (Test-Path -LiteralPath $testsRoot -PathType Container) {
                    $siblingFile = Join-Path $testsRoot ($tag + '.txt')
                    [IO.File]::WriteAllText($siblingFile, 'sibling sentinel')
                }
            }
        }
        catch { }
        $r = Invoke-EntrypointFile -ScriptArgs @()
        Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '26-gate-exit-2'
        Assert-HarnessTrue $Failures (Test-Path -LiteralPath $foreignFile -PathType Leaf) '26-foreign-file-untouched'
        if ($null -ne $siblingFile) {
            Assert-HarnessTrue $Failures (Test-Path -LiteralPath $siblingFile -PathType Leaf) '26-sibling-file-untouched'
        }
    }
    finally {
        if (Test-Path -LiteralPath $foreignDir) {
            Remove-Item -LiteralPath $foreignDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        if ($null -ne $siblingFile -and (Test-Path -LiteralPath $siblingFile)) {
            Remove-Item -LiteralPath $siblingFile -Force -ErrorAction SilentlyContinue
        }
    }

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -notmatch 'ProcessName') '26-no-processname-token'
    $taskkillLines = @(Select-String -InputObject $sources -Pattern '(?i)taskkill' -AllMatches)
    $pidBound = $true
    foreach ($hit in $taskkillLines) {
        if ([string]$hit.Line -notmatch '/PID') {
            $pidBound = $false
        }
    }
    Assert-HarnessTrue $Failures $pidBound '26-taskkill-only-by-owned-pid'
}

# ---------------------------------------------------------------------------
# Case 27: unknown launch/cleanup requires reconciliation; cleanup idempotent.
# ---------------------------------------------------------------------------
function Test-HarnessCase27 {
    param([Collections.Generic.List[string]]$Failures)

    $runs = @()
    for ($k = 0; $k -lt 3; $k++) {
        $before = Get-OwnedResidueSnapshot
        $got = Invoke-EntrypointFile -ScriptArgs @('-Run')
        $after = Get-OwnedResidueSnapshot
        $runs += $got
        Assert-HarnessTrue $Failures ($got.ExitCode -eq 2) ("27-run-{0}-exit-2" -f $k)
        Assert-HarnessNoNewResidue $Failures ("27-run-{0}-no-residue" -f $k) $before $after
    }
    Assert-HarnessTrue $Failures ($runs[1].Stderr -ceq $runs[0].Stderr) '27-repeat-identical'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)reconcil') '27-reconciliation-literal'
    Assert-HarnessTrue $Failures ($sources -match '(?i)idempotent') '27-idempotent-literal'
}

# ---------------------------------------------------------------------------
# Case 28: exact test/resource counts reconcile.
# ---------------------------------------------------------------------------
function Test-HarnessCase28 {
    param([Collections.Generic.List[string]]$Failures)

    $quoted = "& '" + ($script:EntrypointPath -replace "'", "''") + "' -WhatIf -SelectedTestId @('a-907-28','a-907-28')"
    $d = Invoke-EntrypointCommand -CommandBody $quoted
    Assert-HarnessTrue $Failures ($d.ExitCode -eq 2) '28-duplicate-count-rejected'
    $b = Invoke-EntrypointFile -ScriptArgs @('-WhatIf', '-SelectAllRows', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($b.ExitCode -eq 2) '28-contradictory-count-rejected'
    $e = Invoke-EntrypointFile -ScriptArgs @('-WhatIf')
    Assert-HarnessTrue $Failures ($e.ExitCode -eq 2) '28-zero-count-rejected'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)reconcil') '28-reconcile-literal'
    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '28-zero-selection-rejected' { & $seam.Name -SelectedTestId @() }
    Test-HarnessSeamRejects $Failures '28-duplicate-selection-rejected' { & $seam.Name -SelectedTestId @('a-907-28', 'a-907-28') }
}

# ---------------------------------------------------------------------------
# Case 29: missing/duplicate/contradictory receipts prevent Complete.
# ---------------------------------------------------------------------------
function Test-HarnessCase29 {
    param([Collections.Generic.List[string]]$Failures)

    $quoted = "& '" + ($script:EntrypointPath -replace "'", "''") + "' -Run -SelectedTestId @('a-907-29','a-907-29')"
    $d = Invoke-EntrypointCommand -CommandBody $quoted
    Assert-HarnessTrue $Failures ($d.ExitCode -eq 2) '29-duplicate-prevents-complete-path'
    Assert-HarnessTrue $Failures ($d.Stderr -match '(?i)duplicate') '29-duplicate-text'
    $c = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectAllRows', '-SelectedTestId', 'a')
    Assert-HarnessTrue $Failures ($c.ExitCode -eq 2) '29-contradictory-prevents-complete-path'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match 'Complete') '29-complete-literal'
    $seam = Get-HarnessSeamCommand 'WhatIf'
    Test-HarnessSeamRejects $Failures '29-missing-selection-rejected' { & $seam.Name -SelectedTestId @() }
}

# ---------------------------------------------------------------------------
# Case 30: failure fingerprint stable and sensitive to load-bearing evidence.
# ---------------------------------------------------------------------------
function Test-HarnessCase30 {
    param([Collections.Generic.List[string]]$Failures)

    $first = Invoke-EntrypointFile -ScriptArgs @()
    $second = Invoke-EntrypointFile -ScriptArgs @()
    Assert-HarnessTrue $Failures ($first.Stderr -ceq $second.Stderr) '30-identical-evidence-identical-fingerprint'
    $other = Invoke-EntrypointFile -ScriptArgs @('-Run')
    Assert-HarnessTrue $Failures ($other.Stderr -cne $first.Stderr) '30-distinct-evidence-distinct-fingerprint'

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -match '(?i)fingerprint') '30-fingerprint-literal'
    $d1 = Get-HarnessFileDigest $script:CoreModulePath
    $d2 = Get-HarnessFileDigest $script:CoreModulePath
    Assert-HarnessTrue $Failures ($d1 -ceq $d2) '30-module-digest-stable'
}

# Build a Model-complete evidence record whose only difference is the
# redaction verdict. Used by case 31 to prove that a redaction failure is
# non-green at the RUN level while every per-test disposition and every
# cleanup record is carried through unchanged.
function New-HarnessRedactionProbeEvidence {
    param(
        [Parameter(Mandatory)][bool]$RedactionFailed,
        [Parameter()][string]$Disposition = 'Passed'
    )

    $runId = ('0' * 32)
    $cleanup = @{
        resourceKey  = 'owned-run-root'
        state        = 'CleanupVerified'
        alreadyClean = $true
        failures     = @()
    }
    return @{
        redactionFailed    = $RedactionFailed
        sourceIdentity     = @{ inventoryPath = 'p'; selectionKind = 'ExplicitSelection' }
        worktreeIdentity   = @{ ownedRoot = 'r'; runId = $runId; candidateRoot = 'c' }
        inventoryDigest    = ('a' * 64)
        selectedRowDigests = @(('b' * 64))
        harnessVersion     = 'eliot.integration.harness-core.v1'
        providerIdentity   = @{ name = 'p'; revision = 'r' }
        toolIdentities     = @{ powershellVersion = '7'; coreVersion = 'v'; modelLoaded = $true }
        runBinding         = @{
            runId = $runId; testClass = 'integration'; providerName = 'p'; providerRevision = 'r'
            owner = 'integration-harness'; generation = 1
            deadlineUtc = [DateTimeOffset]::UtcNow.AddSeconds(600).ToString('o')
            inventoryDigest = ('a' * 64)
        }
        resourceRecords    = @()
        planRecords        = @()
        readinessRecords   = @()
        perTestDiscovery   = @('a::b::c::d')
        perTestExecution   = @(@{ testIdentity = 'a::b::c::d'; disposition = $Disposition })
        perTestTerminal    = @(@{ testIdentity = 'a::b::c::d'; disposition = $Disposition })
        artifactHandles    = @()
        failureFingerprint = ('c' * 64)
        cleanupRecords     = @($cleanup)
        arithmetic         = @{
            selectedCount = 1; executedCount = 1; evidenceCount = 1
            resourceCount = 1; cleanedCount = 1
        }
        proofCeiling       = 'INTEGRATION-HARNESS-CORE-STATE-MACHINE-ONLY'
    }
}

# ---------------------------------------------------------------------------
# Case 31: secret/connection/path/payload canaries absent.
# ---------------------------------------------------------------------------
function Test-HarnessCase31 {
    param([Collections.Generic.List[string]]$Failures)

    $r = Invoke-EntrypointFile -ScriptArgs @()
    Assert-HarnessNoCanaries $Failures '31-usage-stderr' $r.Stderr
    $u = Invoke-EntrypointFile -ScriptArgs @('-Run', '-SelectedTestId', 'SELFTEST-GUARANTEED-UNKNOWN-907/31')
    Assert-HarnessNoCanaries $Failures '31-delegation-stderr' $u.Stderr
    $entryText = [IO.File]::ReadAllText($script:EntrypointPath)
    Assert-HarnessNoCanaries $Failures '31-entrypoint-source' $entryText

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessNoCanaries $Failures '31-module-sources' $sources
    Assert-HarnessTrue $Failures ($sources -match '(?i)redact') '31-redaction-literal'

    # DEFECT 7 (#907 D9): a redaction failure may not reach a run-level
    # Complete, and the verdict may not be discarded on the way there.
    $coreSource = Read-HarnessModuleSource $script:CoreModulePath
    Assert-HarnessTrue $Failures ($coreSource -notmatch '(?m)^\s*\[void\]\(Test-IntegrationHarnessEvidenceComplete') '31-completeness-verdict-not-discarded'
    $complete = Get-Command -Name 'Complete-IntegrationHarnessRun' -CommandType Function -ErrorAction SilentlyContinue
    Assert-HarnessTrue $Failures ($null -ne $complete) '31-complete-seam-exported'
    if ($null -ne $complete) {
        $cleanup = @{ resourceKey = 'owned-run-root'; state = 'CleanupVerified'; alreadyClean = $true; failures = @() }
        $runRecord = @{ binding = @{ runId = ('0' * 32) }; history = @('CleanupVerified') }

        # Control: complete evidence over a passed test still completes, so the
        # gate below is proven to be load-bearing rather than always-true.
        $ok = & $complete.Name -Run $runRecord `
            -Evidence (New-HarnessRedactionProbeEvidence -RedactionFailed $false) `
            -CleanupRecords @($cleanup)
        Assert-HarnessTrue $Failures ([string]$ok['outcome'] -ceq 'Complete') '31-clean-evidence-completes'
        Assert-HarnessTrue $Failures ([bool]$ok['evidenceComplete']) '31-clean-evidence-verdict-true'

        # The defect itself: identical record, redactionFailed = true.
        $bad = & $complete.Name -Run $runRecord `
            -Evidence (New-HarnessRedactionProbeEvidence -RedactionFailed $true) `
            -CleanupRecords @($cleanup)
        Assert-HarnessTrue $Failures ([string]$bad['outcome'] -cne 'Complete') '31-redaction-failure-blocks-complete'
        Assert-HarnessTrue $Failures ([bool]$bad['evidenceComplete'] -eq $false) '31-redaction-failure-verdict-false'

        # ... and the primary test outcome is still not rewritten: a real
        # AssertionFailed is still a Failed run, reported as such.
        $preserved = & $complete.Name -Run $runRecord `
            -Evidence (New-HarnessRedactionProbeEvidence -RedactionFailed $true -Disposition 'AssertionFailed') `
            -CleanupRecords @($cleanup)
        Assert-HarnessTrue $Failures ([string]$preserved['outcome'] -ceq 'Failed') '31-redaction-failure-preserves-primary-outcome'
        Assert-HarnessTrue $Failures (@($preserved['history']) -contains 'Failed') '31-redaction-failure-preserved-in-history'
    }
}

# ---------------------------------------------------------------------------
# Case 32: no concrete provisioning/global mutation; reverse cleanup preserves
# the original failure for every possible allocation.
# ---------------------------------------------------------------------------
function Test-HarnessCase32 {
    param([Collections.Generic.List[string]]$Failures)

    $names = @(Get-ScriptCommandNames $script:EntrypointPath)
    foreach ($banned in @('Start-Process', 'Stop-Process', 'cargo', 'nextest', 'surreal')) {
        Assert-HarnessTrue $Failures ($names -notcontains $banned) ("32-entrypoint-no-{0}" -f $banned)
    }
    $entryText = [IO.File]::ReadAllText($script:EntrypointPath)
    Assert-HarnessTrue $Failures ($entryText -notmatch '\[Environment\]::SetEnvironmentVariable') '32-entrypoint-no-global-env-mutation'
    Assert-HarnessTrue $Failures ($entryText -match '(?i)reverse order') '32-reverse-cleanup-documented'

    $envBefore = Get-HarnessAmbientSnapshot
    $before = Get-OwnedResidueSnapshot
    $r = Invoke-EntrypointFile -ScriptArgs @()
    $after = Get-OwnedResidueSnapshot
    $envAfter = Get-HarnessAmbientSnapshot
    Assert-HarnessTrue $Failures ($r.ExitCode -eq 2) '32-gate-exit-2'
    Assert-HarnessAmbientPreserved $Failures '32-ambient-preserved' $envBefore $envAfter
    Assert-HarnessNoNewResidue $Failures '32-no-residue' $before $after

    if (-not $script:ModulesAvailable) { return }
    $sources = (Read-HarnessModuleSource $script:CoreModulePath) + "`n" + (Read-HarnessModuleSource $script:ModelModulePath)
    Assert-HarnessTrue $Failures ($sources -notmatch '\[Environment\]::SetEnvironmentVariable\(\s*[''"][^''"]+[''"]\s*,\s*[^,]+,\s*[''"](Machine|User)[''"]') '32-modules-no-machine-user-env'
    Assert-HarnessTrue $Failures ($sources -match '(?i)reverse') '32-reverse-literal'
    Assert-HarnessTrue $Failures ($sources -match '(?i)cleanup') '32-cleanup-literal'
    $vseam = Get-HarnessSeamCommand 'ValidateConfiguration'
    $missing = Join-Path $script:RepoRoot 'SELFTEST-harness-missing-inventory-907-32.json'
    $envPre = Get-HarnessAmbientSnapshot
    try { [void](& $vseam.Name -InventoryPath $missing) } catch {
        if (Test-HarnessContractMismatch $_) { throw }
    }
    $envPost = Get-HarnessAmbientSnapshot
    Assert-HarnessAmbientPreserved $Failures '32-seam-ambient-preserved' $envPre $envPost
}

$script:CaseTitles = @{
    1  = 'exactly one profile; default launches nothing'
    2  = 'WhatIf deterministic finite plan'
    3  = 'WhatIf creates no process/port/pipe/worktree/data resource'
    4  = 'ValidateConfiguration uses validation/plan only'
    5  = 'unavailable prerequisite differs from invalid configuration'
    6  = 'incomplete inventory differs from missing provider'
    7  = 'provider interface rejects arbitrary methods/command fields'
    8  = 'provider revision and inventory digest load-bearing'
    9  = 'unique canonical run root and owner receipt'
    10 = 'path/reparse escape and foreign owner root rejected'
    11 = 'exact selected group union equals inventory subset, no implicit/empty'
    12 = 'incompatible provider/isolation/target/reset groups rejected'
    13 = 'missing/duplicate test identity prevents start'
    14 = 'exact binary/name invocation and zero-match rejection'
    15 = 'prebuilt binary receipt required'
    16 = 'process observed does not mean semantic readiness'
    17 = 'readiness timeout blocks tests and preserves cleanup ownership'
    18 = 'one terminal disposition per selected test'
    19 = 'pass requires exact executed-test receipt; no probe can fabricate one'
    20 = 'assertion/crash/timeout/cancel/infra outcomes distinct'
    21 = 'no automatic retry; first failure preserved'
    22 = 'recurrence preserves every explicit attempt'
    23 = 'reset contamination blocks exactly the affected remainder'
24 = 'wall/idle timeout and binding deadline use the one injected clock'
    25 = 'timeout/cancellation stops the exact owned complete process tree'
    26 = 'foreign PID/name/port/resource never killed/deleted'
    27 = 'unknown launch/cleanup requires reconciliation; cleanup idempotent'
    28 = 'exact test/resource counts reconcile'
    29 = 'missing/duplicate/contradictory receipts prevent Complete'
    30 = 'failure fingerprint stable and sensitive to load-bearing evidence'
    31 = 'redaction failure is non-green but preserves dispositions and cleanup'
    32 = 'no concrete provisioning/global mutation; reverse cleanup preserves failure'
}

function Invoke-HarnessCaseById {
    param([Parameter(Mandatory)][int]$Id)

    $failures = New-HarnessAssertionScope
    $outcome = 'HarnessError'
    $note = ''
    try {
        $null = & "Test-HarnessCase$Id" $failures
        if ($failures.Count -gt 0) {
            $outcome = 'AssertionFailed'
            $note = 'entry/module assertion failures: ' + ($failures -join ' | ')
        }
        elseif (-not $script:ModulesAvailable) {
            $outcome = 'HarnessError'
            $note = 'fail-closed: IntegrationHarness.Core/Model modules absent (' + $script:ImportDetail + '); entrypoint-level assertions executed and held'
        }
        else {
            $outcome = 'Passed'
            $note = 'entrypoint-level and module-level assertions held'
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

function Write-HarnessCaseResult {
    param([Parameter(Mandatory)][int]$Id, [Parameter(Mandatory)][string]$Outcome)

    $result = [ordered]@{
        suite           = $script:SuiteName
        case_id         = $Id
        schema_version  = $script:SchemaVersion
        outcome         = $Outcome
        identity        = ("907/{0}" -f $Id)
        content_digest  = $script:SuiteDigest
        truncated_bytes = 0
        executing_pid   = [Diagnostics.Process]::GetCurrentProcess().Id
        start_instant   = [Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().ToString('o')
    }
    [Console]::Out.WriteLine(($result | ConvertTo-Json -Compress))
}

if ($CaseId -ne 0) {
    $single = $null
    try {
        $single = Invoke-HarnessCaseById -Id $CaseId
    }
    catch {
        $single = [pscustomobject]@{
            CaseId   = $CaseId
            Outcome  = 'HarnessError'
            Failures = @()
            Note     = 'fail-closed dispatcher exception'
        }
    }
    Write-HarnessCaseResult -Id $CaseId -Outcome $single.Outcome
    if ($single.Outcome -eq 'Passed') { exit 0 } else { exit 1 }
}

$diagnosticResults = @()
foreach ($id in $script:MinCaseId..$script:MaxCaseId) {
    $diagnosticResults += Invoke-HarnessCaseById -Id $id
}
'IntegrationHarness.Core diagnostic: {0} cases, modules={1}' -f $diagnosticResults.Count, $script:ImportDetail
foreach ($row in $diagnosticResults) {
    '907/{0} {1} entry_failures={2} title={3}' -f $row.CaseId, $row.Outcome, $row.Failures.Count, $script:CaseTitles[$row.CaseId]
    '  note: {0}' -f $row.Note
}
$passed = @($diagnosticResults | Where-Object { $_.Outcome -eq 'Passed' }).Count
'summary: passed={0} failed={1}' -f $passed, ($diagnosticResults.Count - $passed)
if ($passed -eq $diagnosticResults.Count) { exit 0 } else { exit 1 }
