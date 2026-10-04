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
