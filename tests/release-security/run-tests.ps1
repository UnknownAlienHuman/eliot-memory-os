[CmdletBinding()]
param()

# Release-security deterministic aggregator (issue #1227, Work item W8,
# acceptance A11).
#
# Contract owner: scripts/finalize-eliot-windows-x64-release.ps1 ::
# Get-ReleaseDeterministicTestAggregatorWiring.  That function "Defines —
# never executes — the exact deterministic suite set" and its source comment
# states verbatim:
#
#   "Deterministic aggregator wiring definition (Part B, #1227 gap i).
#    Defines — never executes — the exact deterministic suite set.  The
#    future aggregator (owner: release-test lane; NOT this script) must run
#    every deterministic suite, report a nonzero exact count per suite, and
#    fail closed on zero counts or missing suites.  Live cert/HSM signing is
#    NEVER part of the deterministic set; it remains a separate manual gate
#    requiring an explicit live certificate/HSM and must never be silently
#    reported as executed."
#
# This script is that aggregator.  It consumes the wiring definition and never
# restates the suite list, so a wiring change fails closed here instead of
# diverging silently.
#
# Fail-closed rules enforced below (Architecture A0.3 "a false VERIFIED_COMPLETE
# or other proof claim" and A14.8 "Zero executed expected tests is not PASS"):
#   * every deterministic suite in the wiring must be executed here;
#   * every executed suite must publish its own receipt with status VERIFIED;
#   * every executed suite must report a NONZERO exact case count, derived from
#     the suite's own receipt — never from this aggregator, never fabricated;
#   * a missing, unparseable, unrunnable, zero-case or case-not-held suite is a
#     FAILURE with a nonzero process exit code;
#   * the live certificate/HSM gate is never executed here, is never reported
#     executed, and never silently turns the result green or red.
#
# The case count of a suite is the count of boolean case fields in the receipt
# that suite itself emits after its own guards pass.  The suites publish one
# boolean per executed case rather than a numeric total, so the exact per-suite
# denominators are reported both as an integer and as the full sorted case-name
# list, so a caller can audit them against the suite source.

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$aggregatorPath = [System.IO.Path]::GetFullPath($PSCommandPath)
# The wiring binds the `release-security-smoke` suite to this exact repository
# path, so the aggregator and that suite are one file.  The comparison below
# keeps the self-binding honest in both directions.
$aggregatorRelativePath = 'tests/release-security/run-tests.ps1'
$finalizerScript = Join-Path $repo 'scripts/finalize-eliot-windows-x64-release.ps1'
$releaseScript = Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1'
$reservedReceiptFields = @('component', 'status')

$script:suiteResults = New-Object System.Collections.Generic.List[object]
$script:liveGateResults = New-Object System.Collections.Generic.List[object]
$script:unaccountedError = ''

function Get-ReleaseSecurityChildShell {
    # Exact executable identity for child suites.  Prefer this process's own
    # host so the aggregator never chooses trust from PATH; fall back to an
    # explicit application lookup, and fail closed (null) if neither exists.
    try {
        $ownPath = [string](Get-Process -Id $PID).Path
        if (-not [string]::IsNullOrWhiteSpace($ownPath) -and
            (Test-Path -LiteralPath $ownPath -PathType Leaf)) {
            return $ownPath
        }
    }
    catch {
        # Fall through to the explicit lookup below.
    }
    foreach ($candidate in @('pwsh.exe', 'powershell.exe')) {
        $command = Get-Command -Name $candidate -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($command -and -not [string]::IsNullOrWhiteSpace([string]$command.Source) -and
            (Test-Path -LiteralPath ([string]$command.Source) -PathType Leaf)) {
            return [string]$command.Source
        }
    }
    return $null
}

function Invoke-ReleaseSecurityChild {
    param(
        [Parameter(Mandatory = $true)][string]$Shell,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $lines = @()
    $exitCode = $null
    $launchError = ''
    $previousPreference = $ErrorActionPreference
    # A native child writing to stderr must not be converted into a terminating
    # error by this aggregator's own Stop preference; the child's exit code and
    # parsed receipt are the only verdict inputs.
    $ErrorActionPreference = 'Continue'
    $global:LASTEXITCODE = 0
    try {
        $lines = @(& $Shell @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    }
    catch {
        $launchError = [string]$_.Exception.Message
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{
        exit_code = $exitCode
        lines = $lines
        launch_error = $launchError
    }
}

function ConvertFrom-ReleaseSecurityJson {
    param([Parameter(Mandatory = $true)][string[]]$Lines)
    # Brace-balanced scan for the last complete top-level JSON object.  Suite
    # receipts are pretty-printed multi-line JSON, so a single-line match is
    # not sufficient.
    $best = $null
    for ($start = 0; $start -lt $Lines.Count; $start++) {
        if ($Lines[$start].Trim() -cne '{') {
            continue
        }
        $builder = New-Object System.Text.StringBuilder
        $depth = 0
        $inString = $false
        $escaped = $false
        $closed = $false
        $end = $start
        for ($index = $start; $index -lt $Lines.Count; $index++) {
            $end = $index
            $line = $Lines[$index]
            [void]$builder.Append($line)
            [void]$builder.Append("`n")
            foreach ($character in $line.ToCharArray()) {
                if ($inString) {
                    if ($escaped) {
                        $escaped = $false
                        continue
                    }
                    if ($character -eq [char]'\') {
                        $escaped = $true
                        continue
                    }
                    if ($character -eq [char]'"') {
                        $inString = $false
                    }
                    continue
                }
                if ($character -eq [char]'"') {
                    $inString = $true
                    continue
                }
                if ($character -eq [char]'{') {
                    $depth++
                }
                elseif ($character -eq [char]'}') {
                    $depth--
                    if ($depth -eq 0) {
                        $closed = $true
                        break
                    }
                }
            }
            if ($closed) {
                break
            }
        }
        if (-not $closed) {
            continue
        }
        $candidate = $null
        try {
            $candidate = $builder.ToString() | ConvertFrom-Json
        }
        catch {
            $candidate = $null
        }
        if ($null -ne $candidate) {
            $best = $candidate
        }
        $start = $end
    }
    return $best
}

function Get-ReleaseSecurityReceiptFields {
    param([Parameter(Mandatory = $true)][object]$Receipt)
    # Normalize a receipt that is either an ordered dictionary (executed inline
    # in this process) or a deserialized PSCustomObject (read from a child suite)
    # into a uniform name/value list.
    $fields = New-Object System.Collections.Generic.List[object]
    if ($Receipt -is [System.Collections.Specialized.OrderedDictionary] -or
        $Receipt -is [System.Collections.IDictionary]) {
        foreach ($key in $Receipt.Keys) {
            $fields.Add([pscustomobject]@{ name = [string]$key; value = $Receipt[$key] })
        }
        return $fields
    }
    foreach ($property in $Receipt.PSObject.Properties) {
        $fields.Add([pscustomobject]@{ name = [string]$property.Name; value = $property.Value })
    }
    return $fields
}

function New-ReleaseSecuritySuiteResult {
    param(
        [Parameter(Mandatory = $true)][object]$Entry
    )
    return [pscustomobject]@{
        suite = [string]$Entry.suite
        path = [string]$Entry.path
        kind = [string]$Entry.kind
        live_cert_required = [bool]$Entry.live_cert_required
        nonzero_exact_count_required = [bool]$Entry.nonzero_exact_count_required
        state = 'NOT-RUN'
        executed = $false
        executed_by = 'none'
        executed_cases = 0
        cases = @()
        metadata_keys = @()
        receipt_component = ''
        exit_code = $null
        detail = ''
    }
}

function Set-ReleaseSecuritySuiteOutcome {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][string]$State,
        [Parameter(Mandatory = $true)][string]$Detail,
        [bool]$Executed = $false,
        [string]$ExecutedBy = 'none',
        [AllowNull()][object]$ExitCode = $null
    )
    $Result.state = $State
    $Result.executed = $Executed
    $Result.executed_by = $ExecutedBy
    $Result.detail = $Detail
    if ($null -ne $ExitCode) {
        $Result.exit_code = [int]$ExitCode
    }
    return $Result
}

function Complete-ReleaseSecuritySuiteFromReceipt {
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][object]$Receipt,
        [Parameter(Mandatory = $true)][string]$ExecutedBy,
        [AllowNull()][object]$ExitCode = $null
    )
    $fields = @(Get-ReleaseSecurityReceiptFields $Receipt)
    $fieldNames = @($fields | ForEach-Object { [string]$_.name })
    foreach ($required in $reservedReceiptFields) {
        if ($fieldNames -notcontains $required) {
            return Set-ReleaseSecuritySuiteOutcome $Result 'NO-RECEIPT' `
                "suite receipt is missing the required '$required' field" $true $ExecutedBy $ExitCode
        }
    }
    $statusField = $fields | Where-Object { [string]$_.name -eq 'status' } | Select-Object -First 1
    $status = [string]$statusField.value
    if ($status -cne 'VERIFIED') {
        return Set-ReleaseSecuritySuiteOutcome $Result 'STATUS-NOT-VERIFIED' `
            "suite receipt status is '$status', not 'VERIFIED'" $true $ExecutedBy $ExitCode
    }
    $componentField = $fields | Where-Object { [string]$_.name -eq 'component' } | Select-Object -First 1
    $component = [string]$componentField.value
    if ([string]::IsNullOrWhiteSpace($component)) {
        return Set-ReleaseSecuritySuiteOutcome $Result 'NO-RECEIPT' `
            'suite receipt component identity is empty' $true $ExecutedBy $ExitCode
    }
    $Result.receipt_component = $component
    $caseNames = New-Object System.Collections.Generic.List[string]
    $notHeld = New-Object System.Collections.Generic.List[string]
    $metadataNames = New-Object System.Collections.Generic.List[string]
    foreach ($field in $fields) {
        if ($reservedReceiptFields -contains [string]$field.name) {
            continue
        }
        if ($field.value -is [bool]) {
            $caseNames.Add([string]$field.name)
            if (-not [bool]$field.value) {
                $notHeld.Add([string]$field.name)
            }
            continue
        }
        # Non-boolean receipt fields (for example a role count) are metadata,
        # never cases.  They can never inflate the case denominator.
        $metadataNames.Add([string]$field.name)
    }
    $Result.cases = @($caseNames | Sort-Object)
    $Result.metadata_keys = @($metadataNames | Sort-Object)
    $Result.executed_cases = $Result.cases.Count
    if ($Result.cases.Count -eq 0) {
        return Set-ReleaseSecuritySuiteOutcome $Result 'ZERO-CASES' `
            'suite reported zero executed cases; zero executed is a failure, not a pass' `
            $true $ExecutedBy $ExitCode
    }
    if ($notHeld.Count -ne 0) {
        return Set-ReleaseSecuritySuiteOutcome $Result 'CASE-NOT-HELD' `
            "suite receipt is status VERIFIED but these cases did not hold: $(@($notHeld | Sort-Object) -join ', ')" `
            $true $ExecutedBy $ExitCode
    }
    return Set-ReleaseSecuritySuiteOutcome $Result 'VERIFIED' `
        "executed_cases=$($Result.executed_cases)" $true $ExecutedBy $ExitCode
}

function Get-ReleaseSecurityOutputTail {
    param(
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [int]$Count = 12
    )
    $selected = @($Lines | Select-Object -Last $Count)
    if ($selected.Count -eq 0) {
        return '<no output>'
    }
    return (($selected | ForEach-Object { $_.TrimEnd() }) -join ' | ')
}

function Read-ReleaseSecurityAggregatorWiring {
    param([Parameter(Mandatory = $true)][string]$Shell)
    # The wiring lives in the sealed production finalizer.  Dot-sourcing that
    # script in this process would also install its private function scope and
    # its `Set-StrictMode -Version Latest`, so the definition is read in a
    # child host and consumed here.  The definition is never re-declared here.
    if (-not (Test-Path -LiteralPath $finalizerScript -PathType Leaf)) {
        throw "release finalizer is missing, so the aggregator wiring cannot be read: $finalizerScript"
    }
    $escapedFinalizer = $finalizerScript.Replace("'", "''")
    $command = @"
`$ErrorActionPreference = 'Stop'
. '$escapedFinalizer'
if (-not (Get-Command Get-ReleaseDeterministicTestAggregatorWiring -CommandType Function -ErrorAction SilentlyContinue)) {
    throw 'release finalizer did not expose Get-ReleaseDeterministicTestAggregatorWiring'
}
Get-ReleaseDeterministicTestAggregatorWiring | ConvertTo-Json -Depth 5 -Compress
"@
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))
    $run = Invoke-ReleaseSecurityChild $Shell @(
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
    if (-not [string]::IsNullOrWhiteSpace($run.launch_error)) {
        throw "release finalizer wiring could not be loaded: $($run.launch_error)"
    }
    if ($run.exit_code -ne 0) {
        throw ("release finalizer wiring read exited $($run.exit_code): " +
            (Get-ReleaseSecurityOutputTail $run.lines))
    }
    $candidate = @($run.lines | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_.StartsWith('[') -or $_.StartsWith('{') } |
        Select-Object -Last 1)
    if ($candidate.Count -ne 1) {
        throw 'release finalizer wiring read produced no machine-readable suite definition'
    }
    $wiring = $null
    try {
        $wiring = $candidate[0] | ConvertFrom-Json
    }
    catch {
        throw "release finalizer wiring read produced unparseable JSON: $($_.Exception.Message)"
    }
    return @($wiring)
}

function Assert-ReleaseSecurityWiringShape {
    param([Parameter(Mandatory = $true)][object[]]$Wiring)
    if ($Wiring.Count -eq 0) {
        throw 'release finalizer wiring declared no suites'
    }
    $seenSuite = @{}
    $seenPath = @{}
    foreach ($entry in $Wiring) {
        foreach ($field in @('suite', 'path', 'kind')) {
            $value = [string]$entry.$field
            if ([string]::IsNullOrWhiteSpace($value)) {
                throw "release finalizer wiring entry is missing '$field'"
            }
        }
        $path = [string]$entry.path
        if ([System.IO.Path]::IsPathRooted($path) -or
            $path -match '^[A-Za-z]:' -or
            @($path -split '[\\/]').Where({ $_ -eq '.' -or $_ -eq '..' -or $_ -eq '' }).Count -ne 0) {
            throw "release finalizer wiring path must be a canonical non-traversing relative identity: $path"
        }
        if ($seenSuite.ContainsKey([string]$entry.suite)) {
            throw "release finalizer wiring declares a duplicate suite name: $($entry.suite)"
        }
        $seenSuite[[string]$entry.suite] = $true
        if ($seenPath.ContainsKey($path)) {
            throw "release finalizer wiring binds one path to two suites: $path"
        }
        $seenPath[$path] = $true
        $properties = @($entry.PSObject.Properties.Name)
        if ($properties -notcontains 'live_cert_required' -or
            $properties -notcontains 'nonzero_exact_count_required') {
            throw "release finalizer wiring entry lacks the required live/count classification: $($entry.suite)"
        }
    }
    if (@($Wiring | Where-Object { -not [bool]$_.live_cert_required }).Count -eq 0) {
        throw 'release finalizer wiring declares no deterministic suite; the aggregator has nothing to run'
    }
    return $true
}

function Get-ReleaseSecurityMandatoryParameters {
    param([Parameter(Mandatory = $true)][string]$ScriptPath)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0 -or $null -eq $ast.ParamBlock) {
        return @()
    }
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($parameter in $ast.ParamBlock.Parameters) {
        $mandatory = $false
        foreach ($attribute in @($parameter.Attributes)) {
            if ($attribute -isnot [System.Management.Automation.Language.AttributeAst]) {
                continue
            }
            if ([string]$attribute.TypeName.Name -ne 'Parameter') {
                continue
            }
            foreach ($named in @($attribute.NamedArguments)) {
                if ([string]$named.ArgumentName -eq 'Mandatory' -and
                    [string]$named.Argument.Extent.Text -ceq '$true') {
                    $mandatory = $true
                }
            }
        }
        if ($mandatory) {
            $names.Add("-$($parameter.Name.VariablePath.UserPath)")
        }
    }
    return @($names | Sort-Object)
}

# ---------------------------------------------------------------------------
# Step 1 — the release-security smoke cases, executed here exactly as before.
#
# This is the suite the wiring names `release-security-smoke` at this same
# repository path.  The assertions are unchanged; the terminal receipt is now
# captured instead of printed so the aggregator can measure it with the same
# rule it applies to every child suite.
# ---------------------------------------------------------------------------

$smokeReceipt = $null
$smokeFailure = ''
try {
    $releaseScriptText = Get-Content -LiteralPath $releaseScript -Raw
    if ($releaseScriptText -match '(?m)&\s+\$[^\r\n]*\bversion\b') {
        throw 'release packaging/verification must not execute surreal.exe to obtain version metadata'
    }
    . (Join-Path $repo 'scripts/build-eliot-windows-x64-release.ps1')

    $metadata = (& cargo metadata --format-version 1 --no-deps 2>$null | Out-String) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) {
        throw 'failed to load Cargo metadata for runtime artifact contract tests'
    }
    $runtimePlan = @(Get-RuntimeArtifactPlan $metadata)
    $expectedRuntime = @(
        'eliot/eliot/cli/runtime/eliot.exe'
        'eliot-host/eliot-host/host/runtime/eliot-host.exe'
        'eliot-watchdog/eliot-watchdog/watchdog/runtime/eliot-watchdog.exe'
        'eliot-kernel/eliot-kernel/kernel/runtime/eliot-kernel.exe'
        'eliot-store-surreal/eliot-store-surreal/store_bridge/runtime/eliot-store-surreal.exe'
        'eliotd/eliotd/daemon/runtime/eliotd.exe'
    )
    $actualRuntime = @($runtimePlan | ForEach-Object { "$($_.package)/$($_.binary)/$($_.role)/$($_.relative_path)" })
    if ($actualRuntime.Count -ne $expectedRuntime.Count -or
        (Compare-Object -ReferenceObject $expectedRuntime -DifferenceObject $actualRuntime).Count -ne 0) {
        throw 'Cargo runtime package/bin contract does not match the SystemService contour'
    }
    $missingMetadata = [pscustomobject]@{
        target_directory = $metadata.target_directory
        packages = @($metadata.packages | Where-Object { [string]$_.name -ne 'eliot-watchdog' })
    }
    $missingRejected = $false
    try {
        Get-RuntimeArtifactPlan $missingMetadata | Out-Null
    }
    catch {
        $missingRejected = $_.Exception.Message -match 'eliot-watchdog'
    }
    if (-not $missingRejected) {
        throw 'missing runtime package metadata was not rejected'
    }

    $externalPathRejected = $false
    $testCatalog = [pscustomobject]@{
        runtime_path = 'runtime/surreal.exe'
        artifact_sha256 = ('0' * 64)
        version = '3.1.4'
        pe_machine = '8664'
        sha256 = ('0' * 64)
        source_commit = 'test'
    }
    try {
        Get-VerifiedPinnedSurrealArtifact 'surreal.exe' ('0' * 64) '3.1.4' $testCatalog | Out-Null
    }
    catch {
        $externalPathRejected = $_.Exception.Message -match 'explicit absolute path'
    }
    if (-not $externalPathRejected) {
        throw 'implicit PATH/relative surreal.exe resolution was not rejected'
    }

    $externalPinRejected = $false
    try {
        Get-VerifiedPinnedSurrealArtifact (Join-Path $env:SystemRoot 'System32\cmd.exe') ('0' * 64) '3.1.4' $testCatalog | Out-Null
    }
    catch {
        $externalPinRejected = $_.Exception.Message -match 'resident regular non-reparse|canonical surreal.exe'
    }
    if (-not $externalPinRejected) {
        throw 'non-canonical surreal executable substitution was not rejected'
    }

    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $root = Join-Path $tempBase "eliot-release-security-$([guid]::NewGuid().ToString('N'))"
    try {
        $fixtureRepo = Join-Path $root 'repo'
        $source = Join-Path $fixtureRepo 'payload'
        $destination = Join-Path $root 'copied'
        New-Item -ItemType Directory -Path $source -Force | Out-Null
        $notPe = Join-Path $root 'not-pe.exe'
        Set-Content -LiteralPath $notPe -Value 'not a PE' -Encoding ascii
        $architectureRejected = $false
        try {
            Assert-WindowsX64Pe $notPe 'not-pe.exe'
        }
        catch {
            $architectureRejected = $_.Exception.Message -match 'not a PE executable'
        }
        if (-not $architectureRejected) {
            throw 'non-PE external artifact was not rejected'
        }
        Set-Content -LiteralPath (Join-Path $source 'tracked.txt') -Value 'tracked release payload' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $source 'untracked.txt') -Value 'must not be staged' -Encoding utf8
        & git -C $fixtureRepo init --quiet
        if ($LASTEXITCODE -ne 0) {
            throw 'failed to initialize release security fixture repository'
        }
        & git -C $fixtureRepo add -- payload/tracked.txt
        if ($LASTEXITCODE -ne 0) {
            throw 'failed to stage the tracked release security fixture'
        }
        & git -C $fixtureRepo -c user.name=Eliot -c user.email=eliot.invalid commit --quiet -m fixture
        if ($LASTEXITCODE -ne 0) {
            throw 'failed to commit the tracked release security fixture'
        }
        $sourceCommit = (& git -C $fixtureRepo rev-parse HEAD | Out-String).Trim()

        Copy-TrackedTree $fixtureRepo $sourceCommit 'payload' $destination
        if (-not (Test-Path -LiteralPath (Join-Path $destination 'tracked.txt') -PathType Leaf)) {
            throw 'tracked payload was not copied'
        }
        if (Test-Path -LiteralPath (Join-Path $destination 'untracked.txt')) {
            throw 'untracked payload crossed the release boundary'
        }

        Set-Content -LiteralPath (Join-Path $source 'tracked.txt') -Value 'dirty tracked payload' -Encoding utf8
        $dirtyRejected = $false
        try {
            Copy-TrackedTree $fixtureRepo $sourceCommit 'payload' (Join-Path $root 'dirty-copy')
        }
        catch {
            $dirtyRejected = $_.Exception.Message -match 'differs from pinned commit'
        }
        if (-not $dirtyRejected) {
            throw 'dirty tracked payload was not rejected against the pinned commit'
        }

        $scanRoot = Join-Path $root 'scan'
        New-Item -ItemType Directory -Path $scanRoot -Force | Out-Null
        $syntheticCredential = 'github_' + 'pat_' + ('A' * 40)
        Set-Content -LiteralPath (Join-Path $scanRoot 'payload.json') -Value "{`"api_key`":`"$syntheticCredential`"}" -Encoding utf8
        $rejected = $false
        try {
            Assert-NoReleaseSecrets $scanRoot
        }
        catch {
            $rejected = $_.Exception.Message -match 'secret scan matched'
        }
        if (-not $rejected) {
            throw 'high-confidence credential fixture was not rejected'
        }
        Remove-Item -LiteralPath (Join-Path $scanRoot 'payload.json')
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbGlvdCJ9.signaturebytes'
        [System.IO.File]::WriteAllText(
            (Join-Path $scanRoot 'utf16.txt'),
            "Authorization: Basic mustnotpersist12`r`n$jwt",
            [System.Text.Encoding]::Unicode)
        $utf16Rejected = $false
        try {
            Assert-NoReleaseSecrets $scanRoot
        }
        catch {
            $utf16Rejected = $_.Exception.Message -match 'secret scan matched'
        }
        if (-not $utf16Rejected) {
            throw 'UTF-16 credential fixture was not rejected'
        }

        $documentationRoot = Join-Path $root 'documentation-scan'
        $operationsDocs = Join-Path $documentationRoot 'docs\operations'
        New-Item -ItemType Directory -Path $operationsDocs -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $operationsDocs 'SURREALDB_CREDENTIAL_AUTHORITY.md') -Value '# Credential authority' -Encoding utf8
        Assert-NoReleaseSecrets $documentationRoot

        Set-Content -LiteralPath (Join-Path $scanRoot 'credential.json') -Value '{"status":"redacted"}' -Encoding utf8
        $secretNameRejected = $false
        try {
            Assert-NoReleaseSecrets $scanRoot
        }
        catch {
            $secretNameRejected = $_.Exception.Message -match 'secret-like filename'
        }
        if (-not $secretNameRejected) {
            throw 'secret-like non-document filename was not rejected'
        }

        $smokeReceipt = [ordered]@{
            component = 'eliot_release_security_smoke'
            status = 'VERIFIED'
            tracked_only_copy = $true
            dirty_tracked_rejected = $true
            secret_fixture_rejected = $true
            utf16_fixture_rejected = $true
            credential_document_name_allowed = $true
            secret_filename_rejected = $true
            surreal_path_pin_required = $true
            surreal_filename_pin_rejected = $true
            non_pe_artifact_rejected = $true
        }
    }
    finally {
        $resolvedRoot = [System.IO.Path]::GetFullPath($root)
        if ($resolvedRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $resolvedRoot)) {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
        }
    }
}
catch {
    # Recorded as an explicit FAILED suite below.  This never becomes a pass:
    # the suite state is FAILED and the process exit code is nonzero.
    $smokeFailure = [string]$_.Exception.Message
}

# ---------------------------------------------------------------------------
# Step 2 — consume the wiring definition and partition deterministic vs live.
# ---------------------------------------------------------------------------

$childShell = Get-ReleaseSecurityChildShell
$wiring = @()
$wiringFailure = ''
try {
    if ([string]::IsNullOrWhiteSpace($childShell)) {
        throw 'no runnable PowerShell host could be identified for the aggregator'
    }
    $wiring = Read-ReleaseSecurityAggregatorWiring $childShell
    [void](Assert-ReleaseSecurityWiringShape $wiring)
    $selfAbsolute = [System.IO.Path]::GetFullPath((Join-Path $repo $aggregatorRelativePath))
    if (-not $selfAbsolute.Equals($aggregatorPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw ("the aggregator is not at its wired path '$aggregatorRelativePath'; " +
            "the wiring owner and the aggregator owner have diverged")
    }
    foreach ($entry in $wiring) {
        if ([string]$entry.path -cne $aggregatorRelativePath) {
            continue
        }
        if ([bool]$entry.live_cert_required) {
            throw ("the wiring binds this aggregator path to a live certificate/HSM-gated " +
                "suite; a deterministic aggregator must never own the live gate")
        }
    }
}
catch {
    $wiringFailure = [string]$_.Exception.Message
}

$deterministicEntries = @($wiring | Where-Object { -not [bool]$_.live_cert_required })
$liveEntries = @($wiring | Where-Object { [bool]$_.live_cert_required })

$sourceCommit = 'unavailable'
try {
    $resolvedCommit = (& git rev-parse HEAD 2>$null | Out-String).Trim()
    if ($resolvedCommit -match '^[0-9a-f]{40}$') {
        $sourceCommit = $resolvedCommit
    }
}
catch {
    $sourceCommit = 'unavailable'
}
Write-Host ("RELEASE_SECURITY_AGGREGATOR: start source_commit=$sourceCommit" +
    " wiring_suites=$($wiring.Count) deterministic=$($deterministicEntries.Count) live_gated=$($liveEntries.Count)")

# ---------------------------------------------------------------------------
# Step 3 — run every deterministic suite named by the wiring.
# ---------------------------------------------------------------------------

foreach ($entry in $deterministicEntries) {
    $result = New-ReleaseSecuritySuiteResult $entry
    $suitePath = Join-Path $repo ([string]$entry.path)
    if ([string]$entry.path -ceq $aggregatorRelativePath) {
        # The smoke suite is this file.  Its cases already ran in step 1.
        if ([string]::IsNullOrWhiteSpace($smokeFailure)) {
            if ($null -eq $smokeReceipt) {
                [void](Set-ReleaseSecuritySuiteOutcome $result 'NO-RECEIPT' `
                    'the inline smoke suite finished without publishing its receipt')
            }
            else {
                $result = Complete-ReleaseSecuritySuiteFromReceipt $result $smokeReceipt `
                    'this-aggregator-inline' $null
            }
        }
        else {
            $result = Set-ReleaseSecuritySuiteOutcome $result 'FAILED' `
                "inline smoke suite threw: $smokeFailure" $false 'this-aggregator-inline'
        }
    }
    elseif (-not (Test-Path -LiteralPath $suitePath -PathType Leaf)) {
        $result = Set-ReleaseSecuritySuiteOutcome $result 'MISSING' `
            "declared deterministic suite script is absent: $suitePath"
    }
    elseif ([string]::IsNullOrWhiteSpace($childShell)) {
        $result = Set-ReleaseSecuritySuiteOutcome $result 'NOT-RUNNABLE' `
            'no runnable PowerShell host is available to execute the declared suite'
    }
    else {
        $run = Invoke-ReleaseSecurityChild $childShell @(
            '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $suitePath)
        if (-not [string]::IsNullOrWhiteSpace($run.launch_error)) {
            $result = Set-ReleaseSecuritySuiteOutcome $result 'NOT-RUNNABLE' `
                "suite host could not be launched: $($run.launch_error)"
        }
        elseif ($run.exit_code -ne 0) {
            $result = Set-ReleaseSecuritySuiteOutcome $result 'FAILED' `
                "suite exited $($run.exit_code): $(Get-ReleaseSecurityOutputTail $run.lines)" `
                $true 'child-powershell' $run.exit_code
        }
        else {
            $receipt = ConvertFrom-ReleaseSecurityJson $run.lines
            if ($null -eq $receipt) {
                $result = Set-ReleaseSecuritySuiteOutcome $result 'NO-RECEIPT' `
                    "suite exited 0 but published no parseable receipt: $(Get-ReleaseSecurityOutputTail $run.lines)" `
                    $true 'child-powershell' $run.exit_code
            }
            else {
                $result = Complete-ReleaseSecuritySuiteFromReceipt $result $receipt `
                    'child-powershell' $run.exit_code
            }
        }
    }
    $script:suiteResults.Add($result)
    $exitText = if ($null -eq $result.exit_code) { 'n/a' } else { [string]$result.exit_code }
    Write-Host ("RELEASE_SECURITY_SUITE: $($result.suite) kind=$($result.kind) " +
        "state=$($result.state) executed=$($result.executed.ToString().ToLowerInvariant()) " +
        "executed_by=$($result.executed_by) executed_cases=$($result.executed_cases) " +
        "receipt_component=$($result.receipt_component) exit=$exitText")
    if ($result.state -ne 'VERIFIED') {
        Write-Host "RELEASE_SECURITY_SUITE_DETAIL: $($result.suite) $($result.detail)"
    }
}

# ---------------------------------------------------------------------------
# Step 4 — the live certificate/HSM gate: reported, never executed.
# ---------------------------------------------------------------------------

foreach ($entry in $liveEntries) {
    $gatePath = Join-Path $repo ([string]$entry.path)
    $gatePresent = Test-Path -LiteralPath $gatePath -PathType Leaf
    $mandatory = if ($gatePresent) {
        @(Get-ReleaseSecurityMandatoryParameters $gatePath)
    }
    else {
        @()
    }
    $gateCommand = "pwsh -NoProfile -File $($entry.path)"
    foreach ($name in $mandatory) {
        $gateCommand += " $name <required-by-the-live-gate>"
    }
    $gate = [pscustomobject]@{
        suite = [string]$entry.suite
        path = [string]$entry.path
        kind = [string]$entry.kind
        live_cert_required = $true
        nonzero_exact_count_required = [bool]$entry.nonzero_exact_count_required
        state = if ($gatePresent) { 'NOT-RUN' } else { 'MISSING' }
        executed = $false
        executed_cases = 0
        cases = @()
        path_present = $gatePresent
        mandatory_parameters = $mandatory
        required_command = $gateCommand
        gate = if ($entry.PSObject.Properties.Name -contains 'gate') { [string]$entry.gate } else { '' }
    }
    $script:liveGateResults.Add($gate)
    Write-Host ("RELEASE_SECURITY_LIVE_GATE: $($gate.suite) kind=$($gate.kind) " +
        "state=$($gate.state) executed=false live_cert_required=true path_present=$($gatePresent)")
    Write-Host "RELEASE_SECURITY_LIVE_GATE_COMMAND: $($gate.required_command)"
}
if ($liveGateResults.Count -eq 0) {
    Write-Host 'RELEASE_SECURITY_LIVE_GATE: none declared by the wiring definition'
}
Write-Host ('RELEASE_SECURITY_LIVE_GATE_NOTE: the live certificate/HSM gate is NOT executed by this ' +
    'deterministic aggregator; a NOT-RUN live gate is never reported as executed and is never ' +
    'reported as passed, and it is excluded from the deterministic verdict below.')

# ---------------------------------------------------------------------------
# Step 5 — exact per-suite verdict and process exit code.
# ---------------------------------------------------------------------------

$failedSuites = @($script:suiteResults | Where-Object { $_.state -ne 'VERIFIED' })
$totalCases = 0
foreach ($result in $script:suiteResults) {
    $totalCases += $result.executed_cases
}
$unaccountedSuites = @($deterministicEntries | Where-Object {
        $name = [string]$_.suite
        -not @($script:suiteResults | Where-Object { $_.suite -ceq $name })
    })

$definitionOk = [string]::IsNullOrWhiteSpace($wiringFailure)
$verdict = 'PASS'
if (-not $definitionOk) {
    $verdict = 'FAIL'
}
elseif ($failedSuites.Count -ne 0) {
    $verdict = 'FAIL'
}
elseif ($unaccountedSuites.Count -ne 0) {
    $verdict = 'FAIL'
}
elseif ($script:unaccountedError) {
    $verdict = 'FAIL'
}
elseif ($script:suiteResults.Count -eq 0) {
    $verdict = 'FAIL'
}

$liveState = if ($liveGateResults.Count -eq 0) { 'NONE-DECLARED' } else {
    (@($script:liveGateResults | ForEach-Object { "$($_.suite)=$($_.state)" }) -join ',')
}

$receipt = [ordered]@{
    schema = 'eliot-release-security-aggregator-receipt-v1'
    component = 'eliot_release_security_aggregator'
    status = $verdict
    aggregator_path = $aggregatorRelativePath
    wiring_source = 'scripts/finalize-eliot-windows-x64-release.ps1::Get-ReleaseDeterministicTestAggregatorWiring'
    wiring_suites = $wiring.Count
    deterministic_suites = $script:suiteResults.Count
    live_gated_suites = $script:liveGateResults.Count
    total_executed_cases = $totalCases
    suites = @($script:suiteResults | ForEach-Object {
            [ordered]@{
                suite = $_.suite
                path = $_.path
                kind = $_.kind
                state = $_.state
                executed = $_.executed
                executed_by = $_.executed_by
                nonzero_exact_count_required = $_.nonzero_exact_count_required
                executed_cases = $_.executed_cases
                cases = @($_.cases)
                metadata_keys = @($_.metadata_keys)
                receipt_component = $_.receipt_component
                exit_code = $_.exit_code
                detail = $_.detail
            }
        })
    live_gates = @($script:liveGateResults | ForEach-Object {
            [ordered]@{
                suite = $_.suite
                path = $_.path
                kind = $_.kind
                state = $_.state
                executed = $false
                executed_cases = 0
                path_present = $_.path_present
                mandatory_parameters = @($_.mandatory_parameters)
                required_command = $_.required_command
                gate = $_.gate
            }
        })
    failures = @($failedSuites | ForEach-Object { "$($_.suite)=$($_.state)" })
    unaccounted_suites = @($unaccountedSuites | ForEach-Object { [string]$_.suite })
    definition_error = $wiringFailure
    unaccounted_error = $script:unaccountedError
    live_gate_state = $liveState
    live_gate_excluded_from_deterministic_verdict = $true
    proof_ceiling = 'RELEASE_SECURITY_DETERMINISTIC_ONLY: provider-free fixture suites only. ' +
    'No live certificate/HSM signing, no signed-bundle verification, no publication, no ' +
    'installed-runtime and no Product-Pulse claim. Product proof remains issue #11.'
}

$summaryLines = @(
    "RELEASE_SECURITY_RESULT: $verdict deterministic_suites=$($script:suiteResults.Count) failed_suites=$($failedSuites.Count) total_executed_cases=$totalCases live_gate=$liveState live_gate_excluded_from_deterministic_verdict=true"
    "RELEASE_SECURITY_PROOF_CEILING: $($receipt.proof_ceiling)"
)
foreach ($suite in $script:suiteResults) {
    $summaryLines += "RELEASE_SECURITY_SUITE_RESULT: $($suite.suite) $($suite.state) executed_cases=$($suite.executed_cases) exit=$($suite.exit_code) detail=$($suite.detail)"
}
foreach ($gate in $script:liveGateResults) {
    $summaryLines += "RELEASE_SECURITY_LIVE_GATE_RESULT: $($gate.suite) $($gate.state) executed=false executed_cases=0 required_command=$($gate.required_command)"
}
if ($failedSuites.Count -ne 0) {
    $summaryLines += "RELEASE_SECURITY_FAILED_SUITES: $((@($failedSuites | ForEach-Object { "$($_.suite)=$($_.state)" })) -join ', ')"
}
if ($unaccountedSuites.Count -ne 0) {
    $summaryLines += "RELEASE_SECURITY_UNACCOUNTED_SUITES: $((@($unaccountedSuites | ForEach-Object { [string]$_.suite })) -join ', ')"
}
if (-not [string]::IsNullOrWhiteSpace($wiringFailure)) {
    $summaryLines += "RELEASE_SECURITY_DEFINITION_ERROR: $wiringFailure"
}
if ($script:unaccountedError) {
    $summaryLines += "RELEASE_SECURITY_UNACCOUNTED_ERROR: $($script:unaccountedError)"
}
foreach ($line in $summaryLines) {
    Write-Host $line
}

$receiptJson = $receipt | ConvertTo-Json -Depth 8
Write-Output $receiptJson

if ($verdict -eq 'PASS') {
    exit 0
}
exit 1
