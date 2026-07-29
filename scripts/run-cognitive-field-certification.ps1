[CmdletBinding()]
param(
    [ValidateSet('Prepare', 'Deterministic', 'SealProviderPlan', 'RecordProvider', 'Grade', 'All')]
    [string]$Mode = 'All',
    [string]$RunId,
    [string]$SecondRepository = $env:ELIOT_COGNITIVE_SECOND_REPO,
    [string]$ReportRoot,
    [string]$PrivateRoot,
    [string]$Governor,
    [string]$ProviderCalls,
    [string[]]$ProviderReceipt = @(),
    [ValidateRange(60, 7200)]
    [int]$TestTimeoutSeconds = 3600
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$suitePath = Join-Path $repo 'tests\cognitive\field-v2\suite.json'
$sourceCommit = (& git -C $repo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Could not resolve the exact source commit.'
}
if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = "cognitive-field-$($sourceCommit.Substring(0, 12))"
}
if ([string]::IsNullOrWhiteSpace($SecondRepository)) {
    $SecondRepository = Join-Path $env:LOCALAPPDATA 'Eliot\cognitive-field\second-repos\ripgrep'
}
if ([string]::IsNullOrWhiteSpace($ReportRoot)) {
    $ReportRoot = Join-Path $repo "reports\cognitive-field\$RunId"
}
if ([string]::IsNullOrWhiteSpace($PrivateRoot)) {
    $PrivateRoot = Join-Path $env:LOCALAPPDATA "Eliot\cognitive-field\private\$RunId"
}
$SecondRepository = [IO.Path]::GetFullPath($SecondRepository)
$ReportRoot = [IO.Path]::GetFullPath($ReportRoot)
$PrivateRoot = [IO.Path]::GetFullPath($PrivateRoot)
if ($PrivateRoot.StartsWith($repo, [StringComparison]::OrdinalIgnoreCase) -or
    $PrivateRoot.StartsWith($SecondRepository, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'PrivateRoot must remain outside both Git repositories.'
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Value)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-FileSha256 {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Write-NewOrSameJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Value
    )
    $json = ($Value | ConvertTo-Json -Depth 20) + [Environment]::NewLine
    $parent = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $existing = Get-Content -LiteralPath $Path -Raw
        if ($existing -cne $json) {
            throw "Sealed JSON already exists with different content: $Path"
        }
        return
    }
    [IO.File]::WriteAllText($Path, $json, [Text.UTF8Encoding]::new($false))
}

function Resolve-Governor {
    if (-not [string]::IsNullOrWhiteSpace($Governor)) {
        return (Resolve-Path -LiteralPath $Governor).Path
    }
    & cargo build --offline -p eliot-app --bin eliot-governor
    if ($LASTEXITCODE -ne 0) {
        throw "Governor build failed with exit code $LASTEXITCODE"
    }
    $metadata = (& cargo metadata --offline --no-deps --format-version 1 | ConvertFrom-Json)
    if ($LASTEXITCODE -ne 0) {
        throw 'cargo metadata failed while resolving the Governor executable.'
    }
    $candidate = Join-Path ([string]$metadata.target_directory) 'debug\eliot-governor.exe'
    return (Resolve-Path -LiteralPath $candidate).Path
}

function Invoke-Governor {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & $script:GovernorPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Governor command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

function Assert-ResumableBatchReceipt {
    param(
        [Parameter(Mandatory)]$Receipt,
        [Parameter(Mandatory)][string]$ExpectedSourceCommit,
        [Parameter(Mandatory)][string]$ExpectedArgumentsSha256
    )
    if ($Receipt.schema_version -cne 'eliot-cognitive-verifier-command-v1' -or
        $Receipt.source_commit -cne $ExpectedSourceCommit -or
        $Receipt.arguments_sha256 -cne $ExpectedArgumentsSha256 -or
        [int]$Receipt.exit_code -ne 0) {
        throw "Existing verifier batch receipt failed its sealed binding."
    }
    foreach ($stream in @('stdout', 'stderr')) {
        $pathProperty = "${stream}_path"
        $hashProperty = "${stream}_sha256"
        $path = [IO.Path]::GetFullPath([string]$Receipt.$pathProperty)
        if (-not $path.StartsWith($PrivateRoot, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileSha256 $path) -cne [string]$Receipt.$hashProperty) {
            throw "Existing verifier $stream evidence failed exact readback."
        }
    }
}

function Invoke-VerifierBatch {
    param(
        [Parameter(Mandatory)][string]$BatchId,
        [Parameter(Mandatory)][string]$Program,
        [Parameter(Mandatory)][string[]]$Arguments
    )
    $batchRoot = Join-Path $PrivateRoot "verifiers\$BatchId"
    [IO.Directory]::CreateDirectory($batchRoot) | Out-Null
    $stdoutPath = Join-Path $batchRoot 'stdout.log'
    $stderrPath = Join-Path $batchRoot 'stderr.log'
    $receiptPath = Join-Path $batchRoot 'receipt.json'
    $argumentsMaterial = "$Program`0$($Arguments -join "`0")"
    $argumentsSha256 = Get-Sha256Text $argumentsMaterial
    if (Test-Path -LiteralPath $receiptPath -PathType Leaf) {
        $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        Assert-ResumableBatchReceipt $receipt $sourceCommit $argumentsSha256
        return $receipt
    }
    if ((Test-Path -LiteralPath $stdoutPath) -or (Test-Path -LiteralPath $stderrPath)) {
        throw "Unsealed verifier logs already exist for $BatchId; preserve them and choose a new RunId."
    }
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    & $Program @Arguments 1> $stdoutPath 2> $stderrPath
    $exitCode = $LASTEXITCODE
    $stopwatch.Stop()
    $receipt = [ordered]@{
        schema_version = 'eliot-cognitive-verifier-command-v1'
        source_commit = $sourceCommit
        command_ref = $BatchId
        arguments_sha256 = $argumentsSha256
        exit_code = $exitCode
        elapsed_ms = [uint64][Math]::Round($stopwatch.Elapsed.TotalMilliseconds)
        stdout_path = [IO.Path]::GetFullPath($stdoutPath)
        stdout_sha256 = Get-FileSha256 $stdoutPath
        stderr_path = [IO.Path]::GetFullPath($stderrPath)
        stderr_sha256 = Get-FileSha256 $stderrPath
    }
    Write-NewOrSameJson $receiptPath $receipt
    if ($exitCode -ne 0) {
        throw "Verifier batch $BatchId failed with exit code $exitCode. Raw logs: $batchRoot"
    }
    return [pscustomobject]$receipt
}

function Get-CaseBatchIds {
    param([Parameter(Mandatory)]$Case)
    $ids = [Collections.Generic.List[string]]::new()
    $ids.Add('workspace-verify')
    switch ([string]$Case.family) {
        'U' {
            $ids.Add('live-context-packets')
            $ids.Add('live-memory-retrieval')
        }
        'M' {
            $ids.Add('live-memory-retrieval')
            $ids.Add('live-memory-lifecycle')
        }
        'D' { $ids.Add('live-memory-lifecycle') }
        'R' {
            if ($Case.case_id -eq 'R01') {
                $ids.Add('r01-100k-scale')
            }
            elseif ($Case.case_id -in @('R03', 'R04', 'R05')) {
                $ids.Add('live-writer-recovery')
            }
        }
    }
    return @($ids | Select-Object -Unique)
}

function Invoke-DeterministicCorpus {
    $currentPowerShell = (Get-Process -Id $PID).Path
    $isolated = Join-Path $repo 'scripts\run-isolated-tests.ps1'
    $batches = @{}
    $batches['workspace-verify'] = Invoke-VerifierBatch 'workspace-verify' 'just' @('verify')
    $batches['live-context-packets'] = Invoke-VerifierBatch 'live-context-packets' $currentPowerShell @(
        '-NoProfile', '-File', $isolated,
        '-TestPackage', 'eliot-engine',
        '-TestBinary', 'context_packets_and_proofs',
        '-TestTimeoutSeconds', [string]$TestTimeoutSeconds
    )
    $batches['live-memory-retrieval'] = Invoke-VerifierBatch 'live-memory-retrieval' $currentPowerShell @(
        '-NoProfile', '-File', $isolated,
        '-TestPackage', 'eliot-store',
        '-TestBinary', 'memory_retrieval',
        '-TestTimeoutSeconds', [string]$TestTimeoutSeconds
    )
    $batches['live-memory-lifecycle'] = Invoke-VerifierBatch 'live-memory-lifecycle' $currentPowerShell @(
        '-NoProfile', '-File', $isolated,
        '-TestPackage', 'eliot-engine',
        '-TestBinary', 'memory_lifecycle',
        '-TestTimeoutSeconds', [string]$TestTimeoutSeconds
    )
    $batches['live-writer-recovery'] = Invoke-VerifierBatch 'live-writer-recovery' $currentPowerShell @(
        '-NoProfile', '-File', $isolated,
        '-TestPackage', 'eliot-engine',
        '-TestBinary', 'write_idempotency_and_recovery',
        '-TestTimeoutSeconds', [string]$TestTimeoutSeconds
    )
    $batches['r01-100k-scale'] = Invoke-VerifierBatch 'r01-100k-scale' $currentPowerShell @(
        '-NoProfile', '-File', $isolated,
        '-TestPackage', 'eliot-store',
        '-TestBinary', 'cognitive_field_scale',
        '-TestName', 'r01_large_corpus_retrieval_meets_target_workstation_slos',
        '-RunIgnored',
        '-TestTimeoutSeconds', [string]$TestTimeoutSeconds
    )

    $suite = Get-Content -LiteralPath $suitePath -Raw | ConvertFrom-Json
    foreach ($case in $suite.cases) {
        $conditions = if ([bool]$case.model_backed) {
            @($case.memory_conditions)
        }
        else {
            @($case.memory_conditions | Select-Object -First 1)
        }
        $batchIds = Get-CaseBatchIds $case
        foreach ($condition in $conditions) {
            $commands = foreach ($batchId in $batchIds) {
                $batch = $batches[$batchId]
                [ordered]@{
                    command_ref = [string]$batch.command_ref
                    arguments_sha256 = [string]$batch.arguments_sha256
                    exit_code = [int]$batch.exit_code
                    elapsed_ms = [uint64]$batch.elapsed_ms
                    stdout_path = [string]$batch.stdout_path
                    stdout_sha256 = [string]$batch.stdout_sha256
                    stderr_path = [string]$batch.stderr_path
                    stderr_sha256 = [string]$batch.stderr_sha256
                }
            }
            $receipt = [ordered]@{
                schema_version = 'eliot-cognitive-deterministic-evidence-v1'
                run_id = $RunId
                case_id = [string]$case.case_id
                memory_condition = [string]$condition
                source_commit = $sourceCommit
                verifier_refs = @($case.deterministic_verifier_refs)
                commands = @($commands)
                controller_provider_calls = 0
                truth_revision_before = "git:$sourceCommit"
                truth_revision_after_observability = "git:$sourceCommit"
            }
            $receiptPath = Join-Path $PrivateRoot "receipts\$($case.case_id)\$condition.json"
            Write-NewOrSameJson $receiptPath $receipt
            Invoke-Governor @(
                'cognitive-field', 'record-deterministic',
                '--report-root', $ReportRoot,
                '--private-root', $PrivateRoot,
                '--case-id', [string]$case.case_id,
                '--memory-condition', [string]$condition,
                '--receipt', $receiptPath
            )
        }
    }
}

$script:GovernorPath = Resolve-Governor
if ($Mode -in @('Prepare', 'All')) {
    Invoke-Governor @(
        'cognitive-field', 'prepare',
        '--suite', $suitePath,
        '--run-id', $RunId,
        '--primary-repo', $repo,
        '--second-repo', $SecondRepository,
        '--report-root', $ReportRoot,
        '--private-root', $PrivateRoot
    )
}
if ($Mode -in @('Deterministic', 'All')) {
    Invoke-DeterministicCorpus
}
if ($Mode -in @('SealProviderPlan', 'All')) {
    if ([string]::IsNullOrWhiteSpace($ProviderCalls)) {
        if ($Mode -eq 'SealProviderPlan') {
            throw 'SealProviderPlan requires -ProviderCalls.'
        }
    }
    else {
        Invoke-Governor @(
            'cognitive-field', 'seal-provider-plan',
            '--report-root', $ReportRoot,
            '--private-root', $PrivateRoot,
            '--calls', ([IO.Path]::GetFullPath($ProviderCalls))
        )
    }
}
if ($Mode -in @('RecordProvider', 'All')) {
    if ($ProviderReceipt.Count -eq 0) {
        if ($Mode -eq 'RecordProvider') {
            throw 'RecordProvider requires at least one -ProviderReceipt.'
        }
    }
    else {
        foreach ($receipt in $ProviderReceipt) {
            Invoke-Governor @(
                'cognitive-field', 'record-provider',
                '--report-root', $ReportRoot,
                '--private-root', $PrivateRoot,
                '--receipt', ([IO.Path]::GetFullPath($receipt))
            )
        }
    }
}
if ($Mode -in @('Grade', 'All')) {
    & $script:GovernorPath cognitive-field grade --report-root $ReportRoot --private-root $PrivateRoot
    exit $LASTEXITCODE
}
