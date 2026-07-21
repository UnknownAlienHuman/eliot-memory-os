[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$harness = Join-Path $repo 'scripts\run-phase-l10-l12-cognitive-dogfood.ps1'
$projectId = '11111111-1111-4111-8111-111111111111'
$taskId = '22222222-2222-4222-8222-222222222222'
$temp = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) ("eliot-m6-provider-free-{0}-{1}" -f $PID, [guid]::NewGuid().ToString('N'))))
$lower = $temp.ToLowerInvariant()
if (-not $temp.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase) -or
    $lower.Contains('onedrive') -or $lower.Contains('programdata')) {
    throw "unsafe provider-free test root: $temp"
}

function Write-JsonFile([string]$Path, $Value) {
    New-Item -ItemType Directory -Force (Split-Path -Parent $Path) | Out-Null
    $Value | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Get-StringSha256([string]$Value) {
    return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Value))).ToLowerInvariant()
}

function Get-JsonSha256($Value) {
    return Get-StringSha256 ($Value | ConvertTo-Json -Compress -Depth 100)
}

function ConvertTo-CanonicalJsonValue($Value) {
    if ($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $keys = [string[]]@($Value.Keys | ForEach-Object { [string]$_ })
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        $ordered = [ordered]@{}
        foreach ($key in $keys) { $ordered[$key] = ConvertTo-CanonicalJsonValue $Value[$key] }
        return [pscustomobject]$ordered
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $Value) { $items.Add((ConvertTo-CanonicalJsonValue $item)) }
        return ,$items.ToArray()
    }
    $names = [string[]]@($Value.PSObject.Properties.Name)
    [Array]::Sort($names, [StringComparer]::Ordinal)
    $ordered = [ordered]@{}
    foreach ($name in $names) { $ordered[$name] = ConvertTo-CanonicalJsonValue $Value.PSObject.Properties[$name].Value }
    return [pscustomobject]$ordered
}

function Get-CanonicalJsonSha256($Value) {
    return Get-StringSha256 ((ConvertTo-CanonicalJsonValue $Value) | ConvertTo-Json -Compress -Depth 100)
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-SourceRunnerVerification([string]$CaseId, [string]$InvocationId) {
    $contract = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'verifier\host-output-contract.json') -Raw | ConvertFrom-Json -Depth 100
    $checks = [System.Collections.Generic.List[object]]::new()
    foreach ($field in $contract.required_fields) {
        $checks.Add([pscustomobject][ordered]@{name="required:$field";passed=$true})
    }
    foreach ($name in @(
        'no_chain_of_thought_fields','case_identity','variant_identity','host_identity',
        'host_session_recorded','model_identity','current_truth_revision','exposure_set_exact',
        'negative_transfer_false','candidate_only_write_receipt','launcher_image_attested_in_job',
        'launcher_binary_hash_stable','launcher_binary_matches_execution_seal','provider_image_attested_in_job',
        'provider_binary_hash_stable','provider_binary_matches_execution_seal',
        'provider_bundle_hash_stable','provider_bundle_matches_execution_seal',
        'provider_bundle_namespace_immutable',
        'governor_session_attested','host_outer_protocol_attested'
    )) {
        $checks.Add([pscustomobject][ordered]@{name=$name;passed=$true})
    }
    return [pscustomobject][ordered]@{
        schema_version='eliot-cognitive-local-verification-v1';case_id=$CaseId;invocation_id=$InvocationId
        passed=$true;classification='AuditFindingCandidate';disposition='accepted_as_candidate_pending_governor_disposition'
        truth_promoted=$false;checks=@($checks)
    }
}

function New-FixtureExposure([string]$Root) {
    $cases = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'cases.json') -Raw | ConvertFrom-Json -Depth 100
    $entries = [ordered]@{}
    foreach ($case in $cases.cases) {
        $handles = if ($null -ne $case.reciprocal_flow) { @() } else { @("memory:fixture-$($case.case_id.ToLowerInvariant())") }
        $entries[$case.case_id] = [pscustomobject]@{
            current_truth_revision = "fixture-revision-$($case.case_id.ToLowerInvariant())"
            treatment_handles = $handles
            control_handles = @()
        }
    }
    $path = Join-Path $Root 'exposure.json'
    Write-JsonFile $path ([pscustomobject][ordered]@{
        schema_version='eliot-cognitive-exposure-map-v1';sealed_after_integration=$true;cases=[pscustomobject]$entries
    })
    return $path
}

function New-SourceArtifacts([string]$Root, [switch]$Partial) {
    $base = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\valid-source-write-output.json') -Raw | ConvertFrom-Json -Depth 100
    $exposurePath = Join-Path $Root 'exposure.json'
    $sealedPlan = (& $harness -OutputRoot $Root -ProjectId $projectId -TaskId $taskId -ExposureMap $exposurePath -ProviderFreeTestMode -EliotExe $harness) | ConvertFrom-Json -Depth 100
    foreach ($sourceCall in @($sealedPlan.invocations | Where-Object invocation_role -eq 'source_write')) {
        $canonicalBodyHash = Get-CanonicalJsonSha256 $sourceCall.candidate_body
        $reverse = [ordered]@{}
        foreach ($name in @($sourceCall.candidate_body.PSObject.Properties.Name | Sort-Object -Descending)) {
            $reverse[$name] = $sourceCall.candidate_body.PSObject.Properties[$name].Value
        }
        $reorderedBody = [pscustomobject]$reverse
        if ([string]$sourceCall.candidate_body_sha256 -cne $canonicalBodyHash -or
            (Get-CanonicalJsonSha256 $reorderedBody) -cne $canonicalBodyHash -or
            (Get-JsonSha256 $reorderedBody) -ceq $canonicalBodyHash) {
            throw "source candidate body hash does not match serde_json canonical key ordering for $($sourceCall.invocation_id)"
        }
    }
    $cases = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'cases.json') -Raw | ConvertFrom-Json -Depth 100
    $sources = @(
        [pscustomobject]@{id='LC-01-source-opencode';case='LC-01';host='opencode';revision='fixture-revision-lc-01';write=[string]@($sealedPlan.invocations | Where-Object invocation_id -eq 'LC-01-source-opencode')[0].candidate_write_id;evidence=@('native-health:passed','host-namespace:init-channel-closed','verifier:transport-split')},
        [pscustomobject]@{id='LC-02-source-antigravity';case='LC-02';host='antigravity';revision='fixture-revision-lc-02';write=[string]@($sealedPlan.invocations | Where-Object invocation_id -eq 'LC-02-source-antigravity')[0].candidate_write_id;evidence=@('sibling-render:passed','patched-discovery:failed','verifier:surface-split')}
    )
    if ($Partial) { $sources = @($sources[0]) }
    foreach ($source in $sources) {
        $output = $base | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        $output.case_id = $source.case
        $output.host = $source.host
        $output.host_session_id = "fixture-$($source.id)"
        $output.model = 'fixture-model'
        $output.current_truth_revision = $source.revision
        $output.mechanism_claim = [string]@($cases.cases | Where-Object case_id -eq $source.case)[0].reciprocal_flow.source_statement
        $output.candidate_write_receipt.receipt_id = $source.write
        $output.candidate_write_receipt.write_id = $source.write
        $output.candidate_write_receipt.evidence_refs = @($source.evidence)
        $invocationRoot = Join-Path $Root "invocations\$($source.id)"
        New-Item -ItemType Directory -Force $invocationRoot | Out-Null
        $output | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath (Join-Path $invocationRoot 'raw.stdout') -Encoding utf8
        Write-JsonFile (Join-Path $invocationRoot 'parsed.json') $output
        Write-JsonFile (Join-Path $invocationRoot 'verification.json') (New-SourceRunnerVerification $source.case $source.id)
        Write-JsonFile (Join-Path $invocationRoot 'terminal.json') ([pscustomobject]@{
            terminal=[pscustomobject]@{
                call_id=$source.id;call_number=if($source.case -eq 'LC-01'){5}else{7};status='succeeded'
                candidate_receipt=[pscustomobject]@{receipt_id=$source.write;write_id=$source.write};no_redispatch=$true
            }
            canonical_receipt=[pscustomobject]@{receipt_id=$source.write;write_id=$source.write};replay=$false
        })
    }
    New-PreDispositionArtifacts $Root
}

function New-PreDispositionArtifacts([string]$Root) {
    $plan = (& $harness -OutputRoot $Root -ProjectId $projectId -TaskId $taskId -ExposureMap (Join-Path $Root 'exposure.json') -ProviderFreeTestMode -EliotExe $harness) |
        ConvertFrom-Json -Depth 100
    $eligible = @($plan.invocations | Where-Object { -not $_.requires_disposition })
    $cases = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'cases.json') -Raw | ConvertFrom-Json -Depth 100
    $exposure = Get-Content -LiteralPath (Join-Path $Root 'exposure.json') -Raw | ConvertFrom-Json -Depth 100
    $baseOutput = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'fixtures\valid-host-output.json') -Raw | ConvertFrom-Json -Depth 100
    $attemptRecords = [System.Collections.Generic.List[object]]::new()
    $terminalRecords = [System.Collections.Generic.List[object]]::new()
    $callNumber = 0
    foreach ($invocation in $eligible) {
        $callNumber += 1
        $invocationRoot = Join-Path $Root "invocations\$($invocation.invocation_id)"
        New-Item -ItemType Directory -Force $invocationRoot | Out-Null
        $attempt = [pscustomobject][ordered]@{
            call_id=$invocation.invocation_id;call_number=$callNumber;provider_calls_consumed=$callNumber
            hard_provider_call_cap=18;status='attempting';created_at='2026-07-16T00:00:00Z'
        }
        Write-JsonFile (Join-Path $invocationRoot 'attempt.json') $attempt
        $parsedPath = Join-Path $invocationRoot 'parsed.json'
        $output = if (Test-Path -LiteralPath $parsedPath -PathType Leaf) {
            Get-Content -LiteralPath $parsedPath -Raw | ConvertFrom-Json -Depth 100
        } else {
            $baseOutput | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100
        }
        $case = @($cases.cases | Where-Object case_id -eq $invocation.case_id)[0]
        $entry = $exposure.cases.PSObject.Properties[$invocation.case_id].Value
        $output.case_id = $invocation.case_id
        $output.variant = $invocation.variant
        $output.host = $invocation.host
        $output.host_session_id = "fixture-session-$($invocation.invocation_id)"
        $output.model = 'fixture-model'
        $output.current_truth_revision = $entry.current_truth_revision
        $output.memory_exposure_handles = if ($invocation.variant -eq 'control' -or $invocation.invocation_role -eq 'source_write') { [object[]]::new(0) } else { @($entry.treatment_handles) }
        if ($invocation.variant -eq 'control') {
            $output.memory_used_handles = [object[]]::new(0)
            $output.tool_calls = [object[]]::new(0)
        }
        $rawPath = Join-Path $invocationRoot 'raw.stdout'
        [IO.File]::WriteAllText($rawPath, ($output | ConvertTo-Json -Depth 100), [Text.UTF8Encoding]::new($false))
        Write-JsonFile $parsedPath $output
        $stderrPath = Join-Path $invocationRoot 'raw.stderr'
        [IO.File]::WriteAllText($stderrPath, '', [Text.UTF8Encoding]::new($false))
        $process = [pscustomobject][ordered]@{
            schema_version='eliot-cognitive-process-projection-v1';run_id='fixture-run'
            call_id=$invocation.invocation_id;call_number=$callNumber;host=$invocation.host;model='fixture-model'
            launcher_attested_in_job=$true;launcher_binary_stable=$true;launcher_matches_execution_seal=$true
            provider_attested_in_job=$true;provider_binary_stable=$true;provider_matches_execution_seal=$true
            provider_bundle_stable=$true;provider_bundle_matches_execution_seal=$true;provider_bundle_mutation_attempted=$false
            launcher_pid=1;job_object_containment='fixture';exit_code=0;timed_out=$false;latency_ms=1
            stdout_sha256=Get-FileSha256 $rawPath;stderr_sha256=Get-FileSha256 $stderrPath
        }
        Write-JsonFile (Join-Path $invocationRoot 'process.json') $process
        if (-not (Test-Path -LiteralPath (Join-Path $invocationRoot 'verification.json'))) {
            Write-JsonFile (Join-Path $invocationRoot 'verification.json') ([pscustomobject]@{
                schema_version='eliot-cognitive-local-verification-v1';case_id=$invocation.case_id
                invocation_id=$invocation.invocation_id;passed=$true;classification='AuditFindingCandidate'
                disposition='accepted_as_candidate_pending_governor_disposition';truth_promoted=$false
            })
        }
        $candidateReceipt = if ($invocation.invocation_role -eq 'source_write' -and $null -ne $output.candidate_write_receipt) {
            [pscustomobject][ordered]@{receipt_id=[string]$output.candidate_write_receipt.receipt_id;write_id=[string]$output.candidate_write_receipt.write_id}
        } else { $null }
        $terminal = [pscustomobject][ordered]@{
            call_id=$invocation.invocation_id;call_number=$callNumber;status='succeeded'
            process_sha256=Get-JsonSha256 $process
            stdout_sha256=Get-FileSha256 $rawPath
            stderr_sha256=Get-FileSha256 $stderrPath
            provider_output_sha256=Get-CanonicalJsonSha256 $output
            candidate_receipt=$candidateReceipt
            raw_verifier_receipts=@([pscustomobject]@{receipt_id="raw-$callNumber";write_id="raw-$callNumber"})
            no_redispatch=$true
        }
        $attemptReceipt = [pscustomobject][ordered]@{receipt_id="attempt-$callNumber";write_id="attempt-$callNumber"}
        $terminalReceipt = [pscustomobject][ordered]@{receipt_id="terminal-$callNumber";write_id="terminal-$callNumber"}
        $attemptRecords.Add([pscustomobject][ordered]@{canonical_receipt=$attemptReceipt;receipt_body=$attempt})
        $terminalRecords.Add([pscustomobject][ordered]@{canonical_receipt=$terminalReceipt;receipt_body=$terminal})
        Write-JsonFile (Join-Path $invocationRoot 'terminal.json') ([pscustomobject][ordered]@{
            terminal=$terminal;canonical_receipt=$terminalReceipt;replay=$false
        })
    }
    Write-JsonFile (Join-Path $Root 'provider-free-cognitive-status.json') ([pscustomobject][ordered]@{
        complete=$false
        contract=[pscustomobject]@{run_id='fixture-run';source_commit=('1' * 40);policy_snapshot_id=('2' * 64)}
        canonical_case_dispositions=@()
        contract_receipt=[pscustomobject]@{receipt_id='contract';write_id='contract'}
        attempts=@($attemptRecords)
        terminals=@($terminalRecords)
        provider_calls_consumed=16
        next_call=17
        stopped_no_redispatch=$false
    })
}

function Invoke-Disposition([string]$Root, [string]$Exposure, [string]$Scenario, [string]$Log, [string]$FailurePoint = 'none') {
    $oldScenario = $env:ELIOT_M6_FAKE_SCENARIO
    $oldLog = $env:ELIOT_M6_FAKE_CALL_LOG
    $oldState = $env:ELIOT_M6_FAKE_STATE
    $oldSourceOne = $env:ELIOT_M6_SOURCE_ONE
    $oldSourceTwo = $env:ELIOT_M6_SOURCE_TWO
    $oldBindingOne = $env:ELIOT_M6_BINDING_ONE
    $oldBindingTwo = $env:ELIOT_M6_BINDING_TWO
    try {
        $env:ELIOT_M6_FAKE_SCENARIO = $Scenario
        $env:ELIOT_M6_FAKE_CALL_LOG = $Log
        $env:ELIOT_M6_FAKE_STATE = Join-Path $Root 'fake-canonical-state.json'
        $env:ELIOT_M6_SOURCE_ONE = [string](Get-Content -LiteralPath (Join-Path $Root 'invocations\LC-01-source-opencode\parsed.json') -Raw | ConvertFrom-Json -Depth 100).candidate_write_receipt.write_id
        $env:ELIOT_M6_SOURCE_TWO = [string](Get-Content -LiteralPath (Join-Path $Root 'invocations\LC-02-source-antigravity\parsed.json') -Raw | ConvertFrom-Json -Depth 100).candidate_write_receipt.write_id
        $sealedPlan = Get-Content -LiteralPath (Join-Path $Root 'plan.json') -Raw | ConvertFrom-Json -Depth 100
        $env:ELIOT_M6_BINDING_ONE = (@($sealedPlan.invocations | Where-Object invocation_id -eq 'LC-01-source-opencode')[0].candidate_body | ConvertTo-Json -Compress -Depth 100)
        $env:ELIOT_M6_BINDING_TWO = (@($sealedPlan.invocations | Where-Object invocation_id -eq 'LC-02-source-antigravity')[0].candidate_body | ConvertTo-Json -Compress -Depth 100)
        $parameters = @{
            OutputRoot=$Root;ProjectId=$projectId;TaskId=$taskId;DispositionReciprocal=$true
            ExposureMap=$Exposure;OpenCodeModel='fixture-model';AntigravityModel='fixture-model'
            EliotExe=$harness;ProviderFreeTestMode=$true
            ProviderFreeFailurePoint=$FailurePoint
        }
        return (& $harness @parameters) | ConvertFrom-Json -Depth 100
    }
    finally {
        $env:ELIOT_M6_FAKE_SCENARIO = $oldScenario
        $env:ELIOT_M6_FAKE_CALL_LOG = $oldLog
        $env:ELIOT_M6_FAKE_STATE = $oldState
        $env:ELIOT_M6_SOURCE_ONE = $oldSourceOne
        $env:ELIOT_M6_SOURCE_TWO = $oldSourceTwo
        $env:ELIOT_M6_BINDING_ONE = $oldBindingOne
        $env:ELIOT_M6_BINDING_TWO = $oldBindingTwo
    }
}

function Count-LoggedTool([string]$Log, [string]$Tool) {
    if (-not (Test-Path -LiteralPath $Log)) { return 0 }
    return @((Get-Content -LiteralPath $Log | ForEach-Object { $_ | ConvertFrom-Json }) | Where-Object tool -eq $Tool).Count
}

$result = $null
try {
    New-Item -ItemType Directory -Force $temp | Out-Null
    $selfTestRoot = Join-Path $temp 'self-test'
    $selfTest = (& $harness -OutputRoot $selfTestRoot -ProjectId $projectId -TaskId $taskId -SelfTest -ProviderFreeTestMode -EliotExe $harness) | ConvertFrom-Json -Depth 100
    if (-not $selfTest.passed -or $selfTest.provider_calls -ne 0) {
        throw "provider-free self-test failed: $($selfTest | ConvertTo-Json -Compress -Depth 30)"
    }
    foreach ($requiredCheck in @(
        'invocation_to_call_mapping_exact','per_call_capability_control_environment_exact',
        'tree_hash_cloud_tag_classification_exact','tree_hash_real_junction_rejected',
        'provider_free_exact_contract_builder_all18','pre_gate_requires_exact_fresh_16_chain',
        'positive_complete_canonical_18_chain'
    )) {
        if (@($selfTest.checks | Where-Object { $_.name -ceq $requiredCheck -and $_.passed }).Count -ne 1) {
            throw "provider-free self-test omitted required canonical check $requiredCheck"
        }
    }

    $dryRunRoot = Join-Path $temp 'dry-run'
    $dryRun = (& $harness -OutputRoot $dryRunRoot -ProjectId $projectId -TaskId $taskId -ProviderFreeTestMode -EliotExe $harness) | ConvertFrom-Json -Depth 100
    if ($dryRun.provider_calls_made -ne 0 -or $dryRun.estimated_provider_calls -ne 18 -or
        $dryRun.allocation.opencode -ne 9 -or $dryRun.allocation.antigravity -ne 9 -or
        $dryRun.allocation.controls -ne 4 -or $dryRun.allocation.reciprocal_source_writes -ne 2) {
        throw "dry-run invariants failed: $($dryRun | ConvertTo-Json -Compress -Depth 20)"
    }
    if ($dryRun.confirmation_token -cne 'CONFIRM-18-BOUNDED-PROVIDER-CALLS') {
        throw 'dry-run confirmation token drifted'
    }
    $harnessText = Get-Content -LiteralPath $harness -Raw
    foreach ($requiredRoute in @(
        "'host','cognitive-seal'","'host','cognitive-run'","'host','cognitive-status'",'provider_executable','provider_executable_sha256','instance_name',
        'expected_truth_revision','expected_exposure_handles','expected_provider_bundle_sha256','timeout_seconds','output_root','cognitive-provider-authority','Get-ReconciledCanonicalInvocation','else { Get-AntigravityAgentManifestPath }'
    )) {
        if (-not $harnessText.Contains($requiredRoute, [StringComparison]::Ordinal)) {
            throw "canonical harness route is missing $requiredRoute"
        }
    }
    if ($harnessText.Contains('function Invoke-HostCall', [StringComparison]::Ordinal) -or
        $harnessText.Contains('consumes_provider_call_budget', [StringComparison]::Ordinal)) {
        throw 'legacy direct provider/manual attempt route remains in the canonical harness'
    }

    $validRoot = Join-Path $temp 'reciprocal-valid'
    New-Item -ItemType Directory -Force $validRoot | Out-Null
    $validExposure = New-FixtureExposure $validRoot
    New-SourceArtifacts $validRoot
    Remove-Item -LiteralPath (Join-Path $validRoot 'invocations\LC-01-source-opencode\terminal.json') -Force
    $validLog = Join-Path $validRoot 'mcp-calls.ndjson'
    $disposed = Invoke-Disposition $validRoot $validExposure 'valid' $validLog
    $reconstructedTerminal = Get-Content -LiteralPath (Join-Path $validRoot 'invocations\LC-01-source-opencode\terminal.json') -Raw | ConvertFrom-Json -Depth 100
    $statusReadCount = @(Get-Content -LiteralPath (Join-Path $validRoot 'provider-free-status-reads.ndjson')).Count
    if ($disposed.status -ne 'VERIFIED_ADMITTED' -or @($disposed.flows).Count -ne 2 -or
        (Count-LoggedTool $validLog 'eliot_operator_command') -ne 2 -or
        $reconstructedTerminal.reconstructed_from_canonical_status -ne $true -or $statusReadCount -ne 19 -or
        -not (Test-Path -LiteralPath (Join-Path $validRoot 'reciprocal-disposition-map.json')) -or
        -not (Test-Path -LiteralPath (Join-Path $validRoot 'reciprocal-seal.json'))) {
        throw 'valid reciprocal fixture did not produce two sealed canonical admissions'
    }
    $replayed = Invoke-Disposition $validRoot $validExposure 'valid' $validLog
    if (-not $replayed.replay -or (Count-LoggedTool $validLog 'eliot_operator_command') -ne 2) {
        throw 'reciprocal replay was not live-revalidated without a new operator mutation'
    }

    $unlockRoot = Join-Path $temp 'fake-client-provider-unlock'
    New-Item -ItemType Directory -Force $unlockRoot | Out-Null
    $unlockExposure = New-FixtureExposure $unlockRoot
    $unlockLog = Join-Path $unlockRoot 'mcp-calls.ndjson'
    $oldLog = $env:ELIOT_M6_FAKE_CALL_LOG
    $fakeUnlockBlocked = $false
    try {
        $env:ELIOT_M6_FAKE_CALL_LOG = $unlockLog
        $unlockParameters = @{
            OutputRoot=$unlockRoot;ProjectId=$projectId;TaskId=$taskId;ProviderFreeTestMode=$true
            ExecuteProviders=$true;Confirm='CONFIRM-18-BOUNDED-PROVIDER-CALLS';ExposureMap=$unlockExposure
            OpenCodeModel='fixture-model';AntigravityModel='fixture-model';EliotExe=$harness
        }
        & $harness @unlockParameters 2>$null | Out-Null
    }
    catch { $fakeUnlockBlocked = $_.Exception.Message -like '*can never execute providers*' }
    finally { $env:ELIOT_M6_FAKE_CALL_LOG = $oldLog }
    if (-not $fakeUnlockBlocked -or (Test-Path -LiteralPath $unlockLog) -or
        @(Get-ChildItem -LiteralPath $unlockRoot -Recurse -Filter attempt.json -ErrorAction SilentlyContinue).Count -ne 0) {
        throw 'provider-free fake client could unlock an attempt or provider path'
    }
    $clientParameterRejected = $false
    try {
        & $harness -OutputRoot (Join-Path $temp 'removed-client-parameter') -ProjectId $projectId -TaskId $taskId -ReferenceClient (Join-Path $PSScriptRoot 'fixtures\fake-mcp-reference-client.ps1') 2>$null | Out-Null
    }
    catch { $clientParameterRejected = $_.Exception.Message -like '*ReferenceClient*' }
    if (-not $clientParameterRejected) { throw 'production harness still accepted caller-controlled ReferenceClient' }
    $governorInjectionRejected = $false
    try {
        & $harness -OutputRoot (Join-Path $temp 'forged-governor') -ProjectId $projectId -TaskId $taskId -EliotExe $harness 2>$null | Out-Null
    }
    catch { $governorInjectionRejected = $_.Exception.Message -like '*production governor authority*' }
    if (-not $governorInjectionRejected) { throw 'production harness accepted a caller-controlled governor binary' }
    $configInjectionRejected = $false
    try {
        & $harness -OutputRoot (Join-Path $temp 'forged-config') -ProjectId $projectId -TaskId $taskId -GovernorConfig $harness 2>$null | Out-Null
    }
    catch { $configInjectionRejected = $_.Exception.Message -like '*canonical LocalAppData Eliot config*' }
    if (-not $configInjectionRejected) { throw 'production harness accepted a caller-controlled GovernorConfig' }

    $attemptsBeforeProductionReuse = @(Get-ChildItem -LiteralPath $validRoot -Recurse -Filter attempt.json -ErrorAction SilentlyContinue).Count
    foreach ($productionMode in @('DispositionReciprocal','VerifyArtifacts','ExecuteProviders')) {
        $productionReuseBlocked = $false
        $parameters = @{
            OutputRoot=$validRoot;ProjectId=$projectId;TaskId=$taskId;ExposureMap=$validExposure
            OpenCodeModel='fixture-model';AntigravityModel='fixture-model'
        }
        $parameters[$productionMode] = $true
        if ($productionMode -eq 'ExecuteProviders') {
            $parameters.Confirm = 'CONFIRM-18-BOUNDED-PROVIDER-CALLS'
        }
        try { & $harness @parameters 2>$null | Out-Null }
        catch {
            $productionReuseBlocked = $_.Exception.Message -like '*sealed execution authority*' -or
                $_.Exception.Message -like '*sealed run contract drifted*'
        }
        if (-not $productionReuseBlocked -or
            @(Get-ChildItem -LiteralPath $validRoot -Recurse -Filter attempt.json -ErrorAction SilentlyContinue).Count -ne $attemptsBeforeProductionReuse) {
            throw "test-mode sealed artifacts were reusable by production $productionMode"
        }
    }

    foreach ($scenario in @(
        'wrong_candidate','wrong_evidence','rejected'
    )) {
        $scenarioRoot = Join-Path $temp "reciprocal-$scenario"
        New-Item -ItemType Directory -Force $scenarioRoot | Out-Null
        $scenarioExposure = New-FixtureExposure $scenarioRoot
        New-SourceArtifacts $scenarioRoot
        $scenarioLog = Join-Path $scenarioRoot 'mcp-calls.ndjson'
        $blocked = $false
        try { Invoke-Disposition $scenarioRoot $scenarioExposure $scenario $scenarioLog | Out-Null }
        catch { $blocked = $true }
        if (-not $blocked -or (Count-LoggedTool $scenarioLog 'eliot_operator_command') -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $scenarioRoot 'reciprocal-disposition-map.json'))) {
            throw "$scenario reciprocal fixture was not blocked before operator/provider authority"
        }
    }

    $hashTamperRoot = Join-Path $temp 'reciprocal-canonical-hash-tamper'
    New-Item -ItemType Directory -Force $hashTamperRoot | Out-Null
    $hashTamperExposure = New-FixtureExposure $hashTamperRoot
    New-SourceArtifacts $hashTamperRoot
    Add-Content -LiteralPath (Join-Path $hashTamperRoot 'invocations\LC-01-source-opencode\raw.stdout') -Value ' ' -Encoding utf8
    $hashTamperLog = Join-Path $hashTamperRoot 'mcp-calls.ndjson'
    $hashTamperBlocked = $false
    try { Invoke-Disposition $hashTamperRoot $hashTamperExposure 'valid' $hashTamperLog | Out-Null }
    catch { $hashTamperBlocked = $true }
    if (-not $hashTamperBlocked -or (Count-LoggedTool $hashTamperLog 'eliot_operator_command') -ne 0) {
        throw 'canonical terminal did not block tampered raw provider output before operator authority'
    }

    foreach ($verificationFailure in @('missing','tampered')) {
        $verificationRoot = Join-Path $temp "reciprocal-verification-$verificationFailure"
        New-Item -ItemType Directory -Force $verificationRoot | Out-Null
        $verificationExposure = New-FixtureExposure $verificationRoot
        New-SourceArtifacts $verificationRoot
        $verificationPath = Join-Path $verificationRoot 'invocations\LC-01-source-opencode\verification.json'
        if ($verificationFailure -ceq 'missing') {
            Remove-Item -LiteralPath $verificationPath -Force
        } else {
            $forgedVerification = Get-Content -LiteralPath $verificationPath -Raw | ConvertFrom-Json -Depth 100
            $forgedVerification.checks[0].passed = $false
            Write-JsonFile $verificationPath $forgedVerification
        }
        $verificationLog = Join-Path $verificationRoot 'mcp-calls.ndjson'
        $verificationBlocked = $false
        try { Invoke-Disposition $verificationRoot $verificationExposure 'valid' $verificationLog | Out-Null }
        catch { $verificationBlocked = $true }
        if (-not $verificationBlocked -or
            (Count-LoggedTool $verificationLog 'eliot_operator_command') -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $verificationRoot 'reciprocal-disposition-map.json'))) {
            throw "$verificationFailure verification artifact was not blocked before operator authority"
        }
    }

    foreach ($scenario in @(
        'canonical_absent',
        'canonical_wrong_task',
        'wrong_revision_live',
        'canonical_wrong_candidate',
        'canonical_source_commit_mismatch',
        'canonical_missing_verifier',
        'canonical_unauthorized_role',
        'reject_live',
        'wrong_run_authority_live'
    )) {
        $liveLog = Join-Path $validRoot "mcp-live-$scenario.ndjson"
        $liveBlocked = $false
        try { Invoke-Disposition $validRoot $validExposure $scenario $liveLog | Out-Null }
        catch { $liveBlocked = $true }
        if (-not $liveBlocked -or (Count-LoggedTool $liveLog 'eliot_operator_command') -ne 0) {
            throw "$scenario was not blocked by canonical store disposition revalidation before target/provider execution"
        }
    }

    foreach ($scenario in @('wrong_operator_action','wrong_operator_receipt_id')) {
        $operatorRoot = Join-Path $temp "reciprocal-$scenario"
        New-Item -ItemType Directory -Force $operatorRoot | Out-Null
        $operatorExposure = New-FixtureExposure $operatorRoot
        New-SourceArtifacts $operatorRoot
        $operatorLog = Join-Path $operatorRoot 'mcp-calls.ndjson'
        $operatorBlocked = $false
        try { Invoke-Disposition $operatorRoot $operatorExposure $scenario $operatorLog | Out-Null }
        catch { $operatorBlocked = $true }
        if (-not $operatorBlocked -or (Test-Path -LiteralPath (Join-Path $operatorRoot 'reciprocal-disposition-map.json'))) {
            throw "$scenario forged operator receipt was not rejected"
        }
    }

    foreach ($failurePoint in @('after_flow1_promotion','after_promotions_before_map')) {
        $crashRoot = Join-Path $temp "reciprocal-crash-$failurePoint"
        New-Item -ItemType Directory -Force $crashRoot | Out-Null
        $crashExposure = New-FixtureExposure $crashRoot
        New-SourceArtifacts $crashRoot
        $crashLog = Join-Path $crashRoot 'mcp-calls.ndjson'
        $injected = $false
        try { Invoke-Disposition $crashRoot $crashExposure 'valid' $crashLog $failurePoint | Out-Null }
        catch { $injected = $_.Exception.Message -like '*provider-free injected crash*' }
        if (-not $injected -or (Test-Path -LiteralPath (Join-Path $crashRoot 'reciprocal-disposition-map.json'))) {
            throw "$failurePoint did not interrupt before reciprocal map/seal publication"
        }
        $recovered = Invoke-Disposition $crashRoot $crashExposure 'valid' $crashLog
        $fakeState = Get-Content -LiteralPath (Join-Path $crashRoot 'fake-canonical-state.json') -Raw | ConvertFrom-Json
        if ($recovered.status -ne 'VERIFIED_ADMITTED' -or @($recovered.flows).Count -ne 2 -or
            @($fakeState.promoted | Sort-Object -Unique).Count -ne 2 -or @($fakeState.promoted).Count -ne 2 -or
            -not (Test-Path -LiteralPath (Join-Path $crashRoot 'reciprocal-seal.json'))) {
            throw "$failurePoint did not reconcile exact prior writes without duplicates"
        }
    }

    $partialRoot = Join-Path $temp 'reciprocal-partial'
    New-Item -ItemType Directory -Force $partialRoot | Out-Null
    $partialExposure = New-FixtureExposure $partialRoot
    New-SourceArtifacts $partialRoot -Partial
    $partialLog = Join-Path $partialRoot 'mcp-calls.ndjson'
    $partialBlocked = $false
    try { Invoke-Disposition $partialRoot $partialExposure 'valid' $partialLog | Out-Null }
    catch { $partialBlocked = $true }
    if (-not $partialBlocked -or (Count-LoggedTool $partialLog 'eliot_operator_command') -ne 0) {
        throw 'partial reciprocal fixture was not blocked before operator/provider authority'
    }

    $staleRoot = Join-Path $temp 'reciprocal-stale'
    New-Item -ItemType Directory -Force $staleRoot | Out-Null
    $staleExposure = New-FixtureExposure $staleRoot
    New-SourceArtifacts $staleRoot
    $staleLog = Join-Path $staleRoot 'mcp-calls.ndjson'
    $staleBlocked = $false
    try { Invoke-Disposition $staleRoot $staleExposure 'stale' $staleLog | Out-Null }
    catch { $staleBlocked = $true }
    if (-not $staleBlocked -or (Test-Path -LiteralPath (Join-Path $staleRoot 'reciprocal-disposition-map.json'))) {
        throw 'stale reciprocal canonical readback was not blocked before target/provider execution'
    }

    $partialVerifyBlocked = $false
    $oldScenario = $env:ELIOT_M6_FAKE_SCENARIO
    try {
        $env:ELIOT_M6_FAKE_SCENARIO = 'valid'
        $verifyParameters = @{
            OutputRoot=$validRoot;ProjectId=$projectId;TaskId=$taskId;VerifyArtifacts=$true
            ExposureMap=$validExposure;OpenCodeModel='fixture-model';AntigravityModel='fixture-model'
            EliotExe=$harness;ProviderFreeTestMode=$true
        }
        & $harness @verifyParameters 2>$null | Out-Null
    }
    catch { $partialVerifyBlocked = $true }
    finally { $env:ELIOT_M6_FAKE_SCENARIO = $oldScenario }
    if (-not $partialVerifyBlocked) {
        throw 'VerifyArtifacts did not fail closed when fewer than 18 complete invocation chains existed'
    }

    $operatorCallsBeforeTamper = Count-LoggedTool $validLog 'eliot_operator_command'
    Add-Content -LiteralPath (Join-Path $validRoot 'invocations\LC-01-source-opencode\parsed.json') -Value ' ' -Encoding utf8
    $tamperBlocked = $false
    try { Invoke-Disposition $validRoot $validExposure 'valid' $validLog | Out-Null }
    catch { $tamperBlocked = $true }
    if (-not $tamperBlocked -or (Count-LoggedTool $validLog 'eliot_operator_command') -ne $operatorCallsBeforeTamper) {
        throw 'tampered reciprocal artifact was not blocked by the immutable seal before authority calls'
    }

    $result = [pscustomobject][ordered]@{
        schema_version = 'eliot-cognitive-provider-free-test-run-v1'
        provider_calls = 0
        self_test_passed = $true
        dry_run_passed = $true
        parser_verified = $true
        verifier_verified = $true
        invocation_to_call_mapping_exact = $true
        tree_hash_cloud_tag_classification_exact = $true
        tree_hash_real_junction_rejected = $true
        positive_complete_canonical_18_chain = $true
        canonical_seal_runner_status_routes_only = $true
        preflight_logic_verified = $true
        confirmation_token_sealed = $true
        canonical_reciprocal_valid = $true
        fresh_canonical_status_per_call_verified = $true
        terminal_response_loss_reconstructed_from_status = $true
        canonical_raw_hash_tamper_blocked_before_operator = $true
        source_body_hash_matches_serde_json_canonical_order = $true
        canonical_reciprocal_replay_live_revalidated = $true
        fake_client_cannot_unlock_provider_or_attempt = $true
        caller_controlled_reference_client_parameter_removed = $true
        caller_controlled_governor_and_config_rejected = $true
        test_mode_seals_rejected_by_all_production_modes = $true
        forged_candidate_and_evidence_rejected_blocked_without_operator = $true
        stale_revision_wrong_run_authority_and_reject_live_blocked = $true
        operator_action_and_receipt_bindings_fail_closed = $true
        crash_after_flow1_and_before_map_reconciled_without_duplicates = $true
        partial_blocked_without_operator = $true
        partial_verify_nonzero = $true
        stale_readback_blocked_without_map = $true
        tampered_seal_blocked_without_operator = $true
        exact_call_budget = 18
        temp_root_removed = $false
    }
}
finally {
    if (Test-Path -LiteralPath $temp) {
        Remove-Item -LiteralPath $temp -Recurse -Force
    }
}
$result.temp_root_removed = -not (Test-Path -LiteralPath $temp)
$result | ConvertTo-Json -Compress
