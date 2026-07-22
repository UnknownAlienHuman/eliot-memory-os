[CmdletBinding()]
param(
    [string]$EliotExe,
    [string]$Config,
    [string]$Profile,
    [string]$ToolName,
    [string]$ToolArgumentsJson = '{}',
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
$arguments = $ToolArgumentsJson | ConvertFrom-Json -Depth 100
$scenario = if ($env:ELIOT_M6_FAKE_SCENARIO) { $env:ELIOT_M6_FAKE_SCENARIO } else { 'valid' }
$projectId = '11111111-1111-4111-8111-111111111111'
$taskId = '22222222-2222-4222-8222-222222222222'
$wrongTaskId = '99999999-9999-4999-8999-999999999999'
$sourceOne = if ($env:ELIOT_M6_SOURCE_ONE) { $env:ELIOT_M6_SOURCE_ONE } else { '018fdb63-42f1-7d85-a952-0f8f9169d07c' }
$sourceTwo = if ($env:ELIOT_M6_SOURCE_TWO) { $env:ELIOT_M6_SOURCE_TWO } else { '028fdb63-42f1-7d85-a952-0f8f9169d07d' }
$receiptOne = '038fdb63-42f1-57d5-a952-0f8f9169d07e'
$receiptTwo = '048fdb63-42f1-57d5-a952-0f8f9169d07f'
$sessionOne = '058fdb63-42f1-47d5-a952-0f8f9169d070'
$sessionTwo = '068fdb63-42f1-47d5-a952-0f8f9169d071'
$evidenceOne = @('native-health:passed','host-namespace:init-channel-closed','verifier:transport-split')
$evidenceTwo = @('sibling-render:passed','patched-discovery:failed','verifier:surface-split')

if ($env:ELIOT_M6_FAKE_CALL_LOG) {
    [pscustomobject]@{ profile=$Profile; tool=$ToolName; arguments=$arguments; scenario=$scenario } |
        ConvertTo-Json -Compress -Depth 100 |
        Add-Content -LiteralPath $env:ELIOT_M6_FAKE_CALL_LOG -Encoding utf8
}

function Source-Fields([string]$writeId) {
    $body = if ($writeId -eq $sourceOne -and $env:ELIOT_M6_BINDING_ONE) {
        $env:ELIOT_M6_BINDING_ONE | ConvertFrom-Json -Depth 100
    } elseif ($writeId -eq $sourceTwo -and $env:ELIOT_M6_BINDING_TWO) {
        $env:ELIOT_M6_BINDING_TWO | ConvertFrom-Json -Depth 100
    } else { $null }
    if ($writeId -eq $sourceOne) {
        return [pscustomobject]@{ evidence=$evidenceOne; revision=41; receipt=$receiptOne; session=$sessionOne; case='LC-01'; flow='opencode-to-antigravity'; truth_revision='fixture-revision-lc-01'; statement=if($body){$body.statement}else{'Native health and host transport failure are distinct observations.'}; body=$body }
    }
    return [pscustomobject]@{ evidence=$evidenceTwo; revision=42; receipt=$receiptTwo; session=$sessionTwo; case='LC-02'; flow='antigravity-to-opencode'; truth_revision='fixture-revision-lc-02'; statement=if($body){$body.statement}else{'Native health and host transport failure are distinct observations.'}; body=$body }
}

function Idempotency-Key([string]$writeId) {
    $flow = if ($writeId -eq $sourceOne) { 'opencode-to-antigravity' } else { 'antigravity-to-opencode' }
    $revision = if ($writeId -eq $sourceOne) { '41' } else { '42' }
    $evidence = (Source-Fields $writeId).evidence | Sort-Object
    $material = @('cognitive-contract-v2',$projectId,$taskId,$flow,$writeId,$revision,($evidence -join ',')) -join '|'
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($material))).ToLowerInvariant()
    return 'm6-reciprocal-promote-' + $hash.Substring(0,40)
}

function Source-Binding([string]$writeId) {
    $fields = Source-Fields $writeId
    if ($null -ne $fields.body) {
        return [pscustomobject]@{
            topic=$fields.body.topic;freshness_rule=$fields.body.freshness_rule
            where_applicable=@($fields.body.where_applicable);where_not_applicable=@($fields.body.where_not_applicable)
            negative_constraints=@($fields.body.negative_constraints)
        }
    }
    $material = @('cognitive-contract-v2',$projectId,$taskId,$fields.case,$fields.flow,$fields.truth_revision) -join '|'
    $nonce = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($material))).ToLowerInvariant()
    return [pscustomobject]@{
        topic="m6-reciprocal:$($fields.flow):$nonce"
        freshness_rule="m6-sealed-source-nonce:$nonce;current-truth:$($fields.truth_revision)"
        where_applicable=@("case:$($fields.case)","flow:$($fields.flow)","source-nonce:$nonce")
        where_not_applicable=@('different-project-task-flow-or-source-nonce')
        negative_constraints=@('candidate-only-until-human-operator-review','no-provider-or-self-promotion')
    }
}

$statePath = $env:ELIOT_M6_FAKE_STATE
$state = if ($statePath -and (Test-Path -LiteralPath $statePath -PathType Leaf)) {
    Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -Depth 20
} else { [pscustomobject]@{ promoted=@() } }

function Test-Promoted([string]$writeId) { return $writeId -in @($state.promoted) }
function Set-Promoted([string]$writeId) {
    if (-not $statePath) { return }
    if ($writeId -notin @($state.promoted)) { $state.promoted = @($state.promoted) + $writeId }
    $state | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $statePath -Encoding utf8
    if (@($state.promoted | Sort-Object -Unique).Count -eq 2) {
        $statusPath = Join-Path (Split-Path -Parent $statePath) 'provider-free-cognitive-status.json'
        if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
            $status = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json -Depth 100
            $status.contract | Add-Member -NotePropertyName source_commit -NotePropertyValue ('1' * 40) -Force
            $status.contract | Add-Member -NotePropertyName policy_snapshot_id -NotePropertyValue ('2' * 64) -Force
            $status | Add-Member -NotePropertyName canonical_case_dispositions -NotePropertyValue @(
                [pscustomobject]@{
                    case_id='LC-01';task_id=$taskId;candidate_result_id=$sourceOne;disposition_id=$receiptOne
                    disposition_kind='accepted';actor_session_id=$sessionOne;actor_role_lease_id=$env:ELIOT_ROLE_LEASE_ID
                    evidence_refs=$evidenceOne;verifier_refs=@('verifier:fixture-one');write_receipt_id=$receiptOne
                    task_revision_before=49;task_revision_after=50;source_commit=('1' * 40)
                    policy_snapshot_id=('2' * 64);resolved_from_store=$true
                },
                [pscustomobject]@{
                    case_id='LC-02';task_id=$taskId;candidate_result_id=$sourceTwo;disposition_id=$receiptTwo
                    disposition_kind='accepted';actor_session_id=$sessionTwo;actor_role_lease_id=$env:ELIOT_ROLE_LEASE_ID
                    evidence_refs=$evidenceTwo;verifier_refs=@('verifier:fixture-two');write_receipt_id=$receiptTwo
                    task_revision_before=50;task_revision_after=51;source_commit=('1' * 40)
                    policy_snapshot_id=('2' * 64);resolved_from_store=$true
                }
            ) -Force
            $status | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $statusPath -Encoding utf8
        }
    }
}

$toolCall = switch ($ToolName) {
    'eliot_task_state' {
        [pscustomobject]@{ status='current'; revision_fence=7; task_contract=[pscustomobject]@{
            project_id=$projectId; task_id=$taskId; memory_revision=7
        }}
    }
    'eliot_current_state' {
        $secondStatus = if ($scenario -eq 'rejected') { 'rejected' } else { 'candidate' }
        $weak = [System.Collections.Generic.List[object]]::new()
        if (-not (Test-Promoted $sourceOne)) { $weak.Add([pscustomobject]@{claim_id=$sourceOne;status='candidate';memory_revision=41}) }
        if (-not (Test-Promoted $sourceTwo)) { $weak.Add([pscustomobject]@{claim_id=$sourceTwo;status=$secondStatus;memory_revision=42}) }
        [pscustomobject]@{
            project_id=$projectId
            weak_or_candidate=@($weak)
        }
    }
    'eliot_operator_command' {
        $writeId = ([string]$arguments.command.candidate_ref).Substring('claim:'.Length)
        $fields = Source-Fields $writeId
        $state | Add-Member -NotePropertyName actor_role_lease_id -NotePropertyValue $env:ELIOT_ROLE_LEASE_ID -Force
        Set-Promoted $writeId
        $resultTask = if ($scenario -eq 'wrong_operator_task') { $wrongTaskId } else { $taskId }
        $resultAction = if ($scenario -eq 'wrong_operator_action') { 'archive_memory' } else { 'review_candidate' }
        $resultRevision = if ($scenario -eq 'wrong_operator_revision') { 999 } else { 7 }
        $resultReceiptId = if ($scenario -eq 'wrong_operator_receipt_id') { 'not-a-uuid' } else { $fields.receipt }
        [pscustomobject]@{
            accepted=$true; executed=$true; outcome='candidate_promoted_verified'; revision=$resultRevision
            task_id=$resultTask;action=$resultAction
            canonical_receipt=[pscustomobject]@{receipt_id=$resultReceiptId;write_id=$fields.receipt}
        }
    }
    'eliot_fetch_l2' {
        $handles = @($arguments.handles)
        $writeId = if ($sourceOne -in $handles) { $sourceOne } else { $sourceTwo }
        $fields = Source-Fields $writeId
        $binding = Source-Binding $writeId
        $promoted = Test-Promoted $writeId
        if ($handles.Count -eq 1 -and -not $promoted) {
            $claimId = if ($scenario -in @('forged','wrong_candidate') -and $writeId -eq $sourceTwo) { $sourceOne } else { $writeId }
            $claimTask = if ($scenario -eq 'wrong_task' -and $writeId -eq $sourceTwo) { $wrongTaskId } else { $taskId }
            $project = if ($scenario -eq 'wrong_project' -and $writeId -eq $sourceTwo) { $wrongTaskId } else { $projectId }
            $provenance = if ($scenario -eq 'wrong_evidence' -and $writeId -eq $sourceTwo) { @('forged:evidence') } else { @($fields.evidence) }
            $statement = if ($scenario -eq 'wrong_statement' -and $writeId -eq $sourceTwo) { 'unrelated candidate statement' } else { $fields.statement }
            $topic = if ($scenario -eq 'wrong_topic' -and $writeId -eq $sourceTwo) { 'unrelated-topic' } else { $binding.topic }
            $profile = if ($scenario -eq 'wrong_profile' -and $writeId -eq $sourceTwo) { 'external_auditor' } else { 'cognitive_child' }
            $constraints = if ($scenario -eq 'wrong_constraints' -and $writeId -eq $sourceTwo) { @('forged-constraint') } else { @($binding.negative_constraints) }
            [pscustomobject]@{
                project_id=$project; at_revision=42; verification_runs=@()
                claims=@([pscustomobject]@{
                    claim_id=$claimId; statement=$statement; status='candidate'
                    payload=[pscustomobject]@{
                        task_id=$claimTask;candidate_only=$true;profile=$profile;statement=$statement
                        topic=$topic;freshness_rule=$binding.freshness_rule;provenance_refs=$provenance
                        where_applicable=@($binding.where_applicable);where_not_applicable=@($binding.where_not_applicable)
                        negative_constraints=$constraints
                    }
                })
            }
        } else {
            $sourceRevision = if ($scenario -in @('stale','wrong_revision_live') -and $writeId -eq $sourceTwo) { 999 } else { $fields.revision }
            $idempotency = Idempotency-Key $writeId
            $readProject = if ($scenario -eq 'wrong_project_live' -and $writeId -eq $sourceOne) { $wrongTaskId } else { $projectId }
            $readClaimId = if ($scenario -eq 'wrong_candidate_live' -and $writeId -eq $sourceOne) { $sourceTwo } else { $writeId }
            $readStatus = if ($scenario -eq 'reject_live' -and $writeId -eq $sourceOne) { 'candidate' } else { 'verified' }
            $sourceWrite = if ($scenario -eq 'wrong_write_live' -and $writeId -eq $sourceOne) { $sourceTwo } else { $writeId }
            $readEvidence = if ($scenario -eq 'wrong_evidence_live' -and $writeId -eq $sourceOne) { @('forged:evidence') } else { @($fields.evidence) }
            $verificationId = if ($scenario -eq 'wrong_receipt_live' -and $writeId -eq $sourceOne) { $receiptTwo } else { $fields.receipt }
            $candidateRef = if ($scenario -eq 'wrong_candidate_ref_live' -and $writeId -eq $sourceOne) { "claim:$sourceTwo" } else { "claim:$writeId" }
            $dispositionSession = if ($scenario -eq 'wrong_disposition_session_live' -and $writeId -eq $sourceOne) { $sessionTwo } else { $fields.session }
            $runCandidateRef = if ($scenario -eq 'wrong_run_candidate_ref_live' -and $writeId -eq $sourceOne) { "claim:$sourceTwo" } else { "claim:$writeId" }
            $runRevision = if ($scenario -eq 'wrong_run_revision_live' -and $writeId -eq $sourceOne) { 999 } else { $fields.revision }
            $runAuthority = if ($scenario -eq 'wrong_run_authority_live' -and $writeId -eq $sourceOne) { 'provider' } else { 'human_operator' }
            $runDisposition = if ($scenario -eq 'wrong_run_disposition_live' -and $writeId -eq $sourceOne) { 'reject' } else { 'promote' }
            [pscustomobject]@{
                project_id=$readProject; at_revision=50
                claims=@([pscustomobject]@{
                    claim_id=$readClaimId; statement=$fields.statement; status=$readStatus
                    payload=[pscustomobject]@{
                        task_id=$taskId;candidate_only=$false;admitted_by_operator=$true;profile='cognitive_child';statement=$fields.statement
                        topic=$binding.topic;freshness_rule=$binding.freshness_rule;provenance_refs=@($fields.evidence)
                        where_applicable=@($binding.where_applicable);where_not_applicable=@($binding.where_not_applicable)
                        negative_constraints=@($binding.negative_constraints)
                        operator_candidate_disposition=[pscustomobject]@{
                            disposition=if ($scenario -eq 'reject_live') {'reject'} else {'promote'};source_write_id=$sourceWrite;task_id=$taskId
                            source_memory_revision=$sourceRevision;idempotency_key=$idempotency
                            evidence_refs=$readEvidence;source_provenance_refs=@($fields.evidence)
                            candidate_ref=$candidateRef;operator_session_id=$dispositionSession
                            actor_role_lease_id=$state.actor_role_lease_id
                            actor_controller_lease_id=$null
                        }
                    }
                })
                verification_runs=@([pscustomobject]@{
                    verification_id=$verificationId;result='passed';summary='fixture operator admission'
                    payload=[pscustomobject]@{
                        candidate_original_write_id=$writeId;project_id=$projectId;task_id=$taskId
                        idempotency_key=$idempotency;operator_session_id=$fields.session
                        actor_role_lease_id=$state.actor_role_lease_id
                        actor_controller_lease_id=$null
                        evidence_refs=@($fields.evidence);source_provenance_refs=@($fields.evidence)
                        authority=$runAuthority;candidate_ref=$runCandidateRef
                        candidate_original_revision=$runRevision;disposition=$runDisposition
                    }
                })
            }
        }
    }
    default { throw "unsupported fake MCP tool: $ToolName" }
}

$session = if ($ToolName -eq 'eliot_operator_command' -and [string]$arguments.command.candidate_ref -like "*$sourceTwo") {
    $sessionTwo
} else { $sessionOne }

[pscustomobject][ordered]@{
    component='eliot_mcp_reference_client';status='passed';profile=$Profile
    server=[pscustomobject]@{name='fixture-eliot';version='test'}
    agent_session=[pscustomobject]@{agent_session_id=$session;access_profile=$Profile}
    tool_call=$toolCall;tool_call_error=$null
} | ConvertTo-Json -Depth 100
