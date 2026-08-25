[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifyScript = Join-Path $PSScriptRoot 'verify-acceptance-cycle.ps1'

function Fail([string]$Message) { throw "GEN-ACCEPTANCE-CYCLE: $Message" }
function Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Write-Utf8([string]$Path, [string]$Text) {
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8)
}

$sourceSpecs = @(
    [ordered]@{ path='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md'; role='paused-cell ledger'; anchors=@(@{ line=9; needle='### C0-12' }, @{ line=24; needle='### C0-13' }, @{ line=39; needle='### A-01 / A-03 / A-05' }, @{ line=52; needle='### G-03' }, @{ line=65; needle='### G-10' }) },
    [ordered]@{ path='docs/tasks/RECOVERY_PROGRAM_v1.md'; role='tracked recovery program §5.2'; anchors=@(@{ line=461; needle='### 5.2. ' }) },
    [ordered]@{ path='docs/ARCHITECTURE_CONTRACT.md'; role='repository architecture contract; W0 verifier input'; anchors=@(@{ line=1; needle='# Architecture authority' }, @{ line=10; needle='| Authority | Canonical file | Revision | SHA-256 |' }) },
    [ordered]@{ path='docs/normative/ELIOT_ARCHITECTURE.md'; role='repository normative Architecture projection; W0 verified'; anchors=@(@{ line=1; needle='# ELIOT Architecture' }, @{ line=4; needle='**Версия:** 4.5-draft' }) },
    [ordered]@{ path='docs/normative/ELIOT_IMPLEMENTATION.md'; role='repository normative Implementation projection; W0 verified'; anchors=@(@{ line=1; needle='# ELIOT Implementation' }, @{ line=4; needle='**Версия:** 0.29-draft' }) },
    [ordered]@{ path='docs/normative/INDEX.md'; role='repository normative index projection; W0 verified'; anchors=@(@{ line=1; needle='# ELIOT: предметный индекс' }) },
    [ordered]@{ path='docs/normative/README.md'; role='repository normative README projection; W0 verified'; anchors=@(@{ line=1; needle='# ELIOT: индекс документации' }) },
    [ordered]@{ path='docs/normative/PROJECTION_NOTICE.md'; role='repository normative projection notice; W0 verified'; anchors=@(@{ line=1; needle='# Normative projection notice' }, @{ line=3; needle='byte-for-byte projection' }) },
    [ordered]@{ path='docs/normative/projection-manifest.tsv'; role='repository normative projection manifest; W0 verifier input'; anchors=@(@{ line=1; needle="schema_version`teliot-normative-projection-v1" }, @{ line=3; needle="authority_status`tNOT_AUTHORITY" }) },
    [ordered]@{ path='scripts/verify-normative.ps1'; role='W0 normative verification chain'; anchors=@(@{ line=14; needle='$manifestPath' }, @{ line=128; needle='NORMATIVE_VERIFY: PASS' }) }
)

function Source-Bindings {
    $bindings = @()
    foreach ($spec in $sourceSpecs) {
        $path = [string]$spec.path
        if ([System.IO.Path]::IsPathRooted($path)) { Fail "source path is absolute: $path" }
        $full = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $path))
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Fail "source missing: $path" }
        $anchorBindings = @($spec.anchors | ForEach-Object { [ordered]@{ line=[int]$_.line; needle=[string]$_.needle } })
        $bindings += [ordered]@{ path=$path; role=[string]$spec.role; sha256=(Sha256 $full); anchors=$anchorBindings }
    }
    return @($bindings)
}

$nodes = @(
    [ordered]@{ id='C0-12'; criterion='Versioned, schema-bound security/disclosure/influence contract; fail-closed construction; provider-issued verifier, declassification, disclosure and selection evidence; Q-01 duplicate owner removed.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:9-22' },
    [ordered]@{ id='C0-13'; criterion='Canonical-byte/revision-bound evaluation contract; provider-issued independent evidence; closed verdict/outcome matrix; exact fence/source/artifact/proof-ceiling bindings.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:24-37' },
    [ordered]@{ id='A-01'; criterion='Admitted agent launch path with exact authority, freshness, integrity, taint, privacy, verifier, fence and effect checks; NARROW seals unit/scope/route; no raw launch bypass.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50' },
    [ordered]@{ id='A-03'; criterion='The A-03 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50' },
    [ordered]@{ id='A-05'; criterion='The A-05 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50' },
    [ordered]@{ id='G-03'; criterion='Owner-admitted TaskContract from TaskSelectionEvidence, WorkScope/project identity and source binding; verification bound to task revision/fence/artifact/freshness/proof ceiling; durable canonical lifecycle.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:52-63' },
    [ordered]@{ id='G-10'; criterion='RequestMeta-bound asynchronous blueprint/registry with verifier-bound fresh readiness, complete route fingerprint, resolved bindings and exact Cargo integration.'; ledger_anchor='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:65-76' }
)

$edges = @(
    [ordered]@{ id='E1'; from='C0-12'; to='C0-13'; dependency_class='proof/evidence'; directness='derived_provider_consumer_from_explicit_ledger_requirements'; statement='C0-13 cannot close independence and exact evidence bindings while canonical security/source-assurance evidence remains caller-mintable or duplicated.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:17-20','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:30-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27','docs/architecture/ELIOT_ARCHITECTURE.md:A5.5') },
    [ordered]@{ id='E2'; from='C0-13'; to='G-03'; dependency_class='proof/evidence'; directness='derived_acceptance_binding_not_runtime_call_edge'; statement='G-03 verification acceptance needs the independent verdict, revision/fence, artifact and proof-ceiling bindings owned by C0-13.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:30-37','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:56-63','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.9','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1') },
    [ordered]@{ id='E3'; from='G-03'; to='A-01'; dependency_class='product'; directness='ledger_explicit_cross_cell_prerequisite'; statement='The admitted launch cannot seal task, work unit, scope and revision if G-03 has not supplied owner-admitted TaskContract and task evidence.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:45-48','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:56-58','docs/tasks/RECOVERY_PROGRAM_v1.md:432-440','docs/architecture/ELIOT_IMPLEMENTATION.md:I1.8') },
    [ordered]@{ id='E4'; from='G-10'; to='A-01'; dependency_class='product'; directness='derived_route_readiness_prerequisite'; statement='A-01 NARROW launch decision needs registry-owned selected route, binding and readiness; G-10 lacks those provider-bound facts.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:47-48','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:69-74','docs/architecture/ELIOT_IMPLEMENTATION.md:I3.4','docs/architecture/ELIOT_IMPLEMENTATION.md:P.3') },
    [ordered]@{ id='E5'; from='A-01'; to='C0-13'; dependency_class='proof/evidence'; directness='derived_candidate_to_independent_verdict'; statement='A-01 may produce only candidate launch/provider results; C0-13 is the independent-verdict boundary required before acceptance.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:41-46','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.9') },
    [ordered]@{ id='E6'; from='A-03'; to='C0-13'; dependency_class='proof/evidence'; directness='derived_shared_trio_boundary'; statement='A-03 has no separate acceptance oracle; its result remains candidate evidence until C0-13 independent-verdict conditions hold.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1') },
    [ordered]@{ id='E7'; from='A-05'; to='C0-13'; dependency_class='proof/evidence'; directness='derived_shared_trio_boundary'; statement='A-05 has no separate acceptance oracle; its result remains candidate evidence until C0-13 independent-verdict conditions hold.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1') },
    [ordered]@{ id='E8'; from='G-10'; to='C0-12'; dependency_class='proof/evidence'; directness='derived_source_provenance_and_route_binding'; statement='G-10 readiness/provenance/route evidence must consume canonical security, source-assurance and disclosure semantics.'; evidence=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:70-73','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:17-20','docs/architecture/ELIOT_ARCHITECTURE.md:A12.4','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27') }
)

function Source-Summary([object[]]$sources) {
    return (($sources | ForEach-Object { "- $($_.path) :: $($_.sha256)" }) -join "`n")
}

function Inventory-Text([object[]]$sources) {
    $sourceSummary = Source-Summary $sources
    $nodeRows = ($nodes | ForEach-Object { "| ``$($_.id)`` | $($_.criterion) |" }) -join "`n"
    $edgeRows = ($edges | ForEach-Object { "| ``$($_.id)`` | ``$($_.from)`` → ``$($_.to)`` | $($_.dependency_class) | $($_.directness) |" }) -join "`n"
    $text = @'
# W1-03 — acceptance dependency cycle (content-bound evidence)

Authority: `EVIDENCE_ONLY`. This inventory is a static acceptance graph artifact; it is not a canonical `TerminalWorkUpdate`, product proof, runtime proof, or activation decision.

## Bound source bytes

$sourceSummary

## Repository provenance boundary

`docs/ARCHITECTURE_CONTRACT.md`, the repository `docs/normative/` projections, `docs/normative/projection-manifest.tsv`, and `scripts/verify-normative.ps1` are bound by repository-relative path, SHA-256, and lexical anchors. The W0 normative verifier enforces projection/contract hash equality; W1-03 does not independently reassert equality with an external canonical location and does not read one.

## Exact seven-cell graph

The graph contains exactly seven cells: `C0-12`, `C0-13`, `A-01`, `A-03`, `A-05`, `G-03`, and `G-10`.

| Node | Criterion |
|---|---|
$nodeRows

## Directed acceptance edges

Edges are provider → consumer acceptance dependencies, not runtime or Cargo call edges.

| ID | Edge | Class | Derivation |
|---|---|---|---|
$edgeRows

No A-01/A-03/A-05 ordering edge and no runtime cycle is asserted.

## SCC and concrete cut

The sole non-singleton SCC is exactly `{C0-13, G-03, A-01}` with witness cycle `C0-13 → G-03 → A-01 → C0-13`. `C0-12`, `A-03`, `A-05`, and `G-10` are singleton SCCs in this seven-cell internal graph.

The minimum vertex cut for that witness SCC is concretely size one. Equal cuts are `{A-01}`, `{C0-13}`, and `{G-03}`; selected cut is `{A-01}`. This is a graph result, not an activation decision.

## A-01 Recoverable Deviation proposal

Status: `PROPOSAL_ONLY_NOT_ACTIVATED`.

Only A-01's pre-execution admission boundary may return a typed `PLAN_GAP`/`UNAVAILABLE` candidate naming missing provider identities and the bound source digest set. It may not start a process, issue `DispatchPermit`, widen authority, mint verifier evidence, or emit `VERIFIED_COMPLETE`. A-03 and A-05 remain blocked for real execution. Root acceptance is required; no acceptance is recorded here.

Review requires independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate. Rollback revokes the proposal, restores normal admission, preserves negative evidence, and reruns the graph/trio checks.

Proof ceiling: static ledger/document graph only; no Cargo, runtime, provider, or canonical-result execution proof.

Reproduce:

```powershell
pwsh -NoProfile -File scripts/gen-acceptance-cycle.ps1
pwsh -NoProfile -File scripts/verify-acceptance-cycle.ps1
```
'@
    return $text.Replace('$sourceSummary', $sourceSummary).Replace('$nodeRows', $nodeRows).Replace('$edgeRows', $edgeRows)
}

function Get-DecisionText {
    return @'
# W1-03 proposal — A-01 Recoverable Deviation

Status: `PROPOSAL_ONLY_NOT_ACTIVATED`

Authority: `EVIDENCE_ONLY`. This proposal is not a canonical `TerminalWorkUpdate`, Product Proof, launch authority, or acceptance decision. Root acceptance is intentionally absent.

Owner: Luna-A / Integration Owner, subject to Root acceptance.
Reason: Break only the internal acceptance SCC at the A-01 launch consumer while provider evidence is unavailable; this is a proposal, not an acceptance.
Scope: A-01 pre-execution typed `PLAN_GAP`/`UNAVAILABLE` candidate only; A-03 and A-05 remain blocked.
Review condition: Independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate.
Rollback: Revoke this proposal, restore normal A-01 admission, retain negative evidence, and rerun graph/trio checks.

## Scope

The seven-cell graph has one concrete mixed product/proof SCC: `C0-13 → G-03 → A-01 → C0-13`. Its minimum vertex cut is size one, with equal cuts `{A-01}`, `{C0-13}`, and `{G-03}`. A-01 is the selected proposal cut because the ledger permits a typed-unavailable pre-execution boundary.

Only A-01 may return a typed `PLAN_GAP`/`UNAVAILABLE` candidate with missing provider identities and content-bound source digests. The proposal does not satisfy A-01 acceptance and does not apply to A-03 or A-05.

It may not start a process, issue `DispatchPermit`, widen Session/WorkScope/Task/route/fence/effect authority, fabricate readiness or verifier evidence, emit `VERIFIED_COMPLETE`, or authorize a later wave.

## Review and rollback

Review requires independently executed provider-issued P-03 and C0-06 evidence and the unchanged A-01/A-03/A-05 trio gate. Revoke the proposal, restore the normal A-01 admission predicate, retain typed-unavailable receipts as negative evidence, and rerun graph/trio checks. No canonical product state is created.

## Boundaries

No canonical Architecture/Implementation text, Rust source, Cargo graph, external provider, or authority contract is changed by this proposal. Proof ceiling remains static content-bound graph evidence.
'@
}

function Get-DecisionStatus([string]$Path) {
    $text = [IO.File]::ReadAllText($Path)
    if ($text -notmatch '(?m)^Status: `([^`]+)`') { throw 'Root decision status is missing' }
    return [string]$Matches[1]
}

function Build-Result([object[]]$sources, [string]$inventoryHash, [string]$decisionHash, [string]$decisionStatus) {
    $contractBinding = @($sources | Where-Object { $_.path -eq 'docs/ARCHITECTURE_CONTRACT.md' })[0]
    $manifestBinding = @($sources | Where-Object { $_.path -eq 'docs/normative/projection-manifest.tsv' })[0]
    $verifierBinding = @($sources | Where-Object { $_.path -eq 'scripts/verify-normative.ps1' })[0]
    $projectionPaths = @('docs/normative/ELIOT_ARCHITECTURE.md','docs/normative/ELIOT_IMPLEMENTATION.md','docs/normative/INDEX.md','docs/normative/README.md','docs/normative/PROJECTION_NOTICE.md')
    $projectionBindings = @($sources | Where-Object { $_.path -in $projectionPaths })
    $structured = [ordered]@{
        disposition='completed'
        artifacts=@(
            [ordered]@{ path='swarm/inventory/acceptance-cycle.md'; kind='inventory'; sha256=$inventoryHash },
            [ordered]@{ path='swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md'; kind='decision'; sha256=$decisionHash }
        )
        evidence=@('Static content-bound acceptance graph generated from the seven-cell ledger; no runtime, provider, activation, or terminal proof is claimed.')
        discriminator_before=[ordered]@{ name='result-envelope-shape'; value='legacy W1-03 result fields were top-level'; status='observed' }
        discriminator_after=[ordered]@{ name='result-envelope-shape'; value='eliot.bootstrap-work-result.v1 with rich structured_result'; status='verified' }
        uncertainty=@('The graph is a static acceptance/document graph; no Cargo, runtime, provider, or canonical-result execution evidence exists.')
        unresolved_questions=@('Root must independently decide whether the proposed A-01 Recoverable Deviation is authorized; this artifact does not activate it.')
        proposed_effects=@('If separately authorized, only the typed A-01 pre-execution PLAN_GAP/UNAVAILABLE boundary may change; no product source is changed here.')
        evidence_lineage=@($sources | ForEach-Object { [ordered]@{ path=[string]$_.path; sha256=[string]$_.sha256; role=[string]$_.role } })
        authority_ceiling='EVIDENCE_ONLY; no terminal completion, release WIP, activation, or wave authorization.'
    }
    $legacy = [ordered]@{
        authority_boundary='Static content-bound acceptance graph evidence only.'
        canonical_terminal_work_update_claim='NOT_CLAIMED'
        result_contract_status='GLOBAL_RESULT_CONTRACT_UNRESOLVED'
        work_item_id='W1-03'
        verdict='PROPOSAL_ONLY_NOT_ACTIVATED'
        ledger_cells_exactly=@('C0-12','C0-13','A-01','A-03','A-05','G-03','G-10')
        source_documents=$sources
        provenance=[ordered]@{
            repository_architecture_contract=$contractBinding
            repository_normative_projection_chain=[ordered]@{
                projection_files=$projectionBindings
                manifest=$manifestBinding
                verifier=$verifierBinding
                manifest_authority_status='NOT_AUTHORITY'
                chain_claim='W0_NORMATIVE_VERIFIER_ENFORCES_REPOSITORY_PROJECTION_AND_CONTRACT_HASHES'
            }
            external_canonical_equality='W0_NORMATIVE_VERIFIER_CHAIN_ONLY; NOT_REASSERTED_BY_W1-03'
            portable_binding='REPOSITORY_RELATIVE_PATHS_ONLY; NO_EXTERNAL_CANONICAL_PATH_READ'
        }
        inventory_document=[ordered]@{ path='swarm/inventory/acceptance-cycle.md'; sha256=$inventoryHash }
        root_decision=[ordered]@{ path='swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md'; sha256=$decisionHash; status=$decisionStatus }
        nodes=$nodes
        edges=$edges
        external_dependencies_not_nodes=@(
            [ordered]@{ consumer='C0-12'; provider='Q-01'; kind='product/proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:19-22' }
            [ordered]@{ consumer='A-01'; provider='P-03'; kind='product'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:45-50' }
            [ordered]@{ consumer='A-01'; provider='C0-06'; kind='product/proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:46-50' }
            [ordered]@{ consumer='A-01'; provider='C0-07'; kind='proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:47-50' }
        )
        strongly_connected_components=@(
            [ordered]@{ nodes=@('A-01','C0-13','G-03'); witness_cycle=@('C0-13','G-03','A-01','C0-13'); interpretation='one mixed product/proof SCC; acceptance deadlock, not an executed runtime cycle' }
            [ordered]@{ nodes=@('C0-12'); interpretation='singleton in the seven-cell internal graph; external Q-01 closure remains outside' }
            [ordered]@{ nodes=@('A-03'); interpretation='singleton; shared-trio candidate evidence only' }
            [ordered]@{ nodes=@('A-05'); interpretation='singleton; shared-trio candidate evidence only' }
            [ordered]@{ nodes=@('G-10'); interpretation='singleton; feeds A-01 and C0-12 with no evidenced return edge' }
        )
        minimum_cut=[ordered]@{ scope='seven-cell internal graph only'; cut_type='minimum vertex cut that breaks the witness SCC'; size=1; equal_minimum_cuts=@(@('A-01'),@('C0-13'),@('G-03')); selected_cut_for_proposal=@('A-01'); selected_cut_for_deviation=@('A-01'); edge_cut_alternatives=@(@('E2'),@('E3'),@('E5')) }
        recoverable_deviation=[ordered]@{ status=$decisionStatus; cell='A-01'; owner='Root / Sol for the deviation decision; Luna-A / Integration Owner for any later bounded execution'; reason='Break only the internal acceptance SCC at the launch consumer while provider evidence is unavailable; accepting the deviation does not satisfy A-01 acceptance.'; scope='A-01 pre-execution typed PLAN_GAP/UNAVAILABLE candidate only; A-03 and A-05 remain blocked.'; review_condition='Independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate.'; rollback='Revoke this proposal, restore normal A-01 admission, retain negative evidence, and rerun graph/trio checks.' }
        proof_ceiling='Static content-bound ledger/document graph only; no Cargo, runtime, provider, or canonical-result execution proof.'
    }
    foreach ($property in $legacy.Keys) { $structured[$property] = $legacy[$property] }
    [ordered]@{ schema_version='eliot.bootstrap-work-result.v1'; authority_status='EVIDENCE_ONLY'; work_item_id='W1-03'; structured_result=$structured }
}

if ($SelfTest) {
    & $verifyScript -SelfTest
    exit $LASTEXITCODE
}

$sources = Source-Bindings
$inventoryPath = Join-Path $repoRoot 'swarm/inventory/acceptance-cycle.md'
$decisionPath = Join-Path $repoRoot 'swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md'
$resultPath = Join-Path $repoRoot 'swarm/results/W1-03.json'

if (-not $Check) {
    Write-Utf8 $inventoryPath (Inventory-Text $sources)
    if (-not (Test-Path -LiteralPath $decisionPath -PathType Leaf)) { throw "Root decision missing: $decisionPath" }
    $inventoryHash = Sha256 $inventoryPath
    $decisionHash = Sha256 $decisionPath
    $result = Build-Result $sources $inventoryHash $decisionHash (Get-DecisionStatus $decisionPath)
    Write-Utf8 $resultPath (($result | ConvertTo-Json -Depth 30) + "`n")
} else {
    $checkTemp = Join-Path ([System.IO.Path]::GetTempPath()) ('eliot-w1-03-check-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $checkTemp -Force | Out-Null
    try {
        $expectedInventory = Join-Path $checkTemp 'acceptance-cycle.md'
        $expectedResult = Join-Path $checkTemp 'result.json'
        Write-Utf8 $expectedInventory (Inventory-Text $sources)
        $expectedInventoryHash = Sha256 $expectedInventory
        $decisionHash = Sha256 $decisionPath
        Write-Utf8 $expectedResult ((Build-Result $sources $expectedInventoryHash $decisionHash (Get-DecisionStatus $decisionPath) | ConvertTo-Json -Depth 30) + "`n")
        $pairs = @([ordered]@{ actual=$inventoryPath; expected=$expectedInventory; label='inventory' }, [ordered]@{ actual=$resultPath; expected=$expectedResult; label='result' })
        foreach ($pair in $pairs) {
            $actualBytes = [System.IO.File]::ReadAllBytes($pair.actual)
            $expectedBytes = [System.IO.File]::ReadAllBytes($pair.expected)
            if (([Convert]::ToBase64String($actualBytes)) -cne ([Convert]::ToBase64String($expectedBytes))) { Fail "-Check byte reproduction mismatch: $($pair.label)" }
        }
    } finally { Remove-Item -LiteralPath $checkTemp -Recurse -Force -ErrorAction SilentlyContinue }
}

& $verifyScript
$verifyExit = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
if ($verifyExit -ne 0) { exit $verifyExit }
Write-Output $(if ($Check) { 'CHECK PASS: W1-03 artifacts are content-bound and verified.' } else { 'GENERATE PASS: W1-03 inventory, result, and A-01 proposal generated deterministically and verified.' })
