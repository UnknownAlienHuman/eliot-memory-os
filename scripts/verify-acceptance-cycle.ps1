[CmdletBinding()]
param(
    [switch]$SelfTest,
    [string]$RepoRoot
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = Join-Path $PSScriptRoot '..' }
$repoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
$resultPath = Join-Path $repoRoot 'swarm/results/W1-03.json'
$inventoryPath = Join-Path $repoRoot 'swarm/inventory/acceptance-cycle.md'
$decisionPath = Join-Path $repoRoot 'swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md'

function Fail([string]$Message) { throw "VERIFY-ACCEPTANCE-CYCLE: $Message" }
function Sha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Repo-Path([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Fail 'repository-relative path is empty' }
    if ([System.IO.Path]::IsPathRooted($Path)) { Fail "absolute path is forbidden: $Path" }
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
    $root = $repoRoot.TrimEnd([char]92,[char]47) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $candidate.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { Fail "path escapes repository: $Path" }
    return $candidate
}
function Read-Text([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "artifact missing: $Path" }
    return [System.IO.File]::ReadAllText($Path)
}
function Require-Keys($Object, [string[]]$Keys, [string]$Label) {
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $expected = @($Keys | Sort-Object)
    if (($actual -join '|') -ne ($expected -join '|')) { Fail "$Label keys differ: actual [$($actual -join ',')] expected [$($expected -join ',')]" }
}
function Assert-Digest([string]$Path, [string]$Expected, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "missing $Label" }
    if ($Expected -notmatch '^[0-9a-f]{64}$') { Fail "invalid lowercase SHA-256 binding: $Label" }
    if ((Sha256 $Path) -ne ([string]$Expected).ToLowerInvariant()) { Fail "digest mismatch: $Label" }
}
function Assert-Bound-Artifact($Binding, [string]$ExpectedPath, [string]$Label) {
    if ($null -eq $Binding) { Fail "$Label binding missing" }
    if ([string]$Binding.path -cne $ExpectedPath) { Fail "$Label path is not canonical relative path" }
    Assert-Digest (Repo-Path ([string]$Binding.path)) ([string]$Binding.sha256) $Label
}
function Assert-No-Unstable-Metadata([string]$Path, [string]$Label) {
    $text = Read-Text $Path
    $forbidden = @(
        '(?i)\bHEAD\b', '(?i)\bworktree\b', '(?i)timestamp', '(?i)observed_', '(?i)ACCEPTED_TEMPORARY', '(?i)\bACCEPTED\b',
        '\b\d{4}-\d{2}-\d{2}\b', '(?i)[A-Z]:[\\/]', '(?i)(?<![A-Za-z0-9_])/(?:Users|home|tmp|var)/'
    )
    foreach ($pattern in $forbidden) {
        if ($Label -eq 'decision' -and $pattern -in @('(?i)\bACCEPTED\b','\b\d{4}-\d{2}-\d{2}\b')) { continue }
        if ($text -match $pattern) { Fail "$Label contains unstable or non-portable metadata matching $pattern" }
    }
    if ($text.Contains("`0")) { Fail "$Label contains NUL byte" }
}
function Assert-Contains([string]$Text, [string]$Needle, [string]$Label) { if (-not $Text.Contains($Needle)) { Fail "$Label missing required content: $Needle" } }

$expectedNodes = @('C0-12','C0-13','A-01','A-03','A-05','G-03','G-10')
$expectedEndpoints = @(
    'E1|C0-12|C0-13|proof/evidence','E2|C0-13|G-03|proof/evidence','E3|G-03|A-01|product','E4|G-10|A-01|product',
    'E5|A-01|C0-13|proof/evidence','E6|A-03|C0-13|proof/evidence','E7|A-05|C0-13|proof/evidence','E8|G-10|C0-12|proof/evidence'
)
$expectedEdgeDirectness = @{
    E1='derived_provider_consumer_from_explicit_ledger_requirements'; E2='derived_acceptance_binding_not_runtime_call_edge'; E3='ledger_explicit_cross_cell_prerequisite'; E4='derived_route_readiness_prerequisite';
    E5='derived_candidate_to_independent_verdict'; E6='derived_shared_trio_boundary'; E7='derived_shared_trio_boundary'; E8='derived_source_provenance_and_route_binding'
}
$expectedEdgeStatements = @{
    E1='C0-13 cannot close independence and exact evidence bindings while canonical security/source-assurance evidence remains caller-mintable or duplicated.'
    E2='G-03 verification acceptance needs the independent verdict, revision/fence, artifact and proof-ceiling bindings owned by C0-13.'
    E3='The admitted launch cannot seal task, work unit, scope and revision if G-03 has not supplied owner-admitted TaskContract and task evidence.'
    E4='A-01 NARROW launch decision needs registry-owned selected route, binding and readiness; G-10 lacks those provider-bound facts.'
    E5='A-01 may produce only candidate launch/provider results; C0-13 is the independent-verdict boundary required before acceptance.'
    E6='A-03 has no separate acceptance oracle; its result remains candidate evidence until C0-13 independent-verdict conditions hold.'
    E7='A-05 has no separate acceptance oracle; its result remains candidate evidence until C0-13 independent-verdict conditions hold.'
    E8='G-10 readiness/provenance/route evidence must consume canonical security, source-assurance and disclosure semantics.'
}
$expectedEdgeEvidence = @{
    E1=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:17-20','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:30-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27','docs/architecture/ELIOT_ARCHITECTURE.md:A5.5')
    E2=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:30-37','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:56-63','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.9','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1')
    E3=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:45-48','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:56-58','docs/tasks/RECOVERY_PROGRAM_v1.md:432-440','docs/architecture/ELIOT_IMPLEMENTATION.md:I1.8')
    E4=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:47-48','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:69-74','docs/architecture/ELIOT_IMPLEMENTATION.md:I3.4','docs/architecture/ELIOT_IMPLEMENTATION.md:P.3')
    E5=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:41-46','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.9')
    E6=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1')
    E7=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:31-37','docs/architecture/ELIOT_IMPLEMENTATION.md:I18.1')
    E8=@('reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:70-73','reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:17-20','docs/architecture/ELIOT_ARCHITECTURE.md:A12.4','docs/architecture/ELIOT_IMPLEMENTATION.md:I7.27')
}
$expectedNodeCriteria = @{
    'C0-12'='Versioned, schema-bound security/disclosure/influence contract; fail-closed construction; provider-issued verifier, declassification, disclosure and selection evidence; Q-01 duplicate owner removed.'
    'C0-13'='Canonical-byte/revision-bound evaluation contract; provider-issued independent evidence; closed verdict/outcome matrix; exact fence/source/artifact/proof-ceiling bindings.'
    'A-01'='Admitted agent launch path with exact authority, freshness, integrity, taint, privacy, verifier, fence and effect checks; NARROW seals unit/scope/route; no raw launch bypass.'
    'A-03'='The A-03 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate.'
    'A-05'='The A-05 member of the admitted-launch trio must use the same canonical admission and provider-issued execution boundary; no local authority surrogate.'
    'G-03'='Owner-admitted TaskContract from TaskSelectionEvidence, WorkScope/project identity and source binding; verification bound to task revision/fence/artifact/freshness/proof ceiling; durable canonical lifecycle.'
    'G-10'='RequestMeta-bound asynchronous blueprint/registry with verifier-bound fresh readiness, complete route fingerprint, resolved bindings and exact Cargo integration.'
}
$expectedNodeAnchors = @{
    'C0-12'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:9-22'; 'C0-13'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:24-37'; 'A-01'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50'; 'A-03'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50'; 'A-05'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:39-50'; 'G-03'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:52-63'; 'G-10'='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:65-76'
}
$expectedSourceSpecs = @(
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
$requiredSources = @($expectedSourceSpecs | ForEach-Object { [string]$_.path })

function Reachable([string]$Start, [string]$Target, [hashtable]$Graph, [string]$Removed) {
    if ($Start -eq $Removed -or $Target -eq $Removed) { return $false }
    if ($Start -eq $Target) { return $true }
    $seen = @{}
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Start); $seen[$Start] = $true
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        foreach ($next in $Graph[$current]) {
            if ($next -eq $Removed) { continue }
            if ($next -eq $Target) { return $true }
            if (-not $seen.ContainsKey($next)) { $seen[$next] = $true; $queue.Enqueue($next) }
        }
    }
    return $false
}
function Has-Cycle([string[]]$Nodes, [hashtable]$Graph, [string]$Removed) {
    foreach ($node in $Nodes) {
        if ($node -eq $Removed) { continue }
        foreach ($next in $Graph[$node]) {
            if ($next -eq $Removed) { continue }
            if ($next -eq $node -or (Reachable $next $node $Graph $Removed)) { return $true }
        }
    }
    return $false
}

function Verify-All {
    $resultText = Read-Text $resultPath
    try { $result = $resultText | ConvertFrom-Json -Depth 50 } catch { Fail "result is not valid JSON: $($_.Exception.Message)" }
    Require-Keys $result @('schema_version','authority_status','work_item_id','structured_result') 'BootstrapWorkResult'
    if ([string]$result.schema_version -cne 'eliot.bootstrap-work-result.v1' -or [string]$result.authority_status -cne 'EVIDENCE_ONLY' -or [string]$result.work_item_id -cne 'W1-03') { Fail 'BootstrapWorkResult wrapper fields drifted' }
    if ($result.PSObject.Properties.Name -contains 'terminal_update' -or $result.PSObject.Properties.Name -contains 'attempt_id') { Fail 'terminal_update/attempt_id are forbidden without an admitted attempt' }
    $structuredNames = @($result.structured_result.PSObject.Properties.Name)
    foreach ($requiredStructured in @('artifacts','disposition','discriminator_after','discriminator_before','evidence','evidence_lineage','proposed_effects','uncertainty','unresolved_questions')) { if ($requiredStructured -notin $structuredNames) { Fail "structured_result is missing required field: $requiredStructured" } }
    if ([string]$result.structured_result.disposition -notin @('completed','challenged','blocked','failed')) { Fail 'structured_result disposition is invalid' }
    if ($result.structured_result.PSObject.Properties.Name -contains 'terminal_update' -or $result.structured_result.PSObject.Properties.Name -contains 'attempt_id') { Fail 'nested terminal_update/attempt_id are forbidden' }
    $result = $result.structured_result
    Assert-No-Unstable-Metadata $resultPath 'result'
    Assert-No-Unstable-Metadata $inventoryPath 'inventory'
    Assert-No-Unstable-Metadata $decisionPath 'decision'

    foreach ($legacyRequired in @('authority_boundary','canonical_terminal_work_update_claim','result_contract_status','work_item_id','verdict','ledger_cells_exactly','source_documents','provenance','inventory_document','root_decision','nodes','edges','external_dependencies_not_nodes','strongly_connected_components','minimum_cut','recoverable_deviation','proof_ceiling')) { if ($legacyRequired -notin @($result.PSObject.Properties.Name)) { Fail "result missing legacy evidence field: $legacyRequired" } }
    if ([string]$result.authority_boundary -cne 'Static content-bound acceptance graph evidence only.') { Fail 'authority boundary drift' }
    if ([string]$result.canonical_terminal_work_update_claim -cne 'NOT_CLAIMED') { Fail 'canonical TerminalWorkUpdate claim is not explicitly absent' }
    if ([string]$result.result_contract_status -cne 'GLOBAL_RESULT_CONTRACT_UNRESOLVED') { Fail 'result-contract challenge is not represented' }
    if ([string]$result.work_item_id -cne 'W1-03' -or [string]$result.verdict -cne 'PROPOSAL_ONLY_NOT_ACTIVATED') { Fail 'work item verdict is not proposal-only' }

    $cells = @($result.ledger_cells_exactly | ForEach-Object { [string]$_ })
    if (($cells -join '|') -ne ($expectedNodes -join '|')) { Fail 'ledger_cells_exactly is not the exact seven-cell ordered list' }
    $nodeIds = @($result.nodes | ForEach-Object { [string]$_.id })
    $sortedNodeIds = (@($nodeIds | Sort-Object) -join '|')
    $sortedExpectedNodes = (@($expectedNodes | Sort-Object) -join '|')
    if ($sortedNodeIds -ne $sortedExpectedNodes) { Fail 'node set is not exactly seven cells' }
    if ($nodeIds.Count -ne 7) { Fail 'node count is not seven' }
    foreach ($node in @($result.nodes)) {
        Require-Keys $node @('id','criterion','ledger_anchor') "node $($node.id)"
        if ([string]$node.criterion -cne [string]$expectedNodeCriteria[[string]$node.id] -or [string]$node.ledger_anchor -cne [string]$expectedNodeAnchors[[string]$node.id]) { Fail "node $($node.id) semantic fields drifted" }
    }

    $nodeSet = @{}; foreach ($id in $expectedNodes) { $nodeSet[$id] = $true }
    $graph = @{}; foreach ($id in $expectedNodes) { $graph[$id] = [System.Collections.Generic.List[string]]::new() }
    $seenEdges = @()
    foreach ($edge in @($result.edges)) {
        Require-Keys $edge @('id','from','to','dependency_class','directness','statement','evidence') "edge $($edge.id)"
        $signature = "{0}|{1}|{2}|{3}" -f $edge.id,$edge.from,$edge.to,$edge.dependency_class
        $seenEdges += $signature
        if ($edge.id -notmatch '^E[1-8]$' -or -not $nodeSet.ContainsKey([string]$edge.from) -or -not $nodeSet.ContainsKey([string]$edge.to)) { Fail "edge $($edge.id) escapes exact graph" }
        $expectedParts = @($expectedEndpoints | Where-Object { $_ -like "$($edge.id)|*" })[0].Split('|')
        if ([string]$edge.from -cne $expectedParts[1] -or [string]$edge.to -cne $expectedParts[2] -or [string]$edge.dependency_class -cne $expectedParts[3]) { Fail "edge $($edge.id) endpoint/class semantics drifted" }
        if ([string]$edge.directness -cne [string]$expectedEdgeDirectness[[string]$edge.id] -or [string]$edge.statement -cne [string]$expectedEdgeStatements[[string]$edge.id]) { Fail "edge $($edge.id) directness/statement semantics drifted" }
        if ((@($edge.evidence) -join '|') -cne (@($expectedEdgeEvidence[[string]$edge.id]) -join '|')) { Fail "edge $($edge.id) evidence semantics drifted" }
        [void]$graph[[string]$edge.from].Add([string]$edge.to)
    }
    $sortedEdges = (@($seenEdges | Sort-Object) -join ';')
    $sortedExpectedEdges = (@($expectedEndpoints | Sort-Object) -join ';')
    if ($sortedEdges -ne $sortedExpectedEdges) { Fail 'edge set/endpoints/classes drifted' }

    $expectedExternal = @(
        [ordered]@{ consumer='C0-12'; provider='Q-01'; kind='product/proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:19-22' }
        [ordered]@{ consumer='A-01'; provider='P-03'; kind='product'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:45-50' }
        [ordered]@{ consumer='A-01'; provider='C0-06'; kind='product/proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:46-50' }
        [ordered]@{ consumer='A-01'; provider='C0-07'; kind='proof'; evidence='reports/audit/ELIOT_IMPLEMENTATION_BLOCKERS_20260814.md:47-50' }
    )
    if (@($result.external_dependencies_not_nodes).Count -ne $expectedExternal.Count) { Fail 'external dependency count drifted' }
    for ($externalIndex = 0; $externalIndex -lt $expectedExternal.Count; $externalIndex++) {
        $actualExternal = @($result.external_dependencies_not_nodes)[$externalIndex]
        $expectedExternalItem = $expectedExternal[$externalIndex]
        Require-Keys $actualExternal @('consumer','provider','kind','evidence') 'external dependency'
        foreach ($field in @('consumer','provider','kind','evidence')) { if ([string]$actualExternal.$field -cne [string]$expectedExternalItem[$field]) { Fail "external dependency $field semantics drifted" } }
    }

    if (@($result.source_documents).Count -ne $expectedSourceSpecs.Count) { Fail 'source_documents count drifted' }
    for ($sourceIndex = 0; $sourceIndex -lt $expectedSourceSpecs.Count; $sourceIndex++) {
        $source = @($result.source_documents)[$sourceIndex]
        $expectedSource = $expectedSourceSpecs[$sourceIndex]
        Require-Keys $source @('path','role','sha256','anchors') "source $($source.path)"
        if ([string]$source.path -cne [string]$expectedSource.path -or [string]$source.role -cne [string]$expectedSource.role) { Fail "source path/role mismatch: $($source.path)" }
        Assert-Digest (Repo-Path ([string]$source.path)) ([string]$source.sha256) "source $($source.path)"
        if (@($source.anchors).Count -ne @($expectedSource.anchors).Count) { Fail "source anchor count mismatch: $($source.path)" }
        for ($anchorIndex = 0; $anchorIndex -lt @($expectedSource.anchors).Count; $anchorIndex++) {
            $anchor = @($source.anchors)[$anchorIndex]
            $expectedAnchor = @($expectedSource.anchors)[$anchorIndex]
            Require-Keys $anchor @('line','needle') "source anchor $($source.path)"
            if ([int]$anchor.line -ne [int]$expectedAnchor.line -or [string]$anchor.needle -cne [string]$expectedAnchor.needle) { Fail "source anchor declaration mismatch: $($source.path)" }
            $lines = Get-Content -LiteralPath (Repo-Path $source.path)
            if ($anchor.line -gt $lines.Count -or -not $lines[$anchor.line - 1].Contains($anchor.needle)) { Fail "source anchor mismatch: $($source.path):$($anchor.line)" }
        }
    }
    $boundSources = @($result.source_documents | ForEach-Object { [string]$_.path })
    $sortedSources = (@($boundSources | Sort-Object) -join '|')
    $sortedRequiredSources = (@($requiredSources | Sort-Object) -join '|')
    if ($sortedSources -ne $sortedRequiredSources) { Fail 'required source bindings are incomplete' }
    Assert-Bound-Artifact $result.inventory_document 'swarm/inventory/acceptance-cycle.md' 'inventory'
    Assert-Bound-Artifact $result.root_decision 'swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md' 'decision'
    Require-Keys $result.inventory_document @('path','sha256') 'inventory binding'
    Require-Keys $result.root_decision @('path','sha256','status') 'decision binding'
    $decision = Read-Text $decisionPath
    if ($decision -notmatch '(?m)^Status: `([^`]+)`') { Fail 'decision status is missing' }
    $decisionStatus = [string]$Matches[1]
    if ($decisionStatus -notin @('PROPOSAL_ONLY_NOT_ACTIVATED','ACCEPTED_RECOVERABLE_DEVIATION')) { Fail "unsupported decision status: $decisionStatus" }
    if ([string]$result.root_decision.status -cne $decisionStatus) { Fail 'decision binding status drifted' }

    Require-Keys $result.provenance @('repository_architecture_contract','repository_normative_projection_chain','external_canonical_equality','portable_binding') 'provenance'
    Require-Keys $result.provenance.repository_architecture_contract @('path','role','sha256','anchors') 'provenance contract'
    if ([string]$result.provenance.external_canonical_equality -cne 'W0_NORMATIVE_VERIFIER_CHAIN_ONLY; NOT_REASSERTED_BY_W1-03') { Fail 'external canonical equality claim drifted' }
    if ([string]$result.provenance.portable_binding -cne 'REPOSITORY_RELATIVE_PATHS_ONLY; NO_EXTERNAL_CANONICAL_PATH_READ') { Fail 'portable provenance claim drifted' }
    $contract = $result.provenance.repository_architecture_contract
    if ([string]$contract.path -cne 'docs/ARCHITECTURE_CONTRACT.md' -or [string]$contract.role -cne 'repository architecture contract; W0 verifier input') { Fail 'provenance contract binding drifted' }
    $sourceByPath = @{}; foreach ($boundSource in @($result.source_documents)) { $sourceByPath[[string]$boundSource.path] = $boundSource }
    if (($contract | ConvertTo-Json -Depth 10 -Compress) -ne ($sourceByPath['docs/ARCHITECTURE_CONTRACT.md'] | ConvertTo-Json -Depth 10 -Compress)) { Fail 'provenance contract is not identical to source_documents binding' }
    Require-Keys $result.provenance.repository_normative_projection_chain @('projection_files','manifest','verifier','manifest_authority_status','chain_claim') 'normative projection chain'
    $chain = $result.provenance.repository_normative_projection_chain
    if ([string]$chain.manifest_authority_status -cne 'NOT_AUTHORITY' -or [string]$chain.chain_claim -cne 'W0_NORMATIVE_VERIFIER_ENFORCES_REPOSITORY_PROJECTION_AND_CONTRACT_HASHES') { Fail 'normative chain claim drifted' }
    if (@($chain.projection_files).Count -ne 5) { Fail 'normative projection file count drifted' }
    foreach ($projection in @($chain.projection_files)) {
        Require-Keys $projection @('path','role','sha256','anchors') 'normative projection binding'
        if ([string]$projection.path -notin @('docs/normative/ELIOT_ARCHITECTURE.md','docs/normative/ELIOT_IMPLEMENTATION.md','docs/normative/INDEX.md','docs/normative/README.md','docs/normative/PROJECTION_NOTICE.md')) { Fail "unexpected normative projection: $($projection.path)" }
        if (($projection | ConvertTo-Json -Depth 10 -Compress) -ne ($sourceByPath[[string]$projection.path] | ConvertTo-Json -Depth 10 -Compress)) { Fail "provenance projection is not identical to source_documents: $($projection.path)" }
    }
    foreach ($chainBinding in @($chain.manifest,$chain.verifier,$contract) ) { Assert-Digest (Repo-Path $chainBinding.path) ([string]$chainBinding.sha256) "provenance chain $($chainBinding.path)" }
    if (($chain.manifest | ConvertTo-Json -Depth 10 -Compress) -ne ($sourceByPath['docs/normative/projection-manifest.tsv'] | ConvertTo-Json -Depth 10 -Compress) -or ($chain.verifier | ConvertTo-Json -Depth 10 -Compress) -ne ($sourceByPath['scripts/verify-normative.ps1'] | ConvertTo-Json -Depth 10 -Compress)) { Fail 'provenance manifest/verifier bindings are not identical to source_documents' }
    if ([string]$chain.manifest.path -cne 'docs/normative/projection-manifest.tsv' -or [string]$chain.verifier.path -cne 'scripts/verify-normative.ps1') { Fail 'normative manifest/verifier path drifted' }

    $expectedSccs = @(
        [ordered]@{ nodes=@('A-01','C0-13','G-03'); witness_cycle=@('C0-13','G-03','A-01','C0-13'); interpretation='one mixed product/proof SCC; acceptance deadlock, not an executed runtime cycle' }
        [ordered]@{ nodes=@('C0-12'); interpretation='singleton in the seven-cell internal graph; external Q-01 closure remains outside' }
        [ordered]@{ nodes=@('A-03'); interpretation='singleton; shared-trio candidate evidence only' }
        [ordered]@{ nodes=@('A-05'); interpretation='singleton; shared-trio candidate evidence only' }
        [ordered]@{ nodes=@('G-10'); interpretation='singleton; feeds A-01 and C0-12 with no evidenced return edge' }
    )
    if (@($result.strongly_connected_components).Count -ne $expectedSccs.Count) { Fail 'SCC count drifted' }
    for ($sccIndex = 0; $sccIndex -lt $expectedSccs.Count; $sccIndex++) {
        $actualScc = @($result.strongly_connected_components)[$sccIndex]
        $expectedScc = $expectedSccs[$sccIndex]
        $expectedSccKeys = if ($expectedScc.Contains('witness_cycle')) { @('nodes','witness_cycle','interpretation') } else { @('nodes','interpretation') }
        Require-Keys $actualScc $expectedSccKeys "SCC $sccIndex"
        if ((@($actualScc.nodes) -join '|') -ne (@($expectedScc.nodes) -join '|') -or [string]$actualScc.interpretation -cne [string]$expectedScc.interpretation) { Fail "SCC $sccIndex members/interpretation drifted" }
        if ($expectedScc.Contains('witness_cycle') -and ((@($actualScc.witness_cycle) -join '|') -ne (@($expectedScc.witness_cycle) -join '|'))) { Fail 'SCC witness cycle drifted' }
    }
    $remaining = [System.Collections.Generic.List[string]]::new(); foreach ($id in $expectedNodes) { [void]$remaining.Add($id) }
    $computedSccs = @()
    while ($remaining.Count -gt 0) {
        $seed = $remaining[0]
        $component = @($remaining | Where-Object { (Reachable $seed $_ $graph '') -and (Reachable $_ $seed $graph '') })
        $computedSccs += ,(@($component | Sort-Object))
        foreach ($id in $component) { [void]$remaining.Remove($id) }
    }
    $declaredSccs = @($result.strongly_connected_components | ForEach-Object { (@($_.nodes) | Sort-Object) -join ',' } | Sort-Object)
    $actualSccs = @($computedSccs | ForEach-Object { $_ -join ',' } | Sort-Object)
    if (($declaredSccs -join ';') -ne ($actualSccs -join ';')) { Fail 'SCC declaration does not recompute' }
    $witness = @('A-01','C0-13','G-03')
    $cuts = @(); foreach ($candidate in $witness) { if (-not (Has-Cycle $witness $graph $candidate)) { $cuts += ,@($candidate) } }
    $declaredCuts = @($result.minimum_cut.equal_minimum_cuts | ForEach-Object { (@($_) | Sort-Object) -join ',' } | Sort-Object)
    $actualCuts = @($cuts | ForEach-Object { $_ -join ',' } | Sort-Object)
    if (($declaredCuts -join ';') -ne ($actualCuts -join ';')) { Fail 'minimum cut candidates do not recompute' }
    Require-Keys $result.minimum_cut @('scope','cut_type','size','equal_minimum_cuts','selected_cut_for_proposal','selected_cut_for_deviation','edge_cut_alternatives') 'minimum_cut'
    if ([string]$result.minimum_cut.scope -cne 'seven-cell internal graph only' -or [string]$result.minimum_cut.cut_type -cne 'minimum vertex cut that breaks the witness SCC') { Fail 'minimum_cut scope/type semantics drifted' }
    $expectedEqualCuts = @('A-01','C0-13','G-03')
    if (@($result.minimum_cut.equal_minimum_cuts).Count -ne $expectedEqualCuts.Count) { Fail 'minimum_cut equal cut count drifted' }
    for ($cutIndex = 0; $cutIndex -lt $expectedEqualCuts.Count; $cutIndex++) { if (@($result.minimum_cut.equal_minimum_cuts)[$cutIndex].Count -ne 1 -or [string]@($result.minimum_cut.equal_minimum_cuts)[$cutIndex][0] -cne $expectedEqualCuts[$cutIndex]) { Fail 'minimum_cut equal cuts semantics drifted' } }
    $expectedEdgeCuts = @('E2','E3','E5')
    if (@($result.minimum_cut.edge_cut_alternatives).Count -ne $expectedEdgeCuts.Count) { Fail 'minimum_cut edge alternative count drifted' }
    for ($cutIndex = 0; $cutIndex -lt $expectedEdgeCuts.Count; $cutIndex++) { if (@($result.minimum_cut.edge_cut_alternatives)[$cutIndex].Count -ne 1 -or [string]@($result.minimum_cut.edge_cut_alternatives)[$cutIndex][0] -cne $expectedEdgeCuts[$cutIndex]) { Fail 'minimum_cut edge alternatives semantics drifted' } }
    if ([int]$result.minimum_cut.size -ne 1 -or @($result.minimum_cut.selected_cut_for_proposal).Count -ne 1 -or [string]$result.minimum_cut.selected_cut_for_proposal[0] -cne 'A-01' -or @($result.minimum_cut.selected_cut_for_deviation).Count -ne 1 -or [string]$result.minimum_cut.selected_cut_for_deviation[0] -cne 'A-01') { Fail 'minimum cut is not concrete size-one A-01 proposal cut' }
    Require-Keys $result.recoverable_deviation @('status','cell','owner','reason','scope','review_condition','rollback') 'recoverable_deviation'
    if ([string]$result.recoverable_deviation.status -cne $decisionStatus -or [string]$result.recoverable_deviation.cell -cne 'A-01') { Fail 'recoverable_deviation status/cell drifted' }
    if ($decisionStatus -eq 'ACCEPTED_RECOVERABLE_DEVIATION') {
        if ([string]$result.recoverable_deviation.owner -cne 'Root / Sol for the deviation decision; Luna-A / Integration Owner for any later bounded execution' -or [string]$result.recoverable_deviation.reason -cne 'Break only the internal acceptance SCC at the launch consumer while provider evidence is unavailable; accepting the deviation does not satisfy A-01 acceptance.' -or [string]$result.recoverable_deviation.scope -cne 'A-01 pre-execution typed PLAN_GAP/UNAVAILABLE candidate only; A-03 and A-05 remain blocked.' -or [string]$result.recoverable_deviation.review_condition -cne 'Independently executed provider-issued P-03 and C0-06 evidence plus the unchanged A-01/A-03/A-05 trio gate.' -or [string]$result.recoverable_deviation.rollback -cne 'Revoke this proposal, restore normal A-01 admission, retain negative evidence, and rerun graph/trio checks.') { Fail 'accepted recoverable_deviation semantics drifted' }
    } elseif ([string]$result.recoverable_deviation.owner -cne 'Luna-A / Integration Owner, subject to Root acceptance' -or [string]$result.recoverable_deviation.reason -cne 'Break only the internal acceptance SCC at the launch consumer while provider evidence is unavailable; the proposal is not an acceptance.') { Fail 'proposal recoverable_deviation semantics drifted' }

    $inventory = Read-Text $inventoryPath
    Assert-Contains $inventory 'exactly seven cells' 'inventory'
    Assert-Contains $inventory 'C0-13 → G-03 → A-01 → C0-13' 'inventory witness cycle'
    Assert-Contains $inventory 'minimum vertex cut' 'inventory cut'
    Assert-Contains $inventory 'PROPOSAL_ONLY_NOT_ACTIVATED' 'inventory proposal status'
    foreach ($id in $expectedNodes) { Assert-Contains $inventory "``$id``" 'inventory node' }
    foreach ($source in @($result.source_documents)) { Assert-Contains $inventory "- $($source.path) :: $($source.sha256)" 'inventory source digest binding' }
    Assert-Contains $decision "Status: ``$decisionStatus``" 'decision status'
    if ($decisionStatus -eq 'ACCEPTED_RECOVERABLE_DEVIATION') { Assert-Contains $decision 'Authority: Root / Sol decision under `A0.6`' 'decision acceptance boundary' } else { Assert-Contains $decision 'Root acceptance is intentionally absent' 'decision acceptance boundary' }
    if ($decisionStatus -eq 'ACCEPTED_RECOVERABLE_DEVIATION') {
        if ($decision -notmatch 'not a\s+canonical `TerminalWorkUpdate`') { Fail 'decision authority boundary missing required content' }
        Assert-Contains $decision 'underlying W1 evidence remains `EVIDENCE_ONLY`' 'decision evidence ceiling'
    } else { Assert-Contains $decision 'not a canonical `TerminalWorkUpdate`' 'decision authority boundary' }
    if ($decisionStatus -eq 'ACCEPTED_RECOVERABLE_DEVIATION') { Assert-Contains $decision 'Owner: Root / Sol for the deviation decision' 'decision owner label' } else { Assert-Contains $decision 'Owner: Luna-A / Integration Owner' 'decision owner label' }
    Assert-Contains $decision 'Reason: Break only the internal acceptance SCC' 'decision reason label'
    Assert-Contains $decision 'Scope: A-01 pre-execution' 'decision scope label'
    Assert-Contains $decision 'Review condition: Independently executed' 'decision review label'
    Assert-Contains $decision 'Rollback: Revoke this proposal' 'decision rollback label'
    Assert-Contains $decision 'minimum vertex cut is size one' 'decision cut'
    Assert-Contains $decision 'Only A-01' 'decision scope'
    return 'PASS: W1-03 exact seven cells, content digests, SCC, concrete cut-size-one, proposal-only A-01, authority boundary, and portable artifact properties verified.'
}

function Invoke-SelfTest {
    $temp = Join-Path ([System.IO.Path]::GetTempPath()) ('eliot-w1-03-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $temp -Force | Out-Null
    try {
        $copyPaths = @($requiredSources + 'swarm/results/W1-03.json' + 'swarm/inventory/acceptance-cycle.md' + 'swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md')
        foreach ($relative in $copyPaths) {
            $from = Repo-Path $relative
            $to = Join-Path $temp $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null
            Copy-Item -LiteralPath $from -Destination $to -Force
        }
        $outside = Join-Path $temp 'outside.txt'; [System.IO.File]::WriteAllText($outside, 'x')
        try { Repo-Path ([System.IO.Path]::GetFullPath($outside)); Fail 'absolute-path self-test did not reject external path' } catch { if ($_.Exception.Message -notmatch 'absolute path is forbidden|path escapes repository') { throw } }
        try { Repo-Path '../outside.txt'; Fail 'traversal self-test did not reject escape' } catch { if ($_.Exception.Message -notmatch 'path escapes repository') { throw } }
        $portable = & pwsh -NoProfile -Command "Set-Location ([IO.Path]::GetTempPath()); & '$PSCommandPath' -RepoRoot '$repoRoot'" 2>&1
        if ($LASTEXITCODE -ne 0 -or ($portable -notmatch 'PASS:')) { Fail 'alternate-working-directory verification failed' }
        $artifactPaths = @('swarm/results/W1-03.json','swarm/inventory/acceptance-cycle.md','swarm/decisions/W1-03-A01-RECOVERABLE-DEVIATION.md')
        function Reset-ArtifactFixture { foreach ($reset in $artifactPaths) { Copy-Item -LiteralPath (Repo-Path $reset) -Destination (Join-Path $temp $reset) -Force } }
        function Mutate-Result([string]$CaseName) {
            $path = Join-Path $temp 'swarm/results/W1-03.json'
            $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json -Depth 50
            switch ($CaseName) {
                'minimum_cut.extra_nested' { $value.structured_result.minimum_cut | Add-Member -MemberType NoteProperty -Name extra_nested -Value ([pscustomobject]@{}) }
                'minimum_cut.remove_edge_cut_alternatives' { [void]$value.structured_result.minimum_cut.PSObject.Properties.Remove('edge_cut_alternatives') }
                'minimum_cut.edge_cut_alternatives_extra_member' { $value.structured_result.minimum_cut.edge_cut_alternatives[0] = @('E2','FORGED') }
                'source_documents.forged_role' { $value.structured_result.source_documents[0].role = 'FORGED_ROLE' }
                'source_documents.add' { $value.structured_result.source_documents = @($value.structured_result.source_documents) + @($value.structured_result.source_documents[0]) }
                'source_documents.remove' { $value.structured_result.source_documents = @($value.structured_result.source_documents | Select-Object -Skip 1) }
                'provenance.extra_nested' { $value.structured_result.provenance | Add-Member -MemberType NoteProperty -Name extra_nested -Value ([pscustomobject]@{}) }
                'provenance.remove_chain' { [void]$value.structured_result.provenance.PSObject.Properties.Remove('repository_normative_projection_chain') }
                'nodes.extra_nested' { $value.structured_result.nodes[0] | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'nodes.remove_criterion' { [void]$value.structured_result.nodes[0].PSObject.Properties.Remove('criterion') }
                'edges.extra_nested' { $value.structured_result.edges[0] | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'edges.remove_evidence' { [void]$value.structured_result.edges[0].PSObject.Properties.Remove('evidence') }
                'external_dependencies.extra_nested' { $value.structured_result.external_dependencies_not_nodes[0] | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'external_dependencies.remove' { $value.structured_result.external_dependencies_not_nodes = @($value.structured_result.external_dependencies_not_nodes | Select-Object -Skip 1) }
                'strongly_connected_components.extra_nested' { $value.structured_result.strongly_connected_components[0] | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'strongly_connected_components.remove_witness_cycle' { [void]$value.structured_result.strongly_connected_components[0].PSObject.Properties.Remove('witness_cycle') }
                'recoverable_deviation.extra_nested' { $value.structured_result.recoverable_deviation | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'recoverable_deviation.remove_rollback' { [void]$value.structured_result.recoverable_deviation.PSObject.Properties.Remove('rollback') }
                'inventory_document.extra_nested' { $value.structured_result.inventory_document | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'inventory_document.remove_sha256' { [void]$value.structured_result.inventory_document.PSObject.Properties.Remove('sha256') }
                'root_decision.extra_nested' { $value.structured_result.root_decision | Add-Member -MemberType NoteProperty -Name extra_nested -Value 'tamper' }
                'root_decision.remove_status' { [void]$value.structured_result.root_decision.PSObject.Properties.Remove('status') }
                'ledger_cells_exactly.remove' { $value.structured_result.ledger_cells_exactly = @($value.structured_result.ledger_cells_exactly | Select-Object -Skip 1) }
                default { Fail "unknown structured self-test: $CaseName" }
            }
            [System.IO.File]::WriteAllText($path, (($value | ConvertTo-Json -Depth 50) + "`n"), [System.Text.UTF8Encoding]::new($false))
        }
        $structuredCases = @('minimum_cut.extra_nested','minimum_cut.remove_edge_cut_alternatives','minimum_cut.edge_cut_alternatives_extra_member','source_documents.forged_role','source_documents.add','source_documents.remove','provenance.extra_nested','provenance.remove_chain','nodes.extra_nested','nodes.remove_criterion','edges.extra_nested','edges.remove_evidence','external_dependencies.extra_nested','external_dependencies.remove','strongly_connected_components.extra_nested','strongly_connected_components.remove_witness_cycle','recoverable_deviation.extra_nested','recoverable_deviation.remove_rollback','inventory_document.extra_nested','inventory_document.remove_sha256','root_decision.extra_nested','root_decision.remove_status','ledger_cells_exactly.remove')
        foreach ($case in $structuredCases) { Reset-ArtifactFixture; Mutate-Result $case; $mutationOutput = (& pwsh -NoProfile -File $PSCommandPath -RepoRoot $temp 2>&1 | Out-String); if ($LASTEXITCODE -eq 0 -or $mutationOutput -match 'PASS:') { Fail "structured nested self-test did not fail closed: $case" } }
        foreach ($relative in $artifactPaths) { Reset-ArtifactFixture; $tampered = Join-Path $temp $relative; if ($relative -eq 'swarm/results/W1-03.json') { $tamperedText = [System.IO.File]::ReadAllText($tampered).Replace('"W1-03"','"W1-04"'); [System.IO.File]::WriteAllText($tampered, $tamperedText, [System.Text.UTF8Encoding]::new($false)) } else { Add-Content -LiteralPath $tampered -Value 'tamper' }; $tamperOutput = (& pwsh -NoProfile -File $PSCommandPath -RepoRoot $temp 2>&1 | Out-String); if ($LASTEXITCODE -eq 0 -or $tamperOutput -match 'PASS:') { Fail "artifact byte tamper self-test did not fail closed: $relative" } }
        Write-Output 'SELFTEST PASS: exact nested property/semantic closure, minimum_cut bypasses, forged source role, add/remove families, path portability, and three-artifact byte tamper rejection'
    } finally { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($SelfTest) { Invoke-SelfTest; exit 0 }
Write-Output (Verify-All)
