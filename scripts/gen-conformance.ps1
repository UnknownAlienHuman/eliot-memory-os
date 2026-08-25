[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$SelfTest,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ArchitecturePath = Join-Path $RepoRoot 'docs\normative\ELIOT_ARCHITECTURE.md'
$ImplementationPath = Join-Path $RepoRoot 'docs\normative\ELIOT_IMPLEMENTATION.md'
$DecisionPath = Join-Path $RepoRoot 'swarm\challenges\W1-RESULT-ENVELOPE-CONTRACT.md'
$GeneratorPath = Join-Path $RepoRoot 'scripts\gen-conformance.ps1'
$VerifierPath = Join-Path $RepoRoot 'scripts\verify-conformance.ps1'
$ConformancePath = Join-Path $RepoRoot 'docs\conformance.toml'
$ResultPath = Join-Path $RepoRoot 'swarm\results\W1-04.json'
$SupportingResultPath = Join-Path $RepoRoot 'swarm\results\W1-04-implementation.json'

function Rel([string]$Path) { return ([System.IO.Path]::GetRelativePath($RepoRoot, $Path)).Replace('\','/') }
function Sha([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant() }
function TextSha([string]$Text) {
    $h = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToUpperInvariant() }
    finally { $h.Dispose() }
}
function Norm([string]$Value) { if ($null -eq $Value) { return '' }; return ([regex]::Replace($Value.Trim(), '[\t\r\n ]+', ' ')) }
function Toml([string]$Value) {
    $s = if ($null -eq $Value) { '' } else { [string]$Value }
    return '"' + $s.Replace('\','\\').Replace('"','\"').Replace("`r",'\r').Replace("`n",'\n').Replace("`t",'\t') + '"'
}
function TomlArray($Values) { if ($null -eq $Values -or @($Values).Count -eq 0) { return '[]' }; return '[' + ((@($Values) | % { Toml ([string]$_) }) -join ', ') + ']' }

function Rows([string]$Text, [string]$Start, [string]$End, [string]$Header, [string]$Kind) {
    $inside=$false; $fenced=$false; $head=$false; $sep=$false; $out=[Collections.Generic.List[object]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*```') { $fenced=-not $fenced; continue }; if ($fenced) { continue }
        if (-not $inside) { if ($line -match $Start) { $inside=$true }; continue }; if ($line -match $End) { break }
        if (-not $head) { if ([string]::IsNullOrWhiteSpace($line)) { continue }; if ($line -notmatch $Header) { continue }; $head=$true; continue }
        if (-not $sep) { if ($line -match '^\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*$') { $sep=$true; continue }; if (-not [string]::IsNullOrWhiteSpace($line)) { throw "$Kind table separator is malformed" }; continue }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($Kind -eq 'architecture' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(Invariant|Contract)\s*\|\s*(.*?)\s*\|\s*$') { $out.Add([pscustomobject]@{Id=$Matches[1];Class=$Matches[2];Decision=$Matches[3].Trim()}); continue }
        if ($Kind -eq 'implementation' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$') { $out.Add([pscustomobject]@{Id=$Matches[1];ScopeOwner=$Matches[2].Trim();Proof=$Matches[3].Trim()}); continue }
        if ($line -match '^\|') { throw "$Kind table contains an invalid row: $line" }
    }
    if (-not $inside -or -not $head -or -not $sep) { throw "$Kind table headings/header were not found" }; return $out.ToArray()
}

function AssertPair($A,$I) {
    if (@($A).Count -ne 58 -or @($I).Count -ne 58) { throw 'A16.1 and Appendix H must each contain exactly 58 rows' }
    $ai=@($A|% Id); $ii=@($I|% Id)
    if (@($ai|sort -Unique).Count -ne 58 -or @($ii|sort -Unique).Count -ne 58) { throw 'duplicate architecture IDs' }
    $missing=@($ai|?{$_ -notin $ii}); $extra=@($ii|?{$_ -notin $ai}); if ($missing.Count -or $extra.Count) { throw "anchor sets differ: missing=$($missing -join ',') extra=$($extra -join ',')" }
}
function Scope([string]$Value) {
    $s=Norm $Value; $owner='UNKNOWN'; $handles=$s
    if ($s -match '^(.*?);\s*([^;]+)$') { $handles=$Matches[1].Trim(); $owner=$Matches[2].Trim() }
    [pscustomobject]@{Owner=$owner.Trim('`');Handles=@($handles -split '\s*,\s*'|%{$_.Trim().Trim('`')}|?{$_})}
}
function Model {
    $a=Rows (Get-Content -LiteralPath $ArchitecturePath -Raw) '^## A16\.1\. Decision anchors\s*$' '^## A16\.2\.' '^\|\s*ID\s*\|\s*Класс\s*\|\s*Решение\s*\|\s*$' architecture
    $i=Rows (Get-Content -LiteralPath $ImplementationPath -Raw) '^# Appendix H\. Full Architecture conformance map\s*$' '^# Appendix I\.' '^\|\s*Architecture ID\s*\|\s*Primary implementation sections / owner\s*\|\s*Observable proof family\s*\|\s*$' implementation
    AssertPair $a $i; $by=@{}; $i|%{$by[$_.Id]=$_}
    $an=(($a|%{"$($_.Id)|$($_.Class)|$(Norm $_.Decision)"})-join "`n")+"`n"; $inn=(($a|%{$r=$by[$_.Id];"$($_.Id)|$(Norm $r.ScopeOwner)|$(Norm $r.Proof)"})-join "`n")+"`n"
    [pscustomobject]@{Architecture=$a;Implementation=$i;ById=$by;ArchitectureHash=(Sha $ArchitecturePath);ImplementationHash=(Sha $ImplementationPath);PairHash=(TextSha ($an+"---`n"+$inn));GeneratorHash=(Sha $GeneratorPath);VerifierHash=(Sha $VerifierPath);DecisionHash=(Sha $DecisionPath)}
}
function Conformance($m) {
    $lines=[Collections.Generic.List[string]]::new(); $lines.Add('# GENERATED FILE - DO NOT EDIT. Content-bound projection of A16.1 and Appendix H.')
    $lines.Add('schema_version = "eliot-conformance-v2"'); $lines.Add('authority_status = "GENERATED_PROJECTION"'); $lines.Add('provenance_mode = "CONTENT_BOUND"')
    $lines.Add("architecture_source_path = $(Toml (Rel $ArchitecturePath))"); $lines.Add("implementation_source_path = $(Toml (Rel $ImplementationPath))")
    $lines.Add("generator_path = $(Toml (Rel $GeneratorPath))"); $lines.Add("verifier_path = $(Toml (Rel $VerifierPath))"); $lines.Add("decision_path = $(Toml (Rel $DecisionPath))")
    $lines.Add("architecture_source_sha256 = $(Toml $m.ArchitectureHash)"); $lines.Add("implementation_source_sha256 = $(Toml $m.ImplementationHash)"); $lines.Add("normalized_pair_sha256 = $(Toml $m.PairHash)")
    $lines.Add("generator_source_sha256 = $(Toml $m.GeneratorHash)"); $lines.Add("verifier_source_sha256 = $(Toml $m.VerifierHash)"); $lines.Add("decision_source_sha256 = $(Toml $m.DecisionHash)"); $lines.Add('anchor_count = 58'); $lines.Add('')
    foreach($a in $m.Architecture) { $r=$m.ById[$a.Id]; $p=Scope $r.ScopeOwner; $lines.Add('[[requirement]]'); $lines.Add("id = $(Toml $a.Id)"); $lines.Add("class = $(Toml $a.Class)"); $lines.Add("decision = $(Toml (Norm $a.Decision))"); $lines.Add("owner = $(Toml $p.Owner)"); $lines.Add("source_handles = $(TomlArray $p.Handles)"); $lines.Add('support = "UNKNOWN"'); $lines.Add('invalidation = []'); $lines.Add("observable_proof = $(Toml (Norm $r.Proof))"); $lines.Add('') }
    return (($lines -join "`n")+"`n")
}
function Json([object]$Value) { return ($Value | ConvertTo-Json -Depth 30) }
function Envelope($m,[string]$ConformanceHash) {
    $sources=@([ordered]@{path=(Rel $ArchitecturePath);role='current repository normative projection';sha256=$m.ArchitectureHash},[ordered]@{path=(Rel $ImplementationPath);role='current repository normative projection';sha256=$m.ImplementationHash},[ordered]@{path=(Rel $DecisionPath);role='resolved result-envelope program revision';sha256=$m.DecisionHash})
    $structured=[ordered]@{disposition='completed';artifacts=@([ordered]@{path='docs/conformance.toml';role='generated projection';sha256=$ConformanceHash},[ordered]@{path='swarm/results/W1-04-implementation.json';role='supporting implementation evidence';sha256='supporting-file-not-authority'});evidence=@('58 A16.1 anchors are deterministically projected to 58 Appendix H rows with UNKNOWN support and empty invalidation by default.');discriminator_before=[ordered]@{name='anchor-bijection';value='A16.1/Appendix H mapping and generated envelope required independent verification';status='observed'};discriminator_after=[ordered]@{name='anchor-bijection';value='58x58 exact ID bijection and content-bound BootstrapWorkResult wrapper';status='verified'};uncertainty=@('No generated support or invalidation evidence exists; UNKNOWN and [] remain honest defaults.');unresolved_questions=@('Per-anchor owner/support/invalidation semantics remain unresolved and require a separately admitted work item.');proposed_effects=@('Future implementation may add independently verified support/invalidation evidence; no product or authority contract is changed here.');evidence_lineage=@($sources | ForEach-Object { [ordered]@{path=[string]$_.path;sha256=[string]$_.sha256;role=[string]$_.role} });schema_version='eliot-w1-04-implementation-v2';authority_status='EVIDENCE_ONLY';work_item_id='W1-04';provenance_mode='CONTENT_BOUND';source_documents=$sources;normalized_pair_sha256=$m.PairHash;generator_path=(Rel $GeneratorPath);generator_source_sha256=$m.GeneratorHash;verifier_path=(Rel $VerifierPath);verifier_source_sha256=$m.VerifierHash;result=[ordered]@{disposition='EVIDENCE_ONLY';anchors=58;bijection='58x58 exact ID bijection';support_default='UNKNOWN';invalidation_default=@();ordering='Architecture A16.1 canonical order';authority='generated projection only; no manual mapping source'};contract_challenge_path='swarm/challenges/W1-RESULT-ENVELOPE-CONTRACT.md';verification=@('generator self-test and deterministic generation','generator check of conformance and implementation result','independent verifier self-test and normal verification');residuals=@('No generated evidence exists; every support value remains UNKNOWN and every invalidation list remains empty.','Result remains EVIDENCE_ONLY as BootstrapWorkResult evidence; no terminal attempt is claimed.');authority_ceiling='EVIDENCE_ONLY; no terminal completion, release WIP, activation, or wave authorization.'}
    [ordered]@{schema_version='eliot.bootstrap-work-result.v1';authority_status='EVIDENCE_ONLY';work_item_id='W1-04';structured_result=$structured}
}
function AssertStable($m,$expected,$actual) { if ($actual -cne $expected) { throw 'generated conformance bytes are stale or non-deterministic' } }
function SelfTest {
    $m=Model; $one=Conformance $m; $two=Conformance $m; if($one -cne $two){throw 'determinism failed'}; if($one -notmatch 'schema_version = "eliot-conformance-v2"'){throw 'schema failed'}; if($one -match 'source_revision|worktree|timestamp'){throw 'volatile provenance leaked'}
    $esc=Toml ('q" \\ `t' + [char]9); if($esc -notmatch '\\\\|\\"|\\t'){throw 'TOML escaping failed'}
    $e=Envelope $m (TextSha $one); if($e.schema_version -ne 'eliot.bootstrap-work-result.v1' -or $e.authority_status -ne 'EVIDENCE_ONLY' -or $e.structured_result.disposition -notin @('completed','challenged','blocked','failed')){throw 'BootstrapWorkResult envelope failed'}; if($e.PSObject.Properties.Name -contains 'terminal_update' -or $e.PSObject.Properties.Name -contains 'attempt_id'){throw 'forbidden terminal fields leaked'}
    Write-Output 'SELFTEST PASS: 58x58 model, content-bound determinism, TOML escaping, evidence-only envelope, and envelope digest'
}
if($SelfTest){if($Check -or $PSBoundParameters.ContainsKey('OutputPath')){throw '-SelfTest cannot be combined with -Check or -OutputPath'}; SelfTest; exit 0}
if($Check -and $PSBoundParameters.ContainsKey('OutputPath')){throw '-Check rejects an alternate -OutputPath'}
$m=Model; $target=if($PSBoundParameters.ContainsKey('OutputPath')){[IO.Path]::GetFullPath($OutputPath)}else{$ConformancePath}; $expected=Conformance $m
if($Check){ if(-not(Test-Path $target)){throw "missing conformance artifact: $target"}; AssertStable $m $expected (Get-Content -LiteralPath $target -Raw); if(-not(Test-Path $ResultPath)){throw "missing result artifact: $ResultPath"}; if(-not(Test-Path $SupportingResultPath)){throw "missing supporting evidence artifact: $SupportingResultPath"}; $cHash=Sha $target; $e=Envelope $m $cHash; foreach($rp in @($ResultPath,$SupportingResultPath)){ $actual=(Get-Content -LiteralPath $rp -Raw|ConvertFrom-Json -Depth 30); if((Json $actual).TrimEnd("`r","`n") -ne (Json $e).TrimEnd("`r","`n")){throw "result artifact is stale or non-deterministic: $rp"} }; Write-Output 'CHECK PASS: conformance.toml, canonical W1-04 result, and supporting implementation evidence'; exit 0 }
$parent=Split-Path -Parent $target; if(-not(Test-Path $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null}; [IO.File]::WriteAllText($target,$expected,[Text.UTF8Encoding]::new($false)); if($target -eq $ConformancePath){$e=Envelope $m (Sha $target); $rp=Split-Path -Parent $ResultPath;if(-not(Test-Path $rp)){New-Item -ItemType Directory -Path $rp -Force|Out-Null};$bytes=(Json $e)+"`n";[IO.File]::WriteAllText($ResultPath,$bytes,[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($SupportingResultPath,$bytes,[Text.UTF8Encoding]::new($false));Write-Output 'GENERATED: docs/conformance.toml, canonical W1-04.json, and supporting W1-04-implementation.json (58 anchors)'}else{Write-Output "GENERATED: $target (58 anchors)"}
