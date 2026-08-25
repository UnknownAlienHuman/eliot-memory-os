[CmdletBinding()]
param([switch] $SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) { throw "REFUSAL_VERIFY_FAIL: $Message" }
function Sha([byte[]] $Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function ShaText([string] $Text) { Sha ([Text.Encoding]::UTF8.GetBytes($Text)) }
function Lines([string] $Text) { [regex]::Split($Text, "\r\n|\n|\r") }
function Assert-RepoRelative([string] $Path, [string] $Name) {
    $normalized = $Path.Replace('\\','/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or [IO.Path]::IsPathRooted($normalized) -or $normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.(?:/|$)') {
        Fail "$Name must be repository-relative: $Path"
    }
    return $normalized
}

function Mask([string] $Text) {
    # Independent lexer: this intentionally does not load or dot-source the
    # generator. Only code tokens survive, while line offsets are preserved.
    $a = $Text.ToCharArray(); $b = [char[]]$a.Clone(); $i = 0; $state = 0; $depth = 0; $hash = 0
    while ($i -lt $a.Length) {
        $x = $a[$i]
        if ($state -eq 1) { if ($x -eq "`r" -or $x -eq "`n") { $state = 0 } else { $b[$i] = ' ' }; $i++; continue }
        if ($state -eq 2) { if ($i + 1 -lt $a.Length -and $x -eq '/' -and $a[$i + 1] -eq '*') { $b[$i] = ' '; $b[$i + 1] = ' '; $depth++; $i += 2; continue }; if ($i + 1 -lt $a.Length -and $x -eq '*' -and $a[$i + 1] -eq '/') { $b[$i] = ' '; $b[$i + 1] = ' '; $depth--; $i += 2; if ($depth -eq 0) { $state = 0 }; continue }; if ($x -ne "`r" -and $x -ne "`n") { $b[$i] = ' ' }; $i++; continue }
        if ($state -eq 3) { $ok = $x -eq '"'; if ($ok) { for ($h = 1; $h -le $hash; $h++) { if ($i + $h -ge $a.Length -or $a[$i + $h] -ne '#') { $ok = $false; break } } }; if ($ok) { for ($j = 0; $j -le $hash; $j++) { $b[$i + $j] = ' ' }; $i += 1 + $hash; $state = 0; continue }; if ($x -ne "`r" -and $x -ne "`n") { $b[$i] = ' ' }; $i++; continue }
        if ($state -in @(4,5)) { if ($x -eq '\') { $b[$i] = ' '; if ($i + 1 -lt $a.Length) { $b[$i + 1] = ' '; $i += 2; continue } }; if (($state -eq 4 -and $x -eq '"') -or ($state -eq 5 -and $x -eq "'")) { $b[$i] = ' '; $state = 0; $i++; continue }; if ($x -ne "`r" -and $x -ne "`n") { $b[$i] = ' ' }; $i++; continue }
        if ($i + 1 -lt $a.Length -and $x -eq '/' -and $a[$i + 1] -eq '/') { $b[$i] = ' '; $b[$i + 1] = ' '; $state = 1; $i += 2; continue }; if ($i + 1 -lt $a.Length -and $x -eq '/' -and $a[$i + 1] -eq '*') { $b[$i] = ' '; $b[$i + 1] = ' '; $state = 2; $depth = 1; $i += 2; continue }
        $p = 0; if ($x -eq 'r') { $p = 1 } elseif ($x -eq 'b' -and $i + 1 -lt $a.Length -and $a[$i + 1] -eq 'r') { $p = 2 }; if ($p -gt 0) { $q = $i + $p; while ($q -lt $a.Length -and $a[$q] -eq '#') { $q++ }; if ($q -lt $a.Length -and $a[$q] -eq '"') { $hash = $q - $i - $p; for ($j = 0; $j -le $hash + $p; $j++) { $b[$i + $j] = ' ' }; $i = $q + 1; $state = 3; continue } }
        if ($x -eq '"') { $b[$i] = ' '; $state = 4; $i++; continue }; if ($x -eq "'" -and $i + 2 -lt $a.Length -and ($a[$i + 2] -eq "'" -or $a[$i + 1] -eq '\')) { $b[$i] = ' '; $state = 5; $i++; continue }; $i++
    }
    if ($state -in @(2,3,4,5)) { Fail "unterminated lexical region state=$state" }; -join $b
}

function Close([string] $Text, [int] $Open) {
    $pair = @{ '(' = ')'; '{' = '}'; '[' = ']' }; if (-not $pair.ContainsKey([string]$Text[$Open])) { return -1 }; $s = [Collections.Generic.Stack[char]]::new(); $s.Push([char]$Text[$Open])
    for ($i = $Open + 1; $i -lt $Text.Length; $i++) { $c = $Text[$i]; if ($pair.ContainsKey([string]$c)) { $s.Push([char]$c); continue }; if ($pair.Values -contains [string]$c) { if ($s.Count -eq 0 -or $c -ne $pair[[string]$s.Peek()]) { return -1 }; $null = $s.Pop(); if ($s.Count -eq 0) { return $i } } }; -1
}
function Starts([string] $Text) { $r = [Collections.Generic.List[int]]::new(); $r.Add(0); for ($i = 0; $i -lt $Text.Length; $i++) { if ($Text[$i] -eq "`n") { $r.Add($i + 1) } }; [int[]]$r }
function Num([int[]] $Starts, [int] $Offset) { $lo = 0; $hi = $Starts.Count - 1; while ($lo -le $hi) { $mid = [int](($lo + $hi) / 2); if ($Starts[$mid] -le $Offset) { $lo = $mid + 1 } else { $hi = $mid - 1 } }; $hi + 1 }

function AnchorSets([string] $Normative, [string] $Recovery) {
    $n=@{}; $fence=$null; $fenceLength=0
    foreach($line in (Lines $Normative)){if($null -ne $fence){if($line -match ('^[ \t]*'+[regex]::Escape([string]$fence)+'{'+$fenceLength+',}[ \t]*$')){$fence=$null};continue};$fm=[regex]::Match($line,'^[ \t]*(?<f>`{3,}|~{3,})');if($fm.Success){$fence=$fm.Groups['f'].Value[0];$fenceLength=$fm.Groups['f'].Value.Length;continue};$hm=[regex]::Match($line,'^[ \t]*#{1,6}[ \t]+(?<id>(?:A|I)[0-9]+(?:\.[0-9]+)+)(?:\.|[ \t])');if($hm.Success){$n[$hm.Groups['id'].Value]=$true}}
    $w=@{};foreach($m in [regex]::Matches($Recovery,'(?<![A-Za-z0-9_-])(?:W[0-9]+-[0-9]{2}|A-[0-9]{2})(?![A-Za-z0-9_-])')){$w[$m.Value]=$true};[pscustomobject]@{N=$n;W=$w}
}
function SpanAnchors([string] $Span,[object] $Anchors){$n=@([regex]::Matches($Span,'(?<![A-Za-z0-9_-])(?:A|I)[0-9]+(?:\.[0-9]+)+(?![A-Za-z0-9_-])') | ForEach-Object{$_.Value} | Where-Object{$Anchors.N.ContainsKey($_)} | Select-Object -Unique);$w=@([regex]::Matches($Span,'(?<![A-Za-z0-9_-])(?:W[0-9]+-[0-9]{2}|A-[0-9]{2})(?![A-Za-z0-9_-])') | ForEach-Object{$_.Value} | Where-Object{$Anchors.W.ContainsKey($_)} | Select-Object -Unique);[pscustomobject]@{Normative=if($n.Count){$n -join ';'}else{'UNKNOWN'};Work=if($w.Count){$w -join ';'}else{'UNKNOWN'}}}
function UnsupportedEvidence([string] $Span,[string] $File,[string] $Variant){if($Variant -in @('UnsupportedPlatform','UnsupportedProfile')){return 'variant-name'};if($Span -match '(?i)platform|profile|target_os|target_arch|host|capabilit'){return 'context'};if($File -match '(?i)platform|profile|host|capabilit'){return 'file-name'};$null}
function Semantics([object] $Site,[object] $Anchors){$variant=if($Site.family -like 'macro/*'){$Site.family.Substring(6).TrimEnd('!')}else{($Site.family -split '::')[-1]};$evidence=($Site.span -replace '\s+',' ').Trim();$unsupported=UnsupportedEvidence $Site.span $Site.file $variant;if($variant -in @('todo','unimplemented','Unimplemented','PlanGap')){$class='Unimplemented';$reason=if($variant -eq 'PlanGap'){'PlanGap is a missing-work contract, never Designed'}else{'explicit missing-work marker'}}elseif($variant -eq 'Unavailable'){$class='Unknown';$reason='runtime availability state is not proof of missing work and is not conflated with Unsupported'}elseif($variant -in @('Unsupported','UnsupportedPlatform','UnsupportedProfile')){if($null -ne $unsupported){$class='Designed';$reason="intentional unsupported platform/profile or capability refusal; evidence=$unsupported"}else{$class='Unknown';$reason='Unsupported constructor lacks platform/profile evidence; conservative Unknown'}}else{$class='Unknown';$reason='refusal-like syntax has no conservative contract classification'};$anchors=SpanAnchors $Site.span $Anchors;[pscustomobject]@{Classification=$class;Reason=$reason;Evidence=$evidence;Normative=$anchors.Normative;Work=$anchors.Work}}

function TestRanges([string] $Masked) {
    $ranges = [Collections.Generic.List[object]]::new(); $attributePattern = '#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|test)\s*\]'
    foreach ($attribute in [regex]::Matches($Masked, $attributePattern)) { $open = $Masked.IndexOf('{', $attribute.Index + $attribute.Length); if ($open -lt 0 -or $open -gt [Math]::Min($Masked.Length, $attribute.Index + 4096)) { continue }; $close = Close $Masked $open; if ($close -ge 0) { $ranges.Add([pscustomobject]@{Start=$attribute.Index;End=$close}) } }
    foreach ($module in [regex]::Matches($Masked, '\bmod\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{')) { if ($module.Groups['name'].Value -notmatch '(?i)^(?:test|tests|test_|.*_tests)$') { continue }; $open = $Masked.IndexOf('{',$module.Index+$module.Length-1); $close = Close $Masked $open; if ($close -ge 0) { $ranges.Add([pscustomobject]@{Start=$module.Index;End=$close}) } }
    @($ranges.ToArray())
}
function InTestRange([object[]] $Ranges, [int] $Offset) { foreach($r in $Ranges){if($Offset -ge $r.Start -and $Offset -le $r.End){return $true}};$false }
function InConsumer([string] $Masked, [int] $Start, [int] $End) {
    $prefix = $Masked.Substring(0,$Start); $invocations = [regex]::Matches($prefix,'(?<![A-Za-z0-9_])(?<name>matches|assert_matches|assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\(')
    for($n=$invocations.Count-1;$n -ge 0;$n--){$m=$invocations[$n];$open=$m.Index+$m.Length-1;$close=Close $Masked $open;if($close -lt $Start){continue};if($m.Groups['name'].Value -in @('matches','assert_matches','assert','assert_eq','assert_ne','debug_assert','debug_assert_eq','debug_assert_ne')){return $true};$depth=0;$comma=$false;for($i=$open+1;$i -lt $Start;$i++){$c=$Masked[$i];if($c -in @('(','{','[')){$depth++;continue};if($c -in @(')','}',']')){if($depth -gt 0){$depth--};continue};if($c -eq ',' -and $depth -eq 0){$comma=$true}};if($comma){return $true}}
    $prefixLets=[regex]::Matches($prefix,'\b(?:if\s+|while\s+)?let\b');if($prefixLets.Count -gt 0){$let=$prefixLets[$prefixLets.Count-1];$boundary=[Math]::Max($prefix.LastIndexOf(';'),[Math]::Max($prefix.LastIndexOf('{'),$prefix.LastIndexOf('}')));if($let.Index -ge $boundary -and $prefix.LastIndexOf('=') -lt $let.Index){return $true}}
    $depth=0;$limit=[Math]::Min($Masked.Length,$End+4096);for($i=$End+1;$i -lt $limit;$i++){$c=$Masked[$i];if($c -in @('(','{','[')){$depth++;continue};if($c -in @(')','}',']')){if($depth -gt 0){$depth--};continue};if($depth -eq 0){if($i+1 -lt $Masked.Length -and $Masked.Substring($i,2) -eq '=>'){return $true};if($c -eq ';'){return $false}}};$false
}

function SourceFiles([string] $Root) {
    $cached=@(& git -C $Root ls-files --cached -- '*.rs'); if($LASTEXITCODE -ne 0){Fail "git ls-files --cached exited $LASTEXITCODE"}
    $untracked=@(& git -C $Root ls-files --others --exclude-standard -- '*.rs'); if($LASTEXITCODE -ne 0){Fail "git ls-files --others exited $LASTEXITCODE"}
    $set=@{}; foreach($path in @($cached)+@($untracked)){if([string]::IsNullOrWhiteSpace([string]$path)){continue};$n=([string]$path).Replace('\','/');if($n.StartsWith('/') -or $n -match '(^|/)\.\.(?:/|$)' -or [IO.Path]::IsPathRooted($n)){Fail "source path is not repository-relative: $n"};$set[$n]=$true};$files=@($set.Keys);[Array]::Sort($files,[StringComparer]::Ordinal);[string[]]$files
}
function SourceManifest([string] $Root,[string[]]$Files){$entries=[Collections.Generic.List[object]]::new();$lines=[Collections.Generic.List[string]]::new();foreach($f0 in $Files){$f=Assert-RepoRelative $f0 'source path';$p=Join-Path $Root $f;if(-not(Test-Path $p -PathType Leaf)){Fail "source missing $f"};$d=Sha ([IO.File]::ReadAllBytes($p));$entries.Add([pscustomobject][ordered]@{path=$f;sha256=$d});$lines.Add("$f=$d")};[pscustomobject]@{Entries=@($entries.ToArray());Lines=@($lines.ToArray());Aggregate=ShaText (($lines -join "`n")+"`n")}}
function ContentProvenance([string]$Root,[string[]]$Files,[string[]]$NormativePaths,[string]$MechanismPath,[string]$RegistryPath){$s=SourceManifest $Root $Files;$lines=[Collections.Generic.List[string]]::new();$lines.Add('source-universe=git-cached-plus-nonignored-untracked-rust');foreach($l in $s.Lines){$lines.Add("source|$l")};foreach($p in $NormativePaths){$lines.Add("normative|$p|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $p))))")};$lines.Add("mechanism-review|$MechanismPath|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $MechanismPath))))");$lines.Add("registry-boundary|$RegistryPath|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $RegistryPath))))");[pscustomobject]@{Source=$s;Digest=ShaText (($lines -join "`n")+"`n")}}

function IndependentSites([string] $Root,[string[]]$Files) {
    $pattern = '(?<![A-Za-z0-9_])(?:(?<macro>todo|unimplemented)!\s*(?<open>\()|(?<type>(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9_]*)\s*::\s*(?<variant>PlanGap|Unsupported|UnsupportedPlatform|UnsupportedProfile|Unimplemented|Unavailable)\b)'; $sites = [Collections.Generic.List[object]]::new(); $files = @($Files)
    foreach ($f0 in [string[]]$files) { $f = $f0.Replace('\','/'); $raw = [IO.File]::ReadAllText((Join-Path $Root $f),[Text.UTF8Encoding]::new($false,$true)); $masked = Mask $raw; $testRanges=@(TestRanges $masked); $lineStarts = Starts $raw; foreach ($m in [regex]::Matches($masked,$pattern)) { $s = $m.Index; $e = $m.Index + $m.Length - 1; if ($m.Groups['macro'].Success) { $o = $m.Index + $m.Groups['open'].Index; $e = Close $masked $o; if ($e -lt 0) { Fail "unbalanced macro ${f}:$(Num $lineStarts $s)" } } else { $n = $m.Index + $m.Length; while ($n -lt $masked.Length -and [char]::IsWhiteSpace($masked[$n])) { $n++ }; if ($n -lt $masked.Length -and $masked[$n] -in @('(','{')) { $e = Close $masked $n; if ($e -lt 0) { Fail "unbalanced typed ${f}:$(Num $lineStarts $s)" } } }; if (-not $m.Groups['macro'].Success -and (InConsumer $masked $s $e)) { continue }; $line = Num $lineStarts $s; $endLine = Num $lineStarts $e; $span = $raw.Substring($s,$e-$s+1); $family = if ($m.Groups['macro'].Success) { "macro/$($m.Groups['macro'].Value)!" } else { "typed/$($m.Groups['type'].Value)::$($m.Groups['variant'].Value)" }; $column = $s - $lineStarts[$line-1] + 1; $id = 'R1-' + (ShaText "$f|$family|$line|$endLine|$column|$span").Substring(0,24); $scope=if($f -match '(^|/)(tests?|fixtures?)(/|$)' -or $f -match '(^|/)[^/]+_tests?\.rs$' -or (InTestRange $testRanges $s)){'test-only'}else{'production-or-mixed'}; $sites.Add([pscustomobject]@{id=$id;file=$f;line=$line;end=$endLine;column=$column;family=$family;scope=$scope;span=$span}) } }
    @($sites.ToArray() | Sort-Object file,line,end,family,id)
}

function ParseCsv([string] $Text) {
    if ($Text.Contains("`r") -or $Text.StartsWith([char]0xFEFF)) { Fail 'CSV must be UTF-8 without BOM and LF-only' }; $records = [Collections.Generic.List[object]]::new(); $row = [Collections.Generic.List[string]]::new(); $field = [Text.StringBuilder]::new(); $quoted = $false; $i = 0
    while ($i -lt $Text.Length) { $c = $Text[$i]; if ($quoted) { if ($c -eq '"') { if ($i + 1 -lt $Text.Length -and $Text[$i+1] -eq '"') { $null=$field.Append('"'); $i+=2; continue }; $quoted=$false; $i++; continue }; $null=$field.Append($c); $i++; continue }; if ($c -eq '"' -and $field.Length -eq 0) { $quoted=$true; $i++; continue }; if ($c -eq ',') { $row.Add($field.ToString()); $null=$field.Clear(); $i++; continue }; if ($c -eq "`n") { $row.Add($field.ToString()); $records.Add([string[]]$row); $null=$row.Clear(); $null=$field.Clear(); $i++; continue }; $null=$field.Append($c); $i++ }
    if ($quoted) { Fail 'unterminated CSV quote' }; if ($field.Length -gt 0 -or $row.Count -gt 0) { $row.Add($field.ToString()); $records.Add([string[]]$row) }; [pscustomobject]@{ Rows = $records.ToArray() }
}

$ExpectedCensusDefinition = 'Exact source universe is the sorted union of Git-cached and Git nonignored-untracked Rust files; exact lexical grammar: todo!(...) and unimplemented!(...) plus TypePath::{PlanGap,Unsupported,UnsupportedPlatform,UnsupportedProfile,Unimplemented,Unavailable} constructor/production occurrences; comments, strings, raw strings, chars masked; match arms, let/if-let/while-let patterns, matches!/assert_matches!/assert consumers and nested wrappers excluded; cfg(test)/#[test]/test-module ranges are test-only even inside src/lib.rs; test-only rows retained and scoped.'
$ExpectedGrammar = 'Rust lexical masking; macro=(todo|unimplemented)! ( balanced ); typed=(module::)*UpperIdent::(PlanGap|Unsupported|UnsupportedPlatform|UnsupportedProfile|Unimplemented|Unavailable) followed by balanced (), {} or unit production; consumer detection walks delimiter-aware matches!/assert_matches!/assert wrappers, let patterns, and match-arm arrows, including Err/Some/tuple/struct wrappers; cfg(test), #[test], and test-named module lexical ranges determine test-only scope.'
$ExpectedHistoricalNote = '1371 is non-binding because its source methodology is unavailable and was not reproduced; current count is independently generated.'
$ExpectedAnchorNote = 'UNKNOWN anchors are explicit evidence gaps: the source span contains no validated normative/work identifier; they are not inferred from the historical 1371 baseline.'
$ExpectedNormativePairPaths = @('docs/normative/ELIOT_ARCHITECTURE.md','docs/normative/ELIOT_IMPLEMENTATION.md')
$ExpectedCsvSchema = @('stable_id','file','line','end_line','scope','syntactic_contract_family','normative_anchor','work_item_anchor','classification','reason','evidence','source_sha256')
$ExpectedOutputPaths = @('swarm/inventory/refusals.csv','swarm/results/W1-02.json')
$ExpectedMechanismReviewPath = 'swarm/challenges/W1-02-MECHANISM-REVIEW.md'
$ExpectedRegistryBoundaryPath = 'swarm/challenges/W0-01-HONEST-EMPTY.md'
$ExpectedProofCeiling = 'Static source census and reproducibility only; no runtime capability proof.'

function AssertEnvelopePropertySet([object] $Actual, [object] $Expected, [string] $Name) {
    if ($null -eq $Actual -or $null -eq $Expected) { Fail "result envelope missing $Name" }
    $a = @($Actual.PSObject.Properties.Name | Sort-Object)
    $e = @($Expected.PSObject.Properties.Name | Sort-Object)
    if (($a -join '|') -cne ($e -join '|')) { Fail "result envelope property set mismatch $Name" }
}
function AssertEnvelopeScalar([object] $Actual, [object] $Expected, [string] $Name) {
    if ($null -eq $Actual -or [string]$Actual -cne [string]$Expected) { Fail "result envelope field mismatch $Name" }
}
function AssertEnvelopeArray([object] $Actual, [object] $Expected, [string] $Name) {
    if ($null -eq $Actual -or $null -eq $Expected) { Fail "result envelope array missing $Name" }
    $a = @($Actual); $e = @($Expected)
    if ($a.Count -ne $e.Count) { Fail "result envelope array length mismatch $Name" }
    for ($i = 0; $i -lt $e.Count; $i++) { AssertEnvelopeScalar $a[$i] $e[$i] "$Name[$i]" }
}
function AssertArtifactHashes([object] $Actual, [object] $Expected, [string] $Root) {
    if ($null -eq $Actual -or $null -eq $Expected -or @($Actual).Count -ne @($Expected).Count) { Fail 'result envelope array length mismatch provenance.artifact_hashes' }
    for ($i = 0; $i -lt @($Expected).Count; $i++) {
        AssertEnvelopePropertySet $Actual[$i] $Expected[$i] "provenance.artifact_hashes[$i]"
        AssertEnvelopeScalar $Actual[$i].path $Expected[$i].path "provenance.artifact_hashes[$i].path"
        AssertEnvelopeScalar $Actual[$i].sha256 $Expected[$i].sha256 "provenance.artifact_hashes[$i].sha256"
        $path = Assert-RepoRelative ([string]$Actual[$i].path) 'artifact path'
        if ($path -ceq 'swarm/results/W1-02.json') { Fail 'artifact_hashes must exclude the result itself' }
    }
}
function AssertResultEnvelope([object] $Actual, [object] $Expected) {
    AssertEnvelopePropertySet $Actual $Expected 'root'
    foreach ($name in @('schema_version','authority_status','work_item_id')) {
        AssertEnvelopeScalar $Actual.$name $Expected.$name $name
    }
    if ($Actual.PSObject.Properties['terminal_update']) { Fail 'terminal_update is forbidden without a genuine admitted attempt' }
    $Actual = $Actual.structured_result; $Expected = $Expected.structured_result
    AssertEnvelopePropertySet $Actual $Expected 'structured_result'
    foreach ($name in @('contract_status','census_definition','grammar','historical_baseline','historical_baseline_status','historical_baseline_note','current_row_count','source_file_count','source_digest_aggregate','normative_pair_sha256','proof_ceiling')) { AssertEnvelopeScalar $Actual.$name $Expected.$name $name }
    AssertEnvelopePropertySet $Actual.classification_counts $Expected.classification_counts 'classification_counts'
    foreach ($name in @('Designed','Unimplemented','Unknown')) { AssertEnvelopeScalar $Actual.classification_counts.$name $Expected.classification_counts.$name "classification_counts.$name" }
    AssertEnvelopePropertySet $Actual.anchor_uncertainty $Expected.anchor_uncertainty 'anchor_uncertainty'
    foreach ($name in @('unknown_normative_anchor_count','unknown_work_item_anchor_count','note')) { AssertEnvelopeScalar $Actual.anchor_uncertainty.$name $Expected.anchor_uncertainty.$name "anchor_uncertainty.$name" }
    AssertEnvelopeArray $Actual.normative_pair_paths $Expected.normative_pair_paths 'normative_pair_paths'
    AssertEnvelopeArray $Actual.csv_schema $Expected.csv_schema 'csv_schema'
    AssertEnvelopeArray $Actual.outputs $Expected.outputs 'outputs'
    foreach ($name in @('mechanism_review','registry_boundary')) {
        AssertEnvelopePropertySet $Actual.$name $Expected.$name $name
        foreach ($field in @('path','status','sha256')) { AssertEnvelopeScalar $Actual.$name.$field $Expected.$name.$field "$name.$field" }
    }
    AssertEnvelopePropertySet $Actual.provenance $Expected.provenance 'provenance'
    foreach ($name in @('schema_version','source_universe','source_manifest_sha256','content_digest')) { AssertEnvelopeScalar $Actual.provenance.$name $Expected.provenance.$name "provenance.$name" }
    if($null -eq $Actual.provenance.source_files -or @($Actual.provenance.source_files).Count -ne @($Expected.provenance.source_files).Count){Fail 'provenance.source_files path set mismatch'}
    for($i=0;$i -lt @($Expected.provenance.source_files).Count;$i++){AssertEnvelopePropertySet $Actual.provenance.source_files[$i] $Expected.provenance.source_files[$i] "provenance.source_files[$i]";AssertEnvelopeScalar $Actual.provenance.source_files[$i].path $Expected.provenance.source_files[$i].path "provenance.source_files[$i].path";AssertEnvelopeScalar $Actual.provenance.source_files[$i].sha256 $Expected.provenance.source_files[$i].sha256 "provenance.source_files[$i].sha256";Assert-RepoRelative ([string]$Actual.provenance.source_files[$i].path) 'source path' | Out-Null}
    AssertEnvelopeArray $Actual.provenance.normative_pair $Expected.provenance.normative_pair 'provenance.normative_pair'
    for($i=0;$i -lt @($Expected.provenance.normative_pair).Count;$i++){AssertEnvelopePropertySet $Actual.provenance.normative_pair[$i] $Expected.provenance.normative_pair[$i] "provenance.normative_pair[$i]";AssertEnvelopeScalar $Actual.provenance.normative_pair[$i].path $Expected.provenance.normative_pair[$i].path "provenance.normative_pair[$i].path";AssertEnvelopeScalar $Actual.provenance.normative_pair[$i].sha256 $Expected.provenance.normative_pair[$i].sha256 "provenance.normative_pair[$i].sha256"}
    foreach($name in @('mechanism_review','registry_boundary')){AssertEnvelopePropertySet $Actual.provenance.$name $Expected.provenance.$name "provenance.$name";AssertEnvelopeScalar $Actual.provenance.$name.path $Expected.provenance.$name.path "provenance.$name.path";AssertEnvelopeScalar $Actual.provenance.$name.sha256 $Expected.provenance.$name.sha256 "provenance.$name.sha256";Assert-RepoRelative ([string]$Actual.provenance.$name.path) "provenance.$name path" | Out-Null}
    AssertArtifactHashes $Actual.provenance.artifact_hashes $Expected.provenance.artifact_hashes $Root
    foreach($name in @('authority_status','disposition','discriminator_before','discriminator_after')){AssertEnvelopeScalar $Actual.$name $Expected.$name "structured_result.$name"}
    if($Actual.disposition -notin @('completed','challenged','blocked','failed')){Fail 'invalid Recovery structured disposition'}
    foreach($name in @('artifacts','evidence','uncertainty','unresolved_questions','proposed_effects')){AssertEnvelopeArray $Actual.$name $Expected.$name "structured_result.$name"}
    AssertEnvelopePropertySet $Actual.evidence_lineage $Expected.evidence_lineage 'structured_result.evidence_lineage'
    foreach($name in @('provenance','mechanism_review','registry_boundary','program_revision')){AssertEnvelopeScalar $Actual.evidence_lineage.$name $Expected.evidence_lineage.$name "structured_result.evidence_lineage.$name"}
}

function GetExpectedEnvelope([string] $Root, [object[]] $Rows, [object] $Counts, [int] $UnknownNorm, [int] $UnknownWork, [string[]] $SourceFiles, [string] $Aggregate, [string] $Normative) {
    $mechanismAbsolute = Join-Path $Root $ExpectedMechanismReviewPath
    $registryAbsolute = Join-Path $Root $ExpectedRegistryBoundaryPath
    if (-not (Test-Path $mechanismAbsolute -PathType Leaf) -or -not (Test-Path $registryAbsolute -PathType Leaf)) { Fail 'required challenge linkage file missing' }
    $p=ContentProvenance $Root $SourceFiles $ExpectedNormativePairPaths $ExpectedMechanismReviewPath $ExpectedRegistryBoundaryPath
    $manifest=@($p.Source.Entries | ForEach-Object {[pscustomobject][ordered]@{path=$_.path;sha256=$_.sha256}})
    $mechanismSha=Sha ([IO.File]::ReadAllBytes($mechanismAbsolute));$registrySha=Sha ([IO.File]::ReadAllBytes($registryAbsolute))
    $rich = [pscustomobject][ordered]@{
        schema_version = 'eliot-refusal-inventory-v2'
        contract_status = 'CONTRACT_CHALLENGE'
        work_item_id = 'W1-02'
        census_definition = $ExpectedCensusDefinition
        grammar = $ExpectedGrammar
        historical_baseline = 1371
        historical_baseline_status = 'CONTRACT_CHALLENGE_UNKNOWN_BASELINE'
        historical_baseline_note = $ExpectedHistoricalNote
        current_row_count = $Rows.Count
        classification_counts = [pscustomobject][ordered]@{ Designed = [int]$Counts.Designed; Unimplemented = [int]$Counts.Unimplemented; Unknown = [int]$Counts.Unknown }
        anchor_uncertainty = [pscustomobject][ordered]@{ unknown_normative_anchor_count = $UnknownNorm; unknown_work_item_anchor_count = $UnknownWork; note = $ExpectedAnchorNote }
        source_file_count = $SourceFiles.Count
        source_digest_aggregate = $Aggregate
        normative_pair_sha256 = ShaText $Normative
        normative_pair_paths = $ExpectedNormativePairPaths
        csv_schema = $ExpectedCsvSchema
        outputs = $ExpectedOutputPaths
        proof_ceiling = $ExpectedProofCeiling
        mechanism_review = [pscustomobject][ordered]@{ path = $ExpectedMechanismReviewPath; status = 'MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS'; sha256 = Sha ([IO.File]::ReadAllBytes($mechanismAbsolute)) }
        registry_boundary = [pscustomobject][ordered]@{ path = $ExpectedRegistryBoundaryPath; status = 'HONEST_EMPTY_BOUNDARY_ACCEPTED'; sha256 = Sha ([IO.File]::ReadAllBytes($registryAbsolute)) }
        provenance = [pscustomobject][ordered]@{ schema_version='eliot-content-provenance-v1'; source_universe='git-cached-plus-nonignored-untracked-rust'; source_files=$manifest; source_manifest_sha256=$p.Source.Aggregate; normative_pair=@($ExpectedNormativePairPaths|ForEach-Object{[pscustomobject][ordered]@{path=$_;sha256=Sha ([IO.File]::ReadAllBytes((Join-Path $Root $_)))}}); mechanism_review=[pscustomobject][ordered]@{path=$ExpectedMechanismReviewPath;sha256=$mechanismSha}; registry_boundary=[pscustomobject][ordered]@{path=$ExpectedRegistryBoundaryPath;sha256=$registrySha}; artifact_hashes=@($ExpectedOutputPaths|Where-Object { $_ -cne 'swarm/results/W1-02.json' }|ForEach-Object{[pscustomobject][ordered]@{path=$_;sha256=Sha ([IO.File]::ReadAllBytes((Join-Path $Root $_)))}}|Sort-Object path -Culture ''); content_digest=$p.Digest }
        authority_status = 'EVIDENCE_ONLY'
        disposition = 'challenged'
        artifacts=@($ExpectedOutputPaths)
        evidence=@('pwsh -NoProfile -File scripts/gen-refusals.ps1 -Check','pwsh -NoProfile -File scripts/verify-refusals.ps1 -SelfTest','pwsh -NoProfile -File scripts/verify-refusals.ps1')
        discriminator_before='Prior result bound census provenance to mutable HEAD/worktree state and used a tracked-only source universe.'
        discriminator_after='Both canonical outputs are regenerated from the sorted cached-plus-nonignored-untracked Rust universe and content-bound provenance; no HEAD/worktree state is serialized.'
        uncertainty=@('Historical 1371 baseline has no reproducible source methodology and remains non-binding.','Static census does not prove runtime capability.')
        unresolved_questions=@('Whether UNKNOWN rows can later be promoted requires a separate source-backed contract decision.')
        proposed_effects=@('Do not write UNKNOWN-anchor rows into docs/UNIMPLEMENTED.md; preserve W0-01 honest-empty boundary.')
        evidence_lineage=[pscustomobject][ordered]@{provenance='provenance.content_digest';mechanism_review=$ExpectedMechanismReviewPath;registry_boundary=$ExpectedRegistryBoundaryPath;program_revision='swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'}
    }
    [pscustomobject][ordered]@{schema_version='eliot.bootstrap-work-result.v1';authority_status='EVIDENCE_ONLY';work_item_id='W1-02';structured_result=$rich}
}

function SelfTest {
    $fixture = @'
// todo!("comment")
let s = "Error::PlanGap";
let r = r#"unimplemented!(raw)"#;
todo!("real");
let made = Err(Error::PlanGap("missing"));
match made { Error::PlanGap(_) => {} }
assert!(matches!(made, Error::Unavailable));
let profile = Error::UnsupportedProfile("profile");
#[cfg(test)]
mod tests {
    #[test]
    fn wrapped_consumers() {
        assert_matches!(Some(Err(Error::UnsupportedProfile(_))), Some(Err(Error::UnsupportedProfile(_))));
        if let Some(Err(Error::UnsupportedProfile(_))) = None { }
        while let Some(Err(Error::UnsupportedProfile(_))) = None { }
        match None { Some((Err(Error::UnsupportedProfile(_)), _)) => {} _ => {} }
    }
}
'@
    $semanticAnchors = AnchorSets "## A0.8. synthetic`n" "W1-02"; $semanticFixture = [pscustomobject]@{family='typed/Error::PlanGap';span='Error::PlanGap(A0.8 W1-02)';file='src/lib.rs'}; $semantic = Semantics $semanticFixture $semanticAnchors; if($semantic.Classification -ne 'Unimplemented' -or $semantic.Normative -ne 'A0.8' -or $semantic.Work -ne 'W1-02' -or $semantic.Evidence -ne 'Error::PlanGap(A0.8 W1-02)'){Fail 'self-test semantic recomputation failed'}
    $masked = Mask $fixture; if (@([regex]::Matches($masked,'todo!')).Count -ne 1) { Fail 'self-test lexical masking failed' }; $ranges=@(TestRanges $masked); $profileMatches=[regex]::Matches($masked,'Error::UnsupportedProfile'); $profileOffset=$profileMatches[$profileMatches.Count-1].Index; if($ranges.Count -lt 1 -or -not(InTestRange $ranges $profileOffset)){Fail 'self-test cfg(test) range did not cover nested test module'}; $sites = @(); $pattern='(?<![A-Za-z0-9_])(?:(?<macro>todo|unimplemented)!\s*(?<open>\()|(?<type>(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9_]*)\s*::\s*(?<variant>PlanGap|Unsupported|UnsupportedPlatform|UnsupportedProfile|Unimplemented|Unavailable)\b)'; $consumerFlags=@(); foreach($m in [regex]::Matches($masked,$pattern)){ $e=$m.Index+$m.Length-1; if($m.Groups['macro'].Success){$e=Close $masked ($m.Index+$m.Groups['open'].Index)} else { $n=$m.Index+$m.Length; while($n -lt $masked.Length -and [char]::IsWhiteSpace($masked[$n])){$n++}; if($n -lt $masked.Length -and $masked[$n] -in @('(','{')){$e=Close $masked $n} }; if(-not $m.Groups['macro'].Success){$consumerFlags += (InConsumer $masked $m.Index $e)}; if($m.Groups['macro'].Success -or -not(InConsumer $masked $m.Index $e)){$sites += $m} }; if($sites.Count -ne 3){Fail "self-test occurrence filtering expected 3 got $($sites.Count): $($sites.Value -join ',') flags=$($consumerFlags -join ',')"}; if((ShaText 'a') -eq (ShaText 'b')){Fail 'self-test digest tamper check failed'}; $parsedFixture = @((ParseCsv ('"a","b"' + "`n")).Rows); if($parsedFixture.Count -ne 1){Fail "self-test CSV parser failed count=$($parsedFixture.Count)"}; $tamperCaught=$false; try { ParseCsv ('"unterminated' + "`n") | Out-Null } catch { $tamperCaught=$true }; if(-not $tamperCaught){Fail 'self-test malformed CSV tamper was accepted'}
    $baseEnvelope = [pscustomobject][ordered]@{schema_version='eliot.bootstrap-work-result.v1';authority_status='EVIDENCE_ONLY';work_item_id='W1-02';structured_result=[pscustomobject][ordered]@{schema_version='eliot-refusal-inventory-v2';authority_status='EVIDENCE_ONLY';contract_status='CONTRACT_CHALLENGE';work_item_id='W1-02';census_definition=$ExpectedCensusDefinition;grammar=$ExpectedGrammar;historical_baseline=1371;historical_baseline_status='CONTRACT_CHALLENGE_UNKNOWN_BASELINE';historical_baseline_note=$ExpectedHistoricalNote;current_row_count=744;classification_counts=[pscustomobject][ordered]@{Designed=113;Unimplemented=119;Unknown=512};anchor_uncertainty=[pscustomobject][ordered]@{unknown_normative_anchor_count=737;unknown_work_item_anchor_count=714;note=$ExpectedAnchorNote};source_file_count=544;source_digest_aggregate=('a'*64);normative_pair_sha256=('b'*64);normative_pair_paths=$ExpectedNormativePairPaths;csv_schema=$ExpectedCsvSchema;outputs=$ExpectedOutputPaths;proof_ceiling=$ExpectedProofCeiling;mechanism_review=[pscustomobject][ordered]@{path=$ExpectedMechanismReviewPath;status='MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS';sha256=('c'*64)};registry_boundary=[pscustomobject][ordered]@{path=$ExpectedRegistryBoundaryPath;status='HONEST_EMPTY_BOUNDARY_ACCEPTED';sha256=('d'*64)};provenance=[pscustomobject][ordered]@{schema_version='eliot-content-provenance-v1';source_universe='git-cached-plus-nonignored-untracked-rust';source_files=@([pscustomobject][ordered]@{path='src/a.rs';sha256=('e'*64)});source_manifest_sha256=('a'*64);normative_pair=@([pscustomobject][ordered]@{path=$ExpectedNormativePairPaths[0];sha256=('f'*64)},[pscustomobject][ordered]@{path=$ExpectedNormativePairPaths[1];sha256=('g'*64)});mechanism_review=[pscustomobject][ordered]@{path=$ExpectedMechanismReviewPath;sha256=('c'*64)};registry_boundary=[pscustomobject][ordered]@{path=$ExpectedRegistryBoundaryPath;sha256=('d'*64)};artifact_hashes=@([pscustomobject][ordered]@{path='swarm/inventory/refusals.csv';sha256=('i'*64)});content_digest=('h'*64)};disposition='challenged';artifacts=@($ExpectedOutputPaths);evidence=@('proof');discriminator_before='before';discriminator_after='after';uncertainty=@('u');unresolved_questions=@('q');proposed_effects=@('p');evidence_lineage=[pscustomobject][ordered]@{provenance='provenance.content_digest';mechanism_review=$ExpectedMechanismReviewPath;registry_boundary=$ExpectedRegistryBoundaryPath}}}
    $baseEnvelope.structured_result.evidence_lineage | Add-Member -NotePropertyName program_revision -NotePropertyValue 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'
    $envelopeMutations = @(
        [pscustomobject]@{Name='schema';Mutation={param($x)$x.schema_version='tampered'}}
        [pscustomobject]@{Name='authority';Mutation={param($x)$x.authority_status='tampered'}}
        [pscustomobject]@{Name='contract';Mutation={param($x)$x.structured_result.contract_status='tampered'}}
        [pscustomobject]@{Name='work-item';Mutation={param($x)$x.work_item_id='tampered'}}
        [pscustomobject]@{Name='census-definition';Mutation={param($x)$x.structured_result.census_definition='tampered'}}
        [pscustomobject]@{Name='grammar';Mutation={param($x)$x.structured_result.grammar='tampered'}}
        [pscustomobject]@{Name='historical-baseline';Mutation={param($x)$x.structured_result.historical_baseline=0}}
        [pscustomobject]@{Name='historical-status';Mutation={param($x)$x.structured_result.historical_baseline_status='tampered'}}
        [pscustomobject]@{Name='historical-note';Mutation={param($x)$x.structured_result.historical_baseline_note='tampered'}}
        [pscustomobject]@{Name='row-count';Mutation={param($x)$x.structured_result.current_row_count=0}}
        [pscustomobject]@{Name='classification-counts';Mutation={param($x)$x.structured_result.classification_counts.Designed=0}}
        [pscustomobject]@{Name='anchor-uncertainty';Mutation={param($x)$x.structured_result.anchor_uncertainty.unknown_normative_anchor_count=0}}
        [pscustomobject]@{Name='anchor-work-uncertainty';Mutation={param($x)$x.structured_result.anchor_uncertainty.unknown_work_item_anchor_count=0}}
        [pscustomobject]@{Name='anchor-note';Mutation={param($x)$x.structured_result.anchor_uncertainty.note='tampered'}}
        [pscustomobject]@{Name='source-file-count';Mutation={param($x)$x.structured_result.source_file_count=0}}
        [pscustomobject]@{Name='source-digest';Mutation={param($x)$x.structured_result.source_digest_aggregate='tampered'}}
        [pscustomobject]@{Name='normative-pair';Mutation={param($x)$x.structured_result.normative_pair_sha256='tampered'}}
        [pscustomobject]@{Name='normative-pair-paths';Mutation={param($x)$x.structured_result.normative_pair_paths[0]='tampered'}}
        [pscustomobject]@{Name='csv-schema';Mutation={param($x)$x.structured_result.csv_schema[0]='tampered'}}
        [pscustomobject]@{Name='outputs';Mutation={param($x)$x.structured_result.outputs[0]='tampered'}}
        [pscustomobject]@{Name='proof-ceiling';Mutation={param($x)$x.structured_result.proof_ceiling='tampered'}}
        [pscustomobject]@{Name='mechanism-review-link';Mutation={param($x)$x.structured_result.mechanism_review.path='tampered'}}
        [pscustomobject]@{Name='registry-boundary-link';Mutation={param($x)$x.structured_result.registry_boundary.path='tampered'}}
        [pscustomobject]@{Name='mechanism-review-status';Mutation={param($x)$x.structured_result.mechanism_review.status='tampered'}}
        [pscustomobject]@{Name='mechanism-review-digest';Mutation={param($x)$x.structured_result.mechanism_review.sha256='tampered'}}
        [pscustomobject]@{Name='registry-boundary-status';Mutation={param($x)$x.structured_result.registry_boundary.status='tampered'}}
        [pscustomobject]@{Name='registry-boundary-digest';Mutation={param($x)$x.structured_result.registry_boundary.sha256='tampered'}}
        [pscustomobject]@{Name='provenance-universe';Mutation={param($x)$x.structured_result.provenance.source_universe='tampered'}}
        [pscustomobject]@{Name='provenance-source-path';Mutation={param($x)$x.structured_result.provenance.source_files[0].path='tampered'}}
        [pscustomobject]@{Name='provenance-source-file';Mutation={param($x)$x.structured_result.provenance.source_files[0].sha256='tampered'}}
        [pscustomobject]@{Name='provenance-source-extra';Mutation={param($x)$x.structured_result.provenance.source_files[0]|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='provenance-source-remove';Mutation={param($x)$null=$x.structured_result.provenance.source_files[0].PSObject.Properties.Remove('sha256')}}
        [pscustomobject]@{Name='provenance-manifest-digest';Mutation={param($x)$x.structured_result.provenance.source_manifest_sha256='tampered'}}
        [pscustomobject]@{Name='provenance-normative-path';Mutation={param($x)$x.structured_result.provenance.normative_pair[0].path='tampered'}}
        [pscustomobject]@{Name='provenance-normative-digest';Mutation={param($x)$x.structured_result.provenance.normative_pair[0].sha256='tampered'}}
        [pscustomobject]@{Name='provenance-mechanism-digest';Mutation={param($x)$x.structured_result.provenance.mechanism_review.sha256='tampered'}}
        [pscustomobject]@{Name='provenance-registry-digest';Mutation={param($x)$x.structured_result.provenance.registry_boundary.sha256='tampered'}}
        [pscustomobject]@{Name='provenance-artifact-digest';Mutation={param($x)$x.structured_result.provenance.artifact_hashes[0].sha256='tampered'}}
        [pscustomobject]@{Name='provenance-artifact-extra';Mutation={param($x)$x.structured_result.provenance.artifact_hashes[0]|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='provenance-content-digest';Mutation={param($x)$x.structured_result.provenance.content_digest='tampered'}}
        [pscustomobject]@{Name='terminal-update-added';Mutation={param($x)$x|Add-Member -NotePropertyName terminal_update -NotePropertyValue ([pscustomobject]@{})}}
        [pscustomobject]@{Name='structured-disposition';Mutation={param($x)$x.structured_result.disposition='invalid'}}
        [pscustomobject]@{Name='structured-artifact';Mutation={param($x)$x.structured_result.artifacts[0]='tampered'}}
        [pscustomobject]@{Name='structured-evidence';Mutation={param($x)$x.structured_result.evidence[0]='tampered'}}
        [pscustomobject]@{Name='structured-before';Mutation={param($x)$x.structured_result.discriminator_before='tampered'}}
        [pscustomobject]@{Name='structured-after';Mutation={param($x)$x.structured_result.discriminator_after='tampered'}}
        [pscustomobject]@{Name='structured-uncertainty';Mutation={param($x)$x.structured_result.uncertainty[0]='tampered'}}
        [pscustomobject]@{Name='structured-unresolved';Mutation={param($x)$x.structured_result.unresolved_questions[0]='tampered'}}
        [pscustomobject]@{Name='structured-effects';Mutation={param($x)$x.structured_result.proposed_effects[0]='tampered'}}
        [pscustomobject]@{Name='structured-lineage';Mutation={param($x)$x.structured_result.evidence_lineage.provenance='tampered'}}
        [pscustomobject]@{Name='structured-lineage-mechanism';Mutation={param($x)$x.structured_result.evidence_lineage.mechanism_review='tampered'}}
        [pscustomobject]@{Name='structured-lineage-extra';Mutation={param($x)$x.structured_result.evidence_lineage|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
    )
    foreach($mutation in $envelopeMutations){$copy=$baseEnvelope|ConvertTo-Json -Depth 10|ConvertFrom-Json;& $mutation.Mutation $copy;$caught=$false;try{AssertResultEnvelope $copy $baseEnvelope}catch{$caught=$true};if(-not $caught){Fail "result envelope tamper accepted category=$($mutation.Name)"}}
    Write-Output "REFUSAL_VERIFY_SELF_TEST: PASS envelope_tamper_categories=$($envelopeMutations.Count)"
}

try {
    if ($SelfTest) { SelfTest; exit 0 }
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $csvPath = Join-Path $root 'swarm/inventory/refusals.csv'; $resultPath = Join-Path $root 'swarm/results/W1-02.json'
    if (-not (Test-Path $csvPath -PathType Leaf) -or -not (Test-Path $resultPath -PathType Leaf)) { Fail 'canonical output missing' }
    $strict = [Text.UTF8Encoding]::new($false,$true)
    $header=@('stable_id','file','line','end_line','scope','syntactic_contract_family','normative_anchor','work_item_anchor','classification','reason','evidence','source_sha256')
    $records = @((ParseCsv ([IO.File]::ReadAllText($csvPath,$strict))).Rows)
    if ($records.Count -lt 2 -or ($records[0] -join ',') -ne ($header -join ',')) { Fail "CSV header/empty inventory mismatch records=$($records.Count)" }
    $normative = [IO.File]::ReadAllText((Join-Path $root 'docs/normative/ELIOT_ARCHITECTURE.md'),$strict) + "`n" + [IO.File]::ReadAllText((Join-Path $root 'docs/normative/ELIOT_IMPLEMENTATION.md'),$strict)
    $recovery = [IO.File]::ReadAllText((Join-Path $root 'docs/tasks/RECOVERY_PROGRAM_v1.md'),$strict); $anchorSets = AnchorSets $normative $recovery
    $sourceFiles = SourceFiles $root
    $expected = @(IndependentSites $root $sourceFiles); $rows = @(); $seen=@{}; $counts=@{Designed=0;Unimplemented=0;Unknown=0}; $unknownNorm=0; $unknownWork=0
    for($i=1;$i -lt $records.Count;$i++) {
        $r=[string[]]$records[$i]; if($r.Count -ne 12){Fail "CSV row $i has $($r.Count) fields"}; if($r[0] -notmatch '^R1-[0-9a-f]{24}$' -or $seen.ContainsKey($r[0])){Fail "invalid/duplicate stable id row $i"}; $seen[$r[0]]=1
        $e=$expected[$i-1]; if($null -eq $e){Fail "CSV has extra row $i"}; if($r[0] -ne $e.id -or $r[1] -ne $e.file -or [int]$r[2] -ne $e.line -or [int]$r[3] -ne $e.end -or $r[4] -ne $e.scope -or $r[5] -ne $e.family){Fail "row $i does not match independent constructor census"}
        $sem=Semantics $e $anchorSets; if($r[6] -ne $sem.Normative -or $r[7] -ne $sem.Work -or $r[8] -ne $sem.Classification -or $r[9] -ne $sem.Reason -or $r[10] -ne $sem.Evidence){Fail "semantic field tamper/drift row $i $($e.file):$($e.line)"}
        if($r[6] -eq 'UNKNOWN'){$unknownNorm++}; if($r[7] -eq 'UNKNOWN'){$unknownWork++}; if($r[4] -notin @('test-only','production-or-mixed')){Fail "invalid scope row $i"}; if($r[8] -notin @('Designed','Unimplemented','Unknown')){Fail "invalid classification row $i"}
        $source=Join-Path $root $r[1]; if(-not(Test-Path $source -PathType Leaf)){Fail "missing source $($r[1])"}; if((Sha ([IO.File]::ReadAllBytes($source))) -cne $r[11]){Fail "source digest drift $($r[1])"}; $counts[$r[8]]++; $rows += ,$r
    }
    if($rows.Count -ne $expected.Count){Fail "independent constructor census=$($expected.Count) CSV=$($rows.Count)"}; $sort=@($rows|ForEach-Object{"$($_[1])|$('{0:D8}' -f [int]$_[2])|$('{0:D8}' -f [int]$_[3])|$($_[5])|$($_[0])"}); if(($sort -join "`n") -cne ((@($sort|Sort-Object))-join "`n")){Fail 'CSV rows are not stable sorted'}
    $manifest=SourceManifest $root $sourceFiles; $aggregate=$manifest.Aggregate; $result=Get-Content $resultPath -Raw|ConvertFrom-Json
    $expectedEnvelope = GetExpectedEnvelope $root $rows $counts $unknownNorm $unknownWork ([string[]]$sourceFiles) $aggregate $normative
    AssertResultEnvelope $result $expectedEnvelope
    Write-Output "REFUSAL_VERIFY: PASS rows=$($rows.Count) Designed=$($counts.Designed) Unimplemented=$($counts.Unimplemented) Unknown=$($counts.Unknown) UNKNOWN_ANCHORS(normative=$unknownNorm,work=$unknownWork)"
} catch { Write-Error $_.Exception.Message; exit 1 }
