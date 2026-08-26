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
$BindingDecisionPath = Join-Path $RepoRoot 'swarm\challenges\W1-04-ANCHOR-SYMBOL-INDEX.md'
$GeneratorPath = Join-Path $RepoRoot 'scripts\gen-conformance.ps1'
$VerifierPath = Join-Path $RepoRoot 'scripts\verify-conformance.ps1'
$ConformancePath = Join-Path $RepoRoot 'docs\conformance.toml'
$ResultPath = Join-Path $RepoRoot 'swarm\results\W1-04.json'
$SupportingResultPath = Join-Path $RepoRoot 'swarm\results\W1-04-implementation.json'
$ModulesPath = Join-Path $RepoRoot 'swarm\inventory\modules.json'
$RefusalsPath = Join-Path $RepoRoot 'swarm\inventory\refusals.csv'
$GraphArtifactPath = Join-Path $RepoRoot '.codebase-memory\artifact.json'
$GraphDatabasePath = Join-Path $RepoRoot '.codebase-memory\graph.db.zst'
$ExpectedAnchorCount = 58

function Rel([string]$Path) { ([IO.Path]::GetRelativePath($RepoRoot, $Path)).Replace('\','/') }
function Sha([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant() }
function TextSha([string]$Text) { $h=[Security.Cryptography.SHA256]::Create(); try { ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToUpperInvariant() } finally { $h.Dispose() } }
function Norm([string]$Value) { if ($null -eq $Value) { return '' }; [regex]::Replace($Value.Trim(), '[\t\r\n ]+', ' ') }
function Toml([string]$Value) { $s=if($null -eq $Value){''}else{[string]$Value}; '"'+$s.Replace('\','\\').Replace('"','\"').Replace("`r",'\r').Replace("`n",'\n').Replace("`t",'\t')+'"' }
function TomlArray($Values) { if ($null -eq $Values -or @($Values).Count -eq 0) { return '[]' }; '['+((@($Values)|ForEach-Object { Toml ([string]$_) }) -join ', ')+']' }
function Read-Utf8([string]$Path) { $enc=[Text.UTF8Encoding]::new($false,$true); [IO.File]::ReadAllText($Path,$enc) }

function Rows([string]$Text,[string]$Start,[string]$End,[string]$Header,[string]$Kind) {
    $inside=$false;$fenced=$false;$head=$false;$sep=$false;$out=[Collections.Generic.List[object]]::new()
    foreach($line in ($Text -split "`r?`n")) {
        if($line -match '^\s*```'){$fenced=-not$fenced;continue};if($fenced){continue}
        if(-not$inside){if($line -match $Start){$inside=$true};continue};if($line -match $End){break}
        if(-not$head){if([string]::IsNullOrWhiteSpace($line)){continue};if($line -notmatch $Header){continue};$head=$true;continue}
        if(-not$sep){if($line -match '^\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*$'){$sep=$true;continue};if(-not[string]::IsNullOrWhiteSpace($line)){throw "$Kind table separator is malformed"};continue}
        if([string]::IsNullOrWhiteSpace($line)){continue}
        if($Kind -eq 'architecture' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(Invariant|Contract)\s*\|\s*(.*?)\s*\|\s*$'){$out.Add([pscustomobject]@{Id=$Matches[1];Class=$Matches[2];Decision=$Matches[3].Trim()});continue}
        if($Kind -eq 'implementation' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$'){$out.Add([pscustomobject]@{Id=$Matches[1];ScopeOwner=$Matches[2].Trim();Proof=$Matches[3].Trim()});continue}
        if($line -match '^\|'){throw "$Kind table contains an invalid row: $line"}
    }
    if(-not$inside -or -not$head -or -not$sep){throw "$Kind table headings/header were not found"};$out.ToArray()
}
function AssertPair($A,$I) {
    if(@($A).Count-ne$ExpectedAnchorCount -or @($I).Count-ne$ExpectedAnchorCount){throw "A16.1 and Appendix H must each contain exactly $ExpectedAnchorCount rows"}
    $ai=@($A|ForEach-Object Id);$ii=@($I|ForEach-Object Id)
    if(@($ai|Sort-Object -Unique).Count-ne$ExpectedAnchorCount -or @($ii|Sort-Object -Unique).Count-ne$ExpectedAnchorCount){throw 'duplicate architecture IDs'}
    $missing=@($ai|Where-Object{$_-notin$ii});$extra=@($ii|Where-Object{$_-notin$ai});if($missing.Count-or$extra.Count){throw "anchor sets differ: missing=$($missing-join ',') extra=$($extra-join ',')"}
}
function Scope([string]$Value) { $s=Norm $Value;$h=$s;if($s -match '^(.*?);\s*([^;]+)$'){$h=$Matches[1].Trim()};[pscustomobject]@{Handles=@($h-split '\s*,\s*'|ForEach-Object{$_.Trim().Trim('`')}|Where-Object{$_})} }

function RustLex([string]$Text,[string]$Relative) {
    $text=$Text.Replace("`r`n","`n").Replace("`r","`n");$reservedCount=[regex]::Matches($text,'ELIOT_ARCH_OWNER').Count;$a=$text.ToCharArray();$n=$a.Length;$markers=[Collections.Generic.List[object]]::new();$outerDocs=[Collections.Generic.List[object]]::new();$charPattern=[regex]::new("^(?:b)?'(?:\\(?:[nrt0\\'`"]|x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]{1,6}\})|[^\\'`r`n])'");$i=0;$line=1;$blockDepth=0
    while($i-lt$n){$c=$a[$i];$next=if($i+1-lt$n){$a[$i+1]}else{[char]0}
        if($c-eq'/'-and$next-eq'/'){$end=$text.IndexOf("`n",$i);if($end-lt0){$end=$n};$comment=$text.Substring($i,$end-$i);if($comment-match'^///(?!/)'){$outerDocs.Add([pscustomobject]@{Start=$i;End=$end})};if($comment.Contains('ELIOT_ARCH_OWNER')){$lineStart=$text.LastIndexOf("`n",[Math]::Max(0,$i-1))+1;$prefix=$text.Substring($lineStart,$i-$lineStart);if($prefix-notmatch '^\s*$'){throw "ambiguous source marker syntax: ${Relative}:$line"};$match=[regex]::Match($comment,'^///\s*ELIOT_ARCH_OWNER:\s*(ARCH-[A-Z]+-[0-9]+)\s*$');if(-not$match.Success){throw "ambiguous source marker syntax: ${Relative}:$line"};$markers.Add([pscustomobject]@{Anchor=$match.Groups[1].Value;Offset=$i;Line=$line})};for($k=$i;$k-lt$end;$k++){$a[$k]=' '};$i=$end;continue}
        if($c-eq'/'-and$next-eq'*'){$start=$i;$isOuterDoc=($i+2-lt$n-and$a[$i+2]-eq'*'-and($i+3-ge$n-or$a[$i+3]-ne'*'));$blockDepth=1;$a[$i]=' ';$a[$i+1]=' ';$i+=2;while($i-lt$n-and$blockDepth-gt0){$x=$a[$i];$y=if($i+1-lt$n){$a[$i+1]}else{[char]0};if($x-eq'/'-and$y-eq'*'){$blockDepth++;$a[$i]=' ';$a[$i+1]=' ';$i+=2;continue};if($x-eq'*'-and$y-eq'/'){$blockDepth--;$a[$i]=' ';$a[$i+1]=' ';$i+=2;continue};if($x-eq"`n"){$line++}else{$a[$i]=' '};$i++};if($isOuterDoc){$outerDocs.Add([pscustomobject]@{Start=$start;End=$i})};continue}
        $rawStart=-1;$hashes=0;if($c-eq'r'){$rawStart=$i;$j=$i+1}elseif($c-eq'b'-and$next-eq'r'){$rawStart=$i;$j=$i+2}else{$j=-1};if($j-ge0){while($j-lt$n-and$a[$j]-eq'#'){$hashes++;$j++};if($j-ge$n-or$a[$j]-ne'"'){$rawStart=-1}}
        if($rawStart-ge0){$close='"'+('#'*$hashes);for($k=$rawStart;$k-le$j;$k++){$a[$k]=' '};$i=$j+1;while($i-lt$n){if($text.Substring($i).StartsWith($close,[StringComparison]::Ordinal)){for($k=$i;$k-lt$i+$close.Length;$k++){$a[$k]=' '};$i+=$close.Length;break};if($a[$i]-eq"`n"){$line++}else{$a[$i]=' '};$i++};continue}
        if($c-eq'"'-or($c-eq'b'-and$next-eq'"')){if($c-eq'b'){$a[$i]=' ';$i++};$a[$i]=' ';$i++;while($i-lt$n){if($a[$i]-eq'\'-and$i+1-lt$n){$a[$i]=' ';$i++;if($a[$i]-eq"`n"){$line++}else{$a[$i]=' '};$i++;continue};if($a[$i]-eq'"'){$a[$i]=' ';$i++;break};if($a[$i]-eq"`n"){$line++}else{$a[$i]=' '};$i++};continue}
        if($c-eq"'"-or($c-eq'b'-and$next-eq"'")){$charMatch=$charPattern.Match($text.Substring($i));if($charMatch.Success){for($k=$i;$k-lt$i+$charMatch.Length;$k++){$a[$k]=' '};$i+=$charMatch.Length;continue}}
        if($c-eq"`n"){$line++};$i++
    };if($reservedCount-ne$markers.Count){throw "reserved ELIOT_ARCH_OWNER token appears outside a genuine outer rustdoc marker: $Relative"};[pscustomobject]@{Text=$text;Masked=(-join$a);Markers=$markers.ToArray();OuterDocs=$outerDocs.ToArray()}
}
function CfgArgs([string]$Body) {
    $parts=[Collections.Generic.List[string]]::new();$depth=0;$quoted=$false;$escaped=$false;$start=0
    for($i=0;$i-lt$Body.Length;$i++){$c=$Body[$i];if($quoted){if($escaped){$escaped=$false;continue};if($c-eq'\'){$escaped=$true;continue};if($c-eq'"'){$quoted=$false};continue};if($c-eq'"'){$quoted=$true;continue};if($c-eq'('){$depth++}elseif($c-eq')'){$depth--}elseif($c-eq','-and$depth-eq0){$parts.Add($Body.Substring($start,$i-$start).Trim());$start=$i+1}}
    $tail=$Body.Substring($start).Trim();if($tail.Length-gt0){$parts.Add($tail)};$parts.ToArray()
}
function CfgAtoms([string]$Expression) {
    $expression=$Expression.Trim();if($expression-ceq'test'){return @()};$call=[regex]::Match($expression,'(?s)^(?<op>all|any|not)\s*\((?<body>.*)\)$');if(-not$call.Success){throw "unsupported cfg atom in conservative subset: $(Norm $expression)"};$atoms=[Collections.Generic.List[string]]::new();foreach($arg in @(CfgArgs $call.Groups['body'].Value)){foreach($atom in @(CfgAtoms $arg)){$atoms.Add($atom)}};@($atoms|Sort-Object -Unique -Culture '')
}
function CfgEval([string]$Expression,$Assignment) {
    $expression=$Expression.Trim();if($expression-ceq'test'){return $false};$call=[regex]::Match($expression,'(?s)^(?<op>all|any|not)\s*\((?<body>.*)\)$');if(-not$call.Success){throw "unsupported cfg atom in conservative subset: $(Norm $expression)"};$op=$call.Groups['op'].Value;$args=@(CfgArgs $call.Groups['body'].Value);if($op-eq'not'){if($args.Count-ne1){throw "malformed cfg not() expression: $Expression"};return -not(CfgEval $args[0] $Assignment)};if($op-eq'all'){foreach($arg in $args){if(-not(CfgEval $arg $Assignment)){return $false}};return $true};foreach($arg in $args){if(CfgEval $arg $Assignment){return $true}};$false
}
function CfgPossibility([string]$Expression) {
    $atoms=@(CfgAtoms $Expression);if($atoms.Count-gt12){throw "cfg expression exceeds the 12-atom verification bound: $Expression"};$canTrue=$false;$canFalse=$false;$limit=1-shl$atoms.Count;for($mask=0;$mask-lt$limit;$mask++){$assignment=@{};for($i=0;$i-lt$atoms.Count;$i++){$assignment[$atoms[$i]]=(($mask-band(1-shl$i))-ne0)};$value=CfgEval $Expression $assignment;if($value){$canTrue=$true}else{$canFalse=$true};if($canTrue-and$canFalse){break}};[pscustomobject]@{CanTrue=$canTrue;CanFalse=$canFalse}
}
function CfgAttributes([string]$Masked,[string]$Source) {
    if($null-eq$Source){$Source=$Masked}
    $out=[Collections.Generic.List[object]]::new()
    foreach($match in [regex]::Matches($Masked,'#\s*(?<inner>!)?\[\s*(?<kind>cfg|cfg_attr)\s*\(')){
        $open=$Masked.IndexOf('(',$match.Index);$depth=0;$close=-1
        for($i=$open;$i-lt$Masked.Length;$i++){if($Masked[$i]-eq'('){$depth++}elseif($Masked[$i]-eq')'){$depth--;if($depth-eq0){$close=$i;break}}}
        if($close-lt0){throw 'unterminated cfg attribute'}
        $cursor=$close+1;while($cursor-lt$Masked.Length-and[char]::IsWhiteSpace($Masked[$cursor])){$cursor++}
        if($cursor-ge$Masked.Length-or$Masked[$cursor]-ne']'){throw 'malformed cfg attribute'}
        $body=$Source.Substring($open+1,$close-$open-1);$presence=$null;$nestedBuiltIn=$null
        if($match.Groups['kind'].Value-eq'cfg'){$presence=$body}else{
            $args=@(CfgArgs $body);if($args.Count-lt1){throw 'malformed cfg_attr attribute'};[void](CfgPossibility $args[0])
            $gates=[Collections.Generic.List[string]]::new()
            for($argIndex=1;$argIndex-lt$args.Count;$argIndex++){
                $nested=[regex]::Match($args[$argIndex],'(?s)^cfg\s*\((.*)\)$')
                if($nested.Success){$gates.Add($nested.Groups[1].Value);continue}
                if($args[$argIndex]-match'(?s)^cfg_attr\s*\('){throw 'nested cfg_attr presence gating is not admitted'}
                if($args[$argIndex]-match'^\s*(?:test|bench)\s*$'){$nestedBuiltIn=Norm $args[$argIndex];continue}
            }
            if($gates.Count-gt0){$presence="any(not($($args[0])), all($([string]::Join(', ', $gates))))"}
        }
        $testOnly=$false;$unsupported=$false;$unsupportedMessage=$null
        if($null-ne$nestedBuiltIn){$unsupported=$true;$unsupportedMessage="unsupported nested cfg_attr built-in: $nestedBuiltIn"}
        elseif($null-ne$presence){try{$testOnly=-not(CfgPossibility $presence).CanTrue}catch{if($_.Exception.Message-notmatch'^unsupported cfg atom in conservative subset: '){throw};$unsupported=$true;$unsupportedMessage=$_.Exception.Message}}
        $out.Add([pscustomobject]@{Start=$match.Index;End=$cursor+1;Inner=$match.Groups['inner'].Success;Presence=$presence;TestOnly=$testOnly;Unsupported=$unsupported;UnsupportedMessage=$unsupportedMessage})
    }
    $out.ToArray()
}
function CfgSetCanCompile($Attributes,[switch]$Strict) {
    $unsupported=@($Attributes|Where-Object{$_.Unsupported});if($unsupported.Count-gt0){if($Strict){throw [string]$unsupported[0].UnsupportedMessage};return $false};$expressions=@($Attributes|Where-Object{$null-ne$_.Presence}|ForEach-Object{[string]$_.Presence});if($expressions.Count-eq0){return $true};$combined=if($expressions.Count-eq1){$expressions[0]}else{"all($([string]::Join(', ', $expressions)))"};[bool](CfgPossibility $combined).CanTrue
}
function TestPath([string]$Relative) { $p=$Relative.Replace('\','/');$p-match '(^|/)(tests?|fixtures?)(/|$)' -or $p-match '(?i)(^|/)[^/]*_tests?\.rs$' }
function AssertOuterAttributeRemainder([string]$MaskedText,[string]$Context) {$close=$MaskedText.LastIndexOf(']');if($close-lt0){throw "incomplete outer attribute after source marker at $Context"};$sameLineRemainder=($MaskedText.Substring($close+1)-split "`n",2)[0];if(-not[string]::IsNullOrWhiteSpace($sameLineRemainder)){throw "outer attribute has non-whitespace same-line remainder outside grammar at $Context"}}
function PublicItem($Lines,$MaskedLines,[int]$MarkerLine) {
    $j=$MarkerLine+1;while($j-lt$Lines.Count-and([string]$Lines[$j])-match '^\s*///(?!/)') { if(([string]$Lines[$j])-match 'ELIOT_ARCH_OWNER'){throw "ambiguous source marker near line $($MarkerLine+1)"};$j++ }
    $cfg=[Collections.Generic.List[object]]::new();while($j-lt$MaskedLines.Count-and([string]$MaskedLines[$j])-match '^\s*#\['){$attrSource=[string]$Lines[$j];$attrMasked=[string]$MaskedLines[$j];$depth=([regex]::Matches($attrMasked,'\[')).Count-([regex]::Matches($attrMasked,'\]')).Count;while($depth-gt0){$j++;if($j-ge$MaskedLines.Count){throw "unterminated outer attribute after source marker at line $($MarkerLine+1)"};$sourcePart=[string]$Lines[$j];$maskedPart=[string]$MaskedLines[$j];$attrSource+="`n$sourcePart";$attrMasked+="`n$maskedPart";$depth+=([regex]::Matches($maskedPart,'\[')).Count-([regex]::Matches($maskedPart,'\]')).Count};AssertOuterAttributeRemainder $attrMasked "line $($MarkerLine+1)";foreach($parsed in @(CfgAttributes $attrMasked $attrSource)){$cfg.Add($parsed)};if($attrMasked-match '(?im)^\s*#\[\s*(?:test|bench)\s*\]'){throw "source marker target is test-only at line $($MarkerLine+1)"};$j++};if(-not(CfgSetCanCompile $cfg -Strict)){throw "source marker target is test-only at line $($MarkerLine+1)"}
    if($j-ge$MaskedLines.Count){throw "source marker has no following public Rust item at line $($MarkerLine+1)"};$sourceLine=[string]$Lines[$j];$line=[string]$MaskedLines[$j];if([string]::IsNullOrWhiteSpace($line)){throw "source marker is detached from its public Rust item at line $($MarkerLine+1)"};if($line-match '^\s*pub\s*\(' -or $line-match '^\s*pub\s+use\b'){throw "source marker does not bind a public defining item at line $($j+1)"};if($line-match '^\s*pub\s+(?:(?:async|unsafe|const|extern(?:\s+"[^"]+")?)\s+)*(?<kind>fn|struct|enum|union|trait|type|const|static|mod)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)'){return [pscustomobject]@{Name=$Matches['name'];Line=$j+1;Kind=$Matches['kind'];Text=$sourceLine.Trim()}};throw "source marker is not immediately followed by a public defining Rust item at line $($j+1)"
}
function PackageFor([string]$Relative,$Inventory) {
    $p=$Relative.Replace('\','/');$candidates=[Collections.Generic.List[object]]::new();foreach($m in @($Inventory.manifests)){$root=([IO.Path]::GetDirectoryName(([string]$m.manifest_path).Replace('/',[IO.Path]::DirectorySeparatorChar))).Replace('\','/').TrimEnd('/');$target=@($m.source_modules_and_crates.targets|Where-Object{$p-eq([string]$_.src_path).Replace('\','/')}).Count-gt0;if($target-or$p.StartsWith("$root/",[StringComparison]::OrdinalIgnoreCase)){$candidates.Add([pscustomobject]@{Package=[string]$m.package_name;Root=$root;Exact=$target})}};if($candidates.Count-eq0){throw "package owner is unresolved for ${Relative}"};$exact=@($candidates|Where-Object{$_.Exact}|Select-Object -ExpandProperty Package -Unique);if($exact.Count-gt1){throw "ambiguous exact package target for ${Relative}: $($exact-join ',')"};if($exact.Count-eq1){return $exact[0]};$best=@($candidates|Sort-Object @{Expression={$_.Root.Length};Descending=$true});$top=$best[0];$same=@($best|Where-Object{$_.Root.Length-eq$top.Root.Length}|Select-Object -ExpandProperty Package -Unique);if($same.Count-ne1){throw "ambiguous package containment for ${Relative}: $($same-join ',')"};$top.Package
}
function ModuleCandidates([string]$Root,[string]$ParentRelative,[string]$Name) {
    $parent=$ParentRelative.Replace('\','/');$directory=[IO.Path]::GetDirectoryName($parent).Replace('\','/');$fileName=[IO.Path]::GetFileNameWithoutExtension($parent);$base=if($fileName-in@('lib','main','mod')){$directory}else{if([string]::IsNullOrEmpty($directory)){$fileName}else{"$directory/$fileName"}};@("$base/$Name.rs","$base/$Name/mod.rs")|ForEach-Object{$_.TrimStart('/')}
}
function ExternalProductionModules($Lexed) {
    $out=[Collections.Generic.List[string]]::new();$pattern='(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*;'
    foreach($match in [regex]::Matches($Lexed.Masked,$pattern)){if(-not(IsLexicalTopLevel $Lexed.Masked $match.Index)){continue};if(AttachedOuterDecoration $Lexed $match.Index){continue};$out.Add($match.Groups['name'].Value)};$out.ToArray()
}
function IsLexicalTopLevel([string]$Text,[int]$Offset) {$round=0;$square=0;$curly=0;for($i=0;$i-lt$Offset;$i++){switch($Text[$i]){'('{$round++}')'{$round--}'['{$square++}']'{$square--}'{'{$curly++}'}'{$curly--}}};$round-eq0-and$square-eq0-and$curly-eq0}
function AttachedOuterAttribute([string]$Text,[int]$Offset) {$prefix=$Text.Substring(0,$Offset).TrimEnd();if(-not$prefix.EndsWith(']',[StringComparison]::Ordinal)){return $false};$hash=$prefix.LastIndexOf('#');if($hash-lt0){return $false};$tail=$prefix.Substring($hash);$tail-match '^#\s*\['}
function AttachedOuterDecoration($Lexed,[int]$Offset) {if(AttachedOuterAttribute $Lexed.Masked $Offset){return $true};foreach($doc in @($Lexed.OuterDocs)){if($doc.End-le$Offset-and$Lexed.Masked.Substring([int]$doc.End,$Offset-[int]$doc.End)-match '^\s*$'){return $true}};$false}
function ProductionFileSet([string]$Root,$Inventory) {
    $reachable=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase);$queue=[Collections.Generic.Queue[string]]::new()
    foreach($manifest in @($Inventory.manifests)){foreach($target in @($manifest.source_modules_and_crates.targets)){$kinds=@($target.kind|ForEach-Object{[string]$_});if(@($kinds|Where-Object{$_-in@('test','bench','example','custom-build')}).Count-gt0){continue};$relative=([string]$target.src_path).Replace('\','/');if(-not[string]::IsNullOrWhiteSpace($relative)){$queue.Enqueue($relative)}}}
    while($queue.Count-gt0){$relative=$queue.Dequeue();if($reachable.Contains($relative)){continue};$full=Join-Path $Root $relative;if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw "production Cargo target/module is missing: $relative"};$lexed=RustLex (Read-Utf8 $full) $relative;$crateCfg=@(CfgAttributes $lexed.Masked $lexed.Text|Where-Object{$_.Inner-and(IsLexicalTopLevel $lexed.Masked $_.Start)});if(-not(CfgSetCanCompile $crateCfg)){continue};[void]$reachable.Add($relative);foreach($name in @(ExternalProductionModules $lexed)){$candidates=@(ModuleCandidates $Root $relative $name|Where-Object{Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf});if($candidates.Count-gt1){throw "ambiguous Rust module file for ${relative}::${name}"};if($candidates.Count-eq1){$queue.Enqueue($candidates[0])}}}
    $reachable
}
function AssertBindingUniqueness($Bindings) {
    $pairs=@($Bindings|Group-Object Anchor,Symbol|Where-Object{$_.Count-gt1});if($pairs.Count-gt0){throw "duplicate anchor-symbol pair: $($pairs[0].Name)"}
    $anchors=@($Bindings|Group-Object Anchor|Where-Object{$_.Count-gt1});if($anchors.Count-gt0){throw "anchor has multiple source symbols: $($anchors[0].Name)"}
    $symbols=@($Bindings|Group-Object Symbol|Where-Object{$_.Count-gt1});if($symbols.Count-gt0){throw "symbol has multiple architecture anchors: $($symbols[0].Name)"}
}
function CodeBindings([string]$Root,$Anchors,$Inventory) {
    $known=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($a in $Anchors){[void]$known.Add([string]$a.Id)};$productionFiles=ProductionFileSet $Root $Inventory;$all=[Collections.Generic.List[object]]::new();$files=@(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.rs'|Where-Object{$_.FullName-notmatch '[\\/]\.git[\\/]' -and$_.FullName-notmatch '[\\/]target[\\/]' -and$_.FullName-notmatch '[\\/]\.codebase-memory[\\/]'}|Sort-Object FullName)
    foreach($f in $files){$rel=[IO.Path]::GetRelativePath($Root,$f.FullName).Replace('\','/');$lex=RustLex (Read-Utf8 $f.FullName) $rel;$lines=@($lex.Text -split "`n");$maskedLines=@($lex.Masked -split "`n");$crateCfg=@(CfgAttributes $lex.Masked $lex.Text|Where-Object{$_.Inner-and(IsLexicalTopLevel $lex.Masked $_.Start)});foreach($marker in @($lex.Markers)){$id=[string]$marker.Anchor;if(TestPath $rel){throw "source marker is test-only: ${rel}:$($marker.Line)"};if(-not(IsLexicalTopLevel $lex.Masked ([int]$marker.Offset))){throw "source marker is not at lexical top level: ${rel}:$($marker.Line)"};if(-not(CfgSetCanCompile $crateCfg)){throw "source marker is test-only: ${rel}:$($marker.Line)"};if(AttachedOuterAttribute $lex.Masked ([int]$marker.Offset)){throw "source marker must precede every outer attribute on its target: ${rel}:$($marker.Line)"};if(-not$productionFiles.Contains($rel)){throw "source marker is not reachable from a production Cargo target: ${rel}:$($marker.Line)"};if(-not$known.Contains($id)){throw "unknown architecture anchor in source marker: $id"};$item=PublicItem $lines $maskedLines ([int]$marker.Line-1);$all.Add([pscustomobject]@{Anchor=$id;Symbol="$rel::$($item.Name)";Path=$rel;MarkerLine=[int]$marker.Line;SourceLine=$item.Line;SourceSha256=(Sha $f.FullName);Item=$item.Name;Kind=$item.Kind;Owner=(PackageFor $rel $Inventory)})}}
    AssertBindingUniqueness $all
    $all.ToArray()
}
function RefusalSites([string]$Root,[string]$Path,$Anchors) {
    if(-not(Test-Path -LiteralPath $Path -PathType Leaf)){throw "missing refusals inventory: $Path"};$known=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($a in $Anchors){[void]$known.Add([string]$a.Id)};$rows=@(Import-Csv -LiteralPath $Path);$by=@{};foreach($r in $rows){$id=[string]$r.normative_anchor;if($known.Contains($id)){if(-not(Test-Path -LiteralPath (Join-Path $Root ([string]$r.file)) -PathType Leaf)){throw "refusal site source missing: $($r.file)"};$actual=Sha (Join-Path $Root ([string]$r.file));if(-not$actual.Equals(([string]$r.source_sha256),[StringComparison]::OrdinalIgnoreCase)){throw "refusal site source digest stale: $($r.stable_id)"};$site="$($r.stable_id)@$($r.file):$($r.line)-$($r.end_line)";if(-not$by.ContainsKey($id)){$by[$id]=[Collections.Generic.List[string]]::new()};$by[$id].Add($site)}};foreach($k in @($by.Keys)){$by[$k]=@($by[$k]|Sort-Object -Culture '')};$by
}
function Graph([string]$Artifact,[string]$Database) { if(-not(Test-Path -LiteralPath $Artifact -PathType Leaf)-or-not(Test-Path -LiteralPath $Database -PathType Leaf)){throw 'missing code graph artifact or database'};$a=Read-Utf8 $Artifact|ConvertFrom-Json;if($null-eq$a.nodes-or$null-eq$a.edges-or[string]::IsNullOrWhiteSpace([string]$a.project)-or[string]::IsNullOrWhiteSpace([string]$a.commit)){throw 'graph artifact lacks identity or node/edge counts'};[ordered]@{artifact_path=(Rel $Artifact);artifact_sha256=(Sha $Artifact);database_path=(Rel $Database);database_sha256=(Sha $Database);nodes=[int64]$a.nodes;edges=[int64]$a.edges;artifact_schema_version=[int]$a.schema_version;graph_project=[string]$a.project;graph_commit=[string]$a.commit;database_size=[int64](Get-Item -LiteralPath $Database).Length}
}
function Model {
    $a=Rows (Read-Utf8 $ArchitecturePath) '^## A16\.1\. Decision anchors\s*$' '^## A16\.2\.' '^\|\s*ID\s*\|\s*Класс\s*\|\s*Решение\s*\|\s*$' architecture;$i=Rows (Read-Utf8 $ImplementationPath) '^# Appendix H\. Full Architecture conformance map\s*$' '^# Appendix I\.' '^\|\s*Architecture ID\s*\|\s*Primary implementation sections / owner\s*\|\s*Observable proof family\s*\|\s*$' implementation;AssertPair $a $i;$inv=Read-Utf8 $ModulesPath|ConvertFrom-Json;$bindings=@(CodeBindings $RepoRoot $a $inv);$ref=RefusalSites $RepoRoot $RefusalsPath $a;$by=@{};foreach($r in $i){$by[$r.Id]=$r};$an=(($a|ForEach-Object{"$($_.Id)|$($_.Class)|$(Norm $_.Decision)"})-join "`n")+"`n";$inn=(($a|ForEach-Object{$r=$by[$_.Id];"$($_.Id)|$(Norm $r.ScopeOwner)|$(Norm $r.Proof)"})-join "`n")+"`n";[pscustomobject]@{Architecture=$a;Implementation=$i;ById=$by;Bindings=$bindings;Refusals=$ref;Graph=(Graph $GraphArtifactPath $GraphDatabasePath);ArchitectureHash=(Sha $ArchitecturePath);ImplementationHash=(Sha $ImplementationPath);PairHash=(TextSha($an+"---`n"+$inn));GeneratorHash=(Sha $GeneratorPath);VerifierHash=(Sha $VerifierPath);DecisionHash=(Sha $DecisionPath);BindingDecisionHash=(Sha $BindingDecisionPath);ModulesHash=(Sha $ModulesPath);RefusalsHash=(Sha $RefusalsPath)}
}
function BindingsFor($m,[string]$Id){@($m.Bindings|Where-Object {$_.Anchor -eq $Id})}
function Conformance($m) {
    $unknownOwnerCount=@($m.Architecture|Where-Object{@(BindingsFor $m $_.Id).Count-eq0}).Count
    $l=[Collections.Generic.List[string]]::new();$l.Add('# GENERATED FILE - DO NOT EDIT. Content-bound projection of A16.1, Appendix H, and code-side joins.');$l.Add('schema_version = "eliot-conformance-v3"');$l.Add('authority_status = "GENERATED_PROJECTION"');$l.Add('provenance_mode = "CONTENT_BOUND"');$l.Add("architecture_source_path = $(Toml (Rel $ArchitecturePath))");$l.Add("implementation_source_path = $(Toml (Rel $ImplementationPath))");$l.Add("generator_path = $(Toml (Rel $GeneratorPath))");$l.Add("verifier_path = $(Toml (Rel $VerifierPath))");$l.Add("result_envelope_contract_path = $(Toml (Rel $DecisionPath))");$l.Add("binding_contract_path = $(Toml (Rel $BindingDecisionPath))");$l.Add("modules_inventory_path = $(Toml (Rel $ModulesPath))");$l.Add("refusals_inventory_path = $(Toml (Rel $RefusalsPath))");$l.Add("architecture_source_sha256 = $(Toml $m.ArchitectureHash)");$l.Add("implementation_source_sha256 = $(Toml $m.ImplementationHash)");$l.Add("normalized_pair_sha256 = $(Toml $m.PairHash)");$l.Add("generator_source_sha256 = $(Toml $m.GeneratorHash)");$l.Add("verifier_source_sha256 = $(Toml $m.VerifierHash)");$l.Add("result_envelope_contract_sha256 = $(Toml $m.DecisionHash)");$l.Add("binding_contract_sha256 = $(Toml $m.BindingDecisionHash)");$l.Add("modules_inventory_sha256 = $(Toml $m.ModulesHash)");$l.Add("refusals_inventory_sha256 = $(Toml $m.RefusalsHash)");$l.Add("graph_artifact_path = $(Toml $m.Graph.artifact_path)");$l.Add("graph_artifact_sha256 = $(Toml $m.Graph.artifact_sha256)");$l.Add("graph_database_path = $(Toml $m.Graph.database_path)");$l.Add("graph_database_sha256 = $(Toml $m.Graph.database_sha256)");$l.Add("graph_schema_version = $($m.Graph.artifact_schema_version)");$l.Add("graph_project = $(Toml $m.Graph.graph_project)");$l.Add("graph_commit = $(Toml $m.Graph.graph_commit)");$l.Add("graph_nodes = $($m.Graph.nodes)");$l.Add("graph_edges = $($m.Graph.edges)");$l.Add("graph_database_size = $($m.Graph.database_size)");$l.Add("anchor_count = $ExpectedAnchorCount");$l.Add("code_binding_count = $(@($m.Bindings).Count)");$l.Add("unknown_owner_count = $unknownOwnerCount");$l.Add('')
    foreach($a in $m.Architecture){$r=$m.ById[$a.Id];$p=Scope $r.ScopeOwner;$b=@(BindingsFor $m $a.Id);$owner=if($b.Count-eq1){$b[0].Owner}else{'UNKNOWN'};$symbols=@($b|ForEach-Object Symbol|Sort-Object -Culture '');$symbolSites=@($b|ForEach-Object{"$($_.Path):$($_.SourceLine)"}|Sort-Object -Culture '');$sites=if($m.Refusals.ContainsKey($a.Id)){@($m.Refusals[$a.Id])}else{@()};$l.Add('[[requirement]]');$l.Add("id = $(Toml $a.Id)");$l.Add("class = $(Toml $a.Class)");$l.Add("decision = $(Toml (Norm $a.Decision))");$l.Add("owner = $(Toml $owner)");$l.Add("source_handles = $(TomlArray $p.Handles)");$l.Add("symbols = $(TomlArray $symbols)");$l.Add("symbol_sites = $(TomlArray $symbolSites)");$l.Add("refusal_sites = $(TomlArray $sites)");$l.Add('support = "UNKNOWN"');$l.Add('invalidation = []');$l.Add("observable_proof = $(Toml (Norm $r.Proof))");$l.Add('')}
    foreach($b in @($m.Bindings|Sort-Object Symbol,Anchor -Culture '')){$l.Add('[[symbol_anchor]]');$l.Add("symbol = $(Toml $b.Symbol)");$l.Add("anchor = $(Toml $b.Anchor)");$l.Add("owner = $(Toml $b.Owner)");$l.Add("source_path = $(Toml $b.Path)");$l.Add("marker_line = $($b.MarkerLine)");$l.Add("source_line = $($b.SourceLine)");$l.Add("source_sha256 = $(Toml $b.SourceSha256)");$l.Add("item = $(Toml $b.Item)");$l.Add("item_kind = $(Toml $b.Kind)");$l.Add('')};(($l-join "`n")+"`n")
}
function Json($Value){$Value|ConvertTo-Json -Depth 30}
function Envelope($m,[string]$ConformanceHash){$unknownOwnerCount=@($m.Architecture|Where-Object{@(BindingsFor $m $_.Id).Count-eq0}).Count;$sources=@([ordered]@{path=(Rel $ArchitecturePath);role='current repository normative projection';sha256=$m.ArchitectureHash},[ordered]@{path=(Rel $ImplementationPath);role='current repository normative projection';sha256=$m.ImplementationHash},[ordered]@{path=(Rel $DecisionPath);role='resolved result-envelope contract';sha256=$m.DecisionHash},[ordered]@{path=(Rel $BindingDecisionPath);role='Root-accepted anchor-symbol binding contract';sha256=$m.BindingDecisionHash},[ordered]@{path=(Rel $ModulesPath);role='current module ownership inventory';sha256=$m.ModulesHash},[ordered]@{path=(Rel $RefusalsPath);role='current refusal-site inventory';sha256=$m.RefusalsHash},[ordered]@{path=$m.Graph.artifact_path;role='code graph identity and counts';sha256=$m.Graph.artifact_sha256},[ordered]@{path=$m.Graph.database_path;role='persisted code graph database';sha256=$m.Graph.database_sha256},[ordered]@{path=(Rel $GeneratorPath);role='projection generator';sha256=$m.GeneratorHash},[ordered]@{path=(Rel $VerifierPath);role='independent projection verifier';sha256=$m.VerifierHash});$structured=[ordered]@{disposition='completed';artifacts=@([ordered]@{path='docs/conformance.toml';role='generated projection';sha256=$ConformanceHash},[ordered]@{path='swarm/results/W1-04-implementation.json';role='supporting implementation evidence';sha256='supporting-file-not-authority'});evidence=@("58 A16.1 anchors are projected in canonical order; $(@($m.Bindings).Count) exact production bindings have code-derived owners and $unknownOwnerCount owners remain UNKNOWN.",'Every support value remains UNKNOWN and every invalidation list remains empty.');discriminator_before=[ordered]@{name='code-owned-anchor-bindings';value='zero explicit production anchor-owner bindings; owner inference from Appendix H or names was forbidden';status='observed'};discriminator_after=[ordered]@{name='code-owned-anchor-bindings';value="$(@($m.Bindings).Count) exact code bindings and $unknownOwnerCount UNKNOWN owners with symmetric reverse index";status='verified'};uncertainty=@('No support or invalidation evidence is inferred from a navigation binding.','The persisted graph corroborates project provenance but source markers remain the ownership authority.','Digest and semantic evidence assumes writer quiescence; it is not an atomic snapshot proof and does not claim TOCTOU is fixed.');unresolved_questions=@('The remaining UNKNOWN owners require later exact production bindings.','Per-anchor support and invalidation semantics require separately admitted evidence.');proposed_effects=@('Future implementation lanes may add an exact production marker when they can preserve the one-to-one binding contract.');evidence_lineage=@($sources|ForEach-Object{[ordered]@{path=[string]$_.path;sha256=[string]$_.sha256;role=[string]$_.role}});schema_version='eliot-w1-04-implementation-v3';authority_status='EVIDENCE_ONLY';work_item_id='W1-04';provenance_mode='CONTENT_BOUND';source_documents=$sources;normalized_pair_sha256=$m.PairHash;generator_path=(Rel $GeneratorPath);generator_source_sha256=$m.GeneratorHash;verifier_path=(Rel $VerifierPath);verifier_source_sha256=$m.VerifierHash;result=[ordered]@{disposition='EVIDENCE_ONLY';anchors=$ExpectedAnchorCount;code_bindings=@($m.Bindings).Count;unknown_owners=$unknownOwnerCount;bijection='58x58 exact ID bijection';support_default='UNKNOWN';invalidation_default=@();ordering='Architecture A16.1 canonical order';authority='site-local production rustdoc binding plus current module ownership; no Appendix H owner inference';graph=[ordered]@{schema_version=$m.Graph.artifact_schema_version;project=$m.Graph.graph_project;commit=$m.Graph.graph_commit;nodes=$m.Graph.nodes;edges=$m.Graph.edges}};result_envelope_contract_path=(Rel $DecisionPath);binding_contract_path=(Rel $BindingDecisionPath);verification=@('generator self-test and deterministic generation','generator check of conformance and both result envelopes','independent verifier self-test and normal verification');residuals=@("$unknownOwnerCount anchor owners remain UNKNOWN.",'No generated support or invalidation evidence exists.','Result remains EVIDENCE_ONLY; no terminal attempt is claimed.','Digest and semantic evidence assumes writer quiescence; it is not an atomic snapshot proof and does not claim TOCTOU is fixed.');authority_ceiling='EVIDENCE_ONLY; no terminal completion, release WIP, activation, or wave authorization.'};[ordered]@{schema_version='eliot.bootstrap-work-result.v1';authority_status='EVIDENCE_ONLY';work_item_id='W1-04';structured_result=$structured}
}
function AssertStable([string]$Expected,[string]$Actual){if($Actual-cne$Expected){throw 'generated conformance bytes are stale or non-deterministic'}}
function SelfTest {
    $m=Model
    $one=Conformance $m
    $two=Conformance $m
    if($one-cne$two){throw 'determinism failed'}
    if($one-notmatch 'schema_version = "eliot-conformance-v3"'){throw 'schema v3 failed'}
    if($one-match '(?m)^(?:source_revision|worktree|timestamp)\s*='){throw 'volatile provenance leaked'}
    if($one-match 'Appendix H.*owner'){throw 'Appendix-H owner leaked into generated authority'}
    $esc=Toml ('q" \\ `t'+[char]9);if($esc-notmatch '\\\\|\\"|\\t'){throw 'TOML escaping failed'}

    $tmp=Join-Path ([IO.Path]::GetTempPath()) ('eliot-conformance-selftest-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp|Out-Null
    $fakeA=@([pscustomobject]@{Id='ARCH-TEST-01'},[pscustomobject]@{Id='ARCH-TEST-02'})
    $assertFailure={
        param([string]$Name,[string]$Relative,[string]$Content,[string]$ExpectedPattern)
        $root=Join-Path $tmp $Name
        $full=Join-Path $root $Relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $full) -Force|Out-Null
        [IO.File]::WriteAllText($full,$Content,[Text.UTF8Encoding]::new($false))
        $inventory=[pscustomobject]@{manifests=@([pscustomobject]@{package_name='fixture';manifest_path='Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path=$Relative.Replace('\','/');kind=@('lib')})}})}
        $caught=$false
        try{CodeBindings $root $fakeA $inventory|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch$ExpectedPattern){throw "${Name} threw the wrong error: $($_.Exception.Message)"}}
        if(-not$caught){throw "${Name} did not fail closed"}
    }
    try{
        $positiveRoot=Join-Path $tmp 'positive';$positivePath=Join-Path $positiveRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $positivePath) -Force|Out-Null
        [IO.File]::WriteAllText($positivePath,"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n/// Bound production type.`n#[derive(Clone)]`npub struct Bound;`n",[Text.UTF8Encoding]::new($false))
        $positiveInv=[pscustomobject]@{manifests=@([pscustomobject]@{package_name='fixture';manifest_path='Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path='src/lib.rs';kind=@('lib')})}})}
        $positive=@(CodeBindings $positiveRoot $fakeA $positiveInv)
        if($positive.Count-ne1-or$positive[0].Item-ne'Bound'-or$positive[0].Kind-ne'struct'-or$positive[0].Owner-ne'fixture'){throw 'positive marker binding fixture failed'}

        $semicolonRoot=Join-Path $tmp 'cfg-semicolon';$semicolonPath=Join-Path $semicolonRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $semicolonPath) -Force|Out-Null
        [IO.File]::WriteAllText($semicolonPath,"#[cfg(test)]`nmod tests;`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Real;`nfn later() {}`n",[Text.UTF8Encoding]::new($false))
        $semicolonBindings=@(CodeBindings $semicolonRoot $fakeA $positiveInv)
        if($semicolonBindings.Count-ne1-or$semicolonBindings[0].Item-ne'Real'){throw 'cfg(test) semicolon target created a false enclosing range'}

        $notTestRoot=Join-Path $tmp 'cfg-not-test';$notTestPath=Join-Path $notTestRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $notTestPath) -Force|Out-Null
        [IO.File]::WriteAllText($notTestPath,"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(not(test))]`npub struct ProductionOnly;`n",[Text.UTF8Encoding]::new($false))
        $notTestBindings=@(CodeBindings $notTestRoot $fakeA $positiveInv)
        if($notTestBindings.Count-ne1-or$notTestBindings[0].Item-ne'ProductionOnly'){throw 'cfg(not(test)) production marker was rejected'}

        & $assertFailure 'cfg-any-feature' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(any(test, feature = `"fixture`"))]`npub struct ProductionCapable;`n" 'unsupported cfg atom in conservative subset'

        $featureRoot=Join-Path $tmp 'cfg-feature';$featurePath=Join-Path $featureRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $featurePath) -Force|Out-Null
        [IO.File]::WriteAllText($featurePath,"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(feature = `"fixture`")]`npub struct FeatureOnly;`n",[Text.UTF8Encoding]::new($false))
        & $assertFailure 'cfg-feature-only' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(feature = `"fixture`" )]`npub struct FeatureOnly;`n" 'unsupported cfg atom in conservative subset'

        $fieldCfgRoot=Join-Path $tmp 'cfg-field';$fieldCfgPath=Join-Path $fieldCfgRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $fieldCfgPath) -Force|Out-Null
        [IO.File]::WriteAllText($fieldCfgPath,"pub struct Holder {`n    #[cfg(test)]`n    field: u8,`n}`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Real {}`n",[Text.UTF8Encoding]::new($false))
        $fieldCfgBindings=@(CodeBindings $fieldCfgRoot $fakeA $positiveInv)
        if($fieldCfgBindings.Count-ne1-or$fieldCfgBindings[0].Item-ne'Real'){throw 'cfg-gated field leaked its range into the following production item'}

        $rawAttrRoot=Join-Path $tmp 'raw-attribute';$rawAttrPath=Join-Path $rawAttrRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $rawAttrPath) -Force|Out-Null
        [IO.File]::WriteAllText($rawAttrPath,"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[doc = r#`"`n]`npub struct Phantom;`n`"#]`npub struct Real;`n",[Text.UTF8Encoding]::new($false))
        $rawAttrBindings=@(CodeBindings $rawAttrRoot $fakeA $positiveInv)
        if($rawAttrBindings.Count-ne1-or$rawAttrBindings[0].Item-ne'Real'){throw 'raw-string attribute content was mistaken for a public Rust item'}

        $stringAttrRoot=Join-Path $tmp 'string-attribute';$stringAttrPath=Join-Path $stringAttrRoot 'src/lib.rs';New-Item -ItemType Directory -Path (Split-Path -Parent $stringAttrPath) -Force|Out-Null
        [IO.File]::WriteAllText($stringAttrPath,"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[doc = `"opens [ here`"]`npub struct Real;`npub fn pad() { let s = `"]`"; }`npub struct Impostor;`n",[Text.UTF8Encoding]::new($false))
        $stringAttrBindings=@(CodeBindings $stringAttrRoot $fakeA $positiveInv)
        if($stringAttrBindings.Count-ne1-or$stringAttrBindings[0].Item-ne'Real'){throw 'string attribute brackets absorbed a non-adjacent Rust item'}

        & $assertFailure 'same-line-attribute-item' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[derive(Clone)] pub struct Impostor;`npub struct Victim;`n" 'same-line remainder outside grammar'

        & $assertFailure 'raw-string' 'src/lib.rs' "pub const SPOOF: &str = r#`"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`"#;`n" 'reserved ELIOT_ARCH_OWNER token'
        & $assertFailure 'direct-cfg-test' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(test)]`npub struct Bad;`n" 'test-only'
        & $assertFailure 'nested-production-item' 'src/lib.rs' "mod nested {`n    /// ELIOT_ARCH_OWNER: ARCH-TEST-01`n    pub struct Bad;`n}`n" 'lexical top level'
        & $assertFailure 'macro-generated-item' 'src/lib.rs' "macro_rules! passthrough {`n    (`$(`$i:item)*) => {`$(`$i)*};`n}`npassthrough!(`n    /// ELIOT_ARCH_OWNER: ARCH-TEST-01`n    pub struct Bad;`n);`n" 'lexical top level'
        & $assertFailure 'nested-cfg-test' 'src/lib.rs' "#[cfg(test)]`nmod hidden {`n    /// ELIOT_ARCH_OWNER: ARCH-TEST-01`n    pub struct Bad;`n}`n" 'lexical top level'
        & $assertFailure 'nested-all-test' 'src/lib.rs' "#[cfg(all(test, feature = `"fixture`"))]`nmod hidden {`n    /// ELIOT_ARCH_OWNER: ARCH-TEST-01`n    pub struct Bad;`n}`n" 'lexical top level'
        & $assertFailure 'nested-test-lifetimes' 'src/lib.rs' "#[cfg(test)]`nmod hidden {`n    fn f<'a>() { let _: &'a str = `"`"; }`n    /// ELIOT_ARCH_OWNER: ARCH-TEST-01`n    pub struct Bad;`n}`n" 'lexical top level'
        & $assertFailure 'inner-cfg-test' 'src/lib.rs' "#![cfg(test)]`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Bad;`n" 'test-only'
        & $assertFailure 'cfg-attr-test-gate' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg_attr(not(test), cfg(test))]`npub struct Bad;`n" 'test-only'
        & $assertFailure 'cfg-attr-unsupported-base' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg_attr(unix, derive(Clone))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'correlated-test-only-cfg' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(any(test, all(feature = `"x`", not(feature = `"x`"))))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'unsupported-target-os-correlation' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(any(test, all(target_os = `"windows`", target_os = `"linux`")))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'unsupported-platform-correlation' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(any(test, all(unix, windows)))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'cfg-attr-test-item' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg_attr(not(test), test)]`npub fn Bad() {}`n" 'unsupported nested cfg_attr built-in: test'
        & $assertFailure 'cfg-attr-bench-item' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg_attr(not(test), bench)]`npub fn Bad() {}`n" 'unsupported nested cfg_attr built-in: bench'
        & $assertFailure 'correlated-cfg-attr-gates' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg_attr(not(test), cfg(feature = `"x`"), cfg(not(feature = `"x`")))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'correlated-stacked-cfg' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n#[cfg(any(test, feature = `"x`"))]`n#[cfg(any(test, not(feature = `"x`")))]`npub struct Bad;`n" 'unsupported cfg atom in conservative subset'
        & $assertFailure 'correlated-stacked-inner-cfg' 'src/lib.rs' "#![cfg(any(test, feature = `"x`"))]`n#![cfg(any(test, not(feature = `"x`")))]`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Bad;`n" 'test-only|unsupported cfg atom in conservative subset'
        & $assertFailure 'attribute-before-marker' 'src/lib.rs' "#[cfg(test)]`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Bad;`n" 'must precede every outer attribute'
        & $assertFailure 'test-path' 'tests/test.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Bad;`n" 'test-only'
        & $assertFailure 'blank-detachment' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n`npub struct Bad;`n" 'detached'
        & $assertFailure 'reexport' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub use crate::Thing as Bad;`n" 'does not bind a public defining item'
        & $assertFailure 'unknown-anchor' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-NOTREAL-99`npub struct Bad;`n" 'unknown architecture anchor'

        $orphanRoot=Join-Path $tmp 'orphan';New-Item -ItemType Directory -Path (Join-Path $orphanRoot 'src') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $orphanRoot 'src/lib.rs'),"pub fn root() {}`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $orphanRoot 'src/orphan.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $orphanRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'orphan source marker fixture did not fail closed'}

        $helperRoot=Join-Path $tmp 'test-helper';New-Item -ItemType Directory -Path (Join-Path $helperRoot 'src') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $helperRoot 'src/lib.rs'),"#[cfg(test)]`nmod helpers;`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $helperRoot 'src/helpers.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $helperRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'cfg(test) external helper marker fixture did not fail closed'}

        $multilineHelperRoot=Join-Path $tmp 'multiline-test-helper';New-Item -ItemType Directory -Path (Join-Path $multilineHelperRoot 'src') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $multilineHelperRoot 'src/lib.rs'),"#[cfg(`n    test`n)]`nmod helpers;`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $multilineHelperRoot 'src/helpers.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $multilineHelperRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'multiline cfg(test) helper marker fixture did not fail closed'}

        $cfgAttrHelperRoot=Join-Path $tmp 'cfg-attr-test-helper';New-Item -ItemType Directory -Path (Join-Path $cfgAttrHelperRoot 'src') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $cfgAttrHelperRoot 'src/lib.rs'),"#[cfg_attr(not(test), cfg(test))]`nmod helpers;`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $cfgAttrHelperRoot 'src/helpers.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $cfgAttrHelperRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'cfg_attr test-only helper marker fixture did not fail closed'}

        $docHelperRoot=Join-Path $tmp 'doc-attributed-helper';New-Item -ItemType Directory -Path (Join-Path $docHelperRoot 'src') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $docHelperRoot 'src/lib.rs'),"/// Helper docs.`n// ordinary explanation remains trivia`nmod helpers;`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $docHelperRoot 'src/helpers.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $docHelperRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'rustdoc-attributed helper marker fixture did not fail closed'}

        $inlineRoot=Join-Path $tmp 'inline-module';New-Item -ItemType Directory -Path (Join-Path $inlineRoot 'src/outer') -Force|Out-Null
        [IO.File]::WriteAllText((Join-Path $inlineRoot 'src/lib.rs'),"mod outer {`n    mod helpers;`n}`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $inlineRoot 'src/outer/helpers.rs'),"pub struct Actual;`n",[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText((Join-Path $inlineRoot 'src/helpers.rs'),"/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Ghost;`n",[Text.UTF8Encoding]::new($false))
        $caught=$false;try{CodeBindings $inlineRoot $fakeA $positiveInv|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'not reachable from a production Cargo target'){throw}}
        if(-not$caught){throw 'inline module context orphan marker fixture did not fail closed'}

        $emptyInventory=[pscustomobject]@{manifests=@()}
        $caught=$false;try{PackageFor 'src/lib.rs' $emptyInventory|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'package owner is unresolved'){throw}}
        if(-not$caught){throw 'unresolved package fixture did not fail closed'}
        $ambiguousInventory=[pscustomobject]@{manifests=@(
            [pscustomobject]@{package_name='one';manifest_path='Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path='src/lib.rs';kind=@('lib')})}},
            [pscustomobject]@{package_name='two';manifest_path='Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path='src/lib.rs';kind=@('lib')})}}
        )}
        $caught=$false;try{PackageFor 'src/lib.rs' $ambiguousInventory|Out-Null}catch{$caught=$true;if($_.Exception.Message-notmatch'ambiguous exact package target'){throw}}
        if(-not$caught){throw 'ambiguous package fixture did not fail closed'}
        $overlapInventory=[pscustomobject]@{manifests=@(
            [pscustomobject]@{package_name='exact';manifest_path='Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path='crates/x/src/lib.rs';kind=@('lib')})}},
            [pscustomobject]@{package_name='containing';manifest_path='crates/x/Cargo.toml';source_modules_and_crates=[pscustomobject]@{targets=@([pscustomobject]@{src_path='crates/x/src/other.rs';kind=@('lib')})}}
        )}
        if((PackageFor 'crates/x/src/lib.rs' $overlapInventory)-ne'exact'){throw 'exact package target did not dominate a deeper containment candidate'}

        $caught=$false;try{AssertBindingUniqueness @([pscustomobject]@{Anchor='ARCH-TEST-01';Symbol='src/lib.rs::One'},[pscustomobject]@{Anchor='ARCH-TEST-01';Symbol='src/lib.rs::Two'})}catch{$caught=$true;if($_.Exception.Message-notmatch'anchor has multiple source symbols'){throw}}
        if(-not$caught){throw 'ambiguous anchor fixture did not fail closed'}
        $caught=$false;try{AssertBindingUniqueness @([pscustomobject]@{Anchor='ARCH-TEST-01';Symbol='src/lib.rs::One'},[pscustomobject]@{Anchor='ARCH-TEST-02';Symbol='src/lib.rs::One'})}catch{$caught=$true;if($_.Exception.Message-notmatch'symbol has multiple architecture anchors'){throw}}
        if(-not$caught){throw 'symbol reuse fixture did not fail closed'}
    }finally{
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    $e=Envelope $m (TextSha $one)
    if($e.schema_version-ne'eliot.bootstrap-work-result.v1'-or$e.authority_status-ne'EVIDENCE_ONLY'-or$e.structured_result.disposition-notin @('completed','challenged','blocked','failed')){throw 'BootstrapWorkResult envelope failed'}
    if($e.PSObject.Properties.Name-contains'terminal_update'-or$e.PSObject.Properties.Name-contains'attempt_id'){throw 'forbidden terminal fields leaked'}
    if($e.structured_result.source_documents.Count-ne10){throw 'content-bound source lineage is incomplete'}
    Write-Output 'SELFTEST PASS: schema v3, strict lexical markers, production-item/package ownership, uniqueness, graph provenance, deterministic reverse table, and evidence-only envelope'
}
if($SelfTest){if($Check-or$PSBoundParameters.ContainsKey('OutputPath')){throw '-SelfTest cannot be combined with -Check or -OutputPath'};SelfTest;exit 0}
if($Check-and$PSBoundParameters.ContainsKey('OutputPath')){throw '-Check rejects an alternate -OutputPath'}
$m=Model;$unknown=@($m.Architecture|Where-Object{@(BindingsFor $m $_.Id).Count-eq0}).Count;if($unknown-ge55){throw "normal conformance output has too many UNKNOWN owners: $unknown (must be <55)"};$target=if($PSBoundParameters.ContainsKey('OutputPath')){[IO.Path]::GetFullPath($OutputPath)}else{$ConformancePath};$expected=Conformance $m
if($Check){if(-not(Test-Path -LiteralPath $target -PathType Leaf)){throw "missing conformance artifact: $target"};AssertStable $expected (Read-Utf8 $target);$ch=Sha $target;foreach($rp in @($ResultPath,$SupportingResultPath)){if(-not(Test-Path -LiteralPath $rp -PathType Leaf)){throw "missing result artifact: $rp"};$actual=Get-Content -LiteralPath $rp -Raw|ConvertFrom-Json -Depth 30;$want=Envelope $m $ch;if((Json $actual).TrimEnd("`r","`n")-cne(Json $want).TrimEnd("`r","`n")){throw "result artifact is stale or non-deterministic: $rp"}};Write-Output "CHECK PASS: $ExpectedAnchorCount anchors, code-side joins, reverse symmetry, graph provenance, and canonical W1-04 envelope";exit 0}
$parent=Split-Path -Parent $target;if(-not(Test-Path -LiteralPath $parent)){New-Item -ItemType Directory -Path $parent -Force|Out-Null};[IO.File]::WriteAllText($target,$expected,[Text.UTF8Encoding]::new($false));if($target-eq$ConformancePath){$e=Envelope $m (Sha $target);$bytes=(Json $e)+"`n";[IO.File]::WriteAllText($ResultPath,$bytes,[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($SupportingResultPath,$bytes,[Text.UTF8Encoding]::new($false));Write-Output "GENERATED: docs/conformance.toml, canonical W1-04.json, and supporting W1-04-implementation.json ($ExpectedAnchorCount anchors)"}else{Write-Output "GENERATED: $target ($ExpectedAnchorCount anchors)"}
