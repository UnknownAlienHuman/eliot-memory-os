[CmdletBinding()]
param(
    [switch] $Check,
    [string] $OutputPath,
    [string] $ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) { throw "REFUSAL_GENERATE_FAIL: $Message" }
function Sha([byte[]] $Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function ShaText([string] $Text) { Sha ([Text.Encoding]::UTF8.GetBytes($Text)) }
function Split-Lines([string] $Text) { [regex]::Split($Text, "\r\n|\n|\r") }
function Assert-RepoRelative([string] $Path, [string] $Name) {
    $normalized = $Path.Replace('\\','/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or [IO.Path]::IsPathRooted($normalized) -or $normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.(?:/|$)') {
        Fail "$Name must be repository-relative: $Path"
    }
    return $normalized
}

function Get-LexicallyMasked([string] $Text) {
    # The census grammar is deliberately lexical rather than a broad grep. Rust
    # comments, quoted strings, raw strings, and character literals are blanked;
    # newlines are retained so offsets continue to produce stable line anchors.
    $chars = $Text.ToCharArray(); $masked = [char[]]$chars.Clone(); $i = 0; $state = 'code'; $depth = 0; $hashes = 0
    while ($i -lt $chars.Length) {
        $c = $chars[$i]
        if ($state -eq 'line') { if ($c -eq "`r" -or $c -eq "`n") { $state = 'code' } else { $masked[$i] = ' ' }; $i++; continue }
        if ($state -eq 'block') {
            if ($i + 1 -lt $chars.Length -and $c -eq '/' -and $chars[$i + 1] -eq '*') { $masked[$i] = ' '; $masked[$i + 1] = ' '; $depth++; $i += 2; continue }
            if ($i + 1 -lt $chars.Length -and $c -eq '*' -and $chars[$i + 1] -eq '/') { $masked[$i] = ' '; $masked[$i + 1] = ' '; $depth--; $i += 2; if ($depth -eq 0) { $state = 'code' }; continue }
            if ($c -ne "`r" -and $c -ne "`n") { $masked[$i] = ' ' }; $i++; continue
        }
        if ($state -eq 'raw') {
            $close = $c -eq '"'
            if ($close) { for ($h = 1; $h -le $hashes; $h++) { if ($i + $h -ge $chars.Length -or $chars[$i + $h] -ne '#') { $close = $false; break } } }
            if ($close) { for ($j = 0; $j -le $hashes; $j++) { $masked[$i + $j] = ' ' }; $i += 1 + $hashes; $state = 'code'; continue }
            if ($c -ne "`r" -and $c -ne "`n") { $masked[$i] = ' ' }; $i++; continue
        }
        if ($state -eq 'string' -or $state -eq 'char') {
            if ($c -eq '\') { $masked[$i] = ' '; if ($i + 1 -lt $chars.Length) { if ($chars[$i + 1] -ne "`r" -and $chars[$i + 1] -ne "`n") { $masked[$i + 1] = ' ' }; $i += 2; continue } }
            if (($state -eq 'string' -and $c -eq '"') -or ($state -eq 'char' -and $c -eq "'")) { $masked[$i] = ' '; $state = 'code'; $i++; continue }
            if ($c -ne "`r" -and $c -ne "`n") { $masked[$i] = ' ' }; $i++; continue
        }
        if ($i + 1 -lt $chars.Length -and $c -eq '/' -and $chars[$i + 1] -eq '/') { $masked[$i] = ' '; $masked[$i + 1] = ' '; $state = 'line'; $i += 2; continue }
        if ($i + 1 -lt $chars.Length -and $c -eq '/' -and $chars[$i + 1] -eq '*') { $masked[$i] = ' '; $masked[$i + 1] = ' '; $state = 'block'; $depth = 1; $i += 2; continue }
        $prefix = 0
        if ($c -eq 'r') { $prefix = 1 } elseif ($c -eq 'b' -and $i + 1 -lt $chars.Length -and $chars[$i + 1] -eq 'r') { $prefix = 2 }
        if ($prefix -gt 0) {
            $q = $i + $prefix; while ($q -lt $chars.Length -and $chars[$q] -eq '#') { $q++ }
            if ($q -lt $chars.Length -and $chars[$q] -eq '"') { $hashes = $q - $i - $prefix; for ($j = 0; $j -le $hashes + $prefix; $j++) { $masked[$i + $j] = ' ' }; $i = $q + 1; $state = 'raw'; continue }
        }
        if ($c -eq '"') { $masked[$i] = ' '; $state = 'string'; $i++; continue }
        if ($c -eq "'" -and $i + 2 -lt $chars.Length -and ($chars[$i + 2] -eq "'" -or $chars[$i + 1] -eq '\')) { $masked[$i] = ' '; $state = 'char'; $i++; continue }
        $i++
    }
    if ($state -ne 'code' -and $state -ne 'line') { Fail "unterminated lexical region: $state" }
    -join $masked
}

function Find-ClosingDelimiter([string] $Text, [int] $Open) {
    $pairs = @{ '(' = ')'; '{' = '}'; '[' = ']' }; if (-not $pairs.ContainsKey([string]$Text[$Open])) { return -1 }
    $stack = [Collections.Generic.Stack[char]]::new(); $stack.Push([char]$Text[$Open])
    for ($i = $Open + 1; $i -lt $Text.Length; $i++) {
        $c = $Text[$i]
        if ($pairs.ContainsKey([string]$c)) { $stack.Push([char]$c); continue }
        if ($pairs.Values -contains [string]$c) { if ($stack.Count -eq 0 -or $c -ne $pairs[[string]$stack.Peek()]) { return -1 }; $null = $stack.Pop(); if ($stack.Count -eq 0) { return $i } }
    }
    -1
}

function Get-LineStarts([string] $Text) { $r = [Collections.Generic.List[int]]::new(); $r.Add(0); for ($i = 0; $i -lt $Text.Length; $i++) { if ($Text[$i] -eq "`n") { $r.Add($i + 1) } }; [int[]]$r }
function Get-LineNumber([int[]] $Starts, [int] $Offset) { $lo = 0; $hi = $Starts.Count - 1; while ($lo -le $hi) { $mid = [int](($lo + $hi) / 2); if ($Starts[$mid] -le $Offset) { $lo = $mid + 1 } else { $hi = $mid - 1 } }; $hi + 1 }

function Get-AnchorSets([string] $Normative, [string] $Recovery) {
    $n = @{}; $fence = $null; $fenceLength = 0
    foreach ($line in (Split-Lines $Normative)) {
        if ($null -ne $fence) { if ($line -match ('^[ \t]*' + [regex]::Escape([string]$fence) + '{' + $fenceLength + ',}[ \t]*$')) { $fence = $null }; continue }
        $fm = [regex]::Match($line, '^[ \t]*(?<f>`{3,}|~{3,})'); if ($fm.Success) { $fence = $fm.Groups['f'].Value[0]; $fenceLength = $fm.Groups['f'].Value.Length; continue }
        $hm = [regex]::Match($line, '^[ \t]*#{1,6}[ \t]+(?<id>(?:A|I)[0-9]+(?:\.[0-9]+)+)(?:\.|[ \t])'); if ($hm.Success) { $n[$hm.Groups['id'].Value] = $true }
    }
    $w = @{}; foreach ($m in [regex]::Matches($Recovery, '(?<![A-Za-z0-9_-])(?:W[0-9]+-[0-9]{2}|A-[0-9]{2})(?![A-Za-z0-9_-])')) { $w[$m.Value] = $true }
    [pscustomobject]@{ Normative = $n; Work = $w }
}

function Get-TestRanges([string] $Masked) {
    $ranges = [Collections.Generic.List[object]]::new()
    $attributePattern = '#\s*\[\s*(?:cfg\s*\(\s*test\s*\)|test)\s*\]'
    foreach ($attribute in [regex]::Matches($Masked, $attributePattern)) {
        $open = $Masked.IndexOf('{', $attribute.Index + $attribute.Length)
        if ($open -lt 0 -or $open -gt [Math]::Min($Masked.Length, $attribute.Index + 4096)) { continue }
        $close = Find-ClosingDelimiter $Masked $open
        if ($close -ge 0) { $ranges.Add([pscustomobject]@{ Start = $attribute.Index; End = $close }) }
    }
    foreach ($module in [regex]::Matches($Masked, '\bmod\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{')) {
        if ($module.Groups['name'].Value -notmatch '(?i)^(?:test|tests|test_|.*_tests)$') { continue }
        $open = $Masked.IndexOf('{', $module.Index + $module.Length - 1); $close = Find-ClosingDelimiter $Masked $open
        if ($close -ge 0) { $ranges.Add([pscustomobject]@{ Start = $module.Index; End = $close }) }
    }
    @($ranges.ToArray())
}

function Test-InTestRange([object[]] $Ranges, [int] $Offset) {
    foreach ($range in $Ranges) { if ($Offset -ge $range.Start -and $Offset -le $range.End) { return $true } }; $false
}

function Test-ConsumerMacro([string] $Masked, [int] $Start) {
    $prefix = $Masked.Substring(0, $Start); $macroPattern = '(?<![A-Za-z0-9_])(?<name>matches|assert_matches|assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne)!\s*\('
    $invocations = [regex]::Matches($prefix, $macroPattern)
    for ($index = $invocations.Count - 1; $index -ge 0; $index--) {
        $invocation = $invocations[$index]; $open = $invocation.Index + $invocation.Length - 1; $close = Find-ClosingDelimiter $Masked $open
        if ($close -lt $Start) { continue }
        if ($invocation.Groups['name'].Value -in @('matches','assert_matches','assert','assert_eq','assert_ne','debug_assert','debug_assert_eq','debug_assert_ne')) { return $true }
        $depth = 0; $topLevelComma = $false
        for ($i = $open + 1; $i -lt $Start; $i++) {
            $c = $Masked[$i]
            if ($c -in @('(', '{', '[')) { $depth++; continue }
            if ($c -in @(')', '}', ']')) { if ($depth -gt 0) { $depth-- }; continue }
            if ($c -eq ',' -and $depth -eq 0) { $topLevelComma = $true }
        }
        if ($topLevelComma) { return $true }
    }
    $false
}

function Test-LetPattern([string] $Masked, [int] $Start) {
    $prefix = $Masked.Substring(0, $Start); $letMatches = [regex]::Matches($prefix, '\b(?:if\s+|while\s+)?let\b'); if ($letMatches.Count -eq 0) { return $false }
    $let = $letMatches[$letMatches.Count - 1]; $boundary = [Math]::Max($prefix.LastIndexOf(';'), [Math]::Max($prefix.LastIndexOf('{'), $prefix.LastIndexOf('}')))
    if ($let.Index -lt $boundary) { return $false }
    $eq = $prefix.LastIndexOf('='); $eq -lt $let.Index
}

function Test-MatchArmPattern([string] $Masked, [int] $End) {
    $depth = 0; $limit = [Math]::Min($Masked.Length, $End + 4096)
    for ($i = $End + 1; $i -lt $limit; $i++) {
        $c = $Masked[$i]
        if ($c -in @('(', '{', '[')) { $depth++; continue }
        if ($c -in @(')', '}', ']')) { if ($depth -gt 0) { $depth-- }; continue }
        if ($depth -eq 0) {
            if ($i + 1 -lt $Masked.Length -and $Masked.Substring($i, 2) -eq '=>') { return $true }
            if ($c -eq ';') { return $false }
        }
    }
    $false
}

function Test-PatternOccurrence([string] $Masked, [int] $Start, [int] $End) {
    if (Test-ConsumerMacro $Masked $Start) { return $true }
    if (Test-LetPattern $Masked $Start) { return $true }
    if (Test-MatchArmPattern $Masked $End) { return $true }
    $false
}

function Get-UnsupportedEvidence([string] $Raw, [string] $Relative, [string] $Variant) {
    if ($Variant -in @('UnsupportedPlatform','UnsupportedProfile')) { return 'variant-name' }
    if ($Raw -match '(?i)platform|profile|target_os|target_arch|host|capabilit') { return 'context' }
    if ($Relative -match '(?i)platform|profile|host|capabilit') { return 'file-name' }
    $null
}

function Get-SourceFiles([string] $Root) {
    $cached = @(& git -C $Root ls-files --cached -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git ls-files --cached exited $LASTEXITCODE" }
    $untracked = @(& git -C $Root ls-files --others --exclude-standard -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git ls-files --others exited $LASTEXITCODE" }
    $set = @{}
    foreach ($path in @($cached) + @($untracked)) {
        if ([string]::IsNullOrWhiteSpace([string]$path)) { continue }
        $normalized = ([string]$path).Replace('\','/')
        if ($normalized.StartsWith('/') -or $normalized -match '(^|/)\.\.(?:/|$)' -or [IO.Path]::IsPathRooted($normalized)) { Fail "source path is not repository-relative: $normalized" }
        $set[$normalized] = $true
    }
    $files = @($set.Keys); [Array]::Sort($files, [StringComparer]::Ordinal); [string[]]$files
}

function Get-SourceManifest([string] $Root, [string[]] $SourceFiles) {
    $manifest = [Collections.Generic.List[object]]::new(); $digestLines = [Collections.Generic.List[string]]::new()
    foreach ($relative in $SourceFiles) {
        $relative = Assert-RepoRelative $relative 'source path'; $absolute = Join-Path $Root $relative; if (-not (Test-Path $absolute -PathType Leaf)) { Fail "source file missing: $relative" }
        $digest = Sha ([IO.File]::ReadAllBytes($absolute)); $manifest.Add([ordered]@{ path = $relative; sha256 = $digest }); $digestLines.Add("$relative=$digest")
    }
    [pscustomobject]@{ Files = @($manifest.ToArray()); DigestLines = @($digestLines.ToArray()); Aggregate = ShaText (($digestLines -join "`n") + "`n") }
}

function Get-ContentProvenance([string] $Root, [string[]] $SourceFiles, [string[]] $NormativePaths, [string] $MechanismPath, [string] $RegistryPath) {
    $source = Get-SourceManifest $Root $SourceFiles; $lines = [Collections.Generic.List[string]]::new(); $lines.Add('source-universe=git-cached-plus-nonignored-untracked-rust')
    foreach ($line in $source.DigestLines) { $lines.Add("source|$line") }
    foreach ($path in $NormativePaths) { $lines.Add("normative|$path|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $path))))") }
    $lines.Add("mechanism-review|$MechanismPath|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $MechanismPath))))")
    $lines.Add("registry-boundary|$RegistryPath|$(Sha ([IO.File]::ReadAllBytes((Join-Path $Root $RegistryPath))))")
    [pscustomobject]@{ Source = $source; ContentDigest = ShaText (($lines -join "`n") + "`n"); Lines = @($lines.ToArray()) }
}

function Get-ArtifactHashes([string] $Root, [string[]] $ArtifactPaths, [string] $SelfPath, [string] $GeneratedCsv) {
    $entries = [Collections.Generic.List[object]]::new()
    foreach ($path0 in $ArtifactPaths) {
        $path = Assert-RepoRelative $path0 'artifact path'
        if ($path -ceq $SelfPath) { continue }
        $absolute = Join-Path $Root $path
        if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { Fail "artifact missing: $path" }
        $bytes = if ($path -ceq 'swarm/inventory/refusals.csv') { [Text.Encoding]::UTF8.GetBytes($GeneratedCsv) } else { [IO.File]::ReadAllBytes($absolute) }
        $entries.Add([ordered]@{ path = $path; sha256 = Sha $bytes })
    }
    @($entries.ToArray() | Sort-Object path -Culture '')
}

function Get-RefusalSites([string] $Root, [object] $Anchors, [string[]] $SourceFiles) {
    $strict = [Text.UTF8Encoding]::new($false, $true); $rows = [Collections.Generic.List[object]]::new()
    $pattern = '(?<![A-Za-z0-9_])(?:(?<macro>todo|unimplemented)!\s*(?<open>\()|(?<type>(?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Z][A-Za-z0-9_]*)\s*::\s*(?<variant>PlanGap|Unsupported|UnsupportedPlatform|UnsupportedProfile|Unimplemented|Unavailable)\b)'
    foreach ($relative in [string[]]$SourceFiles) {
        $relative = $relative.Replace('\','/'); $absolute = Join-Path $Root $relative; $raw = [IO.File]::ReadAllText($absolute, $strict); $masked = Get-LexicallyMasked $raw; $testRanges = @(Get-TestRanges $masked); $starts = Get-LineStarts $raw; $digest = Sha ([IO.File]::ReadAllBytes($absolute))
        foreach ($m in [regex]::Matches($masked, $pattern)) {
            $start = $m.Index; $end = $m.Index + $m.Length - 1; $variant = if ($m.Groups['macro'].Success) { $m.Groups['macro'].Value } else { $m.Groups['variant'].Value }
            if ($m.Groups['macro'].Success) { $open = $m.Index + $m.Groups['open'].Index; $close = Find-ClosingDelimiter $masked $open; if ($close -lt 0) { Fail "unbalanced macro delimiter: ${relative}:$(Get-LineNumber $starts $start)" }; $end = $close }
            else {
                $next = $m.Index + $m.Length; while ($next -lt $masked.Length -and [char]::IsWhiteSpace($masked[$next])) { $next++ }
                if ($next -lt $masked.Length -and $masked[$next] -in @('(','{')) { $close = Find-ClosingDelimiter $masked $next; if ($close -lt 0) { Fail "unbalanced typed delimiter: ${relative}:$(Get-LineNumber $starts $start)" }; $end = $close }
            }
            if (-not $m.Groups['macro'].Success -and (Test-PatternOccurrence $masked $start $end)) { continue }
            $line = Get-LineNumber $starts $start; $endLine = Get-LineNumber $starts $end; $span = $raw.Substring($start, $end - $start + 1); $column = $start - $starts[$line - 1] + 1
            $norm = @([regex]::Matches($span, '(?<![A-Za-z0-9_-])(?:A|I)[0-9]+(?:\.[0-9]+)+(?![A-Za-z0-9_-])') | ForEach-Object { $_.Value } | Where-Object { $Anchors.Normative.ContainsKey($_) } | Select-Object -Unique); $work = @([regex]::Matches($span, '(?<![A-Za-z0-9_-])(?:W[0-9]+-[0-9]{2}|A-[0-9]{2})(?![A-Za-z0-9_-])') | ForEach-Object { $_.Value } | Where-Object { $Anchors.Work.ContainsKey($_) } | Select-Object -Unique)
            $evidence = Get-UnsupportedEvidence $span $relative $variant
            if ($variant -in @('todo','unimplemented','Unimplemented','PlanGap')) { $classification = 'Unimplemented'; $reason = if ($variant -eq 'PlanGap') { 'PlanGap is a missing-work contract, never Designed' } else { 'explicit missing-work marker' } }
            elseif ($variant -eq 'Unavailable') { $classification = 'Unknown'; $reason = 'runtime availability state is not proof of missing work and is not conflated with Unsupported' }
            elseif ($variant -in @('Unsupported','UnsupportedPlatform','UnsupportedProfile')) { if ($null -ne $evidence) { $classification = 'Designed'; $reason = "intentional unsupported platform/profile or capability refusal; evidence=$evidence" } else { $classification = 'Unknown'; $reason = 'Unsupported constructor lacks platform/profile evidence; conservative Unknown' } }
            else { $classification = 'Unknown'; $reason = 'refusal-like syntax has no conservative contract classification' }
            $isTest = ($relative -match '(^|/)(tests?|fixtures?)(/|$)' -or $relative -match '(^|/)[^/]+_tests?\.rs$' -or (Test-InTestRange $testRanges $start)); $family = if ($m.Groups['macro'].Success) { "macro/$($m.Groups['macro'].Value)!" } else { "typed/$($m.Groups['type'].Value)::$variant" }; $key = "$relative|$family|$line|$endLine|$column|$span"; $id = 'R1-' + (ShaText $key).Substring(0, 24)
            $rows.Add([pscustomobject][ordered]@{ stable_id = $id; file = $relative; line = $line; end_line = $endLine; scope = if ($isTest) { 'test-only' } else { 'production-or-mixed' }; syntactic_contract_family = $family; normative_anchor = if ($norm.Count) { $norm -join ';' } else { 'UNKNOWN' }; work_item_anchor = if ($work.Count) { $work -join ';' } else { 'UNKNOWN' }; classification = $classification; reason = $reason; evidence = (($span -replace '\s+', ' ').Trim()); source_sha256 = $digest })
        }
    }
    @($rows | Sort-Object file,line,end_line,syntactic_contract_family,stable_id)
}

function CsvField([string] $Value) { '"' + ($Value -replace '"','""') + '"' }
function CsvDocument([object[]] $Rows) { $columns = @('stable_id','file','line','end_line','scope','syntactic_contract_family','normative_anchor','work_item_anchor','classification','reason','evidence','source_sha256'); $lines = [Collections.Generic.List[string]]::new(); $lines.Add(($columns | ForEach-Object { CsvField $_ }) -join ','); foreach ($row in $Rows) { $lines.Add(($columns | ForEach-Object { CsvField ([string]$row.$_) }) -join ',') }; ($lines -join "`n") + "`n" }

$censusDefinition = 'Exact source universe is the sorted union of Git-cached and Git nonignored-untracked Rust files; exact lexical grammar: todo!(...) and unimplemented!(...) plus TypePath::{PlanGap,Unsupported,UnsupportedPlatform,UnsupportedProfile,Unimplemented,Unavailable} constructor/production occurrences; comments, strings, raw strings, chars masked; match arms, let/if-let/while-let patterns, matches!/assert_matches!/assert consumers and nested wrappers excluded; cfg(test)/#[test]/test-module ranges are test-only even inside src/lib.rs; test-only rows retained and scoped.'
$grammar = 'Rust lexical masking; macro=(todo|unimplemented)! ( balanced ); typed=(module::)*UpperIdent::(PlanGap|Unsupported|UnsupportedPlatform|UnsupportedProfile|Unimplemented|Unavailable) followed by balanced (), {} or unit production; consumer detection walks delimiter-aware matches!/assert_matches!/assert wrappers, let patterns, and match-arm arrows, including Err/Some/tuple/struct wrappers; cfg(test), #[test], and test-named module lexical ranges determine test-only scope.'
$normativePairPaths = @('docs/normative/ELIOT_ARCHITECTURE.md','docs/normative/ELIOT_IMPLEMENTATION.md')
$csvSchema = @('stable_id','file','line','end_line','scope','syntactic_contract_family','normative_anchor','work_item_anchor','classification','reason','evidence','source_sha256')
$outputPaths = @('swarm/inventory/refusals.csv','swarm/results/W1-02.json')
$mechanismReviewPath = 'swarm/challenges/W1-02-MECHANISM-REVIEW.md'
$registryBoundaryPath = 'swarm/challenges/W0-01-HONEST-EMPTY.md'
$proofCeiling = 'Static source census and reproducibility only; no runtime capability proof.'

try {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $root 'swarm/inventory/refusals.csv' } elseif (-not [IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $root $OutputPath }
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $root 'swarm/results/W1-02.json' } elseif (-not [IO.Path]::IsPathRooted($ResultPath)) { $ResultPath = Join-Path $root $ResultPath }
    if ($Check -and ($PSBoundParameters.ContainsKey('OutputPath') -or $PSBoundParameters.ContainsKey('ResultPath'))) { Fail '-Check validates only canonical W1-02 outputs' }
    $strict = [Text.UTF8Encoding]::new($false, $true)
    $normativePaths = @((Join-Path $root $normativePairPaths[0]), (Join-Path $root $normativePairPaths[1]))
    $normative = [IO.File]::ReadAllText($normativePaths[0], $strict) + "`n" + [IO.File]::ReadAllText($normativePaths[1], $strict)
    $recovery = [IO.File]::ReadAllText((Join-Path $root 'docs/tasks/RECOVERY_PROGRAM_v1.md'), $strict)
    $anchors = Get-AnchorSets $normative $recovery
    $sourceFiles = Get-SourceFiles $root
    $rows = @(Get-RefusalSites $root $anchors $sourceFiles)
    $csv = CsvDocument $rows
    $mechanismReviewAbsolute = Join-Path $root $mechanismReviewPath
    $registryBoundaryAbsolute = Join-Path $root $registryBoundaryPath
    if (-not (Test-Path $mechanismReviewAbsolute -PathType Leaf) -or -not (Test-Path $registryBoundaryAbsolute -PathType Leaf)) { Fail 'required challenge linkage file missing' }
    $provenance = Get-ContentProvenance $root $sourceFiles $normativePairPaths $mechanismReviewPath $registryBoundaryPath
    $aggregate = $provenance.Source.Aggregate
    $counts = [ordered]@{ Designed = @($rows | ? classification -eq Designed).Count; Unimplemented = @($rows | ? classification -eq Unimplemented).Count; Unknown = @($rows | ? classification -eq Unknown).Count }
    $unknownNorm = @($rows | ? normative_anchor -eq UNKNOWN).Count
    $unknownWork = @($rows | ? work_item_anchor -eq UNKNOWN).Count
    $result = [ordered]@{
        schema_version = 'eliot-refusal-inventory-v2'
        authority_status = 'EVIDENCE_ONLY'
        contract_status = 'CONTRACT_CHALLENGE'
        work_item_id = 'W1-02'
        census_definition = $censusDefinition
        grammar = $grammar
        historical_baseline = 1371
        historical_baseline_status = 'CONTRACT_CHALLENGE_UNKNOWN_BASELINE'
        historical_baseline_note = '1371 is non-binding because its source methodology is unavailable and was not reproduced; current count is independently generated.'
        current_row_count = $rows.Count
        classification_counts = $counts
        anchor_uncertainty = [ordered]@{ unknown_normative_anchor_count = $unknownNorm; unknown_work_item_anchor_count = $unknownWork; note = 'UNKNOWN anchors are explicit evidence gaps: the source span contains no validated normative/work identifier; they are not inferred from the historical 1371 baseline.' }
        source_file_count = $sourceFiles.Count
        source_digest_aggregate = $aggregate
        normative_pair_sha256 = ShaText $normative
        normative_pair_paths = $normativePairPaths
        csv_schema = $csvSchema
        outputs = $outputPaths
        proof_ceiling = $proofCeiling
        mechanism_review = [ordered]@{ path = $mechanismReviewPath; status = 'MECHANISM_CHANGED_ONE_SHOT_AUTHORIZED_IN_PROGRESS'; sha256 = Sha ([IO.File]::ReadAllBytes($mechanismReviewAbsolute)) }
        registry_boundary = [ordered]@{ path = $registryBoundaryPath; status = 'HONEST_EMPTY_BOUNDARY_ACCEPTED'; sha256 = Sha ([IO.File]::ReadAllBytes($registryBoundaryAbsolute)) }
        provenance = [ordered]@{
            schema_version = 'eliot-content-provenance-v1'
            source_universe = 'git-cached-plus-nonignored-untracked-rust'
            source_files = @($provenance.Source.Files)
            source_manifest_sha256 = $aggregate
            normative_pair = @($normativePairPaths | ForEach-Object { [ordered]@{ path = $_; sha256 = Sha ([IO.File]::ReadAllBytes((Join-Path $root $_))) } })
            mechanism_review = [ordered]@{ path = $mechanismReviewPath; sha256 = (Sha ([IO.File]::ReadAllBytes($mechanismReviewAbsolute))) }
            registry_boundary = [ordered]@{ path = $registryBoundaryPath; sha256 = (Sha ([IO.File]::ReadAllBytes($registryBoundaryAbsolute))) }
            artifact_hashes = @(Get-ArtifactHashes $root $outputPaths $outputPaths[1] $csv)
            content_digest = $provenance.ContentDigest
        }
        structured_evidence = [ordered]@{
            authority_status = 'EVIDENCE_ONLY'
            work_item_id = 'W1-02'
            disposition = 'challenged'
            artifacts = @($outputPaths)
            evidence = @('pwsh -NoProfile -File scripts/gen-refusals.ps1 -Check','pwsh -NoProfile -File scripts/verify-refusals.ps1 -SelfTest','pwsh -NoProfile -File scripts/verify-refusals.ps1')
            discriminator_before = 'Prior result bound census provenance to mutable HEAD/worktree state and used a tracked-only source universe.'
            discriminator_after = 'Both canonical outputs are regenerated from the sorted cached-plus-nonignored-untracked Rust universe and content-bound provenance; no HEAD/worktree state is serialized.'
            uncertainty = @('Historical 1371 baseline has no reproducible source methodology and remains non-binding.','Static census does not prove runtime capability.')
            unresolved_questions = @('Whether UNKNOWN rows can later be promoted requires a separate source-backed contract decision.')
            proposed_effects = @('Do not write UNKNOWN-anchor rows into docs/UNIMPLEMENTED.md; preserve W0-01 honest-empty boundary.')
            evidence_lineage = [ordered]@{ provenance = 'provenance.content_digest'; mechanism_review = $mechanismReviewPath; registry_boundary = $registryBoundaryPath; program_revision = 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md' }
        }
    }
    $evidenceProfile = $result['structured_evidence']
    $null = $result.Remove('structured_evidence')
    foreach ($property in $evidenceProfile.Keys) {
        if ($property -ne 'work_item_id' -and -not $result.Contains($property)) { $result[$property] = $evidenceProfile[$property] }
    }
    $result = [ordered]@{
        schema_version = 'eliot.bootstrap-work-result.v1'
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-02'
        structured_result = [pscustomobject]$result
    }
    $json = (($result | ConvertTo-Json -Depth 10) -replace "`r`n", "`n") + "`n"
    if ($Check) { if (-not (Test-Path $OutputPath -PathType Leaf) -or -not (Test-Path $ResultPath -PathType Leaf)) { Fail 'canonical output missing' }; if ([IO.File]::ReadAllText($OutputPath,$strict) -cne $csv) { Fail 'refusals.csv is stale or tampered' }; if ([IO.File]::ReadAllText($ResultPath,$strict) -cne $json) { Fail 'W1-02.json is stale or tampered' }; Write-Output "REFUSAL_GENERATE_CHECK: PASS rows=$($rows.Count) Designed=$($counts.Designed) Unimplemented=$($counts.Unimplemented) Unknown=$($counts.Unknown)"; exit 0 }
    foreach ($path in @($OutputPath,$ResultPath)) { $parent = Split-Path -Parent $path; if (-not (Test-Path $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null } }; [IO.File]::WriteAllText($OutputPath,$csv,[Text.UTF8Encoding]::new($false)); [IO.File]::WriteAllText($ResultPath,$json,[Text.UTF8Encoding]::new($false)); Write-Output "REFUSAL_GENERATE: PASS rows=$($rows.Count) Designed=$($counts.Designed) Unimplemented=$($counts.Unimplemented) Unknown=$($counts.Unknown)"
} catch { Write-Error $_.Exception.Message; exit 1 }
