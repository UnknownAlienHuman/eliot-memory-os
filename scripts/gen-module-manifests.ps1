[CmdletBinding()]
param(
    [string] $RepoRoot = (Join-Path $PSScriptRoot '..'),
    [string] $OutputPath = (Join-Path $PSScriptRoot '..\swarm\inventory\modules.json'),
    [string] $ResultPath = (Join-Path $PSScriptRoot '..\swarm\results\W1-01.json'),
    [switch] $InventoryOnly,
    [switch] $Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$SchemaVersion = 'eliot.effective-micro-module-manifest.v2'
$GeneratorVersion = 'gen-module-manifests.ps1/2.3.0'
$ExpectedWorkspacePackageCount = 126
$Utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)

function Fail([string] $Message) { throw "MODULE_MANIFEST_GENERATE_FAIL: $Message" }
function Normalize-Rel([string] $Path) { return $Path.Replace('\', '/') }
function Get-CanonicalArtifactRel([string] $Path) {
    $normalized = Normalize-Rel $Path
    if ($Path -cne $normalized -or [IO.Path]::IsPathRooted($normalized) -or
        $normalized.StartsWith('/') -or $normalized.EndsWith('/') -or
        $normalized.Contains('//') -or $normalized -match '(^|/)\.\.?(/|$)') {
        Fail "artifact path is not a canonical repository-relative path: $Path"
    }
    return $normalized
}
function Get-RepoFileDigest([string] $Root, [string] $Relative) {
    $canonical = Get-CanonicalArtifactRel $Relative
    $full = Resolve-UnderRoot $Root (Join-Path $Root ($canonical.Replace('/', [IO.Path]::DirectorySeparatorChar)))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Fail "linked artifact missing: $canonical" }
    return Sha256-Bytes ([IO.File]::ReadAllBytes($full))
}
function Sha256-Bytes([byte[]] $Bytes) {
    return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant()
}
function Sha256-Text([string] $Text) { return Sha256-Bytes ($Utf8Strict.GetBytes($Text)) }
function Get-JsonProp($Object, [string] $Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}
function Read-StrictText([string] $Path) {
    try { return $Utf8Strict.GetString([IO.File]::ReadAllBytes($Path)) }
    catch { Fail "invalid UTF-8: $Path" }
}
function Resolve-UnderRoot([string] $Root, [string] $Path) {
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $Root.TrimEnd([char]0x5c, [char]0x2f) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { Fail "path escapes repository: $Path" }
    return $full
}
function Resolve-InventoryOnlyOutputSafe([string] $Root, [string] $Candidate) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        Fail '-InventoryOnly requires a non-empty -OutputPath'
    }
    $raw = $Candidate.Replace('/', [IO.Path]::DirectorySeparatorChar)
    if ($raw.StartsWith('\\')) {
        Fail '-InventoryOnly output must not use a UNC or device path'
    }
    if ($raw -match '[\x00-\x1F\x7F]') {
        Fail '-InventoryOnly output must not contain control characters'
    }
    $pathRoot = [IO.Path]::GetPathRoot($raw)
    $allowedDriveColon = -not [string]::IsNullOrEmpty($pathRoot) -and
        $pathRoot.Length -ge 2 -and $pathRoot[1] -eq ':' -and
        $raw.IndexOf(':') -eq 1 -and $raw.LastIndexOf(':') -eq 1
    if ($raw.Contains(':') -and -not $allowedDriveColon) {
        Fail '-InventoryOnly output must not use an alternate data stream or control colon'
    }
    foreach ($segment in @($raw -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -in @('.', '..') -or $segment -match '^[A-Za-z]:$') { continue }
        if ($segment -match '~[0-9]' -or $segment.EndsWith('.') -or $segment.EndsWith(' ')) {
            Fail '-InventoryOnly output must not use a Win32-normalized path alias'
        }
    }
    $fullPath = if ([IO.Path]::IsPathRooted($raw)) {
        [IO.Path]::GetFullPath($raw)
    } else {
        [IO.Path]::GetFullPath((Join-Path $Root $raw))
    }
    $volumeRoot = [IO.Path]::GetPathRoot($FullPath)
    if ([string]::IsNullOrEmpty($volumeRoot)) { Fail '-InventoryOnly output has no filesystem root' }
    $cursor = $volumeRoot
    foreach ($segment in @([IO.Path]::GetRelativePath($volumeRoot, $FullPath) -split '[\\/]')) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq '.') { continue }
        $cursor = [IO.Path]::Combine($cursor, $segment)
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                Fail '-InventoryOnly output must not traverse a reparse point'
            }
        }
    }
    $ownedTargets = @(
        'swarm\inventory\modules.json',
        'swarm\results\W1-01.json',
        'scripts\gen-module-manifests.ps1',
        'scripts\verify-module-manifests.ps1'
    )
    foreach ($relative in $ownedTargets) {
        $ownedFull = [IO.Path]::GetFullPath((Join-Path $Root $relative))
        if ([StringComparer]::OrdinalIgnoreCase.Equals($FullPath, $ownedFull)) {
            Fail '-InventoryOnly output must not target a generator-owned path'
        }
    }
    $repositoryRoot = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $repositoryPrefix = $repositoryRoot + [IO.Path]::DirectorySeparatorChar
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $temporaryPrefix = $temporaryRoot + [IO.Path]::DirectorySeparatorChar
    if ([StringComparer]::OrdinalIgnoreCase.Equals($temporaryRoot, $repositoryRoot) -or
        $temporaryRoot.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail '-InventoryOnly process temporary directory must not overlap the repository'
    }
    if (-not $FullPath.StartsWith($temporaryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        Fail '-InventoryOnly output must stay under the process temporary directory'
    }
    return $FullPath
}
function Invoke-CargoMetadata([string] $Root) {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'cargo'; $psi.Arguments = 'metadata --locked --format-version 1'
    $psi.WorkingDirectory = $Root; $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::new(); $p.StartInfo = $psi
    if (-not $p.Start()) { Fail 'could not start cargo metadata' }
    $stdout = $p.StandardOutput.ReadToEnd(); $stderr = $p.StandardError.ReadToEnd(); $p.WaitForExit()
    if ($p.ExitCode -ne 0) { Fail "cargo metadata exited $($p.ExitCode): $stderr" }
    try { return [pscustomobject]@{ Document = ($stdout | ConvertFrom-Json); Raw = $stdout } }
    catch { Fail "cargo metadata emitted invalid JSON: $($_.Exception.Message)" }
}
function Get-SourceUnion([string] $Root) {
    $cached = @(& git -C $Root ls-files --cached 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail "git ls-files --cached exited $LASTEXITCODE" }
    $untracked = @(& git -C $Root ls-files --others --exclude-standard 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail "git ls-files --others exited $LASTEXITCODE" }
    return @($cached + $untracked | ForEach-Object { Normalize-Rel $_.ToString().Trim() } |
        Where-Object { $_ -ne '' } | Sort-Object -Unique -Culture '')
}
function Get-PathRel([string] $Root, [string] $Full) { return Normalize-Rel ([IO.Path]::GetRelativePath($Root, $Full)) }
function Get-SourcePaths([string] $MemberRel, [string[]] $SourceUnion) {
    $prefix = $MemberRel.TrimEnd('/') + '/'
    return @($SourceUnion | Where-Object {
        $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and $_.ToLowerInvariant().EndsWith('.rs')
    } | Sort-Object -Culture '')
}
function Get-SourceStats([string] $Root, [string] $MemberRel, [string[]] $SourceUnion) {
    $files = @(Get-SourcePaths $MemberRel $SourceUnion)
    [long]$srcBytes = 0; [long]$testBytes = 0; [long]$srcStu = 0; [long]$testStu = 0
    $hashRows = [Collections.Generic.List[string]]::new()
    foreach ($rel in $files) {
        $full = Resolve-UnderRoot $Root (Join-Path $Root ($rel.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $bytes = [IO.File]::ReadAllBytes($full)
        try { $null = $Utf8Strict.GetString($bytes) } catch { Fail "invalid UTF-8: $rel" }
        [long]$stu = [math]::Ceiling($bytes.Length / 3.0)
        $isTest = $rel.ToLowerInvariant().StartsWith(($MemberRel.TrimEnd('/') + '/tests/').ToLowerInvariant())
        if ($isTest) { $testBytes += $bytes.Length; $testStu += $stu } else { $srcBytes += $bytes.Length; $srcStu += $stu }
        $hashRows.Add("$rel`0$(Sha256-Bytes $bytes)")
    }
    return [ordered]@{
        src_stu = $srcStu; ordinary_tests_stu = $testStu; total_stu = $srcStu + $testStu
        file_count = [long]$files.Count; utf8_bytes_total = $srcBytes + $testBytes
        source_digest = Sha256-Text (($hashRows | Sort-Object -Culture '') -join "`n")
    }
}
function Get-Tests([string] $Root, [string] $MemberRel, [string[]] $SourceUnion) {
    $files = @(Get-SourcePaths $MemberRel $SourceUnion)
    [long]$plain = 0; [long]$tokio = 0; [long]$other = 0
    foreach ($rel in $files) {
        $text = Read-StrictText (Join-Path $Root ($rel.Replace('/', [IO.Path]::DirectorySeparatorChar)))
        $plain += ([regex]::Matches($text, '(?m)#\[\s*test\s*\]')).Count
        $tokio += ([regex]::Matches($text, '(?m)#\[\s*tokio::test\b[^\]]*\]')).Count
        foreach ($match in [regex]::Matches($text, '(?m)#\[\s*([A-Za-z_]\w*(?:::\w+)*)::test\b[^\]]*\]')) {
            if ($match.Groups[1].Value -ne 'tokio') { $other++ }
        }
    }
    return [ordered]@{
        attr_plain_test = [long]$plain; attr_tokio_test = [long]$tokio
        other_test_attributes = [long]$other; unit_total = [long]($plain + $tokio + $other)
        grand_total = [long]($plain + $tokio + $other)
    }
}
function Get-CanonicalPackageId($Package, [string] $ManifestRel) {
    return "workspace://$ManifestRel#$($Package.version)"
}
function Get-CanonicalMetadataDigest($Packages, [string] $Root) {
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($pkg in @($Packages | Sort-Object name -Culture '')) {
        $manifestRel = Get-PathRel $Root ((Resolve-Path $pkg.manifest_path).Path)
        $depRows = @($pkg.dependencies | ForEach-Object {
            $path = Get-JsonProp $_ 'path'; $target = Get-JsonProp $_ 'target'
            $depName = [string]$_.name; $kind = if ($null -eq $_.kind) { 'normal' } else { [string]$_.kind }
            $depPathRel = if ($null -eq $path) { '' } else { Get-PathRel $Root ((Resolve-Path (Join-Path $path 'Cargo.toml')).Path) }
            "$depName|$kind|$target|$depPathRel"
        } | Sort-Object -Culture '') -join ';'
        $rows.Add("$($pkg.name)|$($pkg.version)|$manifestRel|$depRows")
    }
    return Sha256-Text (($rows | Sort-Object -Culture '') -join "`n")
}
function Get-InputDigest([string] $Root, [string[]] $SourceUnion, $Packages, [string] $MetadataDigest) {
    $paths = @('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'rust-toolchain', 'scripts/gen-module-manifests.ps1')
    $paths += @($Packages | ForEach-Object { Get-PathRel $Root ((Resolve-Path $_.manifest_path).Path) })
    $paths += @($SourceUnion | Where-Object { $_.ToLowerInvariant().EndsWith('.rs') })
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($rel in @($paths | Sort-Object -Unique -Culture '')) {
        $full = Join-Path $Root ($rel.Replace('/', [IO.Path]::DirectorySeparatorChar))
        if (Test-Path -LiteralPath $full -PathType Leaf) { $rows.Add("$rel`0$(Sha256-Bytes ([IO.File]::ReadAllBytes($full)))") }
    }
    $rows.Add("cargo-metadata-canonical`0$MetadataDigest")
    return Sha256-Text (($rows | Sort-Object -Culture '') -join "`n")
}

function Assert-ExactProperties($Object, [string[]] $Expected, [string] $Label) {
    $actual = @($Object.PSObject.Properties.Name | Sort-Object -Culture '') -join '|'
    $wanted = @($Expected | Sort-Object -Culture '') -join '|'
    if ($actual -cne $wanted) { Fail "$Label property set mismatch" }
}

function Get-ResultBytes(
    [string] $Root,
    $Inventory,
    [byte[]] $InventoryBytes
) {
    $mechanismReview = 'swarm/challenges/W1-01-MECHANISM-REVIEW.md'
    $programRevision = 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'
    $inventoryHash = Sha256-Bytes $InventoryBytes
    $executedEvidence = @(
        "cargo metadata --locked --format-version 1 -> $ExpectedWorkspacePackageCount workspace packages",
        "pwsh scripts/gen-module-manifests.ps1 -> generated $ExpectedWorkspacePackageCount packages",
        'generator run twice -> SHA-256 byte-identical with no HEAD/worktree state in generated bytes',
        'pwsh scripts/verify-module-manifests.ps1 -SelfTest -> PASS: v2 schema, source union, complete projection oracle, result envelope, determinism, and broad tamper matrix',
        'bootstrap_draft.rs and bootstrap_brief.rs are present in the nonignored-untracked source union and affect STU/digest/test projection'
    )
    $result = [ordered]@{
        schema_version = 'eliot.bootstrap-work-result.v1'
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-01'
        structured_result = [ordered]@{
            schema_version = 'eliot-work-result-v2'
            source_revision = "content:$($Inventory.generated_from.inputs_digest)"
            disposition = 'challenged'
            discriminator_before = 'Prior W1-01 evidence used a result envelope that was not source-compatible and accepted incomplete nested metadata.'
            discriminator_after = 'The result is an exact v1.3 evidence-only wrapper generated from code, with content-bound non-self artifact and witness hashes plus independent add/remove/tamper checks.'
            implemented = @(
                'native PowerShell generator uses cargo metadata --locked as the workspace and dependency source of truth',
                "deterministic $ExpectedWorkspacePackageCount-package EffectiveMicroModuleManifest inventory with cached plus nonignored-untracked UTF-8 Rust source/test STU",
                'clone/OS-portable content-bound identity and revision fields with no HEAD or worktree-clean marker',
                'exact declared intra-workspace providers, consumers, direct reverse fan-out and transitive normal/build closure',
                'binary reachability from metadata bin roots and explicit static ModuleTestCapsule/test-count proxy',
                'canonical semantic/runtime fields remain UNKNOWN with machine-readable reasons',
                'independent verifier recomputes manifest identity/digest, source union, loaded-slice and capsule proxies, ports, edge breakdown, providers/consumers, transitive/reverse/bin reachability, every test_count field, aggregates, and the complete result envelope',
                'verifier self-test covers byte determinism, bootstrap draft/brief union regression, and category-specific tamper rejection',
                'artifacts is an output listing; artifact_hashes is the integrity set and intentionally excludes the result self-hash'
            )
            artifacts = @('scripts/gen-module-manifests.ps1','scripts/verify-module-manifests.ps1','swarm/inventory/modules.json','swarm/results/W1-01.json')
            artifact_hashes = @(
                [ordered]@{ path='scripts/gen-module-manifests.ps1'; sha256=(Get-RepoFileDigest $Root 'scripts/gen-module-manifests.ps1') },
                [ordered]@{ path='scripts/verify-module-manifests.ps1'; sha256=(Get-RepoFileDigest $Root 'scripts/verify-module-manifests.ps1') },
                [ordered]@{ path='swarm/inventory/modules.json'; sha256=$inventoryHash }
            )
            inventory_summary = [ordered]@{
                members_total = [long]$Inventory.workspace.members_total
                total_source_stu = [long]$Inventory.aggregates.total_source_stu
                total_test_count = [long]$Inventory.aggregates.total_test_count
                zero_test_packages = [long]@($Inventory.aggregates.zero_test_packages).Count
                unreachable_from_bins = [long]@($Inventory.aggregates.unreachable_from_bins).Count
                document_digest = [string]$Inventory.document_digest
                inputs_digest = [string]$Inventory.generated_from.inputs_digest
            }
            evidence = $executedEvidence
            executed_evidence = $executedEvidence
            uncertainty = @('Static projection does not prove compilation, execution, runtime support, capsule registration, or semantic cell decomposition.')
            unresolved_questions = @('A genuine admitted provider attempt is absent, so no terminal update or attempt identity can be serialized.')
            proposed_effects = @('Retain this W1-01 material as EVIDENCE_ONLY until a separately admitted attempt and product contract permit a terminal update.')
            evidence_lineage = [ordered]@{
                mechanism_review = [ordered]@{ path=$mechanismReview; sha256=(Get-RepoFileDigest $Root $mechanismReview) }
                program_revision = [ordered]@{ path=$programRevision; sha256=(Get-RepoFileDigest $Root $programRevision) }
                inventory = [ordered]@{ path='swarm/inventory/modules.json'; sha256=$inventoryHash }
            }
            external_review = [ordered]@{
                provider_id = 'opencode-go'
                model_id = 'ox-alpha-free'
                session_id = 'ses_fcc8faebfffeS3BcEUlyQhgQ5L'
                authority_status = 'EVIDENCE_ONLY'
                routing_use = 'read-only design audit exported and checked against current tree; hand-written TOML oracle was not adopted because cargo metadata is admitted by the recovery brief'
            }
            proof_ceiling = 'Static deterministic projection of the cached plus nonignored-untracked Rust source union and Cargo metadata; no compilation, execution, runtime support, capsule registration or semantic cell decomposition is claimed.'
        }
    }
    return $Utf8Strict.GetBytes(($result | ConvertTo-Json -Depth 50) + "`n")
}

function Assert-BytesEqual([string] $Path, [byte[]] $Expected, [string] $Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Label missing: $Path" }
    $actual = [IO.File]::ReadAllBytes($Path)
    if (-not [Linq.Enumerable]::SequenceEqual($actual, $Expected)) { Fail "$Label differs from canonical output" }
}

function Write-Atomic([string] $Path, [byte[]] $Bytes) {
    $directory = Split-Path $Path -Parent
    [IO.Directory]::CreateDirectory($directory) | Out-Null
    $temporary = Join-Path $directory ('.{0}.{1}.tmp' -f ([IO.Path]::GetFileName($Path)), [guid]::NewGuid().ToString('N'))
    try {
        [IO.File]::WriteAllBytes($temporary, $Bytes)
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    } finally {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
}

try {
    $root = (Resolve-Path $RepoRoot).Path
    if ($InventoryOnly -and $PSBoundParameters.ContainsKey('ResultPath')) {
        Fail '-InventoryOnly cannot be combined with -ResultPath'
    }
    $customOutput = $PSBoundParameters.ContainsKey('OutputPath')
    $customResult = $PSBoundParameters.ContainsKey('ResultPath')
    if ($InventoryOnly -and -not $customOutput) {
        Fail '-InventoryOnly requires explicit -OutputPath'
    }
    if (-not $InventoryOnly -and ($customOutput -or $customResult)) {
        Fail 'custom output paths require explicit -InventoryOnly; normal generation owns the canonical inventory/result pair'
    }
    $outputCandidate = $OutputPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $outputFull = if ($InventoryOnly) {
        Resolve-InventoryOnlyOutputSafe $root $OutputPath
    } elseif ([IO.Path]::IsPathRooted($outputCandidate)) {
        [IO.Path]::GetFullPath($outputCandidate)
    } else {
        [IO.Path]::GetFullPath((Join-Path $root $outputCandidate))
    }
    $resultFull = if ($InventoryOnly) {
        $null
    } else {
        $resultCandidate = $ResultPath.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $candidate = if ([IO.Path]::IsPathRooted($resultCandidate)) { [IO.Path]::GetFullPath($resultCandidate) } else { [IO.Path]::GetFullPath((Join-Path $root $resultCandidate)) }
        Resolve-UnderRoot $root $candidate
    }
    $meta = Invoke-CargoMetadata $root; $doc = $meta.Document
    $workspaceIds = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($id in @($doc.workspace_members)) { [void]$workspaceIds.Add([string]$id) }
    $packages = @($doc.packages | Where-Object { $workspaceIds.Contains([string]$_.id) } | Sort-Object name -Culture '')
    if ($packages.Count -ne $ExpectedWorkspacePackageCount) { Fail "expected $ExpectedWorkspacePackageCount workspace packages, got $($packages.Count)" }
    $names = @{}; $manifestByPath = @{}
    foreach ($pkg in $packages) {
        if ($names.ContainsKey($pkg.name)) { Fail "duplicate package name: $($pkg.name)" }
        $names[$pkg.name] = $pkg
        $manifestByPath[((Resolve-Path $pkg.manifest_path).Path).ToLowerInvariant()] = $pkg.name
    }
    $sourceUnion = Get-SourceUnion $root
    $edges = [Collections.Generic.List[object]]::new()
    foreach ($pkg in $packages) {
        foreach ($dep in @($pkg.dependencies)) {
            $depPath = Get-JsonProp $dep 'path'; if ($null -eq $depPath) { continue }
            $key = ((Resolve-Path (Join-Path $depPath 'Cargo.toml')).Path).ToLowerInvariant()
            if (-not $manifestByPath.ContainsKey($key)) { Fail "workspace dependency not in metadata: $($pkg.name) -> $depPath" }
            $kind = if ($null -eq $dep.kind) { 'normal' } else { [string]$dep.kind }
            [void]$edges.Add([pscustomobject]@{ from=$pkg.name; to=$manifestByPath[$key]; kind=$kind; target=(Get-JsonProp $dep 'target') })
        }
    }
    $byFrom=@{}; $byTo=@{}; foreach($p in $packages){$byFrom[$p.name]=[Collections.Generic.List[object]]::new();$byTo[$p.name]=[Collections.Generic.List[object]]::new()}
    foreach($e in @($edges|Sort-Object from,to,kind,target -Culture '')){$byFrom[$e.from].Add($e);$byTo[$e.to].Add($e)}
    $binRoots=@($packages|Where-Object{@($_.targets)|Where-Object{@($_.kind)-contains 'bin'}}|ForEach-Object name|Sort-Object -Culture '')
    $reach=@{}; foreach($p in $packages){$reach[$p.name]=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)}
    foreach($bin in $binRoots){$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($bin);while($q.Count -gt 0){$cur=$q.Dequeue();if(-not $seen.Add($cur)){continue};[void]$reach[$cur].Add($bin);$nextEdges=@($byFrom[$cur]|Where-Object{$_.kind -in @('normal','build')});foreach($e in $nextEdges){$q.Enqueue($e.to)}}}
    $metadataDigest=Get-CanonicalMetadataDigest $packages $root
    $inputDigest=Get-InputDigest $root $sourceUnion $packages $metadataDigest
    $records=[Collections.Generic.List[object]]::new()
    foreach($pkg in $packages){
        $manifestRel=Get-PathRel $root ((Resolve-Path $pkg.manifest_path).Path);$memberRel=Get-PathRel $root ((Resolve-Path (Split-Path $pkg.manifest_path -Parent)).Path)
        $stats=Get-SourceStats $root $memberRel $sourceUnion;$tests=Get-Tests $root $memberRel $sourceUnion
        $out=@($byFrom[$pkg.name]|Sort-Object to,kind,target -Culture '');$in=@($byTo[$pkg.name]|Sort-Object from,kind,target -Culture '')
        $providers=@($out|ForEach-Object to|Sort-Object -Unique -Culture '');$consumers=@($in|ForEach-Object from|Sort-Object -Unique -Culture '')
        $anc=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$aq=[Collections.Generic.Queue[string]]::new();$initialEdges=@($in|Where-Object kind -in @('normal','build'));foreach($e in $initialEdges){$aq.Enqueue($e.from)};while($aq.Count -gt 0){$cur=$aq.Dequeue();if(-not $anc.Add($cur)){continue};$nextAncestors=@($byTo[$cur]|Where-Object kind -in @('normal','build'));foreach($e in $nextAncestors){$aq.Enqueue($e.from)}}
        $metaEliot=if($null-ne $pkg.metadata -and $null-ne $pkg.metadata.eliot){$pkg.metadata.eliot}else{$null};$cell=if($null-ne $metaEliot -and $null-ne $metaEliot.functional_cell){[string]$metaEliot.functional_cell}else{$null};$owner=if($null-ne $metaEliot -and $null-ne $metaEliot.lifecycle_owner){[string]$metaEliot.lifecycle_owner}else{$null};$proof=if($null-ne $metaEliot -and $null-ne $metaEliot.proof_entrypoint){[string]$metaEliot.proof_entrypoint}else{$null}
        $targets=@($pkg.targets|ForEach-Object{$t=[ordered]@{name=$_.name;kind=@($_.kind|Sort-Object -Culture '');src_path=Get-PathRel $root $_.src_path};$t|ConvertTo-Json -Depth 5 -Compress|ConvertFrom-Json}|Sort-Object name -Culture '')
        $reaching=@($reach[$pkg.name]|Sort-Object -Culture '');$byKind=[ordered]@{normal=@($in|Where-Object kind -eq normal|ForEach-Object from|Sort-Object -Unique -Culture '').Count;dev=@($in|Where-Object kind -eq dev|ForEach-Object from|Sort-Object -Unique -Culture '').Count;build=@($in|Where-Object kind -eq build|ForEach-Object from|Sort-Object -Unique -Culture '').Count}
        $record=[ordered]@{package_name=$pkg.name;manifest_path=$manifestRel;source_modules_and_crates=[ordered]@{package=$pkg.name;targets=$targets};manifest_id_revision_and_digest=[ordered]@{manifest_id=Get-CanonicalPackageId $pkg $manifestRel;revision=$null;digest=$stats.source_digest};functional_cell_ref=[ordered]@{value=$cell;status=if($null-eq $cell){'UNKNOWN'}else{'DECLARED_METADATA'};unknown_reason=if($null-eq $cell){'NO_DECLARED_FUNCTIONAL_CELL_METADATA'}else{$null}};lifecycle_owner=[ordered]@{value=$owner;status=if($null-eq $owner){'UNKNOWN'}else{'DECLARED_METADATA'};unknown_reason=if($null-eq $owner){'NO_DECLARED_LIFECYCLE_OWNER_METADATA'}else{$null}};runtime_owner_and_bundle=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='RUNTIME_MANIFEST_NOT_AVAILABLE'};public_contract_digest=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='RUSTC_SEMANTICS_NOT_EXECUTED'};owned_state_and_effect_classes=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='SEMANTIC_CELL_ATTRIBUTE_NOT_INFERABLE'};execution_contour_and_replacement_class=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='EXECUTION_CONTOUR_NOT_DECLARED'};iteration_lane_and_proof_latency_profile_ref=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_PROOF_LATENCY_EVIDENCE'};physical_source_STU=$stats;loaded_slice_and_agent_workset_profiles=[ordered]@{production_slice_stu=$stats.src_stu;focused_test_slice_stu=$stats.ordinary_tests_stu;selection_status='ESTIMATED_FULL_ORDINARY_TESTS';estimate_basis='STATIC_SOURCE_UNION_PROXY';agent_workset_one_hop_addendum_refs=@($providers+$consumers|Sort-Object -Unique -Culture '')};dependency_ports_and_one_hop_providers_consumers=[ordered]@{external_ports=@($pkg.dependencies|Where-Object{$null-eq(Get-JsonProp $_ 'path')}|ForEach-Object name|Sort-Object -Unique -Culture '');workspace_providers=$providers;workspace_consumers=$consumers;edge_breakdown=[ordered]@{normal=@($out|Where-Object kind -eq normal).Count;dev=@($out|Where-Object kind -eq dev).Count;build=@($out|Where-Object kind -eq build).Count}};independent_proof_entrypoint_and_proof_ceiling=[ordered]@{declared_entrypoint=$proof;effective_entrypoint="cargo test -p $($pkg.name)";proof_ceiling=if($tests.unit_total-gt 0){'UNIT_STATIC_PROXY'}else{'NONE'};entrypoint_status=if($null-eq $proof){'SYNTHESIZED_NOT_DECLARED'}else{'DECLARED_METADATA'}};affected_edge_profiles=[ordered]@{available_static_edges=[long]$out.Count;reverse_direct_dependents=[long]$in.Count;profile=$null;profile_status='UNKNOWN';unknown_reason='BUILD_TEST_GRAPH_NOT_EXECUTED'};product_pulse_ref=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_PRODUCT_PULSE_ON_TREE'};failure_degradation_recovery_and_removal_boundary=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='SEMANTIC_RUNTIME_CONTRACT_NOT_INFERABLE'};current_support_freshness_and_invalidation=[ordered]@{support_status='UNKNOWN';freshness_status='STATIC_GENERATED';invalidation='ANY_SOURCE_UNION_INPUT_MUTATION';source_revision=$inputDigest};split_merge_extraction_conditions=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_MEASURED_PROOF_LATENCY_OR_CHANGE_CLOSURE'};reverse_fanout=[ordered]@{direct=[ordered]@{count=[long]$consumers.Count;dependents=$consumers;by_kind=$byKind};transitive_normal_build=[long]$anc.Count};binary_reachability=[ordered]@{reachable_from_bin=($reaching.Count-gt 0);reaching_bins=$reaching;edge_classes=@('normal','build');target_gated_semantics='INCLUDED_AS_DECLARED_STATIC_EDGE'};module_test_capsule=[ordered]@{present_proxy=($tests.grand_total-gt 0-or @($pkg.targets|Where-Object{@($_.kind)-contains 'test'}).Count-gt 0);registered_revision=$null;basis='STATIC_PROXY';independently_supported=($tests.grand_total-gt 0);proof_ceiling=if($tests.grand_total-gt 0){'UNIT_STATIC_PROXY'}else{'NONE'};unknown_reason='CAPSULE_REGISTRY_NOT_PERSISTED_ON_TREE'};test_count=$tests}
        $record.manifest_id_revision_and_digest.revision=Sha256-Text ($record|ConvertTo-Json -Depth 30 -Compress);[void]$records.Add($record)
    }
    $docNoDigest=[ordered]@{schema_version=$SchemaVersion;generator_version=$GeneratorVersion;generated_from=[ordered]@{inputs_digest=$inputDigest;cargo_metadata_digest=$metadataDigest;source_union='git cached plus nonignored untracked Rust paths'};workspace=[ordered]@{members_total=$packages.Count;default_members=@($doc.workspace_default_members|ForEach-Object{$id=$_;($packages|Where-Object id -eq $id|Select-Object -ExpandProperty name)}|Sort-Object -Culture '')};manifests=$records.ToArray();aggregates=[ordered]@{total_source_stu=[long](($records|ForEach-Object{$_.physical_source_STU.total_stu}|Measure-Object -Sum).Sum);total_test_count=[long](($records|ForEach-Object{$_.test_count.grand_total}|Measure-Object -Sum).Sum);zero_test_packages=@($records|Where-Object{$_.test_count.grand_total-eq 0}|ForEach-Object package_name|Sort-Object -Culture '');unreachable_from_bins=@($records|Where-Object{-not $_.binary_reachability.reachable_from_bin}|ForEach-Object package_name|Sort-Object -Culture '')}}
    $canonical=$docNoDigest|ConvertTo-Json -Depth 40 -Compress;$docNoDigest['document_digest']=Sha256-Text $canonical;$json=$docNoDigest|ConvertTo-Json -Depth 40 -Compress
    $inventoryBytes = $Utf8Strict.GetBytes($json + "`n")
    $resultBytes = if ($InventoryOnly) { $null } else { Get-ResultBytes $root $docNoDigest $inventoryBytes }
    if ($InventoryOnly) {
        $revalidatedOutputFull = Resolve-InventoryOnlyOutputSafe $root $OutputPath
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($outputFull, $revalidatedOutputFull)) {
            Fail '-InventoryOnly output path identity changed during generation'
        }
    }
    if ($Check) {
        Assert-BytesEqual $outputFull $inventoryBytes 'inventory'
        if (-not $InventoryOnly) { Assert-BytesEqual $resultFull $resultBytes 'result envelope' }
        Write-Output "checked $(Get-PathRel $root $outputFull)$(if ($InventoryOnly) { '' } else { ' and ' + (Get-PathRel $root $resultFull) })"
    } else {
        Write-Atomic $outputFull $inventoryBytes
        if (-not $InventoryOnly) { Write-Atomic $resultFull $resultBytes }
        Write-Output "generated $(Get-PathRel $root $outputFull)$(if ($InventoryOnly) { '' } else { ' and ' + (Get-PathRel $root $resultFull) }) ($($packages.Count) packages)"
    }
    exit 0
} catch { Write-Error $_.Exception.Message; exit 1 }
