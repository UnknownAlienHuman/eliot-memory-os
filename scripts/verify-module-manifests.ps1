[CmdletBinding()]
param(
    [string] $RepoRoot = (Join-Path $PSScriptRoot '..'),
    [string] $InventoryPath = (Join-Path $PSScriptRoot '..\swarm\inventory\modules.json'),
    [string] $ResultPath = (Join-Path $PSScriptRoot '..\swarm\results\W1-01.json'),
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
$SchemaVersion = 'eliot.effective-micro-module-manifest.v2'
$GeneratorVersion = 'gen-module-manifests.ps1/2.3.0'
$ExpectedWorkspacePackageCount = 126
$script:ResultEnvelopeSelfTestsRan = $false

function Fail([string] $Message) { throw "MODULE_MANIFEST_VERIFY_FAIL: $Message" }
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
function Sha256-Bytes([byte[]] $Bytes) { return ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant() }
function Sha256-Text([string] $Text) { return Sha256-Bytes ($Utf8Strict.GetBytes($Text)) }
function Read-StrictText([string] $Path) { try { return $Utf8Strict.GetString([IO.File]::ReadAllBytes($Path)) } catch { Fail "invalid UTF-8: $Path" } }
function Get-JsonProp($Object, [string] $Name) { if ($null -eq $Object) { return $null }; $p=$Object.PSObject.Properties[$Name]; if ($null -eq $p) { return $null }; return $p.Value }
function Resolve-UnderRoot([string] $Root, [string] $Path) { $full=[IO.Path]::GetFullPath($Path);$prefix=$Root.TrimEnd([char]0x5c,[char]0x2f)+[IO.Path]::DirectorySeparatorChar;if(-not $full.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Fail "path escapes repository: $Path"};return $full }
function Get-PathRel([string] $Root, [string] $Full) { return Normalize-Rel ([IO.Path]::GetRelativePath($Root,$Full)) }
function Invoke-CargoMetadata([string] $Root) {
    $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName='cargo';$psi.Arguments='metadata --locked --format-version 1';$psi.WorkingDirectory=$Root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $p=[Diagnostics.Process]::new();$p.StartInfo=$psi;if(-not $p.Start()){Fail 'could not start cargo metadata'};$stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd();$p.WaitForExit();if($p.ExitCode-ne 0){Fail "cargo metadata exited $($p.ExitCode): $stderr"};try{return [pscustomobject]@{Document=($stdout|ConvertFrom-Json);Raw=$stdout}}catch{Fail 'cargo metadata returned invalid JSON'}
}
function Get-SourceUnion([string] $Root) {
    $a=@(& git -C $Root ls-files --cached 2>&1);if($LASTEXITCODE-ne 0){Fail 'git cached listing failed'}
    $b=@(& git -C $Root ls-files --others --exclude-standard 2>&1);if($LASTEXITCODE-ne 0){Fail 'git untracked listing failed'}
    return @($a+$b|ForEach-Object{Normalize-Rel $_.ToString().Trim()}|Where-Object{$_}|Sort-Object -Unique -Culture '')
}
function Get-SourcePaths([string]$MemberRel,[string[]]$Union){$prefix=$MemberRel.TrimEnd('/')+'/';return @($Union|Where-Object{$_.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)-and $_.ToLowerInvariant().EndsWith('.rs')}|Sort-Object -Culture '')}
function Get-Stats([string]$Root,[string]$MemberRel,[string[]]$Union){$files=@(Get-SourcePaths $MemberRel $Union);[long]$src=0;[long]$test=0;[long]$srcBytes=0;[long]$testBytes=0;$rows=[Collections.Generic.List[string]]::new();foreach($rel in $files){$bytes=[IO.File]::ReadAllBytes((Resolve-UnderRoot $Root (Join-Path $Root ($rel.Replace('/',[IO.Path]::DirectorySeparatorChar)))));try{$null=$Utf8Strict.GetString($bytes)}catch{Fail "invalid UTF-8: $rel"};[long]$stu=[math]::Ceiling($bytes.Length/3.0);if($rel.ToLowerInvariant().StartsWith(($MemberRel.TrimEnd('/')+'/tests/').ToLowerInvariant())){$test+=$stu;$testBytes+=$bytes.Length}else{$src+=$stu;$srcBytes+=$bytes.Length};$rows.Add("$rel`0$(Sha256-Bytes $bytes)")};return [ordered]@{src_stu=$src;ordinary_tests_stu=$test;total_stu=$src+$test;file_count=[long]$files.Count;utf8_bytes_total=$srcBytes+$testBytes;source_digest=Sha256-Text (($rows|Sort-Object -Culture '') -join "`n")}}
function Get-TestCounts([string]$Root,[string]$MemberRel,[string[]]$Union){[long]$plain=0;[long]$tokio=0;[long]$other=0;foreach($rel in @(Get-SourcePaths $MemberRel $Union)){$t=Read-StrictText (Join-Path $Root ($rel.Replace('/',[IO.Path]::DirectorySeparatorChar)));$plain+=([regex]::Matches($t,'(?m)#\[\s*test\s*\]')).Count;$tokio+=([regex]::Matches($t,'(?m)#\[\s*tokio::test\b[^\]]*\]')).Count;foreach($m in [regex]::Matches($t,'(?m)#\[\s*([A-Za-z_]\w*(?:::\w+)*)::test\b[^\]]*\]')){if($m.Groups[1].Value-ne 'tokio'){$other++}}};return [ordered]@{attr_plain_test=$plain;attr_tokio_test=$tokio;other_test_attributes=$other;unit_total=$plain+$tokio+$other;grand_total=$plain+$tokio+$other}}
function Get-CanonicalPackageId($Package,[string]$ManifestRel){return "workspace://$ManifestRel#$($Package.version)"}
function Get-MetadataDigest($Packages,[string]$Root){$rows=[Collections.Generic.List[string]]::new();foreach($p in @($Packages|Sort-Object name -Culture '')){$mr=Get-PathRel $Root ((Resolve-Path $p.manifest_path).Path);$deps=@($p.dependencies|ForEach-Object{$path=Get-JsonProp $_ 'path';$dp=if($null-eq $path){''}else{Get-PathRel $Root ((Resolve-Path (Join-Path $path 'Cargo.toml')).Path)};"$($_.name)|$(if($null-eq $_.kind){'normal'}else{[string]$_.kind})|$(Get-JsonProp $_ 'target')|$dp"}|Sort-Object -Culture '')-join ';';$rows.Add("$($p.name)|$($p.version)|$mr|$deps")};return Sha256-Text (($rows|Sort-Object -Culture '')-join "`n")}
function Get-InputDigest([string]$Root,[string[]]$Union,$Packages,[string]$MetaDigest){$paths=@('Cargo.toml','Cargo.lock','rust-toolchain.toml','rust-toolchain','scripts/gen-module-manifests.ps1');$paths+=@($Packages|ForEach-Object{Get-PathRel $Root ((Resolve-Path $_.manifest_path).Path)});$paths+=@($Union|Where-Object{$_.ToLowerInvariant().EndsWith('.rs')});$rows=[Collections.Generic.List[string]]::new();foreach($rel in @($paths|Sort-Object -Unique -Culture '')){$full=Join-Path $Root ($rel.Replace('/',[IO.Path]::DirectorySeparatorChar));if(Test-Path -LiteralPath $full -PathType Leaf){$rows.Add("$rel`0$(Sha256-Bytes ([IO.File]::ReadAllBytes($full)))")}};$rows.Add("cargo-metadata-canonical`0$MetaDigest");return Sha256-Text (($rows|Sort-Object -Culture '')-join "`n")}
function Compare-Json($Actual,$Expected,[string]$Path){$a=($Actual|ConvertTo-Json -Depth 50 -Compress);$e=($Expected|ConvertTo-Json -Depth 50 -Compress);if($a-cne $e){Fail "projection mismatch: $Path"}}
function Assert-UnknownHonesty($Object,[string]$Path='root'){if($null-eq $Object){return};if($Object -is [Collections.IDictionary]){if($Object.status-eq 'UNKNOWN' -and $null-ne $Object.value){Fail "$Path has UNKNOWN with a value"};foreach($k in $Object.Keys){Assert-UnknownHonesty $Object[$k] "$Path.$k"}}elseif($Object -is [pscustomobject]){foreach($p in $Object.PSObject.Properties){Assert-UnknownHonesty $p.Value "$Path.$($p.Name)"}}elseif($Object -is [Collections.IEnumerable]-and -not($Object-is[string])){foreach($v in $Object){Assert-UnknownHonesty $v $Path}}}
function Get-ExpectedDocument([string]$Root,$Meta,[string[]]$Union){$doc=$Meta.Document;$ids=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);foreach($id in @($doc.workspace_members)){[void]$ids.Add([string]$id)};$packages=@($doc.packages|Where-Object{$ids.Contains([string]$_.id)}|Sort-Object name -Culture '');if($packages.Count-ne $ExpectedWorkspacePackageCount){Fail "Cargo workspace package count is $($packages.Count), expected $ExpectedWorkspacePackageCount"};$byPath=@{};foreach($p in $packages){$byPath[((Resolve-Path $p.manifest_path).Path).ToLowerInvariant()]=$p.name};$edges=[Collections.Generic.List[object]]::new();foreach($p in $packages){foreach($d in @($p.dependencies)){$path=Get-JsonProp $d 'path';if($null-eq $path){continue};$key=((Resolve-Path (Join-Path $path 'Cargo.toml')).Path).ToLowerInvariant();if(-not $byPath.ContainsKey($key)){Fail "unresolved workspace dependency: $($p.name)"};$edges.Add([pscustomobject]@{from=$p.name;to=$byPath[$key];kind=if($null-eq $d.kind){'normal'}else{[string]$d.kind};target=(Get-JsonProp $d 'target')})}}
    $from=@{};$to=@{};foreach($p in $packages){$from[$p.name]=[Collections.Generic.List[object]]::new();$to[$p.name]=[Collections.Generic.List[object]]::new()};foreach($e in @($edges|Sort-Object from,to,kind,target -Culture '')){$from[$e.from].Add($e);$to[$e.to].Add($e)};$bins=@($packages|Where-Object{@($_.targets)|Where-Object{@($_.kind)-contains 'bin'}}|ForEach-Object name|Sort-Object -Culture '');$reach=@{};foreach($p in $packages){$reach[$p.name]=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)};foreach($bin in $bins){$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$q=[Collections.Generic.Queue[string]]::new();$q.Enqueue($bin);while($q.Count-gt 0){$cur=$q.Dequeue();if(-not $seen.Add($cur)){continue};[void]$reach[$cur].Add($bin);foreach($e in @($from[$cur]|Where-Object{$_.kind-in @('normal','build')})){$q.Enqueue($e.to)}}}
    $md=Get-MetadataDigest $packages $Root;$input=Get-InputDigest $Root $Union $packages $md;$records=[Collections.Generic.List[object]]::new();foreach($p in $packages){$mr=Get-PathRel $Root ((Resolve-Path $p.manifest_path).Path);$member=Get-PathRel $Root ((Resolve-Path (Split-Path $p.manifest_path -Parent)).Path);$stats=Get-Stats $Root $member $Union;$tests=Get-TestCounts $Root $member $Union;$out=@($from[$p.name]|Sort-Object to,kind,target -Culture '');$in=@($to[$p.name]|Sort-Object from,kind,target -Culture '');$providers=@($out|ForEach-Object to|Sort-Object -Unique -Culture '');$consumers=@($in|ForEach-Object from|Sort-Object -Unique -Culture '');$anc=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$q2=[Collections.Generic.Queue[string]]::new();foreach($e in @($in|Where-Object kind -in @('normal','build'))){$q2.Enqueue($e.from)};while($q2.Count-gt 0){$cur=$q2.Dequeue();if(-not $anc.Add($cur)){continue};foreach($e in @($to[$cur]|Where-Object kind -in @('normal','build'))){$q2.Enqueue($e.from)}};$me=if($null-ne $p.metadata -and $null-ne $p.metadata.eliot){$p.metadata.eliot}else{$null};$cell=if($null-ne $me -and $null-ne $me.functional_cell){[string]$me.functional_cell}else{$null};$owner=if($null-ne $me -and $null-ne $me.lifecycle_owner){[string]$me.lifecycle_owner}else{$null};$proof=if($null-ne $me -and $null-ne $me.proof_entrypoint){[string]$me.proof_entrypoint}else{$null};$targets=@($p.targets|ForEach-Object{$x=[ordered]@{name=$_.name;kind=@($_.kind|Sort-Object -Culture '');src_path=Get-PathRel $Root $_.src_path};$x|ConvertTo-Json -Depth 5 -Compress|ConvertFrom-Json}|Sort-Object name -Culture '');$reaching=@($reach[$p.name]|Sort-Object -Culture '');$bk=[ordered]@{normal=@($in|Where-Object kind -eq normal|ForEach-Object from|Sort-Object -Unique -Culture '').Count;dev=@($in|Where-Object kind -eq dev|ForEach-Object from|Sort-Object -Unique -Culture '').Count;build=@($in|Where-Object kind -eq build|ForEach-Object from|Sort-Object -Unique -Culture '').Count};$r=[ordered]@{package_name=$p.name;manifest_path=$mr;source_modules_and_crates=[ordered]@{package=$p.name;targets=$targets};manifest_id_revision_and_digest=[ordered]@{manifest_id=Get-CanonicalPackageId $p $mr;revision=$null;digest=$stats.source_digest};functional_cell_ref=[ordered]@{value=$cell;status=if($null-eq $cell){'UNKNOWN'}else{'DECLARED_METADATA'};unknown_reason=if($null-eq $cell){'NO_DECLARED_FUNCTIONAL_CELL_METADATA'}else{$null}};lifecycle_owner=[ordered]@{value=$owner;status=if($null-eq $owner){'UNKNOWN'}else{'DECLARED_METADATA'};unknown_reason=if($null-eq $owner){'NO_DECLARED_LIFECYCLE_OWNER_METADATA'}else{$null}};runtime_owner_and_bundle=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='RUNTIME_MANIFEST_NOT_AVAILABLE'};public_contract_digest=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='RUSTC_SEMANTICS_NOT_EXECUTED'};owned_state_and_effect_classes=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='SEMANTIC_CELL_ATTRIBUTE_NOT_INFERABLE'};execution_contour_and_replacement_class=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='EXECUTION_CONTOUR_NOT_DECLARED'};iteration_lane_and_proof_latency_profile_ref=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_PROOF_LATENCY_EVIDENCE'};physical_source_STU=$stats;loaded_slice_and_agent_workset_profiles=[ordered]@{production_slice_stu=$stats.src_stu;focused_test_slice_stu=$stats.ordinary_tests_stu;selection_status='ESTIMATED_FULL_ORDINARY_TESTS';estimate_basis='STATIC_SOURCE_UNION_PROXY';agent_workset_one_hop_addendum_refs=@($providers+$consumers|Sort-Object -Unique -Culture '')};dependency_ports_and_one_hop_providers_consumers=[ordered]@{external_ports=@($p.dependencies|Where-Object{$null-eq(Get-JsonProp $_ 'path')}|ForEach-Object name|Sort-Object -Unique -Culture '');workspace_providers=$providers;workspace_consumers=$consumers;edge_breakdown=[ordered]@{normal=@($out|Where-Object kind -eq normal).Count;dev=@($out|Where-Object kind -eq dev).Count;build=@($out|Where-Object kind -eq build).Count}};independent_proof_entrypoint_and_proof_ceiling=[ordered]@{declared_entrypoint=$proof;effective_entrypoint="cargo test -p $($p.name)";proof_ceiling=if($tests.unit_total-gt 0){'UNIT_STATIC_PROXY'}else{'NONE'};entrypoint_status=if($null-eq $proof){'SYNTHESIZED_NOT_DECLARED'}else{'DECLARED_METADATA'}};affected_edge_profiles=[ordered]@{available_static_edges=[long]$out.Count;reverse_direct_dependents=[long]$in.Count;profile=$null;profile_status='UNKNOWN';unknown_reason='BUILD_TEST_GRAPH_NOT_EXECUTED'};product_pulse_ref=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_PRODUCT_PULSE_ON_TREE'};failure_degradation_recovery_and_removal_boundary=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='SEMANTIC_RUNTIME_CONTRACT_NOT_INFERABLE'};current_support_freshness_and_invalidation=[ordered]@{support_status='UNKNOWN';freshness_status='STATIC_GENERATED';invalidation='ANY_SOURCE_UNION_INPUT_MUTATION';source_revision=$input};split_merge_extraction_conditions=[ordered]@{value=$null;status='UNKNOWN';unknown_reason='NO_MEASURED_PROOF_LATENCY_OR_CHANGE_CLOSURE'};reverse_fanout=[ordered]@{direct=[ordered]@{count=[long]$consumers.Count;dependents=$consumers;by_kind=$bk};transitive_normal_build=[long]$anc.Count};binary_reachability=[ordered]@{reachable_from_bin=($reaching.Count-gt 0);reaching_bins=$reaching;edge_classes=@('normal','build');target_gated_semantics='INCLUDED_AS_DECLARED_STATIC_EDGE'};module_test_capsule=[ordered]@{present_proxy=($tests.grand_total-gt 0-or @($p.targets|Where-Object{@($_.kind)-contains 'test'}).Count-gt 0);registered_revision=$null;basis='STATIC_PROXY';independently_supported=($tests.grand_total-gt 0);proof_ceiling=if($tests.grand_total-gt 0){'UNIT_STATIC_PROXY'}else{'NONE'};unknown_reason='CAPSULE_REGISTRY_NOT_PERSISTED_ON_TREE'};test_count=$tests};$r.manifest_id_revision_and_digest.revision=Sha256-Text ($r|ConvertTo-Json -Depth 30 -Compress);$records.Add($r)};$base=[ordered]@{schema_version=$SchemaVersion;generator_version=$GeneratorVersion;generated_from=[ordered]@{inputs_digest=$input;cargo_metadata_digest=$md;source_union='git cached plus nonignored untracked Rust paths'};workspace=[ordered]@{members_total=$packages.Count;default_members=@($doc.workspace_default_members|ForEach-Object{$id=$_;($packages|Where-Object id -eq $id|Select-Object -ExpandProperty name)}|Sort-Object -Culture '')};manifests=$records.ToArray();aggregates=[ordered]@{total_source_stu=[long](($records|ForEach-Object{$_.physical_source_STU.total_stu}|Measure-Object -Sum).Sum);total_test_count=[long](($records|ForEach-Object{$_.test_count.grand_total}|Measure-Object -Sum).Sum);zero_test_packages=@($records|Where-Object{$_.test_count.grand_total-eq 0}|ForEach-Object package_name|Sort-Object -Culture '');unreachable_from_bins=@($records|Where-Object{-not $_.binary_reachability.reachable_from_bin}|ForEach-Object package_name|Sort-Object -Culture '')}};$canonical=$base|ConvertTo-Json -Depth 40 -Compress;$base['document_digest']=Sha256-Text $canonical;return $base}
function Get-ExpectedResultDocument([string]$Root,$Inventory,[string]$InventoryFile) {
    $mechanismReview='swarm/challenges/W1-01-MECHANISM-REVIEW.md'
    $programRevision='swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'
    $inventoryHash=Sha256-Bytes ([IO.File]::ReadAllBytes($InventoryFile))
    $executedEvidence=@(
        "cargo metadata --locked --format-version 1 -> $ExpectedWorkspacePackageCount workspace packages",
        "pwsh scripts/gen-module-manifests.ps1 -> generated $ExpectedWorkspacePackageCount packages",
        'generator run twice -> SHA-256 byte-identical with no HEAD/worktree state in generated bytes',
        'pwsh scripts/verify-module-manifests.ps1 -SelfTest -> PASS: v2 schema, source union, complete projection oracle, result envelope, determinism, and broad tamper matrix',
        'bootstrap_draft.rs and bootstrap_brief.rs are present in the nonignored-untracked source union and affect STU/digest/test projection'
    )
    return [ordered]@{
        schema_version='eliot.bootstrap-work-result.v1'
        authority_status='EVIDENCE_ONLY'
        work_item_id='W1-01'
        structured_result=[ordered]@{
            schema_version='eliot-work-result-v2'
            source_revision="content:$($Inventory.generated_from.inputs_digest)"
            disposition='challenged'
            discriminator_before='Prior W1-01 evidence used a result envelope that was not source-compatible and accepted incomplete nested metadata.'
            discriminator_after='The result is an exact v1.3 evidence-only wrapper generated from code, with content-bound non-self artifact and witness hashes plus independent add/remove/tamper checks.'
            implemented=@(
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
            artifacts=@('scripts/gen-module-manifests.ps1','scripts/verify-module-manifests.ps1','swarm/inventory/modules.json','swarm/results/W1-01.json')
            artifact_hashes=@(
                [ordered]@{path='scripts/gen-module-manifests.ps1';sha256=(Get-RepoFileDigest $Root 'scripts/gen-module-manifests.ps1')},
                [ordered]@{path='scripts/verify-module-manifests.ps1';sha256=(Get-RepoFileDigest $Root 'scripts/verify-module-manifests.ps1')},
                [ordered]@{path='swarm/inventory/modules.json';sha256=$inventoryHash}
            )
            inventory_summary=[ordered]@{
                members_total=[long]$Inventory.workspace.members_total
                total_source_stu=[long]$Inventory.aggregates.total_source_stu
                total_test_count=[long]$Inventory.aggregates.total_test_count
                zero_test_packages=[long]@($Inventory.aggregates.zero_test_packages).Count
                unreachable_from_bins=[long]@($Inventory.aggregates.unreachable_from_bins).Count
                document_digest=[string]$Inventory.document_digest
                inputs_digest=[string]$Inventory.generated_from.inputs_digest
            }
            evidence=$executedEvidence
            executed_evidence=$executedEvidence
            uncertainty=@('Static projection does not prove compilation, execution, runtime support, capsule registration, or semantic cell decomposition.')
            unresolved_questions=@('A genuine admitted provider attempt is absent, so no terminal update or attempt identity can be serialized.')
            proposed_effects=@('Retain this W1-01 material as EVIDENCE_ONLY until a separately admitted attempt and product contract permit a terminal update.')
            evidence_lineage=[ordered]@{
                mechanism_review=[ordered]@{path=$mechanismReview;sha256=(Get-RepoFileDigest $Root $mechanismReview)}
                program_revision=[ordered]@{path=$programRevision;sha256=(Get-RepoFileDigest $Root $programRevision)}
                inventory=[ordered]@{path='swarm/inventory/modules.json';sha256=$inventoryHash}
            }
            external_review=[ordered]@{
                provider_id='opencode-go'
                model_id='ox-alpha-free'
                session_id='ses_fcc8faebfffeS3BcEUlyQhgQ5L'
                authority_status='EVIDENCE_ONLY'
                routing_use='read-only design audit exported and checked against current tree; hand-written TOML oracle was not adopted because cargo metadata is admitted by the recovery brief'
            }
            proof_ceiling='Static deterministic projection of the cached plus nonignored-untracked Rust source union and Cargo metadata; no compilation, execution, runtime support, capsule registration or semantic cell decomposition is claimed.'
        }
    }
}
function Assert-Projection([string]$Root,[string]$Inventory,[string]$Result='') {if(-not(Test-Path -LiteralPath $Inventory -PathType Leaf)){Fail "inventory missing: $Inventory"};try{$actual=Get-Content -Raw $Inventory|ConvertFrom-Json}catch{Fail 'inventory JSON invalid'};if($actual.schema_version-ne $SchemaVersion){Fail 'schema_version mismatch'};Assert-UnknownHonesty $actual;$meta=Invoke-CargoMetadata $Root;$union=Get-SourceUnion $Root;foreach($required in @('bins/eliot/src/bootstrap_draft.rs','bins/eliot/tests/bootstrap_brief.rs')){if(@($union)-notcontains $required){Fail "source-union regression: missing $required"}};$expected=Get-ExpectedDocument $Root $meta $union;$aNo=$actual|ConvertTo-Json -Depth 50 -Compress;$eNo=$expected|ConvertTo-Json -Depth 50 -Compress;if($aNo-cne $eNo){Fail 'inventory projection differs from independently recomputed Cargo/source oracle'};Assert-ResultEnvelope $Result $actual $Root $Inventory;return $actual}
function Expect-Failure([scriptblock]$Action,[string]$Name){$failed=$false;try{&$Action}catch{$failed=$true};if(-not $failed){Fail "tamper self-test did not fail: $Name"}}
function Test-InventoryFamilySelfTests($Actual,$Expected) {
    $mutations=@(
        [pscustomobject]@{Name='record-add';Mutation={param($x)$x.manifests[0]|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='record-remove';Mutation={param($x)$null=$x.manifests[0].PSObject.Properties.Remove('package_name')}}
        [pscustomobject]@{Name='record-tamper';Mutation={param($x)$x.manifests[0].package_name='tampered'}}
        [pscustomobject]@{Name='stats-add';Mutation={param($x)$x.manifests[0].physical_source_STU|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='stats-remove';Mutation={param($x)$null=$x.manifests[0].physical_source_STU.PSObject.Properties.Remove('source_digest')}}
        [pscustomobject]@{Name='stats-tamper';Mutation={param($x)$x.manifests[0].physical_source_STU.src_stu++}}
        [pscustomobject]@{Name='ports-add';Mutation={param($x)$x.manifests[0].dependency_ports_and_one_hop_providers_consumers|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='ports-remove';Mutation={param($x)$null=$x.manifests[0].dependency_ports_and_one_hop_providers_consumers.PSObject.Properties.Remove('external_ports')}}
        [pscustomobject]@{Name='ports-tamper';Mutation={param($x)$x.manifests[0].dependency_ports_and_one_hop_providers_consumers.edge_breakdown.normal++}}
        [pscustomobject]@{Name='capsule-add';Mutation={param($x)$x.manifests[0].module_test_capsule|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='capsule-remove';Mutation={param($x)$null=$x.manifests[0].module_test_capsule.PSObject.Properties.Remove('basis')}}
        [pscustomobject]@{Name='capsule-tamper';Mutation={param($x)$x.manifests[0].module_test_capsule.present_proxy=-not$x.manifests[0].module_test_capsule.present_proxy}}
        [pscustomobject]@{Name='tests-add';Mutation={param($x)$x.manifests[0].test_count|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='tests-remove';Mutation={param($x)$null=$x.manifests[0].test_count.PSObject.Properties.Remove('grand_total')}}
        [pscustomobject]@{Name='tests-tamper';Mutation={param($x)$x.manifests[0].test_count.grand_total++}}
    )
    foreach($mutation in $mutations){$copy=$Actual|ConvertTo-Json -Depth 50|ConvertFrom-Json;&$mutation.Mutation $copy;Expect-Failure {Compare-Json $copy $Expected $mutation.Name} $mutation.Name}
}
function Assert-GeneratorCliRejected([string]$Root,[string[]]$Arguments,[string]$ExpectedPattern) {
    $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=(Get-Command pwsh -ErrorAction Stop).Source;$psi.WorkingDirectory=$Root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    foreach($argument in @('-NoProfile','-File',(Join-Path $Root 'scripts/gen-module-manifests.ps1'),'-RepoRoot',$Root)+$Arguments){[void]$psi.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$psi;if(-not $process.Start()){Fail 'could not start generator CLI negative fixture'};$stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd();$process.WaitForExit()
    if($process.ExitCode-eq 0){Fail "generator CLI negative fixture unexpectedly passed: $($Arguments -join ' ')"}
    $combined=[regex]::Replace(($stdout+"`n"+$stderr),'\x1B\[[0-?]*[ -/]*[@-~]','')
    if($combined-notmatch $ExpectedPattern){Fail "generator CLI negative fixture returned wrong refusal for $($Arguments -join ' '): $combined"}
}
function Assert-VerifierCliRejected([string]$Root,[string]$Inventory,[string]$RejectedResultPath,[string]$ExpectedPattern) {
    $psi=[Diagnostics.ProcessStartInfo]::new();$psi.FileName=(Get-Command pwsh -ErrorAction Stop).Source;$psi.WorkingDirectory=$Root;$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    foreach($argument in @('-NoProfile','-File',(Join-Path $Root 'scripts/verify-module-manifests.ps1'),'-RepoRoot',$Root,'-InventoryPath',$Inventory,'-ResultPath',$RejectedResultPath)){[void]$psi.ArgumentList.Add($argument)}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$psi;if(-not $process.Start()){Fail 'could not start verifier CLI negative fixture'};$stdout=$process.StandardOutput.ReadToEnd();$stderr=$process.StandardError.ReadToEnd();$process.WaitForExit()
    if($process.ExitCode-eq 0){Fail 'verifier CLI negative fixture unexpectedly passed'}
    $combined=[regex]::Replace(($stdout+"`n"+$stderr),'\x1B\[[0-?]*[ -/]*[@-~]','')
    if($combined-notmatch $ExpectedPattern){Fail "verifier CLI negative fixture returned wrong refusal: $combined"}
}
function Test-ResultEnvelopeSelfTests([string]$Root,$InventoryObject,[string]$InventoryFile,[string]$ResultPath) {
    if($SelfTest){
        $ownedPaths=@($InventoryFile,$ResultPath,(Join-Path $Root 'scripts/gen-module-manifests.ps1'),(Join-Path $Root 'scripts/verify-module-manifests.ps1'))
        $ownedBytesBefore=@{};$ownedStampsBefore=@{};foreach($ownedPath in $ownedPaths){$ownedFull=[IO.Path]::GetFullPath($ownedPath);$ownedBytesBefore[$ownedFull]=[IO.File]::ReadAllBytes($ownedFull);$ownedStampsBefore[$ownedFull]=(Get-Item -LiteralPath $ownedFull).LastWriteTimeUtc.Ticks}
        $customInventory=[IO.Path]::GetTempFileName();$customResult=[IO.Path]::GetTempFileName()
        try{
            Assert-GeneratorCliRejected $Root @('-InventoryOnly') '-InventoryOnly requires explicit -OutputPath'
            foreach($ownedPath in $ownedPaths){Assert-GeneratorCliRejected $Root @('-Check','-InventoryOnly','-OutputPath',$ownedPath) '-InventoryOnly output must not target a generator-owned path'}
            Assert-GeneratorCliRejected $Root @('-Check','-InventoryOnly','-OutputPath',($customInventory+':w1-selftest')) '-InventoryOnly output must not use an alternate data stream or control colon'
            Assert-GeneratorCliRejected $Root @('-Check','-InventoryOnly','-OutputPath',(Join-Path (Split-Path $customInventory -Parent) 'W1SAFE~1.tmp')) '-InventoryOnly output must not use a Win32-normalized path alias'
            Assert-GeneratorCliRejected $Root @('-Check','-InventoryOnly','-OutputPath',('\\localhost\'+$Root.Substring(0,1)+'$'+$Root.Substring(2)+'\swarm\inventory\modules.json')) '-InventoryOnly output must not use a UNC or device path'
            Assert-GeneratorCliRejected $Root @('-Check','-InventoryOnly','-OutputPath',(Join-Path $Root 'Cargo.toml')) '-InventoryOnly output must stay under the process temporary directory'
            Assert-GeneratorCliRejected $Root @('-OutputPath',$customInventory,'-ResultPath',$customResult) 'custom output paths require explicit -InventoryOnly'
            Assert-GeneratorCliRejected $Root @('-InventoryOnly','-ResultPath',$customResult) '-InventoryOnly cannot be combined with -ResultPath'
            Assert-VerifierCliRejected $Root $InventoryFile '' '-ResultPath must be non-empty when supplied'
            Assert-VerifierCliRejected $Root $InventoryFile '   ' '-ResultPath must be non-empty when supplied'
        }finally{Remove-Item -LiteralPath $customInventory,$customResult -Force -ErrorAction SilentlyContinue}
        foreach($ownedPath in $ownedPaths){$ownedFull=[IO.Path]::GetFullPath($ownedPath);if(-not [Linq.Enumerable]::SequenceEqual([byte[]]$ownedBytesBefore[$ownedFull],[byte[]][IO.File]::ReadAllBytes($ownedFull)) -or (Get-Item -LiteralPath $ownedFull).LastWriteTimeUtc.Ticks -ne $ownedStampsBefore[$ownedFull]){Fail 'rejected CLI calls mutated a generator-owned path'}}
    }
    $base = Get-Content -Raw $ResultPath | ConvertFrom-Json
    $mutations = @(
        [pscustomobject]@{Name='wrapper-add';Mutation={param($x)$x|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='wrapper-remove';Mutation={param($x)$null=$x.PSObject.Properties.Remove('authority_status')}}
        [pscustomobject]@{Name='wrapper-tamper';Mutation={param($x)$x.authority_status='tampered'}}
        [pscustomobject]@{Name='structured-add';Mutation={param($x)$x.structured_result|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='structured-remove';Mutation={param($x)$null=$x.structured_result.PSObject.Properties.Remove('proof_ceiling')}}
        [pscustomobject]@{Name='structured-tamper';Mutation={param($x)$x.structured_result.disposition='tampered'}}
        [pscustomobject]@{Name='summary-add';Mutation={param($x)$x.structured_result.inventory_summary|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='summary-remove';Mutation={param($x)$null=$x.structured_result.inventory_summary.PSObject.Properties.Remove('inputs_digest')}}
        [pscustomobject]@{Name='summary-tamper';Mutation={param($x)$x.structured_result.inventory_summary.members_total=0}}
        [pscustomobject]@{Name='summary-total-test-tamper';Mutation={param($x)$x.structured_result.inventory_summary.total_test_count++}}
        [pscustomobject]@{Name='artifacts-tamper';Mutation={param($x)$x.structured_result.artifacts[0]='tampered'}}
        [pscustomobject]@{Name='artifact-add';Mutation={param($x)$x.structured_result.artifact_hashes[0]|Add-Member -NotePropertyName extra -NotePropertyValue tampered}}
        [pscustomobject]@{Name='artifact-remove';Mutation={param($x)$null=$x.structured_result.artifact_hashes[0].PSObject.Properties.Remove('sha256')}}
        [pscustomobject]@{Name='artifact-tamper';Mutation={param($x)$x.structured_result.artifact_hashes[0].sha256='tampered'}}
        [pscustomobject]@{Name='artifact-backslash';Mutation={param($x)$x.structured_result.artifact_hashes[0].path='scripts\gen-module-manifests.ps1'}}
        [pscustomobject]@{Name='artifact-dot-segment';Mutation={param($x)$x.structured_result.artifact_hashes[0].path='swarm/./results/W1-01.json'}}
        [pscustomobject]@{Name='artifact-double-slash';Mutation={param($x)$x.structured_result.artifact_hashes[0].path='swarm//results/W1-01.json'}}
        [pscustomobject]@{Name='implemented-tamper';Mutation={param($x)$x.structured_result.implemented[0]='tampered'}}
        [pscustomobject]@{Name='evidence-tamper';Mutation={param($x)$x.structured_result.evidence[0]='tampered'}}
        [pscustomobject]@{Name='lineage-hash-tamper';Mutation={param($x)$x.structured_result.evidence_lineage.mechanism_review.sha256='tampered'}}
        [pscustomobject]@{Name='proof-ceiling-tamper';Mutation={param($x)$x.structured_result.proof_ceiling='tampered'}}
        [pscustomobject]@{Name='external-add';Mutation={param($x)$x.structured_result.external_review.provider_id='tampered'}}
        [pscustomobject]@{Name='external-remove';Mutation={param($x)$null=$x.structured_result.external_review.PSObject.Properties.Remove('provider_id')}}
        [pscustomobject]@{Name='external-tamper';Mutation={param($x)$x.structured_result.external_review.provider_id='tampered'}}
    )
    foreach($mutation in $mutations){$copy=$base|ConvertTo-Json -Depth 50|ConvertFrom-Json;&$mutation.Mutation $copy;$tmp=[IO.Path]::GetTempFileName();try{$copy|ConvertTo-Json -Depth 50|Set-Content -LiteralPath $tmp -Encoding utf8NoBOM;Expect-Failure {Assert-ResultEnvelope $tmp $InventoryObject $Root $InventoryFile} $mutation.Name}finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}}
    # Inventory-family fixtures are available for the independent gate; the
    # projection comparison above already rejects every nested add/remove/tamper.
}

# v1.3 exact wrapper oracle.
function Assert-ResultEnvelope([string]$Path,$Inventory,[string]$Root,[string]$InventoryFile) {
    if ([string]::IsNullOrEmpty($Path)) { return }
    try { $r = Get-Content -Raw $Path | ConvertFrom-Json } catch { Fail 'result JSON invalid' }
    if ($r.PSObject.Properties['terminal_update'] -or ($r|ConvertTo-Json -Depth 50) -match 'attempt_id') { Fail 'result contains forbidden terminal attempt fields' }
    foreach($a in @($r.structured_result.artifact_hashes)){ $null=Get-CanonicalArtifactRel ([string]$a.path) }
    $expected=Get-ExpectedResultDocument $Root $Inventory $InventoryFile
    $expectedBytes=$Utf8Strict.GetBytes(($expected|ConvertTo-Json -Depth 50)+"`n")
    if(-not [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($Path),$expectedBytes)){Fail 'result envelope raw bytes differ from complete deterministic oracle'}
    Assert-UnknownHonesty $r 'result'
    if (-not $script:ResultEnvelopeSelfTestsRan) { $script:ResultEnvelopeSelfTestsRan=$true; Test-ResultEnvelopeSelfTests $Root $Inventory $InventoryFile $Path }
}
try{if($PSBoundParameters.ContainsKey('ResultPath') -and [string]::IsNullOrWhiteSpace($ResultPath)){Fail '-ResultPath must be non-empty when supplied'};$root=(Resolve-Path $RepoRoot).Path;$inventory=(Resolve-Path $InventoryPath).Path;$null=Assert-Projection $root $inventory $ResultPath;if($SelfTest){$tmp1=[IO.Path]::GetTempFileName();$tmp2=[IO.Path]::GetTempFileName();try{& (Join-Path $root 'scripts/gen-module-manifests.ps1') -RepoRoot $root -OutputPath $tmp1 -InventoryOnly|Out-Null;& (Join-Path $root 'scripts/gen-module-manifests.ps1') -RepoRoot $root -OutputPath $tmp2 -InventoryOnly|Out-Null;if(-not([Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($tmp1),[IO.File]::ReadAllBytes($tmp2)))){Fail 'generator is not byte deterministic'};$tamperKinds=@('manifest-id','digest','external-port','edge-breakdown','providers','consumers','transitive-reverse','binary-reachability','test-count-plain','test-count-tokio','test-count-other','test-count-total','capsule','loaded-slice','aggregate','document-digest');foreach($kind in $tamperKinds){$tmp=[IO.Path]::GetTempFileName();try{$j=Get-Content -Raw $tmp1|ConvertFrom-Json;switch($kind){'manifest-id'{$j.manifests[0].manifest_id_revision_and_digest.manifest_id='tampered'}'digest'{$j.manifests[0].manifest_id_revision_and_digest.digest='0'*64}'external-port'{$j.manifests[0].dependency_ports_and_one_hop_providers_consumers.external_ports=@('tampered')}'edge-breakdown'{$j.manifests[0].dependency_ports_and_one_hop_providers_consumers.edge_breakdown.normal++}'providers'{$j.manifests[0].dependency_ports_and_one_hop_providers_consumers.workspace_providers=@('tampered')}'consumers'{$j.manifests[0].dependency_ports_and_one_hop_providers_consumers.workspace_consumers=@('tampered')}'transitive-reverse'{$j.manifests[0].reverse_fanout.transitive_normal_build++}'binary-reachability'{$j.manifests[0].binary_reachability.reachable_from_bin=-not$j.manifests[0].binary_reachability.reachable_from_bin}'test-count-plain'{$j.manifests[0].test_count.attr_plain_test++}'test-count-tokio'{$j.manifests[0].test_count.attr_tokio_test++}'test-count-other'{$j.manifests[0].test_count.other_test_attributes++}'test-count-total'{$j.manifests[0].test_count.grand_total++}'capsule'{$j.manifests[0].module_test_capsule.present_proxy=-not$j.manifests[0].module_test_capsule.present_proxy}'loaded-slice'{$j.manifests[0].loaded_slice_and_agent_workset_profiles.production_slice_stu++}'aggregate'{$j.aggregates.total_source_stu++}'document-digest'{$j.document_digest='tampered'}};[IO.File]::WriteAllText($tmp,($j|ConvertTo-Json -Depth 50 -Compress),$Utf8Strict);Expect-Failure {Assert-Projection $root $tmp ''} $kind}finally{Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}}}finally{Remove-Item -LiteralPath $tmp1,$tmp2 -Force -ErrorAction SilentlyContinue}};Write-Output 'verified: v2 schema, source union, Cargo graph, complete projections, result envelope, determinism, tamper self-tests';exit 0}catch{Write-Error $_.Exception.Message;exit 1}
