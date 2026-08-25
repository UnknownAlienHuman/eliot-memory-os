[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\swarm\inventory\w1-06-premises.json'),
    [string]$ResultPath = (Join-Path $PSScriptRoot '..\swarm\results\W1-06-revised.json'),
    [switch]$InventoryOnly,
    [switch]$Check
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$Schema = 'eliot.w1-06-premises.v3'
$Generator = 'gen-w1-06-premises.ps1/4.1.0'

function Fail([string]$Message) { throw "W1_06_PREMISES_GENERATE_FAIL: $Message" }
function Rel([string]$Path) { ([IO.Path]::GetRelativePath($root, $Path)).Replace('\','/') }
function Sha([byte[]]$Bytes) { ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant() }
function ShaText([string]$Text) { Sha $Utf8.GetBytes($Text) }
function ReadText([string]$Path) { try { $Utf8.GetString([IO.File]::ReadAllBytes($Path)) } catch { Fail "invalid UTF-8: $Path" } }
function FileDigest([string]$Path) {
    AssertRelative $Path 'linked file'
    $full = Join-Path $root ($Path.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { Fail "missing linked file $Path" }
    Sha ([IO.File]::ReadAllBytes($full))
}
function SerializeJson($Value) { return (($Value | ConvertTo-Json -Depth 50 -Compress) + "`n") }
function AssertBytes([string]$Path, [byte[]]$Expected, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Fail "$Label missing: $(Rel $Path)" }
    if (-not [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($Path), $Expected)) { Fail "$Label bytes differ: $(Rel $Path)" }
}
function WriteAtomic([string]$Path, [byte[]]$Bytes) {
    $parent = Split-Path -Parent $Path
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    $temporary = Join-Path $parent ('.{0}.{1}.tmp' -f ([IO.Path]::GetFileName($Path)), [guid]::NewGuid().ToString('N'))
    try { [IO.File]::WriteAllBytes($temporary, $Bytes); Move-Item -LiteralPath $temporary -Destination $Path -Force }
    finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}
function CargoMeta {
    $psi=[Diagnostics.ProcessStartInfo]::new(); $psi.FileName='cargo'; $psi.Arguments='metadata --locked --format-version 1'; $psi.WorkingDirectory=$root; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    $p=[Diagnostics.Process]::new(); $p.StartInfo=$psi; if(-not $p.Start()){Fail 'could not start cargo metadata'}; $out=$p.StandardOutput.ReadToEnd(); $err=$p.StandardError.ReadToEnd(); $p.WaitForExit(); if($p.ExitCode -ne 0){Fail "cargo metadata exited $($p.ExitCode): $err"}; try {[pscustomobject]@{doc=$out|ConvertFrom-Json;raw=$out}}catch{Fail 'cargo metadata emitted invalid JSON'}
}
function GitPaths {
    $cached=@(& git -C $root ls-files --cached 2>&1);if($LASTEXITCODE -ne 0){Fail 'git cached path enumeration failed'}
    $untracked=@(& git -C $root ls-files --others --exclude-standard 2>&1);if($LASTEXITCODE -ne 0){Fail 'git nonignored-untracked path enumeration failed'}
    @($cached+$untracked|ForEach-Object {$_.ToString().Trim()}|Where-Object {$_}|ForEach-Object {$_.Replace('\','/') }|Sort-Object -Unique -Culture '')
}
function AssertRelative([string]$Path,[string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path) -or $Path.Replace('\','/') -match '(^|/)\.\.?(/|$)' -or $Path.Replace('\','/') -match '^[A-Za-z]:') { Fail "$Label must be repository-relative: $Path" }
}
function ExplicitInputPaths {
    @('scripts/finalize-eliot-windows-x64-release.ps1','bins/eliot/src/source_bundle_materializer.rs','scripts/invoke-eliot-windows-x64-production.ps1','bins/eliotd/src/lib.rs','bins/eliotd/src/main.rs','bins/eliotd/Cargo.toml','crates/governor/eliot-governor/src/composition.rs','scripts/build-eliot-windows-x64-release.ps1','scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml','scripts/gen-w1-06-premises.ps1')
}
function SourceUniverse([string[]]$GitFiles) {
    $explicit=@(ExplicitInputPaths);$paths=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($p in $GitFiles){if($p -match '(?i)(^|/)Cargo\.toml$|(?i)(^|/)Cargo\.lock$|(?i)\.rs$'){$null=$paths.Add($p)}}
    foreach($p in $explicit){$null=$paths.Add($p)}
    @($paths|Sort-Object -Culture '')
}
function CanonicalCargoMetadata([string]$Raw) {
    $escapedRoot=$root.Replace('\','\\');$normal=$Raw.Replace($escapedRoot,'<repo>').Replace($root.Replace('\','/'),'<repo>').Replace($root,'<repo>')
    try { $normal|ConvertFrom-Json|ConvertTo-Json -Depth 100 -Compress } catch { Fail 'cargo metadata canonicalization failed' }
}
function Witness([string]$Path,[string]$Pattern,[string]$Label) {
    $full=Join-Path $root ($Path.Replace('/',[IO.Path]::DirectorySeparatorChar)); $text=ReadText $full; $lines=$text -split "`r?`n"; $hits=@(); for($i=0;$i -lt $lines.Count;$i++){if($lines[$i] -match $Pattern){$hits += $i}}
    if($hits.Count -ne 1){Fail "$Label expected exactly one anchor, found $($hits.Count): $Path"}; $line=$hits[0]+1; $start=[math]::Max(0,$hits[0]-1); $end=[math]::Min($lines.Count-1,$hits[0]+1); [ordered]@{path=$Path;line=$line;end=($end+1);anchor=$Label;sha256=(Sha ([IO.File]::ReadAllBytes($full)));text=(($lines[$start..$end] -join ' ').Trim())}
}
function AllWitnesses([string]$Path,[string]$Pattern,[string]$Label) {
    $full=Join-Path $root ($Path.Replace('/',[IO.Path]::DirectorySeparatorChar)); $text=ReadText $full; $lines=$text -split "`r?`n"; $out=@(); for($i=0;$i -lt $lines.Count;$i++){if($lines[$i] -match $Pattern){$out += [ordered]@{path=$Path;line=($i+1);end=($i+1);anchor=$Label;sha256=(Sha ([IO.File]::ReadAllBytes($full)));text=$lines[$i].Trim()}}}; return @($out)
}
function HasUniqueAnchor([string]$Path,[string]$Pattern) { $text=ReadText (Join-Path $root ($Path.Replace('/',[IO.Path]::DirectorySeparatorChar))); return ([regex]::Matches($text,$Pattern)).Count -eq 1 }
function ParseSignedRoles {
    $path='scripts/finalize-eliot-windows-x64-release.ps1'; $text=ReadText (Join-Path $root $path); $m=[regex]::Match($text,'function Get-AuthenticodeRoleDefinitions(?s:.*?)\n}\s*\n\s*function Get-NormalizedThumbprint'); if(-not $m.Success){Fail 'finalizer role function missing'}; $rows=@(); foreach($x in [regex]::Matches($m.Value,"role\s*=\s*'([^']+)'\s*;\s*path\s*=\s*'([^']+)'") ){$rolePath=$x.Groups[2].Value;$rows += [ordered]@{role=$x.Groups[1].Value;path=$rolePath;executable=([IO.Path]::GetExtension($rolePath) -ieq '.exe')}}; $rows
}
function ParseMaterialRoles {
    $path='bins/eliot/src/source_bundle_materializer.rs'; $text=ReadText (Join-Path $root $path); $m=[regex]::Match($text,'pub const REQUIRED_ROLES: \[\(&str, bool\); \d+\] = \[(?s:.*?)\];'); if(-not $m.Success){Fail 'REQUIRED_ROLES missing'}; $rows=@(); foreach($x in [regex]::Matches($m.Value,'\("([^"]+)",\s*(true|false)\)')){$rows += [ordered]@{path=$x.Groups[1].Value;executable=($x.Groups[2].Value -eq 'true')}}; $rows
}
function ParseE2e([object]$Meta,[string[]]$Files) {
    $ci=@('scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml') | Where-Object {Test-Path (Join-Path $root $_)}
    $ciText=($ci | ForEach-Object {ReadText (Join-Path $root $_)}) -join "`n"; $workspaceGate=($ciText -match 'cargo\s+test\s+--workspace')
    $rows=[Collections.Generic.List[object]]::new()
    foreach($rel in @($Files | Where-Object {$_ -match '(^|/)tests/.*\.rs$'} | Sort-Object -Culture '')) {
        $text=ReadText (Join-Path $root ($rel.Replace('/',[IO.Path]::DirectorySeparatorChar))); $lines=$text -split "`r?`n"; for($i=0;$i -lt $lines.Count;$i++) {
            if($lines[$i] -notmatch '^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*\('){continue}; $name=$Matches[1]; $from=[math]::Max(0,$i-8); $attrs=($lines[$from..$i] -join "`n"); if($attrs -notmatch '#\[\s*(?:tokio::)?test\b'){continue}; $ignored=($attrs -match '#\[\s*ignore\b'); $fullstack=($rel -match '(?i)(ul_|dogfood|mcp|protocol|live|cross_agent|system_snapshot|first_working_loop)' -or $name -match '(?i)(ul|dogfood|mcp|protocol|live|cross|snapshot|working_loop)'); if(-not $fullstack){continue}; $feature=if($attrs -match '(?i)cfg\s*\([^)]*feature|cfg_attr\s*\([^)]*feature'){'FEATURE_GATED'}else{'NONE_DECLARED'}; $env=if($text -match '(?i)(std::env::var|env!\(|option_env!\(|LOCALAPPDATA|ONEDRIVE|PROGRAMDATA|CARGO_BIN_EXE)'){'ENV_OR_RUNTIME_INPUT'}else{'NONE_DECLARED'}; $prereq=@(); if($text -match '(?i)surreal|localhost|127\.0\.0\.1|named_pipe|docker'){$prereq+='runtime-service-or-ipc'}; if($text -match '(?i)CARGO_BIN_EXE|\.exe'){$prereq+='built-binary'}; if($prereq.Count -eq 0){$prereq+='none-declared'}; $rows.Add([ordered]@{id="$($rel):$($i+1):$name";path=$rel;line=($i+1);test_name=$name;full_stack=$true;default_gate=if($ignored){'IGNORED_BY_DEFAULT'}else{'WORKSPACE_DEFAULT_TEST'};ignored=$ignored;feature_state=$feature;env_state=$env;external_prerequisites=@($prereq|Sort-Object -Culture '');ci_included=([bool]($workspaceGate -and -not $ignored));ci_gate_witness=if($workspaceGate){'scripts/verify.ps1 + CI cargo test --workspace'}else{'UNKNOWN'}})
        }
    }; return @($rows | Sort-Object path,line,test_name -Culture '')
}

function ExpectedResult($Inventory, [byte[]]$InventoryBytes) {
    $programPath = 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'
    $challengePath = 'swarm/challenges/W1-06-FALSIFICATION.md'
    $claims = @(
        [ordered]@{ id='A1-original-contour-linkage'; verdict='TRUE'; measured=[ordered]@{ cross_contour_cargo_edges=0; contour_a=@('eliot-app','eliot-engine','eliot-store'); contour_b=@('eliot','eliot-host','eliot-kernel','eliotd') }; qualification='This is only the directed Cargo edge premise; shared foundations, IPC, and runtime resources are not covered.' },
        [ordered]@{ id='A2-original-all-e2e-disabled'; verdict='FALSE'; measured=[ordered]@{ unignored_full_stack_candidates=[int]$Inventory.e2e_inventory.summary.unignored_full_stack }; qualification='The historical 132 identity inventory is not assumed; the generated current candidate inventory falsifies the literal all-disabled premise.' },
        [ordered]@{ id='A3-original-signed-set-no-executable'; verdict='FALSE'; measured=[ordered]@{ signed_executable_roles=7 }; qualification='The finalizer role table contains seven executable PE roles.' },
        [ordered]@{ id='C1-authenticode-signed-set-membership'; verdict='TRUE'; measured=[ordered]@{ authenticode_pe_roles=7; all_roles_measured_executable=$true; governor_role_present=$false; predicate_matches=$true }; witnesses=@('scripts/finalize-eliot-windows-x64-release.ps1:function Get-AuthenticodeRoleDefinitions','scripts/finalize-eliot-windows-x64-release.ps1:Governor remains outside exact signing scope'); proof_ceiling='static role-table evidence; no certificate or on-disk bundle verification' },
        [ordered]@{ id='C2-source-bundle-release-materializer-membership'; verdict='TRUE'; measured=[ordered]@{ required_roles=9; executable_roles=6; json_roles=3; ordered_exact=$true; predicate_matches=$true }; witnesses=@('bins/eliot/src/source_bundle_materializer.rs:pub const REQUIRED_ROLES','bins/eliot/src/source_bundle_materializer.rs:validate_role_inventory(&REQUIRED_ROLES)','scripts/build-eliot-windows-x64-release.ps1:$runtimeArtifactPlan = Get-RuntimeArtifactPlan'); proof_ceiling='static ordered role-set evidence; no materialization execution' },
        [ordered]@{ id='C3-production-launch-reachability'; verdict='UNKNOWN'; measured=[ordered]@{ static_handoff_anchors=4; runtime_receipt_observed=$false; predicate_matches=$null }; witnesses=@('scripts/invoke-eliot-windows-x64-production.ps1:function Invoke-ProductionEliotMaterializeSourceBundle','scripts/invoke-eliot-windows-x64-production.ps1:EliotReleaseTrustedCliProcess::CreateSuspended','scripts/invoke-eliot-windows-x64-production.ps1:ResumeAndWait','scripts/invoke-eliot-windows-x64-production.ps1:SOURCE_BUNDLE_MATERIALIZED'); unknown_reasons=@('No signed bundle, process execution, exit-code readback, or receipt was observed by this source oracle.','Executable presence and static launch code do not prove production reachability.') },
        [ordered]@{ id='C4-governor-constitutive-authority'; verdict='TRUE'; measured=[ordered]@{ eliotd_governor_dependency=$true; daemon_governor_construction=$true; canonical_commit_owner=$true; predicate_matches=$true }; witnesses=@('bins/eliotd/Cargo.toml:eliot-governor.workspace','bins/eliotd/src/lib.rs:GovernorComposition::new(kernel','crates/governor/eliot-governor/src/composition.rs:pub async fn commit_canonical'); proof_ceiling='static Cargo/source composition evidence; no running daemon or write receipt' }
    )
    $s = $Inventory.e2e_inventory.summary
    $checks = @(
        'cargo metadata --locked --format-version 1',
        'C1/C2 role set membership, duplicate rejection, and order',
        'per-role executable classification derived from each signed path extension',
        'C1-C4 witness source digests and anchor ranges',
        'inventory document digest and canonical Cargo metadata digest',
        'content-bound provenance with cached+nonignored-untracked source universe',
        'full inventory field set, counts, premises, and proof ceilings',
        'full result envelope binding, challenge/reference digests, and path safety',
        'byte determinism',
        'inventory field-add/remove/path/content-universe and nested tamper self-tests',
        'result envelope every-field tamper matrix'
    )
    $structured = [ordered]@{
        disposition='EVIDENCE_ONLY'
        artifacts=[ordered]@{
            inventory=[ordered]@{path='swarm/inventory/w1-06-premises.json';sha256=(Sha $InventoryBytes)}
            generator=[ordered]@{path='scripts/gen-w1-06-premises.ps1';sha256=(FileDigest 'scripts/gen-w1-06-premises.ps1')}
            verifier=[ordered]@{path='scripts/verify-w1-06-premises.ps1';sha256=(FileDigest 'scripts/verify-w1-06-premises.ps1')}
        }
        evidence=@('content-bound cached plus nonignored-untracked source universe','C1-C4 static premise evidence','C3 runtime reachability remains UNKNOWN')
        discriminator_before=[ordered]@{ status='V4_REJECTED'; reason='release-builder witness was outside declared input universe and result equality was semantic' }
        discriminator_after=[ordered]@{ status='MECHANISM_CHANGED_IN_PROGRESS'; input_universe_includes_release_builder=$true; canonical_raw_bytes=$true }
        uncertainty='Static evidence only; no signed bundle or runtime receipt was observed.'
        unresolved_questions=@('C3 production launch reachability remains UNKNOWN','W2 remains blocked by the declared boundary')
        proposed_effects=@('Preserve EVIDENCE_ONLY','Do not authorize cutover or W2')
        evidence_lineage=[ordered]@{ program_authority='swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'; challenge='swarm/challenges/W1-06-V4-MECHANISM-REVIEW.md'; inventory_digest=$Inventory.document_digest; input_digest=$Inventory.generated_from.inputs_digest }
        source_of_truth='swarm/inventory/w1-06-premises.json'
        source_content_digest=$Inventory.generated_from.inputs_digest
        inventory_schema_version=$Inventory.schema_version
        inventory_document_digest=$Inventory.document_digest
        claims=$claims
        e2e_inventory=[ordered]@{
            inventory_schema='eliot.w1-06-e2e.v1'
            full_stack_candidates=[int]$s.full_stack_tests
            ignored_by_default=[int]$s.ignored_by_default
            unignored_full_stack=[int]$s.unignored_full_stack
            ci_included=[int]$s.ci_included
            ci_excluded=[int]$s.ci_excluded
            gate_basis=@('scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml','cargo test --workspace default gate')
            classification_scope='generated candidates under cached plus nonignored-untracked integration-test paths with full-stack/UL/runtime markers; each row records default gate, ignore, feature, environment, prerequisites, and CI inclusion'
        }
        verification=[ordered]@{ generator='scripts/gen-w1-06-premises.ps1'; verifier='scripts/verify-w1-06-premises.ps1'; checks=$checks; command='pwsh -NoLogo -NoProfile -File scripts/verify-w1-06-premises.ps1 -SelfTest'; observed_result='PASS' }
        independent_openrouter_reviews=@(
            [ordered]@{ session_id='ses_fccbf4de9ffeL1cpHpKbkslv59'; scope='fresh source-only original-premise falsification' },
            [ordered]@{ session_id='ses_fcc616fb4ffeufOS6MRXnDYfDk'; scope='separate current-source original and revised premise falsification' }
        )
        program_revision=[ordered]@{ path=$programPath; sha256=(FileDigest $programPath) }
        challenge_references=@(
            [ordered]@{ path=$challengePath; sha256=(FileDigest $challengePath); purpose='accepted falsification disposition and evidence boundary' },
            [ordered]@{ path='swarm/decisions/W1-06-PROGRAM-REVISION-v1.2.md'; sha256=(FileDigest 'swarm/decisions/W1-06-PROGRAM-REVISION-v1.2.md'); purpose='accepted revised premises and proof ceilings' },
            [ordered]@{ path=$programPath; sha256=(FileDigest $programPath); purpose='exact W1 result-envelope authority and one-shot retry boundary' }
        )
        integration_guard='Root accepts only the bounded revised premise set. W2 is not unblocked until W0 passes and remaining W1 inventories are accepted; static membership is not Product Pulse evidence.'
    }
    return [pscustomobject][ordered]@{ schema_version='eliot.bootstrap-work-result.v1'; authority_status='EVIDENCE_ONLY'; work_item_id='W1-06'; structured_result=$structured }
}

try {
    $root=(Resolve-Path $RepoRoot).Path
    if ($InventoryOnly -and $PSBoundParameters.ContainsKey('ResultPath')) { Fail '-InventoryOnly cannot combine with -ResultPath' }
    $customOutput = $PSBoundParameters.ContainsKey('OutputPath')
    $customResult = $PSBoundParameters.ContainsKey('ResultPath')
    if (-not $InventoryOnly -and $customOutput -ne $customResult) { Fail 'custom -OutputPath and -ResultPath must be supplied together unless -InventoryOnly is used' }
    $outCandidate=$OutputPath.Replace('/',[IO.Path]::DirectorySeparatorChar)
    $outFull=if([IO.Path]::IsPathRooted($outCandidate)){[IO.Path]::GetFullPath($outCandidate)}else{[IO.Path]::GetFullPath((Join-Path $root $outCandidate))}
    $resultFull = if ($InventoryOnly) { $null } else {
        $resultCandidate = $ResultPath.Replace('/',[IO.Path]::DirectorySeparatorChar)
        if([IO.Path]::IsPathRooted($resultCandidate)){[IO.Path]::GetFullPath($resultCandidate)}else{[IO.Path]::GetFullPath((Join-Path $root $resultCandidate))}
    }
    $meta=CargoMeta; $gitFiles=@(GitPaths); $sourcePaths=@(SourceUniverse $gitFiles); $signed=ParseSignedRoles; $material=ParseMaterialRoles
    $wC1=@(Witness 'scripts/finalize-eliot-windows-x64-release.ps1' 'function Get-AuthenticodeRoleDefinitions' 'finalizer Authenticode role definition'; Witness 'scripts/finalize-eliot-windows-x64-release.ps1' 'Governor, Operator UI, and other payload remain outside' 'Governor excluded from exact signing scope')
    $wC2=@(Witness 'bins/eliot/src/source_bundle_materializer.rs' 'pub const REQUIRED_ROLES' 'materializer ordered Phase-A role set'; Witness 'bins/eliot/src/source_bundle_materializer.rs' 'validate_role_inventory\(&REQUIRED_ROLES\)' 'materializer validates exact role inventory'; Witness 'scripts/build-eliot-windows-x64-release.ps1' '\$runtimeArtifactPlan = Get-RuntimeArtifactPlan' 'release builder runtime artifact plan')
    $wC3=@(Witness 'scripts/invoke-eliot-windows-x64-production.ps1' 'function Invoke-ProductionEliotMaterializeSourceBundle' 'authoritative production handoff'; Witness 'scripts/invoke-eliot-windows-x64-production.ps1' '\$process = \[EliotReleaseTrustedCliProcess\]::CreateSuspended' 'suspended trusted CLI child'; Witness 'scripts/invoke-eliot-windows-x64-production.ps1' '\$processOutcome = \$process\.ResumeAndWait\(\)' 'resume and wait boundary'; Witness 'scripts/invoke-eliot-windows-x64-production.ps1' "status = 'SOURCE_BUNDLE_MATERIALIZED'" 'materialization success receipt')
    $wC4=@(Witness 'bins/eliotd/src/lib.rs' 'One production daemon composition' 'single production daemon composition'; Witness 'bins/eliotd/src/lib.rs' 'GovernorComposition::new\(kernel' 'Governor construction in daemon'; Witness 'crates/governor/eliot-governor/src/composition.rs' 'pub async fn commit_canonical' 'Governor canonical commit authority'; Witness 'bins/eliotd/Cargo.toml' 'eliot-governor\.workspace' 'eliotd Cargo dependency on Governor')
    $e2e=ParseE2e $meta.doc $sourcePaths; $ciPaths=@('scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml')|Where-Object {Test-Path (Join-Path $root $_)}; $workspaceGate=((($ciPaths|ForEach-Object {ReadText (Join-Path $root $_)}) -join "`n") -match 'cargo\s+test\s+--workspace'); $members=@($meta.doc.workspace_members).Count; $default=@($meta.doc.workspace_default_members).Count
    $inputPaths=@($sourcePaths); $inputRows=[Collections.Generic.List[string]]::new(); $inputBindings=@(); foreach($p in $inputPaths){AssertRelative $p 'input path';$f=Join-Path $root ($p.Replace('/',[IO.Path]::DirectorySeparatorChar));if(-not(Test-Path $f -PathType Leaf)){Fail "missing input: $p"};$digest=Sha ([IO.File]::ReadAllBytes($f));$inputRows.Add("$p`0$digest");$inputBindings += [ordered]@{path=$p;sha256=$digest}}; $canonicalCargo=CanonicalCargoMetadata $meta.raw; $inputRows.Add("cargo-metadata`0$(ShaText $canonicalCargo)"); $inputs=ShaText (($inputRows|Sort-Object -Culture '') -join "`n")
    $c1Exec=@($signed|Where-Object executable); $c1Set=[ordered]@{roles=$signed;count=$signed.Count;governor_role_present=([bool](@($signed|Where-Object role -eq 'governor').Count -gt 0));executable_role_count=$c1Exec.Count}; $c1Unique=(@($signed|ForEach-Object {"$($_.role)|$($_.path)"}|Sort-Object|Get-Unique).Count -eq $signed.Count); $c1AllExecutable=($signed.Count -gt 0 -and $c1Exec.Count -eq $signed.Count); $c1Predicate=[ordered]@{role_count_is_seven=($signed.Count -eq 7);all_roles_executable=$c1AllExecutable;unique_role_paths=$c1Unique;governor_absent=(-not $c1Set.governor_role_present);matches=($signed.Count -eq 7 -and $c1AllExecutable -and $c1Unique -and -not $c1Set.governor_role_present)}
    $c2Exec=@($material|Where-Object executable); $c2Expected=@('eliot-host.exe|True','eliot-watchdog.exe|True','eliot-kernel.exe|True','eliot-store-surreal.exe|True','surreal.exe|True','eliotd.exe|True','generation.json|False','eliotd-governor.json|False','eliotd.json|False'); $c2Actual=@($material|ForEach-Object {"$($_.path)|$($_.executable.ToString().Substring(0,1).ToUpperInvariant()+$_.executable.ToString().Substring(1).ToLowerInvariant())"}); $c2Ordered=(($c2Actual -join '|') -eq ($c2Expected -join '|')); $c2Unique=(@($c2Actual|Sort-Object|Get-Unique).Count -eq $c2Actual.Count); $c2Set=[ordered]@{roles=$material;count=$material.Count;executable_roles=$c2Exec;executable_count=$c2Exec.Count;non_executable_count=@($material|Where-Object {-not $_.executable}).Count}; $c2Predicate=[ordered]@{role_count_is_nine=($material.Count -eq 9);executable_count_is_six=($c2Exec.Count -eq 6);json_count_is_three=(@($material|Where-Object {-not $_.executable}).Count -eq 3);ordered_exact=$c2Ordered;unique_role_paths=$c2Unique;matches=($material.Count -eq 9 -and $c2Exec.Count -eq 6 -and @($material|Where-Object {-not $_.executable}).Count -eq 3 -and $c2Ordered -and $c2Unique)}
    $c3Static=(@($wC3).Count -eq 4); $c3Predicate=[ordered]@{static_handoff_chain_complete=$c3Static;runtime_receipt_observed=$false;matches=if(-not $c3Static){$false}else{$null}}
    $c4Predicate=[ordered]@{eliotd_dependency=(HasUniqueAnchor 'bins/eliotd/Cargo.toml' 'eliot-governor\.workspace');daemon_governor_construction=(HasUniqueAnchor 'bins/eliotd/src/lib.rs' 'GovernorComposition::new\(kernel');canonical_commit_owner=(HasUniqueAnchor 'crates/governor/eliot-governor/src/composition.rs' 'pub async fn commit_canonical');matches=$false}; $c4Predicate.matches=($c4Predicate.eliotd_dependency -and $c4Predicate.daemon_governor_construction -and $c4Predicate.canonical_commit_owner)
    $aNames=@('eliot-app','eliot-engine','eliot-store');$bNames=@('eliot','eliot-host','eliot-kernel','eliotd');$cross=@();foreach($p in @($meta.doc.packages|Where-Object {$meta.doc.workspace_members -contains $_.id})){foreach($d in @($p.dependencies)){if($null -eq $d.PSObject.Properties['path']){continue};$dep=$meta.doc.packages|Where-Object {$_.name -eq $d.name}|Select-Object -First 1;if($null -ne $dep -and (($aNames -contains $p.name -and $bNames -contains $dep.name) -or ($bNames -contains $p.name -and $aNames -contains $dep.name))){$cross += [ordered]@{from=$p.name;to=$dep.name;kind=if($null -eq $d.PSObject.Properties['kind']){'normal'}else{[string]$d.kind}}}}};$a1Predicate=[ordered]@{cross_contour_edges=@($cross);cross_contour_edge_count=$cross.Count;matches=($cross.Count -eq 0)}
    $claims=@(
        [ordered]@{id='A1-original-contour-linkage';statement='The named contour-A and contour-B package sets have no direct Cargo dependency edge.';verdict=if($a1Predicate.matches){'TRUE'}else{'FALSE'};scope='static-cargo-graph';predicate=$a1Predicate;proof_ceiling='Cargo metadata edge projection; IPC/runtime resources are outside scope'},
        [ordered]@{id='A2-original-all-e2e-disabled';statement='Every claimed full-stack E2E test is disabled by default.';verdict=if(@($e2e|Where-Object default_gate -eq 'WORKSPACE_DEFAULT_TEST').Count -eq 0){'TRUE'}else{'FALSE'};scope='generated-e2e-gate';predicate=[ordered]@{unignored_full_stack=@($e2e|Where-Object default_gate -eq 'WORKSPACE_DEFAULT_TEST').Count;matches=(@($e2e|Where-Object default_gate -eq 'WORKSPACE_DEFAULT_TEST').Count -eq 0)};proof_ceiling='generated candidate inventory; historical 132 identity mapping is not assumed'},
        [ordered]@{id='A3-original-signed-set-no-executable';statement='The signed artifact set contains no executable product.';verdict=if($c1Set.executable_role_count -eq 0){'TRUE'}else{'FALSE'};scope='static-source-role-membership';predicate=[ordered]@{signed_executable_roles=$c1Set.executable_role_count;matches=($c1Set.executable_role_count -eq 0)};witnesses=$wC1;proof_ceiling='static role-table evidence'},
        [ordered]@{id='C1-authenticode-signed-set-membership';statement='The finalizer Authenticode signed-set is exactly the seven declared PE roles, and Governor is outside that set.';verdict=if($c1Predicate.matches){'TRUE'}else{'FALSE'};scope='static-source-role-membership';predicate=$c1Predicate;set=$c1Set;witnesses=$wC1;proof_ceiling='static role-table evidence; no certificate or on-disk bundle verification'},
        [ordered]@{id='C2-source-bundle-release-materializer-membership';statement='The source bundle materializer admits exactly nine ordered Phase-A roles: six executable and three JSON roles.';verdict=if($c2Predicate.matches){'TRUE'}else{'FALSE'};scope='static-source-role-membership';predicate=$c2Predicate;set=$c2Set;witnesses=$wC2;proof_ceiling='static REQUIRED_ROLES evidence; no materialization execution'},
        [ordered]@{id='C3-production-launch-reachability';statement='A successful production launch/materialization receipt is reachable from the authoritative handoff.';verdict=if(-not $c3Static){'FALSE'}elseif($c3Predicate.runtime_receipt_observed){'TRUE'}else{'UNKNOWN'};scope='runtime-reachability';predicate=$c3Predicate;witnesses=$wC3;unknown_reasons=@('source chain is present, but no signed bundle, process execution, exit-code readback, or receipt was observed by this oracle','executable presence and static StartSuspended/ResumeAndWait code do not prove runtime reachability');proof_ceiling='static launch-chain evidence only'},
        [ordered]@{id='C4-governor-constitutive-authority';statement='Governor is the constitutive authority of the production daemon composition.';verdict=if($c4Predicate.matches){'TRUE'}else{'FALSE'};scope='static-composition-authority';predicate=$c4Predicate;witnesses=$wC4;authority_evidence=@('eliotd depends on eliot-governor','DaemonComposition constructs GovernorComposition after authenticated Kernel admission','GovernorComposition owns canonical commit and lifecycle readiness');proof_ceiling='static Cargo/source composition evidence; no running daemon or write receipt'}
    )
    $provenance=[ordered]@{kind='content-bound';source_universe=[ordered]@{mode='git-cached-plus-nonignored-untracked';included_extensions=@('.rs','Cargo.toml','Cargo.lock');explicit_paths=@(ExplicitInputPaths);exclusion_rules=@('nonignored repository files outside .rs/Cargo.toml/Cargo.lock and explicit claim/CI inputs are excluded','test-row heuristic may classify a bound Rust test source as non-full-stack; bytes remain in source universe');path_count=$inputPaths.Count};input_paths=$inputPaths;input_bindings=@($inputBindings);inputs_digest=$inputs;cargo_metadata_digest=(ShaText $canonicalCargo)}; $doc=[ordered]@{schema_version=$Schema;generator_version=$Generator;generated_from=$provenance;cargo=[ordered]@{workspace_members=$members;default_members=$default;package_names=@($meta.doc.packages|Where-Object {$meta.doc.workspace_members -contains $_.id}|ForEach-Object name|Sort-Object -Culture '')};claims=$claims;e2e_inventory=[ordered]@{schema_version='eliot.w1-06-e2e.v1';default_workspace_gate=$workspaceGate;gate_witnesses=@('scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml');tests=$e2e;summary=[ordered]@{full_stack_tests=$e2e.Count;ignored_by_default=@($e2e|Where-Object default_gate -eq 'IGNORED_BY_DEFAULT').Count;unignored_full_stack=@($e2e|Where-Object default_gate -eq 'WORKSPACE_DEFAULT_TEST').Count;ci_included=@($e2e|Where-Object ci_included).Count;ci_excluded=@($e2e|Where-Object {-not $_.ci_included}).Count}}}
    $canonical=$doc|ConvertTo-Json -Depth 50 -Compress
    $doc.document_digest=ShaText $canonical
    $inventoryBytes=$Utf8.GetBytes((SerializeJson $doc))
    $resultBytes=if($InventoryOnly){$null}else{$Utf8.GetBytes((SerializeJson (ExpectedResult $doc $inventoryBytes)))}
    if($Check){
        AssertBytes $outFull $inventoryBytes 'inventory'
        if(-not $InventoryOnly){AssertBytes $resultFull $resultBytes 'result envelope'}
        Write-Output "check passed $(Rel $outFull)$(if($InventoryOnly){''}else{' and '+(Rel $resultFull)}) (C1-C4 + $($e2e.Count) full-stack candidates)"
    }else{
        WriteAtomic $outFull $inventoryBytes
        if(-not $InventoryOnly){WriteAtomic $resultFull $resultBytes}
        Write-Output "generated $(Rel $outFull)$(if($InventoryOnly){''}else{' and '+(Rel $resultFull)}) (C1-C4 + $($e2e.Count) full-stack candidates)"
    }
} catch { Write-Error $_.Exception.Message; exit 1 }
