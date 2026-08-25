[CmdletBinding()]
param(
    [string]$RepoRoot = (Join-Path $PSScriptRoot '..'),
    [string]$InventoryPath = (Join-Path $PSScriptRoot '..\swarm\inventory\w1-06-premises.json'),
    [string]$ResultPath = (Join-Path $PSScriptRoot '..\swarm\results\W1-06-revised.json'),
    [switch]$SelfTest,
    [switch]$RegenerateResult
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$Schema = 'eliot.w1-06-premises.v3'
$ResultSchema = 'eliot-w1-06-revised-result.v4'

function Fail([string]$Message) { throw "W1_06_PREMISES_VERIFY_FAIL: $Message" }
function Sha([byte[]]$Bytes) { ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes))).ToLowerInvariant() }
function ShaText([string]$Text) { Sha $Utf8.GetBytes($Text) }
function ReadText([string]$Path) { try { $Utf8.GetString([IO.File]::ReadAllBytes($Path)) } catch { Fail "invalid UTF-8: $Path" } }
function AssertExact($Object, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Object) { Fail "$Label is null" }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object -Culture '')
    $expected = @($Expected | Sort-Object -Culture '')
    if (($actual -join "`0") -cne ($expected -join "`0")) { Fail "$Label fields differ (actual=$($actual -join ',') expected=$($expected -join ','))" }
}
function AssertRelative([string]$Path, [string]$Label) {
    $p = $Path.Replace('\', '/')
    if ([string]::IsNullOrWhiteSpace($Path) -or [IO.Path]::IsPathRooted($Path) -or $p -match '(^|/)\.\.?(/|$)' -or $p -match '^[A-Za-z]:') { Fail "$Label must be repository-relative: $Path" }
}
function GitPaths {
    $cached = @(& git -C $root ls-files --cached 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail 'git cached path enumeration failed' }
    $untracked = @(& git -C $root ls-files --others --exclude-standard 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail 'git nonignored-untracked path enumeration failed' }
    @($cached + $untracked | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ } | ForEach-Object { $_.Replace('\', '/') } | Sort-Object -Unique -Culture '')
}
function ExplicitInputPaths { @(
    'scripts/finalize-eliot-windows-x64-release.ps1',
    'bins/eliot/src/source_bundle_materializer.rs',
    'scripts/invoke-eliot-windows-x64-production.ps1',
    'bins/eliotd/src/lib.rs',
    'bins/eliotd/src/main.rs',
    'bins/eliotd/Cargo.toml',
    'crates/governor/eliot-governor/src/composition.rs',
    'scripts/build-eliot-windows-x64-release.ps1',
    'scripts/verify.ps1',
    '.github/workflows/ci.yml',
    '.github/workflows/candidate-release.yml',
    'scripts/gen-w1-06-premises.ps1'
) }
function SourceUniverse([string[]]$GitFiles) {
    $paths = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($p in $GitFiles) {
        if ($p -match '(?i)(^|/)(Cargo\.toml|Cargo\.lock)$|\.rs$') { $null = $paths.Add($p) }
    }
    foreach ($p in (ExplicitInputPaths)) { $null = $paths.Add($p) }
    @($paths | Sort-Object -Culture '')
}
function CargoRaw {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'cargo'; $psi.Arguments = 'metadata --locked --format-version 1'; $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
    $p = [Diagnostics.Process]::new(); $p.StartInfo = $psi
    if (-not $p.Start()) { Fail 'cargo metadata start failed' }
    $out = $p.StandardOutput.ReadToEnd(); $err = $p.StandardError.ReadToEnd(); $p.WaitForExit()
    if ($p.ExitCode -ne 0) { Fail "cargo metadata failed: $err" }
    $out
}
function CanonicalCargoMetadata([string]$Raw) {
    $escapedRoot = $root.Replace('\', '\\')
    $normal = $Raw.Replace($escapedRoot, '<repo>').Replace($root.Replace('\', '/'), '<repo>').Replace($root, '<repo>')
    try { $normal | ConvertFrom-Json | ConvertTo-Json -Depth 100 -Compress } catch { Fail 'cargo metadata canonicalization failed' }
}
function ExpectedInputDigest([string]$CanonicalCargo, [string[]]$Paths) {
    $rows = [Collections.Generic.List[string]]::new()
    foreach ($p in $Paths) {
        AssertRelative $p 'input path'
        $full = Join-Path $root ($p.Replace('/', [IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path $full -PathType Leaf)) { Fail "missing input: $p" }
        $rows.Add("$p`0$(Sha ([IO.File]::ReadAllBytes($full)))")
    }
    $rows.Add("cargo-metadata`0$(ShaText $CanonicalCargo)")
    ShaText (($rows | Sort-Object -Culture '') -join "`n")
}
function ParseSigned {
    $p = 'scripts/finalize-eliot-windows-x64-release.ps1'
    $m = [regex]::Match((ReadText (Join-Path $root $p)), 'function Get-AuthenticodeRoleDefinitions(?s:.*?)\n}\s*\n\s*function Get-NormalizedThumbprint')
    if (-not $m.Success) { Fail 'signed-role function missing' }
    $r = @()
    foreach ($x in [regex]::Matches($m.Value, "role\s*=\s*'([^']+)'\s*;\s*path\s*=\s*'([^']+)'") ) {
        $rolePath = $x.Groups[2].Value
        $r += [ordered]@{ role = $x.Groups[1].Value; path = $rolePath; executable = ([IO.Path]::GetExtension($rolePath) -ieq '.exe') }
    }
    @($r)
}
function ParseMaterial {
    $p = 'bins/eliot/src/source_bundle_materializer.rs'
    $m = [regex]::Match((ReadText (Join-Path $root $p)), 'pub const REQUIRED_ROLES: \[\(&str, bool\); \d+\] = \[(?s:.*?)\];')
    if (-not $m.Success) { Fail 'REQUIRED_ROLES missing' }
    $r = @()
    foreach ($x in [regex]::Matches($m.Value, '\("([^"]+)",\s*(true|false)\)') ) { $r += [ordered]@{ path = $x.Groups[1].Value; executable = ($x.Groups[2].Value -eq 'true') } }
    @($r)
}
function HasUniqueAnchor([string]$Path, [string]$Pattern) { ([regex]::Matches((ReadText (Join-Path $root ($Path.Replace('/', [IO.Path]::DirectorySeparatorChar)))), $Pattern)).Count -eq 1 }
function CheckWitness($Witness) {
    AssertExact $Witness @('path','line','end','anchor','sha256','text') 'witness'
    AssertRelative ([string]$Witness.path) 'witness path'
    $full = Join-Path $root ($Witness.path.Replace('/', [IO.Path]::DirectorySeparatorChar))
    if (-not (Test-Path $full -PathType Leaf)) { Fail "missing witness file $($Witness.path)" }
    if ((Sha ([IO.File]::ReadAllBytes($full))) -cne [string]$Witness.sha256) { Fail "witness source digest drift $($Witness.path)" }
    $lines = (ReadText $full) -split "`r?`n"
    if ([int]$Witness.line -lt 1 -or [int]$Witness.line -gt $lines.Count -or [int]$Witness.end -lt [int]$Witness.line -or [int]$Witness.end -gt $lines.Count) { Fail "witness range invalid $($Witness.path)" }; if ([string]::IsNullOrWhiteSpace([string]$Witness.anchor) -or [string]::IsNullOrWhiteSpace([string]$Witness.text)) { Fail "witness anchor/text empty $($Witness.path):$($Witness.line)" }; foreach($n in ([int]$Witness.line)..([int]$Witness.end)) { if ($Witness.text.IndexOf(([string]$lines[$n-1]).Trim(), [StringComparison]::Ordinal) -lt 0) { Fail "witness anchor/text drift $($Witness.path):$($Witness.line)" } }
}
function AssertInventory([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) { Fail "inventory missing: $Path" }
    try { $inv = Get-Content -Raw $Path | ConvertFrom-Json } catch { Fail 'invalid inventory JSON' }
    AssertExact $inv @('schema_version','generator_version','generated_from','cargo','claims','e2e_inventory','document_digest') 'inventory'
    if ($inv.schema_version -cne $Schema) { Fail 'inventory schema mismatch' }
    AssertExact $inv.generated_from @('kind','source_universe','input_paths','input_bindings','inputs_digest','cargo_metadata_digest') 'generated_from'
    if ($inv.generated_from.kind -cne 'content-bound') { Fail 'provenance is not content-bound' }
    AssertExact $inv.generated_from.source_universe @('mode','included_extensions','explicit_paths','exclusion_rules','path_count') 'source universe'
    if ($inv.generated_from.source_universe.mode -cne 'git-cached-plus-nonignored-untracked') { Fail 'source universe mode mismatch' }
    if ((@($inv.generated_from.source_universe.included_extensions) -join '|') -cne '.rs|Cargo.toml|Cargo.lock') { Fail 'source extension policy drift' }
    foreach ($p in @($inv.generated_from.source_universe.explicit_paths)) { AssertRelative ([string]$p) 'explicit input path' }
    $metaRaw = CargoRaw; $meta = $metaRaw | ConvertFrom-Json; $canonicalCargo = CanonicalCargoMetadata $metaRaw
    $expectedPaths = @(SourceUniverse @(GitPaths)); $actualPaths = @($inv.generated_from.input_paths)
    if (($actualPaths -join "`0") -cne ($expectedPaths -join "`0")) { Fail 'input path manifest differs from cached+nonignored-untracked source universe' }
    if ([int]$inv.generated_from.source_universe.path_count -ne $actualPaths.Count) { Fail 'source universe path count mismatch' }
    foreach ($p in $actualPaths) { AssertRelative ([string]$p) 'generated input path' }
    $bindingRows=@($inv.generated_from.input_bindings|ForEach-Object { AssertRelative ([string]$_.path) 'input binding path'; "$($_.path)`0$($_.sha256)" }); $expectedBindingRows=@($actualPaths|ForEach-Object { $f=Join-Path $root $_; "$_`0$(Sha ([IO.File]::ReadAllBytes($f)))" }); if (($bindingRows -join '|') -cne ($expectedBindingRows -join '|')) { Fail 'content-bound input bindings stale' }; if ([string]$inv.generated_from.inputs_digest -cne (ExpectedInputDigest $canonicalCargo $actualPaths)) { Fail 'content-bound input digest stale' }
    if ([string]$inv.generated_from.cargo_metadata_digest -cne (ShaText $canonicalCargo)) { Fail 'canonical Cargo metadata digest stale' }
    AssertExact $inv.cargo @('workspace_members','default_members','package_names') 'cargo'
    $ids = @($meta.workspace_members); $packages = @($meta.packages | Where-Object { $ids -contains $_.id })
    if ([int]$inv.cargo.workspace_members -ne $ids.Count -or [int]$inv.cargo.default_members -ne @($meta.workspace_default_members).Count) { Fail 'Cargo workspace counts drift' }
    if (($inv.cargo.package_names -join "`0") -cne ((@($packages | ForEach-Object name | Sort-Object -Culture '') -join "`0"))) { Fail 'Cargo package names drift' }
    AssertExact $inv.e2e_inventory @('schema_version','default_workspace_gate','gate_witnesses','tests','summary') 'e2e inventory'
    foreach ($p in @($inv.e2e_inventory.gate_witnesses)) { AssertRelative ([string]$p) 'gate witness path'; if (-not (Test-Path (Join-Path $root $p) -PathType Leaf)) { Fail "missing gate witness $p" } }
    AssertExact $inv.e2e_inventory.summary @('full_stack_tests','ignored_by_default','unignored_full_stack','ci_included','ci_excluded') 'e2e summary'
    $gate = [bool]$inv.e2e_inventory.default_workspace_gate; $rows = @($inv.e2e_inventory.tests)
    foreach ($row in $rows) {
        AssertExact $row @('id','path','line','test_name','full_stack','default_gate','ignored','feature_state','env_state','external_prerequisites','ci_included','ci_gate_witness') 'e2e row'
        AssertRelative ([string]$row.path) 'e2e path'; if (-not (Test-Path (Join-Path $root $row.path) -PathType Leaf)) { Fail "missing e2e path $($row.path)" }
        if ([int]$row.line -lt 1 -or -not [bool]$row.full_stack) { Fail 'invalid e2e row' }
        if ([bool]$row.ignored -and $row.default_gate -cne 'IGNORED_BY_DEFAULT') { Fail 'ignored gate mismatch' }
        if ((-not [bool]$row.ignored) -and $row.default_gate -cne 'WORKSPACE_DEFAULT_TEST') { Fail 'default gate mismatch' }
        if ([bool]$row.ci_included -ne ($gate -and -not [bool]$row.ignored)) { Fail 'ci inclusion mismatch' }
        $expectedWitness = if ($gate) { 'scripts/verify.ps1 + CI cargo test --workspace' } else { 'UNKNOWN' }
        if ($row.ci_gate_witness -cne $expectedWitness) { Fail 'ci gate witness mismatch' }
    }
    $ignored = @($rows | Where-Object default_gate -eq 'IGNORED_BY_DEFAULT').Count; $unignored = @($rows | Where-Object default_gate -eq 'WORKSPACE_DEFAULT_TEST').Count; $ci = @($rows | Where-Object ci_included).Count; $sum = $rows.Count
    if ([int]$inv.e2e_inventory.summary.full_stack_tests -ne $sum -or [int]$inv.e2e_inventory.summary.ignored_by_default -ne $ignored -or [int]$inv.e2e_inventory.summary.unignored_full_stack -ne $unignored -or [int]$inv.e2e_inventory.summary.ci_included -ne $ci -or [int]$inv.e2e_inventory.summary.ci_excluded -ne ($sum - $ci)) { Fail 'e2e summary mismatch' }
    $signed = ParseSigned; $material = ParseMaterial; $claims = @($inv.claims); $claimIds = @('A1-original-contour-linkage','A2-original-all-e2e-disabled','A3-original-signed-set-no-executable','C1-authenticode-signed-set-membership','C2-source-bundle-release-materializer-membership','C3-production-launch-reachability','C4-governor-constitutive-authority')
    if ((@($claims | ForEach-Object id | Sort-Object) -join '|') -cne ((@($claimIds | Sort-Object) -join '|'))) { Fail 'claim set differs' }
    foreach ($c in $claims) {
        $required = @('id','statement','verdict','scope','predicate','proof_ceiling')
        if ($c.id -in @('A3-original-signed-set-no-executable','C1-authenticode-signed-set-membership','C2-source-bundle-release-materializer-membership','C3-production-launch-reachability','C4-governor-constitutive-authority')) { $required += 'witnesses' }
        if ($c.id -eq 'C3-production-launch-reachability') { $required += 'unknown_reasons' }
        if ($c.id -eq 'C4-governor-constitutive-authority') { $required += 'authority_evidence' }
        if ($c.id -in @('C1-authenticode-signed-set-membership','C2-source-bundle-release-materializer-membership')) { $required += 'set' }
        AssertExact $c $required "claim $($c.id)"
    }
    $c1 = $claims | Where-Object id -eq 'C1-authenticode-signed-set-membership'; $c2 = $claims | Where-Object id -eq 'C2-source-bundle-release-materializer-membership'; $c3 = $claims | Where-Object id -eq 'C3-production-launch-reachability'; $c4 = $claims | Where-Object id -eq 'C4-governor-constitutive-authority'; $a1 = $claims | Where-Object id -eq 'A1-original-contour-linkage'; $a2 = $claims | Where-Object id -eq 'A2-original-all-e2e-disabled'; $a3 = $claims | Where-Object id -eq 'A3-original-signed-set-no-executable'
    AssertExact $c1.set @('roles','count','governor_role_present','executable_role_count') 'C1 set'; $stored1 = @($c1.set.roles | ForEach-Object { "$($_.role)|$($_.path)|$($_.executable)" }); $actual1 = @($signed | ForEach-Object { "$($_.role)|$($_.path)|$($_.executable)" }); if (($stored1 -join '|') -cne ($actual1 -join '|')) { Fail 'C1 role set differs' }
    $c1Exec = @($signed | Where-Object executable).Count; $c1Match = ($signed.Count -eq 7 -and $c1Exec -eq 7 -and @($signed | ForEach-Object { "$($_.role)|$($_.path)" } | Sort-Object | Get-Unique).Count -eq $signed.Count -and -not [bool]$c1.set.governor_role_present)
    if ([int]$c1.set.count -ne $signed.Count -or [int]$c1.set.executable_role_count -ne $c1Exec -or [bool]$c1.predicate.matches -ne $c1Match -or $c1.verdict -ne $(if ($c1Match) { 'TRUE' } else { 'FALSE' })) { Fail 'C1 predicate mismatch' }
    AssertExact $c2.set @('roles','count','executable_roles','executable_count','non_executable_count') 'C2 set'; $actual2 = @($material | ForEach-Object { "$($_.path)|$($_.executable.ToString().Substring(0,1).ToUpperInvariant()+$_.executable.ToString().Substring(1).ToLowerInvariant())" }); $stored2 = @($c2.set.roles | ForEach-Object { "$($_.path)|$($_.executable.ToString().Substring(0,1).ToUpperInvariant()+$_.executable.ToString().Substring(1).ToLowerInvariant())" }); if (($stored2 -join '|') -cne ($actual2 -join '|')) { Fail 'C2 role set differs' }
    $expected2 = 'eliot-host.exe|True|eliot-watchdog.exe|True|eliot-kernel.exe|True|eliot-store-surreal.exe|True|surreal.exe|True|eliotd.exe|True|generation.json|False|eliotd-governor.json|False|eliotd.json|False'; $c2Match = ($actual2.Count -eq 9 -and @($material | Where-Object executable).Count -eq 6 -and @($material | Where-Object { -not $_.executable }).Count -eq 3 -and ($actual2 -join '|') -eq $expected2 -and @($actual2 | Sort-Object | Get-Unique).Count -eq $actual2.Count)
    if ([int]$c2.set.count -ne $material.Count -or [bool]$c2.predicate.matches -ne $c2Match -or $c2.verdict -ne $(if ($c2Match) { 'TRUE' } else { 'FALSE' })) { Fail 'C2 predicate mismatch' }
    $c3Static = (HasUniqueAnchor 'scripts/invoke-eliot-windows-x64-production.ps1' 'function Invoke-ProductionEliotMaterializeSourceBundle' -and HasUniqueAnchor 'scripts/invoke-eliot-windows-x64-production.ps1' '\$process = \[EliotReleaseTrustedCliProcess\]::CreateSuspended' -and HasUniqueAnchor 'scripts/invoke-eliot-windows-x64-production.ps1' '\$processOutcome = \$process\.ResumeAndWait\(\)' -and HasUniqueAnchor 'scripts/invoke-eliot-windows-x64-production.ps1' "status = 'SOURCE_BUNDLE_MATERIALIZED'")
    if ([bool]$c3.predicate.static_handoff_chain_complete -ne $c3Static -or $c3.verdict -cne $(if (-not $c3Static) { 'FALSE' } elseif ([bool]$c3.predicate.runtime_receipt_observed) { 'TRUE' } else { 'UNKNOWN' }) -or @($c3.unknown_reasons).Count -lt 1) { Fail 'C3 proof ceiling/verdict mismatch' }
    $c4Match = (HasUniqueAnchor 'bins/eliotd/Cargo.toml' 'eliot-governor\.workspace' -and HasUniqueAnchor 'bins/eliotd/src/lib.rs' 'GovernorComposition::new\(kernel' -and HasUniqueAnchor 'crates/governor/eliot-governor/src/composition.rs' 'pub async fn commit_canonical')
    if ([bool]$c4.predicate.matches -ne $c4Match -or $c4.verdict -ne $(if ($c4Match) { 'TRUE' } else { 'FALSE' })) { Fail 'C4 predicate mismatch' }
    if ($a1.verdict -cne 'TRUE' -or [int]$a1.predicate.cross_contour_edge_count -ne 0 -or $a2.verdict -cne 'FALSE' -or [int]$a2.predicate.unignored_full_stack -ne $unignored -or $a3.verdict -cne 'FALSE' -or [int]$a3.predicate.signed_executable_roles -ne $c1Exec) { Fail 'original premise record mismatch' }
    foreach ($c in @($c1,$c2,$c3,$c4)) { foreach ($w in @($c.witnesses)) { CheckWitness $w } }
    $docDigest = [string]$inv.document_digest; $canonical = $inv | ConvertTo-Json -Depth 50 -Compress | ConvertFrom-Json; $canonical.PSObject.Properties.Remove('document_digest'); if ($docDigest -cne (ShaText ($canonical | ConvertTo-Json -Depth 50 -Compress))) { Fail 'inventory document digest mismatch' }
    return $inv
}
function FileDigest([string]$Path) {
    AssertRelative $Path 'linked file'; $full = Join-Path $root ($Path.Replace('/', [IO.Path]::DirectorySeparatorChar)); if (-not (Test-Path $full -PathType Leaf)) { Fail "missing linked file $Path" }; Sha ([IO.File]::ReadAllBytes($full))
}
function SerializeJson($Value) { return (($Value | ConvertTo-Json -Depth 50 -Compress) + "`n") }
function ExpectedResult($Inventory) {
    $programPath = 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'; $challengePath = 'swarm/challenges/W1-06-FALSIFICATION.md'
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
    $checks = @('cargo metadata --locked --format-version 1','C1/C2 role set membership, duplicate rejection, and order','per-role executable classification derived from each signed path extension','C1-C4 witness source digests and anchor ranges','inventory document digest and canonical Cargo metadata digest','content-bound provenance with cached+nonignored-untracked source universe','full inventory field set, counts, premises, and proof ceilings','full result envelope binding, challenge/reference digests, and path safety','byte determinism','inventory field-add/remove/path/content-universe and nested tamper self-tests','result envelope every-field tamper matrix')
    $structured = [ordered]@{ disposition='EVIDENCE_ONLY'; artifacts=[ordered]@{ inventory=[ordered]@{path='swarm/inventory/w1-06-premises.json';sha256=(FileDigest 'swarm/inventory/w1-06-premises.json')}; generator=[ordered]@{path='scripts/gen-w1-06-premises.ps1';sha256=(FileDigest 'scripts/gen-w1-06-premises.ps1')}; verifier=[ordered]@{path='scripts/verify-w1-06-premises.ps1';sha256=(FileDigest 'scripts/verify-w1-06-premises.ps1')} }; evidence=@('content-bound cached plus nonignored-untracked source universe','C1-C4 static premise evidence','C3 runtime reachability remains UNKNOWN'); discriminator_before=[ordered]@{ status='V4_REJECTED'; reason='release-builder witness was outside declared input universe and result equality was semantic' }; discriminator_after=[ordered]@{ status='MECHANISM_CHANGED_IN_PROGRESS'; input_universe_includes_release_builder=$true; canonical_raw_bytes=$true }; uncertainty='Static evidence only; no signed bundle or runtime receipt was observed.'; unresolved_questions=@('C3 production launch reachability remains UNKNOWN','W2 remains blocked by the declared boundary'); proposed_effects=@('Preserve EVIDENCE_ONLY','Do not authorize cutover or W2'); evidence_lineage=[ordered]@{ program_authority='swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'; challenge='swarm/challenges/W1-06-V4-MECHANISM-REVIEW.md'; inventory_digest=$Inventory.document_digest; input_digest=$Inventory.generated_from.inputs_digest }; source_of_truth='swarm/inventory/w1-06-premises.json'; source_content_digest=$Inventory.generated_from.inputs_digest; inventory_schema_version=$Inventory.schema_version; inventory_document_digest=$Inventory.document_digest; claims=$claims;
        e2e_inventory=[ordered]@{ inventory_schema='eliot.w1-06-e2e.v1'; full_stack_candidates=[int]$s.full_stack_tests; ignored_by_default=[int]$s.ignored_by_default; unignored_full_stack=[int]$s.unignored_full_stack; ci_included=[int]$s.ci_included; ci_excluded=[int]$s.ci_excluded; gate_basis=@('scripts/verify.ps1','.github/workflows/ci.yml','.github/workflows/candidate-release.yml','cargo test --workspace default gate'); classification_scope='generated candidates under cached plus nonignored-untracked integration-test paths with full-stack/UL/runtime markers; each row records default gate, ignore, feature, environment, prerequisites, and CI inclusion' };
        verification=[ordered]@{ generator='scripts/gen-w1-06-premises.ps1'; verifier='scripts/verify-w1-06-premises.ps1'; checks=$checks; command='pwsh -NoLogo -NoProfile -File scripts/verify-w1-06-premises.ps1 -SelfTest'; observed_result='PASS' };
        independent_openrouter_reviews=@([ordered]@{ session_id='ses_fccbf4de9ffeL1cpHpKbkslv59'; scope='fresh source-only original-premise falsification' },[ordered]@{ session_id='ses_fcc616fb4ffeufOS6MRXnDYfDk'; scope='separate current-source original and revised premise falsification' });
        program_revision=[ordered]@{ path=$programPath; sha256=(FileDigest $programPath) };
        challenge_references=@([ordered]@{ path=$challengePath; sha256=(FileDigest $challengePath); purpose='accepted falsification disposition and evidence boundary' },[ordered]@{ path='swarm/decisions/W1-06-PROGRAM-REVISION-v1.2.md'; sha256=(FileDigest 'swarm/decisions/W1-06-PROGRAM-REVISION-v1.2.md'); purpose='accepted revised premises and proof ceilings' },[ordered]@{ path=$programPath; sha256=(FileDigest $programPath); purpose='exact W1 result-envelope authority and one-shot retry boundary' });
        integration_guard='Root accepts only the bounded revised premise set. W2 is not unblocked until W0 passes and remaining W1 inventories are accepted; static membership is not Product Pulse evidence.'
    }
    return [pscustomobject][ordered]@{ schema_version='eliot.bootstrap-work-result.v1'; authority_status='EVIDENCE_ONLY'; work_item_id='W1-06'; structured_result=$structured }
}
function AssertResult([string]$Path, $Inventory) {
    if (-not (Test-Path $Path -PathType Leaf)) { Fail "result missing: $Path" }
    try { $actual = Get-Content -Raw $Path | ConvertFrom-Json } catch { Fail 'invalid result JSON' }
    $expected = ExpectedResult $Inventory; AssertExact $actual @('schema_version','authority_status','work_item_id','structured_result') 'result'; AssertExact $actual.structured_result @('disposition','artifacts','evidence','discriminator_before','discriminator_after','uncertainty','unresolved_questions','proposed_effects','evidence_lineage','source_of_truth','source_content_digest','inventory_schema_version','inventory_document_digest','claims','e2e_inventory','verification','independent_openrouter_reviews','program_revision','challenge_references','integration_guard') 'structured_result'
    if (-not [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($Path), $Utf8.GetBytes((SerializeJson $expected)))) { Fail 'result envelope raw bytes differ from deterministic expected content' }
    return $actual
}
function AssertRegeneratedInventory([string]$Path) {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        $gen = Join-Path $root 'scripts/gen-w1-06-premises.ps1'
        & pwsh -NoLogo -NoProfile -File $gen -RepoRoot $root -OutputPath $tmp | Out-Null
        if (-not [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($Path), [IO.File]::ReadAllBytes($tmp))) { Fail 'inventory raw bytes differ from deterministic generator output' }
    } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
try {
    $root = (Resolve-Path $RepoRoot).Path
    $invCandidate = $InventoryPath.Replace('/', [IO.Path]::DirectorySeparatorChar); $invPath = if ([IO.Path]::IsPathRooted($invCandidate)) { [IO.Path]::GetFullPath($invCandidate) } else { [IO.Path]::GetFullPath((Join-Path $root $invCandidate)) }
    $resCandidate = $ResultPath.Replace('/', [IO.Path]::DirectorySeparatorChar); $resPath = if ([IO.Path]::IsPathRooted($resCandidate)) { [IO.Path]::GetFullPath($resCandidate) } else { [IO.Path]::GetFullPath((Join-Path $root $resCandidate)) }
    $inventory = AssertInventory $invPath; AssertRegeneratedInventory $invPath; if ($RegenerateResult) { [IO.File]::WriteAllText($resPath, (SerializeJson (ExpectedResult $inventory)), $Utf8) }; $null = AssertResult $resPath $inventory
    if ($SelfTest) {
        $tmp = [IO.Path]::GetTempFileName(); try {
            $gen = Join-Path $root 'scripts/gen-w1-06-premises.ps1'; & pwsh -NoLogo -NoProfile -File $gen -RepoRoot $root -OutputPath $tmp | Out-Null; $a = [IO.File]::ReadAllBytes($tmp); & pwsh -NoLogo -NoProfile -File $gen -RepoRoot $root -OutputPath $tmp | Out-Null; $b = [IO.File]::ReadAllBytes($tmp); if (-not [Linq.Enumerable]::SequenceEqual($a, $b)) { Fail 'generator byte determinism failed' }
            $inventoryCases = @('top-level-add','top-level-remove','e2e-field','e2e-path','witness-field','provenance-field','provenance-path','universe-file','digest-field')
            foreach ($case in $inventoryCases) {
                $j = Get-Content -Raw $tmp | ConvertFrom-Json
                switch ($case) {
                    'top-level-add' { $j | Add-Member -NotePropertyName extra -NotePropertyValue tamper }
                    'top-level-remove' { $j.PSObject.Properties.Remove('cargo') }
                    'e2e-field' { $j.e2e_inventory.tests[0].line = ([int]$j.e2e_inventory.tests[0].line + 1) }
                    'e2e-path' { $j.e2e_inventory.tests[0].path = '../escape.rs' }
                    'witness-field' { $j.claims | Where-Object id -eq 'C1-authenticode-signed-set-membership' | ForEach-Object { $_.witnesses[0].sha256 = ('0' * 64) } }
                    'provenance-field' { $j.generated_from | Add-Member -NotePropertyName extra -NotePropertyValue tamper }
                    'provenance-path' { $j.generated_from.input_paths[0] = '../escape' }
                    'universe-file' { $j.generated_from.input_paths = @($j.generated_from.input_paths | Select-Object -Skip 1) }
                    'digest-field' { $j.document_digest = ('0' * 64) }
                }
                $bad = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllText($bad, ($j | ConvertTo-Json -Depth 50 -Compress), $Utf8); $failed = $false; try { $null = AssertInventory $bad } catch { $failed = $true }; Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue; if (-not $failed) { Fail "inventory tamper accepted: $case" }
            }
            $resultCases = @('header','source-binding','claim-measured','claim-witness','claim-ceiling','claim-unknown','claim-qualification','e2e-count','e2e-scope','verification-check','review-scope','program-digest','challenge-purpose','integration-guard','result-extra','result-remove')
            foreach ($case in $resultCases) {
                $j = Get-Content -Raw $resPath | ConvertFrom-Json
                switch ($case) {
                    'header' { $j.structured_result.disposition = 'TAMPERED' }
                    'source-binding' { $j.structured_result.source_content_digest = ('0' * 64) }
                    'claim-measured' { $j.structured_result.claims | Where-Object id -eq 'C1-authenticode-signed-set-membership' | ForEach-Object { $_.measured.predicate_matches = $false } }
                    'claim-witness' { $j.structured_result.claims | Where-Object id -eq 'C1-authenticode-signed-set-membership' | ForEach-Object { $_.witnesses[0] = 'tampered' } }
                    'claim-ceiling' { $j.structured_result.claims | Where-Object id -eq 'C1-authenticode-signed-set-membership' | ForEach-Object { $_.proof_ceiling = 'too broad' } }
                    'claim-unknown' { $j.structured_result.claims | Where-Object id -eq 'C3-production-launch-reachability' | ForEach-Object { $_.unknown_reasons = @('tampered') } }
                    'claim-qualification' { $j.structured_result.claims | Where-Object id -eq 'A1-original-contour-linkage' | ForEach-Object { $_.qualification = 'tampered' } }
                    'e2e-count' { $j.structured_result.e2e_inventory.full_stack_candidates = 1 }
                    'e2e-scope' { $j.structured_result.e2e_inventory.classification_scope = 'tampered' }
                    'verification-check' { $j.structured_result.verification.checks[0] = 'tampered' }
                    'review-scope' { $j.structured_result.independent_openrouter_reviews[0].scope = 'tampered' }
                    'program-digest' { $j.structured_result.program_revision.sha256 = ('0' * 64) }
                    'challenge-purpose' { $j.structured_result.challenge_references[0].purpose = 'tampered' }
                    'integration-guard' { $j.structured_result.integration_guard = 'W2 ready' }
                    'result-extra' { $j | Add-Member -NotePropertyName extra -NotePropertyValue tamper }
                    'result-remove' { $j.structured_result.PSObject.Properties.Remove('claims') }
                }
                $bad = [IO.Path]::GetTempFileName(); [IO.File]::WriteAllText($bad, ($j | ConvertTo-Json -Depth 50 -Compress), $Utf8); $failed = $false; try { $null = AssertResult $bad $inventory } catch { $failed = $true }; Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue; if (-not $failed) { Fail "result tamper accepted: $case" }
            }
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    Write-Output $(if ($SelfTest) { 'verified: content-bound cached+nonignored-untracked source universe, full inventory/result exact oracle, challenge/reference content binding, path safety, byte determinism, and broad inventory/result tamper matrix' } else { 'verified: content-bound source universe, full inventory/result deterministic oracle, challenge/reference content binding, path safety, and proof ceilings' }); exit 0
} catch { Write-Error $_.Exception.Message; exit 1 }
