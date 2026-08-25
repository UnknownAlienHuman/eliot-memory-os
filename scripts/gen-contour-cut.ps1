[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$SelfTest,
    [string]$OutputPath,
    [string]$ResultPath,
    [switch]$InventoryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$DefaultOutputPath = Join-Path $RepoRoot 'swarm\inventory\contour-cut.json'
$DefaultResultPath = Join-Path $RepoRoot 'swarm\results\W1-05.json'
$SchemaVersion = 'eliot-contour-cut-v4'
$ResultSchemaVersion = 'eliot-w1-05-result-v4'
$MechanismReviewPath = 'swarm/challenges/W1-05-MECHANISM-REVIEW.md'
$ContourA = @('eliot-app', 'eliot-engine', 'eliot-store')
$ContourB = @('eliot', 'eliot-host', 'eliot-kernel', 'eliotd')
$UnknownProcessTarget = 'UNKNOWN_PROCESS_TARGET'
$UnknownIpcTarget = 'UNKNOWN_IPC_TARGET'
$UnknownLaunchTarget = 'UNKNOWN_LAUNCH_TARGET'
$UnknownSchemaOwner = 'UNKNOWN_SCHEMA_OWNER'
$UnknownCanonicalOwner = 'UNKNOWN_CANONICAL_OWNER'

$RegressionFixtures = @(
    [pscustomobject]@{ id = 'dynamic-command-program'; path = 'workspace/tools/eliot-runtime-compiler/src/lib.rs'; motif_id = 'process-constructor'; source_match_pattern = 'Command::new\(program\)'; expected_target = $UnknownProcessTarget; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'dynamic-command-executable'; path = 'bins/eliot-mod-research/src/lib.rs'; motif_id = 'process-constructor'; source_match_pattern = 'Command::new\(executable\)'; expected_target = $UnknownProcessTarget; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'suspended-job-spawn'; path = 'bins/eliot-host/src/lib.rs'; motif_id = 'process-wrapper-spawn'; source_match_pattern = 'SuspendedJobChild::spawn_named\('; expected_target = $UnknownProcessTarget; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'suspended-job-spawn-with-limits'; path = 'crates/instrument/eliot-process-executor/src/lib.rs'; motif_id = 'process-wrapper-spawn'; source_match_pattern = 'SuspendedJobChild::spawn_named_with_limits\('; expected_target = $UnknownProcessTarget; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'dynamic-governor-command'; path = 'crates/eliot-app/src/runtime_bootstrap.rs'; motif_id = 'process-constructor'; source_match_pattern = 'Command::new\(governor\)'; expected_target = $UnknownProcessTarget; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'bootstrap-brief'; path = 'bins/eliot/tests/bootstrap_brief.rs'; motif_id = 'process-constructor'; source_match_pattern = 'CARGO_BIN_EXE_eliot'; expected_target = 'eliot'; expected_source_set = 'cached' }
    [pscustomobject]@{ id = 'bootstrap-draft-file'; path = 'bins/eliot/src/bootstrap_draft.rs'; motif_id = $null; source_match_pattern = $null; expected_target = $null; expected_source_set = 'cached' }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function Get-TextSha256([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToUpperInvariant() }
    finally { $sha.Dispose() }
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToUpperInvariant() }
    finally { $sha.Dispose() }
}

function Assert-ExactProperties($Object, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Object) { throw "$Label is null" }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`0") -cne ($wanted -join "`0")) { throw "$Label fields differ" }
}

function Get-ObjectDigest($Value) {
    return Get-TextSha256 (($Value | ConvertTo-Json -Depth 100 -Compress))
}

function Get-RelativePath([string]$Path) {
    return ([IO.Path]::GetRelativePath($RepoRoot, $Path)).Replace('\', '/')
}

function Get-GitRevision {
    $value = (& git -C $RepoRoot rev-parse HEAD 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "Unable to resolve source revision: $value" }
    return ([string]$value).Trim()
}

function Get-GitPathSet([string[]]$Arguments) {
    $value = @(& git -C $RepoRoot @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "git source-set query failed: $value" }
    return @($value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
}

function New-RustSourceSet([string[]]$CachedPaths, [string[]]$UntrackedPaths, [string]$Root) {
    $cached = @($CachedPaths | Where-Object { $_ } | Sort-Object -Unique)
    $untracked = @($UntrackedPaths | Where-Object { $_ } | Sort-Object -Unique)
    $union = @($cached + $untracked | Sort-Object -Unique)
    if ($union.Count -eq 0) { throw 'Rust source union is empty' }
    $cachedSet = @{}; foreach ($path in $cached) { $cachedSet[[string]$path] = $true }
    $kind = @{}; $bindings = @()
    foreach ($path in $union) {
        $absolute = Join-Path $Root $path
        if (-not (Test-Path -LiteralPath $absolute -PathType Leaf)) { throw "Rust source path is missing: $path" }
        $kind[[string]$path] = if ($cachedSet.ContainsKey([string]$path)) { 'cached' } else { 'nonignored_untracked' }
        $bindings += [ordered]@{ path = [string]$path; sha256 = Get-Sha256 $absolute }
    }
    return [pscustomobject]@{ Cached = @($cached); Untracked = @($untracked); Union = @($union); Kind = $kind; Bindings = @($bindings | Sort-Object path); Digest = Get-TextSha256 (($bindings | Sort-Object path | ForEach-Object { "$($_.path)`0$($_.sha256)" }) -join "`n") }
}

function Get-RustSourceSet {
    $cached = @(Get-GitPathSet @('ls-files', '--cached', '--', '*.rs'))
    $untracked = @(Get-GitPathSet @('ls-files', '--others', '--exclude-standard', '--', '*.rs'))
    return New-RustSourceSet $cached $untracked $RepoRoot
}

function Get-CargoMetadata {
    $raw = (& cargo metadata --format-version 1 --no-deps --manifest-path (Join-Path $RepoRoot 'Cargo.toml') 2>&1)
    if ($LASTEXITCODE -ne 0) { throw "cargo metadata failed: $raw" }
    $text = ($raw -join "`n").Trim()
    try { $json = $text | ConvertFrom-Json } catch { throw "cargo metadata was not JSON: $($_.Exception.Message)" }
    return [pscustomobject]@{ Json = $json; Canonical = ($json | ConvertTo-Json -Depth 100 -Compress) }
}

function Get-PackageRoots($Packages) {
    $roots = @()
    foreach ($package in $Packages) {
        $manifest = [IO.Path]::GetFullPath([string]$package.manifest_path)
        $roots += [pscustomobject]@{ Name = [string]$package.name; Root = (Split-Path -Parent $manifest); Manifest = $manifest }
    }
    return @($roots | Sort-Object { $_.Root.Length } -Descending)
}

function Get-OwnerPackage([string]$RelativePath, $PackageRoots) {
    $absolute = [IO.Path]::GetFullPath((Join-Path $RepoRoot $RelativePath))
    foreach ($root in $PackageRoots) {
        $prefix = $root.Root.TrimEnd('\') + '\'
        if ($absolute.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { return $root.Name }
    }
    return $null
}

function Get-TargetMap($Packages) {
    $map = @{}
    foreach ($package in $Packages) {
        foreach ($target in @($package.targets)) {
            if (@($target.kind) -notcontains 'bin') { continue }
            foreach ($alias in @([string]$target.name, "$($target.name).exe")) {
                if ($alias) { $map[$alias.ToLowerInvariant()] = [string]$package.name }
            }
        }
    }
    return $map
}

function Resolve-TargetPackage([string]$Hint, [hashtable]$TargetMap) {
    if ([string]::IsNullOrWhiteSpace($Hint)) { return $null }
    $clean = $Hint.Trim().Trim('"', "'").ToLowerInvariant()
    if ($TargetMap.ContainsKey($clean)) { return $TargetMap[$clean] }
    if ($clean.EndsWith('.exe') -and $TargetMap.ContainsKey($clean.Substring(0, $clean.Length - 4))) { return $TargetMap[$clean.Substring(0, $clean.Length - 4)] }
    if ($TargetMap.ContainsKey("$clean.exe")) { return $TargetMap["$clean.exe"] }
    return $null
}

function Get-ManifestDependencyLine($Package, [string]$DependencyName) {
    $lines = @(Get-Content -LiteralPath ([string]$Package.manifest_path))
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match ('^\s*' + [regex]::Escape($DependencyName) + '\s*=')) { return $i + 1 }
    }
    return $null
}

function Get-NearestSymbol($Lines, [int]$Index) {
    for ($i = $Index; $i -ge [Math]::Max(0, $Index - 100); $i--) {
        if ($Lines[$i] -match '^\s*(?:(?:pub)(?:\([^)]*\))?\s+)?(?:(?:async)\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)') {
            return [pscustomobject]@{ Name = $Matches[1]; Text = $Lines[$i].Trim() }
        }
    }
    return [pscustomobject]@{ Name = 'module_scope'; Text = '<module-scope>' }
}

function Get-CensusGrammar {
    # This is complete only for the declared grammar over the current source
    # union. It is deliberately not a semantic/runtime call graph claim.
    return @(
        [pscustomobject]@{ id = 'runtime-executable-literal'; pattern = '(?i)\b(?<target>eliot(?:-governor|-host|-kernel|d)(?:\.exe)?)\b'; edge_class = 'runtime_process_observation'; resolver = 'literal'; kind = 'process'; semantics = 'literal executable/process identity' }
        [pscustomobject]@{ id = 'process-constructor'; pattern = '(?i)(?<constructor>(?:(?:std|tokio)::process::)?(?:Command|StdCommand|ProcessCommand|TokioCommand|TokioProcessCommand|AsyncCommand))\s*::\s*new\s*\('; edge_class = 'process_launch_observation'; resolver = 'constructor'; kind = 'process'; semantics = 'qualified/dynamic process constructor; target may remain unknown' }
        [pscustomobject]@{ id = 'process-literal-launch'; pattern = '(?i)(?:(?:std|tokio)::process::)?(?:Command|StdCommand|ProcessCommand|TokioCommand|TokioProcessCommand|AsyncCommand)\s*::\s*new\s*\(\s*"(?<target>[^"]+)"'; edge_class = 'process_launch_observation'; resolver = 'literal'; kind = 'process'; semantics = 'literal process constructor target' }
        [pscustomobject]@{ id = 'process-wrapper-spawn'; pattern = '(?i)\bSuspendedJobChild::spawn_named(?:_with_limits)?\s*\('; edge_class = 'process_wrapper_observation'; resolver = 'unknown'; kind = 'process'; semantics = 'Windows suspended process wrapper operation' }
        [pscustomobject]@{ id = 'process-executor-wrapper'; pattern = '(?i)\b(?:WindowsProcessExecutor|ProcessExecutor|ProcessRequest|ProcessIntent|ProcessStartReceipt|ProcessExecutionAdmissionRequest)\b'; edge_class = 'process_wrapper_observation'; resolver = 'unknown'; kind = 'process'; semantics = 'process-executor wrapper/contract symbol; target remains unknown' }
        [pscustomobject]@{ id = 'windows-process-api'; pattern = '(?i)\b(?:CreateProcess(?:A|W)?|CreateProcessAsUser(?:A|W)?|CreateProcessWithTokenW|CreateProcessWithLogonW)\s*\('; edge_class = 'process_wrapper_observation'; resolver = 'unknown'; kind = 'process'; semantics = 'Windows process API operation' }
        [pscustomobject]@{ id = 'runtime-launch-contract'; pattern = '\b(?<symbol>EliotdLaunchDescriptor|HostStoreBootstrapRequirement|KernelLaunchBinding|launch_nonce|store-bootstrap|eliotd-descriptor)\b'; edge_class = 'launch_control_observation'; resolver = 'unknown'; kind = 'launch'; semantics = 'launch/control contract motif; endpoint remains unknown' }
        [pscustomobject]@{ id = 'ipc-named-pipe-operation'; pattern = '(?i)\b(?<owner>NamedPipeTransport|NamedPipeServer|NamedPipeClient|NamedPipeIpcServer|ClientOptions|ServerOptions|PipeClient|PipeServer)\s*(?:::|\.)\s*(?<operation>connect_authenticated|connect|create|new|open|listen|accept|send_frame|receive_frame)\b'; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'named-pipe client/server/transport operation' }
        [pscustomobject]@{ id = 'ipc-qualified-named-pipe-api'; pattern = '(?i)\b(?:tokio::net::windows::named_pipe::(?:ClientOptions|ServerOptions)|windows_sys::Win32::System::Pipes::[A-Za-z0-9_]+)\b'; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'qualified named-pipe API symbol' }
        [pscustomobject]@{ id = 'ipc-peer-auth'; pattern = '(?i)\b(?:observe_named_pipe_peer_process(?:_in_job)?|authenticate_named_pipe_(?:server|client)|current_process_named_pipe_expectation)\s*\('; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'named-pipe peer identity/authentication operation' }
        [pscustomobject]@{ id = 'ipc-transport-symbol'; pattern = '\b(?:NamedPipeTransport|NamedPipeServer|NamedPipeIpcServer|NamedPipeClient|NamedPipePeerExpectation|KernelClient|DaemonKernelClient|IpcGovernorClient|HookIpcForwarder)\b'; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'IPC transport/client/server symbol' }
        [pscustomobject]@{ id = 'ipc-handshake-symbol'; pattern = '\b(?:connect_authenticated|handshake_rejection_frame|server_hello_frame|client_hello_frame|client_hello|server_hello)\b'; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'IPC handshake/frame symbol' }
        [pscustomobject]@{ id = 'ipc-host-governor-request'; pattern = '\b(?:host_governor_request|IpcGovernorClient)\s*\('; edge_class = 'runtime_ipc_observation'; resolver = 'unknown'; kind = 'ipc'; semantics = 'host/governor IPC request operation' }
        [pscustomobject]@{ id = 'contract-governor-config'; pattern = '\bGovernorConfig\b'; edge_class = 'shared_contract_type'; resolver = 'fixed:eliot-types'; kind = 'contract'; semantics = 'GovernorConfig import/parse/type use; not a runtime join' }
        [pscustomobject]@{ id = 'contract-runtime-contracts'; pattern = '(?i)\b(?:eliot_runtime_contracts|eliot-runtime-contracts)\b'; edge_class = 'shared_contract_type'; resolver = 'fixed:eliot-runtime-contracts'; kind = 'contract'; semantics = 'runtime contract package reference' }
        [pscustomobject]@{ id = 'state-write-receipt'; pattern = '\b(?:write_receipt|write_receipt_by_id)\b'; edge_class = 'state_write_observation'; resolver = 'unknown'; kind = 'state'; semantics = 'write receipt symbol; owner/route is not inferred' }
        [pscustomobject]@{ id = 'schema-version-field'; pattern = '\bschema_version\b'; edge_class = 'schema_observation'; resolver = 'fixed:UNKNOWN_SCHEMA_OWNER'; kind = 'schema'; semantics = 'schema/version field only; never write authority' }
        [pscustomobject]@{ id = 'canonical-write-symbol'; pattern = '\bcommit_canonical\s*\('; edge_class = 'canonical_write_observation'; resolver = 'fixed:eliot-governor'; kind = 'canonical'; semantics = 'canonical write definition/reference; exact caller proof is separate' }
    )
}

function Get-Contour([string]$Package) {
    if ($Package -in $ContourA) { return 'A' }
    if ($Package -in $ContourB) { return 'B' }
    return $null
}

function Get-Direction([string]$From, [string]$To) {
    $fromContour = Get-Contour $From; $toContour = Get-Contour $To
    if ($fromContour -and $toContour -and $fromContour -ne $toContour) { return "${fromContour}_TO_${toContour}" }
    if ($fromContour -and $toContour -and $fromContour -eq $toContour) { return "${fromContour}_INTRA" }
    if ($fromContour -and -not $toContour) { return "${fromContour}_TO_SHARED_OR_UNKNOWN" }
    if (-not $fromContour -and $toContour) { return "EXTERNAL_TO_${toContour}" }
    return 'EXTERNAL_OR_UNKNOWN'
}

function Get-MotifRole([string]$MotifId, [string]$Line) {
    $trimmed = $Line.Trim()
    if ($MotifId -eq 'contract-governor-config') {
        if ($trimmed -match '^use\b|^pub\s+use\b') { return 'import' }
        if ($trimmed -match '(?i)from_str|from_slice|deserialize|toml') { return 'parse' }
        return 'type_reference'
    }
    if ($MotifId -eq 'canonical-write-symbol') {
        if ($trimmed -match '^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+commit_canonical\s*\(') { return 'definition' }
        return 'reference'
    }
    return 'observation'
}

function Get-TargetEvidence($Motif, $Match, [string]$Line, [hashtable]$TargetMap) {
    $hint = $null; $resolution = 'unknown_dynamic_target'
    if ($Motif.resolver -eq 'fixed:*') { return [pscustomobject]@{ Target = $Motif.resolver.Substring(6); Resolution = 'fixed_owner' } }
    if ($Motif.resolver -like 'fixed:*') { return [pscustomobject]@{ Target = $Motif.resolver.Substring(6); Resolution = 'fixed_owner' } }
    if ($Motif.resolver -eq 'literal' -and $Match.Groups['target'].Success) {
        $hint = $Match.Groups['target'].Value; $resolution = 'literal_target'
    } elseif ($Motif.resolver -eq 'constructor') {
        $argument = [regex]::Match($Line, '(?i)::\s*new\s*\(\s*(?<argument>[^,\)]*)').Groups['argument'].Value.Trim()
        $envMatch = [regex]::Match($argument, '(?i)env!\s*\(\s*"CARGO_BIN_EXE_(?<bin>[^"]+)"')
        if ($envMatch.Success) { $hint = $envMatch.Groups['bin'].Value; $resolution = 'cargo_bin_env_target' }
        elseif ($argument -match '^"(?<literal>[^"]+)"$') { $hint = $Matches['literal']; $resolution = 'literal_target' }
        else { $resolution = 'unknown_dynamic_target' }
    }
    $target = Resolve-TargetPackage $hint $TargetMap
    if ($target) { return [pscustomobject]@{ Target = $target; Resolution = $resolution } }
    return [pscustomobject]@{ Target = $UnknownProcessTarget; Resolution = if ($resolution -eq 'literal_target') { 'unknown_literal_target' } else { $resolution } }
}

function New-Row($Values) {
    return [pscustomobject]@{
        id = $Values.id; from = $Values.from; to = $Values.to; edge_class = $Values.edge_class; relation = $Values.relation; direction = $Values.direction; motif_id = $Values.motif_id
        source_path = $Values.source_path; source_line = $Values.source_line; source_symbol = $Values.source_symbol; source_symbol_text = $Values.source_symbol_text; source_pattern = $Values.source_pattern; source_match_text = $Values.source_match_text
        source_file_sha256 = $Values.source_file_sha256; source_symbol_sha256 = if ($null -eq $Values.source_symbol_text) { $null } else { Get-TextSha256 ([string]$Values.source_symbol_text) }; source_match_sha256 = if ($null -eq $Values.source_match_text) { $null } else { Get-TextSha256 ([string]$Values.source_match_text)
        }; source_file_set = $Values.source_file_set; target_resolution = $Values.target_resolution; status = $Values.status; severity = $Values.severity; join_claim = $Values.join_claim; falsifier = $Values.falsifier
    }
}

function Get-CanonicalWriteProof($SourceSet, $PackageRoots) {
    $definitions = @(); $callers = @(); $referencePattern = '\bcommit_canonical\s*\('; $definitionPattern = '^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+commit_canonical\s*\('
    foreach ($relative in $SourceSet.Union) {
        $absolute = Join-Path $RepoRoot $relative; $lines = @(Get-Content -LiteralPath $absolute); $hash = Get-Sha256 $absolute
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -notmatch $referencePattern) { continue }
            $symbol = Get-NearestSymbol $lines $i
            $evidence = [ordered]@{ source_path = $relative; source_line = $i + 1; source_symbol = $symbol.Name; source_symbol_text = $symbol.Text; source_match_text = $lines[$i].Trim(); source_file_sha256 = $hash; source_symbol_sha256 = Get-TextSha256 $symbol.Text; source_match_sha256 = Get-TextSha256 $lines[$i].Trim(); source_file_set = $SourceSet.Kind[$relative]; package = Get-OwnerPackage $relative $PackageRoots }
            if ($lines[$i] -match $definitionPattern) { $definitions += ,[pscustomobject]$evidence } else { $callers += ,[pscustomobject]$evidence }
        }
    }
    return [ordered]@{ symbol = 'commit_canonical'; source_file_set_kind = 'git_cached_plus_nonignored_untracked_rust'; rust_file_count = $SourceSet.Union.Count; definition_pattern = $definitionPattern; reference_pattern = $referencePattern; definition_count = $definitions.Count; caller_count = $callers.Count; definitions = @($definitions | Sort-Object source_path, source_line); callers = @($callers | Sort-Object source_path, source_line); status = if ($definitions.Count -eq 1 -and $callers.Count -eq 0) { 'VERIFIED_ONE_DEFINITION_ZERO_CALLERS' } else { 'FALSIFIED' }; falsifier = 'Any second definition or any non-definition commit_canonical reference in the cached plus non-ignored-untracked Rust union falsifies this §5.1 proof.' }
}

function Get-CensusRows($SourceSet, $PackageRoots, [hashtable]$TargetMap) {
    $rows = New-Object 'System.Collections.Generic.List[object]'; $hitCounts = [ordered]@{}; $rowCounts = [ordered]@{}; $motifs = @(Get-CensusGrammar); $compiled = @{}; $fileCache = @{}; $symbolCache = @{}
    foreach ($motif in $motifs) { $compiled[$motif.id] = [regex]::new([string]$motif.pattern); $hitCounts[$motif.id] = 0; $rowCounts[$motif.id] = 0 }
    foreach ($relative in $SourceSet.Union) {
        $absolute = Join-Path $RepoRoot $relative
        if (-not $fileCache.ContainsKey($relative)) { $fileCache[$relative] = [pscustomobject]@{ Lines = @(Get-Content -LiteralPath $absolute); Hash = Get-Sha256 $absolute; Owner = Get-OwnerPackage $relative $PackageRoots } }
        $entry = $fileCache[$relative]
        for ($lineIndex = 0; $lineIndex -lt $entry.Lines.Count; $lineIndex++) {
            $line = [string]$entry.Lines[$lineIndex]
            foreach ($motif in $motifs) {
                $matches = $compiled[$motif.id].Matches($line)
                if ($matches.Count -eq 0) { continue }
                $hitCounts[$motif.id] += $matches.Count
                foreach ($match in $matches) {
                    $owner = if ($entry.Owner) { [string]$entry.Owner } else { 'UNOWNED' }
                    $targetInfo = Get-TargetEvidence $motif $match $line $TargetMap
                    $to = switch -Regex ($motif.resolver) { '^fixed:' { $targetInfo.Target; break } default { $targetInfo.Target } }
                    $role = Get-MotifRole $motif.id $line
                    $edge = [string]$motif.edge_class; $relation = 'non_join'; $status = 'unknown'; $severity = 'medium'; $falsifier = 'A source motif is evidence only; prove an authenticated invoked process/IPC path before calling it a contour join.'
                    if ($motif.kind -eq 'process') {
                        $status = 'present'; $severity = 'high'; $relation = if ($targetInfo.Target -eq $UnknownProcessTarget) { 'dynamic_or_unresolved_process_observation' } else { 'launch_candidate' }
                        if ($motif.id -eq 'runtime-executable-literal' -and $to -eq 'eliot-app' -and $line -match '(?i)legacy|any_running_process_named|process state|already running|is running|coexist|retire') { $edge = 'negative_observation'; $relation = 'non_join'; $severity = 'high'; $falsifier = 'Find an actual process launch or IPC invocation; a negative coexistence check is not a runtime join.' }
                        elseif ($motif.id -eq 'runtime-executable-literal') { $edge = 'runtime_process_observation'; $relation = if ($to -eq $UnknownProcessTarget) { 'unresolved_process_observation' } else { 'intra_or_external_process_observation' }; $status = if ($to -eq $UnknownProcessTarget) { 'unknown' } else { 'present' }; $severity = if ($to -eq $UnknownProcessTarget) { 'medium' } else { 'high' }; $falsifier = 'A process-name literal is not proof of a launch, IPC connection, or contour join.' }
                        elseif ($motif.id -like 'process-wrapper*' -or $motif.id -eq 'process-executor-wrapper' -or $motif.id -eq 'windows-process-api') { $edge = 'process_wrapper_observation'; $relation = 'process_wrapper_operation'; $to = $UnknownProcessTarget; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'explicit_unknown_process_wrapper' }; $falsifier = 'Resolve the concrete executable and authenticated invocation; a process wrapper symbol alone is not runtime proof.' }
                        elseif ($motif.id -eq 'process-literal-launch' -or $motif.id -eq 'process-constructor') { $edge = 'process_launch_observation'; $falsifier = if ($to -eq $UnknownProcessTarget) { 'Resolve the dynamic process target and show authenticated protocol completion; constructor evidence alone is not runtime success.' } else { 'Show the launched process reaches the target contour and completes an authenticated protocol; construction alone does not prove runtime success.' } }
                    } elseif ($motif.kind -eq 'ipc') {
                        $edge = 'runtime_ipc_observation'; $relation = 'ipc_operation'; $status = 'present'; $severity = 'high'; $to = $UnknownIpcTarget; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'explicit_unknown_ipc_endpoint' }; $falsifier = 'Show the named-pipe endpoint, authenticated peer, and invoked protocol; symbol/operation evidence alone is not a contour join.'
                    } elseif ($motif.kind -eq 'launch') {
                        $edge = 'launch_control_observation'; $relation = 'launch_contract_symbol'; $status = 'unknown'; $severity = 'high'; $to = $UnknownLaunchTarget; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'explicit_unknown_launch_endpoint' }; $falsifier = 'Resolve the launch endpoint and prove an invoked authenticated process path; launch/control contract symbols alone are not a join.'
                    } elseif ($motif.id -eq 'contract-governor-config') {
                        $edge = 'shared_contract_type'; $relation = "type_$role"; $status = 'present'; $severity = 'low'; $falsifier = 'A GovernorConfig import or parse is not a runtime join; require a resolved process/IPC call and independent trace.'
                    } elseif ($motif.id -eq 'contract-runtime-contracts') {
                        $edge = 'shared_contract_type'; $relation = 'contract_reference'; $status = 'present'; $severity = 'low'; $falsifier = 'A contract package reference does not prove runtime connection or authority ownership.'
                    } elseif ($motif.id -eq 'schema-version-field') {
                        $edge = 'schema_observation'; $relation = 'non_join'; $status = 'unknown'; $severity = 'low'; $to = $UnknownSchemaOwner; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'explicit_unknown_schema_owner' }; $falsifier = 'A schema_version field alone cannot establish a write authority or contour join.'
                    } elseif ($motif.id -eq 'state-write-receipt') {
                        $edge = 'state_write_observation'; $relation = 'write_symbol_only'; $status = 'unknown'; $severity = 'high'; $to = $UnknownCanonicalOwner; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'explicit_unknown_canonical_owner' }; $falsifier = 'Identify the single invoked canonical owner and authenticated route; a write_receipt symbol is not proof of ownership.'
                    } elseif ($motif.id -eq 'canonical-write-symbol') {
                        $edge = if ($role -eq 'definition') { 'canonical_write_definition' } else { 'canonical_write_reference' }; $relation = $role; $status = 'present'; $severity = 'critical'; $to = 'eliot-governor'; $targetInfo = [pscustomobject]@{ Target = $to; Resolution = 'fixed_owner' }; $falsifier = 'The separate commit_canonical proof must show exactly one definition and zero callers across the cached plus non-ignored-untracked Rust union.'
                    }
                    if (-not $symbolCache.ContainsKey("$relative`:$($lineIndex + 1)")) { $symbolCache["$relative`:$($lineIndex + 1)"] = Get-NearestSymbol $entry.Lines $lineIndex }
                    $symbol = $symbolCache["$relative`:$($lineIndex + 1)"]
                    $safeTo = if ($to) { [string]$to } else { 'UNRESOLVED' }
                    $id = "CENSUS-$($motif.id)-$owner-$safeTo-$($relative.Replace('/','_').Replace('.','_'))-L$($lineIndex + 1)-$($match.Index)"
                    $null = $rows.Add([object](New-Row @{ id = $id; from = $owner; to = $safeTo; edge_class = $edge; relation = $relation; direction = Get-Direction $owner $safeTo; motif_id = $motif.id; source_path = $relative; source_line = $lineIndex + 1; source_symbol = $symbol.Name; source_symbol_text = $symbol.Text; source_pattern = $motif.pattern; source_match_text = $line.Trim(); source_file_sha256 = $entry.Hash; source_file_set = $SourceSet.Kind[$relative]; target_resolution = $targetInfo.Resolution; status = $status; severity = $severity; join_claim = $false; falsifier = $falsifier }))
                    $rowCounts[$motif.id] += 1
                }
            }
        }
    }
    return [pscustomobject]@{ Rows = $rows.ToArray(); HitCounts = $hitCounts; RowCounts = $rowCounts; HitCount = @($hitCounts.Values | Measure-Object -Sum).Sum; RowCount = $rows.Count }
}

function Get-ManifestEvidence($Package, [string]$DependencyName) {
    $line = Get-ManifestDependencyLine $Package $DependencyName; $path = [string]$Package.manifest_path; $text = if ($null -eq $line) { $null } else { (Get-Content -LiteralPath $path)[$line - 1].Trim() }
    return [pscustomobject]@{ source_path = Get-RelativePath $path; source_line = $line; source_symbol = '[dependencies]'; source_symbol_text = $text; source_pattern = '^\s*' + [regex]::Escape($DependencyName) + '\s*='; source_file_sha256 = Get-Sha256 $path }
}

function New-CargoRows($ByName) {
    $rows = @()
    foreach ($fromName in ($ContourA + $ContourB)) {
        $fromContour = Get-Contour $fromName; $targets = if ($fromContour -eq 'A') { $ContourB } else { $ContourA }; $direction = if ($fromContour -eq 'A') { 'A_TO_B' } else { 'B_TO_A' }
        foreach ($toName in $targets) {
            $package = $ByName[$fromName]; $present = @($package.dependencies | Where-Object { $_.name -eq $toName -and $null -eq $_.source }).Count -gt 0; $evidence = Get-ManifestEvidence $package $toName; $status = if ($present) { 'present' } else { 'absent' }; $matchText = if ($present) { $evidence.source_symbol_text } else { $null }; $severity = if ($present) { 'critical' } else { 'info' }; $falsifier = if ($present) { 'Recompute cargo metadata and remove the direct path dependency.' } else { 'A direct path dependency in cargo metadata falsifies absence.' }
            $rows += ,(New-Row @{ id = "CARGO-$fromName-to-$toName"; from = $fromName; to = $toName; edge_class = 'cargo_dependency'; relation = 'cargo_direct_dependency'; direction = $direction; motif_id = 'cargo-metadata'; source_path = $evidence.source_path; source_line = $evidence.source_line; source_symbol = $evidence.source_symbol; source_symbol_text = $evidence.source_symbol_text; source_pattern = $evidence.source_pattern; source_match_text = $matchText; source_file_sha256 = $evidence.source_file_sha256; source_file_set = 'cargo-manifest'; target_resolution = 'cargo_metadata_direct_edge'; status = $status; severity = $severity; join_claim = $false; falsifier = $falsifier })
        }
    }
    $aDeps = @($ContourA | ForEach-Object { @($ByName[$_].dependencies | Where-Object { $null -eq $_.source } | ForEach-Object name) } | Sort-Object -Unique); $bDeps = @($ContourB | ForEach-Object { @($ByName[$_].dependencies | Where-Object { $null -eq $_.source } | ForEach-Object name) } | Sort-Object -Unique); $shared = @($aDeps | Where-Object { $_ -in $bDeps -and $_ -match '(?i)(contract|type|protocol|receipt|state|config)' } | Sort-Object)
    foreach ($sharedName in $shared) { foreach ($fromName in ($ContourA + $ContourB)) { if (@($ByName[$fromName].dependencies | Where-Object { $_.name -eq $sharedName -and $null -eq $_.source }).Count -eq 0) { continue }; $evidence = Get-ManifestEvidence $ByName[$fromName] $sharedName; $contour = Get-Contour $fromName; $rows += ,(New-Row @{ id = "SHARED-$fromName-to-$sharedName"; from = $fromName; to = $sharedName; edge_class = 'shared_contract_type'; relation = 'cargo_shared_dependency'; direction = "${contour}_TO_SHARED"; motif_id = 'cargo-metadata'; source_path = $evidence.source_path; source_line = $evidence.source_line; source_symbol = $evidence.source_symbol; source_symbol_text = $evidence.source_symbol_text; source_pattern = $evidence.source_pattern; source_match_text = $evidence.source_symbol_text; source_file_sha256 = $evidence.source_file_sha256; source_file_set = 'cargo-manifest'; target_resolution = 'cargo_metadata_shared_dependency'; status = 'present'; severity = 'medium'; join_claim = $false; falsifier = 'Remove the direct shared dependency or demonstrate it is not a contract/type package.' }) } }
    return @($rows)
}

function Get-RegressionEvidence($Census, $SourceSet) {
    $out = @()
    foreach ($fixture in $RegressionFixtures) {
        if (-not ($fixture.path -in $SourceSet.Union)) { throw "Regression fixture source file missing from union: $($fixture.path)" }
        $fixtureHash = Get-Sha256 (Join-Path $RepoRoot $fixture.path)
        if ($null -eq $fixture.motif_id) { $out += [ordered]@{ id = $fixture.id; path = $fixture.path; source_set = $SourceSet.Kind[$fixture.path]; source_file_sha256 = $fixtureHash; motif_id = $null; line = $null; target = $null; source_match_text = $null }; continue }
        $hits = @($Census.Rows | Where-Object { $_.source_path -eq $fixture.path -and $_.motif_id -eq $fixture.motif_id -and $_.source_match_text -match $fixture.source_match_pattern } | Sort-Object source_line, id)
        if ($hits.Count -eq 0) { throw "Regression fixture row missing: $($fixture.id)" }
        $hit = $hits[0]
        if ($hit.to -cne $fixture.expected_target) { throw "Regression fixture target mismatch: $($fixture.id) expected $($fixture.expected_target) got $($hit.to)" }
        $out += [ordered]@{ id = $fixture.id; path = $fixture.path; source_set = $SourceSet.Kind[$fixture.path]; source_file_sha256 = $fixtureHash; motif_id = $fixture.motif_id; line = $hit.source_line; target = $hit.to; source_match_text = $hit.source_match_text }
    }
    return @($out)
}

function Get-Summary($Rows, $Census, $SourceSet) {
    $edgeCounts = [ordered]@{}; foreach ($group in @($Rows | Group-Object edge_class | Sort-Object Name)) { $edgeCounts[$group.Name] = $group.Count }
    $statusCounts = [ordered]@{}; foreach ($group in @($Rows | Group-Object status | Sort-Object Name)) { $statusCounts[$group.Name] = $group.Count }
    $cargo = @($Rows | Where-Object edge_class -eq 'cargo_dependency')
    return [ordered]@{ row_count = $Rows.Count; cargo_direct_present = @($cargo | Where-Object status -eq 'present').Count; cargo_direct_absent = @($cargo | Where-Object status -eq 'absent').Count; source_row_count = $Census.RowCount; source_hit_count = $Census.HitCount; edge_class_counts = $edgeCounts; status_counts = $statusCounts; negative_observation_non_join = @($Rows | Where-Object { $_.edge_class -eq 'negative_observation' -and $_.relation -eq 'non_join' }).Count; process_launch_observation = @($Rows | Where-Object edge_class -eq 'process_launch_observation').Count; process_wrapper_observation = @($Rows | Where-Object edge_class -eq 'process_wrapper_observation').Count; runtime_ipc_observation = @($Rows | Where-Object edge_class -eq 'runtime_ipc_observation').Count; launch_control_observation = @($Rows | Where-Object edge_class -eq 'launch_control_observation').Count; schema_observation = @($Rows | Where-Object edge_class -eq 'schema_observation').Count; state_write_unknown = @($Rows | Where-Object { $_.edge_class -eq 'state_write_observation' -and $_.status -eq 'unknown' }).Count; unknown_process_target = @($Rows | Where-Object to -eq $UnknownProcessTarget).Count; unknown_ipc_target = @($Rows | Where-Object to -eq $UnknownIpcTarget).Count; unknown_launch_target = @($Rows | Where-Object to -eq $UnknownLaunchTarget).Count; cached_rust_file_count = $SourceSet.Cached.Count; nonignored_untracked_rust_file_count = $SourceSet.Untracked.Count; union_rust_file_count = $SourceSet.Union.Count }
}

function Assert-Inventory($Inventory) {
    if ($Inventory.schema_version -ne $SchemaVersion -or $Inventory.authority_status -ne 'EVIDENCE_ONLY') { throw 'inventory schema/authority mismatch' }
    if ($Inventory.cutover_decision.selected -ne $null -or $Inventory.cutover_decision.status -ne 'PENDING_ROOT') { throw 'inventory illegally selected cutover' }
    if ($Inventory.source_scan.file_set_kind -ne 'git_cached_plus_nonignored_untracked_rust' -or $Inventory.source_scan.completeness_statement -ne 'COMPLETE_CURRENT_FILE_SET_DECLARED_GRAMMAR_ONLY' -or $Inventory.source_scan.semantic_exhaustiveness_claim -ne $false -or @($Inventory.source_scan.rust_file_bindings).Count -ne [int]$Inventory.source_scan.union_rust_file_count) { throw 'inventory source-set/completeness declaration mismatch' }
    $rows = @($Inventory.rows); $ids = @($rows | ForEach-Object id); if ($rows.Count -eq 0 -or @($ids | Sort-Object -Unique).Count -ne $ids.Count) { throw 'inventory rows empty or duplicated' }
    $sorted = @($rows | Sort-Object edge_class, direction, from, to, id); if ((@($sorted | ForEach-Object id) -join '|') -cne ($ids -join '|')) { throw 'inventory rows are not canonical' }
    foreach ($row in $rows) { if ($row.status -notin @('present','absent','unknown')) { throw "invalid row status: $($row.id)" }; if ($row.join_claim -ne $false) { throw "runtime join claimed by $($row.id)" } }
    if ($Inventory.canonical_write_proof.definition_count -ne 1 -or $Inventory.canonical_write_proof.caller_count -ne 0 -or $Inventory.canonical_write_proof.status -ne 'VERIFIED_ONE_DEFINITION_ZERO_CALLERS') { throw 'commit_canonical proof is not exact one-definition/zero-callers' }
}

function New-Inventory {
    $metadata = Get-CargoMetadata; $packages = @($metadata.Json.packages | Sort-Object name); $byName = @{}; foreach ($package in $packages) { $byName[[string]$package.name] = $package }
    foreach ($name in ($ContourA + $ContourB)) { if (-not $byName.ContainsKey($name)) { throw "missing contour package: $name" } }
    $roots = Get-PackageRoots $packages; $sourceSet = Get-RustSourceSet; $targets = Get-TargetMap $packages; $census = Get-CensusRows $sourceSet $roots $targets; $cargoRows = New-CargoRows $byName; $rows = @($cargoRows + $census.Rows | Sort-Object edge_class, direction, from, to, id); $summary = Get-Summary $rows $census $sourceSet; $grammar = @(Get-CensusGrammar | ForEach-Object { [ordered]@{ id = $_.id; pattern = $_.pattern; edge_class = $_.edge_class; resolver = $_.resolver; kind = $_.kind; semantics = $_.semantics } }); $targetProjection = [ordered]@{}; foreach ($targetName in @($targets.Keys | Sort-Object)) { $targetProjection[$targetName] = $targets[$targetName] }; $regressions = Get-RegressionEvidence $census $sourceSet; $sourceScan = [ordered]@{ file_set_kind = 'git_cached_plus_nonignored_untracked_rust'; provenance = 'content_bound_path_plus_bytes'; cached_rust_file_count = $sourceSet.Cached.Count; nonignored_untracked_rust_file_count = $sourceSet.Untracked.Count; union_rust_file_count = $sourceSet.Union.Count; nonignored_untracked_rust_files = @($sourceSet.Untracked); rust_files = @($sourceSet.Union); rust_file_bindings = @($sourceSet.Bindings); rust_files_sha256 = $sourceSet.Digest; grammar_file_set = 'direct-read-source-union'; grammar = $grammar; motif_hit_counts = $census.HitCounts; motif_row_counts = $census.RowCounts; hit_count = $census.HitCount; row_count = $census.RowCount; completeness_statement = 'COMPLETE_CURRENT_FILE_SET_DECLARED_GRAMMAR_ONLY'; semantic_exhaustiveness_claim = $false; target_map = $targetProjection; regression_fixtures = $regressions }
    $proof = Get-CanonicalWriteProof $sourceSet $roots; $reviewAbsolute = Join-Path $RepoRoot $MechanismReviewPath; if (-not (Test-Path -LiteralPath $reviewAbsolute -PathType Leaf)) { throw "mechanism review missing: $MechanismReviewPath" }
    return [pscustomobject]@{ schema_version = $SchemaVersion; authority_status = 'EVIDENCE_ONLY'; work_item_id = 'W1-05'; cargo_metadata_sha256 = Get-TextSha256 $metadata.Canonical; mechanism_review = [ordered]@{ path = $MechanismReviewPath; sha256 = Get-Sha256 $reviewAbsolute; status = 'LINKED' }; contours = [ordered]@{ A = $ContourA; B = $ContourB }; cutover_decision = [ordered]@{ status = 'PENDING_ROOT'; owner = 'ROOT'; selected = $null; allowed_options = @('A','B','C') }; source_scan = $sourceScan; rows = $rows; canonical_write_proof = $proof; summary = $summary; proof_ceiling = 'Complete current cached plus non-ignored-untracked Rust file-set census for the declared grammar plus Cargo metadata, content-bound by path and current bytes. This is not a semantic/runtime call graph and does not prove liveness, authenticated invocation, signed bundle, parity, or cutover.'; external_routing_evidence = @('ses_fccf606fcffeCw3AOMDCG4YIiu','ses_fcc6cdf37ffeO3ylWsg4uFG2ct') }
}

function Get-JsonBytes($Value) {
    return [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 100) + "`n")
}

function Get-ResultProjection($Inventory) {
    $rows = @($Inventory.rows)
    $scan = $Inventory.source_scan
    $summary = $Inventory.summary
    $proof = $Inventory.canonical_write_proof
    return [ordered]@{
        disposition = 'IMPLEMENTED'
        contour_a = @($Inventory.contours.A)
        contour_b = @($Inventory.contours.B)
        rows = [int]$summary.row_count
        cargo_direct_edges = [ordered]@{
            A_TO_B = [ordered]@{
                present = @($rows | Where-Object { $_.edge_class -eq 'cargo_dependency' -and $_.direction -eq 'A_TO_B' -and $_.status -eq 'present' }).Count
                absent = @($rows | Where-Object { $_.edge_class -eq 'cargo_dependency' -and $_.direction -eq 'A_TO_B' -and $_.status -eq 'absent' }).Count
            }
            B_TO_A = [ordered]@{
                present = @($rows | Where-Object { $_.edge_class -eq 'cargo_dependency' -and $_.direction -eq 'B_TO_A' -and $_.status -eq 'present' }).Count
                absent = @($rows | Where-Object { $_.edge_class -eq 'cargo_dependency' -and $_.direction -eq 'B_TO_A' -and $_.status -eq 'absent' }).Count
            }
        }
        source_scan = [ordered]@{
            file_set_kind = $scan.file_set_kind
            grammar_file_set = $scan.grammar_file_set
            cached_rust_file_count = [int]$scan.cached_rust_file_count
            nonignored_untracked_rust_file_count = [int]$scan.nonignored_untracked_rust_file_count
            union_rust_file_count = [int]$scan.union_rust_file_count
            grammar_motifs = @($scan.grammar).Count
            hit_count = $scan.hit_count
            row_count = [int]$scan.row_count
            motif_hit_counts = $scan.motif_hit_counts
            motif_row_counts = $scan.motif_row_counts
            provenance = $scan.provenance
            rust_files_sha256 = $scan.rust_files_sha256
        }
        edge_class_counts = $summary.edge_class_counts
        status_counts = $summary.status_counts
        semantic_counts = [ordered]@{
            negative_observation_non_join = [int]$summary.negative_observation_non_join
            process_launch_observation = [int]$summary.process_launch_observation
            process_wrapper_observation = [int]$summary.process_wrapper_observation
            runtime_ipc_observation = [int]$summary.runtime_ipc_observation
            launch_control_observation = [int]$summary.launch_control_observation
            schema_observation = [int]$summary.schema_observation
            state_write_unknown = [int]$summary.state_write_unknown
            unknown_process_target = [int]$summary.unknown_process_target
            unknown_ipc_target = [int]$summary.unknown_ipc_target
            unknown_launch_target = [int]$summary.unknown_launch_target
            present = [int]$summary.status_counts.present
            absent = [int]$summary.status_counts.absent
            unknown = [int]$summary.status_counts.unknown
        }
        regression_fixtures = @($scan.regression_fixtures)
        canonical_write_proof = [ordered]@{
            symbol = $proof.symbol
            source_file_set_kind = $proof.source_file_set_kind
            rust_file_count = [int]$proof.rust_file_count
            definition_count = [int]$proof.definition_count
            caller_count = [int]$proof.caller_count
            definition = "$($proof.definitions[0].source_path):$($proof.definitions[0].source_line)"
            status = $proof.status
        }
        inventory_summary_sha256 = Get-ObjectDigest $summary
        source_scan_sha256 = Get-ObjectDigest $scan
        canonical_write_proof_sha256 = Get-ObjectDigest $proof
        regression_fixtures_sha256 = Get-ObjectDigest $scan.regression_fixtures
        cutover_decision = 'PENDING_ROOT'
    }
}

function Get-ResultBytes($Inventory, [byte[]]$InventoryBytes) {
    if ($Inventory.PSObject.Properties.Name -contains 'source_revision') { throw 'revision provenance is forbidden; use content-bound source evidence' }

    $inventoryPath = 'swarm/inventory/contour-cut.json'
    $generatorRel = 'scripts/gen-contour-cut.ps1'
    $verifierRel = 'scripts/verify-contour-cut.ps1'
    $authorityPath = 'swarm/decisions/W1-RESULT-ENVELOPE-PROGRAM-REVISION-v1.3.md'
    $inventoryHash = Get-BytesSha256 $InventoryBytes
    $generatorHash = Get-Sha256 (Join-Path $RepoRoot $generatorRel)
    $verifierHash = Get-Sha256 (Join-Path $RepoRoot $verifierRel)
    $mechanismHash = Get-Sha256 (Join-Path $RepoRoot $MechanismReviewPath)
    $authorityAbsolute = Join-Path $RepoRoot $authorityPath
    if (-not (Test-Path -LiteralPath $authorityAbsolute -PathType Leaf)) { throw "program authority missing: $authorityPath" }
    $authorityHash = Get-Sha256 $authorityAbsolute
    $scan = $Inventory.source_scan
    $summary = $Inventory.summary
    $proof = $Inventory.canonical_write_proof
    $fixtures = @{}; foreach ($fixture in @($scan.regression_fixtures)) { $fixtures[[string]$fixture.id] = $fixture }
    foreach ($id in @('dynamic-command-program','dynamic-command-executable','suspended-job-spawn','suspended-job-spawn-with-limits','dynamic-governor-command','bootstrap-brief')) { if (-not $fixtures.ContainsKey($id)) { throw "result regression fixture missing: $id" } }

    $findings = @(
        "The full-from-zero mechanism scans the deterministic union of $($scan.cached_rust_file_count) Git-cached and $($scan.nonignored_untracked_rust_file_count) non-ignored-untracked Rust files by direct file reads; it claims completeness only for the $(@($scan.grammar).Count) declared motifs over that current file set, never semantic/runtime exhaustiveness.",
        'Dynamic and qualified process constructors are emitted with exact local target resolution when available and UNKNOWN_PROCESS_TARGET otherwise. Windows suspended-job wrappers, process-executor symbols, Windows CreateProcess APIs, Tokio/Std/qualified constructors, and named-pipe client/server/transport/authentication operations are represented.',
        "Regression rows include $($fixtures['dynamic-command-program'].path):$($fixtures['dynamic-command-program'].line), $($fixtures['dynamic-command-executable'].path):$($fixtures['dynamic-command-executable'].line), $($fixtures['suspended-job-spawn'].path):$($fixtures['suspended-job-spawn'].line), $($fixtures['suspended-job-spawn-with-limits'].path):$($fixtures['suspended-job-spawn-with-limits'].line), $($fixtures['dynamic-governor-command'].path):$($fixtures['dynamic-governor-command'].line), and the cached $($fixtures['bootstrap-brief'].path) fixture.",
        'The bins/eliot/src/main.rs:604 legacy eliot-governor.exe coexistence check is negative_observation/non_join, not a launch/control join. Other legacy/process-state observations are likewise non-join evidence.',
        'schema_version remains schema_observation only; write_receipt/write_receipt_by_id remains unknown state-write evidence; GovernorConfig roles remain import/parse/type_reference and never imply runtime join.',
        "Exact §5.1 proof over the cached plus non-ignored-untracked Rust union is one commit_canonical definition at $($proof.definitions[0].source_path):$($proof.definitions[0].source_line) and zero callers; the independent verifier recomputes anchors and tamper-tests this proof.",
        'No cutover A, B, or C is selected; §5.2 decision authority remains Root.'
    )
    $verification = @(
        'pwsh -NoProfile -File scripts/gen-contour-cut.ps1 -SelfTest: PASS',
        "pwsh -NoProfile -File scripts/gen-contour-cut.ps1: PASS ($($summary.row_count) rows; $($scan.union_rust_file_count) Rust files)",
        'pwsh -NoProfile -File scripts/gen-contour-cut.ps1 -Check: PASS',
        'pwsh -NoProfile -File scripts/verify-contour-cut.ps1 -SelfTest: PASS (omitted edge, source-stage, source/result family envelope, duplicate, negative, and §5.1 tamper checks)',
        'pwsh -NoProfile -File scripts/verify-contour-cut.ps1: PASS (declared grammar, Cargo edges, source anchors/digests, §5.1 proof, and full result envelope independently recomputed)',
        'git diff --check -- scripts/gen-contour-cut.ps1 scripts/verify-contour-cut.ps1 swarm/inventory/contour-cut.json swarm/results/W1-05.json: PASS'
    )
    $limitations = @(
        'The source census is complete only for the declared grammar over the current cached plus non-ignored-untracked Rust union; it is not a semantic/runtime call graph.',
        'Dynamic targets and IPC endpoints remain UNKNOWN unless exact local evidence resolves them; package names, imports, wrappers, and symbols do not imply a runtime connection.',
        'Proof ceiling excludes runtime liveness, authenticated invocation traces, signed bundle validation, parity, Product Pulse, and cutover selection.',
        'Git category and concurrent-worktree observations are non-authoritative; this envelope binds current source bytes, explicit policy constants, and artifact hashes only.'
    )
    $mechanism = [ordered]@{ path = $MechanismReviewPath; sha256 = $mechanismHash; status = 'LINKED' }
    $authority = [ordered]@{ path = $authorityPath; sha256 = $authorityHash }
    $artifacts = [ordered]@{
        inventory = [ordered]@{ path = $inventoryPath; sha256 = $inventoryHash }
        generator = [ordered]@{ path = $generatorRel; sha256 = $generatorHash }
        verifier = [ordered]@{ path = $verifierRel; sha256 = $verifierHash }
        generator_sha256 = $generatorHash
        verifier_sha256 = $verifierHash
        inventory_sha256 = $inventoryHash
    }
    $structured = [ordered]@{
        schema_version = $ResultSchemaVersion
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-05'
        disposition = 'EVIDENCE_ONLY'
        artifacts = $artifacts
        evidence = @('content-bound path plus byte source census','observational Git category fields','full-envelope and per-family tamper verification')
        discriminator_before = [ordered]@{ status = 'TEMPLATE_CONTROLLED_RESULT_REJECTED'; reason = 'Generic evidence fields were inherited from the previous result file' }
        discriminator_after = [ordered]@{ status = 'FULL_FROM_ZERO_RESULT'; content_bound = $true; categories_observational = $true }
        uncertainty = 'Static declared-grammar census only; no runtime liveness or cutover authority.'
        unresolved_questions = @('Runtime invocation and authenticated contour join remain unproven','Root cutover decision remains pending')
        proposed_effects = @('Preserve EVIDENCE_ONLY','Do not select cutover')
        evidence_lineage = [ordered]@{
            program_authority = [ordered]@{ path = $authorityPath; sha256 = $authorityHash }
            challenge = [ordered]@{ path = $MechanismReviewPath; sha256 = $mechanismHash }
            inventory = [ordered]@{ path = $inventoryPath; sha256 = $inventoryHash }
        }
        observed_worktree_state = 'CONTENT_BOUND_SOURCE_UNION; GIT_CATEGORIES_OBSERVATIONAL_ONLY'
        mechanism_review = $mechanism
        program_authority = $authority
        changed_files = @($generatorRel,$verifierRel,$inventoryPath,'swarm/results/W1-05.json',$MechanismReviewPath)
        result = Get-ResultProjection $Inventory
        findings = $findings
        verification = $verification
        limitations = $limitations
        external_routing_evidence = @('ses_fccf606fcffeCw3AOMDCG4YIiu','ses_fcc6cdf37ffeO3ylWsg4uFG2ct')
    }
    $wrapper = [ordered]@{
        schema_version = 'eliot.bootstrap-work-result.v1'
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-05'
        structured_result = $structured
    }
    return Get-JsonBytes $wrapper
}

function Assert-BytesEqual([string]$Path, [byte[]]$Expected, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Label missing: $Path" }
    if (-not [Linq.Enumerable]::SequenceEqual([IO.File]::ReadAllBytes($Path), $Expected)) { throw "$Label stale/non-deterministic: $Path" }
}

function Write-Atomic([string]$Path, [byte[]]$Bytes) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $temporary = Join-Path $parent ('.{0}.{1}.tmp' -f ([IO.Path]::GetFileName($Path)), [guid]::NewGuid().ToString('N'))
    try { [IO.File]::WriteAllBytes($temporary, $Bytes); Move-Item -LiteralPath $temporary -Destination $Path -Force }
    finally { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
}

function Invoke-SelfTest {
    $inventory = New-Inventory; Assert-Inventory $inventory
    $copy = $inventory | ConvertTo-Json -Depth 100 | ConvertFrom-Json; $discoverable = @($copy.rows | Where-Object id -like 'CENSUS-*'); if ($discoverable.Count -eq 0) { throw 'self-test requires source census rows' }; $copy.rows = @($copy.rows | Where-Object id -ne $discoverable[0].id); try { Assert-Inventory $copy; throw 'omitted discoverable edge accepted' } catch { if ($_.Exception.Message -notmatch 'omitted|row_count|inventory') { throw } }
    $copy = $inventory | ConvertTo-Json -Depth 100 | ConvertFrom-Json; $copy.cutover_decision.selected = 'A'; try { Assert-Inventory $copy; throw 'cutover tamper accepted' } catch { if ($_.Exception.Message -notmatch 'cutover') { throw } }
    $copy = $inventory | ConvertTo-Json -Depth 100 | ConvertFrom-Json; $copy.canonical_write_proof.caller_count = 1; try { Assert-Inventory $copy; throw 'commit caller tamper accepted' } catch { if ($_.Exception.Message -notmatch 'commit_canonical|proof') { throw } }
    $fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('eliot-w1-05-source-fixture-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'cached') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $fixtureRoot 'untracked') -Force | Out-Null
    try {
        $cachedPath = Join-Path $fixtureRoot 'cached/cached.rs'
        $untrackedPath = Join-Path $fixtureRoot 'untracked/untracked.rs'
        [IO.File]::WriteAllText($cachedPath, 'fn cached_fixture() {}' + "`n", [Text.UTF8Encoding]::new($false))
        [IO.File]::WriteAllText($untrackedPath, 'fn untracked_fixture() {}' + "`n", [Text.UTF8Encoding]::new($false))
        $synthetic = New-RustSourceSet @('cached/cached.rs') @('untracked/untracked.rs') $fixtureRoot
        if ($synthetic.Cached.Count -ne 1 -or $synthetic.Untracked.Count -ne 1 -or $synthetic.Union.Count -ne 2) { throw 'synthetic source-union fixture counts drifted' }
        if ($synthetic.Kind['cached/cached.rs'] -cne 'cached' -or $synthetic.Kind['untracked/untracked.rs'] -cne 'nonignored_untracked') { throw 'synthetic source-union classification drifted' }
        [IO.File]::WriteAllText((Join-Path $fixtureRoot 'untracked/extra.rs'), 'fn extra_fixture() {}' + "`n", [Text.UTF8Encoding]::new($false))
        $added = New-RustSourceSet @('cached/cached.rs') @('untracked/untracked.rs', 'untracked/extra.rs') $fixtureRoot
        if ($added.Union.Count -ne 3 -or $added.Untracked.Count -ne 2) { throw 'synthetic untracked add fixture failed' }
        $removed = New-RustSourceSet @('cached/cached.rs') @('untracked/untracked.rs') $fixtureRoot
        if ($removed.Union.Count -ne 2 -or $removed.Untracked.Count -ne 1) { throw 'synthetic untracked remove fixture failed' }
        $moved = New-RustSourceSet @('cached/cached.rs', 'untracked/untracked.rs') @() $fixtureRoot
        if ($moved.Cached.Count -ne 2 -or $moved.Untracked.Count -ne 0 -or $moved.Union.Count -ne 2 -or $moved.Kind['untracked/untracked.rs'] -cne 'cached') { throw 'synthetic stage transition fixture failed' }
        if ((@($moved.Bindings | Where-Object path -eq 'untracked/untracked.rs')[0].sha256) -cne (@($synthetic.Bindings | Where-Object path -eq 'untracked/untracked.rs')[0].sha256)) { throw 'synthetic stage transition changed content binding' }
        $before = @($synthetic.Bindings | Where-Object path -eq 'untracked/untracked.rs')[0].sha256
        [IO.File]::WriteAllText($untrackedPath, 'fn untracked_fixture_tampered() {}' + "`n", [Text.UTF8Encoding]::new($false))
        $tampered = New-RustSourceSet @('cached/cached.rs') @('untracked/untracked.rs') $fixtureRoot
        if ($tampered.Bindings[1].sha256 -ceq $before) { throw 'synthetic untracked content tamper accepted' }
    } finally { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Output "SELFTEST PASS: direct-read union, omitted-edge, synthetic cached+untracked fixture, commit proof, and cutover tamper checks ($($inventory.summary.row_count) rows)"
}

if ($SelfTest) {
    if ($Check -or $InventoryOnly -or $PSBoundParameters.ContainsKey('OutputPath') -or $PSBoundParameters.ContainsKey('ResultPath')) { throw '-SelfTest cannot combine with generation/check output options' }
    Invoke-SelfTest
    exit 0
}
if ($InventoryOnly -and $PSBoundParameters.ContainsKey('ResultPath')) { throw '-InventoryOnly cannot combine with -ResultPath' }
$customOutput = $PSBoundParameters.ContainsKey('OutputPath')
$customResult = $PSBoundParameters.ContainsKey('ResultPath')
if (-not $InventoryOnly -and $customOutput -ne $customResult) { throw 'custom -OutputPath and -ResultPath must be supplied together unless -InventoryOnly is used' }
if ($Check -and ($customOutput -or $customResult)) { throw '-Check validates canonical output and result paths only' }
$target = if ($customOutput) { [IO.Path]::GetFullPath($OutputPath) } else { $DefaultOutputPath }
$resultTarget = if ($InventoryOnly) { $null } elseif ($customResult) { [IO.Path]::GetFullPath($ResultPath) } else { $DefaultResultPath }
$inventory = New-Inventory
Assert-Inventory $inventory
$inventoryBytes = Get-JsonBytes $inventory
$resultBytes = if ($InventoryOnly) { $null } else { Get-ResultBytes $inventory $inventoryBytes }
if ($Check) {
    Assert-BytesEqual $target $inventoryBytes 'generated inventory'
    Assert-BytesEqual $resultTarget $resultBytes 'generated result envelope'
    Write-Output "CHECK PASS: $target and $resultTarget ($($inventory.summary.row_count) rows; $($inventory.source_scan.union_rust_file_count) Rust files)"
    exit 0
}
Write-Atomic $target $inventoryBytes
if (-not $InventoryOnly) { Write-Atomic $resultTarget $resultBytes }
Write-Output "GENERATED: $target$(if ($InventoryOnly) { '' } else { ' and ' + $resultTarget }) ($($inventory.summary.row_count) rows; $($inventory.source_scan.union_rust_file_count) Rust files)"
