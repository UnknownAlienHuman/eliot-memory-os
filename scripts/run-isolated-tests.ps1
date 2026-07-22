[CmdletBinding()]
param(
    [switch]$McpOnly,
    [string]$TestPackage = 'eliot-app',
    [string]$TestBinary,
    [string]$BinTarget,
    [string]$TestName,
    [string]$TestFilterExpression,
    [ValidateRange(1, 7200)]
    [int]$TestTimeoutSeconds = 3600,
    [ValidateSet('none', 'success', 'failure', 'retained_handle')]
    [string]$HarnessProbe = 'none',
    [switch]$InjectFailureAfterSecretSetup,
    [string]$EvidenceLogPath,
    [string]$SurrealExecutable = $env:ELIOT_SURREAL_EXE
)

$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$surrealCommandName = if ([string]::IsNullOrWhiteSpace($SurrealExecutable)) { 'surreal' } else { $SurrealExecutable }
$surrealCommand = Get-Command $surrealCommandName -CommandType Application -ErrorAction Stop
$surrealExePath = [IO.Path]::GetFullPath($surrealCommand.Source)
if (-not (Test-Path -LiteralPath $surrealExePath -PathType Leaf)) {
    throw "SurrealDB executable was not resolved to a file: $surrealExePath"
}
$surrealConfigPath = $surrealExePath.Replace('\', '/')
$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$runId = [guid]::NewGuid().ToString('N')
$ownedRoot = [IO.Path]::GetFullPath((Join-Path $tempBase ("eliot-governor-workspace-tests-{0}-{1}" -f $PID, $runId)))
$ownedPrefix = $ownedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$lower = $ownedRoot.ToLowerInvariant()

function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string]$Path)

    $entry = Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force
    while ($null -ne $entry) {
        if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "owned test path crosses a reparse point: $($entry.FullName)"
        }
        $entry = $entry.Parent
    }
}

function Protect-CurrentUserOnlyAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Directory
    )

    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrWhiteSpace($sid) -or -not $sid.StartsWith('S-', [StringComparison]::Ordinal)) {
        throw 'could not resolve the current Windows SID for the owned test secret ACL'
    }
    $userGrant = if ($Directory) { "*$($sid):(OI)(CI)F" } else { "*$($sid):F" }
    $systemGrant = if ($Directory) { '*S-1-5-18:(OI)(CI)F' } else { '*S-1-5-18:F' }
    & icacls.exe $Path '/inheritance:r' '/grant:r' $userGrant '/grant:r' $systemGrant `
        '/remove:g' '*S-1-1-0' '*S-1-5-11' '*S-1-5-32-545' 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "failed to restrict the owned test secret ACL: $Path"
    }
}

function Remove-ExactOwnedSecretRoot {
    param(
        [Parameter(Mandatory)][string]$OwnedRoot,
        [Parameter(Mandatory)][string]$ExpectedTestsRoot,
        [Parameter(Mandatory)][string]$ExpectedRunId
    )

    $resolvedOwnedRoot = [IO.Path]::GetFullPath($OwnedRoot)
    if (-not (Test-Path -LiteralPath $resolvedOwnedRoot)) {
        return
    }
    $resolvedTestsRoot = [IO.Path]::GetFullPath($ExpectedTestsRoot)
    $testsPrefix = $resolvedTestsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $resolvedOwnedRoot.StartsWith($testsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedOwnedRoot) -cne $ExpectedRunId -or
        [IO.Path]::GetFullPath((Split-Path $resolvedOwnedRoot -Parent)) -ine $resolvedTestsRoot) {
        throw "owned test secret cleanup escaped its exact run boundary: $resolvedOwnedRoot"
    }
    Assert-NoReparsePoint $resolvedOwnedRoot

    $marker = Join-Path $resolvedOwnedRoot '.eliot-test-owner.json'
    $secrets = Join-Path $resolvedOwnedRoot 'secrets'
    $password = Join-Path $secrets 'surreal_root_password.txt'
    if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or
        -not (Test-Path -LiteralPath $secrets -PathType Container) -or
        -not (Test-Path -LiteralPath $password -PathType Leaf)) {
        throw "owned test secret root has an incomplete ownership layout: $resolvedOwnedRoot"
    }
    $recordedOwner = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
    if ($recordedOwner.schema_version -cne 'eliot-owned-test-secret-root-v1' -or
        $recordedOwner.run_id -cne $ExpectedRunId -or
        [IO.Path]::GetFullPath([string]$recordedOwner.owned_root) -ine $resolvedOwnedRoot) {
        throw "owned test secret root failed exact ownership verification: $resolvedOwnedRoot"
    }

    $rootEntries = @(Get-ChildItem -LiteralPath $resolvedOwnedRoot -Force)
    $secretEntries = @(Get-ChildItem -LiteralPath $secrets -Force)
    if ($rootEntries.Count -ne 2 -or
        @($rootEntries.Name | Where-Object { $_ -notin @('.eliot-test-owner.json', 'secrets') }).Count -ne 0 -or
        $secretEntries.Count -ne 1 -or
        $secretEntries[0].Name -cne 'surreal_root_password.txt' -or
        ($rootEntries + $secretEntries).Where({
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -ne 0) {
        throw "owned test secret root contains an unexpected entry; preserving it for inspection: $resolvedOwnedRoot"
    }

    Remove-Item -LiteralPath $password -Force
    Remove-Item -LiteralPath $marker -Force
    Remove-Item -LiteralPath $secrets -Force
    Remove-Item -LiteralPath $resolvedOwnedRoot -Force
}

function Stop-ExactOwnedProcess {
    param(
        [Parameter(Mandatory)][Diagnostics.Process]$Process,
        [Parameter(Mandatory)][string]$Role,
        [AllowEmptyCollection()]
        [Parameter(Mandatory)][Collections.Generic.List[string]]$Failures,
        [AllowEmptyCollection()]
        [Parameter(Mandatory)][Collections.Generic.List[object]]$Receipts
    )

    $receipt = [ordered]@{
        role = $Role
        pid = $Process.Id
        graceful_requested = $false
        forced = $false
        stopped = $false
    }
    try {
        $Process.Refresh()
        if (-not $Process.HasExited) {
            $receipt.graceful_requested = $Process.CloseMainWindow()
            if ($receipt.graceful_requested) {
                $Process.WaitForExit(2000) | Out-Null
                $Process.Refresh()
            }
        }
        if (-not $Process.HasExited) {
            Stop-Process -Id $Process.Id -Force -ErrorAction Stop
            $receipt.forced = $true
            if (-not $Process.WaitForExit(10000)) {
                throw "owned process did not exit within the bounded fallback: role=$Role pid=$($Process.Id)"
            }
        }
        $receipt.stopped = $true
    }
    catch {
        $Failures.Add("owned_process_cleanup_failed:$Role")
    }
    $Receipts.Add([pscustomobject]$receipt)
}

function Get-ExactRunOwnedProcesses {
    param(
        [Parameter(Mandatory)][string]$RunId,
        [Parameter(Mandatory)][string]$OwnedRoot,
        [Parameter(Mandatory)][int[]]$ExcludedPids
    )

    $normalizedRoot = $OwnedRoot.Replace('/', '\')
    @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -notin $ExcludedPids -and
        -not [string]::IsNullOrWhiteSpace($_.CommandLine) -and
        ($_.CommandLine.Contains($RunId, [StringComparison]::OrdinalIgnoreCase) -or
            $_.CommandLine.Replace('/', '\').Contains($normalizedRoot, [StringComparison]::OrdinalIgnoreCase))
    })
}

function Merge-ProcessLogs {
    param(
        [Parameter(Mandatory)][string]$StdoutPath,
        [Parameter(Mandatory)][string]$StderrPath,
        [Parameter(Mandatory)][string]$Destination
    )

    $writer = [IO.StreamWriter]::new($Destination, $false, [Text.UTF8Encoding]::new($false))
    try {
        foreach ($path in @($StdoutPath, $StderrPath)) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $reader = [IO.StreamReader]::new($path, [Text.UTF8Encoding]::new($false), $true)
                try {
                    $writer.Write($reader.ReadToEnd())
                }
                finally {
                    $reader.Dispose()
                }
            }
        }
    }
    finally {
        $writer.Dispose()
    }
}

function Read-NextestSummary {
    param([Parameter(Mandatory)][string]$LogPath)

    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
        return $null
    }
    $summaryLine = Get-Content -LiteralPath $LogPath | Where-Object {
        $_ -match '^\s*Summary\s+\['
    } | Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace($summaryLine)) {
        return $null
    }
    $testsRun = if ($summaryLine -match '(?<count>\d+)\s+tests? run:') { [int]$Matches.count } else { $null }
    $passed = if ($summaryLine -match '(?<count>\d+)\s+passed') { [int]$Matches.count } else { 0 }
    $failed = if ($summaryLine -match '(?<count>\d+)\s+failed') { [int]$Matches.count } else { 0 }
    $skipped = if ($summaryLine -match '(?<count>\d+)\s+skipped') { [int]$Matches.count } else { 0 }
    [pscustomobject]@{
        text = $summaryLine.Trim()
        tests_run = $testsRun
        passed = $passed
        failed = $failed
        skipped = $skipped
    }
}

if (-not $ownedPrefix.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase)) {
    throw "isolated test root must descend from TEMP: $ownedRoot"
}
if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) {
    throw "isolated test root crossed a forbidden host boundary: $ownedRoot"
}

$ambientLocalAppData = [Environment]::GetEnvironmentVariable('LOCALAPPDATA', 'Process')
if ([string]::IsNullOrWhiteSpace($ambientLocalAppData)) {
    throw 'LOCALAPPDATA is required for the isolated test secret root'
}
$ambientLocalAppData = [IO.Path]::GetFullPath($ambientLocalAppData)
if (-not [IO.Path]::IsPathFullyQualified($ambientLocalAppData)) {
    throw 'LOCALAPPDATA must be an absolute Windows path'
}
$secretTestsRoot = [IO.Path]::GetFullPath((Join-Path $ambientLocalAppData 'Eliot\tests'))
$secretOwnedRoot = [IO.Path]::GetFullPath((Join-Path $secretTestsRoot $runId))
$secretTestsPrefix = $secretTestsRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $secretOwnedRoot.StartsWith($secretTestsPrefix, [StringComparison]::OrdinalIgnoreCase) -or
    [IO.Path]::GetFileName($secretOwnedRoot) -cne $runId -or
    [IO.Path]::GetFullPath((Split-Path $secretOwnedRoot -Parent)) -ine $secretTestsRoot) {
    throw "owned test secret root escaped its exact run boundary: $secretOwnedRoot"
}
$secretRoot = Join-Path $secretOwnedRoot 'secrets'
$passwordPath = Join-Path $secretRoot 'surreal_root_password.txt'
$passwordConfigPath = "%LOCALAPPDATA%/Eliot/tests/$runId/secrets/surreal_root_password.txt"
$ownerMarkerPath = Join-Path $secretOwnedRoot '.eliot-test-owner.json'

$configPath = Join-Path $ownedRoot 'config\governor.toml'
$storagePath = (Join-Path $ownedRoot 'surrealdb-rocks').Replace('\', '/')
$walPath = (Join-Path $ownedRoot 'control\control.redb').Replace('\', '/')
$blobPath = (Join-Path $ownedRoot 'blobs').Replace('\', '/')
$surqlPath = (Join-Path $repo 'crates\eliot-store\src\surql').Replace('\', '/')
$migrationsPath = (Join-Path $repo 'crates\eliot-store\migrations').Replace('\', '/')
$pidPath = Join-Path $ownedRoot 'tmp\owned-surreal.pid'
$nextestLog = Join-Path $ownedRoot 'reports\nextest-events.log'
$nextestStdout = Join-Path $ownedRoot 'reports\nextest.stdout.log'
$nextestStderr = Join-Path $ownedRoot 'reports\nextest.stderr.log'
$surrealStdout = Join-Path $ownedRoot 'reports\surreal.stdout.log'
$surrealStderr = Join-Path $ownedRoot 'reports\surreal.stderr.log'
$surrealGuardianStdout = Join-Path $ownedRoot 'reports\surreal-guardian.stdout.jsonl'
$surrealGuardianStderr = Join-Path $ownedRoot 'reports\surreal-guardian.stderr.log'
$surrealStopPath = Join-Path $ownedRoot 'tmp\stop-surreal.guardian'
$guardianBuildStdout = Join-Path $ownedRoot 'reports\guardian-build.stdout.log'
$guardianBuildStderr = Join-Path $ownedRoot 'reports\guardian-build.stderr.log'
$guardianStdout = Join-Path $ownedRoot 'reports\guardian.stdout.jsonl'
$guardianStderr = Join-Path $ownedRoot 'reports\guardian.stderr.log'
$guardianExe = Join-Path $repo 'target\debug\eliot-process-guardian.exe'
$probeScript = Join-Path $ownedRoot 'tmp\wrapper-probe.ps1'
$portListener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$portListener.Start()
$port = ([Net.IPEndPoint]$portListener.LocalEndpoint).Port
$portListener.Stop()

$ambientUserRoots = @{}
foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME')) {
    $ambientUserRoots[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$savedEnvironment = @{}
foreach ($name in @(
    'ELIOT_DISABLE_REAL_PROVIDER',
    'ELIOT_GOVERNOR_CONFIG',
    'ELIOT_TEST_SURREAL_BIND',
    'ELIOT_TEST_SURREAL_ENDPOINT',
    'ELIOT_TEST_SURREAL_PASSWORD_FILE',
    'ELIOT_TEST_SURREAL_STORAGE',
    'ELIOT_SURREAL_EXE',
    'SURREAL_USER',
    'SURREAL_PASS'
)) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

$testExit = 1
$childExit = $null
$surrealGuardianProcess = $null
$surrealGuardianOutputTask = $null
$surrealGuardianErrorTask = $null
$surrealGuardianStatus = $null
$guardianBuildProcess = $null
$guardianProcess = $null
$guardianStatus = $null
$nextestTimedOut = $false
$nextestSummary = $null
$nextestLogHash = $null
$cleanupFailures = [Collections.Generic.List[string]]::new()
$cleanupPendingPaths = [Collections.Generic.List[string]]::new()
$processReceipts = [Collections.Generic.List[object]]::new()
$boundedFailureExercised = $false
$secretReparseChecked = $false
$secretAclRestricted = $false
$terminalError = $null
try {
    New-Item -ItemType Directory -Force `
        (Split-Path $configPath), `
        (Split-Path $nextestLog), `
        (Split-Path $probeScript), `
        $secretRoot | Out-Null
    Assert-NoReparsePoint $secretOwnedRoot
    $secretReparseChecked = $true
    Protect-CurrentUserOnlyAcl $secretOwnedRoot -Directory
    $ownerMarker = [ordered]@{
        schema_version = 'eliot-owned-test-secret-root-v1'
        run_id = $runId
        owned_root = $secretOwnedRoot
    }
    [IO.File]::WriteAllText($ownerMarkerPath, ($ownerMarker | ConvertTo-Json -Compress))
    $password = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    [IO.File]::Create($passwordPath).Dispose()
    Protect-CurrentUserOnlyAcl $passwordPath
    [IO.File]::WriteAllText($passwordPath, $password)
    $secretAclRestricted = $true
    if ($InjectFailureAfterSecretSetup) {
        throw 'injected bounded harness failure after secret setup'
    }
    $config = @"
schema_version = "1"

[service]
service_name = "EliotGovernorWorkspaceTests"
instance_id = "isolated-workspace-tests"

[db]
mode = "surreal_rpc_server"

[db.surreal]
exe = "$surrealConfigPath"
bind = "127.0.0.1:$port"
endpoint = "ws://127.0.0.1:$port/rpc"
storage = "rocksdb:$storagePath"
ns = "eliot"
db = "system"
user = "root"
credential_provider = "legacy_password_file"
credential_id = "test-only/isolated-workspace"
password_file = "$passwordConfigPath"
log_level = "warn"
query_timeout_ms = 15000
transaction_timeout_ms = 15000
startup_timeout_ms = 20000
restart_backoff_ms = 200
max_restart_backoff_ms = 2000

[db.surreal.capabilities]
deny_all = true
allow_funcs = ["array", "string", "time", "type", "math", "vector", "search"]
allow_net = []
allow_scripting = false
allow_guests = false

[control_wal]
path = "$walPath"

[blob_store]
root = "$blobPath"

[store]
surql_dir = "$surqlPath"
migrations_dir = "$migrationsPath"
"@
    [IO.File]::WriteAllText($configPath, $config)

    $env:ELIOT_DISABLE_REAL_PROVIDER = '1'
    $env:ELIOT_TEST_ALLOW_LEGACY_OPERATOR_CURSOR_KEY_FILE = '1'
    $env:ELIOT_GOVERNOR_CONFIG = $configPath
    $env:ELIOT_TEST_SURREAL_BIND = "127.0.0.1:$port"
    $env:ELIOT_TEST_SURREAL_ENDPOINT = "ws://127.0.0.1:$port/rpc"
    $env:ELIOT_TEST_SURREAL_PASSWORD_FILE = $passwordConfigPath
    $env:ELIOT_TEST_SURREAL_STORAGE = "rocksdb:$storagePath"
    $env:ELIOT_SURREAL_EXE = $surrealExePath
    $env:SURREAL_USER = 'root'
    $env:SURREAL_PASS = $password

    $guardianBuildProcess = Start-Process -FilePath 'cargo.exe' -ArgumentList @(
        'build', '--offline', '-p', 'eliot-windows-ipc', '--bin', 'eliot-process-guardian'
    ) -WorkingDirectory $repo -RedirectStandardOutput $guardianBuildStdout `
        -RedirectStandardError $guardianBuildStderr -PassThru -WindowStyle Hidden
    if (-not $guardianBuildProcess.WaitForExit(300000)) {
        Stop-ExactOwnedProcess $guardianBuildProcess 'guardian_build' $cleanupFailures $processReceipts
        $guardianBuildProcess = $null
        throw 'native process guardian build exceeded its five-minute bound'
    }
    if ($guardianBuildProcess.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $guardianExe -PathType Leaf)) {
        throw "native process guardian build failed: $($guardianBuildProcess.ExitCode)"
    }

    New-Item -ItemType Directory -Force (Split-Path $pidPath) | Out-Null
    $surrealGuardianInfo = [Diagnostics.ProcessStartInfo]::new()
    $surrealGuardianInfo.FileName = $guardianExe
    $surrealGuardianInfo.WorkingDirectory = $ownedRoot
    $surrealGuardianInfo.UseShellExecute = $false
    $surrealGuardianInfo.CreateNoWindow = $true
    $surrealGuardianInfo.RedirectStandardOutput = $true
    $surrealGuardianInfo.RedirectStandardError = $true
    $surrealGuardianArguments = @(
        '--cwd', $ownedRoot,
        '--timeout-seconds', ([Math]::Min(7200, $TestTimeoutSeconds + 120)).ToString([Globalization.CultureInfo]::InvariantCulture),
        '--stdout', $surrealStdout,
        '--stderr', $surrealStderr,
        '--pid-file', $pidPath,
        '--stop-file', $surrealStopPath,
        '--', $surrealExePath,
        'start', '--bind', "127.0.0.1:$port", '--log', 'warn', '--deny-all',
        '--allow-funcs', 'array,string,time,type,math,vector,search', '--deny-net', '--',
        "rocksdb:$storagePath"
    )
    foreach ($argument in $surrealGuardianArguments) {
        $surrealGuardianInfo.ArgumentList.Add([string]$argument)
    }
    $surrealGuardianProcess = [Diagnostics.Process]::Start($surrealGuardianInfo)
    if ($null -eq $surrealGuardianProcess) {
        throw 'owned SurrealDB process guardian did not start'
    }
    $surrealGuardianOutputTask = $surrealGuardianProcess.StandardOutput.ReadToEndAsync()
    $surrealGuardianErrorTask = $surrealGuardianProcess.StandardError.ReadToEndAsync()
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    $ready = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($surrealGuardianProcess.HasExited) {
            throw "owned SurrealDB guardian exited before readiness: $($surrealGuardianProcess.ExitCode)"
        }
        Push-Location $ownedRoot
        try {
            "RETURN true;" | & $surrealExePath sql `
                --endpoint "ws://127.0.0.1:$port/rpc" `
                --namespace eliot `
                --database system `
                --json `
                --hide-welcome 2>$null | Out-Null
        }
        finally {
            Pop-Location
        }
        if ($LASTEXITCODE -eq 0) {
            $ready = $true
            break
        }
        Start-Sleep -Milliseconds 50
    }
    if (-not $ready) {
        throw "owned SurrealDB did not become ready on port $port"
    }
    $serverStarted = $true

    $nextestArgs = @(
        'nextest', 'run', '--offline', '--workspace', '--all-features',
        '--test-threads', '1', '--no-fail-fast', '--status-level', 'fail',
        '--final-status-level', 'fail', '--failure-output', 'immediate'
    )
    if ($McpOnly) {
        $nextestArgs += @('-p', 'eliot-app', '--test', 'mcp_protocol')
    }
    elseif ($TestBinary) {
        $nextestArgs += @('-p', $TestPackage, '--test', $TestBinary)
        if ($TestName) {
            $nextestArgs += $TestName
        }
    }
    elseif ($BinTarget) {
        $nextestArgs += @('-p', $TestPackage, '--bin', $BinTarget)
        if ($TestName) {
            $nextestArgs += $TestName
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($TestFilterExpression)) {
        $nextestArgs += @('-E', $TestFilterExpression)
    }

    $childProgram = (Get-Command 'cargo.exe' -ErrorAction Stop).Source
    $childArguments = $nextestArgs
    if ($HarnessProbe -ne 'none') {
        $childProgram = (Get-Command 'pwsh.exe' -ErrorAction Stop).Source
        $probeBody = switch ($HarnessProbe) {
            'success' {
                "[Console]::Out.WriteLine('    Summary [   0.001s] 1 tests run: 1 passed, 0 skipped')`r`nexit 0`r`n"
            }
            'failure' {
                "[Console]::Out.WriteLine('    Summary [   0.001s] 1 tests run: 0 passed, 1 failed, 0 skipped')`r`nexit 41`r`n"
            }
            'retained_handle' {
                @'
$info = [Diagnostics.ProcessStartInfo]::new()
$info.FileName = $env:ComSpec
$info.Arguments = '/D /C ping -n 120 127.0.0.1 >NUL'
$info.UseShellExecute = $false
$info.CreateNoWindow = $true
[Diagnostics.Process]::Start($info) | Out-Null
[Console]::Out.WriteLine('    Summary [   0.001s] 1 tests run: 0 passed, 1 failed, 0 skipped')
exit 42
'@
            }
        }
        [IO.File]::WriteAllText($probeScript, $probeBody, [Text.UTF8Encoding]::new($false))
        $childArguments = @('-NoProfile', '-NonInteractive', '-File', $probeScript)
    }

    $guardianInfo = [Diagnostics.ProcessStartInfo]::new()
    $guardianInfo.FileName = $guardianExe
    $guardianInfo.WorkingDirectory = $repo
    $guardianInfo.UseShellExecute = $false
    $guardianInfo.CreateNoWindow = $true
    $guardianInfo.RedirectStandardOutput = $true
    $guardianInfo.RedirectStandardError = $true
    foreach ($argument in @(
        '--cwd', $repo,
        '--timeout-seconds', $TestTimeoutSeconds.ToString([Globalization.CultureInfo]::InvariantCulture),
        '--stdout', $nextestStdout,
        '--stderr', $nextestStderr,
        '--', $childProgram
    ) + $childArguments) {
        $guardianInfo.ArgumentList.Add([string]$argument)
    }
    $guardianProcess = [Diagnostics.Process]::Start($guardianInfo)
    if ($null -eq $guardianProcess) {
        throw 'native process guardian did not start'
    }
    $guardianOutputTask = $guardianProcess.StandardOutput.ReadToEndAsync()
    $guardianErrorTask = $guardianProcess.StandardError.ReadToEndAsync()
    $guardianWaitMilliseconds = [Math]::Min(
        [int]::MaxValue,
        [int64]($TestTimeoutSeconds + 15) * 1000
    )
    if (-not $guardianProcess.WaitForExit([int]$guardianWaitMilliseconds)) {
        $nextestTimedOut = $true
        $terminalError = 'guardian_terminalization_timeout'
        Stop-ExactOwnedProcess $guardianProcess 'nextest_guardian' $cleanupFailures $processReceipts
        $guardianProcess = $null
        $testExit = 124
    }
    else {
        $testExit = $guardianProcess.ExitCode
    }
    $childExit = $testExit
    $guardianOutputText = $guardianOutputTask.GetAwaiter().GetResult()
    $guardianErrorText = $guardianErrorTask.GetAwaiter().GetResult()
    [IO.File]::WriteAllText($guardianStdout, $guardianOutputText, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($guardianStderr, $guardianErrorText, [Text.UTF8Encoding]::new($false))
    $guardianStatusLine = @($guardianOutputText -split "`r?`n" | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }) | Select-Object -Last 1
    if (-not [string]::IsNullOrWhiteSpace($guardianStatusLine)) {
        try {
            $guardianStatus = $guardianStatusLine | ConvertFrom-Json
            $nextestTimedOut = [bool]$guardianStatus.timed_out
            $childExit = [int]$guardianStatus.root_exit_code
        }
        catch {
            $terminalError = 'guardian_status_parse_failed'
        }
    }
    elseif (-not $nextestTimedOut) {
        $terminalError = 'guardian_status_missing'
    }

    Merge-ProcessLogs $nextestStdout $nextestStderr $nextestLog
    $nextestSummary = Read-NextestSummary $nextestLog
    if ($null -eq $nextestSummary) {
        if ($null -eq $terminalError) {
            $terminalError = 'nextest_summary_parse_failed'
        }
        $testExit = 96
    }
    $nextestLogHash = (Get-FileHash -LiteralPath $nextestLog -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($EvidenceLogPath)) {
        $resolvedEvidenceLog = [IO.Path]::GetFullPath($EvidenceLogPath)
        if ($resolvedEvidenceLog.StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'evidence log path must remain outside the run-owned cleanup root'
        }
        New-Item -ItemType Directory -Force (Split-Path $resolvedEvidenceLog) | Out-Null
        Copy-Item -LiteralPath $nextestLog -Destination $resolvedEvidenceLog -Force
    }
    if ($testExit -ne 0) {
        $boundedFailureExercised = $true
    }
}
catch {
    $boundedFailureExercised = $true
    if ($null -eq $terminalError) {
        $terminalError = 'wrapper_exception'
    }
    $testExit = 97
}
finally {
    if ($guardianProcess) {
        Stop-ExactOwnedProcess $guardianProcess 'nextest_guardian' $cleanupFailures $processReceipts
    }
    if ($surrealGuardianProcess) {
        $surrealGuardianExited = $false
        try {
            $surrealGuardianProcess.Refresh()
            if (-not $surrealGuardianProcess.HasExited) {
                [IO.File]::WriteAllText($surrealStopPath, 'stop', [Text.UTF8Encoding]::new($false))
                if (-not $surrealGuardianProcess.WaitForExit(10000)) {
                    Stop-ExactOwnedProcess $surrealGuardianProcess 'surrealdb_guardian_fallback' $cleanupFailures $processReceipts
                    $surrealGuardianProcess = $null
                }
            }
            if ($surrealGuardianProcess) {
                Stop-ExactOwnedProcess $surrealGuardianProcess 'surrealdb_guardian' $cleanupFailures $processReceipts
                $surrealGuardianProcess.Refresh()
                $surrealGuardianExited = $surrealGuardianProcess.HasExited
            }
            else {
                $surrealGuardianExited = $true
            }
        }
        catch {
            $cleanupFailures.Add('owned_process_cleanup_failed:surrealdb_guardian')
        }
        try {
            if ($surrealGuardianExited -and $surrealGuardianOutputTask) {
                $surrealGuardianOutputText = $surrealGuardianOutputTask.GetAwaiter().GetResult()
                [IO.File]::WriteAllText(
                    $surrealGuardianStdout,
                    $surrealGuardianOutputText,
                    [Text.UTF8Encoding]::new($false)
                )
                $surrealGuardianStatusLine = @($surrealGuardianOutputText -split "`r?`n" | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                }) | Select-Object -Last 1
                if (-not [string]::IsNullOrWhiteSpace($surrealGuardianStatusLine)) {
                    $surrealGuardianStatus = $surrealGuardianStatusLine | ConvertFrom-Json
                }
            }
            if ($surrealGuardianExited -and $surrealGuardianErrorTask) {
                $surrealGuardianErrorText = $surrealGuardianErrorTask.GetAwaiter().GetResult()
                [IO.File]::WriteAllText(
                    $surrealGuardianStderr,
                    $surrealGuardianErrorText,
                    [Text.UTF8Encoding]::new($false)
                )
            }
        }
        catch {
            $cleanupFailures.Add('surrealdb_guardian_status_capture_failed')
        }
    }
    if ($guardianBuildProcess) {
        Stop-ExactOwnedProcess $guardianBuildProcess 'guardian_build' $cleanupFailures $processReceipts
    }
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
    try {
        Remove-ExactOwnedSecretRoot $secretOwnedRoot $secretTestsRoot $runId
    }
    catch {
        $cleanupFailures.Add('owned_secret_root_cleanup_failed')
        $cleanupPendingPaths.Add($secretOwnedRoot.Replace('\', '/'))
    }
    $resolvedOwnedRoot = [IO.Path]::GetFullPath($ownedRoot)
    try {
        if (($resolvedOwnedRoot + [IO.Path]::DirectorySeparatorChar).StartsWith($ownedPrefix, [StringComparison]::OrdinalIgnoreCase) -and
            $resolvedOwnedRoot.StartsWith($tempBase, [StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $resolvedOwnedRoot)) {
            $cleanupDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                try {
                    Remove-Item -LiteralPath $resolvedOwnedRoot -Recurse -Force
                }
                catch {
                    if ([DateTime]::UtcNow -ge $cleanupDeadline) {
                        throw
                    }
                    Start-Sleep -Milliseconds 100
                }
            } while (Test-Path -LiteralPath $resolvedOwnedRoot)
        }
    }
    catch {
        $cleanupFailures.Add('owned_temp_root_cleanup_failed')
        $cleanupPendingPaths.Add($resolvedOwnedRoot.Replace('\', '/'))
    }
    if ($cleanupFailures.Count -gt 0) {
        $testExit = 98
        $boundedFailureExercised = $true
    }
}

$ambientUserRootsPreserved = $true
$ambientUserRootMismatches = @()
foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'USERPROFILE', 'HOME')) {
    if ([Environment]::GetEnvironmentVariable($name, 'Process') -cne $ambientUserRoots[$name]) {
        $ambientUserRootsPreserved = $false
        $ambientUserRootMismatches += $name
    }
}

$report = [ordered]@{
    component = 'isolated_workspace_tests'
    final_status = if ($testExit -eq 0) { 'DONE_VERIFIED' } else { 'FAILED_VERIFIER' }
    harness_probe = $HarnessProbe
    provider_calls = 0
    historical_provider_total_expected = 3
    owned_temp_root = $ownedRoot.Replace('\', '/')
    temp_root_removed = -not (Test-Path -LiteralPath $ownedRoot)
    owned_secret_root = $secretOwnedRoot.Replace('\', '/')
    owned_secret_root_removed = -not (Test-Path -LiteralPath $secretOwnedRoot)
    secret_config_path = $passwordConfigPath
    secret_cleanup_scope = 'exact_recorded_run_root_only'
    ambient_user_roots_preserved = $ambientUserRootsPreserved
    ambient_user_root_mismatches = $ambientUserRootMismatches
    bounded_failure_exercised = $boundedFailureExercised
    secret_reparse_checked = $secretReparseChecked
    secret_acl_restricted = $secretAclRestricted
    cleanup_failures = @($cleanupFailures)
    cleanup_pending = @($cleanupPendingPaths)
    owned_process_receipts = @($processReceipts)
    guardian_status = $guardianStatus
    surrealdb_guardian_status = $surrealGuardianStatus
    nextest_timed_out = $nextestTimedOut
    nextest_terminal_summary = $nextestSummary
    nextest_log_sha256 = $nextestLogHash
    child_exit_code = $childExit
    terminal_error = $terminalError
    host_configuration_changes = 0
    workspace_test_exit_code = $testExit
}
$report | ConvertTo-Json -Compress
exit $testExit
