[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EliotExe,

    [string]$Config,

    [ValidateSet('dynamic_agent', 'claude_desktop', 'codex_controller', 'codex_worker', 'external_auditor', 'verifier', 'human_operator', 'human_readonly')]
    [string]$Profile = 'human_readonly',

    [ValidateSet('codex', 'antigravity', 'opencode', 'claude', 'claude-desktop')]
    [string]$HostSurface,

    [AllowEmptyString()]
    [string]$Instance = 'default',

    [string]$ProjectId,

    [string]$Query,

    [string]$ToolName,

    [string]$ToolArgumentsJson = '{}',

    [string]$ClientName = 'eliot-powershell-reference-client',

    [string]$AgentSessionId,

    [string]$TaskId,

    [string]$RoleLeaseId,

    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'

function ConvertTo-NativeCommandLineArgument {
    param(
        [AllowEmptyString()]
        [string]$Argument
    )

    if ($null -eq $Argument) {
        $Argument = ''
    }
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashCount = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashCount += 1
            continue
        }
        if ($character -eq '"') {
            [void]$builder.Append(('\' * (($backslashCount * 2) + 1)))
            [void]$builder.Append('"')
            $backslashCount = 0
            continue
        }
        if ($backslashCount -gt 0) {
            [void]$builder.Append(('\' * $backslashCount))
            $backslashCount = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashCount -gt 0) {
        [void]$builder.Append(('\' * ($backslashCount * 2)))
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertFrom-JsonCompatible {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$InputObject,

        [switch]$AsHashtable
    )

    process {
        $command = Get-Command ConvertFrom-Json
        $supportsDepth = $command.Parameters.ContainsKey('Depth')
        $supportsHashtable = $command.Parameters.ContainsKey('AsHashtable')
        if ($AsHashtable -and $supportsHashtable -and $supportsDepth) {
            return $InputObject | ConvertFrom-Json -AsHashtable -Depth 30
        }
        if ($AsHashtable -and $supportsHashtable) {
            return $InputObject | ConvertFrom-Json -AsHashtable
        }
        if ($supportsDepth) {
            return $InputObject | ConvertFrom-Json -Depth 30
        }
        return $InputObject | ConvertFrom-Json
    }
}

$exe = (Resolve-Path -LiteralPath $EliotExe).Path
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $exe
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$processArguments = [System.Collections.Generic.List[string]]::new()
if ($Config) {
    $processArguments.Add('--config')
    $processArguments.Add((Resolve-Path -LiteralPath $Config).Path)
}
$processArguments.Add('mcp')
$processArguments.Add('stdio')
if ($HostSurface) {
    $processArguments.Add('--host')
    $processArguments.Add($HostSurface)
    if ($PSBoundParameters.ContainsKey('Profile')) {
        $processArguments.Add('--profile')
        $processArguments.Add($Profile)
    }
}
else {
    $processArguments.Add('--profile')
    $processArguments.Add($Profile)
}
if ($Instance) {
    $processArguments.Add('--instance')
    $processArguments.Add($Instance)
}

if ($null -ne $startInfo.ArgumentList) {
    foreach ($argument in $processArguments) {
        $startInfo.ArgumentList.Add($argument)
    }
}
else {
    $startInfo.Arguments = (@(
        $processArguments | ForEach-Object {
            ConvertTo-NativeCommandLineArgument -Argument $_
        }
    ) -join ' ')
}

foreach ($name in @(
    'SURREAL_USER',
    'SURREAL_PASS',
    'ELIOT_TEST_SURREAL_BIND',
    'ELIOT_TEST_SURREAL_ENDPOINT',
    'ELIOT_TEST_SURREAL_PASSWORD_FILE',
    'ELIOT_TEST_SURREAL_STORAGE'
)) {
    [void]$startInfo.Environment.Remove($name)
}
if ($Config) {
    $startInfo.Environment['ELIOT_GOVERNOR_CONFIG'] = (Resolve-Path -LiteralPath $Config).Path
}
if ($AgentSessionId) {
    $startInfo.Environment['ELIOT_AGENT_SESSION_ID'] = $AgentSessionId
}
if ($ProjectId) {
    $startInfo.Environment['ELIOT_PROJECT_ID'] = $ProjectId
}
if ($TaskId) {
    $startInfo.Environment['ELIOT_TASK_ID'] = $TaskId
}
if ($RoleLeaseId) {
    $startInfo.Environment['ELIOT_ROLE_LEASE_ID'] = $RoleLeaseId
}

$requests = [System.Collections.Generic.List[object]]::new()
$requests.Add([ordered]@{
    jsonrpc = '2.0'
    id = 1
    method = 'initialize'
    params = [ordered]@{
        protocolVersion = '2025-06-18'
        capabilities = @{}
        clientInfo = [ordered]@{
            name = $ClientName
            version = '1.0.0'
        }
    }
})
$requests.Add([ordered]@{
    jsonrpc = '2.0'
    id = 2
    method = 'tools/list'
    params = @{}
})
$requests.Add([ordered]@{
    jsonrpc = '2.0'
    id = 3
    method = 'prompts/list'
    params = @{}
})

$nextRequestId = 4
$toolCallResponseIndex = $null
$recallResponseIndex = $null

if ($ToolName) {
    try {
        $toolArguments = $ToolArgumentsJson | ConvertFrom-JsonCompatible -AsHashtable
    }
    catch {
        throw "-ToolArgumentsJson must contain one valid JSON object: $($_.Exception.Message)"
    }
    if (
        $toolArguments -isnot [System.Collections.IDictionary] -and
        $toolArguments -isnot [System.Management.Automation.PSCustomObject]
    ) {
        throw '-ToolArgumentsJson must contain one JSON object'
    }
    $toolCallResponseIndex = $requests.Count
    $requests.Add([ordered]@{
        jsonrpc = '2.0'
        id = $nextRequestId
        method = 'tools/call'
        params = [ordered]@{
            name = $ToolName
            arguments = $toolArguments
        }
    })
    $nextRequestId += 1
}

if ($Query) {
    if (-not $ProjectId) {
        throw '-ProjectId is required when -Query is supplied'
    }
    $recallResponseIndex = $requests.Count
    $requests.Add([ordered]@{
        jsonrpc = '2.0'
        id = $nextRequestId
        method = 'tools/call'
        params = [ordered]@{
            name = 'eliot_recall_l0'
            arguments = [ordered]@{
                project_id = $ProjectId
                query = $Query
                limit = 10
            }
        }
    })
}

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo
if (-not $process.Start()) {
    throw 'failed to start Eliot MCP facade'
}

$stdoutTask = $process.StandardOutput.ReadToEndAsync()
$stderrTask = $process.StandardError.ReadToEndAsync()
foreach ($request in $requests) {
    $process.StandardInput.WriteLine(($request | ConvertTo-Json -Compress -Depth 20))
    if ($request.id -eq 1) {
        $process.StandardInput.WriteLine((([ordered]@{
            jsonrpc = '2.0'
            method = 'notifications/initialized'
        }) | ConvertTo-Json -Compress -Depth 20))
    }
}
$process.StandardInput.Close()

if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    try {
        $process.Kill($true)
    }
    catch [System.Management.Automation.MethodException] {
        # Windows PowerShell 5.1 exposes only Process.Kill().
        $process.Kill()
    }
    throw "Eliot MCP facade timed out after $TimeoutSeconds seconds"
}
$stdout = $stdoutTask.GetAwaiter().GetResult()
$stderr = $stderrTask.GetAwaiter().GetResult()
if ($process.ExitCode -ne 0) {
    throw "Eliot MCP facade exited with code $($process.ExitCode): $stderr"
}

$responses = @($stdout -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
    $_ | ConvertFrom-JsonCompatible
})
if ($responses.Count -ne $requests.Count) {
    throw "expected $($requests.Count) MCP responses, received $($responses.Count)"
}

$toolNames = @($responses[1].result.tools | ForEach-Object { $_.name })
$promptNames = @($responses[2].result.prompts | ForEach-Object { $_.name })
$utf8 = [System.Text.Encoding]::UTF8
$responseBytes = @($responses | ForEach-Object {
    $utf8.GetByteCount(($_ | ConvertTo-Json -Compress -Depth 30))
})
$toolCallResponse = if ($null -ne $toolCallResponseIndex) {
    $responses[$toolCallResponseIndex]
} else { $null }
$recallResponse = if ($null -ne $recallResponseIndex) {
    $responses[$recallResponseIndex]
} else { $null }
if ($ToolName -and $ToolName -notin $toolNames) {
    $surface = if ($HostSurface) { "host '$HostSurface'" } else { "profile '$Profile'" }
    throw "tool '$ToolName' is not exposed by $surface"
}

[ordered]@{
    component = 'eliot_mcp_reference_client'
    status = 'passed'
    executable = $exe
    profile = $responses[0].result.experimental.eliotAgentSession.access_profile
    host_surface = if ($HostSurface) { $HostSurface } else { $null }
    instance = if ($Instance) { $Instance } else { 'isolated_from_config' }
    server = $responses[0].result.serverInfo
    instructions = $responses[0].result.instructions
    agent_session = $responses[0].result.experimental.eliotAgentSession
    tool_names = $toolNames
    prompt_names = $promptNames
    footprint = [ordered]@{
        mcp_schema_bytes = $utf8.GetByteCount(($responses[1].result.tools | ConvertTo-Json -Compress -Depth 30))
        bootstrap_bytes = $utf8.GetByteCount([string]$responses[0].result.instructions)
        largest_response_bytes = ($responseBytes | Measure-Object -Maximum).Maximum
    }
    tool_call = if ($null -ne $toolCallResponse -and $toolCallResponse.PSObject.Properties['result']) {
        $toolCallResponse.result.structuredContent
    } else { $null }
    tool_call_error = if ($null -ne $toolCallResponse -and $toolCallResponse.PSObject.Properties['error']) {
        $toolCallResponse.error
    } else { $null }
    recall = if ($null -ne $recallResponse -and $recallResponse.PSObject.Properties['result']) {
        $recallResponse.result.structuredContent
    } else { $null }
} | ConvertTo-Json -Depth 30
