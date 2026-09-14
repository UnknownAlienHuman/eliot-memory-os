<#
.SYNOPSIS
    Reset developer installation state for Eliot.

.DESCRIPTION
    Safely resets developer installation state:
    - Stops and deletes EliotHost and EliotWatchdog Windows services (if present).
    - Terminates lingering processes: eliot-host, eliot-watchdog, eliot-kernel,
      eliot-store-surreal, surreal, eliotd.
    - Moves ProgramData\Eliot and LocalAppData\Eliot aside to timestamped sibling
      directories (never recursive delete).
    - Deletes credential targets starting with 'eliot/installer-root/v1/' or 'eliot/store/v1/'.
    - Supports -WhatIf / dry-run mode.
    - Idempotent: exits 0 and prints 'RESET: nothing to reset (machine is clean)' when clean.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ProgramDataRoot = 'C:\ProgramData',
    [string]$LocalAppDataRoot = $env:LOCALAPPDATA,
    [switch]$SkipServices,
    [switch]$SkipCredentials,
    [int]$ScmWaitTimeoutSec = 30,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$WhatIf = [bool]$WhatIfPreference

if ([string]::IsNullOrWhiteSpace($LocalAppDataRoot)) {
    $LocalAppDataRoot = Join-Path $env:USERPROFILE 'AppData\Local'
}
if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
    $ProgramDataRoot = 'C:\ProgramData'
}

$foundCount = 0

# 1. Services & Lingering Processes
if (-not $SkipServices) {
    $services = @('EliotHost', 'EliotWatchdog')
    foreach ($svcName in $services) {
        $queryOut = & sc.exe query $svcName 2>&1
        if ($LASTEXITCODE -eq 0) {
            $foundCount++
            if ($WhatIf) {
                Write-Host "WhatIf: Would stop and delete service $svcName"
            } else {
                if ($queryOut -notmatch 'STATE\s+:\s+\d+\s+STOPPED') {
                    & sc.exe stop $svcName *>$null
                    $stopDeadline = (Get-Date).AddSeconds(10)
                    while ((Get-Date) -lt $stopDeadline) {
                        Start-Sleep -Milliseconds 500
                        $q = & sc.exe query $svcName 2>&1
                        if ($q -match 'STATE\s+:\s+\d+\s+STOPPED') {
                            break
                        }
                    }
                }
                & sc.exe delete $svcName *>$null
                $delDeadline = (Get-Date).AddSeconds($ScmWaitTimeoutSec)
                while ((Get-Date) -lt $delDeadline) {
                    & sc.exe query $svcName *>$null
                    if ($LASTEXITCODE -eq 1060) {
                        break
                    }
                    Start-Sleep -Milliseconds 500
                }
                Write-Host "RESET: removed service $svcName"
            }
        }
    }

    $lingeringNames = @('eliot-host', 'eliot-watchdog', 'eliot-kernel', 'eliot-store-surreal', 'surreal', 'eliotd')
    foreach ($procName in $lingeringNames) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $foundCount++
                if ($WhatIf) {
                    Write-Host "WhatIf: Would terminate lingering process $($p.ProcessName) (PID $($p.Id))"
                } else {
                    try {
                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "RESET: terminated lingering process $($p.ProcessName) (PID $($p.Id))"
                    } catch {
                        Write-Warning "Failed to terminate process $($p.ProcessName) (PID $($p.Id)): $_"
                    }
                }
            }
        }
    }
}

# 2. Directories
$pdEliot = Join-Path $ProgramDataRoot 'Eliot'
if (Test-Path -LiteralPath $pdEliot) {
    $foundCount++
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $destPd = Join-Path $ProgramDataRoot "Eliot-reset-$timestamp"
    if (Test-Path -LiteralPath $destPd) {
        $suffix = 1
        while (Test-Path -LiteralPath "${destPd}_$suffix") {
            $suffix++
        }
        $destPd = "${destPd}_$suffix"
    }
    if ($WhatIf) {
        Write-Host "WhatIf: Would move directory `"$pdEliot`" to `"$destPd`""
    } else {
        Move-Item -LiteralPath $pdEliot -Destination $destPd -Force
        Write-Host "RESET: moved `"$pdEliot`" to `"$destPd`""
    }
}

$laEliot = Join-Path $LocalAppDataRoot 'Eliot'
if (Test-Path -LiteralPath $laEliot) {
    $foundCount++
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $destLa = Join-Path $LocalAppDataRoot "Eliot-reset-$timestamp"
    if (Test-Path -LiteralPath $destLa) {
        $suffix = 1
        while (Test-Path -LiteralPath "${destLa}_$suffix") {
            $suffix++
        }
        $destLa = "${destLa}_$suffix"
    }
    if ($WhatIf) {
        Write-Host "WhatIf: Would move directory `"$laEliot`" to `"$destLa`""
    } else {
        Move-Item -LiteralPath $laEliot -Destination $destLa -Force
        Write-Host "RESET: moved `"$laEliot`" to `"$destLa`""
    }
}

# 3. Credentials
if (-not $SkipCredentials) {
    $cmdkeyOutput = & cmdkey.exe /list 2>$null
    $credTargets = @()
    if ($cmdkeyOutput) {
        foreach ($line in $cmdkeyOutput) {
            if ($line -match '^\s*Target:\s*(.+)$') {
                $rawTarget = $matches[1].Trim()
                $cleanTarget = $rawTarget -replace '^LegacyGeneric:target=', ''
                if ($cleanTarget.StartsWith('eliot/installer-root/v1/') -or $cleanTarget.StartsWith('eliot/store/v1/')) {
                    $credTargets += [pscustomobject]@{
                        Raw   = $rawTarget
                        Clean = $cleanTarget
                    }
                }
            }
        }
    }
    foreach ($cred in $credTargets) {
        $foundCount++
        if ($WhatIf) {
            Write-Host "WhatIf: Would delete credential target '$($cred.Clean)'"
        } else {
            & cmdkey.exe /delete:$($cred.Clean) *>$null
            if ($LASTEXITCODE -ne 0 -and $cred.Raw -ne $cred.Clean) {
                & cmdkey.exe /delete:$($cred.Raw) *>$null
            }
            Write-Host "RESET: deleted credential target '$($cred.Clean)'"
        }
    }
}

if ($foundCount -eq 0) {
    Write-Host "RESET: nothing to reset (machine is clean)"
}

$global:LASTEXITCODE = 0
exit 0
