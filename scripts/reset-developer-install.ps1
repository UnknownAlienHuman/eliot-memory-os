<#
.SYNOPSIS
    Reset developer installation state for Eliot.

.DESCRIPTION
    Safely resets developer installation state for system_service:
    - Stops and deletes EliotHost and EliotWatchdog Windows services (if present).
    - Terminates lingering processes whose executable path is under the ProgramData\Eliot
      installation root. (Never kills processes by bare name, preserving any owner
      eliotd/surreal outside).
    - Moves ProgramData\Eliot aside to a timestamped sibling directory (never recursive delete).
      (%LOCALAPPDATA%\Eliot is NEVER touched; it holds the owner's live legacy ELIOT data).
    - Deletes credential targets starting with 'eliot/installer-root/v1/'.
      ('eliot/store/v1/*' credentials belong to legacy store and are NEVER deleted).
    - Supports -WhatIf / dry-run mode.
    - Idempotent: exits 0 and prints 'RESET: nothing to reset (machine is clean)' when clean.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ProgramDataRoot = 'C:\ProgramData',
    [switch]$SkipServices,
    [switch]$SkipCredentials,
    [int]$ScmWaitTimeoutSec = 30,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$WhatIf = [bool]$WhatIfPreference

if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
    $ProgramDataRoot = 'C:\ProgramData'
}

$pdEliot = Join-Path $ProgramDataRoot 'Eliot'
$installRootPrefix = [System.IO.Path]::GetFullPath($pdEliot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

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

    # Lingering processes: kill ONLY processes whose executable path is under the ProgramData\Eliot installation root.
    # Never kill processes by bare name, preserving any owner surreal/eliotd running outside.
    $lingeringNames = @('eliot-host', 'eliot-watchdog', 'eliot-kernel', 'eliot-store-surreal', 'surreal', 'eliotd')
    foreach ($procName in $lingeringNames) {
        $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($procs) {
            foreach ($p in $procs) {
                $procPath = $null
                try {
                    $procPath = $p.Path
                } catch {}
                if (-not $procPath) {
                    try {
                        $cim = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
                        $procPath = $cim.ExecutablePath
                    } catch {}
                }

                if ([string]::IsNullOrWhiteSpace($procPath)) {
                    continue
                }

                $fullProcPath = [System.IO.Path]::GetFullPath($procPath)
                if (-not $fullProcPath.StartsWith($installRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    # Outside ProgramData\Eliot installation root - do NOT kill
                    continue
                }

                $foundCount++
                if ($WhatIf) {
                    Write-Host "WhatIf: Would terminate lingering process $($p.ProcessName) (PID $($p.Id), Path `"$procPath`")"
                } else {
                    try {
                        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                        Write-Host "RESET: terminated lingering process $($p.ProcessName) (PID $($p.Id), Path `"$procPath`")"
                    } catch {
                        Write-Warning "Failed to terminate process $($p.ProcessName) (PID $($p.Id)): $_"
                    }
                }
            }
        }
    }
}

# 2. Directories (system_service installation root only)
# Note: %LOCALAPPDATA%\Eliot holds the owner's live legacy ELIOT data (122 GB: data, blobs, backups, .swarm)
# and is NEVER moved, deleted, or edited by an install reset.
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

# 3. Credentials (installer-root only; eliot/store/v1/* belongs to legacy store and is NEVER deleted)
if (-not $SkipCredentials) {
    $cmdkeyOutput = & cmdkey.exe /list 2>$null
    $credTargets = @()
    if ($cmdkeyOutput) {
        foreach ($line in $cmdkeyOutput) {
            if ($line -match '^\s*Target:\s*(.+)$') {
                $rawTarget = $matches[1].Trim()
                $cleanTarget = $rawTarget -replace '^LegacyGeneric:target=', ''
                if ($cleanTarget.StartsWith('eliot/installer-root/v1/')) {
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
