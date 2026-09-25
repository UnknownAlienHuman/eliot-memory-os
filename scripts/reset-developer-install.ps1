<#
.SYNOPSIS
    Return a developer machine to the "not installed" state for the Eliot system_service profile.

.DESCRIPTION
    Developer-machine reset for the system_service installation profile only. It is
    not a product uninstall lifecycle (I3.13) and it is not install rollback
    machinery (#1325 / T10, deferred to the production phase by owner decision
    2026-09-14).

    Every artifact handled here is read out of current installation source, never
    guessed:

    - Windows services `EliotHost` and `EliotWatchdog`
      (crates/foundation/eliot-runtime-contracts/src/installation_activation.rs::InstallationScmRole::service_name,
       bins/eliot-watchdog/src/lib.rs::SERVICE_NAME). The reset stops each one and
       deletes it, then waits until `sc.exe query` reports it absent before it
       claims removal. A service that survives the wait is reported and fails the
       reset instead of being reported as removed.
      The EliotHost-to-EliotWatchdog service-object control grant
      (crates/kernel/eliot-installation/src/scm_approval.rs) lives on the SCM
      service object, so `sc.exe delete` removes the grant with the service; no
      separate ACL step exists or is guessed.
    - Any process whose image path is under the installation root
      `<ProgramDataRoot>\Eliot`. The staged executables under that root are the
      canonical package roles
      (crates/kernel/eliot-installation/src/package_planner.rs::REQUIRED_PACKAGE_ROLES,
       bins/eliot/src/source_bundle_materializer.rs::REQUIRED_ROLES). Selection is by
       image path, not by process name, so every staged executable is covered and no
       owner process running from anywhere else is ever targeted.
    - The installation root itself, moved aside to a timestamped sibling
       `Eliot-reset-<UTC timestamp>`. The root is `<profile anchor root>\Eliot`
       (crates/kernel/eliot-installation/src/package_planner.rs: "SystemService/UserMode
       staging_root must equal profile_anchor_root\Eliot\packages";
       scripts/invoke-eliot-windows-x64-production.ps1::New-ProductionMaterializeContract).
       It is never a recursive delete: previous state stays inspectable and nothing
       half-installed is left in place.
       %LOCALAPPDATA%\Eliot is NEVER moved, deleted, or edited: it holds the owner's
       live legacy ELIOT data and is not part of the system_service installation root.
    - Windows Credential Manager targets under `eliot/installer-root/v1/`
      (crates/kernel/eliot-installation/src/transaction.rs::InstallationSecretReference::validate).
      `eliot/store/v1/*` targets
      (crates/kernel/eliot-installation/src/credential_provision.rs::validate_store_credential_target)
      belong to the legacy Store and are NEVER deleted.

    The reset is idempotent: on a clean machine it finds nothing, prints
    "RESET: nothing to reset (machine is clean)" and exits 0. Any artifact that
    could not be returned to the absent state is reported explicitly and the reset
    exits non-zero, so a caller never mistakes a partial reset for a clean machine.

    Supports -WhatIf / dry-run mode.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ProgramDataRoot = 'C:\ProgramData',
    [switch]$SkipServices,
    [switch]$SkipCredentials,
    [int]$ScmWaitTimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
$WhatIf = [bool]$WhatIfPreference

if ([string]::IsNullOrWhiteSpace($ProgramDataRoot)) {
    $ProgramDataRoot = 'C:\ProgramData'
}

# `sc.exe query` exit code for a service that is not registered.
$SC_SERVICE_DOES_NOT_EXIST = 1060

$pdEliot = Join-Path $ProgramDataRoot 'Eliot'
$installRootPrefix = [System.IO.Path]::GetFullPath($pdEliot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar

# Counts printed once so the operator sees exactly what was found, removed and moved.
$foundCount = 0
$stats = [ordered]@{ services = 0; processes = 0; directories = 0; credentials = 0 }
$failures = [System.Collections.Generic.List[string]]::new()

function Get-EliotServiceRegistration {
    param([string]$Name)
    $output = & sc.exe query $Name 2>&1
    return [pscustomobject]@{
        Name     = $Name
        ExitCode = $LASTEXITCODE
        Output   = (($output | ForEach-Object { [string]$_ }) -join "`n")
    }
}

function Test-UnderInstallRoot {
    param([string]$Path, [string]$Prefix)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        return ([System.IO.Path]::GetFullPath($Path)).StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)
    } catch {
        return $Path.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)
    }
}

# 1. Services, then any process still running out of the installation root.
if (-not $SkipServices) {
    foreach ($svcName in @('EliotHost', 'EliotWatchdog')) {
        $query = Get-EliotServiceRegistration -Name $svcName
        if ($query.ExitCode -eq $SC_SERVICE_DOES_NOT_EXIST) { continue }
        if ($query.ExitCode -ne 0) {
            # Neither present nor provably absent: report instead of silently skipping.
            $failures.Add("sc.exe query $svcName returned $($query.ExitCode), so its registration state is not provable: $($query.Output)")
            continue
        }

        $foundCount++
        if ($WhatIf) {
            $stats.services++
            Write-Host "RESET: would stop and delete service $svcName"
            continue
        }

        if ($query.Output -notmatch 'STATE\s+:\s+\d+\s+STOPPED') {
            & sc.exe stop $svcName *>$null
            $stopDeadline = (Get-Date).AddSeconds(10)
            while ((Get-Date) -lt $stopDeadline) {
                Start-Sleep -Milliseconds 500
                if ((Get-EliotServiceRegistration -Name $svcName).Output -match 'STATE\s+:\s+\d+\s+STOPPED') {
                    break
                }
            }
        }

        & sc.exe delete $svcName *>$null
        $deleteDeadline = (Get-Date).AddSeconds($ScmWaitTimeoutSec)
        while ((Get-Date) -lt $deleteDeadline) {
            if ((Get-EliotServiceRegistration -Name $svcName).ExitCode -ne 0) { break }
            Start-Sleep -Milliseconds 500
        }

        $final = Get-EliotServiceRegistration -Name $svcName
        if ($final.ExitCode -eq $SC_SERVICE_DOES_NOT_EXIST) {
            $stats.services++
            Write-Host "RESET: removed service $svcName"
        } else {
            $failures.Add("service $svcName is still registered after sc.exe delete (sc.exe query exit $($final.ExitCode)): $($final.Output)")
        }
    }

    # Lingering processes: terminate ONLY processes whose image is under the installation
    # root. Selection is by image path, so the owner's eliot/surreal/eliotd running
    # anywhere else is never targeted.
    $running = @()
    # Reading the process table is not a mutation, so ShouldProcess must not apply to
    # it; keeping -WhatIf scoped to real actions keeps the dry-run output readable.
    $restoreWhatIfPreference = $WhatIfPreference
    $WhatIfPreference = $false
    try {
        $running = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop |
            Where-Object { Test-UnderInstallRoot -Path $_.ExecutablePath -Prefix $installRootPrefix })
    } catch {
        $failures.Add("cannot enumerate Win32_Process to find installation-root processes: $_")
    } finally {
        $WhatIfPreference = $restoreWhatIfPreference
    }

    foreach ($proc in $running) {
        $foundCount++
        if ($WhatIf) {
            $stats.processes++
            Write-Host "RESET: would terminate lingering process $($proc.Name) (PID $($proc.ProcessId), Path `"$($proc.ExecutablePath)`")"
            continue
        }
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        $remaining = Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue
        if ($remaining) {
            $failures.Add("process $($proc.Name) (PID $($proc.ProcessId)) survived termination; path `"$($proc.ExecutablePath)`"")
        } else {
            $stats.processes++
            Write-Host "RESET: terminated lingering process $($proc.Name) (PID $($proc.ProcessId), Path `"$($proc.ExecutablePath)`")"
        }
    }
}

# 2. Installation root (system_service installation root only)
# Note: %LOCALAPPDATA%\Eliot holds the owner's live legacy ELIOT data (data, blobs,
# backups, .swarm) and is NEVER moved, deleted, or edited by an install reset.
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
        $stats.directories++
        Write-Host "RESET: would move directory `"$pdEliot`" to `"$destPd`""
    } else {
        $moved = $false
        try {
            Move-Item -LiteralPath $pdEliot -Destination $destPd
            $moved = $true
        } catch {
            $failures.Add("cannot move installation root `"$pdEliot`" to `"$destPd`": $_")
        }
        if ($moved) {
            if (Test-Path -LiteralPath $pdEliot) {
                $failures.Add("installation root `"$pdEliot`" still exists after move to `"$destPd`"")
            } else {
                $stats.directories++
                Write-Host "RESET: moved `"$pdEliot`" to `"$destPd`""
            }
        }
    }
}

# 3. Credentials (installer-root only; eliot/store/v1/* belongs to the legacy store
#    and is NEVER deleted)
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
            $stats.credentials++
            Write-Host "RESET: would delete credential target '$($cred.Clean)'"
            continue
        }
        & cmdkey.exe /delete:$($cred.Clean) *>$null
        $deleteCode = $LASTEXITCODE
        if ($deleteCode -ne 0 -and $cred.Raw -ne $cred.Clean) {
            & cmdkey.exe /delete:$($cred.Raw) *>$null
            $deleteCode = $LASTEXITCODE
        }
        if ($deleteCode -ne 0) {
            $failures.Add("cmdkey /delete for installer-root credential '$($cred.Clean)' returned $deleteCode")
        } else {
            $stats.credentials++
            Write-Host "RESET: deleted credential target '$($cred.Clean)'"
        }
    }
}

if ($foundCount -eq 0) {
    Write-Host "RESET: nothing to reset (machine is clean)"
} else {
    Write-Host ("RESET: found {0} machine-level artifact(s); services removed {1}, processes terminated {2}, directories moved {3}, credentials deleted {4}" -f $foundCount, $stats.services, $stats.processes, $stats.directories, $stats.credentials)
}

if ($failures.Count -gt 0) {
    foreach ($failure in $failures) {
        Write-Warning "RESET: $failure"
    }
    Write-Host "RESET: FAILED - the machine is NOT in the 'not installed' state ($($failures.Count) unresolved)"
    $global:LASTEXITCODE = 1
    exit 1
}

$global:LASTEXITCODE = 0
exit 0
