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
      Termination is PID-reuse-safe (audit 5899416555): the reset retains PID plus
      Win32_Process creation time/image identity at observation, re-reads the live
      process immediately before termination, and kills only when the creation
      identity matches and the image is still under the exact canonical install
      root. A vanished original is already absent; a changed, reused, or
      indeterminate identity is a bounded failure and never authority to kill the
      replacement. A post-termination re-read proves the original object is gone.
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
      Enumeration is fail-closed (audit 5899416555): the exact `cmdkey /list` exit
      status is checked, the authoritative set comes from the locale-independent
      CredEnumerateW owner API (never complete-empty inferred from missing English
      `Target:` lines), each delete is followed by an authoritative re-enumeration
      proving the exact target absent, and exit 0 requires one complete current
      enumeration with no admitted installer-root credential. Any unprovable
      credential state is reported and exits non-zero, never known-empty.

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

# Locale-independent Credential Manager enumeration state (audit 5899416555).
$script:EliotCredApiReady = $false
$script:EliotCredApiAttempted = $false
$script:EliotCredApiLoadError = ''

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

function Get-InstallRootProcessById {
    <#
    .SYNOPSIS
        Re-reads one live process by PID for PID-reuse-safe termination.

    .DESCRIPTION
        Returns the current Win32_Process object for the PID, or $null only when a
        successful query proves no such PID exists. Throws on any query failure so
        the caller treats indeterminate state as a bounded failure and never kills.
    #>
    param([int]$ProcessId)
    $result = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction Stop
    if ($null -eq $result) { return $null }
    $arr = @($result)
    if ($arr.Count -eq 0) { return $null }
    return $arr[0]
}

function Initialize-EliotCredApi {
    <#
    .SYNOPSIS
        Loads the locale-independent CredEnumerateW owner API once.
    #>
    if ($script:EliotCredApiReady) { return $true }
    if ($script:EliotCredApiAttempted) { return $false }
    $script:EliotCredApiAttempted = $true
    try {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EliotCredEnum {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct EliotFileTime { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct EliotCredential {
        public uint Flags;
        public uint Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        public EliotFileTime LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr creds);
    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);
    public static string[] EnumerateTargetNames() {
        int count;
        IntPtr creds;
        if (!CredEnumerateW(null, 0, out count, out creds)) {
            int err = Marshal.GetLastWin32Error();
            throw new System.ComponentModel.Win32Exception(err, "CredEnumerateW failed");
        }
        try {
            string[] names = new string[count];
            for (int i = 0; i < count; i++) {
                IntPtr p = Marshal.ReadIntPtr(creds, i * IntPtr.Size);
                EliotCredential c = (EliotCredential)Marshal.PtrToStructure(p, typeof(EliotCredential));
                names[i] = c.TargetName;
            }
            return names;
        } finally { CredFree(creds); }
    }
}
'@ -ErrorAction Stop
        $script:EliotCredApiReady = $true
        return $true
    } catch {
        $msg = [string]$_
        if ($msg -match 'already exists') {
            $script:EliotCredApiReady = $true
            return $true
        }
        if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) }
        $script:EliotCredApiLoadError = $msg
        $script:EliotCredApiReady = $false
        return $false
    }
}

function Get-InstallerRootCredentialEnumeration {
    <#
    .SYNOPSIS
        Authoritative installer-root credential enumeration (audit 5899416555).

    .DESCRIPTION
        Checks the exact `cmdkey /list` exit status and unions the best-effort
        English `Target:` parse with the locale-independent CredEnumerateW owner
        API. Complete is true only when cmdkey exited 0 AND the owner API
        succeeded. Incomplete state is recorded in $failures by this function, so
        callers must never treat its empty set as known-empty. `eliot/store/v1/*`
        is never admitted by construction.
    #>
    $cmdkeyLines = @()
    $cmdkeyExit = -1
    $cmdkeyFailed = $false
    $cmdkeyDiag = ''
    try {
        $raw = & cmdkey.exe /list 2>&1
        $cmdkeyExit = $LASTEXITCODE
        if ($null -ne $raw) { $cmdkeyLines = @($raw | ForEach-Object { [string]$_ }) }
        if ($cmdkeyExit -ne 0) {
            $cmdkeyFailed = $true
            $cmdkeyDiag = (($cmdkeyLines | Select-Object -First 3) -join ' | ')
            if ($cmdkeyDiag.Length -gt 500) { $cmdkeyDiag = $cmdkeyDiag.Substring(0, 500) }
        }
    } catch {
        $cmdkeyFailed = $true
        $cmdkeyDiag = [string]$_
        if ($cmdkeyDiag.Length -gt 500) { $cmdkeyDiag = $cmdkeyDiag.Substring(0, 500) }
        $cmdkeyExit = -1
    }

    $cmdkeyTargets = @()
    foreach ($line in $cmdkeyLines) {
        if ($line -match '^\s*Target:\s*(.+)$') {
            $rawTarget = $matches[1].Trim()
            $cleanTarget = $rawTarget -replace '^LegacyGeneric:target=', ''
            if ($cleanTarget.StartsWith('eliot/installer-root/v1/')) {
                $cmdkeyTargets += [pscustomobject]@{
                    Raw   = $rawTarget
                    Clean = $cleanTarget
                }
            }
        }
    }

    $apiTargets = @()
    $apiOk = $false
    $apiError = ''
    try {
        if (-not (Initialize-EliotCredApi)) { throw $script:EliotCredApiLoadError }
        $names = [EliotCredEnum]::EnumerateTargetNames()
        $apiOk = $true
        foreach ($n in $names) {
            if ([string]::IsNullOrEmpty($n)) { continue }
            $rawTarget = $n.Trim()
            $cleanTarget = $rawTarget -replace '^LegacyGeneric:target=', ''
            if ($cleanTarget.StartsWith('eliot/installer-root/v1/')) {
                $apiTargets += [pscustomobject]@{
                    Raw   = $rawTarget
                    Clean = $cleanTarget
                }
            }
        }
    } catch {
        $apiOk = $false
        $apiError = [string]$_
        if ($apiError.Length -gt 500) { $apiError = $apiError.Substring(0, 500) }
    }

    if ($cmdkeyFailed -or ($cmdkeyExit -ne 0)) {
        $failures.Add("cmdkey /list returned exit $cmdkeyExit, so installer-root credential state is not provable (complete-empty unknown): $cmdkeyDiag")
    }
    if (-not $apiOk) {
        $failures.Add("locale-independent credential enumeration (CredEnumerateW) failed, so installer-root credential state is not provable: $apiError")
    }
    $complete = (($cmdkeyExit -eq 0) -and (-not $cmdkeyFailed) -and $apiOk)

    $seen = @{}
    $union = @()
    foreach ($t in ($cmdkeyTargets + $apiTargets)) {
        if (-not $seen.ContainsKey($t.Clean)) {
            $seen[$t.Clean] = $true
            $union += $t
        }
    }

    return [pscustomobject]@{
        Complete = $complete
        Targets  = $union
    }
}

function Test-InstallerRootCredentialAbsent {
    <#
    .SYNOPSIS
        Proves one exact installer-root target absent by authoritative re-enumeration.
    #>
    param([string]$CleanTarget)
    $re = Get-InstallerRootCredentialEnumeration
    if (-not $re.Complete) { return $false }
    foreach ($t in $re.Targets) {
        if ($t.Clean -eq $CleanTarget) { return $false }
    }
    return $true
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
    # anywhere else is never targeted. Termination is PID-reuse-safe: PID plus
    # Win32_Process creation time/image identity is retained at observation, the live
    # process is re-read immediately before termination, and only the same creation
    # identity still under the exact canonical install root is killed.
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
        $observedPid = [int]$proc.ProcessId
        $observedName = [string]$proc.Name
        $observedPath = [string]$proc.ExecutablePath
        $observedCreation = $null
        try { $observedCreation = [string]$proc.CreationDate } catch { $observedCreation = $null }
        if ($WhatIf) {
            $stats.processes++
            Write-Host "RESET: would terminate lingering process $observedName (PID $observedPid, Path `"$observedPath`")"
            continue
        }
        if ([string]::IsNullOrEmpty($observedCreation)) {
            $failures.Add("process $observedName (PID $observedPid) has no readable creation identity, so it cannot be proven to be the observed object; not terminating replacement (path `"$observedPath`")")
            continue
        }
        $current = $null
        $rereadFailed = $false
        $rereadError = ''
        try {
            $current = Get-InstallRootProcessById -ProcessId $observedPid
        } catch {
            $rereadFailed = $true
            $rereadError = [string]$_
            if ($rereadError.Length -gt 500) { $rereadError = $rereadError.Substring(0, 500) }
        }
        if ($rereadFailed) {
            $failures.Add("cannot re-read PID $observedPid ($observedName) before termination, so its identity is indeterminate; not terminating (observed creation $observedCreation): $rereadError")
            continue
        }
        if ($null -eq $current) {
            $stats.processes++
            Write-Host "RESET: lingering process $observedName (PID $observedPid) already exited"
            continue
        }
        $currentCreation = $null
        try { $currentCreation = [string]$current.CreationDate } catch { $currentCreation = $null }
        $currentPath = [string]$current.ExecutablePath
        if ([string]::IsNullOrEmpty($currentCreation)) {
            $failures.Add("PID $observedPid ($observedName) has no readable creation identity on re-read, so PID reuse cannot be excluded; not terminating (observed creation $observedCreation, current path `"$currentPath`")")
            continue
        }
        if ($currentCreation -ne $observedCreation) {
            $failures.Add("PID $observedPid was reused (observed $observedName creation $observedCreation, current creation $currentCreation path `"$currentPath`"); not terminating the replacement")
            continue
        }
        if (-not (Test-UnderInstallRoot -Path $currentPath -Prefix $installRootPrefix)) {
            $failures.Add("PID $observedPid ($observedName) image left the installation root before termination (observed `"$observedPath`", current `"$currentPath`"); not terminating")
            continue
        }
        if (-not [string]::Equals($currentPath, $observedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $failures.Add("PID $observedPid ($observedName) image changed before termination (observed `"$observedPath`", current `"$currentPath`"); not terminating")
            continue
        }
        Stop-Process -Id $observedPid -Force -ErrorAction SilentlyContinue
        $post = $null
        $postFailed = $false
        $postError = ''
        try {
            $post = Get-InstallRootProcessById -ProcessId $observedPid
        } catch {
            $postFailed = $true
            $postError = [string]$_
            if ($postError.Length -gt 500) { $postError = $postError.Substring(0, 500) }
        }
        if ($postFailed) {
            $failures.Add("cannot re-read PID $observedPid ($observedName) after termination, so the original object (creation $observedCreation) is not proven gone: $postError")
        } elseif ($null -eq $post) {
            $stats.processes++
            Write-Host "RESET: terminated lingering process $observedName (PID $observedPid, Path `"$observedPath`")"
        } else {
            $postCreation = $null
            try { $postCreation = [string]$post.CreationDate } catch { $postCreation = $null }
            if ((-not [string]::IsNullOrEmpty($postCreation)) -and ($postCreation -ne $observedCreation)) {
                $stats.processes++
                Write-Host "RESET: terminated lingering process $observedName (PID $observedPid, Path `"$observedPath`"; PID now reused by creation $postCreation)"
            } else {
                $failures.Add("process $observedName (PID $observedPid, creation $observedCreation) survived termination; path `"$observedPath`"")
            }
        }
    }
}

function Reset-InstallationRoot {
    <#
    .SYNOPSIS
        Moves the system_service installation root aside to a timestamped sibling.

    .DESCRIPTION
        Never a recursive delete: the previous state stays inspectable and nothing
        half-installed is left in place. %LOCALAPPDATA%\Eliot is NEVER moved, deleted
        or edited - it holds the owner's live legacy ELIOT data.

    .OUTPUTS
        [int] The number of installation-root artifacts found (0 or 1). The caller
        owns the running total, because incrementing a script-scope counter from a
        function would silently create a child-scope copy.
    #>
    if (-not (Test-Path -LiteralPath $pdEliot)) { return 0 }

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
        return 1
    }

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
    return 1
}

function Remove-InstallerRootCredentials {
    <#
    .SYNOPSIS
        Deletes only the installer-root credential targets and never the legacy store.

    .DESCRIPTION
        `eliot/installer-root/v1/*` targets belong to the installation and are deleted.
        `eliot/store/v1/*` targets belong to the legacy Store and are NEVER deleted.
        Fail-closed (audit 5899416555): the exact cmdkey exit status is checked, the
        authoritative set is the union of the English cmdkey parse and the
        locale-independent CredEnumerateW owner API, each delete is proven by an
        authoritative re-enumeration, and a final complete enumeration must contain
        no admitted installer-root credential before this step reports clean.

    .OUTPUTS
        [int] The number of installer-root credential targets found. Unprovable
        enumeration returns 1 so the caller never reports known-empty.
    #>
    if ($SkipCredentials) { return 0 }

    $initial = Get-InstallerRootCredentialEnumeration
    if (-not $initial.Complete) {
        if ($initial.Targets.Count -eq 0) { return 1 }
    }
    if ($initial.Targets.Count -eq 0) { return 0 }

    if ($WhatIf) {
        foreach ($cred in $initial.Targets) {
            $stats.credentials++
            Write-Host "RESET: would delete credential target '$($cred.Clean)'"
        }
        return $initial.Targets.Count
    }

    foreach ($cred in $initial.Targets) {
        & cmdkey.exe /delete:$($cred.Clean) *>$null
        $deleteCode = $LASTEXITCODE
        if ($deleteCode -ne 0 -and $cred.Raw -ne $cred.Clean) {
            & cmdkey.exe /delete:$($cred.Raw) *>$null
            $deleteCode = $LASTEXITCODE
        }
        if ($deleteCode -ne 0) {
            $failures.Add("cmdkey /delete for installer-root credential '$($cred.Clean)' returned $deleteCode")
        } else {
            if (Test-InstallerRootCredentialAbsent -CleanTarget $cred.Clean) {
                $stats.credentials++
                Write-Host "RESET: deleted credential target '$($cred.Clean)'"
            } else {
                $failures.Add("installer-root credential '$($cred.Clean)' not proven absent after cmdkey /delete (re-enumeration still lists it or is incomplete)")
            }
        }
    }

    $final = Get-InstallerRootCredentialEnumeration
    if ($final.Complete -and ($final.Targets.Count -gt 0)) {
        foreach ($t in $final.Targets) {
            $failures.Add("installer-root credential '$($t.Clean)' still present after reset (final enumeration)")
        }
        return $final.Targets.Count
    }
    if (-not $final.Complete -and ($initial.Targets.Count -eq 0)) { return 1 }
    return $initial.Targets.Count
}

function Write-ResetSummary {
    <#
    .SYNOPSIS
        Reports exactly what the reset found, removed and moved.

    .DESCRIPTION
        On a clean machine nothing was found, so the reset is idempotent: this prints
        the exact "nothing to reset" line the operator and the repository checks expect,
        and the caller exits 0. Otherwise every counter is printed so a partial reset is
        visible rather than implied.

    .OUTPUTS
        [bool] $true when nothing was found, i.e. the machine was already clean.
    #>
    if ($foundCount -eq 0) {
        Write-Host "RESET: nothing to reset (machine is clean)"
        return $true
    }
    Write-Host ("RESET: found {0} machine-level artifact(s); services removed {1}, processes terminated {2}, directories moved {3}, credentials deleted {4}" -f $foundCount, $stats.services, $stats.processes, $stats.directories, $stats.credentials)
    return $false
}

# 2. Installation root (system_service installation root only).
# 3. Credentials (installer-root only; eliot/store/v1/* belongs to the legacy store and
#    is NEVER deleted).
# Each step is a named function so the Scope bullet it implements is individually
# addressable, and each returns how many artifacts it found.
$foundCount += Reset-InstallationRoot
$foundCount += Remove-InstallerRootCredentials

$machineWasClean = Write-ResetSummary

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
