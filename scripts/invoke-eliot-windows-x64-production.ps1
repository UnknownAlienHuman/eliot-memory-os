[CmdletBinding()]
param(
    [string]$UnsignedBundle,
    [string]$SignedBundle,
    [string]$SignToolPath,
    [string]$CertificateStoreLocation,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl,
    [string]$OutputBundle,
    [string]$Output,
    [string]$Store,
    [string]$Generation,
    [string]$Installation,
    [string]$LineageId,
    [UInt64]$Sequence,
    [string]$TransactionId,
    [string]$StagingRoot,
    [UInt64]$MinimumStoreAvailableBytes,
    [string]$RecoveryCommand,
    [ValidateSet('system_service', 'user_mode', 'portable_dev')]
    [string]$Profile,
    [string]$ProfileAnchorRoot,
    [string]$InstallationKey
)

$ErrorActionPreference = 'Stop'
if ($MyInvocation.InvocationName -eq '.') {
    throw 'the canonical production materialize launcher cannot be dot-sourced'
}
$script:ProductionCliSigningScope = 'runtime-materializer-six-plus-cli-pe-roles'
$script:ProductionCliSigningPolicy = 'authenticode-rfc3161'
$script:ProductionCliVerifier = 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS'
$script:ProductionCliCodeSigningEku = '1.3.6.1.5.5.7.3.3'
$script:ProductionCliTimestampAttributeOid = '1.3.6.1.4.1.311.3.3.1'
$script:ProductionCliSha256Oid = '2.16.840.1.101.3.4.2.1'
$script:ProductionInstallationContract = 'eliot.kernel.installation'
$script:ProductionInstallationContractVersion = '3.0.0'
$script:ProductionMaterializedRoles = @(
    [pscustomobject]@{ name = 'eliot-host.exe'; executable = $true }
    [pscustomobject]@{ name = 'eliot-watchdog.exe'; executable = $true }
    [pscustomobject]@{ name = 'eliot-kernel.exe'; executable = $true }
    [pscustomobject]@{ name = 'eliot-store-surreal.exe'; executable = $true }
    [pscustomobject]@{ name = 'surreal.exe'; executable = $true }
    [pscustomobject]@{ name = 'eliotd.exe'; executable = $true }
    [pscustomobject]@{ name = 'generation.json'; executable = $false }
    [pscustomobject]@{ name = 'eliotd-governor.json'; executable = $false }
    [pscustomobject]@{ name = 'eliotd.json'; executable = $false }
)

$finalizerScript = Join-Path $PSScriptRoot 'finalize-eliot-windows-x64-release.ps1'
if (-not (Test-Path -LiteralPath $finalizerScript -PathType Leaf)) {
    throw "trusted CLI launcher cannot find its release finalizer: $finalizerScript"
}
. $finalizerScript

function Initialize-EliotReleaseTrustedCliProcess {
    if ('EliotReleaseTrustedCliProcess' -as [type]) { return }
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

public sealed class EliotReleaseProcessEvidence
{
    public UInt32 ProcessId { get; set; }
    public UInt64 StartTime100ns { get; set; }
    public string ImagePath { get; set; }
}

public sealed class EliotReleaseProcessOutcome
{
    public EliotReleaseProcessEvidence PostResumeEvidence { get; set; }
    public Int32 ExitCode { get; set; }
    public string StandardOutput { get; set; }
    public string StandardError { get; set; }
}

public sealed class EliotReleaseTrustedCliProcess : IDisposable
{
    private const UInt32 CREATE_SUSPENDED = 0x00000004;
    private const UInt32 WAIT_OBJECT_0 = 0x00000000;
    private const UInt32 INFINITE = 0xffffffff;
    private const UInt32 STILL_ACTIVE = 259;
    private const UInt32 STARTF_USESTDHANDLES = 0x00000100;
    private const UInt32 HANDLE_FLAG_INHERIT = 0x00000001;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME
    {
        public UInt32 Low;
        public UInt32 High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public UInt32 nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public UInt32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public UInt16 wShowWindow;
        public UInt16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessW(
        string applicationName,
        StringBuilder commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        bool inheritHandles,
        UInt32 creationFlags,
        IntPtr environment,
        string currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process,
        UInt32 flags,
        StringBuilder imagePath,
        ref UInt32 imagePathLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(
        IntPtr process,
        out FILETIME creation,
        out FILETIME exit,
        out FILETIME kernel,
        out FILETIME user);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr process, out UInt32 exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr process, UInt32 exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out IntPtr readPipe,
        out IntPtr writePipe,
        ref SECURITY_ATTRIBUTES pipeAttributes,
        UInt32 size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(
        IntPtr handle,
        UInt32 mask,
        UInt32 flags);

    private IntPtr process;
    private IntPtr thread;
    private bool resumed;
    private bool completed;
    private bool disposed;
    private readonly UInt32 processId;
    private readonly StreamReader standardOutput;
    private readonly StreamReader standardError;
    private readonly Task<string> standardOutputRead;
    private readonly Task<string> standardErrorRead;

    private EliotReleaseTrustedCliProcess(
        PROCESS_INFORMATION information,
        StreamReader output,
        StreamReader error)
    {
        process = information.hProcess;
        thread = information.hThread;
        processId = information.dwProcessId;
        standardOutput = output;
        standardError = error;
        standardOutputRead = output.ReadToEndAsync();
        standardErrorRead = error.ReadToEndAsync();
    }

    public static EliotReleaseTrustedCliProcess CreateSuspended(
        string applicationPath,
        string[] arguments,
        string currentDirectory)
    {
        if (String.IsNullOrWhiteSpace(applicationPath) || !Path.IsPathRooted(applicationPath))
            throw new ArgumentException("applicationPath must be absolute", "applicationPath");
        if (String.IsNullOrWhiteSpace(currentDirectory) || !Path.IsPathRooted(currentDirectory))
            throw new ArgumentException("currentDirectory must be absolute", "currentDirectory");
        if (arguments == null) arguments = new string[0];

        StringBuilder commandLine = new StringBuilder();
        AppendQuotedArgument(commandLine, applicationPath);
        foreach (string argument in arguments)
        {
            commandLine.Append(' ');
            AppendQuotedArgument(commandLine, argument ?? String.Empty);
        }
        if (commandLine.Length >= 32767)
            throw new ArgumentException("trusted CLI command line exceeds the Windows limit", "arguments");

        SECURITY_ATTRIBUTES inheritable = new SECURITY_ATTRIBUTES {
            nLength = checked((UInt32)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES))),
            lpSecurityDescriptor = IntPtr.Zero,
            bInheritHandle = true
        };
        IntPtr stdoutRead = IntPtr.Zero;
        IntPtr stdoutWrite = IntPtr.Zero;
        IntPtr stderrRead = IntPtr.Zero;
        IntPtr stderrWrite = IntPtr.Zero;
        IntPtr stdinRead = IntPtr.Zero;
        IntPtr stdinWrite = IntPtr.Zero;
        PROCESS_INFORMATION information = new PROCESS_INFORMATION();
        StreamReader outputReader = null;
        StreamReader errorReader = null;
        EliotReleaseTrustedCliProcess child = null;
        try
        {
            if (!CreatePipe(out stdoutRead, out stdoutWrite, ref inheritable, 0) ||
                !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
                !CreatePipe(out stderrRead, out stderrWrite, ref inheritable, 0) ||
                !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0) ||
                !CreatePipe(out stdinRead, out stdinWrite, ref inheritable, 0) ||
                !SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "trusted CLI standard-stream pipe creation failed");

            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = checked((UInt32)Marshal.SizeOf(typeof(STARTUPINFO)));
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdInput = stdinRead;
            startup.hStdOutput = stdoutWrite;
            startup.hStdError = stderrWrite;
            if (!CreateProcessW(
                applicationPath,
                commandLine,
                IntPtr.Zero,
                IntPtr.Zero,
                true,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                currentDirectory,
                ref startup,
                out information))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "CREATE_SUSPENDED trusted CLI launch failed");
            if (information.hProcess == IntPtr.Zero || information.hThread == IntPtr.Zero ||
                information.dwProcessId == 0)
                throw new InvalidDataException("CreateProcessW returned incomplete trusted CLI handles");

            CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero;
            CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;
            CloseHandle(stdinRead); stdinRead = IntPtr.Zero;
            CloseHandle(stdinWrite); stdinWrite = IntPtr.Zero;
            outputReader = new StreamReader(
                new FileStream(new SafeFileHandle(stdoutRead, true), FileAccess.Read, 65536, false),
                new UTF8Encoding(false, true), true, 65536, false);
            stdoutRead = IntPtr.Zero;
            errorReader = new StreamReader(
                new FileStream(new SafeFileHandle(stderrRead, true), FileAccess.Read, 65536, false),
                new UTF8Encoding(false, true), true, 65536, false);
            stderrRead = IntPtr.Zero;
            child = new EliotReleaseTrustedCliProcess(information, outputReader, errorReader);
            outputReader = null;
            errorReader = null;
            information.hProcess = IntPtr.Zero;
            information.hThread = IntPtr.Zero;
            child.Observe();
            return child;
        }
        catch
        {
            if (child != null) child.Dispose();
            else
            {
                if (information.hProcess != IntPtr.Zero)
                {
                    TerminateProcess(information.hProcess, 0xe107);
                    WaitForSingleObject(information.hProcess, 5000);
                    CloseHandle(information.hProcess);
                }
                if (information.hThread != IntPtr.Zero) CloseHandle(information.hThread);
                if (outputReader != null) outputReader.Dispose();
                if (errorReader != null) errorReader.Dispose();
            }
            throw;
        }
        finally
        {
            if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
            if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
            if (stderrRead != IntPtr.Zero) CloseHandle(stderrRead);
            if (stderrWrite != IntPtr.Zero) CloseHandle(stderrWrite);
            if (stdinRead != IntPtr.Zero) CloseHandle(stdinRead);
            if (stdinWrite != IntPtr.Zero) CloseHandle(stdinWrite);
        }
    }

    public EliotReleaseProcessEvidence Observe()
    {
        ThrowIfDisposed();
        FILETIME creation;
        FILETIME exit;
        FILETIME kernel;
        FILETIME user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "trusted CLI process start-time readback failed");
        UInt64 startTime = ((UInt64)creation.High << 32) | creation.Low;
        if (startTime == 0)
            throw new InvalidDataException("trusted CLI process start time is zero");
        StringBuilder path = new StringBuilder(32768);
        UInt32 length = checked((UInt32)path.Capacity);
        if (!QueryFullProcessImageNameW(process, 0, path, ref length) || length == 0 || length >= path.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "trusted CLI process image readback failed");
        return new EliotReleaseProcessEvidence {
            ProcessId = processId,
            StartTime100ns = startTime,
            ImagePath = path.ToString()
        };
    }

    public EliotReleaseProcessOutcome ResumeAndWait()
    {
        ThrowIfDisposed();
        if (resumed) throw new InvalidOperationException("trusted CLI process was already resumed");
        EliotReleaseProcessEvidence before = Observe();
        UInt32 previousSuspendCount = ResumeThread(thread);
        if (previousSuspendCount == UInt32.MaxValue || previousSuspendCount != 1)
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "trusted CLI ResumeThread did not consume exactly one suspension");
        resumed = true;
        EliotReleaseProcessEvidence after = Observe();
        if (before.ProcessId != after.ProcessId ||
            before.StartTime100ns != after.StartTime100ns ||
            !String.Equals(before.ImagePath, after.ImagePath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("trusted CLI process identity changed across ResumeThread");
        if (WaitForSingleObject(process, INFINITE) != WAIT_OBJECT_0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "trusted CLI wait failed");
        UInt32 exitCode;
        if (!GetExitCodeProcess(process, out exitCode) || exitCode == STILL_ACTIVE)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "trusted CLI exit-code readback failed");
        string stdout = standardOutputRead.GetAwaiter().GetResult();
        string stderr = standardErrorRead.GetAwaiter().GetResult();
        if (stdout.Length > 4 * 1024 * 1024 || stderr.Length > 4 * 1024 * 1024)
            throw new InvalidDataException("trusted CLI output exceeded the bounded capture limit");
        completed = true;
        return new EliotReleaseProcessOutcome {
            PostResumeEvidence = after,
            ExitCode = unchecked((Int32)exitCode),
            StandardOutput = stdout,
            StandardError = stderr
        };
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        if (process != IntPtr.Zero && !completed)
        {
            TerminateProcess(process, 0xe107);
            WaitForSingleObject(process, 5000);
        }
        if (thread != IntPtr.Zero)
        {
            CloseHandle(thread);
            thread = IntPtr.Zero;
        }
        if (process != IntPtr.Zero)
        {
            CloseHandle(process);
            process = IntPtr.Zero;
        }
        standardOutput.Dispose();
        standardError.Dispose();
    }

    private void ThrowIfDisposed()
    {
        if (disposed || process == IntPtr.Zero || thread == IntPtr.Zero)
            throw new ObjectDisposedException("EliotReleaseTrustedCliProcess");
    }

    private static void AppendQuotedArgument(StringBuilder commandLine, string argument)
    {
        if (argument.IndexOf('\0') >= 0)
            throw new ArgumentException("trusted CLI argument contains a NUL character", "argument");
        bool quote = argument.Length == 0 || argument.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) >= 0;
        if (!quote)
        {
            commandLine.Append(argument);
            return;
        }
        commandLine.Append('"');
        int backslashes = 0;
        foreach (char value in argument)
        {
            if (value == '\\')
            {
                backslashes++;
                continue;
            }
            if (value == '"')
            {
                commandLine.Append('\\', backslashes * 2 + 1);
                commandLine.Append('"');
                backslashes = 0;
                continue;
            }
            if (backslashes > 0)
            {
                commandLine.Append('\\', backslashes);
                backslashes = 0;
            }
            commandLine.Append(value);
        }
        if (backslashes > 0) commandLine.Append('\\', backslashes * 2);
        commandLine.Append('"');
    }
}
'@
}

function Get-Utf8StringSha256([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-ExactWindowsPath([string]$Left, [string]$Right) {
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd('\')
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd('\')
    return [string]::Equals($leftPath, $rightPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Assert-ProductionScalar([string]$Value, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.IndexOf([char]0) -ge 0 -or
        $Value -match '[\r\n]') {
        throw "$Purpose must be nonblank and free of control/newline characters"
    }
    return $Value
}

function Assert-ProductionAbsentPath([string]$Path, [string]$Purpose) {
    $resolved = Get-FullyQualifiedWindowsPath $Path $Purpose
    if ([System.IO.File]::Exists($resolved) -or [System.IO.Directory]::Exists($resolved)) {
        throw "$Purpose must be an absent create-new path: $resolved"
    }
    $parent = Split-Path -Parent $resolved
    [void](Assert-ExistingBundleDirectory $parent "$Purpose parent")
    return $resolved
}

function Assert-PathOutsideBundle([string]$Path, [string]$Bundle, [string]$Purpose) {
    $candidate = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $root = [System.IO.Path]::GetFullPath($Bundle).TrimEnd('\')
    if ([string]::Equals($candidate, $root, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidate.StartsWith("$root\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Purpose must be outside the immutable release bundle: $root"
    }
}

function New-ProductionMaterializeContract {
    param(
        [string]$UnsignedBundlePath,
        [string]$SignedBundlePath,
        [string]$OutputBundlePath,
        [string]$OutputPath,
        [string]$StorePath,
        [string]$GenerationValue,
        [string]$InstallationValue,
        [string]$LineageIdValue,
        [UInt64]$SequenceValue,
        [string]$TransactionIdValue,
        [string]$StagingRootPath,
        [UInt64]$MinimumStoreAvailableBytesValue,
        [string]$RecoveryCommandValue,
        [string]$ProfileValue,
        [string]$ProfileAnchorRootPath,
        [string]$InstallationKeyValue
    )
    $unsigned = Assert-ExistingBundleDirectory $UnsignedBundlePath 'UnsignedBundle'
    $signed = Assert-ExistingBundleDirectory $SignedBundlePath 'SignedBundle'
    $outputBundlePath = Assert-ProductionAbsentPath $OutputBundlePath 'OutputBundle'
    $outputPath = Assert-ProductionAbsentPath $OutputPath 'Output'
    $storePath = Assert-ProductionAbsentPath $StorePath 'Store'
    $staging = Assert-ExistingBundleDirectory $StagingRootPath 'StagingRoot'
    $anchor = Assert-ExistingBundleDirectory $ProfileAnchorRootPath 'ProfileAnchorRoot'
    foreach ($candidate in @($outputBundlePath, $outputPath, $storePath)) {
        Assert-PathOutsideBundle $candidate $unsigned 'materialize output'
        Assert-PathOutsideBundle $candidate $signed 'materialize output'
    }
    $uniqueOutputs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($candidate in @($outputBundlePath, $outputPath, $storePath)) {
        if (-not $uniqueOutputs.Add($candidate.TrimEnd('\'))) {
            throw 'OutputBundle, Output, and Store must be three distinct create-new paths'
        }
    }
    if ($SequenceValue -eq 0) { throw 'Sequence must be non-zero' }
    if ($MinimumStoreAvailableBytesValue -eq 0) {
        throw 'MinimumStoreAvailableBytes must be non-zero'
    }
    $generation = Assert-ProductionScalar $GenerationValue 'Generation'
    if ([System.IO.Path]::IsPathRooted($generation) -or
        @($generation -split '[\\/]').Where({ $_ -eq '.' -or $_ -eq '..' -or $_ -eq '' }).Count -ne 0) {
        throw 'Generation must be a canonical non-traversing relative identity'
    }
    $profile = Assert-ProductionScalar $ProfileValue 'Profile'
    if ($profile -notin @('system_service', 'user_mode', 'portable_dev')) {
        throw 'Profile must be system_service, user_mode, or portable_dev'
    }
    $installationKey = $null
    if (-not [string]::IsNullOrWhiteSpace($InstallationKeyValue)) {
        if ($InstallationKeyValue -cnotmatch '^[0-9a-f]{64}$') {
            throw 'InstallationKey must be an exact lowercase SHA-256 when supplied'
        }
        $installationKey = $InstallationKeyValue
    }
    elseif ($profile -ne 'portable_dev') {
        throw 'InstallationKey is required for system_service and user_mode profiles'
    }
    return [pscustomobject]@{
        unsigned_bundle = $unsigned
        signed_bundle = $signed
        output_bundle = $outputBundlePath
        output = $outputPath
        store = $storePath
        generation = $generation
        installation = Assert-ProductionScalar $InstallationValue 'Installation'
        lineage_id = Assert-ProductionScalar $LineageIdValue 'LineageId'
        sequence = [UInt64]$SequenceValue
        transaction_id = Assert-ProductionScalar $TransactionIdValue 'TransactionId'
        staging_root = $staging
        minimum_store_available_bytes = [UInt64]$MinimumStoreAvailableBytesValue
        recovery_command = Assert-ProductionScalar $RecoveryCommandValue 'RecoveryCommand'
        profile = $profile
        profile_anchor_root = $anchor
        installation_key = $installationKey
    }
}

function Assert-ProductionMaterializeOutputsAbsent([object]$Contract, [string]$Purpose) {
    foreach ($definition in @(
            [pscustomobject]@{ name = 'OutputBundle'; path = [string]$Contract.output_bundle }
            [pscustomobject]@{ name = 'Output'; path = [string]$Contract.output }
            [pscustomobject]@{ name = 'Store'; path = [string]$Contract.store }
        )) {
        if ([System.IO.File]::Exists($definition.path) -or
            [System.IO.Directory]::Exists($definition.path)) {
            throw "$Purpose observed non-create-new $($definition.name): $($definition.path)"
        }
    }
}

function Get-PinnedCliObservation([object]$Handle, [string]$ExpectedPath) {
    if (-not $Handle -or $Handle.IsInvalid -or $Handle.IsClosed) {
        throw 'trusted CLI retained file handle is unavailable'
    }
    $path = [EliotReleaseNativeFileSystem]::ReadFinalPath($Handle)
    $identity = [EliotReleaseNativeFileSystem]::ReadIdentity($Handle)
    $digest = [EliotReleaseNativeFileSystem]::ReadSha256AndSize($Handle)
    if (-not (Test-ExactWindowsPath $path $ExpectedPath) -or
        [uint64]$identity.FileIndex -eq 0 -or [uint32]$identity.NumberOfLinks -ne 1) {
        throw 'trusted CLI retained path/file identity is not exact'
    }
    return [pscustomobject]@{
        path = [System.IO.Path]::GetFullPath($ExpectedPath)
        volume_serial_number = [uint32]$identity.VolumeSerialNumber
        file_index = [uint64]$identity.FileIndex
        bytes = [int64]$digest.Bytes
        sha256 = [string]$digest.Sha256
    }
}

function Test-PinnedCliObservationEqual([object]$Left, [object]$Right) {
    return $Left -and $Right -and
        (Test-ExactWindowsPath ([string]$Left.path) ([string]$Right.path)) -and
        [uint32]$Left.volume_serial_number -eq [uint32]$Right.volume_serial_number -and
        [uint64]$Left.file_index -eq [uint64]$Right.file_index -and
        [int64]$Left.bytes -eq [int64]$Right.bytes -and
        [string]$Left.sha256 -ceq [string]$Right.sha256
}

function New-TrustedSignedRolePins([string]$SignedBundlePath) {
    $pins = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($definition in @(Get-AuthenticodeRoleDefinitions)) {
            $path = Join-Path $SignedBundlePath ([string]$definition.path).Replace('/', '\')
            $handle = [EliotReleaseNativeFileSystem]::OpenFileReadFence($path)
            try {
                [void]$pins.Add([pscustomobject]@{
                        role = [string]$definition.role
                        role_path = ([string]$definition.path).Replace('\', '/')
                        path = [System.IO.Path]::GetFullPath($path)
                        handle = $handle
                        observation = Get-PinnedCliObservation $handle $path
                    })
                $handle = $null
            }
            finally {
                if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
            }
        }
        if ($pins.Count -ne 7) { throw 'trusted release role pin inventory is not exactly seven' }
        return ,@($pins)
    }
    catch {
        foreach ($pin in $pins) {
            if ($pin.handle -and -not $pin.handle.IsClosed) { $pin.handle.Dispose() }
        }
        throw
    }
}

function Assert-TrustedSignedRolePins([object[]]$Pins, [string]$Purpose) {
    if (-not $Pins -or $Pins.Count -ne 7) {
        throw "$Purpose retained signed-role set is incomplete"
    }
    foreach ($pin in $Pins) {
        $current = Get-PinnedCliObservation $pin.handle ([string]$pin.path)
        if (-not (Test-PinnedCliObservationEqual $pin.observation $current)) {
            throw "$Purpose retained signed role changed: $($pin.role_path)"
        }
    }
}

function Close-TrustedSignedRolePins([object[]]$Pins) {
    if (-not $Pins) { return }
    foreach ($pin in $Pins) {
        if ($pin.handle -and -not $pin.handle.IsClosed) { $pin.handle.Dispose() }
    }
}

function Get-TrustedSignedRolePin([object[]]$Pins, [string]$Role) {
    $matches = @($Pins | Where-Object { [string]$_.role -ceq $Role })
    if ($matches.Count -ne 1) { throw "trusted signed role is missing or duplicated: $Role" }
    return $matches[0]
}

function New-TrustedCliDirectoryPins([string]$RuntimeDirectory) {
    $pins = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    try {
        $current = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($RuntimeDirectory))
        while ($current) {
            if ($seen.Add($current.FullName)) {
                [void]$pins.Add((New-NativeDirectoryPin $current.FullName $false))
            }
            $current = $current.Parent
        }
        return ,@($pins)
    }
    catch {
        for ($index = $pins.Count - 1; $index -ge 0; $index--) {
            Close-NativeDirectoryPin $pins[$index]
        }
        throw
    }
}

function Assert-TrustedCliDirectoryPins([object[]]$Pins, [string]$Purpose) {
    if (-not $Pins -or $Pins.Count -lt 2) {
        throw "$Purpose retained directory chain is incomplete"
    }
    foreach ($pin in $Pins) {
        Assert-NativeDirectoryPin $pin $Purpose
    }
}

function Close-TrustedCliDirectoryPins([object[]]$Pins) {
    if (-not $Pins) { return }
    for ($index = $Pins.Count - 1; $index -ge 0; $index--) {
        Close-NativeDirectoryPin $Pins[$index]
    }
}

function New-TrustedCliManifestPins([string]$SignedBundlePath) {
    $definitions = @(
        [pscustomobject]@{ name = 'release'; path = (Join-Path $SignedBundlePath 'RELEASE.json') }
        [pscustomobject]@{ name = 'runtime'; path = (Join-Path $SignedBundlePath 'runtime\RUNTIME_ARTIFACTS.json') }
        [pscustomobject]@{ name = 'checksums'; path = (Join-Path $SignedBundlePath 'SHA256SUMS.json') }
        [pscustomobject]@{ name = 'verified'; path = (Join-Path $SignedBundlePath 'SIGNING_VERIFIED.json') }
    )
    $pins = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($definition in $definitions) {
            $handle = [EliotReleaseNativeFileSystem]::OpenFileReadFence([string]$definition.path)
            try {
                $observation = Get-PinnedCliObservation $handle ([string]$definition.path)
                $text = [EliotReleaseNativeFileSystem]::ReadUtf8Text($handle)
                [void]$pins.Add([pscustomobject]@{
                        name = [string]$definition.name
                        path = [string]$definition.path
                        handle = $handle
                        observation = $observation
                        text = $text
                    })
                $handle = $null
            }
            finally {
                if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
            }
        }
        return ,@($pins)
    }
    catch {
        foreach ($pin in $pins) {
            if ($pin.handle -and -not $pin.handle.IsClosed) { $pin.handle.Dispose() }
        }
        throw
    }
}

function Assert-TrustedCliManifestPins([object[]]$Pins, [string]$Purpose) {
    if (-not $Pins -or $Pins.Count -ne 4) {
        throw "$Purpose retained manifest set is incomplete"
    }
    foreach ($pin in $Pins) {
        $observation = Get-PinnedCliObservation $pin.handle ([string]$pin.path)
        $text = [EliotReleaseNativeFileSystem]::ReadUtf8Text($pin.handle)
        if (-not (Test-PinnedCliObservationEqual $pin.observation $observation) -or
            [string]$pin.text -cne [string]$text) {
            throw "$Purpose retained manifest changed: $($pin.name)"
        }
    }
}

function Close-TrustedCliManifestPins([object[]]$Pins) {
    if (-not $Pins) { return }
    foreach ($pin in $Pins) {
        if ($pin.handle -and -not $pin.handle.IsClosed) { $pin.handle.Dispose() }
    }
}

function Get-TrustedCliManifestTexts([object[]]$Pins) {
    $texts = [ordered]@{}
    foreach ($pin in $Pins) {
        if ($texts.Contains([string]$pin.name)) {
            throw "trusted CLI retained manifest is duplicated: $($pin.name)"
        }
        $texts[[string]$pin.name] = [string]$pin.text
    }
    return [pscustomobject]$texts
}

function Get-VerifiedSignedRoleManifestBinding(
    [string]$SignedBundlePath,
    [string]$RoleName,
    [string]$RolePath,
    [object]$PinnedObservation,
    [object]$PinnedManifestTexts,
    [object]$Verification,
    [string]$ExpectedThumbprint,
    [string]$ExpectedTimestampUrl
) {
    $bundle = Assert-ExistingBundleDirectory $SignedBundlePath 'SignedBundle'
    $normalizedRolePath = $RolePath.Replace('\', '/')
    if (-not $Verification -or [string]$Verification.status -cne 'VERIFIED_SIGNED' -or
        [string]$Verification.verification_kind -cne 'READ_ONLY_SNAPSHOT' -or
        $Verification.durable_install_authority -ne $false -or
        [string]$Verification.signed_scope -cne $script:ProductionCliSigningScope -or
        [int]$Verification.roles -ne 7 -or
        -not (Test-ExactWindowsPath ([string]$Verification.bundle) $bundle)) {
        throw 'trusted CLI launch requires the exact seven-role public bundle verification result'
    }

    if (-not $PinnedManifestTexts) {
        throw 'trusted CLI launch requires retained signed-manifest bytes'
    }
    $release = [string]$PinnedManifestTexts.release | ConvertFrom-Json
    $runtime = [string]$PinnedManifestTexts.runtime | ConvertFrom-Json
    $checksums = [string]$PinnedManifestTexts.checksums | ConvertFrom-Json
    $verified = [string]$PinnedManifestTexts.verified | ConvertFrom-Json
    foreach ($manifest in @($release, $runtime, $checksums)) {
        if ($manifest.signed -ne $true -or
            [string]$manifest.signature_policy -cne $script:ProductionCliSigningPolicy -or
            [string]$manifest.signed_scope -cne $script:ProductionCliSigningScope) {
            throw 'trusted CLI launch observed a manifest outside the exact signed boundary'
        }
    }

    $releaseArtifact = @($release.runtime_artifacts | Where-Object {
            ([string]$_.path).Replace('\', '/') -ceq $normalizedRolePath -and
            [string]$_.role -ceq $RoleName
        })
    $runtimeArtifact = @($runtime.artifacts | Where-Object {
            ([string]$_.path).Replace('\', '/') -ceq $normalizedRolePath -and
            [string]$_.role -ceq $RoleName
        })
    $checksumEntry = @($checksums.files | Where-Object {
            ([string]$_.path).Replace('\', '/') -ceq $normalizedRolePath
        })
    $roleReceipt = @($release.signature_evidence.roles | Where-Object {
            ([string]$_.role_path).Replace('\', '/') -ceq $normalizedRolePath -and
            [string]$_.role -ceq $RoleName
        })
    if ($releaseArtifact.Count -ne 1 -or $runtimeArtifact.Count -ne 1 -or
        $checksumEntry.Count -ne 1 -or $roleReceipt.Count -ne 1) {
        throw 'trusted CLI signed artifact/hash/receipt binding is missing or duplicated'
    }

    $receiptJson = [string]($roleReceipt[0] | ConvertTo-Json -Depth 12 -Compress)
    $globalEvidenceJson = [string]($release.signature_evidence | ConvertTo-Json -Depth 12 -Compress)
    if ($globalEvidenceJson -cne [string]($runtime.signature_evidence | ConvertTo-Json -Depth 12 -Compress) -or
        $globalEvidenceJson -cne [string]($checksums.signature_evidence | ConvertTo-Json -Depth 12 -Compress) -or
        $globalEvidenceJson -cne [string]($verified.signature_evidence | ConvertTo-Json -Depth 12 -Compress) -or
        $receiptJson -cne [string]($releaseArtifact[0].signature_evidence | ConvertTo-Json -Depth 12 -Compress) -or
        $receiptJson -cne [string]($runtimeArtifact[0].signature_evidence | ConvertTo-Json -Depth 12 -Compress)) {
        throw 'trusted CLI signature evidence is not exactly repeated across signed manifests'
    }

    $thumbprint = Get-NormalizedThumbprint $ExpectedThumbprint 'CertificateThumbprint'
    $timestampUrl = (Assert-ExplicitRfc3161TimestampUrl $ExpectedTimestampUrl)
    if ([string]$release.signature_evidence.signer.thumbprint -cne $thumbprint -or
        [string]$release.signature_evidence.signer.code_signing_eku -cne $script:ProductionCliCodeSigningEku -or
        [string]$release.signature_evidence.timestamp.url -cne $timestampUrl -or
        [string]$release.signature_evidence.timestamp.protocol -cne 'RFC3161' -or
        [string]$roleReceipt[0].status -cne 'Valid' -or
        [string]$roleReceipt[0].signer_thumbprint -cne $thumbprint -or
        $roleReceipt[0].timestamped -ne $true -or
        [string]$roleReceipt[0].timestamp_url -cne $timestampUrl -or
        [string]$roleReceipt[0].timestamp_protocol -cne 'RFC3161' -or
        [string]$roleReceipt[0].timestamp_attribute_oid -cne $script:ProductionCliTimestampAttributeOid -or
        [string]$roleReceipt[0].timestamp_message_imprint_algorithm_oid -cne $script:ProductionCliSha256Oid -or
        $roleReceipt[0].timestamp_cms_signature_valid -ne $true -or
        [int]$roleReceipt[0].signtool_verify_exit_code -ne 0 -or
        [string]$roleReceipt[0].signtool_verify_policy -cne '/pa /all /v /tw' -or
        [string]$roleReceipt[0].verifier -cne $script:ProductionCliVerifier) {
        throw 'trusted CLI signer/EKU/RFC3161 public-readback binding is malformed'
    }

    foreach ($artifact in @($releaseArtifact[0], $runtimeArtifact[0], $checksumEntry[0])) {
        if ([string]$artifact.sha256 -cne [string]$PinnedObservation.sha256 -or
            [int64]$artifact.bytes -ne [int64]$PinnedObservation.bytes) {
            throw 'trusted CLI retained bytes do not match the signed release inventory'
        }
    }

    return [pscustomobject]@{
        role = $RoleName
        role_path = $normalizedRolePath
        sha256 = [string]$PinnedObservation.sha256
        bytes = [int64]$PinnedObservation.bytes
        signer_thumbprint = $thumbprint
        signer_subject = [string]$roleReceipt[0].signer_subject
        code_signing_eku = $script:ProductionCliCodeSigningEku
        timestamp_url = $timestampUrl
        timestamp_protocol = 'RFC3161'
        timestamp_message_imprint = [string]$roleReceipt[0].timestamp_message_imprint
        timestamp_message_imprint_algorithm_oid = $script:ProductionCliSha256Oid
        timestamp_certificate_thumbprint = [string]$roleReceipt[0].timestamp_certificate_thumbprint
        signature_evidence_sha256 = Get-Utf8StringSha256 $globalEvidenceJson
    }
}

function Get-VerifiedSignedRoleManifestBindings(
    [string]$SignedBundlePath,
    [object[]]$RolePins,
    [object]$PinnedManifestTexts,
    [object]$Verification,
    [string]$ExpectedThumbprint,
    [string]$ExpectedTimestampUrl
) {
    $bindings = [System.Collections.Generic.List[object]]::new()
    foreach ($pin in $RolePins) {
        [void]$bindings.Add((Get-VerifiedSignedRoleManifestBinding `
                    $SignedBundlePath `
                    ([string]$pin.role) `
                    ([string]$pin.role_path) `
                    $pin.observation `
                    $PinnedManifestTexts `
                    $Verification `
                    $ExpectedThumbprint `
                    $ExpectedTimestampUrl))
    }
    if ($bindings.Count -ne 7) { throw 'signed role binding inventory is not exactly seven' }
    return ,@($bindings)
}

function New-ProductionMaterializePathPins([object]$Contract) {
    $paths = @(
        (Split-Path -Parent ([string]$Contract.output_bundle)),
        (Split-Path -Parent ([string]$Contract.output)),
        (Split-Path -Parent ([string]$Contract.store)),
        [string]$Contract.staging_root,
        [string]$Contract.profile_anchor_root
    )
    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $pins = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($path in $paths) {
            $resolved = [System.IO.Path]::GetFullPath($path).TrimEnd('\')
            if ($seen.Add($resolved)) {
                [void]$pins.Add((New-NativeDirectoryPin $resolved $false))
            }
        }
        return ,@($pins)
    }
    catch {
        foreach ($pin in $pins) { Close-NativeDirectoryPin $pin }
        throw
    }
}

function Assert-ProductionMaterializePathPins([object[]]$Pins, [string]$Purpose) {
    if (-not $Pins) { throw "$Purpose retained materialize path set is empty" }
    foreach ($pin in $Pins) { Assert-NativeDirectoryPin $pin $Purpose }
}

function Close-ProductionMaterializePathPins([object[]]$Pins) {
    if (-not $Pins) { return }
    for ($index = $Pins.Count - 1; $index -ge 0; $index--) {
        Close-NativeDirectoryPin $Pins[$index]
    }
}

function New-ProductionMaterializeArguments([object]$Contract, [object[]]$RolePins) {
    $hostRole = Get-TrustedSignedRolePin $RolePins 'host'
    $watchdog = Get-TrustedSignedRolePin $RolePins 'watchdog'
    $kernel = Get-TrustedSignedRolePin $RolePins 'kernel'
    $storeBridge = Get-TrustedSignedRolePin $RolePins 'store_bridge'
    $database = Get-TrustedSignedRolePin $RolePins 'database'
    $daemon = Get-TrustedSignedRolePin $RolePins 'daemon'
    $arguments = [System.Collections.Generic.List[string]]::new()
    foreach ($value in @(
            'installation', 'materialize-source-bundle',
            '--eliot-host', [string]$hostRole.path,
            '--eliot-watchdog', [string]$watchdog.path,
            '--eliot-kernel', [string]$kernel.path,
            '--eliot-store-surreal', [string]$storeBridge.path,
            '--surreal', [string]$database.path,
            '--eliotd', [string]$daemon.path,
            '--output-bundle', [string]$Contract.output_bundle,
            '--output', [string]$Contract.output,
            '--store', [string]$Contract.store,
            '--generation', [string]$Contract.generation,
            '--installation', [string]$Contract.installation,
            '--lineage-id', [string]$Contract.lineage_id,
            '--sequence', ([UInt64]$Contract.sequence).ToString([Globalization.CultureInfo]::InvariantCulture),
            '--transaction-id', [string]$Contract.transaction_id,
            '--staging-root', [string]$Contract.staging_root,
            '--minimum-store-available-bytes', ([UInt64]$Contract.minimum_store_available_bytes).ToString([Globalization.CultureInfo]::InvariantCulture),
            '--recovery-command', [string]$Contract.recovery_command,
            '--profile', [string]$Contract.profile,
            '--profile-anchor-root', [string]$Contract.profile_anchor_root
        )) {
        [void]$arguments.Add([string]$value)
    }
    if ($Contract.installation_key) {
        [void]$arguments.Add('--installation-key')
        [void]$arguments.Add([string]$Contract.installation_key)
    }
    return @($arguments)
}

function ConvertFrom-ProductionJsonObjectStream([string]$Text) {
    if ($null -eq $Text) { throw 'materialize child stdout is unavailable' }
    $objects = [System.Collections.Generic.List[object]]::new()
    $start = -1
    $depth = 0
    $inString = $false
    $escaped = $false
    for ($index = 0; $index -lt $Text.Length; $index++) {
        $character = $Text[$index]
        if ($depth -eq 0) {
            if ([char]::IsWhiteSpace($character)) { continue }
            if ($character -ne '{') {
                throw 'materialize child stdout contains non-JSON or a non-object value'
            }
            $start = $index
            $depth = 1
            $inString = $false
            $escaped = $false
            continue
        }
        if ($inString) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') { $inString = $false }
            continue
        }
        if ($character -eq '"') { $inString = $true; continue }
        if ($character -eq '{') { $depth++; continue }
        if ($character -eq '}') {
            $depth--
            if ($depth -eq 0) {
                $json = $Text.Substring($start, $index - $start + 1)
                try { [void]$objects.Add(($json | ConvertFrom-Json -ErrorAction Stop)) }
                catch { throw "materialize child emitted invalid JSON: $($_.Exception.Message)" }
                $start = -1
            }
        }
    }
    if ($depth -ne 0 -or $inString) { throw 'materialize child stdout ended inside a JSON object' }
    return @($objects)
}

function Assert-ProductionMaterializeReceipt(
    [object]$Contract,
    [object]$ProcessOutcome
) {
    if (-not $ProcessOutcome -or [int]$ProcessOutcome.ExitCode -ne 0) {
        throw "materialize child did not exit successfully: $([int]$ProcessOutcome.ExitCode)"
    }
    if (-not [string]::IsNullOrWhiteSpace([string]$ProcessOutcome.StandardError)) {
        throw 'materialize child emitted stderr on a claimed successful handoff'
    }
    $objects = @(ConvertFrom-ProductionJsonObjectStream ([string]$ProcessOutcome.StandardOutput))
    if ($objects.Count -ne 2) {
        throw 'materialize child success requires exactly GENERATED then SOURCE_BUNDLE_MATERIALIZED'
    }
    $generated = $objects[0]
    $materialized = $objects[1]
    if ([string]$generated.contract -cne $script:ProductionInstallationContract -or
        [string]$generated.contract_version -cne $script:ProductionInstallationContractVersion -or
        [string]$generated.status -cne 'GENERATED' -or
        [string]$generated.transaction_id -cne [string]$Contract.transaction_id -or
        [string]$generated.generation -cne [string]$Contract.generation -or
        -not (Test-ExactWindowsPath ([string]$generated.output) ([string]$Contract.output)) -or
        -not (Test-ExactWindowsPath ([string]$generated.store) ([string]$Contract.store)) -or
        $generated.source_publication_bound -ne $true -or
        [string]$generated.durable_authority -cne 'DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID' -or
        [string]$generated.output_role -cne 'DIAGNOSTIC_NON_IMPORTABLE') {
        throw 'GENERATED receipt is not bound to the exact typed materialize transaction/output/store'
    }
    if ([string]$materialized.contract -cne $script:ProductionInstallationContract -or
        [string]$materialized.contract_version -cne $script:ProductionInstallationContractVersion -or
        [string]$materialized.status -cne 'SOURCE_BUNDLE_MATERIALIZED' -or
        [string]$materialized.handoff -cne 'SOURCE_PUBLICATION_BOUND_TO_GENERATED_PLAN' -or
        [string]$materialized.transaction_id -cne [string]$Contract.transaction_id -or
        [string]$materialized.generation -cne [string]$Contract.generation -or
        -not (Test-ExactWindowsPath ([string]$materialized.output) ([string]$Contract.output)) -or
        -not (Test-ExactWindowsPath ([string]$materialized.store) ([string]$Contract.store)) -or
        -not (Test-ExactWindowsPath ([string]$materialized.bundle_path) ([string]$Contract.output_bundle)) -or
        [string]$materialized.durable_authority -cne 'DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID' -or
        [string]$materialized.output_role -cne 'DIAGNOSTIC_NON_IMPORTABLE' -or
        [int]$materialized.file_count -ne 9 -or @($materialized.files).Count -ne 9) {
        throw 'SOURCE_BUNDLE_MATERIALIZED receipt is not bound to the exact typed handoff'
    }
    return [pscustomobject]@{ generated = $generated; materialized = $materialized }
}

function Get-ProductionMaterializeReadback([object]$Contract, [object]$Receipt) {
    $outputHandle = $null
    $storeHandle = $null
    $bundlePin = $null
    $roleHandles = [System.Collections.Generic.List[object]]::new()
    try {
        $outputHandle = [EliotReleaseNativeFileSystem]::OpenFileReadFence([string]$Contract.output)
        $storeHandle = [EliotReleaseNativeFileSystem]::OpenFileReadFence([string]$Contract.store)
        $outputObservation = Get-PinnedCliObservation $outputHandle ([string]$Contract.output)
        $storeObservation = Get-PinnedCliObservation $storeHandle ([string]$Contract.store)
        $outputJson = [EliotReleaseNativeFileSystem]::ReadUtf8Text($outputHandle) | ConvertFrom-Json -ErrorAction Stop
        if ([string]$outputJson.transaction_id -cne [string]$Contract.transaction_id) {
            throw 'diagnostic transaction output is not bound to the requested transaction id'
        }
        $bundlePin = New-NativeDirectoryPin ([string]$Contract.output_bundle) $false
        $directoryFacts = @(
            $Receipt.materialized.source_identity,
            $Receipt.materialized.directory_publication.source_identity,
            $Receipt.materialized.directory_publication.destination_identity)
        foreach ($fact in $directoryFacts) {
            if (-not $fact -or
                [uint32]$fact.volume_serial_number -ne [uint32]$bundlePin.identity.VolumeSerialNumber -or
                [uint64]$fact.file_index -ne [uint64]$bundlePin.identity.FileIndex) {
                throw 'materialized bundle directory identity differs from its final receipt'
            }
        }
        $receiptFiles = @($Receipt.materialized.files)
        for ($index = 0; $index -lt $script:ProductionMaterializedRoles.Count; $index++) {
            $definition = $script:ProductionMaterializedRoles[$index]
            $fact = $receiptFiles[$index]
            if ([string]$fact.relative_path -cne [string]$definition.name -or
                [bool]$fact.executable -ne [bool]$definition.executable) {
                throw 'materialized nine-role receipt is missing, reordered, or substituted'
            }
            $rolePath = Join-Path ([string]$Contract.output_bundle) ([string]$definition.name)
            $handle = [EliotReleaseNativeFileSystem]::OpenFileReadFence($rolePath)
            try {
                $observed = Get-PinnedCliObservation $handle $rolePath
                if ([int64]$fact.size -ne [int64]$observed.bytes -or
                    [string]$fact.sha256 -cne [string]$observed.sha256 -or
                    -not $fact.destination_identity -or
                    [uint32]$fact.destination_identity.volume_serial_number -ne [uint32]$observed.volume_serial_number -or
                    [uint64]$fact.destination_identity.file_index -ne [uint64]$observed.file_index -or
                    ([bool]$definition.executable -and (-not $fact.pe -or -not $fact.authenticode)) -or
                    (-not [bool]$definition.executable -and ($fact.pe -or $fact.authenticode))) {
                    throw "materialized role readback differs from receipt: $($definition.name)"
                }
                [void]$roleHandles.Add([pscustomobject]@{ handle = $handle; observation = $observed })
                $handle = $null
            }
            finally {
                if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
            }
        }
        return [pscustomobject]@{
            output = $outputObservation
            store = $storeObservation
            bundle = [pscustomobject]@{
                path = [string]$bundlePin.path
                volume_serial_number = [uint32]$bundlePin.identity.VolumeSerialNumber
                file_index = [uint64]$bundlePin.identity.FileIndex
            }
            roles = @($roleHandles | ForEach-Object { $_.observation })
        }
    }
    finally {
        foreach ($item in $roleHandles) {
            if ($item.handle -and -not $item.handle.IsClosed) { $item.handle.Dispose() }
        }
        if ($bundlePin) { Close-NativeDirectoryPin $bundlePin }
        if ($storeHandle -and -not $storeHandle.IsClosed) { $storeHandle.Dispose() }
        if ($outputHandle -and -not $outputHandle.IsClosed) { $outputHandle.Dispose() }
    }
}

function Invoke-ProductionEliotMaterializeSourceBundle {
    param(
        [Parameter(Mandatory = $true)][object]$Contract,
        [Parameter(Mandatory = $true)][string]$SignTool,
        [Parameter(Mandatory = $true)][string]$StoreLocation,
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$Rfc3161Url
    )
    $signed = Assert-ExistingBundleDirectory ([string]$Contract.signed_bundle) 'SignedBundle'
    $runtimeDirectory = Join-Path $signed 'runtime'
    $directoryPins = $null
    $manifestPins = $null
    $rolePins = $null
    $materializePathPins = $null
    $process = $null
    try {
        $directoryPins = New-TrustedCliDirectoryPins $runtimeDirectory
        $manifestPins = New-TrustedCliManifestPins $signed
        $rolePins = New-TrustedSignedRolePins $signed
        $materializePathPins = New-ProductionMaterializePathPins $Contract
        $cliPin = Get-TrustedSignedRolePin $rolePins 'cli'
        $cliPath = [string]$cliPin.path
        $pinned = $cliPin.observation
        $manifestTexts = Get-TrustedCliManifestTexts $manifestPins
        Assert-TrustedCliDirectoryPins $directoryPins 'trusted CLI path before verification'
        Assert-TrustedCliManifestPins $manifestPins 'trusted CLI evidence before verification'
        Assert-TrustedSignedRolePins $rolePins 'trusted release before verification'
        Assert-ProductionMaterializePathPins $materializePathPins 'materialize paths before verification'
        Assert-ProductionMaterializeOutputsAbsent $Contract 'materialize preflight'

        $plan = New-AuthenticodeVerificationPlan `
            ([string]$Contract.unsigned_bundle) $signed $SignTool $StoreLocation $Thumbprint $Rfc3161Url
        Invoke-ReleaseBundleInputVerification $plan.unsigned_bundle | Out-Null
        $baseline = New-ReleaseFinalizationBaseline $plan.unsigned_bundle
        $certificateIdentity = Resolve-CodeSigningCertificateIdentity `
            $plan.certificate_store_location $plan.certificate_thumbprint
        $verification = Test-FinalizedReleaseBundle `
            $signed $null $baseline $plan $certificateIdentity
        $bindings = Get-VerifiedSignedRoleManifestBindings `
            $signed $rolePins $manifestTexts $verification $Thumbprint $Rfc3161Url
        Assert-TrustedCliDirectoryPins $directoryPins 'trusted CLI path after verification'
        Assert-TrustedCliManifestPins $manifestPins 'trusted CLI evidence after verification'
        Assert-TrustedSignedRolePins $rolePins 'trusted release after verification'
        Assert-ProductionMaterializePathPins $materializePathPins 'materialize paths after verification'
        Assert-ProductionMaterializeOutputsAbsent $Contract 'materialize post-verification prelaunch'

        Initialize-EliotReleaseTrustedCliProcess
        $arguments = New-ProductionMaterializeArguments $Contract $rolePins
        $process = [EliotReleaseTrustedCliProcess]::CreateSuspended($cliPath, $arguments, $signed)
        $created = $process.Observe()
        if (-not (Test-ExactWindowsPath ([string]$created.ImagePath) $cliPath)) {
            throw 'suspended child image path does not match the retained CLI path'
        }
        $processImageHandle = $null
        try {
            $processImageHandle = [EliotReleaseNativeFileSystem]::OpenFileReadFence([string]$created.ImagePath)
            $processImage = Get-PinnedCliObservation $processImageHandle $cliPath
            if (-not (Test-PinnedCliObservationEqual $pinned $processImage)) {
                throw 'suspended child image file identity/hash does not match the retained CLI handle'
            }
        }
        finally {
            if ($processImageHandle -and -not $processImageHandle.IsClosed) { $processImageHandle.Dispose() }
        }

        Assert-TrustedCliDirectoryPins $directoryPins 'trusted CLI path before resume'
        Assert-TrustedCliManifestPins $manifestPins 'trusted CLI evidence before resume'
        Assert-TrustedSignedRolePins $rolePins 'trusted release before resume'
        Assert-ProductionMaterializePathPins $materializePathPins 'materialize paths before resume'
        Assert-ProductionMaterializeOutputsAbsent $Contract 'materialize suspended-child boundary'
        $beforeResumeFile = Get-PinnedCliObservation $cliPin.handle $cliPath
        $beforeResumeProcess = $process.Observe()
        if (-not (Test-PinnedCliObservationEqual $pinned $beforeResumeFile) -or
            [uint32]$beforeResumeProcess.ProcessId -ne [uint32]$created.ProcessId -or
            [uint64]$beforeResumeProcess.StartTime100ns -ne [uint64]$created.StartTime100ns -or
            -not (Test-ExactWindowsPath ([string]$beforeResumeProcess.ImagePath) $cliPath)) {
            throw 'trusted CLI identity changed before ResumeThread'
        }

        $processOutcome = $process.ResumeAndWait()
        Assert-TrustedCliDirectoryPins $directoryPins 'trusted CLI path after child completion'
        Assert-TrustedCliManifestPins $manifestPins 'trusted CLI evidence after child completion'
        Assert-TrustedSignedRolePins $rolePins 'trusted release after child completion'
        Assert-ProductionMaterializePathPins $materializePathPins 'materialize paths after child completion'
        $afterCompletion = Get-PinnedCliObservation $cliPin.handle $cliPath
        if (-not (Test-PinnedCliObservationEqual $pinned $afterCompletion) -or
            -not (Test-ExactWindowsPath ([string]$processOutcome.PostResumeEvidence.ImagePath) $cliPath) -or
            [uint32]$processOutcome.PostResumeEvidence.ProcessId -ne [uint32]$created.ProcessId -or
            [uint64]$processOutcome.PostResumeEvidence.StartTime100ns -ne [uint64]$created.StartTime100ns) {
            throw 'trusted CLI retained/process identity changed across execution'
        }

        if ([int]$processOutcome.ExitCode -ne 0) {
            return [ordered]@{
                schema = 'eliot-production-materialize-launch-v2'
                status = 'MATERIALIZE_CHILD_REJECTED_OR_UNKNOWN'
                signed_bundle = $signed
                process = [ordered]@{
                    process_id = [uint32]$created.ProcessId
                    start_time_100ns = [uint64]$created.StartTime100ns
                    image_path = [string]$created.ImagePath
                }
                exit_code = [int]$processOutcome.ExitCode
                standard_output = [string]$processOutcome.StandardOutput
                standard_error = [string]$processOutcome.StandardError
                child_succeeded = $false
            }
        }
        $receipt = Assert-ProductionMaterializeReceipt $Contract $processOutcome
        $readback = Get-ProductionMaterializeReadback $Contract $receipt

        return [ordered]@{
            schema = 'eliot-production-materialize-launch-v2'
            status = 'SOURCE_BUNDLE_MATERIALIZED'
            signed_bundle = $signed
            cli = [ordered]@{
                path = [string]$pinned.path
                volume_serial_number = [uint32]$pinned.volume_serial_number
                file_index = [uint64]$pinned.file_index
                bytes = [int64]$pinned.bytes
                sha256 = [string]$pinned.sha256
                signer_thumbprint = [string]$bindings[0].signer_thumbprint
                signer_subject = [string]$bindings[0].signer_subject
                code_signing_eku = [string]$bindings[0].code_signing_eku
                timestamp_url = [string]$bindings[0].timestamp_url
                timestamp_protocol = [string]$bindings[0].timestamp_protocol
                timestamp_message_imprint = [string]$bindings[0].timestamp_message_imprint
                timestamp_message_imprint_algorithm_oid = [string]$bindings[0].timestamp_message_imprint_algorithm_oid
                timestamp_certificate_thumbprint = [string]$bindings[0].timestamp_certificate_thumbprint
                signature_evidence_sha256 = [string]$bindings[0].signature_evidence_sha256
            }
            signed_roles = $bindings
            process = [ordered]@{
                process_id = [uint32]$created.ProcessId
                start_time_100ns = [uint64]$created.StartTime100ns
                image_path = [string]$created.ImagePath
            }
            exit_code = [int]$processOutcome.ExitCode
            child_succeeded = $true
            generated_receipt = $receipt.generated
            materialized_receipt = $receipt.materialized
            output_readback = $readback
        }
    }
    finally {
        if ($process) { $process.Dispose() }
        Close-ProductionMaterializePathPins $materializePathPins
        Close-TrustedSignedRolePins $rolePins
        Close-TrustedCliManifestPins $manifestPins
        Close-TrustedCliDirectoryPins $directoryPins
    }
}

foreach ($required in @{
        UnsignedBundle = $UnsignedBundle
        SignedBundle = $SignedBundle
        SignToolPath = $SignToolPath
        CertificateStoreLocation = $CertificateStoreLocation
        CertificateThumbprint = $CertificateThumbprint
        TimestampUrl = $TimestampUrl
        OutputBundle = $OutputBundle
        Output = $Output
        Store = $Store
        Generation = $Generation
        Installation = $Installation
        LineageId = $LineageId
        TransactionId = $TransactionId
        StagingRoot = $StagingRoot
        RecoveryCommand = $RecoveryCommand
        Profile = $Profile
        ProfileAnchorRoot = $ProfileAnchorRoot
    }.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
        throw "-$($required.Key) is required for the production CLI launcher"
    }
}
$contract = New-ProductionMaterializeContract `
    -UnsignedBundlePath $UnsignedBundle `
    -SignedBundlePath $SignedBundle `
    -OutputBundlePath $OutputBundle `
    -OutputPath $Output `
    -StorePath $Store `
    -GenerationValue $Generation `
    -InstallationValue $Installation `
    -LineageIdValue $LineageId `
    -SequenceValue $Sequence `
    -TransactionIdValue $TransactionId `
    -StagingRootPath $StagingRoot `
    -MinimumStoreAvailableBytesValue $MinimumStoreAvailableBytes `
    -RecoveryCommandValue $RecoveryCommand `
    -ProfileValue $Profile `
    -ProfileAnchorRootPath $ProfileAnchorRoot `
    -InstallationKeyValue $InstallationKey
$outcome = Invoke-ProductionEliotMaterializeSourceBundle `
    -Contract $contract `
    -SignTool $SignToolPath `
    -StoreLocation $CertificateStoreLocation `
    -Thumbprint $CertificateThumbprint `
    -Rfc3161Url $TimestampUrl
$outcome | ConvertTo-Json -Depth 12
exit ([int]$outcome.exit_code)
