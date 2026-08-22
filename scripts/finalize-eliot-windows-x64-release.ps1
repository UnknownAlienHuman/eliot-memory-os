[CmdletBinding()]
param(
    [string]$UnsignedBundle,
    [string]$SignedBundle,
    [string]$SignToolPath,
    [string]$CertificateStoreLocation,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl,
    [string]$VerifyBundle,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

# Keep the signing seam beside the existing release builder.  The builder is
# dot-sourced for its source-bound bundle verifier and PE/path guards; this
# script never builds Cargo targets, installs services, or talks to SCM.
$releaseBuilder = Join-Path $PSScriptRoot 'build-eliot-windows-x64-release.ps1'
. $releaseBuilder

Set-StrictMode -Version Latest

$script:AuthenticodeCodeSigningEku = '1.3.6.1.5.5.7.3.3'
$script:X509EnhancedKeyUsageExtensionOid = '2.5.29.37'
$script:AuthenticodeSigningPolicy = 'authenticode-rfc3161'
$script:AuthenticodeSigningScope = 'runtime-materializer-six-pe-roles'
$script:StagingOwnerMarker = '.eliot-release-staging-owner'
$script:Rfc3161TimestampAttributeOid = '1.3.6.1.4.1.311.3.3.1'
$script:Rfc3161TstInfoContentTypeOid = '1.2.840.113549.1.9.16.1.4'
$script:Sha256AlgorithmOid = '2.16.840.1.101.3.4.2.1'

function Initialize-ReleaseNativeFileSystem {
    if ('EliotReleaseNativeFileSystem' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public sealed class EliotReleaseFileIdentity
{
    public UInt32 VolumeSerialNumber { get; set; }
    public UInt64 FileIndex { get; set; }
    public UInt32 Attributes { get; set; }
    public UInt32 NumberOfLinks { get; set; }
}

public sealed class EliotReleaseOwnedDirectory
{
    public SafeFileHandle Handle { get; set; }
    public EliotReleaseFileIdentity Identity { get; set; }
    public string FinalPath { get; set; }
}

public sealed class EliotReleaseFileDigest
{
    public Int64 Bytes { get; set; }
    public string Sha256 { get; set; }
}

public static class EliotReleaseNativeFileSystem
{
    private const UInt32 FILE_READ_ATTRIBUTES = 0x80;
    private const UInt32 FILE_READ_DATA = 0x1;
    private const UInt32 FILE_LIST_DIRECTORY = 0x1;
    private const UInt32 FILE_WRITE_DATA = 0x2;
    private const UInt32 FILE_ADD_SUBDIRECTORY = 0x4;
    private const UInt32 DELETE_ACCESS = 0x00010000;
    private const UInt32 SYNCHRONIZE = 0x00100000;
    private const UInt32 FILE_SHARE_READ = 0x1;
    private const UInt32 FILE_SHARE_WRITE = 0x2;
    private const UInt32 FILE_SHARE_DELETE = 0x4;
    private const UInt32 OPEN_EXISTING = 3;
    private const UInt32 FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const UInt32 FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const UInt32 FILE_ATTRIBUTE_DIRECTORY = 0x10;
    private const UInt32 FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
    private const UInt32 FILE_CREATE = 2;
    private const UInt32 FILE_DIRECTORY_FILE = 0x00000001;
    private const UInt32 FILE_NON_DIRECTORY_FILE = 0x00000040;
    private const UInt32 FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020;
    private const UInt32 OBJ_CASE_INSENSITIVE = 0x00000040;
    private const UInt64 FILE_CREATED = 2;
    private const Int32 FILE_RENAME_INFORMATION_CLASS = 10;
    private const Int32 FILE_DISPOSITION_INFO_EX_CLASS = 21;
    private const UInt32 FILE_DISPOSITION_FLAG_DELETE = 0x1;
    private const UInt32 FILE_DISPOSITION_FLAG_POSIX_SEMANTICS = 0x2;
    private const UInt32 DUPLICATE_SAME_ACCESS = 0x2;

    [StructLayout(LayoutKind.Sequential)]
    private struct FILETIME { public UInt32 Low; public UInt32 High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public UInt32 FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public UInt32 VolumeSerialNumber;
        public UInt32 FileSizeHigh;
        public UInt32 FileSizeLow;
        public UInt32 NumberOfLinks;
        public UInt32 FileIndexHigh;
        public UInt32 FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES
    {
        public Int32 Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_STATUS_BLOCK
    {
        public IntPtr StatusOrPointer;
        public UIntPtr Information;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, UInt32 desiredAccess, UInt32 shareMode, IntPtr securityAttributes,
        UInt32 creationDisposition, UInt32 flagsAndAttributes, IntPtr templateFile);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern Int32 NtCreateFile(
        out IntPtr fileHandle, UInt32 desiredAccess, ref OBJECT_ATTRIBUTES objectAttributes,
        out IO_STATUS_BLOCK ioStatusBlock, IntPtr allocationSize, UInt32 fileAttributes,
        UInt32 shareAccess, UInt32 createDisposition, UInt32 createOptions,
        IntPtr eaBuffer, UInt32 eaLength);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern UInt32 RtlNtStatusToDosError(Int32 status);

    [DllImport("ntdll.dll", ExactSpelling = true)]
    private static extern Int32 NtSetInformationFile(
        SafeFileHandle fileHandle, out IO_STATUS_BLOCK ioStatusBlock,
        IntPtr fileInformation, UInt32 length, Int32 fileInformationClass);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetFileInformationByHandle(
        SafeFileHandle file, Int32 fileInformationClass, IntPtr fileInformation, UInt32 bufferSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool FlushFileBuffers(SafeFileHandle file);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(
        IntPtr sourceProcess, SafeFileHandle sourceHandle, IntPtr targetProcess,
        out SafeFileHandle targetHandle, UInt32 desiredAccess, bool inheritHandle, UInt32 options);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file, out BY_HANDLE_FILE_INFORMATION information);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern UInt32 GetFinalPathNameByHandleW(
        SafeFileHandle file, StringBuilder path, UInt32 pathLength, UInt32 flags);

    public static EliotReleaseOwnedDirectory CreateDirectoryNewRetained(
        SafeFileHandle parent, string childName, bool shareDelete)
    {
        if (parent == null || parent.IsInvalid || parent.IsClosed)
            throw new InvalidOperationException("retained parent handle is unavailable");
        if (String.IsNullOrWhiteSpace(childName) || childName == "." || childName == ".." ||
            childName.IndexOfAny(new char[] { '\\', '/', ':' }) >= 0)
            throw new ArgumentException("create-new directory requires one relative child name", "childName");
        int byteLength = checked(childName.Length * 2);
        if (byteLength > UInt16.MaxValue - 2)
            throw new PathTooLongException("create-new directory child name is too long");

        IntPtr nameBuffer = IntPtr.Zero;
        IntPtr unicodeStringPointer = IntPtr.Zero;
        bool parentAdded = false;
        IntPtr rawHandle = IntPtr.Zero;
        try
        {
            nameBuffer = Marshal.StringToHGlobalUni(childName);
            UNICODE_STRING unicodeString = new UNICODE_STRING {
                Length = (UInt16)byteLength,
                MaximumLength = (UInt16)(byteLength + 2),
                Buffer = nameBuffer
            };
            unicodeStringPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(unicodeString, unicodeStringPointer, false);

            parent.DangerousAddRef(ref parentAdded);
            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodeStringPointer,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK ioStatus;
            Int32 status = NtCreateFile(
                out rawHandle,
                FILE_LIST_DIRECTORY | FILE_WRITE_DATA | FILE_ADD_SUBDIRECTORY | FILE_READ_ATTRIBUTES | DELETE_ACCESS | SYNCHRONIZE,
                ref attributes,
                out ioStatus,
                IntPtr.Zero,
                FILE_ATTRIBUTE_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE | (shareDelete ? FILE_SHARE_DELETE : 0),
                FILE_CREATE,
                FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero,
                0);
            if (status != 0)
                throw new Win32Exception((Int32)RtlNtStatusToDosError(status),
                    "atomic create-new retained directory failed: " + childName);
            if (rawHandle == IntPtr.Zero || rawHandle == new IntPtr(-1) || ioStatus.Information.ToUInt64() != FILE_CREATED)
                throw new InvalidDataException("NtCreateFile did not return one newly created directory handle");

            SafeFileHandle owned = new SafeFileHandle(rawHandle, true);
            rawHandle = IntPtr.Zero;
            try
            {
                EliotReleaseFileIdentity identity = ReadIdentity(owned);
                if ((identity.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                    (identity.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || identity.FileIndex == 0)
                    throw new InvalidDataException("atomic create returned reparse/non-directory identity");
                return new EliotReleaseOwnedDirectory {
                    Handle = owned,
                    Identity = identity,
                    FinalPath = ReadFinalPath(owned)
                };
            }
            catch
            {
                owned.Dispose();
                throw;
            }
        }
        finally
        {
            if (rawHandle != IntPtr.Zero && rawHandle != new IntPtr(-1))
                new SafeFileHandle(rawHandle, true).Dispose();
            if (parentAdded) parent.DangerousRelease();
            if (unicodeStringPointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodeStringPointer);
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
        }
    }

    public static SafeFileHandle CreateFileNewForWrite(SafeFileHandle parent, string childName)
    {
        if (parent == null || parent.IsInvalid || parent.IsClosed)
            throw new InvalidOperationException("retained destination-directory handle is unavailable");
        if (String.IsNullOrWhiteSpace(childName) || childName == "." || childName == ".." ||
            childName.IndexOfAny(new char[] { '\\', '/', ':' }) >= 0)
            throw new ArgumentException("create-new file requires one relative child name", "childName");
        int byteLength = checked(childName.Length * 2);
        if (byteLength > UInt16.MaxValue - 2)
            throw new PathTooLongException("create-new file child name is too long");

        IntPtr nameBuffer = IntPtr.Zero;
        IntPtr unicodeStringPointer = IntPtr.Zero;
        bool parentAdded = false;
        IntPtr rawHandle = IntPtr.Zero;
        try
        {
            nameBuffer = Marshal.StringToHGlobalUni(childName);
            UNICODE_STRING unicodeString = new UNICODE_STRING {
                Length = (UInt16)byteLength,
                MaximumLength = (UInt16)(byteLength + 2),
                Buffer = nameBuffer
            };
            unicodeStringPointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
            Marshal.StructureToPtr(unicodeString, unicodeStringPointer, false);
            parent.DangerousAddRef(ref parentAdded);
            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES {
                Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES)),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodeStringPointer,
                Attributes = OBJ_CASE_INSENSITIVE,
                SecurityDescriptor = IntPtr.Zero,
                SecurityQualityOfService = IntPtr.Zero
            };
            IO_STATUS_BLOCK ioStatus;
            Int32 status = NtCreateFile(
                out rawHandle,
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | DELETE_ACCESS | SYNCHRONIZE,
                ref attributes,
                out ioStatus,
                IntPtr.Zero,
                0x80,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_FLAG_OPEN_REPARSE_POINT,
                IntPtr.Zero,
                0);
            if (status != 0)
                throw new Win32Exception((Int32)RtlNtStatusToDosError(status),
                    "atomic create-new retained file failed: " + childName);
            if (rawHandle == IntPtr.Zero || rawHandle == new IntPtr(-1) || ioStatus.Information.ToUInt64() != FILE_CREATED)
                throw new InvalidDataException("NtCreateFile did not return one newly created file handle");
            SafeFileHandle owned = new SafeFileHandle(rawHandle, true);
            rawHandle = IntPtr.Zero;
            return owned;
        }
        finally
        {
            if (rawHandle != IntPtr.Zero && rawHandle != new IntPtr(-1))
                new SafeFileHandle(rawHandle, true).Dispose();
            if (parentAdded) parent.DangerousRelease();
            if (unicodeStringPointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodeStringPointer);
            if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
        }
    }

    public static SafeFileHandle OpenFileReadFence(string path)
    {
        SafeFileHandle handle = CreateFileW(
            path, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "open no-follow no-write file fence failed: " + path);
        }
        EliotReleaseFileIdentity identity = ReadIdentity(handle);
        if ((identity.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (identity.Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 || identity.FileIndex == 0 ||
            identity.NumberOfLinks != 1)
        {
            handle.Dispose();
            throw new InvalidDataException("file fence is reparse/directory/hardlinked/identity-zero: " + path);
        }
        return handle;
    }

    public static SafeFileHandle DuplicateSameAccess(SafeFileHandle source)
    {
        if (source == null || source.IsInvalid || source.IsClosed)
            throw new InvalidOperationException("file handle is unavailable for duplication");
        SafeFileHandle duplicate;
        IntPtr process = GetCurrentProcess();
        if (!DuplicateHandle(process, source, process, out duplicate, 0, false, DUPLICATE_SAME_ACCESS))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "file handle duplication failed");
        return duplicate;
    }

    public static EliotReleaseFileDigest ReadSha256AndSize(SafeFileHandle source)
    {
        using (SafeFileHandle duplicate = DuplicateSameAccess(source))
        using (FileStream stream = new FileStream(duplicate, FileAccess.Read, 65536, false))
        using (SHA256 sha = SHA256.Create())
        {
            stream.Seek(0, SeekOrigin.Begin);
            byte[] hash = sha.ComputeHash(stream);
            StringBuilder text = new StringBuilder(hash.Length * 2);
            foreach (byte value in hash) text.Append(value.ToString("x2"));
            return new EliotReleaseFileDigest { Bytes = stream.Length, Sha256 = text.ToString() };
        }
    }

    public static void DeleteFileByHandle(SafeFileHandle file)
    {
        if (file == null || file.IsInvalid || file.IsClosed)
            throw new InvalidOperationException("marker ownership handle is unavailable for deletion");
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buffer, unchecked((Int32)(
                FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS)));
            if (!SetFileInformationByHandle(file, FILE_DISPOSITION_INFO_EX_CLASS, buffer, 4))
                throw new Win32Exception(Marshal.GetLastWin32Error(),
                    "handle-bound staging marker deletion failed");
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static SafeFileHandle OpenDirectoryNoFollow(
        string path, bool shareDelete, bool allowChildDirectoryChanges)
    {
        UInt32 share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        if (shareDelete) share |= FILE_SHARE_DELETE;
        UInt32 desiredAccess = FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        if (allowChildDirectoryChanges)
            desiredAccess |= FILE_LIST_DIRECTORY | FILE_ADD_SUBDIRECTORY;
        SafeFileHandle handle = CreateFileW(
            path, desiredAccess, share, IntPtr.Zero, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "open no-follow directory failed: " + path);
        }
        EliotReleaseFileIdentity identity = ReadIdentity(handle);
        if ((identity.Attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
            (identity.Attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
        {
            handle.Dispose();
            throw new InvalidDataException("directory is reparse or not a directory: " + path);
        }
        return handle;
    }

    public static EliotReleaseFileIdentity ReadIdentity(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(handle, out information))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "directory identity readback failed");
        return new EliotReleaseFileIdentity {
            VolumeSerialNumber = information.VolumeSerialNumber,
            FileIndex = ((UInt64)information.FileIndexHigh << 32) | information.FileIndexLow,
            Attributes = information.FileAttributes,
            NumberOfLinks = information.NumberOfLinks
        };
    }

    public static string ReadFinalPath(SafeFileHandle handle)
    {
        StringBuilder buffer = new StringBuilder(32768);
        UInt32 length = GetFinalPathNameByHandleW(handle, buffer, (UInt32)buffer.Capacity, 0);
        if (length == 0 || length >= buffer.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "directory path readback failed");
        string path = buffer.ToString();
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + path.Substring(8);
        if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            return path.Substring(4);
        return path;
    }

    public static void PublishDirectoryHandleCreateNew(
        SafeFileHandle ownershipFence, SafeFileHandle destinationParent, string destinationLeaf)
    {
        if (ownershipFence == null || ownershipFence.IsInvalid || ownershipFence.IsClosed ||
            destinationParent == null || destinationParent.IsInvalid || destinationParent.IsClosed)
            throw new InvalidOperationException("staging ownership fence is unavailable at commit");
        if (String.IsNullOrWhiteSpace(destinationLeaf) || destinationLeaf == "." || destinationLeaf == ".." ||
            destinationLeaf.IndexOfAny(new char[] { '\\', '/', ':' }) >= 0)
            throw new ArgumentException("publication requires one relative destination leaf", "destinationLeaf");

        string sourcePath = ReadFinalPath(ownershipFence);
        string retainedParentPath = ReadFinalPath(destinationParent);
        string sourceParentPath = Path.GetDirectoryName(sourcePath);
        if (String.IsNullOrWhiteSpace(sourceParentPath) ||
            !String.Equals(sourceParentPath, retainedParentPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException(
                "handle-bound publication requires the retained source and destination parent to match");

        string destinationPath = Path.GetFullPath(Path.Combine(retainedParentPath, destinationLeaf));
        if (!String.Equals(Path.GetDirectoryName(destinationPath), retainedParentPath,
            StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("publication destination escaped the retained parent");
        byte[] name = Encoding.Unicode.GetBytes(destinationLeaf);
        int rootOffset = IntPtr.Size == 8 ? 8 : 4;
        int lengthOffset = rootOffset + IntPtr.Size;
        int nameOffset = lengthOffset + 4;
        int fixedSize = IntPtr.Size == 8 ? 24 : 16;
        int bufferSize = checked(fixedSize + name.Length);
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        bool parentAdded = false;
        bool ownershipAdded = false;
        try
        {
            for (int index = 0; index < bufferSize; index++) Marshal.WriteByte(buffer, index, 0);
            destinationParent.DangerousAddRef(ref parentAdded);
            ownershipFence.DangerousAddRef(ref ownershipAdded);
            Marshal.WriteByte(buffer, 0, 0); // FileRenameInformation ReplaceIfExists=FALSE.
            Marshal.WriteIntPtr(buffer, rootOffset, destinationParent.DangerousGetHandle());
            Marshal.WriteInt32(buffer, lengthOffset, name.Length);
            Marshal.Copy(name, 0, new IntPtr(buffer.ToInt64() + nameOffset), name.Length);
            IO_STATUS_BLOCK ioStatus;
            Int32 status = NtSetInformationFile(
                ownershipFence, out ioStatus, buffer, (UInt32)bufferSize,
                FILE_RENAME_INFORMATION_CLASS);
            if (status != 0)
                throw new Win32Exception((Int32)RtlNtStatusToDosError(status),
                    "handle-relative create-new directory publication failed: " + destinationLeaf);
        }
        finally
        {
            if (ownershipAdded) ownershipFence.DangerousRelease();
            if (parentAdded) destinationParent.DangerousRelease();
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static bool FlushDirectoryHandle(SafeFileHandle directory)
    {
        return directory != null && !directory.IsInvalid && !directory.IsClosed && FlushFileBuffers(directory);
    }
}
'@
}

function Test-NativeIdentityEqual([object]$Left, [object]$Right) {
    return $Left -and $Right -and
        [uint32]$Left.VolumeSerialNumber -eq [uint32]$Right.VolumeSerialNumber -and
        [uint64]$Left.FileIndex -eq [uint64]$Right.FileIndex -and
        [uint64]$Left.FileIndex -ne 0
}

function New-NativeDirectoryPin(
    [string]$Path,
    [bool]$ShareDelete,
    [bool]$AllowChildDirectoryChanges = $false
) {
    Initialize-ReleaseNativeFileSystem
    $expected = Get-FullyQualifiedWindowsPath $Path 'native directory pin'
    $handle = [EliotReleaseNativeFileSystem]::OpenDirectoryNoFollow(
        $expected,
        $ShareDelete,
        $AllowChildDirectoryChanges)
    try {
        $observedPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($handle)
        $identity = [EliotReleaseNativeFileSystem]::ReadIdentity($handle)
        if ([string]::Compare($observedPath, $expected, $true) -ne 0 -or [uint64]$identity.FileIndex -eq 0) {
            throw "native directory pin path/identity mismatch: $expected"
        }
        return [pscustomobject]@{
            path = $expected
            identity = $identity
            handle = $handle
        }
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Assert-NativeDirectoryPin([object]$Pin, [string]$Purpose) {
    if (-not $Pin -or -not $Pin.handle -or $Pin.handle.IsClosed -or $Pin.handle.IsInvalid) {
        throw "$Purpose native directory pin is unavailable"
    }
    $path = [EliotReleaseNativeFileSystem]::ReadFinalPath($Pin.handle)
    $identity = [EliotReleaseNativeFileSystem]::ReadIdentity($Pin.handle)
    if ([string]::Compare($path, [string]$Pin.path, $true) -ne 0 -or
        -not (Test-NativeIdentityEqual $identity $Pin.identity)) {
        throw "$Purpose native directory path/identity changed"
    }
}

function Close-NativeDirectoryPin([object]$Pin) {
    if ($Pin -and $Pin.handle -and -not $Pin.handle.IsClosed) { $Pin.handle.Dispose() }
}

function Get-AuthenticodeRoleDefinitions {
    # These are the six executable roles admitted by
    # bins/eliot/src/source_bundle_materializer.rs::REQUIRED_ROLES.  The
    # release also contains the CLI, Governor, Operator, and other payload;
    # they are deliberately outside this exact canary signing scope.
    @(
        [ordered]@{ role = 'host'; path = 'runtime/eliot-host.exe' }
        [ordered]@{ role = 'watchdog'; path = 'runtime/eliot-watchdog.exe' }
        [ordered]@{ role = 'kernel'; path = 'runtime/eliot-kernel.exe' }
        [ordered]@{ role = 'store_bridge'; path = 'runtime/eliot-store-surreal.exe' }
        [ordered]@{ role = 'database'; path = 'runtime/surreal.exe' }
        [ordered]@{ role = 'daemon'; path = 'runtime/eliotd.exe' }
    )
}

function Get-NormalizedThumbprint([string]$Thumbprint, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Thumbprint) -or $Thumbprint -cnotmatch '^[0-9A-Fa-f]{40}$') {
        throw "$Purpose must be the exact 40-hex SHA-1 certificate thumbprint with no separators"
    }
    return $Thumbprint.ToLowerInvariant()
}

function Get-FullyQualifiedWindowsPath([string]$Path, [string]$Purpose) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw "$Purpose must be a fully-qualified Windows path"
    }
    if ($Path -match '^(?:\\\\\?\\|\\\\\.\\|\\\?\?\\)' -or
        ($Path -cnotmatch '^[A-Za-z]:\\' -and
            $Path -cnotmatch '^\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+(?:\\|$)')) {
        throw "$Purpose must be drive-rooted or an exact UNC path; drive-relative and root-relative paths are forbidden"
    }
    $segments = @($Path -split '\\')
    if ($segments -contains '.' -or $segments -contains '..') {
        throw "$Purpose must not contain dot path segments"
    }
    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($resolved -cnotmatch '^[A-Za-z]:\\' -and
        $resolved -cnotmatch '^\\\\[^\\/:*?"<>|]+\\[^\\/:*?"<>|]+(?:\\|$)') {
        throw "$Purpose did not resolve to a fully-qualified Windows path"
    }
    return $resolved
}

function Assert-ExplicitAbsoluteFile([string]$Path, [string]$Purpose) {
    $resolved = Get-FullyQualifiedWindowsPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        throw "$Purpose does not exist as a regular file: $resolved"
    }
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (-not ($file -is [System.IO.FileInfo]) -or
        ($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not [string]::IsNullOrWhiteSpace([string]$file.LinkType) -or
        @($file.Target | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }).Count -ne 0) {
        throw "$Purpose must be a resident regular non-reparse file: $resolved"
    }
    $parent = $file.Directory
    while ($parent) {
        if (($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Purpose parent directory is a reparse point: $($parent.FullName)"
        }
        $next = $parent.Parent
        if (-not $next -or $next.FullName -eq $parent.FullName) { break }
        $parent = $next
    }
    return $file
}

function Assert-ExistingBundleDirectory([string]$Path, [string]$Purpose) {
    $resolved = Get-FullyQualifiedWindowsPath $Path $Purpose
    if (-not (Test-Path -LiteralPath $resolved -PathType Container)) {
        throw "$Purpose does not exist as an absolute directory: $resolved"
    }
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose must not be a reparse-point directory: $resolved"
    }
    return $resolved
}

function Assert-AbsentOutputBundle([string]$Path, [string]$Purpose) {
    $resolved = Get-FullyQualifiedWindowsPath $Path $Purpose
    if (Test-Path -LiteralPath $resolved) {
        throw "$Purpose already exists; overwrite/adoption is forbidden: $resolved"
    }
    $parent = Split-Path -Parent $resolved
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "$Purpose parent directory must already exist: $parent"
    }
    $parentItem = Get-Item -LiteralPath $parent -ErrorAction Stop
    if (($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Purpose parent directory must not be a reparse point: $parent"
    }
    return $resolved
}

function Assert-ExplicitRfc3161TimestampUrl([string]$Url) {
    if ([string]::IsNullOrWhiteSpace($Url)) {
        throw 'TimestampUrl is required and must be an explicit absolute RFC3161 endpoint'
    }
    $uri = $null
    if (-not [System.Uri]::TryCreate($Url, [System.UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -notin @('http', 'https') -or [string]::IsNullOrWhiteSpace($uri.Host)) {
        throw 'TimestampUrl must be an explicit absolute HTTP(S) RFC3161 endpoint; PATH/environment fallback is forbidden'
    }
    return $uri.AbsoluteUri
}

function Assert-ExplicitCertificateStore([string]$StoreLocation) {
    if ([string]::IsNullOrWhiteSpace($StoreLocation) -or
        $StoreLocation -cnotmatch '^Cert:\\(CurrentUser|LocalMachine)\\My$') {
        throw 'CertificateStoreLocation must be exactly Cert:\CurrentUser\My or Cert:\LocalMachine\My'
    }
    $parts = $StoreLocation -split '\\'
    [ordered]@{
        location = $StoreLocation
        scope = $parts[1]
        store = $parts[2]
    }
}

function Test-CertificateCodeSigningEku([object]$Certificate) {
    foreach ($extension in @($Certificate.Extensions)) {
        if (-not ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) -or
            [string]$extension.Oid.Value -cne $script:X509EnhancedKeyUsageExtensionOid) {
            continue
        }
        foreach ($oid in @($extension.EnhancedKeyUsages)) {
            if ([string]$oid.Value -ceq $script:AuthenticodeCodeSigningEku) {
                return $true
            }
        }
        return $false
    }
    return $false
}

function Assert-CodeSigningCertificateIdentity([object]$Certificate, [string]$StoreLocation, [string]$Thumbprint) {
    [void](Assert-ExplicitCertificateStore $StoreLocation)
    if (-not $Certificate) {
        throw "no certificate with exact thumbprint $Thumbprint was found in $StoreLocation"
    }
    $expectedThumbprint = Get-NormalizedThumbprint $Thumbprint 'CertificateThumbprint'
    $actualThumbprint = ([string]$Certificate.Thumbprint).Replace(' ', '').ToLowerInvariant()
    if ($actualThumbprint -ne $expectedThumbprint) {
        throw "certificate thumbprint readback differs from the exact requested thumbprint: $actualThumbprint"
    }
    if (-not (Test-CertificateCodeSigningEku $Certificate)) {
        throw "certificate $expectedThumbprint does not carry the Code Signing EKU ($script:AuthenticodeCodeSigningEku)"
    }
    if ([string]::IsNullOrWhiteSpace([string]$Certificate.Subject)) {
        throw "certificate $expectedThumbprint has no signer subject"
    }
    return $Certificate
}

function Assert-CodeSigningCertificate([object]$Certificate, [string]$StoreLocation, [string]$Thumbprint) {
    $validated = Assert-CodeSigningCertificateIdentity $Certificate $StoreLocation $Thumbprint
    if ($validated.HasPrivateKey -ne $true) {
        throw "certificate $(Get-NormalizedThumbprint $Thumbprint 'CertificateThumbprint') does not have an available private key"
    }
    return $validated
}

function Resolve-CodeSigningCertificateIdentity([string]$StoreLocation, [string]$Thumbprint) {
    $store = Assert-ExplicitCertificateStore $StoreLocation
    $expectedThumbprint = Get-NormalizedThumbprint $Thumbprint 'CertificateThumbprint'
    $certificateMatches = @(
        Get-ChildItem -Path $store.location -ErrorAction Stop |
            Where-Object {
                ([string]$_.Thumbprint).Replace(' ', '').ToLowerInvariant() -eq $expectedThumbprint
            }
    )
    if ($certificateMatches.Count -ne 1) {
        throw "certificate store $($store.location) must contain exactly one certificate with thumbprint $expectedThumbprint; found $($certificateMatches.Count)"
    }
    return Assert-CodeSigningCertificateIdentity $certificateMatches[0] $store.location $expectedThumbprint
}

function Resolve-CodeSigningCertificate([string]$StoreLocation, [string]$Thumbprint) {
    $certificate = Resolve-CodeSigningCertificateIdentity $StoreLocation $Thumbprint
    return Assert-CodeSigningCertificate $certificate $StoreLocation $Thumbprint
}

function Get-SignToolArguments([object]$Plan, [string]$Path) {
    $arguments = [System.Collections.Generic.List[string]]::new()
    [void]$arguments.Add('sign')
    [void]$arguments.Add('/fd')
    [void]$arguments.Add('sha256')
    # SignTool requires /td after /tr for the RFC3161 digest selection.
    [void]$arguments.Add('/tr')
    [void]$arguments.Add($Plan.timestamp_url)
    [void]$arguments.Add('/td')
    [void]$arguments.Add('sha256')
    [void]$arguments.Add('/sha1')
    [void]$arguments.Add($Plan.certificate_thumbprint)
    [void]$arguments.Add('/s')
    [void]$arguments.Add($Plan.certificate_store_name)
    if ($Plan.certificate_store_scope -eq 'LocalMachine') {
        [void]$arguments.Add('/sm')
    }
    [void]$arguments.Add('/u')
    [void]$arguments.Add($script:AuthenticodeCodeSigningEku)
    [void]$arguments.Add($Path)
    return @($arguments)
}

function Get-SignToolVerifyArguments([string]$Path) {
    return @('verify', '/pa', '/all', '/v', '/tw', $Path)
}

function New-AuthenticodeSigningPlan(
    [string]$UnsignedBundle,
    [string]$SignedBundle,
    [string]$SignToolPath,
    [string]$CertificateStoreLocation,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl
) {
    $source = Assert-ExistingBundleDirectory $UnsignedBundle 'UnsignedBundle'
    $destination = Assert-AbsentOutputBundle $SignedBundle 'SignedBundle'
    if ([string]::Equals($source, $destination, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'SignedBundle must be a distinct create-only path from UnsignedBundle'
    }
    $sourcePrefix = "$($source.TrimEnd('\'))\"
    if ($destination.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'SignedBundle must not be inside UnsignedBundle; source adoption/recursive staging is forbidden'
    }
    $signTool = Assert-ExplicitAbsoluteFile $SignToolPath 'SignToolPath'
    if ($signTool.Extension -cne '.exe' -or $signTool.Name -ine 'signtool.exe') {
        throw "SignToolPath must name an explicit signtool.exe: $($signTool.FullName)"
    }
    $store = Assert-ExplicitCertificateStore $CertificateStoreLocation
    $thumbprint = Get-NormalizedThumbprint $CertificateThumbprint 'CertificateThumbprint'
    $timestamp = Assert-ExplicitRfc3161TimestampUrl $TimestampUrl

    $releasePath = Join-Path $source 'RELEASE.json'
    $runtimePath = Join-Path $source 'runtime/RUNTIME_ARTIFACTS.json'
    if (-not (Test-Path -LiteralPath $releasePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) {
        throw 'UnsignedBundle must contain RELEASE.json and runtime/RUNTIME_ARTIFACTS.json'
    }
    $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
    if ($release.signed -ne $false -or $runtime.signed -ne $false -or
        [string]$release.signature_evidence -ne 'not-issued' -or
        [string]$runtime.signature_evidence -ne 'not-issued') {
        throw 'UnsignedBundle is not at the explicit unsigned signing boundary'
    }

    $roles = @(Get-AuthenticodeRoleDefinitions)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($role in $roles) {
        $relative = [string]$role.path
        if (-not $seen.Add($relative)) {
            throw "signing role path is duplicated: $relative"
        }
        $candidate = Join-Path $source $relative
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "exact Authenticode signing role is missing: $relative"
        }
        $entries = @($runtime.artifacts | Where-Object { [string]$_.path -eq $relative })
        if ($entries.Count -ne 1 -or [string]$entries[0].role -ne [string]$role.role) {
            throw "runtime artifact manifest does not bind exact signing role $($role.role): $relative"
        }
    }

    [ordered]@{
        schema = 'eliot-authenticode-signing-plan-v1'
        unsigned_bundle = $source
        signed_bundle = $destination
        signtool_path = $signTool.FullName
        certificate_store_location = $store.location
        certificate_store_scope = $store.scope
        certificate_store_name = $store.store
        certificate_thumbprint = $thumbprint
        timestamp_url = $timestamp
        file_digest_algorithm = 'sha256'
        timestamp_digest_algorithm = 'sha256'
        signer_eku = $script:AuthenticodeCodeSigningEku
        signing_scope = $script:AuthenticodeSigningScope
        roles = @($roles)
    }
}

function New-AuthenticodeVerificationPlan(
    [string]$UnsignedBundle,
    [string]$SignedBundle,
    [string]$SignToolPath,
    [string]$CertificateStoreLocation,
    [string]$CertificateThumbprint,
    [string]$TimestampUrl
) {
    $source = Assert-ExistingBundleDirectory $UnsignedBundle 'UnsignedBundle'
    $destination = Assert-ExistingBundleDirectory $SignedBundle 'VerifyBundle'
    if ([string]::Equals($source, $destination, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'VerifyBundle must be distinct from UnsignedBundle'
    }
    $signTool = Assert-ExplicitAbsoluteFile $SignToolPath 'SignToolPath'
    if ($signTool.Name -ine 'signtool.exe') { throw 'SignToolPath must name exact signtool.exe' }
    $store = Assert-ExplicitCertificateStore $CertificateStoreLocation
    [pscustomobject][ordered]@{
        unsigned_bundle = $source
        signed_bundle = $destination
        signtool_path = $signTool.FullName
        certificate_store_location = $store.location
        certificate_store_scope = $store.scope
        certificate_store_name = $store.store
        certificate_thumbprint = Get-NormalizedThumbprint $CertificateThumbprint 'CertificateThumbprint'
        timestamp_url = Assert-ExplicitRfc3161TimestampUrl $TimestampUrl
    }
}

function Invoke-ConfiguredSignTool([string]$SignToolPath, [string[]]$Arguments) {
    $output = & $SignToolPath @Arguments 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed with exit code ${LASTEXITCODE}: $output"
    }
}

function Invoke-ConfiguredSignToolVerify([string]$SignToolPath, [string[]]$Arguments) {
    $output = & $SignToolPath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "signtool verify failed or warned with exit code ${exitCode}: $output"
    }
    [ordered]@{
        exit_code = 0
        arguments = @($Arguments)
    }
}

function Read-AuthenticodeSignature([string]$Path) {
    $command = Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if (-not $command) {
        throw 'Get-AuthenticodeSignature is unavailable; Windows WinTrust readback is required'
    }
    return Get-AuthenticodeSignature -LiteralPath $Path
}

function Get-CertificateThumbprint([object]$Certificate) {
    return ([string]$Certificate.Thumbprint).Replace(' ', '').ToLowerInvariant()
}

function Assert-AuthenticodeReadback(
    [object]$Signature,
    [object]$Plan,
    [string]$Path,
    [string]$ExpectedSignerSubject,
    [string]$ExpectedRolePath,
    [object]$TimestampEvidence,
    [object]$SignToolEvidence
) {
    $status = if ($Signature) { [string]$Signature.Status } else { '<null>' }
    if (-not $Signature -or [string]$Signature.Status -cne 'Valid') {
        throw "WinTrust Authenticode readback is not Valid for ${Path}: $status"
    }
    $signer = $Signature.SignerCertificate
    if (-not $signer -or (Get-CertificateThumbprint $signer) -ne [string]$Plan.certificate_thumbprint) {
        throw "Authenticode signer substitution/readback mismatch for $Path"
    }
    if ([string]$signer.Subject -cne $ExpectedSignerSubject) {
        throw "Authenticode signer subject mismatch for $Path"
    }
    $timestamp = $Signature.TimeStamperCertificate
    if (-not $timestamp -or [string]::IsNullOrWhiteSpace([string]$timestamp.Thumbprint) -or
        [string]::IsNullOrWhiteSpace([string]$timestamp.Subject)) {
        throw "RFC3161 timestamp certificate is missing from Authenticode readback for $Path"
    }
    if (-not $TimestampEvidence -or [string]$TimestampEvidence.protocol -cne 'RFC3161' -or
        [string]$TimestampEvidence.attribute_oid -cne $script:Rfc3161TimestampAttributeOid -or
        [string]$TimestampEvidence.message_imprint_algorithm -cne 'sha256' -or
        [string]$TimestampEvidence.message_imprint_algorithm_oid -cne $script:Sha256AlgorithmOid -or
        [string]$TimestampEvidence.message_imprint -cne [string]$TimestampEvidence.signer_signature_sha256 -or
        $TimestampEvidence.cms_signature_valid -ne $true -or
        (Get-CertificateThumbprint $timestamp) -cne [string]$TimestampEvidence.timestamp_certificate_thumbprint -or
        [string]$timestamp.Subject -cne [string]$TimestampEvidence.timestamp_certificate_subject) {
        throw "RFC3161 token proof does not match WinTrust timestamp readback for $Path"
    }
    if (-not $SignToolEvidence) {
        throw "independent signtool /tw verification is missing for $Path"
    }
    $expectedVerifyArguments = @(Get-SignToolVerifyArguments $Path)
    $observedVerifyArguments = @($SignToolEvidence.arguments)
    if ([int]$SignToolEvidence.exit_code -ne 0 -or
        $observedVerifyArguments.Count -ne $expectedVerifyArguments.Count) {
        throw "independent signtool /tw verification is missing for $Path"
    }
    for ($index = 0; $index -lt $expectedVerifyArguments.Count; $index++) {
        if ([string]$observedVerifyArguments[$index] -cne [string]$expectedVerifyArguments[$index]) {
            throw "independent signtool verification argv differs at index $index for $Path"
        }
    }
    $rolePath = $ExpectedRolePath
    if ([string]::IsNullOrWhiteSpace($rolePath)) {
        $resolvedPath = [System.IO.Path]::GetFullPath($Path)
        $resolvedBundle = ([System.IO.Path]::GetFullPath([string]$Plan.signed_bundle)).TrimEnd('\')
        $prefix = "$resolvedBundle\"
        if (-not $resolvedPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "cannot derive a role-relative path outside the signed bundle: $Path"
        }
        $rolePath = $resolvedPath.Substring($prefix.Length).Replace('\', '/')
    }
    [ordered]@{
        role_path = $rolePath.Replace('\', '/')
        status = 'Valid'
        signer_thumbprint = [string]$Plan.certificate_thumbprint
        signer_subject = [string]$signer.Subject
        timestamped = $true
        timestamp_certificate_thumbprint = Get-CertificateThumbprint $timestamp
        timestamp_certificate_subject = [string]$timestamp.Subject
        timestamp_url = [string]$Plan.timestamp_url
        timestamp_protocol = [string]$TimestampEvidence.protocol
        timestamp_attribute_oid = [string]$TimestampEvidence.attribute_oid
        timestamp_message_imprint_algorithm = [string]$TimestampEvidence.message_imprint_algorithm
        timestamp_message_imprint_algorithm_oid = [string]$TimestampEvidence.message_imprint_algorithm_oid
        timestamp_message_imprint = [string]$TimestampEvidence.message_imprint
        signer_signature_sha256 = [string]$TimestampEvidence.signer_signature_sha256
        timestamp_generalized_time = [string]$TimestampEvidence.generalized_time
        timestamp_cms_signature_valid = $true
        signtool_verify_exit_code = 0
        signtool_verify_policy = '/pa /all /v /tw'
        verifier = 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS'
    }
}

function Get-ReleaseFileInventory(
    [string]$Root,
    [switch]$ExcludeChecksumManifest,
    [string[]]$ExcludePaths = @()
) {
    $resolved = [System.IO.Path]::GetFullPath($Root)
    $excluded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($excludedPath in @($ExcludePaths)) {
        [void]$excluded.Add(([string]$excludedPath).Replace('\', '/'))
    }
    $entries = foreach ($file in @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force -ErrorAction Stop | Sort-Object FullName)) {
        if (($file.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "release inventory refuses a reparse file: $($file.FullName)"
        }
        $relative = $file.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
        if ($ExcludeChecksumManifest -and $relative -eq 'SHA256SUMS.json') { continue }
        if ($excluded.Contains($relative)) { continue }
        [ordered]@{
            path = $relative
            sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            bytes = [int64]$file.Length
        }
    }
    return @($entries)
}

function Get-ReleaseDirectoryInventory([string]$Root) {
    $resolved = [System.IO.Path]::GetFullPath($Root)
    $entries = foreach ($directory in @(
            Get-ChildItem -LiteralPath $resolved -Directory -Recurse -Force -ErrorAction Stop |
                Sort-Object FullName)) {
        if (($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "release inventory refuses a reparse directory: $($directory.FullName)"
        }
        $directory.FullName.Substring($resolved.Length).TrimStart([char]'\').Replace('\', '/')
    }
    return @($entries)
}

function Get-Sha256HexFromBytes([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-PeCertificateLayout([string]$Path) {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 256 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
        throw "release signing role is not a PE image: $Path"
    }
    $peOffset = [System.BitConverter]::ToInt32($bytes, 0x3c)
    if ($peOffset -lt 64 -or $peOffset + 24 -ge $bytes.Length -or
        $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
        $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
        throw "release signing role has an invalid PE header: $Path"
    }
    $optional = $peOffset + 24
    $magic = [System.BitConverter]::ToUInt16($bytes, $optional)
    $dataDirectories = if ($magic -eq 0x20b) { $optional + 112 } elseif ($magic -eq 0x10b) { $optional + 96 } else { -1 }
    $checksumOffset = $optional + 64
    $certificateDirectoryOffset = $dataDirectories + 32
    if ($dataDirectories -lt 0 -or $certificateDirectoryOffset + 8 -gt $bytes.Length -or
        $checksumOffset + 4 -gt $bytes.Length) {
        throw "release signing role optional header is malformed: $Path"
    }
    $certificateOffset = [uint32][System.BitConverter]::ToUInt32($bytes, $certificateDirectoryOffset)
    $certificateSize = [uint32][System.BitConverter]::ToUInt32($bytes, $certificateDirectoryOffset + 4)
    [ordered]@{
        path = $Path
        bytes_data = $bytes
        bytes = [int64]$bytes.Length
        pe_offset = $peOffset
        optional_magic = ('0x{0:x4}' -f $magic)
        checksum_offset = $checksumOffset
        certificate_directory_offset = $certificateDirectoryOffset
        certificate_offset = [uint64]$certificateOffset
        certificate_size = [uint64]$certificateSize
    }
}

function Get-UnsignedPeBaselineEvidence([string]$Path, [string]$RolePath) {
    $layout = Get-PeCertificateLayout $Path
    if ([uint64]$layout.certificate_offset -ne 0 -or [uint64]$layout.certificate_size -ne 0) {
        throw "unsigned source contains a PE certificate table: $RolePath"
    }
    $normalized = [byte[]]$layout.bytes_data.Clone()
    for ($index = 0; $index -lt 4; $index++) { $normalized[[int]$layout.checksum_offset + $index] = 0 }
    for ($index = 0; $index -lt 8; $index++) { $normalized[[int]$layout.certificate_directory_offset + $index] = 0 }
    [ordered]@{
        role_path = $RolePath
        unsigned_bytes = [int64]$layout.bytes
        checksum_offset = [int]$layout.checksum_offset
        certificate_directory_offset = [int]$layout.certificate_directory_offset
        normalized_image_sha256 = Get-Sha256HexFromBytes $normalized
    }
}

function Assert-PeCertificateTableOnlyDelta([object]$Baseline, [string]$SignedPath) {
    $layout = Get-PeCertificateLayout $SignedPath
    $unsignedBytes = [int64]$Baseline.unsigned_bytes
    $certificateOffset = [uint64]$layout.certificate_offset
    $certificateSize = [uint64]$layout.certificate_size
    if ([int]$layout.checksum_offset -ne [int]$Baseline.checksum_offset -or
        [int]$layout.certificate_directory_offset -ne [int]$Baseline.certificate_directory_offset -or
        $certificateOffset -lt [uint64]$unsignedBytes -or $certificateOffset -gt [uint64]($unsignedBytes + 7) -or
        ($certificateOffset % 8) -ne 0 -or $certificateSize -lt 8 -or
        $certificateOffset + $certificateSize -ne [uint64]$layout.bytes) {
        throw "Authenticode change is not one appended certificate table: $($Baseline.role_path)"
    }
    for ($index = $unsignedBytes; $index -lt [int64]$certificateOffset; $index++) {
        if ($layout.bytes_data[[int]$index] -ne 0) {
            throw "Authenticode alignment padding is not zero: $($Baseline.role_path)"
        }
    }
    $prefix = [byte[]]::new([int]$unsignedBytes)
    [System.Array]::Copy($layout.bytes_data, 0, $prefix, 0, [int]$unsignedBytes)
    for ($index = 0; $index -lt 4; $index++) { $prefix[[int]$Baseline.checksum_offset + $index] = 0 }
    for ($index = 0; $index -lt 8; $index++) { $prefix[[int]$Baseline.certificate_directory_offset + $index] = 0 }
    $normalizedHash = Get-Sha256HexFromBytes $prefix
    if ($normalizedHash -cne [string]$Baseline.normalized_image_sha256) {
        throw "PE image changed outside the Authenticode certificate table: $($Baseline.role_path)"
    }
    $certificateLength = [uint32][System.BitConverter]::ToUInt32($layout.bytes_data, [int]$certificateOffset)
    $revision = [uint16][System.BitConverter]::ToUInt16($layout.bytes_data, [int]$certificateOffset + 4)
    $certificateType = [uint16][System.BitConverter]::ToUInt16($layout.bytes_data, [int]$certificateOffset + 6)
    if ($certificateLength -lt 8 -or $certificateLength -gt $certificateSize -or
        $revision -ne 0x0200 -or $certificateType -ne 0x0002) {
        throw "PE certificate table is not one PKCS#7 WIN_CERTIFICATE: $($Baseline.role_path)"
    }
    [ordered]@{
        normalized_image_sha256 = $normalizedHash
        unsigned_bytes = $unsignedBytes
        signed_bytes = [int64]$layout.bytes
        certificate_table_offset = [uint64]$certificateOffset
        certificate_table_size = [uint64]$certificateSize
        win_certificate_length = [uint32]$certificateLength
    }
}

function Get-PePkcs7Payload([string]$Path) {
    $layout = Get-PeCertificateLayout $Path
    $offset = [int64]$layout.certificate_offset
    $size = [int64]$layout.certificate_size
    if ($offset -le 0 -or $size -lt 8 -or $offset + $size -gt [int64]$layout.bytes) {
        throw "PE does not contain a bounded certificate table: $Path"
    }
    $length = [int][System.BitConverter]::ToUInt32($layout.bytes_data, [int]$offset)
    if ($length -lt 9 -or $length -gt $size -or
        [System.BitConverter]::ToUInt16($layout.bytes_data, [int]$offset + 4) -ne 0x0200 -or
        [System.BitConverter]::ToUInt16($layout.bytes_data, [int]$offset + 6) -ne 0x0002) {
        throw "PE WIN_CERTIFICATE is not PKCS#7: $Path"
    }
    $payload = [byte[]]::new($length - 8)
    [System.Array]::Copy($layout.bytes_data, [int]$offset + 8, $payload, 0, $payload.Length)
    return ,$payload
}

function Read-DerElement([byte[]]$Data, [object]$State, [int]$ExpectedTag) {
    if ([int]$State.Offset -ge $Data.Length) { throw 'DER element is truncated' }
    $tag = [int]$Data[[int]$State.Offset]
    $State.Offset = [int]$State.Offset + 1
    if ($ExpectedTag -ge 0 -and $tag -ne $ExpectedTag) {
        throw "DER tag mismatch: expected=0x$('{0:x2}' -f $ExpectedTag) actual=0x$('{0:x2}' -f $tag)"
    }
    if ([int]$State.Offset -ge $Data.Length) { throw 'DER length is truncated' }
    $first = [int]$Data[[int]$State.Offset]
    $State.Offset = [int]$State.Offset + 1
    if (($first -band 0x80) -eq 0) {
        $length = $first
    }
    else {
        $count = $first -band 0x7f
        if ($count -lt 1 -or $count -gt 4 -or [int]$State.Offset + $count -gt $Data.Length) {
            throw 'DER uses an invalid or indefinite length'
        }
        $length = 0
        for ($index = 0; $index -lt $count; $index++) {
            $length = ($length * 256) + [int]$Data[[int]$State.Offset]
            $State.Offset = [int]$State.Offset + 1
        }
    }
    $contentOffset = [int]$State.Offset
    $end = $contentOffset + $length
    if ($length -lt 0 -or $end -gt $Data.Length) { throw 'DER content is truncated' }
    $State.Offset = $end
    [pscustomobject]@{ tag = $tag; content_offset = $contentOffset; length = $length; end = $end }
}

function Get-DerElementContent([byte[]]$Data, [object]$Element) {
    $content = [byte[]]::new([int]$Element.length)
    if ($content.Length -gt 0) {
        [System.Array]::Copy($Data, [int]$Element.content_offset, $content, 0, $content.Length)
    }
    return ,$content
}

function ConvertFrom-DerObjectIdentifier([byte[]]$Bytes) {
    if ($Bytes.Length -eq 0) { throw 'DER object identifier is empty' }
    $first = [int]$Bytes[0]
    $parts = [System.Collections.Generic.List[string]]::new()
    $firstArc = if ($first -lt 40) { 0 } elseif ($first -lt 80) { 1 } else { 2 }
    $secondArc = if ($firstArc -lt 2) { $first % 40 } else { $first - 80 }
    [void]$parts.Add([string]$firstArc)
    [void]$parts.Add([string]$secondArc)
    $value = [uint64]0
    for ($index = 1; $index -lt $Bytes.Length; $index++) {
        $value = ($value -shl 7) -bor [uint64]($Bytes[$index] -band 0x7f)
        if (($Bytes[$index] -band 0x80) -eq 0) {
            [void]$parts.Add([string]$value)
            $value = 0
        }
    }
    if (($Bytes[-1] -band 0x80) -ne 0) { throw 'DER object identifier is truncated' }
    return [string]::Join('.', $parts)
}

function Read-Rfc3161TstInfo([byte[]]$Data) {
    $outerState = [pscustomobject]@{ Offset = 0 }
    $outer = Read-DerElement $Data $outerState 0x30
    if ([int]$outerState.Offset -ne $Data.Length) { throw 'TSTInfo has trailing DER data' }
    $sequence = Get-DerElementContent $Data $outer
    $state = [pscustomobject]@{ Offset = 0 }
    [void](Read-DerElement $sequence $state 0x02) # version
    [void](Read-DerElement $sequence $state 0x06) # policy
    $messageImprintElement = Read-DerElement $sequence $state 0x30
    $messageImprint = Get-DerElementContent $sequence $messageImprintElement
    $imprintState = [pscustomobject]@{ Offset = 0 }
    $algorithmElement = Read-DerElement $messageImprint $imprintState 0x30
    $algorithm = Get-DerElementContent $messageImprint $algorithmElement
    $algorithmState = [pscustomobject]@{ Offset = 0 }
    $algorithmOidElement = Read-DerElement $algorithm $algorithmState 0x06
    $algorithmOid = ConvertFrom-DerObjectIdentifier (Get-DerElementContent $algorithm $algorithmOidElement)
    $imprintElement = Read-DerElement $messageImprint $imprintState 0x04
    $imprint = Get-DerElementContent $messageImprint $imprintElement
    if ([int]$imprintState.Offset -ne $messageImprint.Length) { throw 'TSTInfo messageImprint has trailing data' }
    [void](Read-DerElement $sequence $state 0x02) # serialNumber
    $timeElement = Read-DerElement $sequence $state 0x18
    $timeText = [System.Text.Encoding]::ASCII.GetString((Get-DerElementContent $sequence $timeElement))
    if ($timeText -cnotmatch '^\d{14}(?:\.\d+)?Z$') { throw 'TSTInfo genTime is not canonical UTC GeneralizedTime' }
    [ordered]@{
        message_imprint_algorithm_oid = $algorithmOid
        message_imprint = ([System.BitConverter]::ToString($imprint)).Replace('-', '').ToLowerInvariant()
        generalized_time = $timeText
    }
}

function Read-Rfc3161TimestampEvidence([string]$Path) {
    try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    $payload = [byte[]](Get-PePkcs7Payload $Path)
    $authenticodeCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $authenticodeCms.Decode($payload)
    $authenticodeCms.CheckSignature($true)
    if ($authenticodeCms.SignerInfos.Count -ne 1) {
        throw "Authenticode PKCS#7 must contain exactly one signer: $Path"
    }
    $signerInfo = $authenticodeCms.SignerInfos[0]
    $timestampAttributes = @($signerInfo.UnsignedAttributes | Where-Object {
            [string]$_.Oid.Value -ceq $script:Rfc3161TimestampAttributeOid
        })
    if ($timestampAttributes.Count -ne 1 -or $timestampAttributes[0].Values.Count -ne 1) {
        throw "exact RFC3161 unauthenticated timestamp token is missing: $Path"
    }
    if ($signerInfo.CounterSignerInfos.Count -ne 0) {
        throw "legacy Authenticode countersignature is not accepted as RFC3161 evidence: $Path"
    }
    $timestampCms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $timestampCms.Decode([byte[]]$timestampAttributes[0].Values[0].RawData)
    $timestampCms.CheckSignature($true)
    if ([string]$timestampCms.ContentInfo.ContentType.Value -cne $script:Rfc3161TstInfoContentTypeOid -or
        $timestampCms.SignerInfos.Count -ne 1 -or -not $timestampCms.SignerInfos[0].Certificate) {
        throw "RFC3161 timestamp CMS content/signer is malformed: $Path"
    }
    $tstInfo = Read-Rfc3161TstInfo ([byte[]]$timestampCms.ContentInfo.Content)
    if ([string]$tstInfo.message_imprint_algorithm_oid -cne $script:Sha256AlgorithmOid) {
        throw "RFC3161 messageImprint is not SHA-256: $Path"
    }
    $signatureValueHash = Get-Sha256HexFromBytes ([byte[]]$signerInfo.GetSignature())
    if ([string]$tstInfo.message_imprint -cne $signatureValueHash) {
        throw "RFC3161 messageImprint does not hash the Authenticode SignerInfo signature: $Path"
    }
    $timestampCertificate = $timestampCms.SignerInfos[0].Certificate
    [ordered]@{
        protocol = 'RFC3161'
        attribute_oid = $script:Rfc3161TimestampAttributeOid
        tst_info_content_type_oid = $script:Rfc3161TstInfoContentTypeOid
        message_imprint_algorithm = 'sha256'
        message_imprint_algorithm_oid = $script:Sha256AlgorithmOid
        message_imprint = [string]$tstInfo.message_imprint
        signer_signature_sha256 = $signatureValueHash
        generalized_time = [string]$tstInfo.generalized_time
        timestamp_certificate_thumbprint = Get-CertificateThumbprint $timestampCertificate
        timestamp_certificate_subject = [string]$timestampCertificate.Subject
        cms_signature_valid = $true
    }
}

function Assert-RuntimeArtifactBindings([string]$Bundle) {
    $runtimePath = Join-Path $Bundle 'runtime/RUNTIME_ARTIFACTS.json'
    $releasePath = Join-Path $Bundle 'RELEASE.json'
    $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
    $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $runtimeArtifacts = @($runtime.artifacts)
    $releaseArtifacts = @($release.runtime_artifacts)
    if ($runtimeArtifacts.Count -eq 0 -or $releaseArtifacts.Count -ne $runtimeArtifacts.Count -or
        [int]$release.runtime_artifact_count -ne $runtimeArtifacts.Count) {
        throw 'runtime/release artifact counts are not exact'
    }
    if ([string]$runtime.source_commit -cne [string]$release.source_commit -or
        [string]$runtime.version -cne [string]$release.version -or
        [string]$runtime.architecture -cne [string]$release.architecture) {
        throw 'runtime/release artifact manifests do not share one release identity'
    }
    $paths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($artifact in $runtimeArtifacts) {
        $relative = ([string]$artifact.path).Replace('\', '/')
        $segments = @($relative -split '/')
        if ([string]::IsNullOrWhiteSpace($relative) -or [System.IO.Path]::IsPathRooted($relative) -or
            $segments -contains '' -or $segments -contains '.' -or $segments -contains '..' -or
            -not $paths.Add($relative)) {
            throw "runtime artifact path is unsafe or duplicated: $relative"
        }
        $candidate = Join-Path $Bundle $relative.Replace('/', '\')
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "runtime artifact is missing: $relative"
        }
        $actualHash = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $actualBytes = [int64](Get-Item -LiteralPath $candidate).Length
        if ([string]$artifact.sha256 -cne $actualHash -or [int64]$artifact.bytes -ne $actualBytes) {
            throw "runtime artifact hash/size is stale: $relative"
        }
        $releaseMatch = @($releaseArtifacts | Where-Object {
                ([string]$_.path).Replace('\', '/') -eq $relative
            })
        if ($releaseMatch.Count -ne 1) {
            throw "RELEASE.json does not bind exactly one runtime artifact: $relative"
        }
        foreach ($field in @('package', 'binary', 'role', 'path', 'source', 'version', 'architecture', 'sha256', 'bytes')) {
            if ([string]$releaseMatch[0].$field -cne [string]$artifact.$field) {
                throw "runtime/release artifact field differs for ${relative}: $field"
            }
        }
    }
    [ordered]@{
        source_commit = [string]$release.source_commit
        version = [string]$release.version
        architecture = [string]$release.architecture
        artifact_count = $runtimeArtifacts.Count
    }
}

function New-ReleaseFinalizationBaseline([string]$Bundle) {
    [void](Assert-RuntimeArtifactBindings $Bundle)
    $peRoles = foreach ($role in @(Get-AuthenticodeRoleDefinitions)) {
        Get-UnsignedPeBaselineEvidence (Join-Path $Bundle $role.path) ([string]$role.path)
    }
    [ordered]@{
        bundle = [System.IO.Path]::GetFullPath($Bundle)
        files = @(Get-ReleaseFileInventory $Bundle)
        directories = @(Get-ReleaseDirectoryInventory $Bundle)
        pe_roles = @($peRoles)
    }
}

function Assert-SourceBaselineReadback([object]$Baseline) {
    $actual = @(Get-ReleaseFileInventory ([string]$Baseline.bundle))
    Assert-InventoryEqual @($Baseline.files) $actual 'unsigned source baseline readback'
    Assert-DirectoryInventoryEqual @($Baseline.directories) @(Get-ReleaseDirectoryInventory ([string]$Baseline.bundle)) 'unsigned source directory baseline readback'
}

function Assert-ExactFinalizationDelta([object]$Baseline, [string]$FinalBundle) {
    Assert-DirectoryInventoryEqual @($Baseline.directories) @(Get-ReleaseDirectoryInventory $FinalBundle) 'finalization directory delta'
    $before = @($Baseline.files)
    $after = @(Get-ReleaseFileInventory $FinalBundle)
    $beforeByPath = @{}
    $afterByPath = @{}
    foreach ($entry in $before) { $beforeByPath[[string]$entry.path] = $entry }
    foreach ($entry in $after) { $afterByPath[[string]$entry.path] = $entry }

    $rolePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($role in @(Get-AuthenticodeRoleDefinitions)) { [void]$rolePaths.Add([string]$role.path) }
    $manifestPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($path in @('RELEASE.json', 'runtime/RUNTIME_ARTIFACTS.json', 'SHA256SUMS.json')) {
        [void]$manifestPaths.Add($path)
    }

    foreach ($entry in $before) {
        $path = [string]$entry.path
        if ($path -eq 'SIGNING_REQUIRED.txt') {
            if ($afterByPath.ContainsKey($path)) {
                throw 'finalization delta retained SIGNING_REQUIRED.txt'
            }
            continue
        }
        if (-not $afterByPath.ContainsKey($path)) {
            throw "finalization delta removed an unapproved path: $path"
        }
        $final = $afterByPath[$path]
        $changed = [string]$entry.sha256 -cne [string]$final.sha256 -or
            [int64]$entry.bytes -ne [int64]$final.bytes
        if ($rolePaths.Contains($path) -or $manifestPaths.Contains($path)) {
            if (-not $changed) { throw "approved finalization path did not change: $path" }
        }
        elseif ($changed) {
            throw "non-role release path changed during signing: $path"
        }
    }
    foreach ($entry in $after) {
        $path = [string]$entry.path
        if (-not $beforeByPath.ContainsKey($path) -and $path -cne 'SIGNING_VERIFIED.json') {
            throw "finalization delta added an unapproved path: $path"
        }
    }
    if ($beforeByPath.ContainsKey('SIGNING_VERIFIED.json') -or
        -not $beforeByPath.ContainsKey('SIGNING_REQUIRED.txt') -or
        -not $afterByPath.ContainsKey('SIGNING_VERIFIED.json')) {
        throw 'finalization marker transition is not exact create-new/remove-old'
    }
    $peEvidence = foreach ($role in @(Get-AuthenticodeRoleDefinitions)) {
        $peBaseline = @($Baseline.pe_roles | Where-Object { [string]$_.role_path -eq [string]$role.path })
        if ($peBaseline.Count -ne 1) { throw "PE baseline is missing or duplicated: $($role.path)" }
        $evidence = Assert-PeCertificateTableOnlyDelta $peBaseline[0] (Join-Path $FinalBundle $role.path)
        $evidence['role_path'] = [string]$role.path
        [pscustomobject]$evidence
    }
    [void](Assert-RuntimeArtifactBindings $FinalBundle)
    [ordered]@{
        signed_roles_changed = $rolePaths.Count
        manifests_changed = $manifestPaths.Count
        marker_transition = 'SIGNING_REQUIRED.txt->SIGNING_VERIFIED.json'
        pe_normalization = @($peEvidence)
    }
}

function Assert-InventoryEqual([object[]]$Expected, [object[]]$Actual, [string]$Purpose) {
    if (@($Expected).Count -ne @($Actual).Count) {
        throw "$Purpose file count changed: expected=$(@($Expected).Count) actual=$(@($Actual).Count)"
    }
    for ($index = 0; $index -lt @($Expected).Count; $index++) {
        if ([string]$Expected[$index].path -cne [string]$Actual[$index].path -or
            [string]$Expected[$index].sha256 -cne [string]$Actual[$index].sha256 -or
            [int64]$Expected[$index].bytes -ne [int64]$Actual[$index].bytes) {
            throw "$Purpose differs at inventory entry $index"
        }
    }
}

function Assert-DirectoryInventoryEqual([string[]]$Expected, [string[]]$Actual, [string]$Purpose) {
    if (@($Expected).Count -ne @($Actual).Count) {
        throw "$Purpose directory count changed: expected=$(@($Expected).Count) actual=$(@($Actual).Count)"
    }
    for ($index = 0; $index -lt @($Expected).Count; $index++) {
        if ([string]$Expected[$index] -cne [string]$Actual[$index]) {
            throw "$Purpose differs at directory entry $index"
        }
    }
}

function New-OwnedStagingDirectory(
    [string]$Parent,
    [string]$Leaf,
    [scriptblock]$StagingPathFactory,
    [object]$ParentPin,
    [scriptblock]$AfterAtomicCreateHook
) {
    $resolvedParent = Get-FullyQualifiedWindowsPath $Parent 'staging parent'
    if (-not (Test-Path -LiteralPath $resolvedParent -PathType Container)) {
        throw "staging parent does not exist: $resolvedParent"
    }
    $token = [guid]::NewGuid().ToString('N')
    $staging = if ($StagingPathFactory) {
        & $StagingPathFactory $resolvedParent $Leaf $token
    }
    else {
        Join-Path $resolvedParent ".${Leaf}.authenticode-${token}.partial"
    }
    $staging = Get-FullyQualifiedWindowsPath ([string]$staging) 'owned staging path'
    if ([string]::Compare((Split-Path -Parent $staging), $resolvedParent, $true) -ne 0) {
        throw 'owned staging path must be a same-parent fully-qualified child'
    }

    # NtCreateFile(FILE_CREATE|FILE_DIRECTORY_FILE) resolves one relative leaf
    # under the retained parent and returns the new no-follow/no-delete-sharing
    # handle in the same system call. There is no create-then-open adoption gap.
    Initialize-ReleaseNativeFileSystem
    $localParentPin = $null
    $rootFence = $null
    $markerHandle = $null
    $markerWriteHandle = $null
    $stream = $null
    try {
        $effectiveParentPin = $ParentPin
        if (-not $effectiveParentPin) {
            $localParentPin = New-NativeDirectoryPin $resolvedParent $false $true
            $effectiveParentPin = $localParentPin
        }
        Assert-NativeDirectoryPin $effectiveParentPin 'atomic staging parent'
        if ([string]::Compare([string]$effectiveParentPin.path, $resolvedParent, $true) -ne 0) {
            throw 'atomic staging parent pin differs from the requested parent'
        }
        $childName = Split-Path -Leaf $staging
        $created = [EliotReleaseNativeFileSystem]::CreateDirectoryNewRetained(
            $effectiveParentPin.handle,
            $childName,
            $false)
        $rootFence = [pscustomobject]@{
            path = [string]$created.FinalPath
            identity = $created.Identity
            handle = $created.Handle
        }
        if ([string]::Compare([string]$rootFence.path, $staging, $true) -ne 0 -or
            -not (Test-NativeIdentityEqual $rootFence.identity $created.Identity)) {
            throw 'atomic staging create returned an unexpected path/identity'
        }
        if ($AfterAtomicCreateHook) { & $AfterAtomicCreateHook $staging $rootFence | Out-Null }
        Assert-NativeDirectoryPin $rootFence 'atomic staging ownership'

        $ownership = [pscustomobject][ordered]@{
            path = $staging
            token = $token
            native_identity = $rootFence.identity
            root_fence = $rootFence
            directory_fences = [System.Collections.Generic.List[object]]::new()
            child_fences_released = $false
            marker_fence = $null
            marker_sha256 = $null
            marker_bytes = [int64]0
            marker_removed = $false
            quarantined = $false
        }
        $markerHandle = [EliotReleaseNativeFileSystem]::CreateFileNewForWrite(
            $rootFence.handle,
            $script:StagingOwnerMarker)
        $markerIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity($markerHandle)
        $markerPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($markerHandle)
        $expectedMarkerPath = Join-Path $staging $script:StagingOwnerMarker
        if ([string]::Compare($markerPath, $expectedMarkerPath, $true) -ne 0) {
            throw 'atomic staging marker create returned an unexpected path'
        }
        $markerWriteHandle = [EliotReleaseNativeFileSystem]::DuplicateSameAccess($markerHandle)
        $stream = [System.IO.FileStream]::new($markerWriteHandle, [System.IO.FileAccess]::Write)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($token)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose()
        $stream = $null
        $markerWriteHandle = $null
        $ownership.marker_fence = [pscustomobject]@{
            path = $markerPath
            identity = $markerIdentity
            handle = $markerHandle
        }
        $ownership.marker_sha256 = Get-Sha256HexFromBytes $bytes
        $ownership.marker_bytes = [int64]$bytes.Length
        $markerHandle = $null
        return $ownership
    }
    catch {
        # A failed post-create readback leaves the new partial quarantined. No
        # pathname deletion is permitted when ownership was not returned.
        Close-NativeDirectoryPin $rootFence
        throw
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($markerWriteHandle -and -not $markerWriteHandle.IsClosed) { $markerWriteHandle.Dispose() }
        if ($markerHandle -and -not $markerHandle.IsClosed) { $markerHandle.Dispose() }
        Close-NativeDirectoryPin $localParentPin
    }
}

function Test-OwnedStagingIdentity([object]$Ownership) {
    if (-not $Ownership) { return $false }
    $path = Get-FullyQualifiedWindowsPath ([string]$Ownership.path) 'owned staging identity path'
    try {
        Assert-NativeDirectoryPin $Ownership.root_fence 'owned staging root'
        if ([string]::Compare([string]$Ownership.root_fence.path, $path, $true) -ne 0 -or
            -not (Test-NativeIdentityEqual $Ownership.root_fence.identity $Ownership.native_identity)) {
            return $false
        }
        foreach ($fence in @($Ownership.directory_fences)) {
            Assert-NativeDirectoryPin $fence 'owned staging child contour'
        }
    }
    catch {
        return $false
    }
    if ($Ownership.marker_removed -eq $true) { return $true }
    try {
        Assert-NativeDirectoryPin $Ownership.marker_fence 'owned staging marker'
        $markerIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity(
            $Ownership.marker_fence.handle)
        $markerDigest = [EliotReleaseNativeFileSystem]::ReadSha256AndSize(
            $Ownership.marker_fence.handle)
    }
    catch {
        return $false
    }
    return [uint32]$markerIdentity.NumberOfLinks -eq 1 -and
        [int64]$markerDigest.Bytes -eq [int64]$Ownership.marker_bytes -and
        [string]$markerDigest.Sha256 -ceq [string]$Ownership.marker_sha256
}

function Remove-OwnedStagingMarker([object]$Ownership) {
    if (-not (Test-OwnedStagingIdentity $Ownership)) {
        throw 'owned staging identity changed before marker removal'
    }
    $marker = Join-Path ([string]$Ownership.path) $script:StagingOwnerMarker
    [EliotReleaseNativeFileSystem]::DeleteFileByHandle($Ownership.marker_fence.handle)
    Close-NativeDirectoryPin $Ownership.marker_fence
    $Ownership.marker_removed = $true
    if (Test-Path -LiteralPath $marker) {
        throw 'handle-bound staging marker deletion did not remove the owned name'
    }
}

function Remove-OwnedStagingDirectory([object]$Ownership) {
    if (-not $Ownership) { return }
    # Recursive pathname cleanup is deliberately forbidden: even a successful
    # identity check followed by handle close has a substitution window. A
    # pre-commit failure therefore quarantines the partial for reconciliation.
    $Ownership.quarantined = $true
}

function Release-OwnedStagingChildFences([object]$Ownership) {
    if (-not $Ownership -or $Ownership.child_fences_released -eq $true) { return }
    $children = @($Ownership.directory_fences)
    for ($index = $children.Count - 1; $index -ge 0; $index--) {
        Close-NativeDirectoryPin $children[$index]
    }
    $Ownership.child_fences_released = $true
}

function Close-OwnedStagingFences([object]$Ownership) {
    if (-not $Ownership) { return }
    Close-NativeDirectoryPin $Ownership.marker_fence
    Release-OwnedStagingChildFences $Ownership
    Close-NativeDirectoryPin $Ownership.root_fence
}

function Close-RetainedReleaseFileContour([object[]]$Contour) {
    foreach ($fence in @($Contour)) {
        if ($fence -and $fence.handle -and -not $fence.handle.IsClosed) {
            $fence.handle.Dispose()
        }
    }
}

function Assert-RetainedReleaseFileContour(
    [object[]]$Contour,
    [string]$Root,
    [string]$Purpose
) {
    $resolvedRoot = Get-FullyQualifiedWindowsPath $Root "$Purpose root"
    foreach ($fence in @($Contour)) {
        if (-not $fence -or -not $fence.handle -or
            $fence.handle.IsClosed -or $fence.handle.IsInvalid) {
            throw "$Purpose retained file handle is unavailable: $($fence.relative_path)"
        }
        $expectedPath = [System.IO.Path]::GetFullPath((
                Join-Path $resolvedRoot ([string]$fence.relative_path).Replace('/', '\')))
        $observedPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($fence.handle)
        $observedIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity($fence.handle)
        $observedDigest = [EliotReleaseNativeFileSystem]::ReadSha256AndSize($fence.handle)
        if ([string]::Compare($observedPath, $expectedPath, $true) -ne 0 -or
            -not (Test-NativeIdentityEqual $observedIdentity $fence.identity) -or
            [uint32]$observedIdentity.NumberOfLinks -ne 1 -or
            [int64]$observedDigest.Bytes -ne [int64]$fence.bytes -or
            [string]$observedDigest.Sha256 -cne [string]$fence.sha256) {
            throw "$Purpose retained file path/identity/hash/size differs: $($fence.relative_path)"
        }
    }
}

function New-RetainedReleaseFileContour(
    [string]$Root,
    [object[]]$Inventory,
    [object[]]$PriorContour = @()
) {
    $resolvedRoot = Get-FullyQualifiedWindowsPath $Root 'retained file contour root'
    $priorByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prior in @($PriorContour)) {
        if ($priorByPath.ContainsKey([string]$prior.relative_path)) {
            throw "prior retained file contour duplicates a path: $($prior.relative_path)"
        }
        $priorByPath.Add([string]$prior.relative_path, $prior)
    }
    $seenPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    $seenIdentities = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal)
    $contour = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($entry in @($Inventory | Sort-Object { [string]$_.path })) {
            $relative = ([string]$entry.path).Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($relative) -or $relative.StartsWith('/') -or
                $relative.IndexOf(':') -ge 0 -or
                @($relative.Split('/') | Where-Object { $_ -eq '.' -or $_ -eq '..' }).Count -ne 0 -or
                -not $seenPaths.Add($relative)) {
                throw "retained file contour contains an unsafe/duplicate path: $relative"
            }
            $expectedPath = [System.IO.Path]::GetFullPath((
                    Join-Path $resolvedRoot $relative.Replace('/', '\')))
            if (-not $expectedPath.StartsWith($resolvedRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "retained file contour escaped its root: $relative"
            }
            $handle = [EliotReleaseNativeFileSystem]::OpenFileReadFence($expectedPath)
            $fence = $null
            try {
                $identity = [EliotReleaseNativeFileSystem]::ReadIdentity($handle)
                $observedPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($handle)
                $digest = [EliotReleaseNativeFileSystem]::ReadSha256AndSize($handle)
                if ([string]::Compare($observedPath, $expectedPath, $true) -ne 0 -or
                    [int64]$digest.Bytes -ne [int64]$entry.bytes -or
                    [string]$digest.Sha256 -cne [string]$entry.sha256) {
                    throw "retained file contour did not match inventory: $relative"
                }
                $identityKey = '{0:x8}:{1:x16}' -f
                    [uint32]$identity.VolumeSerialNumber,
                    [uint64]$identity.FileIndex
                if (-not $seenIdentities.Add($identityKey)) {
                    throw "retained file contour refuses duplicate/hardlinked identity: $relative"
                }
                $prior = $null
                if ($priorByPath.TryGetValue($relative, [ref]$prior) -and
                    (-not (Test-NativeIdentityEqual $identity $prior.identity) -or
                        [int64]$digest.Bytes -ne [int64]$prior.bytes -or
                        [string]$digest.Sha256 -cne [string]$prior.sha256)) {
                    throw "published file differs from the pre-commit identity/hash/size: $relative"
                }
                $fence = [pscustomobject]@{
                    relative_path = $relative
                    identity = $identity
                    sha256 = [string]$digest.Sha256
                    bytes = [int64]$digest.Bytes
                    handle = $handle
                }
                [void]$contour.Add($fence)
                $handle = $null
            }
            finally {
                if ($handle -and -not $handle.IsClosed) { $handle.Dispose() }
            }
        }
        if ($priorByPath.Count -gt 0 -and $priorByPath.Count -ne $contour.Count) {
            throw 'published file contour count differs from the pre-commit contour'
        }
        Assert-RetainedReleaseFileContour @($contour) $resolvedRoot 'newly acquired file contour'
        return @($contour)
    }
    catch {
        Close-RetainedReleaseFileContour @($contour)
        throw
    }
}

function Assert-PublishedDirectoryContour(
    [object]$Ownership,
    [string]$PublishedRoot
) {
    $root = Get-FullyQualifiedWindowsPath $PublishedRoot 'published contour root'
    $rootPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($Ownership.root_fence.handle)
    $rootIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity($Ownership.root_fence.handle)
    if ([string]::Compare($rootPath, $root, $true) -ne 0 -or
        -not (Test-NativeIdentityEqual $rootIdentity $Ownership.native_identity)) {
        throw 'published root handle path/identity differs'
    }
    foreach ($fence in @($Ownership.directory_fences)) {
        $expected = [System.IO.Path]::GetFullPath((Join-Path $root ([string]$fence.relative_path)))
        if (-not $expected.StartsWith($root + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'published child contour escaped the destination root'
        }
        $readback = $null
        try {
            $readback = New-NativeDirectoryPin $expected $true
            if (-not (Test-NativeIdentityEqual $readback.identity $fence.identity)) {
                throw "published child directory identity differs: $($fence.relative_path)"
            }
        }
        finally {
            Close-NativeDirectoryPin $readback
        }
    }
}

function Copy-BundleIntoOwnedStaging([string]$Source, [object]$Ownership) {
    $sourceRoot = Get-FullyQualifiedWindowsPath $Source 'unsigned bundle copy source'
    $stagingRoot = Get-FullyQualifiedWindowsPath ([string]$Ownership.path) 'owned staging copy destination'
    if (-not (Test-OwnedStagingIdentity $Ownership)) {
        throw 'owned staging identity changed before source copy'
    }

    # Every destination directory is created relative to its retained parent
    # handle and remains fenced for the complete staging lifetime. Files are
    # likewise created relative to that handle with FILE_CREATE.
    $sourceQueue = [System.Collections.Generic.Queue[object]]::new()
    $sourceQueue.Enqueue([pscustomobject]@{
            source_path = $sourceRoot
            destination_path = $stagingRoot
            destination_fence = $Ownership.root_fence
        })
    while ($sourceQueue.Count -gt 0) {
        $current = $sourceQueue.Dequeue()
        foreach ($item in @(Get-ChildItem -LiteralPath $current.source_path -Force -ErrorAction Stop | Sort-Object FullName)) {
                if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "unsigned source copy refuses reparse point: $($item.FullName)"
                }
                $itemPath = [System.IO.Path]::GetFullPath([string]$item.FullName)
                $relativePath = $itemPath.Substring($sourceRoot.Length).TrimStart('\')
                if ([string]::IsNullOrWhiteSpace($relativePath) -or
                    $relativePath.StartsWith('..\', [System.StringComparison]::Ordinal) -or
                    $relativePath.IndexOf(':') -ge 0) {
                    throw "unsigned source copy produced an unsafe relative path: $itemPath"
                }
                if ($relativePath -ceq $script:StagingOwnerMarker) {
                    throw "unsigned source contains reserved staging owner marker: $script:StagingOwnerMarker"
                }
                $destinationPath = [System.IO.Path]::GetFullPath((Join-Path $stagingRoot $relativePath))
                if (-not $destinationPath.StartsWith($stagingRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "unsigned source copy escaped the owned staging root: $relativePath"
                }

                if ($item -is [System.IO.DirectoryInfo]) {
                    $created = [EliotReleaseNativeFileSystem]::CreateDirectoryNewRetained(
                        $current.destination_fence.handle,
                        [string]$item.Name,
                        $true)
                    $childFence = [pscustomobject]@{
                        path = [string]$created.FinalPath
                        relative_path = $relativePath
                        identity = $created.Identity
                        handle = $created.Handle
                    }
                    if ([string]::Compare([string]$childFence.path, $destinationPath, $true) -ne 0) {
                        Close-NativeDirectoryPin $childFence
                        throw "atomic child-directory create returned an unexpected path: $relativePath"
                    }
                    [void]$Ownership.directory_fences.Add($childFence)
                    $sourceQueue.Enqueue([pscustomobject]@{
                            source_path = $itemPath
                            destination_path = $destinationPath
                            destination_fence = $childFence
                        })
                    continue
                }
                if (-not ($item -is [System.IO.FileInfo])) {
                    throw "unsigned source contains an unsupported filesystem object: $itemPath"
                }

                $sourceStream = $null
                $destinationStream = $null
                $destinationHandle = $null
                try {
                    $sourceStream = [System.IO.File]::Open(
                        $itemPath,
                        [System.IO.FileMode]::Open,
                        [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::Read)
                    $destinationHandle = [EliotReleaseNativeFileSystem]::CreateFileNewForWrite(
                        $current.destination_fence.handle,
                        [string]$item.Name)
                    $observedDestination = [EliotReleaseNativeFileSystem]::ReadFinalPath($destinationHandle)
                    $destinationIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity($destinationHandle)
                    if ([string]::Compare($observedDestination, $destinationPath, $true) -ne 0 -or
                        ([uint32]$destinationIdentity.Attributes -band [uint32][System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                        ([uint32]$destinationIdentity.Attributes -band [uint32][System.IO.FileAttributes]::Directory) -ne 0) {
                        throw "atomic child-file create returned an unexpected path/type: $relativePath"
                    }
                    $destinationStream = [System.IO.FileStream]::new($destinationHandle, [System.IO.FileAccess]::Write)
                    $sourceStream.CopyTo($destinationStream)
                    $destinationStream.Flush($true)
                }
                finally {
                    if ($destinationStream) { $destinationStream.Dispose() }
                    if ($destinationHandle -and -not $destinationHandle.IsClosed) { $destinationHandle.Dispose() }
                    if ($sourceStream) { $sourceStream.Dispose() }
                }
        }
    }
    if (-not (Test-OwnedStagingIdentity $Ownership)) {
        throw 'owned staging contour changed during source copy'
    }
}

function ConvertTo-SignatureEvidence([object]$Plan, [object]$Certificate, [object[]]$RoleEvidence) {
    $firstRole = @($RoleEvidence)[0]
    [ordered]@{
        schema = 'eliot-authenticode-signature-evidence-v1'
        status = 'VERIFIED'
        policy = $script:AuthenticodeSigningPolicy
        scope = $script:AuthenticodeSigningScope
        signer = [ordered]@{
            store_location = [string]$Plan.certificate_store_location
            thumbprint = [string]$Plan.certificate_thumbprint
            subject = [string]$Certificate.Subject
            has_private_key = $true
            code_signing_eku = $script:AuthenticodeCodeSigningEku
        }
        timestamp = [ordered]@{
            url = [string]$Plan.timestamp_url
            digest_algorithm = [string]$firstRole.timestamp_message_imprint_algorithm
            digest_algorithm_oid = [string]$firstRole.timestamp_message_imprint_algorithm_oid
            protocol = [string]$firstRole.timestamp_protocol
            attribute_oid = [string]$firstRole.timestamp_attribute_oid
        }
        verifier = 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS'
        roles = @($RoleEvidence)
    }
}

function Set-JsonFile([string]$Path, [object]$Value) {
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8
}

function Set-ObjectProperty([object]$Object, [string]$Name, [object]$Value) {
    $property = $Object.PSObject.Properties[$Name]
    if ($property) {
        $property.Value = $Value
    }
    else {
        Add-Member -InputObject $Object -MemberType NoteProperty -Name $Name -Value $Value
    }
}

function Update-SignedReleaseManifests([string]$Bundle, [object]$Plan, [object]$Certificate, [object[]]$RoleEvidence) {
    $runtimePath = Join-Path $Bundle 'runtime/RUNTIME_ARTIFACTS.json'
    $releasePath = Join-Path $Bundle 'RELEASE.json'
    $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json
    $release = Get-Content -LiteralPath $releasePath -Raw | ConvertFrom-Json
    $signatureEvidence = ConvertTo-SignatureEvidence $Plan $Certificate $RoleEvidence
    $byPath = @{}
    foreach ($receipt in $RoleEvidence) { $byPath[[string]$receipt.role_path] = $receipt }

    $runtimeArtifacts = foreach ($artifact in @($runtime.artifacts)) {
        $path = ([string]$artifact.path).Replace('\', '/')
        $copy = [ordered]@{}
        foreach ($property in $artifact.PSObject.Properties) {
            $copy[$property.Name] = $property.Value
        }
        $candidate = Join-Path $Bundle $path
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "runtime manifest points to a missing artifact while finalizing: $path"
        }
        $copy['sha256'] = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash.ToLowerInvariant()
        $copy['bytes'] = [int64](Get-Item -LiteralPath $candidate).Length
        if ($byPath.ContainsKey($path)) {
            $copy['signature_policy'] = $script:AuthenticodeSigningPolicy
            $copy['signature_evidence'] = $byPath[$path]
        }
        [pscustomobject]$copy
    }
    Set-ObjectProperty $runtime 'signed' $true
    Set-ObjectProperty $runtime 'signature_policy' $script:AuthenticodeSigningPolicy
    Set-ObjectProperty $runtime 'signature_evidence' $signatureEvidence
    Set-ObjectProperty $runtime 'signed_scope' $script:AuthenticodeSigningScope
    Set-ObjectProperty $runtime 'artifacts' @($runtimeArtifacts)
    Set-JsonFile $runtimePath $runtime

    $releaseArtifacts = foreach ($artifact in @($release.runtime_artifacts)) {
        $path = ([string]$artifact.path).Replace('\', '/')
        $runtimeArtifact = @($runtime.artifacts | Where-Object { ([string]$_.path).Replace('\', '/') -eq $path })
        if ($runtimeArtifact.Count -ne 1) {
            throw "RELEASE.json runtime artifact is not bound to RUNTIME_ARTIFACTS.json: $path"
        }
        $copy = [ordered]@{}
        foreach ($property in $artifact.PSObject.Properties) {
            $copy[$property.Name] = $property.Value
        }
        $copy['sha256'] = [string]$runtimeArtifact[0].sha256
        $copy['bytes'] = [int64]$runtimeArtifact[0].bytes
        if ($byPath.ContainsKey($path)) {
            $copy['signature_policy'] = $script:AuthenticodeSigningPolicy
            $copy['signature_evidence'] = $byPath[$path]
        }
        [pscustomobject]$copy
    }
    Set-ObjectProperty $release 'signed' $true
    Set-ObjectProperty $release 'signature_policy' $script:AuthenticodeSigningPolicy
    Set-ObjectProperty $release 'signature_evidence' $signatureEvidence
    Set-ObjectProperty $release 'signed_scope' $script:AuthenticodeSigningScope
    Set-ObjectProperty $release 'public_distribution_ready' $true
    Set-ObjectProperty $release 'runtime_artifacts' @($releaseArtifacts)
    Set-JsonFile $releasePath $release

    $unsignedMarker = Join-Path $Bundle 'SIGNING_REQUIRED.txt'
    if (Test-Path -LiteralPath $unsignedMarker) {
        Remove-Item -LiteralPath $unsignedMarker -Force
    }
    Set-JsonFile (Join-Path $Bundle 'SIGNING_VERIFIED.json') ([ordered]@{
            schema = 'eliot-authenticode-signing-verification-v1'
            source_commit = [string]$release.source_commit
            version = [string]$release.version
            signature_evidence = $signatureEvidence
        })

    $hashes = Get-ReleaseFileInventory $Bundle -ExcludeChecksumManifest -ExcludePaths @($script:StagingOwnerMarker)
    Set-JsonFile (Join-Path $Bundle 'SHA256SUMS.json') ([ordered]@{
            component = 'eliot_windows_x64_release_manifest'
            version = [string]$release.version
            source_commit = [string]$release.source_commit
            architecture = [string]$release.architecture
            signed = $true
            signature_policy = $script:AuthenticodeSigningPolicy
            signed_scope = $script:AuthenticodeSigningScope
            signature_evidence = $signatureEvidence
            files = @($hashes)
        })
    return $signatureEvidence
}

function Test-FinalizedReleaseBundle(
    [string]$Path,
    [scriptblock]$SignatureReader,
    [object]$Baseline,
    [object]$ExpectedPlan,
    [object]$ExpectedCertificate,
    [scriptblock]$SignToolVerifier,
    [scriptblock]$TimestampTokenReader
) {
    $resolved = Assert-ExistingBundleDirectory $Path 'SignedBundle'
    Assert-NoReleaseSecrets $resolved
    foreach ($required in @(
            'RELEASE.json',
            'runtime/RUNTIME_ARTIFACTS.json',
            'SHA256SUMS.json',
            'SIGNING_VERIFIED.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $resolved $required) -PathType Leaf)) {
            throw "finalized bundle is missing required asset: $required"
        }
    }
    if (Test-Path -LiteralPath (Join-Path $resolved 'SIGNING_REQUIRED.txt')) {
        throw 'finalized bundle retained the unsigned SIGNING_REQUIRED.txt marker'
    }
    $release = Get-Content -LiteralPath (Join-Path $resolved 'RELEASE.json') -Raw | ConvertFrom-Json
    $runtime = Get-Content -LiteralPath (Join-Path $resolved 'runtime/RUNTIME_ARTIFACTS.json') -Raw | ConvertFrom-Json
    $checksum = Get-Content -LiteralPath (Join-Path $resolved 'SHA256SUMS.json') -Raw | ConvertFrom-Json
    $verified = Get-Content -LiteralPath (Join-Path $resolved 'SIGNING_VERIFIED.json') -Raw | ConvertFrom-Json
    foreach ($manifest in @($release, $runtime, $checksum)) {
        if ($manifest.signed -ne $true -or [string]$manifest.signature_policy -cne $script:AuthenticodeSigningPolicy -or
            [string]$manifest.signed_scope -cne $script:AuthenticodeSigningScope) {
            throw 'a finalized manifest does not carry the exact signed boundary'
        }
    }
    if ([string]$verified.schema -cne 'eliot-authenticode-signing-verification-v1' -or
        [string]$verified.signature_evidence.status -cne 'VERIFIED') {
        throw 'SIGNING_VERIFIED.json is not an exact verification receipt'
    }
    $releaseEvidence = $release.signature_evidence | ConvertTo-Json -Depth 12 -Compress
    $runtimeEvidence = $runtime.signature_evidence | ConvertTo-Json -Depth 12 -Compress
    $checksumEvidence = $checksum.signature_evidence | ConvertTo-Json -Depth 12 -Compress
    if ($releaseEvidence -cne $runtimeEvidence -or $releaseEvidence -cne $checksumEvidence) {
        throw 'RELEASE.json, RUNTIME_ARTIFACTS.json, and SHA256SUMS.json do not share exact signature evidence'
    }
    $roles = @(Get-AuthenticodeRoleDefinitions)
    $evidenceRoles = @($release.signature_evidence.roles)
    if ($evidenceRoles.Count -ne $roles.Count) {
        throw "finalized signature evidence role count mismatch: $($evidenceRoles.Count)"
    }
    if (-not $ExpectedPlan -or -not $ExpectedCertificate) {
        throw 'finalized verification requires an external signing plan and exact certificate readback'
    }
    Assert-CodeSigningCertificateIdentity $ExpectedCertificate $ExpectedPlan.certificate_store_location $ExpectedPlan.certificate_thumbprint | Out-Null
    $plan = [pscustomobject]@{
        signed_bundle = $resolved
        signtool_path = [string]$ExpectedPlan.signtool_path
        certificate_store_location = [string]$ExpectedPlan.certificate_store_location
        certificate_thumbprint = [string]$ExpectedPlan.certificate_thumbprint
        timestamp_url = [string]$ExpectedPlan.timestamp_url
    }
    if ([string]$release.signature_evidence.signer.store_location -cne [string]$plan.certificate_store_location -or
        [string]$release.signature_evidence.signer.thumbprint -cne [string]$plan.certificate_thumbprint -or
        [string]$release.signature_evidence.signer.subject -cne [string]$ExpectedCertificate.Subject -or
        [string]$release.signature_evidence.timestamp.url -cne [string]$plan.timestamp_url -or
        $plan.certificate_thumbprint -notmatch '^[0-9a-f]{40}$' -or
        [string]::IsNullOrWhiteSpace([string]$release.signature_evidence.signer.subject) -or
        $release.signature_evidence.signer.has_private_key -ne $true -or
        [string]$release.signature_evidence.signer.code_signing_eku -cne $script:AuthenticodeCodeSigningEku -or
        [string]$release.signature_evidence.verifier -cne 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS' -or
        [string]$release.signature_evidence.timestamp.protocol -cne 'RFC3161' -or
        [string]$release.signature_evidence.timestamp.digest_algorithm -cne 'sha256' -or
        [string]$release.signature_evidence.timestamp.digest_algorithm_oid -cne $script:Sha256AlgorithmOid -or
        [string]$release.signature_evidence.timestamp.attribute_oid -cne $script:Rfc3161TimestampAttributeOid) {
        throw 'finalized signature evidence signer/timestamp binding is malformed'
    }
    if (-not $SignatureReader) { $SignatureReader = ${function:Read-AuthenticodeSignature} }
    if (-not $SignToolVerifier) { $SignToolVerifier = ${function:Invoke-ConfiguredSignToolVerify} }
    if (-not $TimestampTokenReader) { $TimestampTokenReader = ${function:Read-Rfc3161TimestampEvidence} }
    foreach ($role in $roles) {
        $relative = [string]$role.path
        $receipt = @($evidenceRoles | Where-Object { [string]$_.role_path -eq $relative })
        if ($receipt.Count -ne 1) {
            throw "finalized signature evidence is missing or duplicated for $relative"
        }
        if ([string]$receipt[0].role -cne [string]$role.role -or
            [string]$receipt[0].status -cne 'Valid' -or
            [string]$receipt[0].signer_thumbprint -cne [string]$plan.certificate_thumbprint -or
            [string]$receipt[0].signer_subject -cne [string]$release.signature_evidence.signer.subject -or
            $receipt[0].timestamped -ne $true -or
            [string]$receipt[0].timestamp_url -cne [string]$plan.timestamp_url -or
            [string]$receipt[0].timestamp_protocol -cne 'RFC3161' -or
            [string]$receipt[0].timestamp_attribute_oid -cne $script:Rfc3161TimestampAttributeOid -or
            [string]$receipt[0].timestamp_message_imprint_algorithm_oid -cne $script:Sha256AlgorithmOid -or
            $receipt[0].timestamp_cms_signature_valid -ne $true -or
            [int]$receipt[0].signtool_verify_exit_code -ne 0 -or
            [string]$receipt[0].signtool_verify_policy -cne '/pa /all /v /tw' -or
            [string]$receipt[0].verifier -cne 'SignTool(/pa,/all,/v,/tw)+Get-AuthenticodeSignature/WinTrust+RFC3161-CMS') {
            throw "finalized signature evidence is missing or substituted for $relative"
        }
        $pathValue = Join-Path $resolved $relative
        $verifyArguments = @(Get-SignToolVerifyArguments $pathValue)
        $signToolEvidence = & $SignToolVerifier $plan.signtool_path $verifyArguments $pathValue
        $readback = & $SignatureReader $pathValue
        $timestampEvidence = & $TimestampTokenReader $pathValue
        $readbackEvidence = Assert-AuthenticodeReadback $readback $plan $pathValue ([string]$ExpectedCertificate.Subject) $relative $timestampEvidence $signToolEvidence
        if ([string]$readbackEvidence.timestamp_certificate_thumbprint -cne [string]$receipt[0].timestamp_certificate_thumbprint -or
            [string]$readbackEvidence.timestamp_certificate_subject -cne [string]$receipt[0].timestamp_certificate_subject -or
            [string]$readbackEvidence.timestamp_message_imprint -cne [string]$receipt[0].timestamp_message_imprint -or
            [string]$readbackEvidence.signer_signature_sha256 -cne [string]$receipt[0].signer_signature_sha256) {
            throw "RFC3161 timestamp certificate substitution/readback mismatch for $relative"
        }

        $runtimeArtifact = @($runtime.artifacts | Where-Object { ([string]$_.path).Replace('\', '/') -eq $relative })
        $releaseArtifact = @($release.runtime_artifacts | Where-Object { ([string]$_.path).Replace('\', '/') -eq $relative })
        $runtimeArtifactEvidence = ''
        $releaseArtifactEvidence = ''
        $receiptEvidence = [string]($receipt[0] | ConvertTo-Json -Depth 12 -Compress)
        if ($runtimeArtifact.Count -eq 1 -and $releaseArtifact.Count -eq 1) {
            $runtimeArtifactEvidence = [string]($runtimeArtifact[0].signature_evidence | ConvertTo-Json -Depth 12 -Compress)
            $releaseArtifactEvidence = [string]($releaseArtifact[0].signature_evidence | ConvertTo-Json -Depth 12 -Compress)
        }
        if ($runtimeArtifact.Count -ne 1 -or $releaseArtifact.Count -ne 1) {
            throw "runtime/release artifact signature binding is missing or duplicated for $relative"
        }
        if ([string]$runtimeArtifact[0].signature_policy -cne $script:AuthenticodeSigningPolicy -or
            [string]$releaseArtifact[0].signature_policy -cne $script:AuthenticodeSigningPolicy -or
            $runtimeArtifactEvidence -cne $releaseArtifactEvidence -or
            $runtimeArtifactEvidence -cne $receiptEvidence) {
            throw "runtime/release artifact signature binding is not coherent for $relative"
        }
    }
    if ([string]($verified.signature_evidence | ConvertTo-Json -Depth 12 -Compress) -cne $releaseEvidence) {
        throw 'SIGNING_VERIFIED.json does not repeat the exact release signature evidence'
    }
    $declared = @($checksum.files)
    $actual = @(Get-ReleaseFileInventory $resolved -ExcludeChecksumManifest)
    if ($declared.Count -ne $actual.Count) {
        throw "SHA256SUMS.json file count mismatch: declared=$($declared.Count) actual=$($actual.Count)"
    }
    $declaredByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($entry in $declared) {
        $path = [string]$entry.path
        if ($declaredByPath.ContainsKey($path)) {
            throw "SHA256SUMS.json contains a duplicate path: $path"
        }
        $declaredByPath.Add($path, $entry)
    }
    $actualByPath = [System.Collections.Generic.Dictionary[string, object]]::new(
        [System.StringComparer]::Ordinal)
    foreach ($entry in $actual) {
        $path = [string]$entry.path
        if ($actualByPath.ContainsKey($path)) {
            throw "release inventory contains a duplicate path: $path"
        }
        $actualByPath.Add($path, $entry)
    }
    foreach ($entry in $declared) {
        $path = [string]$entry.path
        if (-not $actualByPath.ContainsKey($path)) {
            throw "SHA256SUMS.json path is missing from final bytes: $path"
        }
        $observed = $actualByPath[$path]
        if ([string]$entry.sha256 -cne [string]$observed.sha256 -or
            [int64]$entry.bytes -ne [int64]$observed.bytes) {
            throw "SHA256SUMS.json does not match final bytes: $path"
        }
    }
    foreach ($entry in $actual) {
        $path = [string]$entry.path
        if (-not $declaredByPath.ContainsKey($path)) {
            throw "final bytes contain an unmanifested path: $path"
        }
    }
    [void](Assert-RuntimeArtifactBindings $resolved)
    if ($Baseline) {
        [void](Assert-ExactFinalizationDelta $Baseline $resolved)
    }
    [ordered]@{
        component = 'eliot_windows_x64_release_verify'
        status = 'VERIFIED_SIGNED'
        verification_kind = 'READ_ONLY_SNAPSHOT'
        durable_install_authority = $false
        bundle = $resolved
        signed_scope = $script:AuthenticodeSigningScope
        roles = $roles.Count
        files = $actual.Count
    }
}

function Invoke-ReleaseBundleFinalization {
    param(
        [Parameter(Mandatory = $true)][object]$Plan,
        [scriptblock]$SignToolInvoker,
        [scriptblock]$SignToolVerifier,
        [scriptblock]$SignatureReader,
        [scriptblock]$TimestampTokenReader,
        [scriptblock]$CertificateResolver,
        [scriptblock]$InputValidator,
        [scriptblock]$OutputValidator,
        [scriptblock]$StagingFactory,
        [scriptblock]$StagingPathFactory,
        [scriptblock]$AfterStagingCreateHook,
        [scriptblock]$AfterChildFencesReleasedHook,
        [scriptblock]$AfterMoveHook,
        [scriptblock]$AfterFinalValidatorHook
    )
    if (-not $SignToolInvoker) { $SignToolInvoker = ${function:Invoke-ConfiguredSignTool} }
    if (-not $SignToolVerifier) { $SignToolVerifier = ${function:Invoke-ConfiguredSignToolVerify} }
    if (-not $SignatureReader) { $SignatureReader = ${function:Read-AuthenticodeSignature} }
    if (-not $TimestampTokenReader) { $TimestampTokenReader = ${function:Read-Rfc3161TimestampEvidence} }
    if (-not $CertificateResolver) { $CertificateResolver = ${function:Resolve-CodeSigningCertificate} }
    if (-not $InputValidator) { $InputValidator = ${function:Test-ReleaseBundle} }
    if (-not $OutputValidator) { $OutputValidator = ${function:Test-FinalizedReleaseBundle} }
    if (-not $StagingFactory) { $StagingFactory = ${function:New-OwnedStagingDirectory} }

    $parent = Split-Path -Parent $Plan.signed_bundle
    $leaf = Split-Path -Leaf $Plan.signed_bundle
    $ownership = $null
    $committed = $false
    $sourcePin = $null
    $parentPin = $null
    $destinationPin = $null
    $stagingFileContour = @()
    $postCommitFileContour = @()
    $finalInventory = @()
    try {
        # Retained no-follow source and destination-parent handles close the
        # path substitution window before the complete source checkpoint.
        $sourcePin = New-NativeDirectoryPin $Plan.unsigned_bundle $false
        $parentPin = New-NativeDirectoryPin $parent $false $true
        & $InputValidator $Plan.unsigned_bundle | Out-Null
        $baseline = New-ReleaseFinalizationBaseline $Plan.unsigned_bundle
        Assert-NativeDirectoryPin $sourcePin 'unsigned source'
        Assert-NativeDirectoryPin $parentPin 'publication parent'

        $certificate = & $CertificateResolver $Plan.certificate_store_location $Plan.certificate_thumbprint
        Assert-CodeSigningCertificate $certificate $Plan.certificate_store_location $Plan.certificate_thumbprint | Out-Null
        $signerSubject = [string]$certificate.Subject

        # A builder-produced input must still be genuinely unsigned; a stale
        # signed directory may not be adopted merely because its JSON says false.
        foreach ($role in @(Get-AuthenticodeRoleDefinitions)) {
            $sourceRole = Join-Path $Plan.unsigned_bundle $role.path
            $readback = & $SignatureReader $sourceRole
            if (-not $readback -or [string]$readback.Status -cne 'NotSigned') {
                throw "UnsignedBundle role is not independently NotSigned: $($role.path)"
            }
        }

        $ownership = & $StagingFactory $parent $leaf $StagingPathFactory $parentPin
        $staging = [string]$ownership.path
        if ($AfterStagingCreateHook) { & $AfterStagingCreateHook $ownership | Out-Null }
        Copy-BundleIntoOwnedStaging $Plan.unsigned_bundle $ownership
        $stagingInventory = @(Get-ReleaseFileInventory $staging -ExcludePaths @($script:StagingOwnerMarker))
        Assert-InventoryEqual @($baseline.files) $stagingInventory 'unsigned bundle copy'
        Assert-DirectoryInventoryEqual @($baseline.directories) @(Get-ReleaseDirectoryInventory $staging) 'unsigned bundle copy'
        Assert-SourceBaselineReadback $baseline
        # The ownership marker is outside the release inventory. Delete its
        # retained identity by handle after the copy equality gate, then run
        # every path-based scanner and the complete unsigned bundle validator.
        Remove-OwnedStagingMarker $ownership
        Assert-NoReleaseSecrets $staging
        & $InputValidator $staging | Out-Null
        Assert-InventoryEqual @($baseline.files) @(Get-ReleaseFileInventory $staging) 'validated unsigned staging bundle'
        Assert-SourceBaselineReadback $baseline

        $roleEvidence = [System.Collections.Generic.List[object]]::new()
        foreach ($role in @(Get-AuthenticodeRoleDefinitions)) {
            $path = Join-Path $staging $role.path
            $arguments = @(Get-SignToolArguments $Plan $path)
            & $SignToolInvoker $Plan.signtool_path $arguments $path
            $verifyArguments = @(Get-SignToolVerifyArguments $path)
            $signToolEvidence = & $SignToolVerifier $Plan.signtool_path $verifyArguments $path
            $readback = & $SignatureReader $path
            $timestampEvidence = & $TimestampTokenReader $path
            $receipt = Assert-AuthenticodeReadback $readback $Plan $path $signerSubject ([string]$role.path) $timestampEvidence $signToolEvidence
            $peBaseline = @($baseline.pe_roles | Where-Object { [string]$_.role_path -eq [string]$role.path })
            if ($peBaseline.Count -ne 1) { throw "PE baseline is missing or duplicated: $($role.path)" }
            $peEvidence = Assert-PeCertificateTableOnlyDelta $peBaseline[0] $path
            foreach ($property in $peEvidence.GetEnumerator()) { $receipt[$property.Key] = $property.Value }
            $receipt.role = [string]$role.role
            [void]$roleEvidence.Add([pscustomobject]$receipt)
        }
        if ($roleEvidence.Count -ne 6) {
            throw "exact six Authenticode roles were not signed: $($roleEvidence.Count)"
        }

        $signatureEvidence = Update-SignedReleaseManifests $staging $Plan $certificate @($roleEvidence)
        Assert-SourceBaselineReadback $baseline
        $finalInventory = @(Get-ReleaseFileInventory $staging)
        $stagingFileContour = @(New-RetainedReleaseFileContour $staging $finalInventory)
        if (-not (Test-OwnedStagingIdentity $ownership)) {
            throw 'owned staging directory contour changed during file-fence acquisition'
        }
        & $OutputValidator $staging $SignatureReader $baseline $Plan $certificate $SignToolVerifier $TimestampTokenReader | Out-Null
        Assert-RetainedReleaseFileContour $stagingFileContour $staging 'pre-commit final file contour'

        Assert-NativeDirectoryPin $sourcePin 'unsigned source'
        Assert-NativeDirectoryPin $parentPin 'publication parent'
        if (-not (Test-OwnedStagingIdentity $ownership)) {
            throw 'owned staging contour changed before handle-bound publication'
        }
        # Windows refuses an ancestor-directory rename while descendant handles
        # remain open, even with FILE_SHARE_DELETE. Release the exact file and
        # directory identity contours only after complete pre-commit validation;
        # the retained root and parent fences remain live. Post-commit acquisition
        # must match every pre-commit file identity/hash/size before success.
        Close-RetainedReleaseFileContour $stagingFileContour
        Release-OwnedStagingChildFences $ownership
        if ($AfterChildFencesReleasedHook) {
            & $AfterChildFencesReleasedHook $ownership | Out-Null
        }
        Assert-NativeDirectoryPin $ownership.root_fence 'owned staging root at publication'
        Assert-NativeDirectoryPin $parentPin 'publication parent at publication'
        # NtSetInformationFile(FileRenameInformation) with
        # ReplaceIfExists=FALSE publishes the retained staging object to one
        # relative leaf under the retained parent handle. It cannot resolve a
        # process-relative destination or replace a preexisting target.
        [EliotReleaseNativeFileSystem]::PublishDirectoryHandleCreateNew(
            $ownership.root_fence.handle,
            $parentPin.handle,
            $leaf)
        $committed = $true
        try {
            if ($AfterMoveHook) { & $AfterMoveHook $Plan.signed_bundle $ownership | Out-Null }
            $movedPath = [EliotReleaseNativeFileSystem]::ReadFinalPath($ownership.root_fence.handle)
            $movedIdentity = [EliotReleaseNativeFileSystem]::ReadIdentity($ownership.root_fence.handle)
            if ([string]::Compare($movedPath, [string]$Plan.signed_bundle, $true) -ne 0 -or
                -not (Test-NativeIdentityEqual $movedIdentity $ownership.native_identity)) {
                throw 'post-commit moved source path/identity readback differs'
            }
            $destinationPin = New-NativeDirectoryPin $Plan.signed_bundle $true
            if (-not (Test-NativeIdentityEqual $destinationPin.identity $ownership.native_identity)) {
                throw 'post-commit destination identity differs from owned staging identity'
            }
            Assert-PublishedDirectoryContour $ownership $Plan.signed_bundle
            $postCommitFileContour = @(New-RetainedReleaseFileContour `
                    $Plan.signed_bundle `
                    $finalInventory `
                    $stagingFileContour)
            Assert-PublishedDirectoryContour $ownership $Plan.signed_bundle
            Assert-NativeDirectoryPin $parentPin 'publication parent'
            Assert-NativeDirectoryPin $sourcePin 'unsigned source'
            # Publication success is withheld until the moved destination has
            # passed the complete signature, manifest, checksum and delta gate.
            & $OutputValidator $Plan.signed_bundle $SignatureReader $baseline $Plan $certificate $SignToolVerifier $TimestampTokenReader | Out-Null
            if ($AfterFinalValidatorHook) {
                & $AfterFinalValidatorHook $Plan.signed_bundle $postCommitFileContour $ownership | Out-Null
            }
            Assert-RetainedReleaseFileContour $postCommitFileContour $Plan.signed_bundle 'post-commit final file contour'
            Assert-InventoryEqual $finalInventory @(Get-ReleaseFileInventory $Plan.signed_bundle) 'post-commit final inventory'
            Assert-SourceBaselineReadback $baseline
            Assert-PublishedDirectoryContour $ownership $Plan.signed_bundle
            $rootFlushed = [EliotReleaseNativeFileSystem]::FlushDirectoryHandle($ownership.root_fence.handle)
            $parentFlushed = [EliotReleaseNativeFileSystem]::FlushDirectoryHandle($parentPin.handle)
            if (-not $rootFlushed -or -not $parentFlushed) {
                throw 'post-commit directory metadata flush was unavailable'
            }
        }
        catch {
            return [ordered]@{
                component = 'eliot_windows_x64_release_finalize'
                status = 'COMMITTED_UNKNOWN'
                reason = 'POST_COMMIT_READBACK_FAILED'
                bundle = $Plan.signed_bundle
                staging_token = [string]$ownership.token
                durable_install_authority = $false
                next_authoritative_handoff = 'eliot installation materialize-source-bundle'
                detail = [string]$_.Exception.Message
            }
        }
        [ordered]@{
            component = 'eliot_windows_x64_release_finalize'
            status = 'COMMITTED_UNKNOWN'
            reason = 'MUTABLE_DIRECTORY_REQUIRES_CONSUMER_RECONCILIATION'
            bundle = $Plan.signed_bundle
            staging_token = [string]$ownership.token
            immediate_readback = 'VERIFIED_SIGNED_SNAPSHOT'
            durable_install_authority = $false
            next_authoritative_handoff = 'eliot installation materialize-source-bundle'
            signed_scope = $script:AuthenticodeSigningScope
            roles = 6
            signature_evidence = $signatureEvidence
            detail = 'The committed directory passed immediate readback but its namespace cannot remain frozen through a durable consumer handoff.'
        }
    }
    finally {
        if (-not $committed -and $ownership) {
            Remove-OwnedStagingDirectory $ownership
        }
        Close-RetainedReleaseFileContour $postCommitFileContour
        Close-RetainedReleaseFileContour $stagingFileContour
        Close-NativeDirectoryPin $destinationPin
        Close-OwnedStagingFences $ownership
        Close-NativeDirectoryPin $parentPin
        Close-NativeDirectoryPin $sourcePin
    }
}

function Get-FinalizationProcessExitCode([object]$Outcome) {
    if (-not $Outcome) { throw 'finalization produced no typed outcome' }
    switch -CaseSensitive ([string]$Outcome.status) {
        'COMMITTED_UNKNOWN' { return 75 }
        default { throw "finalization produced an unexpected status: $($Outcome.status)" }
    }
}

if ($MyInvocation.InvocationName -eq '.') {
    return
}

if ($VerifyBundle) {
    foreach ($required in @{
            UnsignedBundle = $UnsignedBundle
            SignToolPath = $SignToolPath
            CertificateStoreLocation = $CertificateStoreLocation
            CertificateThumbprint = $CertificateThumbprint
            TimestampUrl = $TimestampUrl
        }.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
            throw "-$($required.Key) is required for external-policy signed-bundle verification"
        }
    }
    $verificationPlan = New-AuthenticodeVerificationPlan $UnsignedBundle $VerifyBundle $SignToolPath $CertificateStoreLocation $CertificateThumbprint $TimestampUrl
    Test-ReleaseBundle $verificationPlan.unsigned_bundle | Out-Null
    $verificationBaseline = New-ReleaseFinalizationBaseline $verificationPlan.unsigned_bundle
    $verificationCertificate = Resolve-CodeSigningCertificateIdentity $verificationPlan.certificate_store_location $verificationPlan.certificate_thumbprint
    Test-FinalizedReleaseBundle $VerifyBundle $null $verificationBaseline $verificationPlan $verificationCertificate | ConvertTo-Json -Depth 12
    exit 0
}

foreach ($required in @{
        UnsignedBundle = $UnsignedBundle
        SignedBundle = $SignedBundle
        SignToolPath = $SignToolPath
        CertificateStoreLocation = $CertificateStoreLocation
        CertificateThumbprint = $CertificateThumbprint
        TimestampUrl = $TimestampUrl
    }.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace([string]$required.Value)) {
        throw "-$($required.Key) is required; use -PlanOnly to inspect a complete explicit signing plan"
    }
}

$plan = New-AuthenticodeSigningPlan $UnsignedBundle $SignedBundle $SignToolPath $CertificateStoreLocation $CertificateThumbprint $TimestampUrl
if ($PlanOnly) {
    $plan | ConvertTo-Json -Depth 8
    exit 0
}

$outcome = Invoke-ReleaseBundleFinalization $plan
$exitCode = Get-FinalizationProcessExitCode $outcome
$outcome | ConvertTo-Json -Depth 12
exit $exitCode
