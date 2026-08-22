using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class EliotMaterializerProtocolHelper
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileAttributeReparsePoint = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    private sealed class FileIdentity
    {
        public uint VolumeSerialNumber;
        public ulong FileIndex;
    }

    private sealed class Role
    {
        public string Flag;
        public string Name;
        public bool Executable;
        public string Source;
        public FileIdentity SourceIdentity;
        public FileIdentity DestinationIdentity;
        public long Bytes;
        public string Sha256;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    public static int Main(string[] arguments)
    {
        try
        {
            Run(arguments);
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("eliot materializer protocol helper rejected input: " + error.Message);
            return 2;
        }
    }

    private static void Run(string[] arguments)
    {
        if (arguments == null || arguments.Length < 2 ||
            !String.Equals(arguments[0], "installation", StringComparison.Ordinal) ||
            !String.Equals(arguments[1], "materialize-source-bundle", StringComparison.Ordinal))
        {
            throw new InvalidDataException("exact installation materialize-source-bundle command is required");
        }

        Dictionary<string, string> values = ParseArguments(arguments);
        Role[] roles = new Role[]
        {
            NewExecutableRole("--eliot-host", "eliot-host.exe", values),
            NewExecutableRole("--eliot-watchdog", "eliot-watchdog.exe", values),
            NewExecutableRole("--eliot-kernel", "eliot-kernel.exe", values),
            NewExecutableRole("--eliot-store-surreal", "eliot-store-surreal.exe", values),
            NewExecutableRole("--surreal", "surreal.exe", values),
            NewExecutableRole("--eliotd", "eliotd.exe", values),
            NewJsonRole("generation.json"),
            NewJsonRole("eliotd-governor.json"),
            NewJsonRole("eliotd.json")
        };

        string outputBundle = RequireAbsolute(values, "--output-bundle");
        string output = RequireAbsolute(values, "--output");
        string store = RequireAbsolute(values, "--store");
        string transactionId = Require(values, "--transaction-id");
        string generation = Require(values, "--generation");
        RequireAbsolute(values, "--staging-root");
        RequireAbsolute(values, "--profile-anchor-root");
        Require(values, "--installation");
        Require(values, "--lineage-id");
        Require(values, "--sequence");
        Require(values, "--minimum-store-available-bytes");
        Require(values, "--recovery-command");
        Require(values, "--profile");

        AssertAbsent(outputBundle, "output bundle");
        AssertAbsent(output, "diagnostic output");
        AssertAbsent(store, "transaction store");
        Directory.CreateDirectory(outputBundle);

        for (int index = 0; index < roles.Length; index++)
        {
            Role role = roles[index];
            string destination = Path.Combine(outputBundle, role.Name);
            if (role.Executable)
            {
                role.SourceIdentity = ReadIdentity(role.Source, false);
                File.Copy(role.Source, destination, false);
            }
            else
            {
                role.SourceIdentity = null;
                WriteCreateNew(
                    destination,
                    Encoding.UTF8.GetBytes(
                        "{\"schema\":\"eliot-live-signing-test-role-v1\",\"role\":" +
                        Quote(role.Name) + ",\"transaction_id\":" + Quote(transactionId) + "}\n"));
            }
            role.DestinationIdentity = ReadIdentity(destination, false);
            role.Bytes = new FileInfo(destination).Length;
            role.Sha256 = ReadSha256(destination);
            if (role.SourceIdentity == null)
            {
                role.SourceIdentity = role.DestinationIdentity;
            }
        }

        WriteCreateNew(
            output,
            Encoding.UTF8.GetBytes("{\"transaction_id\":" + Quote(transactionId) + "}\n"));
        WriteCreateNew(store, Encoding.UTF8.GetBytes("eliot-live-signing-test-store-v1\n"));

        FileIdentity directoryIdentity = ReadIdentity(outputBundle, true);
        string generated = "{" +
            "\"contract\":\"eliot.kernel.installation\"," +
            "\"contract_version\":\"3.0.0\"," +
            "\"status\":\"GENERATED\"," +
            "\"transaction_id\":" + Quote(transactionId) + "," +
            "\"generation\":" + Quote(generation) + "," +
            "\"output\":" + Quote(Path.GetFullPath(output)) + "," +
            "\"store\":" + Quote(Path.GetFullPath(store)) + "," +
            "\"source_publication_bound\":true," +
            "\"durable_authority\":\"DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID\"," +
            "\"output_role\":\"DIAGNOSTIC_NON_IMPORTABLE\"" +
            "}";

        StringBuilder files = new StringBuilder();
        for (int index = 0; index < roles.Length; index++)
        {
            if (index != 0)
            {
                files.Append(',');
            }
            files.Append(RoleJson(roles[index]));
        }
        string identity = IdentityJson(directoryIdentity);
        string materialized = "{" +
            "\"contract\":\"eliot.kernel.installation\"," +
            "\"contract_version\":\"3.0.0\"," +
            "\"status\":\"SOURCE_BUNDLE_MATERIALIZED\"," +
            "\"handoff\":\"SOURCE_PUBLICATION_BOUND_TO_GENERATED_PLAN\"," +
            "\"transaction_id\":" + Quote(transactionId) + "," +
            "\"generation\":" + Quote(generation) + "," +
            "\"output\":" + Quote(Path.GetFullPath(output)) + "," +
            "\"store\":" + Quote(Path.GetFullPath(store)) + "," +
            "\"bundle_path\":" + Quote(Path.GetFullPath(outputBundle)) + "," +
            "\"durable_authority\":\"DURABLE_TRANSACTION_STORE_PLUS_TRANSACTION_ID\"," +
            "\"output_role\":\"DIAGNOSTIC_NON_IMPORTABLE\"," +
            "\"source_identity\":" + identity + "," +
            "\"directory_publication\":{\"source_identity\":" + identity +
                ",\"destination_identity\":" + identity + "}," +
            "\"file_count\":9," +
            "\"files\":[" + files.ToString() + "]" +
            "}";

        Console.Out.WriteLine(generated);
        Console.Out.WriteLine(materialized);
    }

    private static Dictionary<string, string> ParseArguments(string[] arguments)
    {
        if (((arguments.Length - 2) % 2) != 0)
        {
            throw new InvalidDataException("typed materialize arguments must be flag/value pairs");
        }
        HashSet<string> allowed = new HashSet<string>(StringComparer.Ordinal)
        {
            "--eliot-host", "--eliot-watchdog", "--eliot-kernel",
            "--eliot-store-surreal", "--surreal", "--eliotd",
            "--output-bundle", "--output", "--store", "--generation",
            "--installation", "--lineage-id", "--sequence", "--transaction-id",
            "--staging-root", "--minimum-store-available-bytes", "--recovery-command",
            "--profile", "--profile-anchor-root", "--installation-key"
        };
        Dictionary<string, string> result = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int index = 2; index < arguments.Length; index += 2)
        {
            string flag = arguments[index];
            string value = arguments[index + 1];
            if (!allowed.Contains(flag) || result.ContainsKey(flag) || String.IsNullOrWhiteSpace(value))
            {
                throw new InvalidDataException("unknown, duplicated, or empty typed argument: " + flag);
            }
            result.Add(flag, value);
        }
        return result;
    }

    private static Role NewExecutableRole(
        string flag,
        string expectedName,
        Dictionary<string, string> values)
    {
        string source = RequireAbsolute(values, flag);
        if (!File.Exists(source) ||
            !String.Equals(Path.GetFileName(source), expectedName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("signed executable source is not exact: " + expectedName);
        }
        return new Role { Flag = flag, Name = expectedName, Executable = true, Source = source };
    }

    private static Role NewJsonRole(string name)
    {
        return new Role { Name = name, Executable = false };
    }

    private static string Require(Dictionary<string, string> values, string flag)
    {
        string value;
        if (!values.TryGetValue(flag, out value) || String.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException("required typed argument is missing: " + flag);
        }
        return value;
    }

    private static string RequireAbsolute(Dictionary<string, string> values, string flag)
    {
        string value = Require(values, flag);
        if (!Path.IsPathRooted(value))
        {
            throw new InvalidDataException("typed path must be absolute: " + flag);
        }
        return Path.GetFullPath(value);
    }

    private static void AssertAbsent(string path, string purpose)
    {
        if (File.Exists(path) || Directory.Exists(path))
        {
            throw new IOException(purpose + " must be create-new");
        }
        string parent = Path.GetDirectoryName(path);
        if (String.IsNullOrWhiteSpace(parent) || !Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException(purpose + " parent is unavailable");
        }
    }

    private static void WriteCreateNew(string path, byte[] bytes)
    {
        using (FileStream stream = new FileStream(
            path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, FileOptions.WriteThrough))
        {
            stream.Write(bytes, 0, bytes.Length);
            stream.Flush(true);
        }
    }

    private static FileIdentity ReadIdentity(string path, bool directory)
    {
        uint flags = FileFlagOpenReparsePoint | (directory ? FileFlagBackupSemantics : 0u);
        using (SafeFileHandle handle = CreateFileW(
            Path.GetFullPath(path),
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            flags,
            IntPtr.Zero))
        {
            if (handle.IsInvalid)
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(), "file identity open failed: " + path);
            }
            ByHandleFileInformation information;
            if (!GetFileInformationByHandle(handle, out information))
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error(), "file identity readback failed: " + path);
            }
            if ((information.FileAttributes & FileAttributeReparsePoint) != 0 ||
                information.FileIndexHigh == 0 && information.FileIndexLow == 0)
            {
                throw new InvalidDataException("file identity is reparse or zero: " + path);
            }
            return new FileIdentity
            {
                VolumeSerialNumber = information.VolumeSerialNumber,
                FileIndex = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow
            };
        }
    }

    private static string ReadSha256(string path)
    {
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (SHA256 algorithm = SHA256.Create())
        {
            byte[] digest = algorithm.ComputeHash(stream);
            StringBuilder text = new StringBuilder(digest.Length * 2);
            for (int index = 0; index < digest.Length; index++)
            {
                text.Append(digest[index].ToString("x2", CultureInfo.InvariantCulture));
            }
            return text.ToString();
        }
    }

    private static string RoleJson(Role role)
    {
        return "{" +
            "\"relative_path\":" + Quote(role.Name) + "," +
            "\"executable\":" + (role.Executable ? "true" : "false") + "," +
            "\"size\":" + role.Bytes.ToString(CultureInfo.InvariantCulture) + "," +
            "\"sha256\":" + Quote(role.Sha256) + "," +
            "\"source_identity\":" + IdentityJson(role.SourceIdentity) + "," +
            "\"destination_identity\":" + IdentityJson(role.DestinationIdentity) + "," +
            "\"pe\":" + (role.Executable ? "{\"machine\":\"8664\"}" : "null") + "," +
            "\"authenticode\":" + (role.Executable ? "{\"status\":\"Valid\"}" : "null") +
            "}";
    }

    private static string IdentityJson(FileIdentity identity)
    {
        return "{\"volume_serial_number\":" +
            identity.VolumeSerialNumber.ToString(CultureInfo.InvariantCulture) +
            ",\"file_index\":" + identity.FileIndex.ToString(CultureInfo.InvariantCulture) + "}";
    }

    private static string Quote(string value)
    {
        if (value == null)
        {
            return "null";
        }
        StringBuilder result = new StringBuilder(value.Length + 2);
        result.Append('"');
        foreach (char character in value)
        {
            switch (character)
            {
                case '"': result.Append("\\\""); break;
                case '\\': result.Append("\\\\"); break;
                case '\b': result.Append("\\b"); break;
                case '\f': result.Append("\\f"); break;
                case '\n': result.Append("\\n"); break;
                case '\r': result.Append("\\r"); break;
                case '\t': result.Append("\\t"); break;
                default:
                    if (character < 0x20)
                    {
                        result.Append("\\u");
                        result.Append(((int)character).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else
                    {
                        result.Append(character);
                    }
                    break;
            }
        }
        result.Append('"');
        return result.ToString();
    }
}
