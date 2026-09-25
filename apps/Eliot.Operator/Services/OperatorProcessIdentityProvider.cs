using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Principal;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// The Operator cannot prove which installation, user session or process it is
/// running as. That is a fail-closed condition, never a degraded fallback: an
/// unproven identity produces no handoff binding at all.
public sealed class OperatorProcessIdentityException(string reason)
    : Exception(reason);

/// Observes the exact current installation, Windows user SID, logon Session
/// and Operator process generation once per process.
///
/// The artifact fingerprint is deliberately bounded: file length, the last
/// write instant, and a SHA-256 over the leading fingerprint window. That is
/// enough to distinguish artifact generations, costs a fixed bounded read, and
/// never turns process startup into a full-image hash.
public static class OperatorProcessIdentityProvider
{
    /// Leading bytes hashed into the artifact fingerprint. The full image is
    /// never read; the bound is a hard allocation cap, not a sample policy.
    public const int FingerprintWindowBytes = 1024 * 1024;
    public const long MaxArtifactBytes = 2L * 1024 * 1024 * 1024;

    private static readonly Lazy<OperatorProcessIdentity> Observed =
        new(Observe, LazyThreadSafetyMode.ExecutionAndPublication);

    /// The identity of this process. Observed once; a failure is sticky and
    /// surfaced as a typed refusal.
    public static OperatorProcessIdentity Current => Observed.Value;

    public static OperatorProcessIdentity Observe()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new OperatorProcessIdentityException(
                "the Operator handoff binding requires an authenticated Windows user session");
        }

        var baseDirectory = AppContext.BaseDirectory;
        if (string.IsNullOrWhiteSpace(baseDirectory))
        {
            throw new OperatorProcessIdentityException("the installation root of this Operator process is unobservable");
        }
        string installationId;
        try
        {
            installationId = Path.GetFullPath(baseDirectory);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new OperatorProcessIdentityException("the installation root of this Operator process is not addressable");
        }

        string userSid;
        int logonSessionId;
        int processId;
        long processStartTicks;
        using (var process = Process.GetCurrentProcess())
        {
            try
            {
                logonSessionId = process.SessionId;
                processId = process.Id;
                processStartTicks = process.StartTime.ToUniversalTime().Ticks;
            }
            catch (Exception error) when (error is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
            {
                throw new OperatorProcessIdentityException("this Operator process cannot name its own logon session");
            }
        }
        if (logonSessionId <= 0)
        {
            throw new OperatorProcessIdentityException("this Operator process has no interactive logon session");
        }

        try
        {
            userSid = WindowsIdentity.GetCurrent().User?.Value
                ?? throw new OperatorProcessIdentityException("this Operator process has no authenticated user SID");
        }
        catch (System.Security.SecurityException)
        {
            throw new OperatorProcessIdentityException("this Operator process user SID could not be authenticated");
        }

        var identity = new OperatorProcessIdentity(
            installationId,
            userSid,
            logonSessionId,
            FingerprintOfCurrentImage(),
            string.Create(
                CultureInfo.InvariantCulture,
                $"{processId}:{processStartTicks}"));
        identity.Validate();
        return identity;
    }

    /// Bounded artifact-generation fingerprint of the running image.
    private static string FingerprintOfCurrentImage()
    {
        var image = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(image) || !File.Exists(image))
        {
            throw new OperatorProcessIdentityException("the running Operator image is unobservable");
        }
        FileInfo info;
        try
        {
            info = new FileInfo(image);
        }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or IOException)
        {
            throw new OperatorProcessIdentityException("the running Operator image is not addressable");
        }
        if (info.Length <= 0 || info.Length > MaxArtifactBytes)
        {
            throw new OperatorProcessIdentityException("the running Operator image exceeds the bounded artifact size");
        }

        var window = (int)Math.Min(info.Length, FingerprintWindowBytes);
        var buffer = new byte[window];
        int read;
        try
        {
            using var stream = new FileStream(
                image,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 4096,
                options: FileOptions.SequentialScan);
            read = ReadExactly(stream, buffer);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new OperatorProcessIdentityException("the running Operator image could not be read");
        }

        var prefix = new byte[read + sizeof(long) + sizeof(long)];
        Buffer.BlockCopy(buffer, 0, prefix, 0, read);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(prefix.AsSpan(read), info.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(
            prefix.AsSpan(read + sizeof(long)),
            info.LastWriteTimeUtc.Ticks);
        return Convert.ToHexString(SHA256.HashData(prefix));
    }

    private static int ReadExactly(Stream stream, byte[] buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer, total, buffer.Length - total);
            if (read <= 0) break;
            total += read;
        }
        return total;
    }
}
