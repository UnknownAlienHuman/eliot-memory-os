namespace Eliot.Operator.Protocol;

/// Bounded redacted startup diagnostics. Records carry the stage, the
/// exception type name, and the HRESULT only: messages, stack traces, pipe
/// names, nonces, endpoints, credentials, and command/query bodies never enter
/// the log. Every record is length-capped and the log file is rotation-capped.
public static class OperatorDiagnostics
{
    public const int MaxStageChars = 128;
    public const int MaxTypeChars = 256;
    public const int MaxRecordChars = 512;
    public const long MaxLogBytes = 64 * 1024;

    public static string FormatStartupRecord(
        string stage,
        string? exceptionType,
        int? hresult)
    {
        var safeStage = Bound(stage, MaxStageChars);
        var record = exceptionType is null
            ? $"{DateTimeOffset.UtcNow:O} {safeStage}"
            : $"{DateTimeOffset.UtcNow:O} {safeStage} type={Bound(exceptionType, MaxTypeChars)} hresult=0x{hresult ?? 0:X8}";
        return record.Length <= MaxRecordChars ? record : record[..MaxRecordChars];
    }

    public static bool ShouldRotate(long currentBytes) => currentBytes > MaxLogBytes;

    /// Bounded redacted record of the loaded wire adapter. It carries which
    /// schema, contract hash, single consumer, proof ceiling and removal
    /// condition this process pinned — never an endpoint, nonce, credential,
    /// command/query body or protected record content. This is the I15.4
    /// "record which reference/version was used, never the value" rule.
    public static string FormatAdapterRecord(string description)
    {
        var record = $"{DateTimeOffset.UtcNow:O} wire-adapter {Bound(description, MaxRecordChars * 4)}";
        return record.Length <= MaxRecordChars ? record : record[..MaxRecordChars];
    }

    private static string Bound(string? value, int max)
    {
        var text = (value ?? string.Empty).Trim();
        var filtered = new string(text.Where(character => !char.IsControl(character)).ToArray());
        return filtered.Length <= max ? filtered : filtered[..max];
    }
}
