using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Bounded user-local recovery journal for operator mutations.
///
/// The journal stores only the typed operator envelope and its local recovery
/// metadata. It never stores the inherited broker endpoint, pipe name, handoff
/// nonce, bearer material, or a credential-bearing request. A record is
/// written before the first send and removed only after a terminal owner
/// receipt is observed. A record left in Submitted/PossiblyExecuted state at
/// process restart is conservatively promoted to UnknownReconciling, so a
/// restart cannot create a second logical mutation.
public sealed class OperatorPendingOperationJournal
{
    public const int MaxOperations = 32;
    public const int MaxEnvelopeChars = 64 * 1024;
    public const long MaxJournalBytes = 2 * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        MaxDepth = 32
    };

    private static readonly string[] ForbiddenFieldFragments =
    [
        "credential",
        "password",
        "secret",
        "authorization",
        "bearer",
        "cookie",
        "endpoint",
        "pipe",
        "nonce",
        "token"
    ];

    private readonly string _path;
    private readonly object _gate = new();

    private OperatorPendingOperationJournal(string path) => _path = path;

    public static OperatorPendingOperationJournal CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            throw new OperatorPendingOperationJournalException(
                "user-local application data is unavailable; operator recovery is disabled");
        }

        return new OperatorPendingOperationJournal(Path.Combine(
            localAppData,
            "Eliot",
            "Operator",
            "pending-operations.json"));
    }

    /// Loads records that survived a process boundary. Any non-terminal
    /// record is explicitly marked unknown before it is returned or used, and
    /// the normalized state is durably rewritten before the UI can reconcile.
    public IReadOnlyList<OperatorPendingOperation> LoadForRecovery()
    {
        lock (_gate)
        {
            var loaded = ReadLocked();
            var recovered = loaded
                .Where(operation => !IsTerminal(operation.Phase))
                .Select(operation => operation.WithPhase(OperatorOperationPhase.UnknownReconciling))
                .ToArray();
            if (!loaded.SequenceEqual(recovered))
            {
                WriteLocked(recovered);
            }

            return recovered;
        }
    }

    /// Replaces the complete bounded journal using a durable temp-file swap.
    /// The caller owns the in-memory list and serializes calls through this
    /// service; a failed write leaves the prior file intact.
    public void Save(IReadOnlyCollection<OperatorPendingOperation> operations)
    {
        lock (_gate)
        {
            ValidateCollection(operations);
            WriteLocked(operations.ToArray());
        }
    }

    private OperatorPendingOperation[] ReadLocked()
    {
        if (!File.Exists(_path))
        {
            return [];
        }

        try
        {
            var info = new FileInfo(_path);
            if (info.Length > MaxJournalBytes)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal exceeds its bounded size");
            }

            var bytes = File.ReadAllBytes(_path);
            var operations = JsonSerializer.Deserialize<OperatorPendingOperation[]>(bytes, Json)
                ?? throw new OperatorPendingOperationJournalException(
                    "pending operation journal is empty or unreadable");
            ValidateCollection(operations);
            return operations;
        }
        catch (OperatorPendingOperationJournalException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new OperatorPendingOperationJournalException(
                "pending operation journal could not be read safely",
                error);
        }
    }

    private void WriteLocked(IReadOnlyCollection<OperatorPendingOperation> operations)
    {
        var directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new OperatorPendingOperationJournalException(
                "pending operation journal has no user-local directory");
        }

        Directory.CreateDirectory(directory);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(operations, Json);
        if (bytes.Length > MaxJournalBytes)
        {
            throw new OperatorPendingOperationJournalException(
                "pending operation journal exceeds its bounded size");
        }

        var temporary = $"{_path}.tmp-{Guid.NewGuid():N}";
        try
        {
            using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 4096,
                options: FileOptions.SequentialScan | FileOptions.WriteThrough))
            {
                stream.Write(bytes, 0, bytes.Length);
                stream.Flush(flushToDisk: true);
            }

            // MoveFileEx(REPLACE_EXISTING) is used by the Windows runtime for
            // this same-volume swap. The old file remains until the complete
            // new document has been flushed.
            File.Move(temporary, _path, overwrite: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw new OperatorPendingOperationJournalException(
                "pending operation journal could not be durably updated",
                error);
        }
        finally
        {
            try
            {
                if (File.Exists(temporary)) File.Delete(temporary);
            }
            catch
            {
                // Preserve the existing journal and surface the original
                // update result; orphaned temp files contain only the bounded
                // envelope and are never treated as a recovery journal.
            }
        }
    }

    private static void ValidateCollection(IEnumerable<OperatorPendingOperation> operations)
    {
        var materialized = operations.ToArray();
        if (materialized.Length > MaxOperations)
        {
            throw new OperatorPendingOperationJournalException(
                $"pending operation journal exceeds the {MaxOperations}-operation bound");
        }

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var operation in materialized)
        {
            if (operation is null)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal contains a null record");
            }

            if (!ids.Add(operation.OperationId))
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal contains duplicate operation identity");
            }

            try
            {
                OperatorIntentContract.RequireOperationId(operation.OperationId);
                OperatorIntentContract.RequireText(operation.CommandName, "command_name");
            }
            catch (InvalidOperationException error)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal contains an invalid operation identity",
                    error);
            }

            if (string.IsNullOrEmpty(operation.EnvelopeJson)
                || operation.EnvelopeJson.Length > MaxEnvelopeChars)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation envelope exceeds its bounded size");
            }

            try
            {
                using var document = JsonDocument.Parse(operation.EnvelopeJson);
                EnsureJournalSafe(document.RootElement);
                var envelope = document.RootElement.Deserialize<OperatorIntentEnvelope>(Json)
                    ?? throw new InvalidOperationException("envelope is empty");
                envelope.Validate();
                if (!string.Equals(envelope.OperationId, operation.OperationId, StringComparison.Ordinal)
                    || envelope.ExpectedRevision != operation.ExpectedRevision)
                {
                    throw new InvalidOperationException("journal metadata does not bind the envelope");
                }
            }
            catch (Exception error) when (error is JsonException or InvalidOperationException)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal contains an invalid or credential-bearing envelope",
                    error);
            }
        }
    }

    private static void EnsureJournalSafe(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (IsForbiddenField(property.Name))
                    {
                        throw new InvalidOperationException(
                            $"field '{property.Name}' is not allowed in the user-local journal");
                    }
                    EnsureJournalSafe(property.Value);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray()) EnsureJournalSafe(item);
                break;
        }
    }

    private static bool IsForbiddenField(string field)
    {
        if (string.Equals(field, "idempotency_key", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return ForbiddenFieldFragments.Any(fragment =>
            field.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTerminal(OperatorOperationPhase phase) => phase is
        OperatorOperationPhase.Receipted
        or OperatorOperationPhase.Rejected
        or OperatorOperationPhase.Cancelled
        or OperatorOperationPhase.StaleFence;
}

public sealed class OperatorPendingOperationJournalException : Exception
{
    public OperatorPendingOperationJournalException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
