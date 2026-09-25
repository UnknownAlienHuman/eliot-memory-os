using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Bounded user-local recovery journal for operator mutations.
///
/// The journal stores only the typed owner request and its local recovery
/// metadata. It never stores the inherited broker endpoint, pipe name, handoff
/// nonce, bearer material, or a credential-bearing request. A record is
/// written before the first send and removed only after a terminal owner
/// receipt is observed. A record left in Submitted/PossiblyExecuted state at
/// process restart is conservatively promoted to UnknownReconciling, so a
/// restart cannot create a second logical mutation.
public sealed class OperatorPendingOperationJournal : IDisposable
{
    public const int MaxOperations = 32;
    public const int MaxEnvelopeChars = 64 * 1024;
    public const long MaxJournalBytes = 2 * 1024 * 1024;

    private static readonly JsonSerializerOptions Json = OperatorJson.Reader;

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

    /// The typed UserAutomation route carries no transport authenticator: the
    /// named owner route supplies session, principal, State Fence and operation
    /// identity server-side, and the surface supplies only the closed operation
    /// plus one retry-stable idempotency key. Its only `nonce` is the
    /// operator-supplied one-shot `run_now` intent guard, so the handoff-nonce
    /// class of field is not applicable to this route. Every other credential
    /// and endpoint class still applies.
    private static readonly string[] UserAutomationForbiddenFieldFragments =
    [
        "credential",
        "password",
        "secret",
        "authorization",
        "bearer",
        "cookie",
        "endpoint",
        "pipe",
        "token"
    ];

    // The named mutex is the cross-process writer lease. The process gate also
    // serializes the live owner, while the registry below rejects a second
    // journal object before Mutex recursion can make it look like an owner.
    private static readonly ConcurrentDictionary<string, object> ProcessGates = new(
        StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, byte> LiveProcessOwners = new(
        StringComparer.OrdinalIgnoreCase);

    private readonly string? _path;
    private readonly object _gate;
    private readonly string? _processOwnerKey;
    private readonly Mutex? _writerMutex;
    private readonly string? _writerUnavailableReason;
    private bool _writerOwned;
    private bool _disposed;

    private OperatorPendingOperationJournal(
        string? path,
        string? processOwnerKey,
        Mutex? writerMutex,
        bool writerOwned,
        string? writerUnavailableReason)
    {
        _path = path;
        _gate = ProcessGates.GetOrAdd(
            processOwnerKey ?? path ?? "<unavailable>",
            static _ => new object());
        _processOwnerKey = processOwnerKey;
        _writerMutex = writerMutex;
        _writerOwned = writerOwned;
        _writerUnavailableReason = writerUnavailableReason;
    }

    public static OperatorPendingOperationJournal CreateDefault()
    {
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(localAppData))
        {
            return new OperatorPendingOperationJournal(
                path: null,
                processOwnerKey: null,
                writerMutex: null,
                writerOwned: false,
                writerUnavailableReason:
                    "user-local application data is unavailable; operator mutations are disabled");
        }

        var path = Path.Combine(
            localAppData,
            "Eliot",
            "Operator",
            "pending-operations.json");
        var processOwnerKey = CanonicalizePath(path);
        if (!LiveProcessOwners.TryAdd(processOwnerKey, 0))
        {
            return new OperatorPendingOperationJournal(
                path,
                processOwnerKey: null,
                writerMutex: null,
                writerOwned: false,
                writerUnavailableReason:
                    "another Eliot Operator journal object already owns this user-local path in this process; this instance is read-only");
        }

        Mutex? mutex = null;
        try
        {
            mutex = new Mutex(initiallyOwned: false, BuildWriterMutexName(processOwnerKey));
            bool acquired;
            try
            {
                acquired = mutex.WaitOne(millisecondsTimeout: 0);
            }
            catch (AbandonedMutexException)
            {
                // The previous owner exited without disposing the lease. The
                // OS has transferred ownership to this caller; the journal
                // loader below will still promote every nonterminal record.
                acquired = true;
            }

            if (!acquired)
            {
                mutex.Dispose();
                ReleaseProcessOwner(processOwnerKey);
                return new OperatorPendingOperationJournal(
                    path,
                    processOwnerKey: null,
                    writerMutex: null,
                    writerOwned: false,
                    writerUnavailableReason:
                        "another Eliot Operator instance owns the pending-operation journal; this instance is read-only until it exits");
            }

            return new OperatorPendingOperationJournal(
                path,
                processOwnerKey,
                mutex,
                writerOwned: true,
                writerUnavailableReason: null);
        }
        catch (Exception error) when (
            error is UnauthorizedAccessException
            or IOException
            or ArgumentException
            or NotSupportedException
            or System.Threading.WaitHandleCannotBeOpenedException
            or System.Security.SecurityException)
        {
            mutex?.Dispose();
            ReleaseProcessOwner(processOwnerKey);
            return new OperatorPendingOperationJournal(
                path,
                processOwnerKey: null,
                writerMutex: null,
                writerOwned: false,
                writerUnavailableReason:
                    "the user-local pending-operation writer lease could not be established; operator mutations are disabled");
        }
        catch
        {
            mutex?.Dispose();
            ReleaseProcessOwner(processOwnerKey);
            throw;
        }
    }

    private static string CanonicalizePath(string path) =>
        Path.GetFullPath(path).ToUpperInvariant();

    private static string BuildWriterMutexName(string path)
    {
        var identity = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(path)));
        return $"Global\\Eliot.Operator.PendingOperationJournal.{identity}";
    }

    private static void ReleaseProcessOwner(string processOwnerKey)
    {
        ((ICollection<KeyValuePair<string, byte>>)LiveProcessOwners)
            .Remove(new KeyValuePair<string, byte>(processOwnerKey, 0));
    }

    /// Loads records that survived a process boundary. Any non-terminal
    /// record is explicitly marked unknown before it is returned or used, and
    /// the normalized state is durably rewritten before the UI can reconcile.
    public IReadOnlyList<OperatorPendingOperation> LoadForRecovery()
    {
        lock (_gate)
        {
            EnsureWriter();
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
    /// The lifetime writer lease prevents a second process from replacing the
    /// file from a stale in-memory array; the process gate covers additional
    /// journal objects created in this process. A failed write leaves the prior
    /// file intact and is reported through the typed recovery exception.
    public void Save(IReadOnlyCollection<OperatorPendingOperation> operations)
    {
        lock (_gate)
        {
            EnsureWriter();
            ValidateCollection(operations);
            WriteLocked(operations.ToArray());
        }
    }

    private OperatorPendingOperation[] ReadLocked()
    {
        EnsureWriter();
        if (!File.Exists(_path!))
        {
            return [];
        }

        try
        {
            var info = new FileInfo(_path!);
            if (info.Length > MaxJournalBytes)
            {
                throw new OperatorPendingOperationJournalException(
                    "pending operation journal exceeds its bounded size");
            }

            var bytes = File.ReadAllBytes(_path!);
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
        EnsureWriter();
        string? temporary = null;
        try
        {
            // Directory creation is part of the same typed persistence path as
            // the file swap. A denied or unavailable user profile must block
            // the owner send through TryPersistPendingState, never escape as an
            // unclassified startup/command exception.
            var directory = Path.GetDirectoryName(_path!);
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

            temporary = $"{_path!}.tmp-{Guid.NewGuid():N}";
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
            File.Move(temporary, _path!, overwrite: true);
        }
        catch (Exception error) when (
            error is IOException
            or UnauthorizedAccessException
            or JsonException
            or ArgumentException
            or NotSupportedException
            or System.Security.SecurityException)
        {
            throw new OperatorPendingOperationJournalException(
                "pending operation journal could not be durably updated",
                error);
        }
        finally
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(temporary) && File.Exists(temporary)) File.Delete(temporary);
            }
            catch
            {
                // Preserve the existing journal and surface the original
                // update result; orphaned temp files contain only the bounded
                // envelope and are never treated as a recovery journal.
            }
        }
    }

    private void EnsureWriter()
    {
        if (_disposed)
        {
            throw new OperatorPendingOperationJournalException(
                "pending-operation journal has been disposed; operator mutations are disabled");
        }

        if (!_writerOwned || _writerMutex is null)
        {
            throw new OperatorPendingOperationJournalException(
                _writerUnavailableReason
                ?? "the pending-operation journal writer lease is unavailable; operator mutations are disabled");
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                if (_writerOwned && _writerMutex is not null)
                {
                    _writerMutex.ReleaseMutex();
                }
            }
            catch (ApplicationException)
            {
                // The OS may already have released the lease during process
                // teardown. Disposal must not mask the window close path.
            }
            finally
            {
                _writerOwned = false;
                _writerMutex?.Dispose();
                if (_processOwnerKey is not null)
                {
                    ReleaseProcessOwner(_processOwnerKey);
                }
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
                EnsureJournalSafe(document.RootElement, operation.Route);
                switch (operation.Route)
                {
                    case OperatorMutationRoute.OperatorCommand:
                        var envelope = document.RootElement.Deserialize<OperatorIntentEnvelope>(Json)
                            ?? throw new InvalidOperationException("envelope is empty");
                        envelope.Validate();
                        if (!string.Equals(envelope.OperationId, operation.OperationId, StringComparison.Ordinal)
                            || operation.ExpectedRevision is null
                            || envelope.ExpectedRevision != operation.ExpectedRevision.Value)
                        {
                            throw new InvalidOperationException("journal metadata does not bind the envelope");
                        }
                        break;
                    case OperatorMutationRoute.UserAutomation:
                        var automation = document.RootElement.Deserialize<UserAutomationOperatorRequest>(Json)
                            ?? throw new InvalidOperationException("request is empty");
                        automation.Validate();
                        if (!string.Equals(automation.IdempotencyKey, operation.OperationId, StringComparison.Ordinal)
                            || operation.ExpectedRevision is not null
                            || !automation.Operation.IsEffect)
                        {
                            throw new InvalidOperationException("journal metadata does not bind the typed request");
                        }
                        break;
                    default:
                        throw new InvalidOperationException("unknown mutation route");
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

    private static void EnsureJournalSafe(JsonElement element, OperatorMutationRoute route)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (IsForbiddenField(property.Name, route))
                    {
                        throw new InvalidOperationException(
                            $"field '{property.Name}' is not allowed in the user-local journal");
                    }
                    EnsureJournalSafe(property.Value, route);
                }
                break;
            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray()) EnsureJournalSafe(item, route);
                break;
        }
    }

    private static bool IsForbiddenField(string field, OperatorMutationRoute route)
    {
        if (string.Equals(field, "idempotency_key", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var fragments = route == OperatorMutationRoute.UserAutomation
            ? UserAutomationForbiddenFieldFragments
            : ForbiddenFieldFragments;
        return fragments.Any(fragment =>
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
