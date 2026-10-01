using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Eliot.Operator.Protocol.Generated;

namespace Eliot.Operator.Protocol;

/// Closed UserAutomation operation surface carried by the authenticated
/// Governor command. Except for the read-only context handshake, each request
/// also carries the exact owner-issued StateFence witness against which the
/// Kernel admits the operation. It contains no principal, Store receipt,
/// scheduler, provider credential, or ambient settings.
[JsonPolymorphic(
    TypeDiscriminatorPropertyName = OperatorScheduleContract.USER_AUTOMATION_OPERATION_DISCRIMINATOR)]
[JsonDerivedType(typeof(UserAutomationGetContextOperation), "get_context")]
[JsonDerivedType(typeof(UserAutomationNormalizeScheduleOperation), "normalize_schedule")]
[JsonDerivedType(typeof(UserAutomationMigrateLegacyScheduleOperation), "migrate_legacy_schedule")]
[JsonDerivedType(typeof(UserAutomationCreateOperation), "create")]
[JsonDerivedType(typeof(UserAutomationListOperation), "list")]
[JsonDerivedType(typeof(UserAutomationStatusOperation), "status")]
[JsonDerivedType(typeof(UserAutomationHistoryOperation), "history")]
[JsonDerivedType(typeof(UserAutomationPauseOperation), "pause")]
[JsonDerivedType(typeof(UserAutomationResumeOperation), "resume")]
[JsonDerivedType(typeof(UserAutomationEditOperation), "edit")]
[JsonDerivedType(typeof(UserAutomationRunNowOperation), "run_now")]
[JsonDerivedType(typeof(UserAutomationRemoveOperation), "remove")]
[JsonDerivedType(typeof(UserAutomationInspectLastFailureOperation), "inspect_last_failure")]
public abstract record UserAutomationOperation
{
    public abstract void Validate();

    /// True when the operation is an effect rather than a read. Effects
    /// follow the owner's admission and approval policy and retain one
    /// operation identity until a terminal receipt; reads execute immediately
    /// inside existing authority and retain nothing.
    ///
    /// This is a local routing classifier, not part of the operation. It is a
    /// method rather than a property because System.Text.Json serializes a
    /// public getter by default: the owner-side
    /// `UserAutomationOperation` is `deny_unknown_fields`, so a serialized
    /// `isEffect` member would make every request undecodable. A method has no
    /// serialized surface at all, which keeps the exclusion exact for the
    /// abstract declaration, every derived record, the polymorphic
    /// `UserAutomationOperation` contract and the outer request at once.
    public abstract bool IsEffect();
}

/// Read-only authenticated route handshake. This operation is never shown as
/// a business action and its result supplies the StateFence for the next
/// independently identified request.
public sealed record UserAutomationGetContextOperation : UserAutomationOperation
{
    public override void Validate() { }

    public override bool IsEffect() => false;
}

/// <summary>Ask the authenticated Kernel owner to normalize one immutable revision draft.</summary>
public sealed record UserAutomationNormalizeScheduleOperation(
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision,
    [property: JsonPropertyName("occurrence_count")] ushort OccurrenceCount)
    : UserAutomationOperation
{
    public override void Validate()
    {
        if (Revision is null) throw new InvalidOperationException("normalize_schedule requires one revision draft.");
        Revision.ValidateForNormalizationSubmission();
        UserAutomationScheduleMirror.RequireNormalizationOccurrenceCount(OccurrenceCount);
    }

    // Normalization is retained by the Kernel owner with its original request
    // and receipt. It writes owner state but does not activate the automation.
    public override bool IsEffect() => true;
}

/// <summary>Explicitly migrate a legacy immutable revision into a distinct successor.</summary>
public sealed record UserAutomationMigrateLegacyScheduleOperation(
    [property: JsonPropertyName("previous_revision")] UserAutomationRevision PreviousRevision,
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision,
    [property: JsonPropertyName("occurrence_count")] ushort OccurrenceCount)
    : UserAutomationOperation
{
    public override void Validate()
    {
        if (PreviousRevision is null || Revision is null)
        {
            throw new InvalidOperationException("migrate_legacy_schedule requires previous and candidate revisions.");
        }
        Revision.ValidateForMigrationNormalizationSubmission(PreviousRevision);
        UserAutomationScheduleMirror.RequireNormalizationOccurrenceCount(OccurrenceCount);
    }

    // Migration is retained by the Kernel owner with its original request
    // and receipt. It writes owner state but does not activate the automation.
    public override bool IsEffect() => true;
}

public sealed record UserAutomationCreateOperation(
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision,
    [property: JsonPropertyName("normalization_receipt_envelope")] JsonElement NormalizationReceiptEnvelope)
    : UserAutomationOperation
{
    public override void Validate()
    {
        // An absent `revision` member decodes to null before this check runs, so
        // it is refused by name here rather than dereferenced below. The
        // retained-byte readers, the pending journal and the reconciliation
        // loop all report a refusal as InvalidOperationException, so a
        // dereference here would escape every one of them as a null fault
        // instead of the closed-shape refusal they are written to handle.
        if (Revision is null)
        {
            throw new InvalidOperationException("create requires one typed revision payload.");
        }
        Revision.Validate();
        UserAutomationNormalizationReceiptEnvelope.Validate(
            NormalizationReceiptEnvelope,
            Revision,
            UserAutomationNormalizationReceiptEnvelope.NormalizationOperationKind);
    }

    public override bool IsEffect() => true;
}

public sealed record UserAutomationListOperation(
    [property: JsonPropertyName("include_retired")] bool IncludeRetired)
    : UserAutomationOperation
{
    public override void Validate() { }

    public override bool IsEffect() => false;
}

public sealed record UserAutomationStatusOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
}

public sealed record UserAutomationHistoryOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
}

public sealed record UserAutomationPauseOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
}

public sealed record UserAutomationResumeOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
}

public sealed record UserAutomationEditOperation(
    [property: JsonPropertyName("previous_revision")] UserAutomationRevision PreviousRevision,
    [property: JsonPropertyName("revision")] UserAutomationRevision Revision,
    [property: JsonPropertyName("normalization_receipt_envelope")] JsonElement NormalizationReceiptEnvelope)
    : UserAutomationOperation
{
    public override void Validate()
    {
        // Refused by name for the same reason as `create`: a missing member
        // decodes to null, and both required revisions are load-bearing here.
        if (PreviousRevision is null || Revision is null)
        {
            throw new InvalidOperationException("edit requires both typed revision payloads.");
        }
        Revision.Validate();
        var previousIsLegacy = false;
        try
        {
            PreviousRevision.Validate();
        }
        catch (InvalidOperationException)
        {
            PreviousRevision.ValidateForLegacyScheduleMigration();
            previousIsLegacy = true;
        }
        if (!string.Equals(PreviousRevision.AutomationId, Revision.AutomationId, StringComparison.Ordinal)
            || !string.Equals(Revision.Supersedes, PreviousRevision.Revision, StringComparison.Ordinal)
            || string.Equals(PreviousRevision.Revision, Revision.Revision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("UserAutomation edit must supersede one distinct revision of the same automation.");
        }
        if (previousIsLegacy)
        {
            UserAutomationNormalizationReceiptEnvelope.Validate(
                NormalizationReceiptEnvelope,
                Revision,
                UserAutomationNormalizationReceiptEnvelope.LegacyMigrationOperationKind);
        }
        else
        {
            // This local relation catches reuse of a receipt projection after a
            // source-field edit. The Kernel still validates the complete
            // original envelope against the immutable revision and scope.
            UserAutomationScheduleMirror.RequireV3SourceDigestConsistencyForEdit(
                PreviousRevision.Schedule,
                Revision.Schedule);
            UserAutomationNormalizationReceiptEnvelope.Validate(
                NormalizationReceiptEnvelope,
                Revision,
                UserAutomationNormalizationReceiptEnvelope.NormalizationOperationKind);
        }
    }

    public override bool IsEffect() => true;
}

/// Shallow transport binding for the exact original owner receipt envelope.
/// The Kernel owns the full receipt schema and semantic authority validation;
/// this boundary checks only the identity join needed to carry the unmodified
/// envelope beside its immutable revision.
internal static class UserAutomationNormalizationReceiptEnvelope
{
    internal const string NormalizationOperationKind =
        OperatorScheduleContract.USER_AUTOMATION_NORMALIZATION_OPERATION_KIND;
    internal const string LegacyMigrationOperationKind =
        OperatorScheduleContract.USER_AUTOMATION_LEGACY_MIGRATION_OPERATION_KIND;

    internal static void Validate(
        JsonElement envelope,
        UserAutomationRevision revision,
        string expectedOperationKind)
    {
        ArgumentNullException.ThrowIfNull(revision);
        if (envelope.ValueKind != JsonValueKind.Object
            || !UserAutomationOutcomeClassifier.HasUniqueObjectPropertiesRecursively(envelope)
            || !HasExactProperties(envelope, "identity", "core")
            || !envelope.TryGetProperty("identity", out var identity)
            || !HasExactProperties(identity, "receipt_id", "canonical_sha256")
            || !TryReadBoundedText(identity, "receipt_id", OperatorScheduleContract.MAX_TEXT_BYTES, out var receiptId)
            || !TryReadLowerSha256(identity, "canonical_sha256", out _)
            || !envelope.TryGetProperty("core", out var core)
            || core.ValueKind != JsonValueKind.Object
            || !core.TryGetProperty("operation", out var operation)
            || operation.ValueKind != JsonValueKind.Object
            || !HasUniqueProperties(operation)
            || !TryReadBoundedText(operation, "operation_kind", OperatorScheduleContract.MAX_TEXT_BYTES, out var operationKind)
            || !string.Equals(operationKind, expectedOperationKind, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "normalization_receipt_envelope must be the closed owner receipt identity bound to this operation kind");
        }

        if (revision.Schedule is null
            || revision.Schedule.NormalizationBinding is null
            || !string.Equals(
                revision.Schedule.NormalizationBinding.ReceiptId,
                receiptId,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "normalization_receipt_envelope.identity.receipt_id must equal the revision schedule receipt identity");
        }
    }

    private static bool HasExactProperties(JsonElement value, params string[] names)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var actual = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!actual.Add(property.Name)) return false;
        }
        return actual.Count == names.Length && names.All(actual.Contains);
    }

    private static bool HasUniqueProperties(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return false;
        var names = new HashSet<string>(StringComparer.Ordinal);
        return value.EnumerateObject().All(property => names.Add(property.Name));
    }

    private static bool TryReadBoundedText(
        JsonElement value,
        string propertyName,
        int maxUtf8Bytes,
        out string text)
    {
        text = string.Empty;
        return value.TryGetProperty(propertyName, out var member)
            && member.ValueKind == JsonValueKind.String
            && (text = member.GetString() ?? string.Empty).Length > 0
            && !text.Any(char.IsControl)
            && Encoding.UTF8.GetByteCount(text) <= maxUtf8Bytes;
    }

    private static bool TryReadLowerSha256(JsonElement value, string propertyName, out string digest)
    {
        digest = string.Empty;
        if (!TryReadBoundedText(value, propertyName, 64, out digest) || digest.Length != 64)
        {
            return false;
        }
        return digest.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    }
}

public sealed record UserAutomationRunNowOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision,
    [property: JsonPropertyName("nonce")] string Nonce)
    : UserAutomationOperation
{
    public override void Validate()
    {
        UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);
        UserAutomationContract.RequireText(Nonce, "nonce");
    }

    public override bool IsEffect() => true;
}

public sealed record UserAutomationRemoveOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("automation_revision")] string AutomationRevision)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireIdentity(AutomationId, AutomationRevision);

    public override bool IsEffect() => true;
}

public sealed record UserAutomationInspectLastFailureOperation(
    [property: JsonPropertyName("automation_id")] string AutomationId)
    : UserAutomationOperation
{
    public override void Validate() => UserAutomationContract.RequireText(AutomationId, "automation_id");

    public override bool IsEffect() => false;
}

/// Exact authenticated UserAutomation front-door payload. The named route
/// adds the authenticated session, principal, request metadata and issued
/// operation identity. The read-only get_context handshake omits
/// expected_state_fence; every later request carries the unchanged fence that
/// handshake returned.
public sealed record UserAutomationOperatorRequest(
    [property: JsonPropertyName("operation")] UserAutomationOperation Operation,
    [property: JsonPropertyName("idempotency_key")] string IdempotencyKey,
    [property: JsonPropertyName("expected_state_fence")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        JsonElement? ExpectedStateFence)
{
    /// The retry-stable identity of one typed operation. It is derived from
    /// the exact canonical operation bytes, so a lost response, a transport
    /// reconnect or an operator resubmission of the same typed operation
    /// carries the SAME identity and cannot create a second logical mutation.
    /// Two genuinely different operations always differ, because the
    /// distinguishing field is part of the canonical bytes.
    public static string DeriveIdempotencyKey(UserAutomationOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        operation.Validate();
        var canonical = JsonSerializer.Serialize(operation, OperatorJson.Writer);
        var bytes = Encoding.UTF8.GetBytes(canonical);
        if (bytes.Length > OperatorProtocol.MaxRetainedInputChars)
        {
            throw new InvalidOperationException("typed UserAutomation operation exceeds the canonical input bound");
        }
        var digest = SHA256.HashData(bytes);
        return Convert.ToHexString(digest.AsSpan(0, 16)).ToLowerInvariant();
    }

    public static UserAutomationOperatorRequest Create(UserAutomationOperation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (operation is not UserAutomationGetContextOperation)
        {
            throw new InvalidOperationException(
                "a UserAutomation business request requires a fresh owner State Fence witness");
        }

        return CreateContext();
    }

    /// Mints the short-lived read-only handshake identity. It is deliberately
    /// unique per call so a newly authenticated session cannot receive a
    /// retained result from an earlier context read.
    public static UserAutomationOperatorRequest CreateContext() =>
        new(
            new UserAutomationGetContextOperation(),
            Guid.NewGuid().ToString("N"),
            ExpectedStateFence: null);

    /// Mints one business request from the same typed operation and exact
    /// owner-issued fence. The fence is retained and replayed byte-for-byte;
    /// it is never reacquired while reconciling this identity.
    public static UserAutomationOperatorRequest Create(
        UserAutomationOperation operation,
        JsonElement expectedStateFence)
    {
        ArgumentNullException.ThrowIfNull(operation);
        if (operation is UserAutomationGetContextOperation)
        {
            throw new InvalidOperationException("get_context must not carry an expected State Fence");
        }

        return new UserAutomationOperatorRequest(
            operation,
            DeriveIdempotencyKey(operation),
            expectedStateFence.Clone());
    }

    public void Validate()
    {
        // `operation` is a required reference-typed member and an absent member
        // decodes to null, so the `Operation.Validate()` call below is itself
        // the dereference. The `[JsonPolymorphic]` base refuses an unmapped or
        // unknown `kind`, but that is a different claim: a decoded request
        // whose `operation` member is `null` reaches this method with nothing
        // in front of it, and `DeriveIdempotencyKey` does not stand in front
        // either — its `ArgumentNullException.ThrowIfNull` at :195 refuses a
        // caller-supplied argument, never a decoded request record. A
        // `NullReferenceException` is not an `InvalidOperationException`, so
        // the fault would escape `MainViewModel.cs:473` and
        // `OperatorPendingOperationJournal.cs:495`, which both filter on
        // `JsonException or InvalidOperationException`, instead of the
        // withheld, still-reconciling outcome they are written to produce.
        // Refused by name here, one fixed sentence over the wire member,
        // exactly as `create`, `edit` and `UserAutomationRevision` refuse
        // theirs. This fires before the journal's own
        // `Request.Operation.IsEffect()` at :486, so that second dereference
        // is covered by the same refusal. This adds no bound, no wire member
        // and no digest input: `DeriveIdempotencyKey` digests
        // `JsonSerializer.Serialize(operation, OperatorJson.Writer)`, which
        // this method does not touch, so a previously valid request carried
        // the member, its retained bytes still validate and still re-derive
        // the same idempotency key.
        if (Operation is null) throw new InvalidOperationException("operation must be present.");
        Operation.Validate();
        OperatorIntentContract.RequireOperationId(IdempotencyKey);
        if (Operation is UserAutomationGetContextOperation)
        {
            if (ExpectedStateFence is not null)
            {
                throw new InvalidOperationException("get_context must omit expected_state_fence");
            }
        }
        else if (ExpectedStateFence is not { } expectedStateFence
            || !UserAutomationOutcomeClassifier.IsClosedStateFence(expectedStateFence))
        {
            throw new InvalidOperationException(
                "a UserAutomation business request requires one closed expected_state_fence");
        }
    }

    /// Validates the CURRENT-shape identity binding: the operation decodes
    /// through today's closed contract, the key is syntactically valid, and
    /// the key is exactly the digest today's serializer derives from those
    /// same canonical operation bytes.
    ///
    /// This is the sendable-identity invariant. It is required of fresh
    /// `Create` output, at the live transport boundary and for current-shape
    /// recovery, so a corrupted or edited journal entry cannot travel under
    /// an identity that names a different operation. It must never be
    /// applied to a superseded-shape retained record: that key was derived
    /// from bytes that included the old local classifier, so recomputing it
    /// under today's serializer names a different request commitment, and
    /// the record stays withheld under its exact retained key.
    public void ValidateCurrentIdentity()
    {
        Validate();
        if (!string.Equals(IdempotencyKey, DeriveIdempotencyKey(Operation), StringComparison.Ordinal))
        {
            throw new InvalidOperationException("idempotency_key does not name the retained typed operation.");
        }
    }
}

/// One typed UserAutomation request read from a retained user-local envelope,
/// together with whether the retained bytes still encode the superseded local
/// read/effect classifier.
///
/// Retained bytes are read, never rewritten. The current closed profile is the
/// authority on the exact field set: a request that decodes through it carries
/// nothing beyond the contract, because it refuses every unmapped member. Only
/// one deviation is tolerated, and only here: the single known member the
/// superseded generation emitted for the local classifier. That member is
/// non-authoritative recovery metadata — the read/effect classification is
/// re-derived from the decoded typed operation, never trusted from the old
/// bytes — and its presence never makes the envelope sendable. This profile is
/// never used to read or write a live request, so the live wire keeps refusing
/// unknown fields.
public sealed record UserAutomationRetainedRequest(
    UserAutomationOperatorRequest Request,
    bool CarriesSupersededLocalClassifier)
{
    /// The exact member name the superseded generation produced for the local
    /// `IsEffect` property under the closed Web naming policy.
    public const string SupersededLocalClassifierMember = "isEffect";

    /// The outer business request is exactly these three members. It is stated
    /// here rather than read back off the request type so the retained envelope
    /// is checked against the wire contract, not against its own reader.
    private static readonly string[] RequestMemberNames = ["operation", "idempotency_key", "expected_state_fence"];

    /// The one tolerated deviation, scoped to retained local recovery bytes.
    /// `OperatorJson.Reader` itself is untouched, so no unrelated surface
    /// inherits the tolerance. `Skip` is applied only to the retained bytes
    /// after the single known member has been removed, and
    /// `RequireSameMembersAndValues` then proves the result is exactly today's
    /// canonical encoding — so anything this profile skipped is refused there.
    private static readonly JsonSerializerOptions SupersededShapeJson = new(OperatorJson.Reader)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip
    };

    /// Reads one retained envelope without altering it. The decoded identity is
    /// the one the bytes already carry; it is never re-derived from today's
    /// serializer, because a re-encoded payload is a different request
    /// commitment than the one the retained key names.
    ///
    /// Every refusal is reported as one exception type, so a caller can tell
    /// "these retained bytes are not a closed UserAutomation envelope" from
    /// "this record is fine" without also handling serializer internals.
    public static UserAutomationRetainedRequest Read(string envelopeJson)
    {
        ArgumentNullException.ThrowIfNull(envelopeJson);
        UserAutomationRetainedRequest? current;
        try
        {
            current = ReadCurrentShape(envelopeJson);
        }
        catch (Exception error) when (error is JsonException or NotSupportedException)
        {
            // The current shape refused. `NotSupportedException` is how the
            // polymorphic converter reports a member it cannot bind before it
            // reaches the discriminator, so it is a shape refusal too.
            current = null;
        }
        if (current is not null)
        {
            return current;
        }

        try
        {
            return ReadSupersededShape(envelopeJson);
        }
        catch (Exception error) when (error is JsonException or NotSupportedException)
        {
            throw new InvalidOperationException(
                "retained UserAutomation request is not a closed UserAutomation envelope",
                error);
        }
    }

    /// The retained bytes decode through the current closed profile, so they
    /// carry nothing beyond the contract: that profile refuses every unmapped
    /// member.
    private static UserAutomationRetainedRequest ReadCurrentShape(string envelopeJson)
    {
        using var document = JsonDocument.Parse(envelopeJson);
        if (document.RootElement.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("retained UserAutomation request is not one JSON object");
        }
        return new UserAutomationRetainedRequest(
            document.RootElement.Deserialize<UserAutomationOperatorRequest>(OperatorJson.Reader)
                ?? throw new InvalidOperationException("retained UserAutomation request is empty"),
            CarriesSupersededLocalClassifier: false);
    }

    /// The one tolerated deviation: the retained bytes are today's canonical
    /// encoding of the same typed operation plus the single known local
    /// classifier the superseded generation wrote. Nothing else is accepted.
    private static UserAutomationRetainedRequest ReadSupersededShape(string envelopeJson)
    {
        using var document = JsonDocument.Parse(envelopeJson);
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("retained UserAutomation request is not one JSON object");
        }
        RequireExactMembers(root, RequestMemberNames);
        var operation = root.GetProperty("operation");
        if (operation.ValueKind != JsonValueKind.Object
            || !operation.TryGetProperty(SupersededLocalClassifierMember, out var classifier)
            || classifier.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "retained UserAutomation request does not carry the known superseded local classifier");
        }

        // The exact shape today's closed profile accepts: the retained bytes
        // with the one known local classifier removed and nothing else changed,
        // so the strict profile then validates the result at every depth.
        var superseded = JsonSerializer.Deserialize<UserAutomationOperatorRequest>(
                WithoutSupersededClassifier(root, operation), SupersededShapeJson)
            ?? throw new InvalidOperationException("retained UserAutomation request is empty");

        // The retained bytes must equal today's canonical encoding of that same
        // typed operation plus the one classifier, compared member by member so
        // member order is irrelevant. Anything the closed serializer would not
        // write itself — an extra field at any depth, a changed value, a
        // different casing — is refused here.
        using var canonical = JsonDocument.Parse(
            JsonSerializer.Serialize(superseded.Operation, OperatorJson.Writer));
        RequireSameMembersAndValues(operation, canonical.RootElement, classifier);
        // The retained classifier must equal the locally derived classifier
        // for the same typed operation: the superseded serializer wrote the
        // live value of `IsEffect()`, so a disagreeing Boolean is not output
        // of that serializer and is refused here rather than classified as
        // the known legacy shape. The value stays non-authoritative recovery
        // metadata — routing re-derives `IsEffect()` from the typed
        // operation — and the record remains unsendable either way.
        if (superseded.Operation is null
            || classifier.GetBoolean() != superseded.Operation.IsEffect())
        {
            throw new InvalidOperationException(
                "retained UserAutomation operation carries a local classifier the superseded serializer could not have produced");
        }
        return new UserAutomationRetainedRequest(
            superseded,
            CarriesSupersededLocalClassifier: true);
    }

    /// Rewrites the retained envelope with the one known local classifier
    /// removed and every other byte, at every depth, copied verbatim.
    private static string WithoutSupersededClassifier(JsonElement root, JsonElement operation)
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            foreach (var property in root.EnumerateObject())
            {
                if (property.NameEquals("operation"))
                {
                    writer.WritePropertyName(property.Name);
                    writer.WriteStartObject();
                    foreach (var member in operation.EnumerateObject())
                    {
                        if (!string.Equals(member.Name, SupersededLocalClassifierMember, StringComparison.Ordinal))
                        {
                            member.WriteTo(writer);
                        }
                    }
                    writer.WriteEndObject();
                    continue;
                }
                property.WriteTo(writer);
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static void RequireExactMembers(JsonElement element, IEnumerable<string> expected)
    {
        var actual = element.EnumerateObject().Select(property => property.Name).ToArray();
        if (!new HashSet<string>(actual, StringComparer.Ordinal).SetEquals(expected))
        {
            throw new InvalidOperationException(
                "retained UserAutomation request carries members outside the closed contract");
        }
    }

    /// Compares the retained operation with the canonical encoding of the same
    /// typed operation plus the tolerated member, by name and by value. This is
    /// the whole tolerance boundary: anything today's serializer would not write
    /// itself is refused here.
    private static void RequireSameMembersAndValues(
        JsonElement retained,
        JsonElement canonical,
        JsonElement classifier)
    {
        if (retained.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "retained UserAutomation operation is not one JSON object");
        }
        var actual = retained.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
        var expected = canonical.EnumerateObject()
            .ToDictionary(property => property.Name, property => property.Value, StringComparer.Ordinal);
        expected[SupersededLocalClassifierMember] = classifier;
        if (actual.Count != expected.Count)
        {
            throw new InvalidOperationException(
                "retained UserAutomation operation carries members outside the closed contract");
        }
        foreach (var (name, value) in expected)
        {
            if (!actual.TryGetValue(name, out var retainedValue)
                || !JsonElement.DeepEquals(retainedValue, value))
            {
                throw new InvalidOperationException(
                    "retained UserAutomation operation differs from the closed contract outside the known local classifier");
            }
        }
    }
}

/// Typed immutable revision payload used only for create/edit operations. The
/// canonical owner still decides normalization, admission and identity.
public sealed record UserAutomationRevision(
    [property: JsonPropertyName("automation_id")] string AutomationId,
    [property: JsonPropertyName("revision")] string Revision,
    [property: JsonPropertyName("supersedes")] string? Supersedes,
    [property: JsonPropertyName("owner_principal")] string OwnerPrincipal,
    [property: JsonPropertyName("work_scope")] UserAutomationWorkScope WorkScope,
    [property: JsonPropertyName("natural_language_intent")] string NaturalLanguageIntent,
    [property: JsonPropertyName("schedule")] UserAutomationNormalizedSchedule Schedule,
    [property: JsonPropertyName("mode")] string Mode,
    [property: JsonPropertyName("task")] UserAutomationTaskBinding Task,
    [property: JsonPropertyName("portable_skill_package_revision_refs")] IReadOnlyList<string> PortableSkillPackageRevisionRefs,
    [property: JsonPropertyName("workdir_ref")] string WorkdirRef,
    [property: JsonPropertyName("route_cost_policy")] UserAutomationRouteCostPolicy RouteCostPolicy,
    [property: JsonPropertyName("provider_policy")] UserAutomationProviderPolicy ProviderPolicy,
    [property: JsonPropertyName("delivery_target")] UserAutomationDeliveryTarget DeliveryTarget,
    [property: JsonPropertyName("preflight_contract_revision")] string PreflightContractRevision,
    [property: JsonPropertyName("resource_ceiling")] UserAutomationResourceCeiling ResourceCeiling,
    [property: JsonPropertyName("overlap_policy")] string OverlapPolicy,
    [property: JsonPropertyName("recursion_policy")] UserAutomationRecursionPolicy RecursionPolicy,
    [property: JsonPropertyName("configuration_state")] string ConfigurationState,
    [property: JsonPropertyName("work_class")] string WorkClass,
    [property: JsonPropertyName("current_execution_refs")] IReadOnlyList<string> CurrentExecutionRefs,
    [property: JsonPropertyName("execution_history_query_ref")] string ExecutionHistoryQueryRef)
{
    public void Validate() => Validate(allowReceiptFreeSchedule: false, legacySchedule: false);

    internal void ValidateForNormalizationSubmission() => Validate(allowReceiptFreeSchedule: true, legacySchedule: false);

    internal void ValidateForMigrationNormalizationSubmission(UserAutomationRevision previousRevision)
    {
        ArgumentNullException.ThrowIfNull(previousRevision);
        ValidateForNormalizationSubmission();
        previousRevision.ValidateForLegacyScheduleMigration();
        if (!string.Equals(AutomationId, previousRevision.AutomationId, StringComparison.Ordinal)
            || string.Equals(Revision, previousRevision.Revision, StringComparison.Ordinal)
            || !string.Equals(Supersedes, previousRevision.Revision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "legacy schedule migration must create a distinct immutable revision immediately superseding its predecessor.");
        }
    }

    internal void ValidateForLegacyScheduleMigration() => Validate(allowReceiptFreeSchedule: false, legacySchedule: true);

    private void Validate(bool allowReceiptFreeSchedule, bool legacySchedule)
    {
        // Each nested record below is a required reference-typed member that
        // decodes to null when the member is absent, and every one of them is
        // dereferenced by this method: either directly, or by a nested
        // `Validate()` call, which is an instance call on that same null
        // reference and faults identically. `ResourceCeiling` and
        // `RecursionPolicy` hold no reference-typed member of their own, but
        // that does not make them safe here — the call itself is the
        // dereference. A `NullReferenceException` is not an
        // `InvalidOperationException`, so it would escape every handler written
        // to contain a closed-shape refusal — the retained-byte readers, the
        // pending journal, the reconciliation loop — as an untyped fault
        // instead of the withheld, still-reconciling outcome they are written
        // to produce. They are therefore refused by name here, one fixed
        // sentence over a literal field name, exactly as the two revision
        // payloads are refused in `create` and `edit`. This adds no bound, no
        // wire member and no digest input: a previously valid revision carried
        // every one of them, so its retained bytes still validate and still
        // re-derive the same idempotency key.
        if (WorkScope is null) throw new InvalidOperationException("work_scope must be present.");
        if (Schedule is null) throw new InvalidOperationException("schedule must be present.");
        if (Task is null) throw new InvalidOperationException("task must be present.");
        if (RouteCostPolicy is null) throw new InvalidOperationException("route_cost_policy must be present.");
        if (ProviderPolicy is null) throw new InvalidOperationException("provider_policy must be present.");
        if (DeliveryTarget is null) throw new InvalidOperationException("delivery_target must be present.");
        if (ResourceCeiling is null) throw new InvalidOperationException("resource_ceiling must be present.");
        if (RecursionPolicy is null) throw new InvalidOperationException("recursion_policy must be present.");
        UserAutomationContract.RequireText(AutomationId, "automation_id");
        UserAutomationContract.RequireText(Revision, "revision");
        UserAutomationContract.RequireText(OwnerPrincipal, "owner_principal");
        UserAutomationContract.RequireText(NaturalLanguageIntent, "natural_language_intent");
        UserAutomationContract.RequireText(WorkdirRef, "workdir_ref");
        UserAutomationContract.RequireText(PreflightContractRevision, "preflight_contract_revision");
        UserAutomationContract.RequireText(ExecutionHistoryQueryRef, "execution_history_query_ref");
        UserAutomationContract.RequireOneOf(Mode, "mode", "AGENT", "DETERMINISTIC_PROCESS");
        UserAutomationContract.RequireOneOf(ConfigurationState, "configuration_state", "ACTIVE", "PAUSED", "BLOCKED_CONFIG", "RETIRED");
        UserAutomationContract.RequireOneOf(
            WorkClass,
            "work_class",
            "CONTROL",
            "INTERACTIVE",
            "VERIFICATION",
            "CANONICAL_WRITE",
            "NORMAL_BACKGROUND",
            "MODEL_JOBS",
            "SWARM",
            "REPORTING",
            "MAINTENANCE");
        UserAutomationContract.RequireOneOf(OverlapPolicy, "overlap_policy", "FORBID_OVERLAP", "QUEUE_ONE", "COALESCE_LATEST");
        if (Supersedes is not null) UserAutomationContract.RequireText(Supersedes, "supersedes");
        WorkScope.Validate();
        if (legacySchedule)
        {
            Schedule.ValidateForLegacyScheduleMigration();
        }
        else if (allowReceiptFreeSchedule)
        {
            Schedule.ValidateForOwnerNormalizationSubmission();
        }
        else
        {
            Schedule.Validate();
        }
        Task.Validate();
        UserAutomationContract.RequireTextList(PortableSkillPackageRevisionRefs, "portable_skill_package_revision_refs");
        if (!string.Equals(WorkdirRef, WorkScope.WorkdirRef, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("workdir_ref must equal work_scope.workdir_ref.");
        }
        RouteCostPolicy.Validate();
        ProviderPolicy.Validate();
        DeliveryTarget.Validate();
        if (!string.Equals(PreflightContractRevision, UserAutomationContract.PreflightContractRevision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("preflight_contract_revision is not the admitted UserAutomation contract.");
        }
        ResourceCeiling.Validate();
        RecursionPolicy.Validate();
        UserAutomationContract.RequireTextList(CurrentExecutionRefs, "current_execution_refs");
        if (CurrentExecutionRefs.Zip(CurrentExecutionRefs.Skip(1)).Any(pair => string.Equals(pair.First, pair.Second, StringComparison.Ordinal)))
        {
            throw new InvalidOperationException("current_execution_refs must not contain adjacent duplicates.");
        }
        if (Mode == "AGENT" && (Task.Kind != "AGENT_TASK" || ProviderPolicy is not UserAutomationAllowedProviderPolicy))
        {
            throw new InvalidOperationException("AGENT revisions require an agent task and allowed provider policy.");
        }
        if (Mode == "DETERMINISTIC_PROCESS"
            && (Task.Kind != "QUALIFIED_SCRIPT"
                || Task.CapabilityProfile.ModelAccess
                || Task.CapabilityProfile.ProviderAccess
                || Task.CapabilityProfile.AutomationScheduling
                || ProviderPolicy is not UserAutomationDeterministicOnlyProviderPolicy
                || WorkClass == "MODEL_JOBS"))
        {
            throw new InvalidOperationException("DETERMINISTIC_PROCESS revisions must exclude model, provider and scheduling access.");
        }
    }
}

public sealed record UserAutomationNormalizedSchedule(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("expression")] string Expression,
    [property: JsonPropertyName("calendar")] string Calendar,
    [property: JsonPropertyName("timezone")] string Timezone,
    [property: JsonPropertyName("dst_fold")] string DstFold,
    [property: JsonPropertyName("dst_gap")] string DstGap,
    [property: JsonPropertyName("start_at")] string StartAt,
    [property: JsonPropertyName("end_at")] string? EndAt,
    [property: JsonPropertyName("next_occurrences")] IReadOnlyList<string> NextOccurrences,
    [property: JsonPropertyName("normalization_receipt")]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        UserAutomationScheduleNormalizationReceipt? NormalizationBinding)
{
    /// <summary>
    /// Validates the bounded wire shape and exact supported contract version of
    /// the supplied occurrence set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every field of the versioned occurrence record is checked against the
    /// grammar in <c>UserAutomationScheduleMirror</c>, which is a generated port
    /// of the Kernel owner contract. This check does not prove owner issuance or
    /// substitute for Kernel validation. The following rules apply:
    /// </para>
    /// <list type="bullet">
    /// <item>
    /// The exact contract version and the pinned zone database release are
    /// read from the supplied occurrence bytes. They are not a second copy
    /// carried on this record: the owner side is <c>deny_unknown_fields</c>, so
    /// a member the owner does not know would make every request undecodable.
    /// </item>
    /// <item>
    /// A legacy shape-only occurrence is refused by name, with the
    /// re-normalization action attached. The revision is never rewritten here;
    /// an immutable revision is only ever superseded by a new one.
    /// </item>
    /// <item>
    /// Ordering is decided by the resolved canonical instant, never by a lexical
    /// comparison of the raw records. Mixed offsets are exactly the case where
    /// the two disagree, and the Kernel orders by the instant.
    /// </item>
    /// </list>
    /// <para>
    /// This is a shape and evidence check only. It is not admission, and it does
    /// not make the schedule normalized: normalization is the owner's act, and
    /// a successful pass here is reported as "admitted for submission", never as
    /// "normalized".
    /// </para>
    /// </remarks>
    public void Validate() => Validate(allowReceiptFreeDraft: false);

    internal void ValidateForNormalizationSubmission() => Validate(allowReceiptFreeDraft: true);

    internal void ValidateForOwnerNormalizationSubmission()
    {
        ValidateSourceFields();
        if (NextOccurrences is null || NextOccurrences.Count != 0)
        {
            throw new InvalidOperationException(
                "schedule.next_occurrences must be empty until the Kernel owner normalizes this revision.");
        }
        if (NormalizationBinding is not null)
        {
            throw new InvalidOperationException(
                "schedule.normalization_receipt must be omitted until the Kernel owner normalizes this revision.");
        }
        _ = UserAutomationScheduleMirror.ReadScheduleProjection(
            Timezone, DstFold, DstGap, StartAt, EndAt, Array.Empty<string>());
    }

    internal void ValidateForLegacyScheduleMigration()
    {
        ValidateSourceFields();
        if (NextOccurrences is null || NextOccurrences.Count == 0
            || NextOccurrences.Count > OperatorScheduleContract.MAX_REFERENCES)
        {
            throw new InvalidOperationException(
                "legacy schedule.next_occurrences must contain a bounded non-empty occurrence set.");
        }
        if (Kind == "ONE_SHOT" && NextOccurrences.Count != 1)
        {
            throw new InvalidOperationException("legacy ONE_SHOT schedules require one next occurrence.");
        }

        foreach (var occurrence in NextOccurrences)
        {
            UserAutomationContract.RequireText(occurrence, "schedule.next_occurrences");
            if (Encoding.UTF8.GetByteCount(occurrence) > OperatorScheduleContract.MAX_TEXT_BYTES
                || !UserAutomationScheduleMirror.IsLegacyOccurrenceEncoding(occurrence))
            {
                throw new UserAutomationScheduleContractException(
                    "LegacyScheduleEncoding",
                    UserAutomationScheduleMirror.OwnerText("LegacyScheduleEncoding", "schedule.next_occurrences"),
                    "migration requires a uniformly retired V1, V2, or V3 occurrence set; preserve the predecessor unchanged");
            }
        }
    }

    private void ValidateSourceFields()
    {
        UserAutomationContract.RequireOneOf(Kind, "schedule.kind", "ONE_SHOT", "RECURRING");
        UserAutomationContract.RequireText(Expression, "schedule.expression");
        UserAutomationContract.RequireText(Calendar, "schedule.calendar");
        UserAutomationContract.RequireText(Timezone, "schedule.timezone");
        UserAutomationContract.RequireOneOf(DstFold, "schedule.dst_fold", "FIRST", "SECOND", "REJECT");
        UserAutomationContract.RequireOneOf(DstGap, "schedule.dst_gap", "SHIFT_FORWARD", "REJECT");
        UserAutomationContract.RequireText(StartAt, "schedule.start_at");
        if (EndAt is not null) UserAutomationContract.RequireText(EndAt, "schedule.end_at");
    }

    private void Validate(bool allowReceiptFreeDraft)
    {
        // Draft Create/Edit revisions omit the owner-issued receipt. A retained
        // or returned revision must include it and is checked below.
        UserAutomationContract.RequireOneOf(Kind, "schedule.kind", "ONE_SHOT", "RECURRING");
        UserAutomationContract.RequireText(Expression, "schedule.expression");
        UserAutomationContract.RequireText(Calendar, "schedule.calendar");
        UserAutomationContract.RequireText(Timezone, "schedule.timezone");
        UserAutomationContract.RequireOneOf(DstFold, "schedule.dst_fold", "FIRST", "SECOND", "REJECT");
        UserAutomationContract.RequireOneOf(DstGap, "schedule.dst_gap", "SHIFT_FORWARD", "REJECT");
        UserAutomationContract.RequireText(StartAt, "schedule.start_at");
        if (EndAt is not null) UserAutomationContract.RequireText(EndAt, "schedule.end_at");
        UserAutomationContract.RequireTextList(NextOccurrences, "schedule.next_occurrences");
        if (NextOccurrences.Count == 0)
        {
            throw new InvalidOperationException("schedule.next_occurrences must be non-empty.");
        }
        if (Kind == "ONE_SHOT" && NextOccurrences.Count != 1)
        {
            throw new InvalidOperationException("ONE_SHOT schedules require one next occurrence.");
        }
        var projection = UserAutomationScheduleMirror.ReadScheduleProjection(
            Timezone, DstFold, DstGap, StartAt, EndAt, NextOccurrences);
        if (NormalizationBinding is null)
        {
            if (!allowReceiptFreeDraft)
            {
                throw new InvalidOperationException(
                    "schedule.normalization_receipt must be present on an admitted revision.");
            }

            return;
        }

        NormalizationBinding.Validate();
        if (!string.Equals(NormalizationBinding.SourceDigest, projection.SourceDigest, StringComparison.Ordinal))
        {
            throw new UserAutomationScheduleContractException(
                "Invalid",
                UserAutomationScheduleMirror.OwnerText("Invalid", "schedule.normalization_receipt.source_digest"),
                "obtain a new owner normalization for this schedule source; preserve the current immutable revision");
        }

        if (!string.Equals(
                NormalizationBinding.ZoneDatabaseRevision,
                projection.PinnedZoneDatabaseRelease,
                StringComparison.Ordinal))
        {
            throw new UserAutomationScheduleContractException(
                "ZoneDatabaseRevision",
                UserAutomationScheduleMirror.OwnerText(
                    "ZoneDatabaseRevision", "schedule.normalization_receipt.zone_database_revision"),
                "obtain a new owner normalization against the pinned zone database; preserve the current immutable revision");
        }
    }

    /// <summary>
    /// The local projection of the exact supported schedule contract carried by
    /// the caller-supplied occurrence bytes.
    /// </summary>
    /// <remarks>
    /// This is a METHOD, not a property, for the same reason
    /// <c>UserAutomationOperation.IsEffect</c> is: the owner-side request records
    /// are <c>deny_unknown_fields</c>, so a serialized member the owner does not
    /// know would make every request undecodable. A method has no serialized
    /// surface at all, which keeps the exclusion exact.
    /// <para>
    /// This local projection carries only what the supplied bytes decide. It is
    /// NOT an owner-issued normalization receipt, and it does not certify that
    /// the owner admitted or normalized the revision.
    /// </para>
    /// </remarks>
    public UserAutomationScheduleProjection ReadLocalProjection(bool allowReceiptFreeDraft = false)
    {
        if (allowReceiptFreeDraft)
        {
            ValidateForNormalizationSubmission();
        }
        else
        {
            Validate();
        }

        var projection = UserAutomationScheduleMirror.ReadScheduleProjection(
            Timezone, DstFold, DstGap, StartAt, EndAt, NextOccurrences);
        return projection with { NormalizationReceipt = NormalizationBinding };
    }
}

/// <summary>
/// Owner-issued normalization evidence for an admitted schedule. A Create/Edit
/// submission may omit it so the Store compiler can issue the receipt; parsing
/// a caller-supplied value does not prove owner issuance.
/// </summary>
/// <remarks>
/// Persisted/read revisions require this value. For a fresh Create/Edit
/// revision, null is omitted from the request so the owner can normalize the
/// schedule and issue the receipt.
/// <para>
/// <b>Why the C# member on the schedule is named <c>NormalizationBinding</c>.</b>
/// The schedule exposes the same JSON member as <c>normalization_receipt</c>;
/// this distinct C# name keeps it separate from the projection method.
/// </para>
/// <para>
/// Every member below is checked for bounded wire shape ONLY. The digests are
/// SHA-256 values over owner-defined canonical bytes that this surface does not
/// reproduce. The Operator never treats a locally well-formed receipt as proof
/// of normalization or provenance.
/// </para>
/// </remarks>
public sealed record UserAutomationScheduleNormalizationReceipt(
    [property: JsonPropertyName("receipt_id")] string ReceiptId,
    [property: JsonPropertyName("normalizer_authority")] string NormalizerAuthority,
    [property: JsonPropertyName("source_digest")] string SourceDigest,
    [property: JsonPropertyName("zone_database_revision")] string ZoneDatabaseRevision,
    [property: JsonPropertyName("occurrences_digest")] string OccurrencesDigest)
{
    /// <summary>
    /// Checks the closed owner shape of the receipt and nothing about its
    /// authority.
    /// </summary>
    /// <remarks>
    /// The pinned zone database revision is the one the owner admits, checked
    /// against the generated constant rather than a second copy of the token.
    /// The two digest members are held to the owner's own 64-hex digest shape
    /// so a malformed value is refused here instead of travelling to the owner,
    /// but their CONTENTS are unverified: this surface cannot recompute either
    /// one and never asserts that the occurrence set matches the expression.
    /// </remarks>
    public void Validate()
    {
        RequireBoundedText(ReceiptId, "schedule.normalization_receipt.receipt_id", OperatorScheduleContract.MAX_TEXT_BYTES);
        RequireBoundedText(NormalizerAuthority, "schedule.normalization_receipt.normalizer_authority", 256);
        RequireDigest(SourceDigest, "schedule.normalization_receipt.source_digest");
        RequireDigest(
            OccurrencesDigest, "schedule.normalization_receipt.occurrences_digest");
        UserAutomationContract.RequireOneOf(
            ZoneDatabaseRevision,
            "schedule.normalization_receipt.zone_database_revision",
            OperatorScheduleContract.PINNED_ZONE_DATABASE_RELEASE);
    }

    private static void RequireDigest(string value, string field)
    {
        UserAutomationContract.RequireText(value, field);
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new InvalidOperationException($"{field} must be a 64-character hex digest.");
        }
    }

    private static void RequireBoundedText(string value, string field, int maxBytes)
    {
        UserAutomationContract.RequireText(value, field);
        if (Encoding.UTF8.GetByteCount(value) > maxBytes)
        {
            throw new InvalidOperationException($"{field} exceeds its UTF-8 byte bound.");
        }
    }
}

public sealed record UserAutomationWorkScope(
    [property: JsonPropertyName("scope_id")] string ScopeId,
    [property: JsonPropertyName("product_id")] string ProductId,
    [property: JsonPropertyName("workdir_ref")] string WorkdirRef)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(ScopeId, "work_scope.scope_id");
        UserAutomationContract.RequireText(ProductId, "work_scope.product_id");
        UserAutomationContract.RequireText(WorkdirRef, "work_scope.workdir_ref");
    }
}

public sealed record UserAutomationTaskBinding(
    [property: JsonPropertyName("qualified_ref")] string QualifiedRef,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("capability_profile")] UserAutomationCapabilityProfile CapabilityProfile)
{
    public void Validate()
    {
        // `capability_profile` is a required reference-typed member and an
        // absent member decodes to null, so the call below is itself the
        // dereference; `UserAutomationCapabilityProfile` holds no
        // reference-typed member of its own and an empty body, but that does
        // not make it safe here, for the same reason
        // `UserAutomationRevision.Validate` states for `resource_ceiling` and
        // `recursion_policy`: the call is the dereference. It also fires
        // FIRST — `UserAutomationRevision.Validate` reaches
        // `Task.CapabilityProfile.ModelAccess` only after `Task.Validate()`
        // returns — so the merged revision refusal provably does not close
        // this path, and a `create`/`edit` envelope missing the member still
        // faults untyped today. A `NullReferenceException` is not an
        // `InvalidOperationException`, so it would escape every handler
        // written to contain a closed-shape refusal (`MainViewModel`, the
        // pending journal, the reconciliation loop) instead of the withheld,
        // still-reconciling outcome they are written to produce. Refused by
        // name here, one fixed sentence over the wire member. This adds no
        // bound, no wire member and no digest input: a previously valid task
        // binding carried the member, so its retained bytes still validate
        // and still re-derive the same idempotency key.
        if (CapabilityProfile is null) throw new InvalidOperationException("task.capability_profile must be present.");
        UserAutomationContract.RequireText(QualifiedRef, "task.qualified_ref");
        UserAutomationContract.RequireOneOf(Kind, "task.kind", "AGENT_TASK", "QUALIFIED_SCRIPT");
        CapabilityProfile.Validate();
    }
}

public sealed record UserAutomationCapabilityProfile(
    [property: JsonPropertyName("model_access")] bool ModelAccess,
    [property: JsonPropertyName("provider_access")] bool ProviderAccess,
    [property: JsonPropertyName("automation_scheduling")] bool AutomationScheduling)
{
    public void Validate() { }
}

[JsonPolymorphic(TypeDiscriminatorPropertyName = "kind")]
[JsonDerivedType(typeof(UserAutomationAllowedProviderPolicy), "allowed")]
[JsonDerivedType(typeof(UserAutomationDeterministicOnlyProviderPolicy), "deterministic_only")]
public abstract record UserAutomationProviderPolicy
{
    public abstract void Validate();
}

public sealed record UserAutomationAllowedProviderPolicy(
    [property: JsonPropertyName("fingerprints")] IReadOnlyList<UserAutomationProviderFingerprint> Fingerprints)
    : UserAutomationProviderPolicy
{
    public override void Validate()
    {
        // `fingerprints` is a required reference-typed member and an absent
        // member decodes to null, so the `.Count` below is a direct
        // dereference with nothing in front of it. `RequireTextList` cannot
        // stand in front of it: this member is a list of records, not
        // `IEnumerable<string>`. `UserAutomationRevision.Validate` refuses a
        // null `provider_policy`, but the policy record being present is not
        // the same claim as its own members being present. A
        // `NullReferenceException` is not an `InvalidOperationException`, so
        // the fault would escape every handler written to contain a
        // closed-shape refusal (`MainViewModel`, the pending journal, the
        // reconciliation loop) instead of the withheld, still-reconciling
        // outcome they are written to produce. Refused by name here, one fixed
        // sentence over the wire member. This adds no bound, no wire member
        // and no digest input: a previously valid policy carried the member,
        // so its retained bytes still validate and still re-derive the same
        // idempotency key.
        if (Fingerprints is null) throw new InvalidOperationException("provider_policy.fingerprints must be present.");
        if (Fingerprints.Count == 0) throw new InvalidOperationException("provider_policy.fingerprints must not be empty.");
        // The element type is a reference record, so `"fingerprints": [null]`
        // decodes to a list holding `null` and the `Validate()` call below is
        // a dereference on that element, not on the list. This is still a
        // refusal of the FIELD, not of a slot: the wire member is not valid
        // unless every slot in it holds a present record, and the file names
        // the field for every refusal inside a list, never a slot —
        // `RequireTextList` passes its own `field` to `RequireText` per element
        // rather than any index, and `RequireOneOf(IEnumerable<string>, ...)`
        // does the same. So it needs no new reason string, no new type and no
        // new fault code: the sentence is the one already emitted for this
        // exact wire member by the guard above. Same typed
        // `InvalidOperationException`, so the contained handlers
        // (`MainViewModel.cs:473`, `OperatorPendingOperationJournal.cs:495`)
        // hold this fault exactly as they hold the twelve above instead of
        // letting a `NullReferenceException` past them. No bound, no wire
        // member and no digest input change: a previously valid policy held a
        // non-null fingerprint in every slot, so its retained bytes still
        // validate and still re-derive the same idempotency key.
        if (Fingerprints.Any(fingerprint => fingerprint is null)) throw new InvalidOperationException("provider_policy.fingerprints must be present.");
        foreach (var fingerprint in Fingerprints) fingerprint.Validate();
        if (Fingerprints.Zip(Fingerprints.Skip(1)).Any(pair => pair.First == pair.Second))
        {
            throw new InvalidOperationException("provider_policy.fingerprints must not contain adjacent duplicates.");
        }
    }
}

public sealed record UserAutomationDeterministicOnlyProviderPolicy : UserAutomationProviderPolicy
{
    public override void Validate() { }
}

public sealed record UserAutomationProviderFingerprint(
    [property: JsonPropertyName("provider")] string Provider,
    [property: JsonPropertyName("model")] string Model,
    [property: JsonPropertyName("adapter")] string Adapter,
    [property: JsonPropertyName("fingerprint")] string Fingerprint)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(Provider, "provider.provider");
        UserAutomationContract.RequireText(Model, "provider.model");
        UserAutomationContract.RequireText(Adapter, "provider.adapter");
        UserAutomationContract.RequireText(Fingerprint, "provider.fingerprint");
    }
}

public sealed record UserAutomationRouteCostPolicy(
    [property: JsonPropertyName("route_ref")] string RouteRef,
    [property: JsonPropertyName("max_cost_units")] ulong MaxCostUnits,
    [property: JsonPropertyName("max_duration_ms")] ulong MaxDurationMs,
    [property: JsonPropertyName("policy_revision")] ulong? PolicyRevision)
{
    public void Validate()
    {
        UserAutomationContract.RequireText(RouteRef, "route_cost.route_ref");
        if (MaxCostUnits == 0 || MaxDurationMs == 0) throw new InvalidOperationException("route cost ceilings must be nonzero.");
    }
}

public sealed record UserAutomationDeliveryTarget(
    [property: JsonPropertyName("target_ref")] string TargetRef,
    [property: JsonPropertyName("channels")] IReadOnlyList<string> Channels,
    [property: JsonPropertyName("recipient_refs")] IReadOnlyList<string> RecipientRefs)
{
    public void Validate()
    {
        // `channels` is a required reference-typed member and an absent member
        // decodes to null, so the `.Count` below is a direct dereference with
        // nothing in front of it: the `RequireOneOf` that follows it is
        // reached too late, and the `RequireTextList` further down covers
        // `recipient_refs`, not this member. `UserAutomationRevision.Validate`
        // refuses a null `delivery_target`, but the target record being
        // present is not the same claim as its own members being present. A
        // `NullReferenceException` is not an `InvalidOperationException`, so
        // the fault would escape every handler written to contain a
        // closed-shape refusal (`MainViewModel`, the pending journal, the
        // reconciliation loop) instead of the withheld, still-reconciling
        // outcome they are written to produce. Refused by name here, one fixed
        // sentence over the wire member. This adds no bound, no wire member
        // and no digest input: a previously valid target carried the member,
        // so its retained bytes still validate and still re-derive the same
        // idempotency key.
        if (Channels is null) throw new InvalidOperationException("delivery.channels must be present.");
        UserAutomationContract.RequireText(TargetRef, "delivery.target_ref");
        if (Channels.Count == 0) throw new InvalidOperationException("delivery.channels must not be empty.");
        UserAutomationContract.RequireOneOf(Channels, "delivery.channels", "CONTROL_BOARD", "NATIVE_TOAST", "WINDOWS_EVENT_LOG", "RECOVERY_FALLBACK");
        UserAutomationContract.RequireTextList(RecipientRefs, "delivery.recipient_refs");
    }
}

public sealed record UserAutomationResourceCeiling(
    [property: JsonPropertyName("max_runtime_ms")] ulong MaxRuntimeMs,
    [property: JsonPropertyName("max_output_bytes")] ulong MaxOutputBytes,
    [property: JsonPropertyName("max_child_count")] uint MaxChildCount)
{
    public void Validate()
    {
        if (MaxRuntimeMs == 0 || MaxOutputBytes == 0) throw new InvalidOperationException("resource ceilings must be nonzero.");
    }
}

public sealed record UserAutomationRecursionPolicy(
    [property: JsonPropertyName("allow_child_automation")] bool AllowChildAutomation,
    [property: JsonPropertyName("max_child_depth")] ushort MaxChildDepth)
{
    public void Validate()
    {
        if (!AllowChildAutomation && MaxChildDepth != 0) throw new InvalidOperationException("disabled child automation requires max_child_depth=0.");
    }
}

public static class UserAutomationContract
{
    public const string Route = "eliot_user_automation";

    /// <summary>
    /// The admitted preflight contract revision, read from the GENERATED mirror
    /// of the owner contract rather than hand-copied, so a Kernel change to the
    /// revision cannot be absorbed silently by this one consumer.
    /// </summary>
    public const string PreflightContractRevision =
        Generated.OperatorScheduleContract.USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION;

    public static readonly IReadOnlyList<string> OperationKinds = Array.AsReadOnly(
        OperatorScheduleContract.USER_AUTOMATION_OPERATION_KINDS
            .Where(kind => !string.Equals(kind, "get_context", StringComparison.Ordinal))
            .ToArray());

    public static void RequireText(string? value, string field)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{field} must be nonblank and contain no control characters.");
        }
    }

    public static void RequireIdentity(string automationId, string automationRevision)
    {
        RequireText(automationId, "automation_id");
        RequireText(automationRevision, "automation_revision");
    }

    public static void RequireTextList(IEnumerable<string> values, string field)
    {
        if (values is null) throw new InvalidOperationException($"{field} must be present.");
        foreach (var value in values) RequireText(value, field);
    }

    public static void RequireOneOf(string value, string field, params string[] allowed)
    {
        RequireText(value, field);
        if (!allowed.Contains(value, StringComparer.Ordinal))
        {
            throw new InvalidOperationException($"{field} is not an admitted value.");
        }
    }

    public static void RequireOneOf(IEnumerable<string> values, string field, params string[] allowed)
    {
        foreach (var value in values) RequireOneOf(value, field, allowed);
    }
}
