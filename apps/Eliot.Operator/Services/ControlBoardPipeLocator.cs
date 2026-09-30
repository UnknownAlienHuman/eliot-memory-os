using System.Text.Json;
using Eliot.Operator.Protocol;

namespace Eliot.Operator.Services;

/// Locates the role-filtered ControlBoard/Operator IPC pipe by reading the
/// runtime owner's own published identity.
///
/// I11.8 binds the WinUI client through TWO transports: the interactive User
/// Broker, and authenticated local IPC. They are not one pipe. The broker's
/// one-shot handoff pipe is the first; the only server of that name accepts
/// `operator_challenge` and then `redeem_operator_handoff` and answers
/// anything else `BROKER_PROTOCOL_SEQUENCE_REJECTED`
/// (`serve_operator_pipe_connection`,
/// `bins/eliot-user-broker/src/main.rs`). The second is the
/// Governor/ControlBoard IPC, whose owner is the runtime instance: it binds
/// that pipe, publishes it in its own runtime publication, and serves
/// `eliot_ipc_handshake` on it with its existing role filter and binding
/// validator (`RuntimeInstance::pipe_name` and `IpcServer::bind` in
/// `crates/eliot-app/src/named_pipe_ipc.rs`).
///
/// This locator therefore never reads the ControlBoard pipe name from the
/// broker handoff. `OperatorEndpoint.pipe_name` names the broker's transport
/// and only that, and the broker owner now pins it to its own pipe
/// (`OperatorEndpoint::validate`). The name used for the `eliot_ipc_handshake`
/// leg is read from the publication the runtime owner itself wrote, so the UI
/// is routed onto the existing owner instead of guessing, deriving,
/// defaulting or caching a name. A publication that is absent, oversized,
/// malformed, of another schema/instance/protocol generation, not `ready`, or
/// that names the broker's handoff pipe is a typed refusal; none of those
/// yields a name, and there is no second attempt, no default and no cached
/// fallback.
///
/// The publication is an ADDRESS, never an authority: nothing read here
/// proves a grant, and authentication remains the serving owner's own
/// handshake, role filter and binding validator. No path, executable, token
/// or record content from the publication is used or retained.
internal static class ControlBoardPipeLocator
{
    private const string Shape = "controlboard_publication";

    /// `RuntimeInstance::starting_publication` / `publish` writes this
    /// schema for every published generation
    /// (`crates/eliot-app/src/runtime_instance.rs`).
    private const string PublicationSchemaVersion = "eliot-runtime-publication-v1";

    /// `RuntimePublicationState::Ready`. Only a `ready` generation is
    /// serving, so a `starting`, `stopping` or `failed` owner is refused
    /// rather than dialled.
    private const string ReadyState = "ready";

    /// `DEFAULT_INSTANCE_NAME`. The owner publishes the default standalone
    /// instance at a stable, unhashed root
    /// (`RuntimeInstance::select` -> `eliot_home().join("instances").join(name)`),
    /// so this locator reads the owner's own file instead of re-deriving the
    /// hashed publication root a default-config selection would use. The one
    /// hashed-derivation rule stays in the crate that owns it.
    private const string DefaultInstanceName = "default";

    /// Encoded-byte ceiling for one owner publication before it is decoded.
    /// The publication is a small flat object of scalars; anything larger is
    /// not the owner's shape and is refused whole, never truncated.
    private const int MaxPublicationChars = 65_536;

    /// Returns the ControlBoard/Operator IPC pipe name, already stripped of
    /// the `\\.\pipe\` prefix that `NamedPipeClientStream` does not want.
    ///
    /// `handoffPipeName` is the broker-issued name from the consumed
    /// endpoint. It is used only for the one invariant this locator owns:
    /// the two transports must be different pipes.
    public static string ReadPipeName(string? handoffPipeName)
    {
        if (string.IsNullOrWhiteSpace(handoffPipeName))
        {
            throw new OperatorProtocolException(Shape, "handoff_pipe");
        }

        var encoded = ReadPublication();
        OperatorJsonGuard.ValidateFramedLine(
            encoded,
            OperatorProtocol.MaxControlMembers,
            OperatorProtocol.MaxControlStringChars,
            OperatorProtocol.MaxControlDepth,
            OperatorProtocol.MaxControlTokens,
            Shape);
        using var publication = JsonDocument.Parse(encoded, new JsonDocumentOptions
        {
            MaxDepth = OperatorProtocol.MaxControlDepth
        });
        var root = publication.RootElement;
        if (!string.Equals(
                BrokerPipeClient.RequiredString(root, "schema_version", Shape),
                PublicationSchemaVersion,
                StringComparison.Ordinal))
        {
            throw new OperatorProtocolException(Shape, "schema");
        }
        if (!string.Equals(
                BrokerPipeClient.RequiredString(root, "protocol_version", Shape),
                OperatorProtocol.IpcProtocolVersion,
                StringComparison.Ordinal))
        {
            throw new OperatorProtocolException(Shape, "protocol");
        }
        if (!string.Equals(
                BrokerPipeClient.RequiredString(root, "instance_name", Shape),
                DefaultInstanceName,
                StringComparison.Ordinal))
        {
            throw new OperatorProtocolException(Shape, "instance");
        }
        if (!string.Equals(
                BrokerPipeClient.RequiredString(root, "state", Shape),
                ReadyState,
                StringComparison.Ordinal))
        {
            throw new OperatorProtocolException(Shape, "not_ready");
        }

        var published = BrokerPipeClient.RequiredString(root, "pipe_name", Shape);
        // The one structural invariant here: the ControlBoard pipe is a
        // different transport from the broker handoff pipe. An equal name is
        // refused so `eliot_ipc_handshake` can never be written to the
        // broker's one-shot pipe, which would answer it
        // `BROKER_PROTOCOL_SEQUENCE_REJECTED` and close.
        if (string.Equals(published, handoffPipeName, StringComparison.OrdinalIgnoreCase))
        {
            throw new OperatorProtocolException(Shape, "pipe_shared_with_handoff");
        }

        // The same `\\.\pipe\` normalisation the broker leg applies to its own
        // owner-issued name (`BrokerPipeClient.OwnerIssuedPipeName`); it is
        // what `NamedPipeClientStream` accepts, not an authority decision.
        var normalized = published.Replace(@"\\.\pipe\", string.Empty, StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(normalized) || normalized.Length == published.Length)
        {
            throw new OperatorProtocolException(Shape, "field:pipe_name");
        }
        return normalized;
    }

    private static string ReadPublication()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Eliot",
            "instances",
            DefaultInstanceName,
            "runtime",
            "publication.json");
        try
        {
            if (new FileInfo(path).Length > MaxPublicationChars)
            {
                throw new OperatorProtocolException(Shape, "publication_cap");
            }
            var encoded = File.ReadAllText(path);
            return encoded.Length > MaxPublicationChars
                ? throw new OperatorProtocolException(Shape, "publication_cap")
                : encoded;
        }
        catch (OperatorProtocolException)
        {
            throw;
        }
        catch (Exception error) when (error is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or NotSupportedException)
        {
            // No publication, an unreadable one, or no local application data
            // root. There is no second attempt and no default: the serving
            // owner publishes its own address or the UI has none.
            throw new OperatorProtocolException(Shape, "publication_unreadable");
        }
    }
}
