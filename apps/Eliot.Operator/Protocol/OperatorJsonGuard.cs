using System.Text;
using System.Text.Json;

namespace Eliot.Operator.Protocol;

/// A protected control shape (endpoint, handshake, receipt control fields)
/// failed closed decoding. Only the shape name and reason travel; values
/// never do.
public sealed class OperatorProtocolException(string shape, string reason)
    : InvalidOperationException($"Operator {shape} refused: {reason}")
{
    public string Shape { get; } = shape;
    public string Reason { get; } = reason;
}

/// Closed-shape guard for small protected control objects (endpoint,
/// handshake, receipt control fields). It rejects unknown properties and
/// duplicate keys before trusted use, and enforces independent member, depth,
/// string, and token caps before allocation. Bounded opaque result payloads
/// remain untrusted data and never pass through this guard as control.
public static class OperatorJsonGuard
{
    /// Validates that `rawJson` is one JSON object whose depth-1 properties
    /// are exactly members of `allowedProperties` (no unknown, no duplicate
    /// at any object level) within the given caps. Only the property names of
    /// a rejection are reported; values are never echoed.
    public static void ValidateClosedObject(
        string rawJson,
        IReadOnlyCollection<string> allowedProperties,
        int maxMembers,
        int maxStringChars,
        int maxDepth,
        int maxTokens,
        string shapeName) =>
        ValidateCore(rawJson, allowedProperties, maxMembers, maxStringChars, maxDepth, maxTokens, shapeName);

    /// Validates framing only for a server-owned line (handshake, tool
    /// response): caps plus duplicate-key rejection at every object level,
    /// without an allow-list the UI does not own. The caller still requires
    /// the exact control fields it trusts before use.
    public static void ValidateFramedLine(
        string rawJson,
        int maxMembers,
        int maxStringChars,
        int maxDepth,
        int maxTokens,
        string shapeName) =>
        ValidateCore(rawJson, null, maxMembers, maxStringChars, maxDepth, maxTokens, shapeName);

    private static void ValidateCore(
        string rawJson,
        IReadOnlyCollection<string>? allowedProperties,
        int maxMembers,
        int maxStringChars,
        int maxDepth,
        int maxTokens,
        string shapeName)
    {
        if (string.IsNullOrEmpty(rawJson))
        {
            throw new OperatorProtocolException(shapeName, "empty");
        }
        var bytes = Encoding.UTF8.GetBytes(rawJson);
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = maxDepth
        });
        var objectDepths = new Stack<HashSet<string>>(maxDepth + 1);
        var memberCount = 0;
        var tokenCount = 0;
        var sawRootObject = false;
        var rootClosed = false;
        while (reader.Read())
        {
            tokenCount++;
            if (tokenCount > maxTokens)
            {
                throw new OperatorProtocolException(shapeName, "token_cap");
            }
            if (reader.CurrentDepth > maxDepth)
            {
                throw new OperatorProtocolException(shapeName, "depth_cap");
            }
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    if (reader.CurrentDepth == 0)
                    {
                        sawRootObject = true;
                    }
                    objectDepths.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.EndObject:
                    if (objectDepths.Count == 0)
                    {
                        throw new OperatorProtocolException(shapeName, "shape");
                    }
                    objectDepths.Pop();
                    if (objectDepths.Count == 0)
                    {
                        rootClosed = true;
                    }
                    break;
                case JsonTokenType.PropertyName:
                    var name = reader.GetString() ?? string.Empty;
                    if (name.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "name_cap");
                    }
                    if (objectDepths.Count == 0
                        || !objectDepths.Peek().Add(name))
                    {
                        throw new OperatorProtocolException(shapeName, $"duplicate:{name}");
                    }
                    memberCount++;
                    if (memberCount > maxMembers)
                    {
                        throw new OperatorProtocolException(shapeName, "member_cap");
                    }
                    if (objectDepths.Count == 1 && allowedProperties is not null && !allowedProperties.Contains(name))
                    {
                        throw new OperatorProtocolException(shapeName, $"unknown:{name}");
                    }
                    break;
                case JsonTokenType.String:
                    if (reader.ValueSpan.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "string_cap");
                    }
                    break;
                case JsonTokenType.Number:
                    if (reader.ValueSpan.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "string_cap");
                    }
                    break;
            }
        }
        if (!sawRootObject || !rootClosed)
        {
            throw new OperatorProtocolException(shapeName, "shape");
        }
    }
}
