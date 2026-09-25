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
        ValidateCore(rawJson, allowedProperties, maxMembers, maxStringChars, maxDepth, maxTokens, maxTokens, shapeName);

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
        ValidateCore(rawJson, null, maxMembers, maxStringChars, maxDepth, maxTokens, maxTokens, shapeName);

    /// Validates one full owner response line. In addition to the framing
    /// caps this bounds total array items and long string/number values, so a
    /// single oversized container or literal is refused on its own axis before
    /// the decoded object is allocated. Duplicate property names are refused
    /// at every object level.
    public static void ValidateFramedResponse(
        string rawJson,
        int maxMembers,
        int maxStringChars,
        int maxDepth,
        int maxTokens,
        int maxArrayItems,
        string shapeName) =>
        ValidateCore(rawJson, null, maxMembers, maxStringChars, maxDepth, maxTokens, maxArrayItems, shapeName);

    private static void ValidateCore(
        string rawJson,
        IReadOnlyCollection<string>? allowedProperties,
        int maxMembers,
        int maxStringChars,
        int maxDepth,
        int maxTokens,
        int maxArrayItems,
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
        // `containers` tracks the open container kind at every level so an
        // array element is counted for scalars and nested containers alike;
        // `objectKeys` carries the per-object duplicate-key set.
        var containers = new Stack<bool>(maxDepth + 1);
        var objectKeys = new Stack<HashSet<string>>(maxDepth + 1);
        var memberCount = 0;
        var itemCount = 0;
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
                    CountArrayElement();
                    if (containers.Count == 0)
                    {
                        sawRootObject = true;
                    }
                    containers.Push(false);
                    objectKeys.Push(new HashSet<string>(StringComparer.Ordinal));
                    break;
                case JsonTokenType.EndObject:
                    if (containers.Count == 0 || containers.Peek() || objectKeys.Count == 0)
                    {
                        throw new OperatorProtocolException(shapeName, "shape");
                    }
                    containers.Pop();
                    objectKeys.Pop();
                    if (containers.Count == 0)
                    {
                        rootClosed = true;
                    }
                    break;
                case JsonTokenType.StartArray:
                    CountArrayElement();
                    containers.Push(true);
                    break;
                case JsonTokenType.EndArray:
                    if (containers.Count == 0 || !containers.Peek())
                    {
                        throw new OperatorProtocolException(shapeName, "shape");
                    }
                    containers.Pop();
                    break;
                case JsonTokenType.PropertyName:
                    var name = reader.GetString() ?? string.Empty;
                    if (name.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "name_cap");
                    }
                    if (objectKeys.Count == 0
                        || !objectKeys.Peek().Add(name))
                    {
                        throw new OperatorProtocolException(shapeName, $"duplicate:{name}");
                    }
                    memberCount++;
                    if (memberCount > maxMembers)
                    {
                        throw new OperatorProtocolException(shapeName, "member_cap");
                    }
                    if (containers.Count == 1 && !containers.Peek()
                        && allowedProperties is not null
                        && !allowedProperties.Contains(name))
                    {
                        throw new OperatorProtocolException(shapeName, $"unknown:{name}");
                    }
                    break;
                case JsonTokenType.String:
                    CountArrayElement();
                    if (reader.ValueSpan.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "string_cap");
                    }
                    break;
                case JsonTokenType.Number:
                    CountArrayElement();
                    if (reader.ValueSpan.Length > maxStringChars)
                    {
                        throw new OperatorProtocolException(shapeName, "string_cap");
                    }
                    break;
                case JsonTokenType.True:
                case JsonTokenType.False:
                case JsonTokenType.Null:
                    CountArrayElement();
                    break;
            }
        }
        if (!sawRootObject || !rootClosed)
        {
            throw new OperatorProtocolException(shapeName, "shape");
        }

        void CountArrayElement()
        {
            if (containers.Count == 0 || !containers.Peek())
            {
                return;
            }
            itemCount++;
            if (itemCount > maxArrayItems)
            {
                throw new OperatorProtocolException(shapeName, "array_item_cap");
            }
        }
    }
}
