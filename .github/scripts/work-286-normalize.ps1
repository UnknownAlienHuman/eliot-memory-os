$ErrorActionPreference = 'Stop'

$path = 'crates/agent/eliot-agent-opencode/src/catalogue.rs'
$source = [IO.File]::ReadAllText($path).Replace("`r`n", "`n")

$source = $source.Replace("use std::path::Path;`n`n", '')
$source = [Text.RegularExpressions.Regex]::Replace(
    $source,
    'fn evidence_refs\(\s*groups: impl IntoIterator<Item = impl IntoIterator<Item = String>>,\s*\)',
    'fn evidence_refs(groups: Vec<Vec<String>>)'
)
$source = $source.Replace('evidence_refs([', 'evidence_refs(vec![')
$source = [Text.RegularExpressions.Regex]::Replace(
    $source,
    '(?m)^    #\[serde\(default\)\]\n    output: Option<u64>,\n',
    ''
)
$source = $source.Replace(
    'use std::path::PathBuf;',
    'use std::path::{Path, PathBuf};'
)

$metadataPattern = '(?s)    fn metadata\(value: Value\) -> UnknownFields \{.*?^    \}\n\n    fn model'
$metadataReplacement = @'
    fn metadata(value: Value) -> UnknownFields {
        value
            .as_object()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect()
    }

    fn model
'@.Replace("`r`n", "`n")
$updated = [Text.RegularExpressions.Regex]::Replace(
    $source,
    $metadataPattern,
    $metadataReplacement,
    [Text.RegularExpressions.RegexOptions]::Multiline
)
if ($updated -eq $source) {
    throw 'SOURCE_PATCH_FAILED: metadata fixture'
}
$source = $updated
$source = $source.Replace(
    'model.id.clone().expect("model id")',
    'model.id.clone().unwrap_or_else(|| "missing-model-id".to_owned())'
)
$source = $source.Replace(
    'let is_connected = connected.contains(provider.id.as_str()) || provider.connected == Some(true);',
    'let is_connected = connected.contains(provider.id.as_str()) || provider.connected.is_some_and(|value| value);'
)

[IO.File]::WriteAllText($path, $source, [Text.UTF8Encoding]::new($false))
