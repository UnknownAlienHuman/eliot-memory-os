#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'VERIFY_NORMATIVE_FAIL: %s\n' "$1" >&2
    exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
projection_root="$repo_root/docs/normative"
manifest_path="$projection_root/projection-manifest.tsv"
contract_path="$repo_root/docs/ARCHITECTURE_CONTRACT.md"

[[ -d "$projection_root" ]] || fail "projection directory is missing"
[[ -f "$manifest_path" ]] || fail "projection manifest is missing"
[[ -f "$contract_path" ]] || fail "architecture contract is missing"

expected_files=(
    ELIOT_ARCHITECTURE.md
    ELIOT_IMPLEMENTATION.md
    INDEX.md
    README.md
)

declare -A expected_set=()
for file in "${expected_files[@]}"; do
    expected_set["${file,,}"]="$file"
done

declare -A metadata=()
declare -A manifest_hash=()
declare -A manifest_seen=()

while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" == \#* ]] && continue

    IFS=$'\t' read -r key field2 field3 extra <<< "$line"
    case "$key" in
        projection_file)
            [[ -z "${extra:-}" && -n "${field2:-}" && -n "${field3:-}" ]] ||
                fail "projection_file record must have exactly 3 TSV fields"
            path_key="${field2,,}"
            [[ -n "${expected_set[$path_key]+x}" ]] ||
                fail "manifest contains an unexpected projection file: $field2"
            [[ -z "${manifest_seen[$path_key]+x}" ]] ||
                fail "manifest contains a duplicate projection file: $field2"
            [[ "$field3" =~ ^[0-9A-Fa-f]{64}$ ]] ||
                fail "manifest contains an invalid SHA-256 for $field2"
            manifest_seen["$path_key"]=1
            manifest_hash["$path_key"]="${field3^^}"
            ;;
        schema_version|kind|authority_status)
            [[ -z "${field3:-}" && -z "${extra:-}" && -n "${field2:-}" ]] ||
                fail "metadata record must have exactly 2 TSV fields: $key"
            [[ -z "${metadata[$key]+x}" ]] ||
                fail "manifest contains duplicate metadata key: $key"
            metadata["$key"]="$field2"
            ;;
        *)
            fail "unknown manifest record: $key"
            ;;
    esac
done < "$manifest_path"

[[ "${metadata[schema_version]:-}" == 'eliot-normative-projection-v1' ]] ||
    fail 'unsupported or missing projection manifest schema'
[[ "${metadata[kind]:-}" == 'non_authority_projection' &&
   "${metadata[authority_status]:-}" == 'NOT_AUTHORITY' ]] ||
    fail 'projection is not explicitly marked NOT_AUTHORITY'
(( ${#manifest_seen[@]} == ${#expected_files[@]} )) ||
    fail "manifest must contain exactly ${#expected_files[@]} projection files"

contract_hash() {
    local file="$1"
    local row
    local hash
    mapfile -t rows < <(grep -F "| \`$file\` |" "$contract_path" || true)
    (( ${#rows[@]} == 1 )) || fail "contract hash row is missing or ambiguous for $file"
    mapfile -t hashes < <(printf '%s\n' "${rows[0]}" | grep -Eio '[0-9a-f]{64}' || true)
    (( ${#hashes[@]} == 1 )) || fail "contract hash row is missing or ambiguous for $file"
    hash="${hashes[0]}"
    printf '%s' "$hash" | tr '[:lower:]' '[:upper:]'
}

hash_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print toupper($1)}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print toupper($1)}'
    else
        fail 'sha256sum or shasum is required'
    fi
}

for file in "${expected_files[@]}"; do
    path="$projection_root/$file"
    [[ -f "$path" ]] || fail "projection file is missing: $file"

    mapfile -t matches < <(find "$projection_root" -type f -iname "$file" -print)
    (( ${#matches[@]} == 1 )) || fail "projection file is duplicated or moved: $file"
    [[ "${matches[0]}" == "$path" ]] || fail "projection file is duplicated or moved: $file"

    key="${file,,}"
    actual_hash="$(hash_file "$path")"
    [[ "$actual_hash" == "${manifest_hash[$key]}" ]] ||
        fail "manifest hash mismatch for $file: expected ${manifest_hash[$key]}, actual $actual_hash"

    if [[ "$file" == ELIOT_ARCHITECTURE.md || "$file" == ELIOT_IMPLEMENTATION.md ]]; then
        expected_contract_hash="$(contract_hash "$file")"
        [[ "$actual_hash" == "$expected_contract_hash" ]] ||
            fail "contract hash mismatch for $file: expected $expected_contract_hash, actual $actual_hash"
    fi
done

printf 'NORMATIVE_VERIFY: PASS projection=docs/normative files=%s authority=NOT_AUTHORITY\n' "${#expected_files[@]}"
