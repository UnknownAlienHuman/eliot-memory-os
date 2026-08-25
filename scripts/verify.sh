#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="$repo_root/scripts/verify.ps1"

if [[ ! -f "$profile" ]]; then
    printf 'VERIFY_FAIL: profile is missing: %s\n' "$profile" >&2
    exit 1
fi

if command -v pwsh >/dev/null 2>&1; then
    pwsh_path="$(command -v pwsh)"
elif [[ -x "/mnt/c/Program Files/PowerShell/7/pwsh.exe" ]]; then
    pwsh_path="/mnt/c/Program Files/PowerShell/7/pwsh.exe"
else
    printf 'VERIFY_FAIL: PowerShell 7 (pwsh) is required for profile %s\n' "$profile" >&2
    exit 1
fi

profile_for_pwsh="$profile"
platform="$(uname -s 2>/dev/null || true)"

# The Windows workspace parent config intentionally points at the native
# Windows build cache and sccache binary.  WSL/Linux must not inherit those
# host-specific paths.  Preserve explicit caller overrides and use the native
# user cache only when this wrapper is the entrypoint.
if [[ "$platform" == Linux* ]]; then
    if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
        cache_root="${XDG_CACHE_HOME:-${HOME}/.cache}"
        export CARGO_TARGET_DIR="$cache_root/eliot-memory-os-target"
    fi
    if [[ -z "${CARGO_BUILD_RUSTC_WRAPPER:-}" ]] && ! command -v sccache >/dev/null 2>&1; then
        export CARGO_BUILD_RUSTC_WRAPPER=/usr/bin/env
    fi
fi

if [[ "$pwsh_path" == /mnt/* && -n "$(command -v wslpath || true)" ]]; then
    profile_for_pwsh="$(wslpath -w "$profile")"
elif [[ "$platform" == CYGWIN* || "$platform" == MINGW* ]] &&
      [[ "$pwsh_path" == /* && -n "$(command -v cygpath || true)" ]]; then
    profile_for_pwsh="$(cygpath -w "$profile")"
fi

if [[ "${1:-}" == '--list' ]]; then
    shift
    set -- '-List' "$@"
fi

exec "$pwsh_path" -NoProfile -File "$profile_for_pwsh" "$@"
