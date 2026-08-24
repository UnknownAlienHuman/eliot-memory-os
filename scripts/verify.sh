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
if [[ "$pwsh_path" == /mnt/* && -n "$(command -v wslpath || true)" ]]; then
    profile_for_pwsh="$(wslpath -w "$profile")"
elif [[ "$pwsh_path" == /* && -n "$(command -v cygpath || true)" ]]; then
    profile_for_pwsh="$(cygpath -w "$profile")"
fi

if [[ "${1:-}" == '--list' ]]; then
    shift
    set -- '-List' "$@"
fi

exec "$pwsh_path" -NoProfile -File "$profile_for_pwsh" "$@"
