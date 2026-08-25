#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="$repo_root/scripts/verify-normative.ps1"

if [[ ! -f "$profile" ]]; then
    printf 'VERIFY_NORMATIVE_FAIL: profile is missing: %s\n' "$profile" >&2
    exit 1
fi

if command -v pwsh >/dev/null 2>&1; then
    pwsh_path="$(command -v pwsh)"
elif [[ -x "/mnt/c/Program Files/PowerShell/7/pwsh.exe" ]]; then
    pwsh_path="/mnt/c/Program Files/PowerShell/7/pwsh.exe"
else
    printf 'VERIFY_NORMATIVE_FAIL: PowerShell 7 (pwsh) is required for profile %s\n' "$profile" >&2
    exit 1
fi

platform="$(uname -s 2>/dev/null || true)"
is_wsl=false
if [[ "$platform" == Linux* ]] && {
    [[ -n "${WSL_DISTRO_NAME:-}" ]] ||
    [[ -n "${WSL_INTEROP:-}" ]] ||
    { [[ -r /proc/sys/kernel/osrelease ]] && grep -qiE 'microsoft|wsl' /proc/sys/kernel/osrelease; }
}; then
    is_wsl=true
fi

profile_for_pwsh="$profile"
if [[ "$is_wsl" == true && "$pwsh_path" == /mnt/* && -n "$(command -v wslpath || true)" ]]; then
    profile_for_pwsh="$(wslpath -w "$profile")"
elif [[ "$platform" == CYGWIN* || "$platform" == MINGW* ]] &&
      [[ "$pwsh_path" == /* && -n "$(command -v cygpath || true)" ]]; then
    profile_for_pwsh="$(cygpath -w "$profile")"
fi

exec "$pwsh_path" -NoProfile -File "$profile_for_pwsh" "$@"
