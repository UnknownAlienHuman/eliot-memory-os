import io, sys

ROOT = r'C:\Development\Rust\projects\eliot-swarm\MC-18'
p = ROOT + r'\bins\eliot-agent-bridge\src\cli_contract.rs'
t = io.open(p, encoding='utf-8').read()
assert '\r' not in t

old1 = '''impl std::str::FromStr for Profile {
    type Err = CliError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "SPINE_FUNCTIONAL" => Ok(Self::SpineFunctional),
            "FULL_COMPOSITION" => Ok(Self::FullComposition),
            other => Err(CliError::UnsupportedProfile(other.to_owned())),
        }
    }
}
'''

block = '''
/// Canonical MCP access name of the Codex controller edge (issue #18).
///
/// Ported from `crates/eliot-app/src/mcp_stdio.rs::McpAccessProfile::parse`:
/// there `default` and `codex_controller` both select the controller, but the
/// bridge admits only the explicit spelling. `default` stays
/// [`CliError::UnsupportedProfile`] so a missing profile can never silently
/// become controller authority.
const CODEX_CONTROLLER_PROFILE_NAME: &str = "codex_controller";

/// Scope evidence the Codex controller edge presents (issue #18, names from
/// `mcp_stdio.rs::scoped_host_session_from_env`): either the single-use
/// opaque scope capability or the Governor-bound session plus role lease.
const CODEX_SCOPE_TOKEN_ENV: &str = "ELIOT_CODEX_SCOPE_TOKEN";
const CODEX_AGENT_SESSION_ENV: &str = "ELIOT_AGENT_SESSION_ID";
const CODEX_ROLE_LEASE_ENV: &str = "ELIOT_ROLE_LEASE_ID";

/// Shape of one opaque Codex scope capability
/// (`mcp_stdio.rs::codex_scope_capability_path`): at most 128 bytes starting
/// with the `cs1.` prefix. Shape only; the capability file itself is never
/// opened here.
const CODEX_SCOPE_TOKEN_PREFIX: &str = "cs1.";
const CODEX_SCOPE_TOKEN_MAX_LEN: usize = 128;

/// Typed Codex controller scope/capability admission rejection (issue #18).
///
/// Presence/shape admission only: the bridge mints and verifies no session,
/// lease, or capability. Verification belongs to the session owner on the
/// admitted Kernel path (the declaration digest plus live Kernel challenge
/// behind `kernel_ports_with_declaration`), so this gate can never become a
/// second Governor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CodexScopeError {
    /// No scope evidence: neither the opaque capability nor session+lease.
    MissingScope,
    /// Opaque capability mixed with a raw role lease.
    MixedTokenAndLease,
    /// Opaque capability with an invalid shape.
    MalformedToken,
}

impl CodexScopeError {
    /// Stable machine-readable rejection code.
    const fn code(self) -> &'static str {
        match self {
            Self::MissingScope => "CODEX_CONTROLLER_SCOPE_REQUIRED",
            Self::MixedTokenAndLease => "CODEX_SCOPE_TOKEN_MIXED_WITH_ROLE_LEASE",
            Self::MalformedToken => "CODEX_SCOPE_TOKEN_MALFORMED",
        }
    }
}

impl fmt::Display for CodexScopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Self::MissingScope => {
                "Codex controller MCP requires an active Governor-bound Session and TaskRoleLease (ELIOT_AGENT_SESSION_ID plus ELIOT_ROLE_LEASE_ID) or a single-use Codex scope capability (ELIOT_CODEX_SCOPE_TOKEN)"
            }
            Self::MixedTokenAndLease => {
                "opaque Codex scope capability cannot be mixed with a raw role lease"
            }
            Self::MalformedToken => "invalid opaque Codex scope token shape",
        };
        write!(formatter, "{}: {}", self.code(), detail)
    }
}
impl std::error::Error for CodexScopeError {}

/// True when the named scope variable carries a non-empty value. An empty
/// value is absent: it admits nothing.
fn scope_var_present(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// Admits the Codex controller edge: validates the `codex_controller` access
/// name and gates on scope/capability evidence (issue #18, ported from the
/// `mcp_stdio.rs` host-`None` parse arm, `scoped_host_session_from_env`, and
/// the `run` controller scope requirement).
///
/// Returns the admitted serving contour: the Codex edge is served on the
/// admitted `SPINE_FUNCTIONAL` contour, the same contour the delegated
/// Claude/OpenCode host edges use, never on a codex-specific contour or a
/// Governor path. The legacy host-`None` scopeless serve is deliberately not
/// ported: an evidence-free controller invocation fails closed here instead
/// of being served as an anonymous session.
fn admit_codex_controller() -> Result<Profile, CodexScopeError> {
    let token = std::env::var_os(CODEX_SCOPE_TOKEN_ENV).and_then(|value| {
        let text = value.to_string_lossy().into_owned();
        (!text.is_empty()).then_some(text)
    });
    if let Some(token) = token {
        if scope_var_present(CODEX_ROLE_LEASE_ENV) {
            return Err(CodexScopeError::MixedTokenAndLease);
        }
        if token.len() > CODEX_SCOPE_TOKEN_MAX_LEN
            || !token.starts_with(CODEX_SCOPE_TOKEN_PREFIX)
        {
            return Err(CodexScopeError::MalformedToken);
        }
        return Ok(Profile::SpineFunctional);
    }
    if !(scope_var_present(CODEX_AGENT_SESSION_ENV)
        && scope_var_present(CODEX_ROLE_LEASE_ENV))
    {
        return Err(CodexScopeError::MissingScope);
    }
    Ok(Profile::SpineFunctional)
}

/// Parses one `--profile` value: a declared contour, or the Codex controller
/// access name through [`admit_codex_controller`]. Any other name stays
/// [`CliError::UnsupportedProfile`]; a scope-gate rejection surfaces as
/// [`CliError::MalformedArgument`] carrying the stable [`CodexScopeError`]
/// code, reusing the frozen error contract the bridge entry point handles.
fn parse_profile_arg(value: &str) -> Result<Profile, CliError> {
    match value.parse::<Profile>() {
        Ok(profile) => Ok(profile),
        Err(CliError::UnsupportedProfile(_)) if value == CODEX_CONTROLLER_PROFILE_NAME => {
            admit_codex_controller()
                .map_err(|error| CliError::MalformedArgument(error.to_string()))
        }
        Err(error) => Err(error),
    }
}
'''

assert t.count(old1) == 1, 'anchor FromStr'
t = t.replace(old1, old1 + block)

n1 = '''                profile = Some(value.parse()?);
                index += 2;'''
assert t.count(n1) == 1, 'anchor profile space-2'
t = t.replace(n1, '''                profile = Some(parse_profile_arg(value)?);
                index += 2;''')

n3 = '''                profile = Some(value.parse()?);
                index += 1;'''
assert t.count(n3) == 1, 'anchor profile space-1'
t = t.replace(n3, '''                profile = Some(parse_profile_arg(value)?);
                index += 1;''')

assert 'admit_codex_controller' in t
assert t.count('parse_profile_arg') == 3
assert 'value.parse()?' not in t
io.open(p, 'w', encoding='utf-8', newline='').write(t)
print('cli_contract patched OK')
