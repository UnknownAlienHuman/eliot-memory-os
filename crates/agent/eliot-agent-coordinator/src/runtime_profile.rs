//! Kernel-owned runtime configuration surface: the I14.2 queue-profile
//! defaults live in `runtime.toml`, not in Architecture.
//!
//! I14.2 closes with the sentence "Numbers are defaults in `runtime.toml`,
//! not Architecture", and the doc comment on
//! [`SchedulingProfile::i14_2_initial`] in `model.rs` names this module as the
//! owner that produces those values: "This is not a second configuration
//! source. It reads no file, no environment variable and no working
//! directory; the Kernel runtime profile loader that produces these values is
//! a separate owner (#1679 item 2, #1687) and is not wired here." That loader
//! is this module (#1687 W2). It reads exactly one caller-supplied file and
//! compiles it into the existing [`SchedulingProfile`] through the existing
//! [`PolicyBoundClassLimits`] type and the existing
//! [`SchedulingProfile::i14_2_initial`] constructor.
//!
//! It adds no second queue-profile type, no second limits type, no second
//! validator and no second configuration source. Per-class legality is decided
//! once, by the existing `validate` chain: this module only refuses what the
//! typed document cannot express, and `i14_2_initial` remains the only place
//! that applies the I14.2 item-ceiling defaults and the only legality gate.
//!
//! # Accepted document
//!
//! ```toml
//! schema_version = "eliot-agent-coordinator/runtime-profile-v1"
//! profile_revision = "queue-profile-1"
//!
//! [[classes]]
//! work_class = "control"
//! max_items = 64
//! max_bytes = 67108864
//! max_concurrency = 4
//! deadline_ms = 30000
//! weight = 1000
//!
//! [[classes.wip_partitions]]
//! key = "ROUTE"
//! max_in_flight = 4
//! ```
//!
//! `work_class` accepts exactly the nine closed I14.1 wire spellings
//! (`control`, `interactive`, `verification`, `canonical_write`,
//! `normal_background`, `model_jobs`, `swarm`, `reporting`, `maintenance`)
//! through the existing [`WorkClass`] boundary type, whose `Deserialize` is
//! already the sole validated constructor from a wire string. `key` accepts
//! the four existing [`WipPartitionKey`] names. Unknown fields are refused on
//! the document, on each class entry and inside each partition, so a typo is a
//! refusal and never an ignored limit.
//!
//! # Defaults and refusals
//!
//! I14.2 fixes an item ceiling for only five pools and no other ceiling at
//! all, so the file is the default source for exactly those five numbers and a
//! required source for everything else:
//!
//! - `max_items` is the only optional field. A present value always wins; an
//!   absent value is the existing `Option` contract and takes the I14.2
//!   documented default for `interactive`, `verification`, `canonical_write`,
//!   `normal_background` and `reporting`. For `control`, `model_jobs`, `swarm`
//!   and `maintenance` I14.2 names no ceiling, so an absent value is a typed
//!   refusal from `i14_2_initial`, never a default.
//! - `max_bytes`, `max_concurrency`, `deadline_ms`, `weight` and
//!   `wip_partitions` are required on every class. I14.1 states "Each has
//!   bounded items, bytes, concurrency and deadline profile", so no class may
//!   be constructed without a byte ceiling and this module supplies no number
//!   for any of them.
//!
//! # Fail-closed
//!
//! An unreadable, non-UTF-8, oversized, malformed, unknown-field, wrong-type,
//! wrongly-versioned or incomplete document is a typed
//! [`RuntimeProfileRejection`], never a silent fall back to a default. There is
//! no partial adoption: the profile is returned only after
//! `i14_2_initial` has accepted all nine classes.
//!
//! An absent file is its own typed case ([`RuntimeProfileRejection::Absent`])
//! and is deliberately *not* a defaulted profile. I14.2 fixes no byte,
//! concurrency, deadline, weight or WIP value for any class and no item
//! ceiling for four of them, so "no file" cannot be compiled into a complete
//! nine-class policy without inventing numbers that no fragment states.
//! Silently defaulting it would let an installation that never wrote a
//! runtime profile run on nine ceilings this repository cannot justify.
//!
//! # Bounded behaviour
//!
//! The read is bounded by [`RUNTIME_PROFILE_MAX_BYTES`] and stops at the first
//! byte past that bound, so a larger file is a refusal, not a truncated parse.
//! The bounded reader is the enforcement point, so the bound holds for a file
//! that grows while it is being read. The loader reads no environment variable,
//! no working directory, no clock, no network and no process, takes no
//! authority, mutates no state and publishes no receipt. `profile_revision` is
//! required rather than synthesized so every pull outcome can be attributed to
//! the exact configuration revision that produced its ceilings.
//!
//! # Caller
//!
//! `caller: STITCH`. Nothing in the tree calls this loader yet, and this module
//! does not invent a caller. The upstream reason is recorded on
//! `AgentCoordinator::pull_next` in `core.rs` and is narrower than "no profile
//! was supplied": in production this coordinator's `attempts` map is empty,
//! because no production issuer of the provider-verified
//! `ProviderAdmissionReceipt` that `AgentCoordinator::admit` requires exists in
//! this tree, and the `eliotd` fabric admits through a separate
//! `FabricAdmission` vocabulary that never reaches this coordinator. Wiring this
//! loader alone would therefore compile a profile for a projection that is
//! permanently empty. The blocking join is a type-level join between those two
//! independently owned admission vocabularies — **not** the #1678 reservation
//! saga, which owns the ORS `AdmissionReservation` type, appears nowhere in this
//! crate, and assigns its own fabric-side binding to #1701. The profile-free
//! `AgentCoordinator::next_ready` is likewise exercised only from in-crate
//! tests. The composition root that compiles this document is a separate owner.

use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::model::{
    CoordinatorError, PolicyBoundClassLimits, SchedulingProfile, WipPartitionLimit, WorkClass,
    validate_text,
};

/// File name of the Kernel-owned runtime configuration document.
///
/// I14.2 names `runtime.toml` as the surface its numbers are defaults in. The
/// loader takes the resolved path from its caller, so this constant is the
/// canonical name and never an implicit search of a working directory.
pub const RUNTIME_PROFILE_FILE_NAME: &str = "runtime.toml";

/// Exact `schema_version` this loader admits.
///
/// A document naming any other revision is refused, so a future shape cannot
/// be read by a loader that does not understand it.
pub const RUNTIME_PROFILE_SCHEMA_VERSION: &str = "eliot-agent-coordinator/runtime-profile-v1";

/// Upper bound on the bytes kept from one runtime configuration document.
///
/// Nine class entries with a handful of scalars each are kilobytes; this bound
/// is two orders of magnitude above any real document. It bounds the read, not
/// a queue profile: I14.2 fixes no number here. The loader reads one byte past
/// it so an exact-bound document stays distinguishable from an oversized one,
/// which is why it is an upper bound on retained bytes and the enforced read
/// limit is this plus one.
pub const RUNTIME_PROFILE_MAX_BYTES: usize = 64 * 1024;

/// Typed refusals of the Kernel runtime configuration surface.
///
/// Every variant is fail-closed. None carries document content: the reason is
/// the decoder's own field/type complaint or the offending path, so an
/// operator can locate the defect without the rejection echoing the file.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum RuntimeProfileRejection {
    /// No document exists at the caller-supplied path.
    ///
    /// This is explicitly distinct from a parse failure, and it does not
    /// resolve to a defaulted profile: I14.1 requires a bounded byte profile
    /// for all nine classes and I14.2 fixes no item ceiling for `control`,
    /// `model_jobs`, `swarm` or `maintenance`, so an absent document supplies
    /// too little policy to compile nine classes.
    #[error(
        "runtime configuration is absent at {0}: it is the only source of the queue-profile values I14.1 and I14.2 leave to policy, so absence is a refusal and not a defaulted profile"
    )]
    Absent(String),
    /// The document exists but could not be read as bounded UTF-8 text.
    #[error("runtime configuration is not readable bounded UTF-8: {0}")]
    Unreadable(String),
    /// The document was read and is not a valid runtime configuration profile.
    ///
    /// This covers a syntax error, an unknown field, a wrong value type, a
    /// missing required field, a wrong `schema_version` and a blank
    /// `profile_revision`. The reason names the field or type defect only.
    #[error("runtime configuration document rejected: {0}")]
    SchemaRejected(String),
}

/// One class entry of the Kernel runtime configuration document.
///
/// The shape is the file's own spelling of the existing
/// [`PolicyBoundClassLimits`] contract, not a second limits type:
/// `max_items` keeps its `Option` default semantics, and every other ceiling
/// is a required field because I14.2 fixes none of them.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClassLimits {
    /// One of the nine closed I14.1 classes.
    pub work_class: WorkClass,
    /// Item ceiling for this class. `None` takes the I14.2 documented default
    /// and is accepted only for the five classes I14.2 gives a number to; a
    /// present value always wins.
    pub max_items: Option<usize>,
    /// Byte ceiling for this class. Required and positive: I14.1 bounds bytes
    /// for every class and this loader supplies no number for any of them.
    pub max_bytes: u64,
    /// Concurrency ceiling for this class.
    pub max_concurrency: usize,
    /// Deadline ceiling for this class.
    pub deadline_ms: u64,
    /// I14.8 weight of this class in the weighted fair pull.
    pub weight: u32,
    /// I14.8 WIP partitions of this class. At least one is required by the
    /// existing per-class validator.
    pub wip_partitions: Vec<WipPartitionLimit>,
}

/// The decoded Kernel runtime configuration document.
///
/// Decoding is separated from compiling on purpose, and the split mirrors the
/// existing typed precedence surface in `eliotd::canonical_config_precedence`:
/// a typed `deny_unknown_fields` document, a typed fail-closed error, and one
/// later step that validates and resolves. It is the only in-tree `runtime.toml`
/// shape, so the legacy Governor file is not the second configuration source
/// and does not need a competing parser.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfileDocument {
    /// Must equal [`RUNTIME_PROFILE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Caller-owned revision of this document. It becomes the compiled
    /// profile's `profile_revision`, which is recorded in every pull outcome
    /// and is the only value whose change re-opens a saturated limit.
    pub profile_revision: String,
    /// One entry per I14.1 class. Completeness and uniqueness are decided by
    /// [`SchedulingProfile::i14_2_initial`], not re-derived here.
    pub classes: Vec<RuntimeClassLimits>,
}

impl RuntimeProfileDocument {
    /// Decodes one typed runtime configuration document.
    ///
    /// Unknown fields, duplicate keys, wrong value types and missing required
    /// fields are refusals. The returned document is decoded but not yet
    /// validated: [`compile_runtime_scheduling_profile`] is the validating
    /// entry point, so a document is never compiled without its schema identity
    /// and text fields being checked exactly once.
    ///
    /// # Errors
    /// Returns [`CoordinatorError::RuntimeProfileRejected`] with
    /// [`RuntimeProfileRejection::SchemaRejected`] for any decode failure. The
    /// decoder's rendered span, which would echo the offending line, is
    /// deliberately not used; only its field/type reason is reported.
    pub fn from_toml(text: &str) -> Result<Self, CoordinatorError> {
        toml::from_str(text).map_err(|error| {
            RuntimeProfileRejection::SchemaRejected(error.message().to_owned()).into()
        })
    }

    /// Validates the document-level fields only.
    ///
    /// Class ceilings are deliberately not checked here: per-class legality
    /// belongs to the existing [`SchedulingProfile::i14_2_initial`] chain, and
    /// checking it twice would create a second validator that could disagree
    /// with the first.
    fn validate(&self) -> Result<(), CoordinatorError> {
        validate_text(&self.schema_version, "schema_version")?;
        if self.schema_version != RUNTIME_PROFILE_SCHEMA_VERSION {
            return Err(RuntimeProfileRejection::SchemaRejected(format!(
                "unsupported schema_version, expected {RUNTIME_PROFILE_SCHEMA_VERSION}"
            ))
            .into());
        }
        validate_text(&self.profile_revision, "profile_revision")?;
        Ok(())
    }
}

/// Reads and decodes the Kernel runtime configuration document at `path`.
///
/// The path is supplied by the caller. This function resolves no environment
/// variable, no working directory and no installation root of its own, so the
/// configuration location is a decision of the composition root rather than
/// ambient state.
///
/// The document is read through a reader capped at one byte past
/// [`RUNTIME_PROFILE_MAX_BYTES`] rather than in full, so a mistakenly supplied
/// oversized file is refused after a bounded read instead of after a whole-file
/// allocation.
///
/// # Errors
/// Returns [`RuntimeProfileRejection::Absent`] when no document exists at
/// `path`, [`RuntimeProfileRejection::Unreadable`] when it cannot be read as
/// bounded UTF-8, and [`RuntimeProfileRejection::SchemaRejected`] when it does
/// not decode. An absent document is never treated as a default profile.
pub fn load_runtime_profile_document(
    path: &Path,
) -> Result<RuntimeProfileDocument, CoordinatorError> {
    let refusal = |error: std::io::Error| -> CoordinatorError {
        if error.kind() == std::io::ErrorKind::NotFound {
            return RuntimeProfileRejection::Absent(path.display().to_string()).into();
        }
        RuntimeProfileRejection::Unreadable(format!("{}: {error}", path.display())).into()
    };
    let oversized = || {
        RuntimeProfileRejection::Unreadable(format!(
            "{}: document exceeds the {RUNTIME_PROFILE_MAX_BYTES} byte read bound",
            path.display()
        ))
    };
    let file = std::fs::File::open(path).map_err(refusal)?;
    // The bound is enforced by capping the reader itself, not by measuring a
    // whole-file read afterwards: `Take` yields at most
    // `RUNTIME_PROFILE_MAX_BYTES + 1` bytes over the whole call, so that is the
    // most that can ever be read from the file. The one extra byte is what
    // distinguishes an exact-bound document from an oversized one, so nothing is
    // truncated and then accepted. The conversion is checked rather than an
    // unchecked narrowing cast, and no filesystem metadata is consulted: the
    // file may grow after it is opened, and the bounded reader stays the
    // enforcement point either way.
    let read_limit = u64::try_from(RUNTIME_PROFILE_MAX_BYTES)
        .ok()
        .and_then(|bound| bound.checked_add(1))
        .ok_or_else(oversized)?;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(refusal)?;
    if bytes.len() > RUNTIME_PROFILE_MAX_BYTES {
        return Err(oversized().into());
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        RuntimeProfileRejection::Unreadable(format!("{}: not UTF-8", path.display()))
    })?;
    RuntimeProfileDocument::from_toml(&text)
}

/// Compiles the decoded document into the I14.2 initial scheduling profile.
///
/// This is the single validating entry point: it checks the document-level
/// fields, converts each class entry into the existing
/// [`PolicyBoundClassLimits`], and hands them to the existing
/// [`SchedulingProfile::i14_2_initial`], which applies the documented I14.2
/// item-ceiling defaults for the five classes that have one and refuses the
/// four that do not. No default, ceiling or legality rule is computed here.
///
/// # Errors
/// Returns [`CoordinatorError::RuntimeProfileRejected`] for a document-level
/// refusal, and the existing coordinator errors for the profile-level ones:
/// [`CoordinatorError::InvalidField`] for a missing required ceiling,
/// [`CoordinatorError::IdentityConflict`] for a class the document omits,
/// [`CoordinatorError::DuplicateIdentity`] for a repeated class, and any
/// [`CoordinatorError`] from [`SchedulingProfile::validate`].
pub fn compile_runtime_scheduling_profile(
    document: RuntimeProfileDocument,
) -> Result<SchedulingProfile, CoordinatorError> {
    document.validate()?;
    let policy = document
        .classes
        .into_iter()
        .map(|class| PolicyBoundClassLimits {
            work_class: class.work_class,
            max_items: class.max_items,
            max_bytes: class.max_bytes,
            max_concurrency: class.max_concurrency,
            deadline_ms: class.deadline_ms,
            weight: class.weight,
            wip_partitions: class.wip_partitions,
        })
        .collect::<Vec<PolicyBoundClassLimits>>();
    SchedulingProfile::i14_2_initial(document.profile_revision, &policy)
}

/// Loads the Kernel-owned runtime configuration at `path` and compiles the
/// I14.2 initial scheduling profile from it.
///
/// This is the production entry point of the surface: one bounded read of
/// [`RUNTIME_PROFILE_FILE_NAME`]'s document, one typed decode, and one
/// compilation through the existing constructor and validator. It grants no
/// authority, mutates no state, reads no clock and publishes no receipt; the
/// returned profile is the policy input for [`crate::AgentCoordinator`]'s
/// profile-bound `pull_next`.
///
/// # Errors
/// As [`load_runtime_profile_document`] for the read and decode refusals, and
/// as [`compile_runtime_scheduling_profile`] for the compile refusals.
pub fn load_runtime_scheduling_profile(path: &Path) -> Result<SchedulingProfile, CoordinatorError> {
    compile_runtime_scheduling_profile(load_runtime_profile_document(path)?)
}
