//! Wasmtime-specific generated bindings for the six frozen typed worlds.
//!
//! Single engine/linker/binding owner for `eliot:current@0.1.0` (issue #758).
//! One typed binding module per #756 world, generated from the single
//! `wit/typed` directory with the pinned Wasmtime component facility.
//! No hand-copied schema, no second neutral-runtime engine, no WASI.
//!
//! Determinism contract (P4.4): each module below is exactly one
//! `wasmtime::component::bindgen!` expansion over the single `wit/typed`
//! directory with the workspace-pinned `wasmtime` facility. No expanded
//! output is checked in: the checked-in bytes are the generation inputs
//! (the six `world` selections) plus the hand-maintained identity tables
//! (`TYPED_PACKAGE_ID`, `TYPED_WIT_VERSION`, the `TypedWorld` name maps,
//! `export_matches_interface`, `typed_wit_digest`). Rebuilding against the
//! locked workspace regenerates byte-identical bindings from the same WIT
//! bytes; a WIT change regenerates all six modules on the next build, and
//! no manual edit to expanded code is possible. Reviewers re-derive this by
//! comparing each module's `world` against the `world` declarations in
//! `wit/typed` and `typed_wit_digest` against the checked-in WIT bytes.

use eliot_wasm_runtime::Sha256Digest;

/// Frozen typed package identity from #756.
pub const TYPED_PACKAGE_ID: &str = "eliot:current@0.1.0";
/// Frozen typed package version.
pub const TYPED_WIT_VERSION: &str = "0.1.0";
/// Legacy world that must never satisfy a typed selection.
pub const LEGACY_WORLD: &str = "eliot:wasm/guest";
/// Legacy export that marks a legacy/component mismatch.
pub const LEGACY_EXPORT: &str = "run";

/// Generated engine bindings for the `context-admission` world (`wit/typed`).
pub mod context_admission {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "context-admission",
    });
}

/// Generated engine bindings for the `context-assembly` world (`wit/typed`).
pub mod context_assembly {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "context-assembly",
    });
}

/// Generated engine bindings for the `cue-activation` world (`wit/typed`).
pub mod cue_activation {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "cue-activation",
    });
}

/// Generated engine bindings for the `dreamer-handler` world (`wit/typed`).
pub mod dreamer_handler {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "dreamer-handler",
    });
}

/// Generated engine bindings for the `memory-curation-screen` world (`wit/typed`).
pub mod memory_curation_screen {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "memory-curation-screen",
    });
}

/// Generated engine bindings for the `dreamer-cycle` world (`wit/typed`).
pub mod dreamer_cycle {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "dreamer-cycle",
    });
}

/// The six frozen typed worlds.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TypedWorld {
    /// `context-admission` world exporting the `admission` interface.
    ContextAdmission,
    /// `context-assembly` world exporting the `assembly` interface.
    ContextAssembly,
    /// `cue-activation` world exporting the `activation` interface.
    CueActivation,
    /// `dreamer-handler` world exporting the `handler` interface.
    DreamerHandler,
    /// `memory-curation-screen` world exporting the `screen` interface.
    MemoryCurationScreen,
    /// `dreamer-cycle` world exporting the `cycle` interface.
    DreamerCycle,
}

impl TypedWorld {
    /// All six worlds in contract order.
    #[must_use]
    pub const fn all() -> [Self; 6] {
        [
            Self::ContextAdmission,
            Self::ContextAssembly,
            Self::CueActivation,
            Self::DreamerHandler,
            Self::MemoryCurationScreen,
            Self::DreamerCycle,
        ]
    }

    /// Canonical world name as declared in WIT.
    #[must_use]
    pub const fn world_name(self) -> &'static str {
        match self {
            Self::ContextAdmission => "context-admission",
            Self::ContextAssembly => "context-assembly",
            Self::CueActivation => "cue-activation",
            Self::DreamerHandler => "dreamer-handler",
            Self::MemoryCurationScreen => "memory-curation-screen",
            Self::DreamerCycle => "dreamer-cycle",
        }
    }

    /// Exported interface name for this world.
    #[must_use]
    pub const fn interface_name(self) -> &'static str {
        match self {
            Self::ContextAdmission => "admission",
            Self::ContextAssembly => "assembly",
            Self::CueActivation => "activation",
            Self::DreamerHandler => "handler",
            Self::MemoryCurationScreen => "screen",
            Self::DreamerCycle => "cycle",
        }
    }

    /// Domain operation name for this world's interface.
    #[must_use]
    pub const fn domain_func(self) -> &'static str {
        match self {
            Self::ContextAdmission => "admit",
            Self::ContextAssembly => "assemble",
            Self::CueActivation => "activate",
            Self::DreamerHandler => "handle",
            Self::MemoryCurationScreen => "screen",
            Self::DreamerCycle => "step",
        }
    }

    /// Descriptor probe present on every typed interface.
    #[must_use]
    pub const fn describe_func(self) -> &'static str {
        "describe"
    }

    /// Parses an explicit world selection. Unknown spellings are denied,
    /// never auto-probed or promoted from legacy.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "context-admission" => Some(Self::ContextAdmission),
            "context-assembly" => Some(Self::ContextAssembly),
            "cue-activation" => Some(Self::CueActivation),
            "dreamer-handler" => Some(Self::DreamerHandler),
            "memory-curation-screen" => Some(Self::MemoryCurationScreen),
            "dreamer-cycle" => Some(Self::DreamerCycle),
            _ => None,
        }
    }
}

impl std::fmt::Display for TypedWorld {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.world_name())
    }
}

/// Matches a registered interface only when the export also names the exact
/// frozen package version. A bare interface or a foreign package cannot prove
/// that identity before instantiation.
#[must_use]
pub fn export_matches_interface(export_name: &str, interface: &str) -> bool {
    TypedWorld::all()
        .iter()
        .any(|world| world.interface_name() == interface)
        && (export_name == format!("{TYPED_PACKAGE_ID}/{interface}")
            || export_name == format!("eliot:current/{interface}@{TYPED_WIT_VERSION}"))
}

/// Stable digest of the exact frozen WIT bytes (all seven files, sorted
/// concatenation). Used as the ABI identity in receipts; the digest value
/// itself is excluded from the hashed payload by construction.
#[must_use]
pub fn typed_wit_digest() -> Sha256Digest {
    // Sorted file order for a deterministic identity.
    let parts: [&[u8]; 7] = [
        include_bytes!("../wit/typed/context-admission.wit"),
        include_bytes!("../wit/typed/context-assembly.wit"),
        include_bytes!("../wit/typed/cue-activation.wit"),
        include_bytes!("../wit/typed/descriptor.wit"),
        include_bytes!("../wit/typed/dreamer-cycle.wit"),
        include_bytes!("../wit/typed/dreamer-handler.wit"),
        include_bytes!("../wit/typed/memory-curation-screen.wit"),
    ];
    let mut combined = Vec::new();
    for part in parts {
        combined.extend_from_slice(part);
        combined.push(b'\n');
    }
    Sha256Digest::of_bytes(&combined)
}
