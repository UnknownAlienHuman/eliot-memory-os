//! Wasmtime-specific generated bindings for the six frozen typed worlds.
//!
//! Single engine/linker/binding owner for `eliot:current@0.1.0` (issue #758).
//! One typed binding module per #756 world, generated from the single
//! `wit/typed` directory with the pinned Wasmtime component facility.
//! No hand-copied schema, no second neutral-runtime engine, no WASI.

use eliot_wasm_runtime::Sha256Digest;

/// Frozen typed package identity from #756.
pub const TYPED_PACKAGE_ID: &str = "eliot:current@0.1.0";
/// Frozen typed package version.
pub const TYPED_WIT_VERSION: &str = "0.1.0";
/// Legacy world that must never satisfy a typed selection.
pub const LEGACY_WORLD: &str = "eliot:wasm/guest";
/// Legacy export that marks a legacy/component mismatch.
pub const LEGACY_EXPORT: &str = "run";

pub mod context_admission {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "context-admission",
    });
}

pub mod context_assembly {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "context-assembly",
    });
}

pub mod cue_activation {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "cue-activation",
    });
}

pub mod dreamer_handler {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "dreamer-handler",
    });
}

pub mod memory_curation_screen {
    wasmtime::component::bindgen!({
        path: "wit/typed",
        world: "memory-curation-screen",
    });
}

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

/// Returns true when a component export name identifies the expected
/// interface, accepting both bare (`admission`) and fully qualified
/// (`eliot:current@0.1.0/admission`) spellings. Anything else is a
/// missing/wrong export, never an implicit match.
#[must_use]
pub fn export_matches_interface(export_name: &str, interface: &str) -> bool {
    if export_name == interface {
        return true;
    }
    if let Some((_, tail)) = export_name.rsplit_once('/')
        && tail == interface
    {
        return true;
    }
    if let Some((_, tail)) = export_name.rsplit_once(':')
        && tail == interface
    {
        return true;
    }
    false
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
