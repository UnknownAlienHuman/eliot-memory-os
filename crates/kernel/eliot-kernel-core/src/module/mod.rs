//! The Kernel decision-core modules, organized by causal subproperty.
//!
//! Each submodule maps to one P-07 slice and owns one causal responsibility:
//!
//! - [`epoch_and_fence`] — authority epoch activation and exact route fencing;
//! - [`generation_routing`] — runtime generation routes and cutover decisions;
//! - [`control_reserve_front_door`] — the bounded control reserve and the
//!   synchronous front-door admission core;
//! - [`control_reserve_profile_compiler`] — the I14.3 multidimensional
//!   capacity-profile compiler joining owner-produced evidence into one
//!   canonical row per frozen bottleneck, kept separate from the front-door
//!   slice because it describes no front-door capacity of its own;
//! - [`control_reserve_process_owner`] — the I14.3 Host/Kernel process-tree
//!   owner adapter issuing genuinely owner-accounted process
//!   launch/termination permits against its own held partitions, kept
//!   separate from the front-door slice because it enforces other frozen
//!   dimensions;
//! - [`control_reserve_ors_evidence`] — the I14.3 Kernel composition join
//!   validating the ORS owner's two published rows into compiler-ready
//!   evidence records, kept separate from the compiler because it copies
//!   owner quantities rather than compiling the profile;
//! - [`recovery_state_view`] — the role-filtered, non-semantic recovery view;
//! - [`notification_state`] — canonical persistent notification records;
//! - [`compatibility_handshake`] — the versioned I1.12 process-handshake
//!   compatibility envelope and rollback admission;
//! - [`process_health`] — the I1.10 seven-dimension process-health projection,
//!   kept separate from the module-generation and cutover machines.
//! - [`runtime_health`] — the authenticated compatibility and health carrier
//!   consumed by Host and native-worker;
//! - [`generation_readiness`] — the generation-readiness gate consuming the
//!   completed I6.4 module contract and its resolved required-capability graph;
//! - [`module_lifecycle_order`] — the provider-first startup and
//!   reverse-required drain order over that resolved graph.

pub mod compatibility_handshake;
pub mod control_reserve_front_door;
pub mod control_reserve_ors_evidence;
pub mod control_reserve_process_owner;
pub mod control_reserve_profile_compiler;
pub mod epoch_and_fence;
pub mod generation_readiness;
pub mod generation_routing;
pub mod module_lifecycle_order;
pub mod notification_state;
pub mod process_health;
pub mod recovery_state_view;
pub mod runtime_health;
