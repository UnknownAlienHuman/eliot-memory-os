//! The Kernel decision-core modules, organized by causal subproperty.
//!
//! Each submodule maps to one P-07 slice and owns one causal responsibility:
//!
//! - [`epoch_and_fence`] — authority epoch activation and exact route fencing;
//! - [`generation_routing`] — runtime generation routes and cutover decisions;
//! - [`control_reserve_front_door`] — the bounded control reserve and the
//!   synchronous front-door admission core;
//! - [`recovery_state_view`] — the role-filtered, non-semantic recovery view;
//! - [`work_class_admission`] — the I14.1 work-class admission scheduler with
//!   one bounded pool per class, the reserved control partition, the documented
//!   shedding order and the admitted work record carrying retry budget and
//!   cancellation state;
//! - [`notification_state`] — canonical persistent notification records;
//! - [`compatibility_handshake`] — the versioned I1.12 process-handshake
//!   compatibility envelope and rollback admission;
//! - [`process_health`] — the I1.10 seven-dimension process-health projection,
//!   kept separate from the module-generation and cutover machines.
//! - [`runtime_health`] — the authenticated compatibility and health carrier
//!   consumed by Host and native-worker.

pub mod compatibility_handshake;
pub mod control_reserve_front_door;
pub mod epoch_and_fence;
pub mod generation_routing;
pub mod notification_state;
pub mod process_health;
pub mod recovery_state_view;
pub mod runtime_health;
pub mod work_class_admission;
