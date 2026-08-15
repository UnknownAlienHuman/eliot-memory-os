//! The Kernel decision-core modules, organized by causal subproperty.
//!
//! Each submodule maps to one P-07 slice and owns one causal responsibility:
//!
//! - [`epoch_and_fence`] — authority epoch activation and exact route fencing;
//! - [`generation_routing`] — runtime generation routes and cutover decisions;
//! - [`control_reserve_front_door`] — the bounded control reserve and the
//!   synchronous front-door admission core;
//! - [`recovery_state_view`] — the role-filtered, non-semantic recovery view.

pub mod control_reserve_front_door;
pub mod epoch_and_fence;
pub mod generation_routing;
pub mod recovery_state_view;
