//! Typed input/output and protocol-range declarations for one I6.4 module contract.
//!
//! [`ModuleContract`] carries the module's own protocol names, but I6.4 also
//! obliges every hot module to declare its inputs/outputs and its protocol
//! range. Those two declarations live here, bound to the contract they name,
//! instead of as new fields on [`ModuleContract`]:
//!
//! * an input/output reference is a [`ContractIdentity`] minted by the real
//!   versioned owner contract (for example
//!   [`crate::hot_path_contract_identity`],
//!   [`crate::i14_backpressure_contract_identity`] or
//!   [`crate::contract_identity`]), never an invented name, so a reference
//!   resolves exactly when it equals the identity its owner publishes;
//! * a protocol range declares the admitted `[min_version, max_version]`
//!   interval for one protocol name the contract carries. It is a declaration
//!   only: range negotiation stays owned by the Kernel compatibility handshake
//!   and is not recreated here.
//!
//! Both bindings refuse an invalid contract, bind only the module they name,
//! and manufacture no readiness, health, test success or activation authority.

use eliot_contracts::{ContractId, ContractIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ModuleContract, RuntimeContractError, hot_path::invalid};

/// One admitted protocol interval for a single protocol name.
///
/// The interval is inclusive on both ends. Negotiation of the effective
/// version stays with the Kernel compatibility owner; this declaration only
/// records which interval the module contract admits for the named protocol.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolRangeDeclaration {
    /// Protocol name exactly as carried by the bound [`ModuleContract`].
    pub protocol: String,
    /// Lowest admitted protocol version.
    pub min_version: u32,
    /// Highest admitted protocol version.
    pub max_version: u32,
}

impl ProtocolRangeDeclaration {
    /// Validates the declared protocol name and its version interval.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        if self.protocol.trim().is_empty() {
            return Err(RuntimeContractError::Blank { field: "protocol" });
        }
        if self.protocol.chars().any(char::is_control) {
            return Err(invalid("protocol", "must not contain control characters"));
        }
        if self.min_version > self.max_version {
            return Err(invalid(
                "protocol_range",
                "min_version must not exceed max_version",
            ));
        }
        Ok(())
    }
}

/// The admitted protocol-range set bound to one module contract.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleProtocolRanges {
    /// Module whose contract these ranges declare.
    pub module_id: ContractId,
    /// One interval per protocol the bound contract carries.
    pub ranges: Vec<ProtocolRangeDeclaration>,
}

impl ModuleProtocolRanges {
    /// Validates every declaration and refuses a twice-declared protocol.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        let mut seen: Vec<&str> = Vec::with_capacity(self.ranges.len());
        for range in &self.ranges {
            range.validate()?;
            if seen.contains(&range.protocol.as_str()) {
                return Err(invalid(
                    "protocol_ranges",
                    "must not declare a protocol twice",
                ));
            }
            seen.push(range.protocol.as_str());
        }
        Ok(())
    }

    /// Binds these ranges to the contract they name.
    ///
    /// The contract itself must validate, the ranges must validate, and the
    /// declared set must equal the contract's protocol set in both
    /// directions: a contract protocol without an admitted interval and an
    /// interval for a protocol the contract does not carry are both refused.
    pub fn binds_contract(&self, contract: &ModuleContract) -> Result<(), RuntimeContractError> {
        contract.validate()?;
        self.validate()?;
        if self.module_id != contract.module_id {
            return Err(invalid(
                "module_id",
                "protocol ranges bind only the module they name",
            ));
        }
        for protocol in &contract.protocols {
            if !self.ranges.iter().any(|range| &range.protocol == protocol) {
                return Err(invalid(
                    "protocol_ranges",
                    "contract protocol has no admitted range declaration",
                ));
            }
        }
        for range in &self.ranges {
            if !contract.protocols.contains(&range.protocol) {
                return Err(invalid(
                    "protocol_ranges",
                    "range declaration names no contract protocol",
                ));
            }
        }
        Ok(())
    }
}

/// Typed input/output contract references bound to one module contract.
///
/// Each entry is the [`ContractIdentity`] published by the real versioned
/// owner of that input or output. An empty list is an explicit declaration
/// that the module takes no typed input (or produces no typed output); it is
/// never a default filled in by the loader.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleIoBinding {
    /// Module whose contract these references declare.
    pub module_id: ContractId,
    /// Versioned owner contracts this module consumes.
    pub inputs: Vec<ContractIdentity>,
    /// Versioned owner contracts this module produces.
    pub outputs: Vec<ContractIdentity>,
}

/// Validates one reference list: every identity must carry a well-formed
/// shape digest, and one contract must not be referenced twice in the list.
fn identities(
    values: &[ContractIdentity],
    field: &'static str,
) -> Result<(), RuntimeContractError> {
    for identity in values {
        identity.validate()?;
    }
    for (index, identity) in values.iter().enumerate() {
        if values[..index].contains(identity) {
            return Err(invalid(field, "must not reference one contract twice"));
        }
    }
    Ok(())
}

impl ModuleIoBinding {
    /// Validates every referenced owner identity and refuses duplicates.
    pub fn validate(&self) -> Result<(), RuntimeContractError> {
        identities(&self.inputs, "inputs")?;
        identities(&self.outputs, "outputs")?;
        Ok(())
    }

    /// Binds these references to the contract they name.
    ///
    /// The contract itself must validate and the module identities must be
    /// equal. Resolution of each reference against the identity its owner
    /// publishes stays with the admitting consumer; this binding only
    /// guarantees the references are well-formed, duplicate-free and owned
    /// by the named module.
    pub fn binds_contract(&self, contract: &ModuleContract) -> Result<(), RuntimeContractError> {
        contract.validate()?;
        self.validate()?;
        if self.module_id != contract.module_id {
            return Err(invalid(
                "module_id",
                "input/output references bind only the module they name",
            ));
        }
        Ok(())
    }
}
