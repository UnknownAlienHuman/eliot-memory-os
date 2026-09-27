//! Single typed owner-neutral bridge recovery continuation selector (issue #2798).
//!
//! This is the sole mechanical contract for the `recovery_scope` leg that
//! crosses Bridge, Kernel, and ORS. The Bridge encodes it, the Kernel
//! validates it mechanically without interpreting window meaning, and ORS
//! owns window/page meaning on the parsed value. No other selector shape
//! exists: absence of a selector opens a window, and every tagged selector
//! names an already-open window.
//!
//! There is deliberately no `open` kind. An explicit open tag would be a
//! second contract for "no selector"; initial reads omit the leg instead,
//! and every owner on the path treats a missing or null leg as the open
//! request.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{ContractError, validate_text};

/// Wire version of the recovery selector contract.
pub const BRIDGE_RECOVERY_SELECTOR_VERSION: u64 = 1;
/// Maximum streams named by one outer stream-list page.
pub const BRIDGE_RECOVERY_MAX_STREAMS_PER_PAGE: u64 = 4;
/// Maximum events carried by one stream page.
pub const BRIDGE_RECOVERY_MAX_EVENTS_PER_PAGE: u64 = 128;
/// Maximum gaps carried by one gap page.
pub const BRIDGE_RECOVERY_MAX_GAPS_PER_PAGE: u64 = 256;
/// Maximum UTF-8 bytes of one selector text leg.
pub const BRIDGE_RECOVERY_MAX_SELECTOR_TEXT_BYTES: usize = 1024;

/// One closed, versioned recovery continuation selector.
///
/// The selector is a pure read cursor: it never acknowledges a consumed
/// frontier and never mutates owner state. `window_key` binds the finite
/// owner-issued window; every other leg binds one bounded dimension of the
/// walk inside that window.
#[derive(Clone, Debug, Eq, PartialEq, JsonSchema, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BridgeRecoverySelector {
    /// One outer stream-enumeration page. `after_stream` is the decimal
    /// owner-list cursor the page must advance past.
    Streams {
        version: u64,
        window_key: String,
        after_stream: String,
        stream_limit: u64,
    },
    /// One event/gap page within a single stream. `after_sequence` is the
    /// exclusive predecessor already returned; the cut legs must match the
    /// retained owner cut exactly.
    Stream {
        version: u64,
        window_key: String,
        stream_id: String,
        after_sequence: u64,
        upper_sequence: u64,
        expected_revision: u64,
        retention_floor: u64,
        event_limit: u64,
        gap_offset: u64,
        gap_limit: u64,
    },
    /// One unscoped-gap page. `after_gap_scope` names the gap-owner digest
    /// the page resumes from, with `gap_offset` inside that owner.
    UnscopedGaps {
        version: u64,
        window_key: String,
        after_gap_scope: String,
        gap_offset: u64,
        gap_limit: u64,
    },
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ContractError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_selector_text(value: &str, field: &'static str) -> Result<(), ContractError> {
    validate_text(value, field)?;
    if value.len() > BRIDGE_RECOVERY_MAX_SELECTOR_TEXT_BYTES {
        return Err(ContractError::TooLong {
            field,
            maximum_bytes: BRIDGE_RECOVERY_MAX_SELECTOR_TEXT_BYTES,
        });
    }
    Ok(())
}

fn validate_gap_budget(gap_offset: u64, gap_limit: u64) -> Result<(), ContractError> {
    if gap_limit == 0 || gap_limit > BRIDGE_RECOVERY_MAX_GAPS_PER_PAGE {
        return Err(ContractError::InvalidSelector {
            field: "gap_limit",
            reason: "gap budget must stay within the owner gap cap",
        });
    }
    if gap_offset.checked_add(gap_limit).is_none() {
        return Err(ContractError::InvalidSelector {
            field: "gap_offset",
            reason: "gap continuation offset and budget must not overflow",
        });
    }
    Ok(())
}

impl BridgeRecoverySelector {
    /// Parses one closed mechanical selector. Unknown kinds, unknown fields,
    /// wrong JSON types, and bound violations all fail; window meaning is
    /// left to the owning store.
    pub fn parse(value: &Value) -> Result<Self, ContractError> {
        let selector: Self =
            serde_json::from_value(value.clone()).map_err(|_| ContractError::InvalidSelector {
                field: "recovery_selector",
                reason: "recovery selector must be a closed version-1 streams, stream, or unscoped_gaps object",
            })?;
        selector.validate()?;
        Ok(selector)
    }

    /// Builds one outer stream-list continuation selector.
    pub fn streams(
        window_key: String,
        after_stream: String,
        stream_limit: u64,
    ) -> Result<Self, ContractError> {
        let selector = Self::Streams {
            version: BRIDGE_RECOVERY_SELECTOR_VERSION,
            window_key,
            after_stream,
            stream_limit,
        };
        selector.validate()?;
        Ok(selector)
    }

    /// Builds one stream event/gap continuation selector.
    #[allow(
        clippy::too_many_arguments,
        reason = "the stream selector carries the full retained cut plus both page budgets"
    )]
    pub fn stream(
        window_key: String,
        stream_id: String,
        after_sequence: u64,
        upper_sequence: u64,
        expected_revision: u64,
        retention_floor: u64,
        event_limit: u64,
        gap_offset: u64,
        gap_limit: u64,
    ) -> Result<Self, ContractError> {
        let selector = Self::Stream {
            version: BRIDGE_RECOVERY_SELECTOR_VERSION,
            window_key,
            stream_id,
            after_sequence,
            upper_sequence,
            expected_revision,
            retention_floor,
            event_limit,
            gap_offset,
            gap_limit,
        };
        selector.validate()?;
        Ok(selector)
    }

    /// Builds one unscoped-gap continuation selector.
    pub fn unscoped_gaps(
        window_key: String,
        after_gap_scope: String,
        gap_offset: u64,
        gap_limit: u64,
    ) -> Result<Self, ContractError> {
        let selector = Self::UnscopedGaps {
            version: BRIDGE_RECOVERY_SELECTOR_VERSION,
            window_key,
            after_gap_scope,
            gap_offset,
            gap_limit,
        };
        selector.validate()?;
        Ok(selector)
    }

    /// Encodes the exact wire object every owner parses with [`Self::parse`].
    #[must_use]
    pub fn to_value(&self) -> Value {
        match self {
            Self::Streams {
                version,
                window_key,
                after_stream,
                stream_limit,
            } => json!({
                "version": version, "kind": "streams", "window_key": window_key,
                "after_stream": after_stream, "stream_limit": stream_limit,
            }),
            Self::Stream {
                version,
                window_key,
                stream_id,
                after_sequence,
                upper_sequence,
                expected_revision,
                retention_floor,
                event_limit,
                gap_offset,
                gap_limit,
            } => json!({
                "version": version, "kind": "stream", "window_key": window_key,
                "stream_id": stream_id, "after_sequence": after_sequence,
                "upper_sequence": upper_sequence, "expected_revision": expected_revision,
                "retention_floor": retention_floor, "event_limit": event_limit,
                "gap_offset": gap_offset, "gap_limit": gap_limit,
            }),
            Self::UnscopedGaps {
                version,
                window_key,
                after_gap_scope,
                gap_offset,
                gap_limit,
            } => json!({
                "version": version, "kind": "unscoped_gaps", "window_key": window_key,
                "after_gap_scope": after_gap_scope, "gap_offset": gap_offset, "gap_limit": gap_limit,
            }),
        }
    }

    /// Validates the closed mechanical shape and bounds. Owner meaning
    /// (window retention, cut binding, revision movement) is out of scope.
    pub fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Streams {
                version,
                window_key,
                after_stream,
                stream_limit,
            } => {
                if *version != BRIDGE_RECOVERY_SELECTOR_VERSION {
                    return Err(ContractError::InvalidSelector {
                        field: "version",
                        reason: "recovery selector version 1 is required",
                    });
                }
                validate_digest(window_key, "window_key")?;
                validate_selector_text(after_stream, "after_stream")?;
                if after_stream.parse::<u64>().is_err() {
                    return Err(ContractError::InvalidSelector {
                        field: "after_stream",
                        reason: "stream-list continuation must be a decimal owner cursor",
                    });
                }
                if *stream_limit == 0 || *stream_limit > BRIDGE_RECOVERY_MAX_STREAMS_PER_PAGE {
                    return Err(ContractError::InvalidSelector {
                        field: "stream_limit",
                        reason: "stream-list page must use the admitted bound",
                    });
                }
            }
            Self::Stream {
                version,
                window_key,
                stream_id,
                after_sequence,
                upper_sequence,
                expected_revision,
                retention_floor,
                event_limit,
                gap_offset,
                gap_limit,
            } => {
                if *version != BRIDGE_RECOVERY_SELECTOR_VERSION {
                    return Err(ContractError::InvalidSelector {
                        field: "version",
                        reason: "recovery selector version 1 is required",
                    });
                }
                validate_digest(window_key, "window_key")?;
                validate_selector_text(stream_id, "stream_id")?;
                if stream_id.contains("::") {
                    return Err(ContractError::InvalidSelector {
                        field: "stream_id",
                        reason: "stream identity must not contain the key separator",
                    });
                }
                if *expected_revision == 0 {
                    return Err(ContractError::Zero {
                        field: "expected_revision",
                    });
                }
                if after_sequence > upper_sequence || retention_floor > upper_sequence {
                    return Err(ContractError::InvalidInterval {
                        field: "after_sequence",
                    });
                }
                if *event_limit == 0 || *event_limit > BRIDGE_RECOVERY_MAX_EVENTS_PER_PAGE {
                    return Err(ContractError::InvalidSelector {
                        field: "event_limit",
                        reason: "event budget must stay within the owner page cap",
                    });
                }
                validate_gap_budget(*gap_offset, *gap_limit)?;
            }
            Self::UnscopedGaps {
                version,
                window_key,
                after_gap_scope,
                gap_offset,
                gap_limit,
            } => {
                if *version != BRIDGE_RECOVERY_SELECTOR_VERSION {
                    return Err(ContractError::InvalidSelector {
                        field: "version",
                        reason: "recovery selector version 1 is required",
                    });
                }
                validate_digest(window_key, "window_key")?;
                validate_digest(after_gap_scope, "after_gap_scope")?;
                validate_gap_budget(*gap_offset, *gap_limit)?;
            }
        }
        Ok(())
    }

    /// Returns the bound window identity.
    #[must_use]
    pub fn window_key(&self) -> &str {
        match self {
            Self::Streams { window_key, .. }
            | Self::Stream { window_key, .. }
            | Self::UnscopedGaps { window_key, .. } => window_key,
        }
    }

    /// Returns the stream page legs, if this is a stream selector.
    #[must_use]
    #[allow(
        clippy::type_complexity,
        reason = "the stream selector legs travel as one exact tuple"
    )]
    pub fn stream_page(&self) -> Option<(&str, u64, u64, u64, u64, u64, u64, u64)> {
        match self {
            Self::Stream {
                stream_id,
                after_sequence,
                upper_sequence,
                expected_revision,
                retention_floor,
                event_limit,
                gap_offset,
                gap_limit,
                ..
            } => Some((
                stream_id,
                *after_sequence,
                *upper_sequence,
                *expected_revision,
                *retention_floor,
                *event_limit,
                *gap_offset,
                *gap_limit,
            )),
            _ => None,
        }
    }

    /// Returns the decimal stream-list cursor and page budget, if this is a
    /// stream-list selector.
    #[must_use]
    pub fn stream_list(&self) -> Option<(u64, u64)> {
        match self {
            Self::Streams {
                after_stream,
                stream_limit,
                ..
            } => after_stream
                .parse::<u64>()
                .ok()
                .map(|after| (after, *stream_limit)),
            _ => None,
        }
    }

    /// Returns the unscoped-gap legs, if this is an unscoped-gap selector.
    #[must_use]
    pub fn unscoped_gap_page(&self) -> Option<(&str, u64, u64)> {
        match self {
            Self::UnscopedGaps {
                after_gap_scope,
                gap_offset,
                gap_limit,
                ..
            } => Some((after_gap_scope, *gap_offset, *gap_limit)),
            _ => None,
        }
    }
}
