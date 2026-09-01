//! Bounded EBP/1 byte framing for the `eliot_ipc` transport facade.
//!
//! The wire boundary follows Implementation `I7.2`: a four-byte little-endian
//! body length precedes the encoded body; zero and oversized lengths are
//! rejected before body allocation. Implementation `I7.3` keeps handshake
//! fields and session binding above this byte cell.
//!
//! This private module follows Implementation `I2.23`: a small group used by one
//! parent remains an ordinary Rust module. The control loop and identity/session
//! visibility remain governed by Architecture `A10.1` and `A12.2`; this cell
//! owns no pipe, process, authentication, admission, or lifecycle state.

use super::{TransportError, TransportLimits};
use eliot_protocol::{Frame, JsonCodec, ProtocolError};

/// Incremental decoder that preserves bytes after a partial read for recovery.
#[derive(Debug)]
pub struct FrameDecoder {
    pub(super) bytes: Vec<u8>,
}

impl FrameDecoder {
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Adds a read fragment and returns at most one complete frame.
    pub fn push(
        &mut self,
        fragment: &[u8],
        limits: TransportLimits,
    ) -> Result<Option<Frame>, TransportError> {
        let limits = limits.validate()?;
        if fragment.is_empty() {
            return Ok(None);
        }
        // Inspect the prefix before admitting attacker-controlled bytes.  A
        // giant fragment must never be appended merely to discover that it is
        // oversized.
        let declared = if self.bytes.len() < 4 {
            if self.bytes.len() + fragment.len() < 4 {
                self.bytes.extend_from_slice(fragment);
                return Ok(None);
            }
            let mut prefix = [0_u8; 4];
            let existing = self.bytes.len();
            prefix[..existing].copy_from_slice(&self.bytes);
            prefix[existing..].copy_from_slice(&fragment[..4 - existing]);
            usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| {
                TransportError::Protocol(ProtocolError::OversizeFrame {
                    actual: usize::MAX,
                    maximum: limits.max_frame_bytes,
                })
            })?
        } else {
            usize::try_from(u32::from_le_bytes([
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
            ]))
            .map_err(|_| {
                TransportError::Protocol(ProtocolError::OversizeFrame {
                    actual: usize::MAX,
                    maximum: limits.max_frame_bytes,
                })
            })?
        };
        if declared == 0 || declared > limits.max_frame_bytes {
            self.bytes.clear();
            return Err(TransportError::Protocol(ProtocolError::OversizeFrame {
                actual: declared,
                maximum: limits.max_frame_bytes,
            }));
        }
        let total = 4 + declared;
        if self.bytes.len() + fragment.len() > total {
            return Err(TransportError::Backpressure);
        }
        self.bytes.extend_from_slice(fragment);
        if self.bytes.len() < 4 {
            return Ok(None);
        }
        if self.bytes.len() < total {
            return Ok(None);
        }
        let wire: Vec<u8> = self.bytes.drain(..total).collect();
        decode_frame(&wire, limits).map(Some)
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encodes one validated semantic frame using the negotiated bounded profile.
pub fn encode_frame(frame: &Frame, limits: TransportLimits) -> Result<Vec<u8>, TransportError> {
    let limits = limits.validate()?;
    JsonCodec::with_max_frame_bytes(limits.max_frame_bytes)
        .encode(frame)
        .map_err(TransportError::Protocol)
}

/// Decodes one complete frame and rejects trailing or partial bytes.
pub fn decode_frame(wire: &[u8], limits: TransportLimits) -> Result<Frame, TransportError> {
    let limits = limits.validate()?;
    JsonCodec::with_max_frame_bytes(limits.max_frame_bytes)
        .decode(wire)
        .map_err(TransportError::Protocol)
}
