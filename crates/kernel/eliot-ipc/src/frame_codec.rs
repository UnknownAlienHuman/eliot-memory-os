//! Bounded EBP/1 byte framing for the `eliot_ipc` transport facade.
//!
//! The wire boundary follows Implementation `I7.2`: a four-byte little-endian
//! body length precedes the encoded body; zero and oversized lengths are
//! rejected before body allocation. Inline size tiers enforced here (issue
//! #1881): 4 MiB default frame maximum, 64 KiB hot-response default for the
//! `Cancel` / heartbeat / `Control` recovery lane, and 256 KiB hard ceiling
//! for structured `Response` / `Event` bodies. Payloads above their
//! applicable inline ceiling must use an immutable Blob/Resource handle;
//! oversized inline bodies surface as `OversizeFrame` and are never emitted.
//! Implementation `I7.3` keeps handshake
//! fields and session binding above this byte cell.
//!
//! This private module follows Implementation `I2.23`: a small group used by one
//! parent remains an ordinary Rust module. The control loop and identity/session
//! visibility remain governed by Architecture `A10.1` and `A12.2`; this cell
//! owns no pipe, process, authentication, admission, or lifecycle state.
//!
//! # Buffer/length invariants for the coupled unsafe transport
//!
//! The `windows_transport` wrappers in `super` (`send_wire`, `receive_wire`,
//! `read_exact_reported`) expose raw byte buffers to the OS through a live
//! pipe handle. This codec is the enforceable safe wrapper for the framing
//! slice of that boundary:
//!
//! - OS-visible buffer lifetime: a caller must keep the `wire` buffer alive
//!   until the terminal observation (`Delivered` / `UnknownOutcome` / typed
//!   `TransportError`, including `Timeout` and `Cancelled`). Dropping or
//!   mutating the buffer while the OS may still observe it would widen the
//!   unsafe window owned by the transport wrapper.
//! - Exact transferred range: only the `drain(..total)` bytes for one
//!   `4 + declared` frame are ever exposed for I/O or decoding. Partial
//!   bytes stay buffered; trailing bytes are never silently absorbed.
//! - Oversize-before-alloc: the declared length is rejected before any
//!   body-sized allocation. No attacker-controlled length reaches
//!   `with_capacity` / `resize` / `collect`.
//! - One-over boundaries: `buffered + incoming == total` is the single
//!   complete case; `> total` is `Backpressure`, never truncation.
//! - Distinct terminal observations: empty fragment (`Ok(None)`, no progress)
//!   vs partial (`Ok(None)`, buffered for recovery) vs zero-length
//!   (`ZeroLengthFrame`) vs oversize (`OversizeFrame`) vs trailing
//!   (`Backpressure` here, `TrailingBytes` in `decode_frame`) are never fused.

use super::{
    TransportError, TransportLimits, check_inline_response_ceiling, inline_ceiling_for_kind,
};
use eliot_protocol::{Frame, FrameKind, JsonCodec, ProtocolError};

/// Wire prefix length: four-byte little-endian body length (Implementation `I7.2`).
const FRAME_PREFIX_LEN: usize = 4;

fn oversize_unrepresentable(maximum: usize) -> TransportError {
    // Coupled unsafe use: `usize` cannot represent this `u32` on this target,
    // so no OS-visible range could be constructed; fail closed before any I/O.
    TransportError::Protocol(ProtocolError::OversizeFrame {
        actual: usize::MAX,
        maximum,
    })
}

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
    ///
    /// The caller must keep `fragment` alive for the duration of this call
    /// only; the decoder copies admitted bytes. The returned frame owns its
    /// bytes, so no borrowed range outlives the OS-visible transfer.
    pub fn push(
        &mut self,
        fragment: &[u8],
        limits: TransportLimits,
    ) -> Result<Option<Frame>, TransportError> {
        let limits = limits.validate()?;
        // Empty read fragment is not a frame and not an error: it carries no
        // bytes the OS transferred, so there is no terminal observation and no
        // state change. This stays distinct from a zero-length declared frame.
        if fragment.is_empty() {
            return Ok(None);
        }
        // Inspect the prefix before admitting attacker-controlled bytes. A
        // giant fragment must never be appended merely to discover that it is
        // oversized; otherwise the oversize-before-alloc invariant coupled to
        // the transport's `with_capacity` + `resize` discipline would break.
        let declared = if self.bytes.len() < FRAME_PREFIX_LEN {
            let existing = self.bytes.len();
            let buffered_total = self
                .bytes
                .len()
                .checked_add(fragment.len())
                .ok_or(TransportError::Backpressure)?;
            if buffered_total < FRAME_PREFIX_LEN {
                // Still no complete prefix: buffer the partial prefix for
                // recovery and report no terminal observation.
                self.bytes.extend_from_slice(fragment);
                return Ok(None);
            }
            let needed = FRAME_PREFIX_LEN
                .checked_sub(existing)
                .ok_or_else(|| oversize_unrepresentable(limits.max_frame_bytes))?;
            // `buffered_total >= 4` proves `fragment.len() >= needed`; use a
            // fallible slice so malformed input returns a typed error instead
            // of a panicking index.
            let head = fragment.get(..needed).ok_or(TransportError::Protocol(
                ProtocolError::PartialFrame {
                    expected: FRAME_PREFIX_LEN,
                    actual: buffered_total,
                },
            ))?;
            let mut prefix = [0_u8; FRAME_PREFIX_LEN];
            prefix
                .get_mut(..existing)
                .and_then(|dst| {
                    self.bytes.get(..existing).map(|src| {
                        dst.copy_from_slice(src);
                    })
                })
                .ok_or_else(|| oversize_unrepresentable(limits.max_frame_bytes))?;
            prefix
                .get_mut(existing..)
                .map(|dst| {
                    dst.copy_from_slice(head);
                })
                .ok_or_else(|| oversize_unrepresentable(limits.max_frame_bytes))?;
            usize::try_from(u32::from_le_bytes(prefix))
                .map_err(|_| oversize_unrepresentable(limits.max_frame_bytes))?
        } else {
            // Prefix already buffered; read it without a panicking index so a
            // corrupted internal length cannot become a panic on public input.
            let prefix: [u8; FRAME_PREFIX_LEN] = self
                .bytes
                .get(..FRAME_PREFIX_LEN)
                .and_then(|slice| slice.try_into().ok())
                .ok_or_else(|| oversize_unrepresentable(limits.max_frame_bytes))?;
            usize::try_from(u32::from_le_bytes(prefix))
                .map_err(|_| oversize_unrepresentable(limits.max_frame_bytes))?
        };
        // Zero-length declared body is a distinct terminal observation from
        // oversize and from an empty read fragment. Reject before allocation
        // with its own typed error so the OS never observes a zero-byte body
        // range as if it were a frame.
        if declared == 0 {
            self.bytes.clear();
            return Err(TransportError::Protocol(ProtocolError::ZeroLengthFrame));
        }
        // Oversize-before-alloc: reject `declared > max` before any
        // body-sized allocation. Clears the poisoned prefix so the next read
        // resynchronizes instead of interpreting body bytes as a new prefix.
        // This preserves the `OversizeFrame` vs `Backpressure` distinction.
        if declared > limits.max_frame_bytes {
            self.bytes.clear();
            return Err(TransportError::Protocol(ProtocolError::OversizeFrame {
                actual: declared,
                maximum: limits.max_frame_bytes,
            }));
        }
        // Exact `4 + declared` with overflow check: on targets where `usize`
        // cannot hold `u32::MAX + 4`, fail closed instead of wrapping the
        // OS-visible range.
        let total = FRAME_PREFIX_LEN
            .checked_add(declared)
            .ok_or_else(|| oversize_unrepresentable(limits.max_frame_bytes))?;
        // One-over boundary with overflow-checked accounting: `== total` is
        // the single complete case, `> total` is trailing and therefore
        // `Backpressure` (never silent truncation). No bytes are admitted on
        // this path, so the existing partial stays buffered for bounded retry.
        let incoming_total = self
            .bytes
            .len()
            .checked_add(fragment.len())
            .ok_or(TransportError::Backpressure)?;
        if incoming_total > total {
            return Err(TransportError::Backpressure);
        }
        self.bytes.extend_from_slice(fragment);
        // Prefix completeness is already proven above, so only the
        // partial-vs-complete distinction remains here.
        if self.bytes.len() < total {
            return Ok(None);
        }
        // `incoming_total <= total` plus `len >= total` proves `len == total`,
        // so this drain cannot panic and exposes exactly one frame's
        // OS-visible range. The `wire` buffer stays alive until `decode_frame`
        // returns its terminal observation below.
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
///
/// The returned `wire` buffer must stay alive until the transport wrapper's
/// `write_all` reaches its terminal observation (`Delivered` vs
/// `UnknownOutcome` / `Timeout`); the exact transferred range is the whole
/// buffer.
///
/// Inline ceilings (issue #1881) are enforced before the wire is returned:
/// the control-recovery lane defaults to 64 KiB and structured
/// `Response` / `Event` bodies are hard-capped at 256 KiB, all under the
/// 4 MiB frame default. A body above its applicable ceiling yields
/// `OversizeFrame` and is never emitted inline; the caller must use an
/// immutable Blob/Resource handle instead.
pub fn encode_frame(frame: &Frame, limits: TransportLimits) -> Result<Vec<u8>, TransportError> {
    let limits = limits.validate()?;
    let wire = JsonCodec::with_max_frame_bytes(limits.max_frame_bytes)
        .encode(frame)
        .map_err(TransportError::Protocol)?;
    let body_len = wire.len().saturating_sub(FRAME_PREFIX_LEN);
    check_inline_response_ceiling(frame, body_len, limits.max_frame_bytes)?;
    Ok(wire)
}

/// Decodes one complete frame and rejects trailing or partial bytes.
///
/// `wire` must be exactly one `4 + declared` frame kept alive until this call
/// returns. Short input yields `PartialFrame`, extra bytes yield
/// `TrailingBytes`, zero body yields `ZeroLengthFrame`, and an over-limit body
/// yields `OversizeFrame`; these terminal observations stay distinct and are
/// enforced by the bounded codec without panicking on malformed input.
///
/// The applicable inline ceiling (64 KiB control-recovery default, 256 KiB
/// structured hard ceiling, 4 MiB frame default) is selected from the length
/// prefix plus a kind probe of the staged body, then enforced by the bounded
/// codec itself: an over-tier body is rejected from its declared length
/// before the body is allocated or decoded, with the 4 MiB frame bound as
/// the outer cap. The ceiling is re-checked after decoding as the
/// post-decode invariant, so an oversized inline body is rejected on receipt
/// as well as on emission.
///
/// Wire staging in `FrameDecoder::push` remains bounded by the outer 4 MiB
/// cap (the kind lives inside the body, so no tier can be selected before
/// the frame is staged); decoded-body allocation and parsing are bounded by
/// the tier ceiling selected here.
pub fn decode_frame(wire: &[u8], limits: TransportLimits) -> Result<Frame, TransportError> {
    let limits = limits.validate()?;
    let ceiling = tier_ceiling_for_wire(wire, limits.max_frame_bytes);
    let frame = JsonCodec::with_max_frame_bytes(ceiling)
        .decode(wire)
        .map_err(TransportError::Protocol)?;
    let body_len = wire.len().saturating_sub(FRAME_PREFIX_LEN);
    check_inline_response_ceiling(&frame, body_len, limits.max_frame_bytes)?;
    Ok(frame)
}

/// Minimal kind probe decoded from the staged body before the full frame.
///
/// Reuses the protocol `FrameKind` wire shape, so the tier lookup cannot
/// drift from the negotiated encoding. Unparseable bodies yield `None` and
/// fall back to the outer frame bound with the codec's canonical error
/// disposition.
#[derive(serde::Deserialize)]
struct KindProbe {
    kind: Option<FrameKind>,
}

/// Probes the frame kind carried by one staged body without decoding it.
fn peek_frame_kind(body: &[u8]) -> Option<FrameKind> {
    serde_json::from_slice::<KindProbe>(body).ok()?.kind
}

/// Selects the decode cap for one wire image before the body is decoded.
///
/// When `wire` is exactly one `4 + declared` frame within the outer bound,
/// the applicable inline tier (64 KiB control-recovery, 256 KiB structured,
/// outer bound otherwise) becomes the codec cap, so the codec rejects an
/// over-tier body from its length prefix before allocating or parsing the
/// body. Any other shape (short prefix, zero, outer-oversize, partial,
/// trailing) keeps the outer cap, preserving the codec's canonical
/// `PartialFrame` / `ZeroLengthFrame` / `OversizeFrame` / `TrailingBytes`
/// dispositions unchanged.
fn tier_ceiling_for_wire(wire: &[u8], max_frame_bytes: usize) -> usize {
    let Some(prefix_slice) = wire.get(..FRAME_PREFIX_LEN) else {
        return max_frame_bytes;
    };
    let prefix: [u8; FRAME_PREFIX_LEN] = match prefix_slice.try_into() {
        Ok(prefix) => prefix,
        Err(_) => return max_frame_bytes,
    };
    let declared = u32::from_le_bytes(prefix);
    let Ok(declared) = usize::try_from(declared) else {
        return max_frame_bytes;
    };
    if declared == 0 || declared > max_frame_bytes {
        return max_frame_bytes;
    }
    let Some(total) = FRAME_PREFIX_LEN.checked_add(declared) else {
        return max_frame_bytes;
    };
    if wire.len() != total {
        return max_frame_bytes;
    }
    match peek_frame_kind(&wire[FRAME_PREFIX_LEN..]) {
        Some(kind) => inline_ceiling_for_kind(kind, max_frame_bytes),
        None => max_frame_bytes,
    }
}
