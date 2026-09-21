//! Popup delivery selection with quiet-hours scoping (issue #1780).
//!
//! This composition helper decides only whether a popup/toast is emitted.
//! Canonical creation and `ControlBoard` visibility are never suppressed:
//! [`DeliveryDecision::create_canonical`] and
//! [`DeliveryDecision::board_visible`] are always true. Quiet hours suppress
//! only non-critical popups; critical records always pop up unless they are
//! acknowledged or resolved. Acknowledgement stops toast repeats while the
//! record stays unresolved at the Kernel owner.

/// Severity used for popup selection. It mirrors the Kernel-owned
/// canonical severity without taking ownership of notification state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PopupSeverity {
    Information,
    Warning,
    Critical,
}

/// Half-open quiet-hours window expressed in whole hours (`0..24`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuietHours {
    start_hour: u8,
    end_hour: u8,
}

impl QuietHours {
    /// Creates a quiet-hours window. Hours are clock hours in `0..24`;
    /// the window wraps past midnight when `end_hour <= start_hour`.
    #[must_use]
    pub const fn new(start_hour: u8, end_hour: u8) -> Option<Self> {
        if start_hour >= 24 || end_hour >= 24 || start_hour == end_hour {
            return None;
        }
        Some(Self {
            start_hour,
            end_hour,
        })
    }

    /// Returns true when `hour` falls inside the quiet window.
    #[must_use]
    pub const fn contains(self, hour: u8) -> bool {
        if hour >= 24 {
            return false;
        }
        if self.start_hour < self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Popup selection outcome. Canonical creation and board visibility are
/// unconditional by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryDecision {
    pub create_canonical: bool,
    pub board_visible: bool,
    pub popup: bool,
}

/// Selects delivery for one notification attempt.
///
/// - `acknowledged` stops toast repeats but leaves the record unresolved;
/// - `resolved` stops all popups;
/// - `quiet_hours_active` suppresses only non-critical popups.
#[must_use]
pub fn select_delivery(
    severity: PopupSeverity,
    acknowledged: bool,
    resolved: bool,
    quiet_hours_active: bool,
) -> DeliveryDecision {
    let popup =
        !resolved && !acknowledged && (!quiet_hours_active || severity == PopupSeverity::Critical);
    DeliveryDecision {
        create_canonical: true,
        board_visible: true,
        popup,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_hours_suppress_only_noncritical_popups() {
        let Some(window) = QuietHours::new(22, 7) else {
            panic!("valid window");
        };
        assert!(window.contains(23));
        assert!(window.contains(3));
        assert!(!window.contains(12));

        let info_quiet = select_delivery(PopupSeverity::Information, false, false, true);
        assert!(info_quiet.create_canonical);
        assert!(info_quiet.board_visible);
        assert!(!info_quiet.popup);

        let warning_quiet = select_delivery(PopupSeverity::Warning, false, false, true);
        assert!(!warning_quiet.popup);
        assert!(warning_quiet.create_canonical);
        assert!(warning_quiet.board_visible);

        let critical_quiet = select_delivery(PopupSeverity::Critical, false, false, true);
        assert!(critical_quiet.popup);
        assert!(critical_quiet.create_canonical);
        assert!(critical_quiet.board_visible);

        let info_loud = select_delivery(PopupSeverity::Information, false, false, false);
        assert!(info_loud.popup);
    }

    #[test]
    fn ack_stops_repeats_and_resolution_stops_all_popups() {
        assert!(!select_delivery(PopupSeverity::Critical, true, false, false).popup);
        assert!(!select_delivery(PopupSeverity::Critical, false, true, false).popup);
        assert!(!select_delivery(PopupSeverity::Information, true, false, false).popup);
    }

    #[test]
    fn invalid_windows_are_rejected() {
        assert!(QuietHours::new(24, 7).is_none());
        assert!(QuietHours::new(22, 22).is_none());
    }
}
