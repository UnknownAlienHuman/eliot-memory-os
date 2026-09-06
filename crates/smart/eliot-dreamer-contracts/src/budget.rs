//! Provider-neutral independent budget dimensions and limits.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the closed budget schema, class ceilings, and the no-cross-subsidy
//! check. Owns no enforcement, metering, runtime, or approval behavior: each
//! dimension is checked independently and under-use in one dimension can
//! never cover over-use in another.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;

/// Class ceiling for `input_bytes`.
pub const INPUT_BYTES_CEILING: u64 = 1_048_576;
/// Class ceiling for `output_bytes`.
pub const OUTPUT_BYTES_CEILING: u64 = 1_048_576;
/// Class ceiling for `source_width`.
pub const SOURCE_WIDTH_CEILING: u64 = 512;
/// Class ceiling for `reference_width`.
pub const REFERENCE_WIDTH_CEILING: u64 = 512;
/// Class ceiling for `model_calls`.
pub const MODEL_CALLS_CEILING: u64 = 64;
/// Class ceiling for `attempts`.
pub const ATTEMPTS_CEILING: u64 = 16;
/// Class ceiling for `candidates`.
pub const CANDIDATES_CEILING: u64 = 16;
/// Class ceiling for `wall_ms`.
pub const WALL_MS_CEILING: u64 = 600_000;
/// Class ceiling for `work_fan_out`.
pub const WORK_FAN_OUT_CEILING: u64 = 32;
/// Class ceiling for `report_bytes`.
pub const REPORT_BYTES_CEILING: u64 = 1_048_576;
/// Class ceiling for `max_stu`.
pub const STU_CEILING: u64 = 10_000;

/// Closed set of independent budget dimensions. No open `Other` variant:
/// unknown spellings are rejected so usage can never be booked against an
/// unnamed dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum BudgetDimension {
    /// Admitted input bytes.
    #[serde(rename = "input_bytes")]
    InputBytes,
    /// Admitted output bytes.
    #[serde(rename = "output_bytes")]
    OutputBytes,
    /// Admitted source width (distinct sources consulted).
    #[serde(rename = "source_width")]
    SourceWidth,
    /// Admitted reference width (distinct references consulted).
    #[serde(rename = "reference_width")]
    ReferenceWidth,
    /// Admitted provider model calls.
    #[serde(rename = "model_calls")]
    ModelCalls,
    /// Admitted attempts.
    #[serde(rename = "attempts")]
    Attempts,
    /// Admitted candidates.
    #[serde(rename = "candidates")]
    Candidates,
    /// Admitted wall-clock milliseconds.
    #[serde(rename = "wall_ms")]
    WallMs,
    /// Admitted work fan-out (parallel work items).
    #[serde(rename = "work_fan_out")]
    WorkFanOut,
    /// Admitted report bytes.
    #[serde(rename = "report_bytes")]
    ReportBytes,
}

impl BudgetDimension {
    /// Returns the exact wire spelling of this dimension.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputBytes => "input_bytes",
            Self::OutputBytes => "output_bytes",
            Self::SourceWidth => "source_width",
            Self::ReferenceWidth => "reference_width",
            Self::ModelCalls => "model_calls",
            Self::Attempts => "attempts",
            Self::Candidates => "candidates",
            Self::WallMs => "wall_ms",
            Self::WorkFanOut => "work_fan_out",
            Self::ReportBytes => "report_bytes",
        }
    }

    /// Returns the class ceiling for this dimension.
    pub const fn ceiling(self) -> u64 {
        match self {
            Self::InputBytes => INPUT_BYTES_CEILING,
            Self::OutputBytes => OUTPUT_BYTES_CEILING,
            Self::SourceWidth => SOURCE_WIDTH_CEILING,
            Self::ReferenceWidth => REFERENCE_WIDTH_CEILING,
            Self::ModelCalls => MODEL_CALLS_CEILING,
            Self::Attempts => ATTEMPTS_CEILING,
            Self::Candidates => CANDIDATES_CEILING,
            Self::WallMs => WALL_MS_CEILING,
            Self::WorkFanOut => WORK_FAN_OUT_CEILING,
            Self::ReportBytes => REPORT_BYTES_CEILING,
        }
    }
}

/// Parses an exact wire spelling into a [`BudgetDimension`], rejecting
/// anything else as fail-closed.
pub fn parse_budget_dimension(value: &str) -> Result<BudgetDimension, ContractViolation> {
    match value {
        "input_bytes" => Ok(BudgetDimension::InputBytes),
        "output_bytes" => Ok(BudgetDimension::OutputBytes),
        "source_width" => Ok(BudgetDimension::SourceWidth),
        "reference_width" => Ok(BudgetDimension::ReferenceWidth),
        "model_calls" => Ok(BudgetDimension::ModelCalls),
        "attempts" => Ok(BudgetDimension::Attempts),
        "candidates" => Ok(BudgetDimension::Candidates),
        "wall_ms" => Ok(BudgetDimension::WallMs),
        "work_fan_out" => Ok(BudgetDimension::WorkFanOut),
        "report_bytes" => Ok(BudgetDimension::ReportBytes),
        _ => Err(ContractViolation::UnknownVariant {
            field: "budget_dimension",
            value: value.to_owned(),
        }),
    }
}

/// Every independent budget dimension in canonical order.
pub const DEX_BUDGET_DIMENSIONS: &[&str] = &[
    "input_bytes",
    "output_bytes",
    "source_width",
    "reference_width",
    "model_calls",
    "attempts",
    "candidates",
    "wall_ms",
    "work_fan_out",
    "report_bytes",
];

/// Every independent budget dimension as typed values, in canonical order.
pub(crate) const ALL_BUDGET_DIMENSIONS: [BudgetDimension; 10] = [
    BudgetDimension::InputBytes,
    BudgetDimension::OutputBytes,
    BudgetDimension::SourceWidth,
    BudgetDimension::ReferenceWidth,
    BudgetDimension::ModelCalls,
    BudgetDimension::Attempts,
    BudgetDimension::Candidates,
    BudgetDimension::WallMs,
    BudgetDimension::WorkFanOut,
    BudgetDimension::ReportBytes,
];

/// Independent per-dimension budget limits. `None` means the limit is
/// unknown at rest; unknown-as-unlimited is forbidden at authorization time,
/// so [`BudgetLimits::require_exact`] rejects any `None` before usage can be
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    /// Admitted input bytes, if known.
    pub input_bytes: Option<u64>,
    /// Admitted output bytes, if known.
    pub output_bytes: Option<u64>,
    /// Admitted source width, if known.
    pub source_width: Option<u64>,
    /// Admitted reference width, if known.
    pub reference_width: Option<u64>,
    /// Admitted model calls, if known.
    pub model_calls: Option<u64>,
    /// Admitted attempts, if known.
    pub attempts: Option<u64>,
    /// Admitted candidates, if known.
    pub candidates: Option<u64>,
    /// Admitted wall-clock milliseconds, if known.
    pub wall_ms: Option<u64>,
    /// Admitted work fan-out, if known.
    pub work_fan_out: Option<u64>,
    /// Admitted report bytes, if known.
    pub report_bytes: Option<u64>,
    /// Admitted synthetic throttle units, if known.
    pub max_stu: Option<u64>,
}

impl BudgetLimits {
    /// Validates every present limit against its class ceiling. `None`
    /// (unknown) is allowed at rest. `Some(0)` is rejected for
    /// `model_calls`, `attempts`, and `candidates` because a bounded count
    /// of zero authorizes nothing and would silently disable the job; byte,
    /// width, time, and STU limits may be zero.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let output_bytes = self.output_bytes;
        let source_width = self.source_width;
        let reference = self.reference_width;
        let work_fan_out = self.work_fan_out;
        let report_bytes = self.report_bytes;
        for (value, dim, ceiling, allow_zero) in [
            (self.input_bytes, "input_bytes", INPUT_BYTES_CEILING, true),
            (output_bytes, "output_bytes", OUTPUT_BYTES_CEILING, true),
            (source_width, "source_width", SOURCE_WIDTH_CEILING, true),
            (reference, "reference_width", REFERENCE_WIDTH_CEILING, true),
            (self.model_calls, "model_calls", MODEL_CALLS_CEILING, false),
            (self.attempts, "attempts", ATTEMPTS_CEILING, false),
            (self.candidates, "candidates", CANDIDATES_CEILING, false),
            (self.wall_ms, "wall_ms", WALL_MS_CEILING, true),
            (work_fan_out, "work_fan_out", WORK_FAN_OUT_CEILING, true),
            (report_bytes, "report_bytes", REPORT_BYTES_CEILING, true),
            (self.max_stu, "max_stu", STU_CEILING, true),
        ] {
            check_limit(value, dim, ceiling, allow_zero)?;
        }
        Ok(())
    }

    /// Requires every limit to be exact: any `None` (unknown) fails because
    /// unknown-as-unlimited cannot authorize usage. Present values are then
    /// validated against their class ceilings.
    pub fn require_exact(&self) -> Result<(), ContractViolation> {
        for (value, dim) in [
            (self.input_bytes, "input_bytes"),
            (self.output_bytes, "output_bytes"),
            (self.source_width, "source_width"),
            (self.reference_width, "reference_width"),
            (self.model_calls, "model_calls"),
            (self.attempts, "attempts"),
            (self.candidates, "candidates"),
            (self.wall_ms, "wall_ms"),
            (self.work_fan_out, "work_fan_out"),
            (self.report_bytes, "report_bytes"),
            (self.max_stu, "max_stu"),
        ] {
            require_known(value, dim)?;
        }
        self.validate()
    }
}

/// Observed per-dimension budget consumption plus synthetic throttle units.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetUsage {
    /// Consumed input bytes.
    pub input_bytes: u64,
    /// Consumed output bytes.
    pub output_bytes: u64,
    /// Consulted source width.
    pub source_width: u64,
    /// Consulted reference width.
    pub reference_width: u64,
    /// Performed model calls.
    pub model_calls: u64,
    /// Performed attempts.
    pub attempts: u64,
    /// Produced candidates.
    pub candidates: u64,
    /// Elapsed wall-clock milliseconds.
    pub wall_ms: u64,
    /// Observed work fan-out.
    pub work_fan_out: u64,
    /// Emitted report bytes.
    pub report_bytes: u64,
    /// Consumed synthetic throttle units.
    pub stu_used: u64,
}

impl BudgetUsage {
    /// Returns `Ok` exactly when every consumed dimension fits inside its
    /// corresponding `Some` limit. Fails when any usage exceeds its limit or
    /// when any limit is `None` (unknown-as-unlimited cannot authorize
    /// usage). Each dimension is checked independently.
    pub fn fits(&self, limits: &BudgetLimits) -> Result<(), ContractViolation> {
        check_usage(self, limits, false)
    }

    /// Returns the consumed amount for one dimension.
    pub const fn of(self, dimension: BudgetDimension) -> u64 {
        match dimension {
            BudgetDimension::InputBytes => self.input_bytes,
            BudgetDimension::OutputBytes => self.output_bytes,
            BudgetDimension::SourceWidth => self.source_width,
            BudgetDimension::ReferenceWidth => self.reference_width,
            BudgetDimension::ModelCalls => self.model_calls,
            BudgetDimension::Attempts => self.attempts,
            BudgetDimension::Candidates => self.candidates,
            BudgetDimension::WallMs => self.wall_ms,
            BudgetDimension::WorkFanOut => self.work_fan_out,
            BudgetDimension::ReportBytes => self.report_bytes,
        }
    }
}

/// Checks usage against limits with no compensation across dimensions.
pub fn check_no_cross_subsidy(
    usage: &BudgetUsage,
    limits: &BudgetLimits,
) -> Result<(), ContractViolation> {
    check_usage(usage, limits, true)
}

fn check_limit(
    value: Option<u64>,
    dimension: &'static str,
    ceiling: u64,
    allow_zero: bool,
) -> Result<(), ContractViolation> {
    let Some(bound) = value else {
        return Ok(());
    };
    if bound == 0 && !allow_zero {
        return Err(ContractViolation::Budget {
            dimension,
            reason: std::format!("bounded {dimension} of 0 authorizes no work"),
        });
    }
    if bound > ceiling {
        return Err(ContractViolation::Budget {
            dimension,
            reason: std::format!("limit {bound} exceeds class ceiling {ceiling}"),
        });
    }
    Ok(())
}

fn require_known(value: Option<u64>, dimension: &'static str) -> Result<(), ContractViolation> {
    if value.is_none() {
        return Err(ContractViolation::Budget {
            dimension,
            reason: "unknown limit cannot authorize usage".to_owned(),
        });
    }
    Ok(())
}

fn limit_of(limits: &BudgetLimits, dimension: BudgetDimension) -> Option<u64> {
    match dimension {
        BudgetDimension::InputBytes => limits.input_bytes,
        BudgetDimension::OutputBytes => limits.output_bytes,
        BudgetDimension::SourceWidth => limits.source_width,
        BudgetDimension::ReferenceWidth => limits.reference_width,
        BudgetDimension::ModelCalls => limits.model_calls,
        BudgetDimension::Attempts => limits.attempts,
        BudgetDimension::Candidates => limits.candidates,
        BudgetDimension::WallMs => limits.wall_ms,
        BudgetDimension::WorkFanOut => limits.work_fan_out,
        BudgetDimension::ReportBytes => limits.report_bytes,
    }
}

fn unknown_reason(cross: bool) -> String {
    if cross {
        "unknown limit cannot authorize usage; no compensation across dimensions".to_owned()
    } else {
        "unknown limit cannot authorize usage".to_owned()
    }
}

fn over_reason(cross: bool, used: u64, cap: u64, label: &str) -> String {
    if cross {
        std::format!(
            "usage {used} exceeds limit {cap} on {label}; under-use elsewhere cannot compensate"
        )
    } else {
        std::format!("usage {used} exceeds limit {cap}")
    }
}

fn check_usage(
    usage: &BudgetUsage,
    limits: &BudgetLimits,
    cross_subsidy_spelling: bool,
) -> Result<(), ContractViolation> {
    for dimension in ALL_BUDGET_DIMENSIONS {
        let used = usage.of(dimension);
        let Some(cap) = limit_of(limits, dimension) else {
            return Err(ContractViolation::Budget {
                dimension: dimension.as_str(),
                reason: unknown_reason(cross_subsidy_spelling),
            });
        };
        if used > cap {
            return Err(ContractViolation::Budget {
                dimension: dimension.as_str(),
                reason: over_reason(
                    cross_subsidy_spelling,
                    used,
                    cap,
                    &std::format!("{dimension:?}"),
                ),
            });
        }
    }
    let Some(cap) = limits.max_stu else {
        return Err(ContractViolation::Budget {
            dimension: "max_stu",
            reason: unknown_reason(cross_subsidy_spelling),
        });
    };
    if usage.stu_used > cap {
        return Err(ContractViolation::Budget {
            dimension: "max_stu",
            reason: over_reason(cross_subsidy_spelling, usage.stu_used, cap, "STU"),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn ceiling_limits() -> BudgetLimits {
        BudgetLimits {
            input_bytes: Some(INPUT_BYTES_CEILING),
            output_bytes: Some(OUTPUT_BYTES_CEILING),
            source_width: Some(SOURCE_WIDTH_CEILING),
            reference_width: Some(REFERENCE_WIDTH_CEILING),
            model_calls: Some(MODEL_CALLS_CEILING),
            attempts: Some(ATTEMPTS_CEILING),
            candidates: Some(CANDIDATES_CEILING),
            wall_ms: Some(WALL_MS_CEILING),
            work_fan_out: Some(WORK_FAN_OUT_CEILING),
            report_bytes: Some(REPORT_BYTES_CEILING),
            max_stu: Some(STU_CEILING),
        }
    }

    fn usage_at(dimension: BudgetDimension, value: u64) -> BudgetUsage {
        let mut usage = BudgetUsage::default();
        match dimension {
            BudgetDimension::InputBytes => usage.input_bytes = value,
            BudgetDimension::OutputBytes => usage.output_bytes = value,
            BudgetDimension::SourceWidth => usage.source_width = value,
            BudgetDimension::ReferenceWidth => usage.reference_width = value,
            BudgetDimension::ModelCalls => usage.model_calls = value,
            BudgetDimension::Attempts => usage.attempts = value,
            BudgetDimension::Candidates => usage.candidates = value,
            BudgetDimension::WallMs => usage.wall_ms = value,
            BudgetDimension::WorkFanOut => usage.work_fan_out = value,
            BudgetDimension::ReportBytes => usage.report_bytes = value,
        }
        usage
    }

    fn limits_at(dimension: BudgetDimension, value: u64) -> BudgetLimits {
        let mut limits = ceiling_limits();
        match dimension {
            BudgetDimension::InputBytes => limits.input_bytes = Some(value),
            BudgetDimension::OutputBytes => limits.output_bytes = Some(value),
            BudgetDimension::SourceWidth => limits.source_width = Some(value),
            BudgetDimension::ReferenceWidth => limits.reference_width = Some(value),
            BudgetDimension::ModelCalls => limits.model_calls = Some(value),
            BudgetDimension::Attempts => limits.attempts = Some(value),
            BudgetDimension::Candidates => limits.candidates = Some(value),
            BudgetDimension::WallMs => limits.wall_ms = Some(value),
            BudgetDimension::WorkFanOut => limits.work_fan_out = Some(value),
            BudgetDimension::ReportBytes => limits.report_bytes = Some(value),
        }
        limits
    }

    // WORK_UNIT_CASE: 578/10
    #[test]
    fn every_dimension_exact_bound_ceiling_accepted_ceiling_plus_one_rejected() {
        assert_eq!(DEX_BUDGET_DIMENSIONS.len(), 10);
        for (index, dimension) in ALL_BUDGET_DIMENSIONS.iter().enumerate() {
            assert_eq!(DEX_BUDGET_DIMENSIONS[index], dimension.as_str());
            let parsed = parse_budget_dimension(dimension.as_str()).expect("known dimension");
            assert_eq!(parsed, *dimension);
            let ceiling = dimension.ceiling();
            let limit = limit_of(&ceiling_limits(), *dimension).expect("ceiling set");
            assert_eq!(ceiling, limit);
            assert!(limits_at(*dimension, ceiling).validate().is_ok());
            let over = limits_at(*dimension, ceiling + 1)
                .validate()
                .expect_err("ceiling+1");
            match over {
                ContractViolation::Budget {
                    dimension: dim,
                    reason,
                } => {
                    assert_eq!(dim, dimension.as_str());
                    assert!(reason.contains("ceiling"), "reason: {reason}");
                }
                other => panic!("wrong violation for {dimension:?}: {other:?}"),
            }
            let limits = ceiling_limits();
            assert!(usage_at(*dimension, ceiling).fits(&limits).is_ok());
            let err = usage_at(*dimension, ceiling + 1)
                .fits(&limits)
                .expect_err("usage+1");
            match err {
                ContractViolation::Budget { dimension: dim, .. } => {
                    assert_eq!(dim, dimension.as_str());
                }
                other => panic!("wrong violation for {dimension:?}: {other:?}"),
            }
        }
        assert!(ceiling_limits().validate().is_ok() && ceiling_limits().require_exact().is_ok());
        let mut stu = usage_at(BudgetDimension::InputBytes, 0);
        stu.stu_used = STU_CEILING + 1;
        assert!(stu.fits(&ceiling_limits()).is_err());
        stu.stu_used = STU_CEILING;
        assert!(stu.fits(&ceiling_limits()).is_ok());
    }

    // WORK_UNIT_CASE: 578/11
    #[test]
    fn zero_unknown_and_class_ceiling_boundaries() {
        for dimension in [
            BudgetDimension::ModelCalls,
            BudgetDimension::Attempts,
            BudgetDimension::Candidates,
        ] {
            let err = limits_at(dimension, 0).validate().expect_err("zero bound");
            match err {
                ContractViolation::Budget { dimension: dim, .. } => {
                    assert_eq!(dim, dimension.as_str());
                }
                other => panic!("wrong violation for {dimension:?}: {other:?}"),
            }
        }
        assert!(limits_at(BudgetDimension::InputBytes, 0).validate().is_ok());
        assert!(limits_at(BudgetDimension::WallMs, 0).validate().is_ok());
        let mut unknown = ceiling_limits();
        unknown.model_calls = None;
        assert!(unknown.validate().is_ok(), "unknown allowed at rest");
        assert!(
            unknown.require_exact().is_err(),
            "unknown forbidden when exact"
        );
        let usage = usage_at(BudgetDimension::ModelCalls, 1);
        let err = usage.fits(&unknown).expect_err("unknown cannot authorize");
        match err {
            ContractViolation::Budget { dimension, reason } => {
                assert_eq!(dimension, "model_calls");
                assert!(reason.contains("unknown limit"), "reason: {reason}");
            }
            other => panic!("wrong violation for unknown limit: {other:?}"),
        }
        let mut above = ceiling_limits();
        above.attempts = Some(ATTEMPTS_CEILING + 1);
        assert!(above.validate().is_err() && above.require_exact().is_err());
        assert!(parse_budget_dimension("other").is_err() && parse_budget_dimension("").is_err());
    }

    // WORK_UNIT_CASE: 578/12
    #[test]
    fn under_use_cannot_cover_over_use_in_another_dimension() {
        let mut limits = ceiling_limits();
        limits.input_bytes = Some(1000);
        limits.output_bytes = Some(100);
        let skewed = BudgetUsage {
            input_bytes: 10,
            output_bytes: 101,
            ..BudgetUsage::default()
        };
        let err = skewed.fits(&limits).expect_err("over-use must fail");
        match err {
            ContractViolation::Budget { dimension, .. } => {
                assert_eq!(dimension, "output_bytes");
            }
            other => panic!("wrong violation for skewed usage: {other:?}"),
        }
        let err = check_no_cross_subsidy(&skewed, &limits).expect_err("cross-subsidy");
        match err {
            ContractViolation::Budget { dimension, reason } => {
                assert_eq!(dimension, "output_bytes");
                assert!(
                    reason.contains("compensat"),
                    "reason must state independence: {reason}"
                );
            }
            other => panic!("wrong violation for cross-subsidy: {other:?}"),
        }
        let mut within = skewed;
        within.output_bytes = 100;
        assert!(within.fits(&limits).is_ok() && check_no_cross_subsidy(&within, &limits).is_ok());
        assert_eq!(DEX_BUDGET_DIMENSIONS.len(), 10);
        let mut ceilings: Vec<u64> = ALL_BUDGET_DIMENSIONS.iter().map(|d| d.ceiling()).collect();
        ceilings.push(STU_CEILING);
        assert_eq!(ceilings.len(), 11);
        let total: u128 = ceilings.iter().map(|c| u128::from(*c)).sum();
        assert!(total < u128::from(u64::MAX) && total > 0);
        let mut seen: Vec<&str> = DEX_BUDGET_DIMENSIONS.to_vec();
        seen.push("max_stu");
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 11);
        assert!(ceiling_limits().require_exact().is_ok());
    }
}
