//! Usage and cost facts, stored separately from the metric registry (I16.5).
//!
//! I16.5 ends its `Usage and cost` group with `Store separately:` and then names
//! the facts to store, the scope axis, the truth hierarchy, and the rule that
//! subscription quota is not converted to currency. This module is that store.
//! It is a distinct typed value with its own bounded bucket capacity; it is not
//! extra label dimensions on [`crate::metrics::OpenMetrics`] and it is not a
//! second exposition. Nothing here is ever scraped as a metric, and no usage or
//! cost fact is ever recorded through a metric label.
//!
//! # The three properties that make the separation load-bearing
//!
//! ## 1. Scope is a type
//!
//! [`UsageScope`] is a closed three-variant enum, so a fact filed as a
//! [`UsageScope::Child`] can never be read back as a root total and an
//! [`UsageScope::Aggregate`] is not a root. The scope is part of [`UsageKey`],
//! so two scopes are two buckets and never one number.
//!
//! ## 2. Truth source is a type
//!
//! [`UsageTruth`] is the I16.5 hierarchy as a closed enum whose declaration order
//! is the hierarchy, strongest source first: `provider invoice/API meter`,
//! `provider SDK/account meter`, `runtime telemetry`, `ELIOT estimate`,
//! `unknown/not_exposed`. The truth level is also part of [`UsageKey`], so an
//! ELIOT estimate filed under `eliot_estimate` occupies a different bucket from
//! a provider invoice filed under `provider_invoice` and cannot replace it.
//! [`UsageTruth::admits_billed_currency`] then refuses a currency amount at every
//! level below the two provider money sources, so an estimate is not money even
//! if a caller files it under a provider level.
//!
//! ## 3. Quota is not currency, by construction
//!
//! [`SubscriptionQuota`] holds a consumed numerator, a window denominator, a
//! reset instant, and a source. It has no currency field, no minor-unit field,
//! and no conversion method, and there is no `From` implementation from it to
//! [`BilledCost`]. [`BilledCost`] has private fields and its only constructor
//! takes a [`CurrencyContract`], so the sole path from a subscription quota
//! fraction to a currency amount is a caller that separately holds a provider
//! contract — which is exactly the condition I16.5 states.
//!
//! # Bounded retention
//!
//! I16.9 states that telemetry consumes the same CPU, memory, I/O, queue and
//! context resources it observes, so this store is bounded by
//! [`crate::config::MAX_USAGE_COST_BUCKETS`]. A bucket beyond the bound is
//! refused with a typed [`UsageCostError::BucketStoreFull`] and counted by
//! [`UsageCostStore::refused_facts`], so a full store is visible rather than
//! silently dropping facts.
//!
//! # No composite view exists
//!
//! I16.5 requires nominal cost and retry/replay/compaction cost to stay
//! separate, and I16.6 forbids a single performance score. [`IncidentalCost`]
//! keeps its four axes as four fields and has no summing method, this store has
//! no cross-bucket total, and no method on this module returns an overall cost or
//! performance figure. [`UsageCostStore::keys`] returns bucket identities, not
//! numbers, so a reader must choose which bucket and which truth level it means.
//!
//! # Wire shapes
//!
//! This store deliberately carries no `serde` derive. It is in-process state,
//! and adding a serialized boundary here would require regenerating the
//! repository's shipped serde-boundary inventory, which is outside this change's
//! permitted file set. Every field is required by construction because the
//! fields are the constructor's own typed parameters; there is no defaulted or
//! optional wire field to reconcile.
//!
//! Normative anchors: I16.5 usage and cost, I16.6 performance views, I16.9
//! retention and telemetry cost.

use std::collections::BTreeMap;

use crate::config::{MAX_USAGE_COST_BUCKETS, MAX_USAGE_COST_ID_CHARS};
use crate::metric_groups::{RouteFingerprintId, WorkClass, is_label_value_byte};

/// Number of ASCII characters in a currency code.
const CURRENCY_CODE_CHARS: usize = 3;

/// Fact name used in [`UsageCostError::TruthNotAdmittedForFact`].
const USAGE_FACT: &str = "a usage reading";
const WITHHELD_FACT: &str = "a withheld-denominator reading";
const QUOTA_FACT: &str = "a subscription quota reading";
const BILLED_FACT: &str = "a provider-contract currency amount";
const ESTIMATE_FACT: &str = "an ELIOT cost estimate";

/// Which of I16.5's three usage/cost scopes a fact belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UsageScope {
    /// The top-level unit of work.
    Root,
    /// One child of a root unit of work.
    Child,
    /// A total over several children of one root unit of work.
    Aggregate,
}

impl UsageScope {
    /// The stable scope name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Child => "child",
            Self::Aggregate => "aggregate",
        }
    }

    /// Every scope, in increasing breadth.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Root, Self::Child, Self::Aggregate]
    }
}

/// The I16.5 truth hierarchy, strongest source first.
///
/// The declaration order *is* the hierarchy, so the derived ordering places a
/// provider invoice/API meter above a provider SDK/account meter, that above
/// runtime telemetry, that above an ELIOT estimate, and that above the unknown
/// level. A weaker reading therefore never displaces a stronger one, because the
/// truth level is part of [`UsageKey`] and the two live in different buckets.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UsageTruth {
    /// `provider invoice/API meter`.
    ProviderInvoice,
    /// `provider SDK/account meter`.
    ProviderAccountMeter,
    /// `runtime telemetry`.
    RuntimeTelemetry,
    /// `ELIOT estimate`.
    EliotEstimate,
    /// `unknown/not_exposed`.
    NotExposed,
}

impl UsageTruth {
    /// The stable truth name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderInvoice => "provider_invoice",
            Self::ProviderAccountMeter => "provider_account_meter",
            Self::RuntimeTelemetry => "runtime_telemetry",
            Self::EliotEstimate => "eliot_estimate",
            Self::NotExposed => "not_exposed",
        }
    }

    /// Every truth level, strongest source first.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::ProviderInvoice,
            Self::ProviderAccountMeter,
            Self::RuntimeTelemetry,
            Self::EliotEstimate,
            Self::NotExposed,
        ]
    }

    /// Whether this level can carry a currency amount.
    ///
    /// Only the two provider money sources can. I16.5 ranks runtime telemetry,
    /// an ELIOT estimate and the unknown level below the provider sources and
    /// states that subscription quota is not converted to currency without a
    /// provider contract, so no other level admits a [`BilledCost`].
    #[must_use]
    pub const fn admits_billed_currency(self) -> bool {
        matches!(self, Self::ProviderInvoice | Self::ProviderAccountMeter)
    }

    /// Whether this level can observe a usage figure.
    ///
    /// [`UsageTruth::NotExposed`] cannot: I16.9 states that missing telemetry
    /// means missing observability and is never evidence that no event occurred,
    /// so the unknown level carries a withheld denominator through
    /// [`UsageCostStore::record_not_exposed`] rather than a figure.
    #[must_use]
    pub const fn admits_observed_figure(self) -> bool {
        !matches!(self, Self::NotExposed)
    }
}

/// The provider whose meter reported a usage or cost fact.
///
/// Bounded to the exporter's label charset and to
/// [`crate::config::MAX_USAGE_COST_ID_CHARS`], so a provider identity is a
/// bounded name and never a URL carrying a credential and never free text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderId(String);

impl ProviderId {
    /// Validates and wraps one provider identity.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::BlankIdentifier`] for an empty identity,
    /// [`UsageCostError::OverBoundIdentifier`] when it exceeds
    /// [`crate::config::MAX_USAGE_COST_ID_CHARS`], and
    /// [`UsageCostError::UnrenderableIdentifier`] when it holds a byte outside
    /// the bounded identifier charset.
    pub fn new(identifier: &str) -> Result<Self, UsageCostError> {
        if identifier.is_empty() {
            return Err(UsageCostError::BlankIdentifier);
        }
        let chars = identifier.chars().count();
        if chars > MAX_USAGE_COST_ID_CHARS {
            return Err(UsageCostError::OverBoundIdentifier { chars });
        }
        if !identifier.bytes().all(is_label_value_byte) {
            return Err(UsageCostError::UnrenderableIdentifier);
        }
        Ok(Self(identifier.to_owned()))
    }

    /// The validated provider identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A three-letter currency code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    /// Validates and wraps one currency code: exactly three ASCII uppercase
    /// letters.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::MalformedCurrencyCode`] when the value is not
    /// three ASCII uppercase letters, carrying the observed length rather than
    /// the rejected value.
    pub fn new(code: &str) -> Result<Self, UsageCostError> {
        if code.len() != CURRENCY_CODE_CHARS || !code.bytes().all(|byte| byte.is_ascii_uppercase())
        {
            return Err(UsageCostError::MalformedCurrencyCode {
                chars: code.chars().count(),
            });
        }
        Ok(Self(code.to_owned()))
    }

    /// The validated currency code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The provider contract that authorises one currency for one billed amount.
///
/// I16.5 states that subscription quota is not converted to currency without a
/// provider contract. [`BilledCost`] can only be built from one of these, so a
/// quota fraction, an ELIOT estimate, or any other non-provider figure has no
/// path into a currency amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrencyContract {
    provider: ProviderId,
    currency: CurrencyCode,
}

impl CurrencyContract {
    /// Binds one provider to one currency.
    #[must_use]
    pub fn new(provider: ProviderId, currency: CurrencyCode) -> Self {
        Self { provider, currency }
    }

    /// The contracting provider.
    #[must_use]
    pub fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// The contracted currency.
    #[must_use]
    pub fn currency(&self) -> &CurrencyCode {
        &self.currency
    }
}

/// A provider-contract-backed currency amount.
///
/// The fields are private and the only constructor takes a [`CurrencyContract`],
/// so an amount in currency exists only where a provider contract exists. The
/// amount is an integer count of the contracted currency's minor units, so a
/// stored value is never a bare floating-point currency guess.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BilledCost {
    contract: CurrencyContract,
    minor_units: u64,
}

impl BilledCost {
    /// Builds one currency amount under an explicit provider contract.
    #[must_use]
    pub fn under_contract(contract: CurrencyContract, minor_units: u64) -> Self {
        Self {
            contract,
            minor_units,
        }
    }

    /// The contracting provider and currency this amount was reported under.
    #[must_use]
    pub fn contract(&self) -> &CurrencyContract {
        &self.contract
    }

    /// The amount, in the contracted currency's minor units.
    #[must_use]
    pub fn minor_units(&self) -> u64 {
        self.minor_units
    }
}

/// The countable resource an ELIOT cost estimate is denominated in.
///
/// There is deliberately no currency member. I16.5 ranks an estimate below every
/// provider money source and forbids converting subscription quota into
/// currency, so an estimate names a countable resource and never an amount of
/// money.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EstimateUnit {
    /// Prompt and input tokens the estimate prices.
    InputTokens,
    /// Cached-input tokens the estimate prices.
    CachedInputTokens,
    /// Output tokens the estimate prices.
    OutputTokens,
    /// Exposed reasoning tokens the estimate prices.
    ExposedReasoningTokens,
    /// Native child processes the estimate prices.
    NativeChildProcesses,
}

impl EstimateUnit {
    /// The stable unit name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTokens => "input_tokens",
            Self::CachedInputTokens => "cached_input_tokens",
            Self::OutputTokens => "output_tokens",
            Self::ExposedReasoningTokens => "exposed_reasoning_tokens",
            Self::NativeChildProcesses => "native_child_processes",
        }
    }

    /// Every estimate unit, in I16.5 order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::InputTokens,
            Self::CachedInputTokens,
            Self::OutputTokens,
            Self::ExposedReasoningTokens,
            Self::NativeChildProcesses,
        ]
    }
}

/// An ELIOT cost estimate: a magnitude in a named countable unit.
///
/// An estimate belongs to the [`UsageTruth::EliotEstimate`] bucket, the fourth
/// level of the truth hierarchy, so it can never be presented as a provider
/// amount; and it carries no currency because [`EstimateUnit`] has no currency
/// member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CostEstimate {
    magnitude: u64,
    unit: EstimateUnit,
}

impl CostEstimate {
    /// Builds one estimate over a countable unit.
    #[must_use]
    pub fn new(magnitude: u64, unit: EstimateUnit) -> Self {
        Self { magnitude, unit }
    }

    /// The estimated magnitude.
    #[must_use]
    pub fn magnitude(&self) -> u64 {
        self.magnitude
    }

    /// The countable unit the estimate is denominated in.
    #[must_use]
    pub fn unit(&self) -> EstimateUnit {
        self.unit
    }
}

/// The surface a subscription quota window was read from.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QuotaSource {
    /// A window the provider's own subscription surface reported.
    ProviderSubscription,
    /// A window this runtime observed from its own account telemetry.
    RuntimeObserved,
}

impl QuotaSource {
    /// The stable source name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderSubscription => "provider_subscription",
            Self::RuntimeObserved => "runtime_observed",
        }
    }

    /// Every quota source.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::ProviderSubscription, Self::RuntimeObserved]
    }
}

/// A subscription quota reading: the consumed fraction of a window, the reset
/// instant, and the source that reported it.
///
/// There is deliberately no currency field, no minor-unit field, and no
/// conversion method, and there is no `From` implementation to [`BilledCost`].
/// I16.5 stores a quota as a fraction, a reset and a source, and states that
/// subscription quota is not converted to currency without a provider contract;
/// a reading filed here carries no contract, so the only route from a quota
/// fraction to a currency amount is a caller that separately holds a
/// [`CurrencyContract`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionQuota {
    consumed_numerator: u64,
    consumed_denominator: u64,
    resets_at_ms: i64,
    source: QuotaSource,
}

impl SubscriptionQuota {
    /// Builds one quota reading from a consumed fraction of a named window.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::ZeroQuotaWindow`] when the window denominator is
    /// zero, and [`UsageCostError::OverBoundQuotaFraction`] when the consumed
    /// numerator exceeds its denominator.
    pub fn new(
        consumed_numerator: u64,
        consumed_denominator: u64,
        resets_at_ms: i64,
        source: QuotaSource,
    ) -> Result<Self, UsageCostError> {
        if consumed_denominator == 0 {
            return Err(UsageCostError::ZeroQuotaWindow);
        }
        if consumed_numerator > consumed_denominator {
            return Err(UsageCostError::OverBoundQuotaFraction {
                consumed_numerator,
                consumed_denominator,
            });
        }
        Ok(Self {
            consumed_numerator,
            consumed_denominator,
            resets_at_ms,
            source,
        })
    }

    /// Consumed units within the window.
    #[must_use]
    pub fn consumed_numerator(&self) -> u64 {
        self.consumed_numerator
    }

    /// The window the fraction is measured against.
    #[must_use]
    pub fn consumed_denominator(&self) -> u64 {
        self.consumed_denominator
    }

    /// The window reset instant, in Unix milliseconds.
    #[must_use]
    pub fn resets_at_ms(&self) -> i64 {
        self.resets_at_ms
    }

    /// The surface the window was read from.
    #[must_use]
    pub fn source(&self) -> QuotaSource {
        self.source
    }
}

/// The token facts I16.5 requires: input, cached input, output and exposed
/// reasoning tokens.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TokenCounts {
    /// Prompt and input tokens.
    pub input: u64,
    /// Input tokens the provider served from its cache.
    pub cached_input: u64,
    /// Completion and output tokens.
    pub output: u64,
    /// Reasoning tokens the provider exposed. Never inferred from a total.
    pub exposed_reasoning: u64,
}

/// The count facts I16.5 requires: request, tool, model and native-child counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CallCounts {
    /// Top-level requests.
    pub requests: u64,
    /// Tool invocations.
    pub tool_calls: u64,
    /// Model calls.
    pub model_calls: u64,
    /// Native child processes started.
    pub native_children: u64,
}

/// The resource facts I16.5 requires: wall time and CPU/RAM/process use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceUse {
    /// Wall-clock time in milliseconds.
    pub wall_time_ms: u64,
    /// CPU time in milliseconds.
    pub cpu_time_ms: u64,
    /// Peak resident memory in bytes.
    pub ram_bytes: u64,
    /// Native processes observed in this scope's process tree.
    pub process_count: u32,
}

/// The four non-nominal cost axes I16.5 names and I16.6 requires to stay apart
/// from nominal cost: retry, replay, compaction and environment.
///
/// Each axis is its own field and this type has no summing method, so no total
/// can be formed from the four without a reader choosing which axis it means.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IncidentalCost {
    /// Wall time spent retrying.
    pub retry_ms: u64,
    /// Wall time spent replaying.
    pub replay_ms: u64,
    /// Wall time spent compacting.
    pub compaction_ms: u64,
    /// Wall time spent on environment setup and teardown.
    pub environment_ms: u64,
}

/// The non-monetary usage facts of one bucket.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UsageFacts {
    /// Input, cached input, output and exposed reasoning tokens.
    pub tokens: TokenCounts,
    /// Request, tool, model and native-child counts.
    pub calls: CallCounts,
    /// Wall time and CPU, RAM and process use.
    pub resources: ResourceUse,
    /// Retry, replay, compaction and environment cost, kept apart from nominal
    /// cost.
    pub incidental: IncidentalCost,
}

/// The bounded bucket identity of one usage and cost fact.
///
/// Scope and truth are part of the identity, not attributes of a record, so a
/// fact filed as a child at the estimate level cannot be read back as a root
/// provider-invoice fact: the two keys differ, and each bucket holds its own
/// fact.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct UsageKey {
    /// Root, child or aggregate scope.
    pub scope: UsageScope,
    /// The truth level of the reading in this bucket.
    pub truth: UsageTruth,
    /// The known work class the work was admitted under.
    pub work_class: WorkClass,
    /// The route the work ran under. `None` for an aggregate over several
    /// routes; `Some` for a root or a child.
    pub route: Option<RouteFingerprintId>,
}

/// One bucket's separately stored usage and cost fact.
///
/// All fields are private, so a record can only be produced by
/// [`UsageCostStore`], and each optional field is only reachable through the
/// record method whose truth rules admit it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageCostRecord {
    key: UsageKey,
    usage: Option<UsageFacts>,
    withheld: Option<CallCounts>,
    quota: Option<SubscriptionQuota>,
    billed_cost: Option<BilledCost>,
    estimated_cost: Option<CostEstimate>,
}

impl UsageCostRecord {
    fn empty(key: UsageKey) -> Self {
        Self {
            key,
            usage: None,
            withheld: None,
            quota: None,
            billed_cost: None,
            estimated_cost: None,
        }
    }

    /// The bucket identity this fact was filed under.
    #[must_use]
    pub fn key(&self) -> &UsageKey {
        &self.key
    }

    /// The observed usage figures, when this bucket carries them.
    #[must_use]
    pub fn usage(&self) -> Option<&UsageFacts> {
        self.usage.as_ref()
    }

    /// The call counts known to have happened but not exposed as figures.
    #[must_use]
    pub fn withheld(&self) -> Option<&CallCounts> {
        self.withheld.as_ref()
    }

    /// The subscription quota reading, when this bucket carries one.
    #[must_use]
    pub fn quota(&self) -> Option<&SubscriptionQuota> {
        self.quota.as_ref()
    }

    /// The provider-contract currency amount, when this bucket carries one.
    #[must_use]
    pub fn billed_cost(&self) -> Option<&BilledCost> {
        self.billed_cost.as_ref()
    }

    /// The ELIOT estimate, when this bucket carries one.
    #[must_use]
    pub fn estimated_cost(&self) -> Option<&CostEstimate> {
        self.estimated_cost.as_ref()
    }
}

/// Typed usage and cost rejection.
///
/// Every variant names the failing identity — the observed length, the offered
/// numerator and denominator, the refused truth level, the declared bound — and
/// no variant carries a free-text value, so a refusal is not itself a
/// disclosure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum UsageCostError {
    /// An identity value was empty.
    #[error("usage/cost identifier must be non-blank")]
    BlankIdentifier,
    /// An identity value exceeded the declared identifier bound.
    #[error("usage/cost identifier exceeds the bounded character count at {chars} characters")]
    OverBoundIdentifier {
        /// Observed length in characters.
        chars: usize,
    },
    /// An identity value held a byte outside the bounded identifier charset.
    #[error("usage/cost identifier holds a byte outside the bounded charset")]
    UnrenderableIdentifier,
    /// A currency code was not three ASCII uppercase letters.
    #[error("usage/cost currency code is not three uppercase letters (length {chars})")]
    MalformedCurrencyCode {
        /// Observed length in characters.
        chars: usize,
    },
    /// A quota window had a zero denominator, so no fraction exists.
    #[error("usage/cost quota window must have a non-zero denominator")]
    ZeroQuotaWindow,
    /// A quota numerator exceeded its window.
    #[error("usage/cost quota fraction {consumed_numerator} exceeds window {consumed_denominator}")]
    OverBoundQuotaFraction {
        /// The consumed numerator offered.
        consumed_numerator: u64,
        /// The window denominator it was offered against.
        consumed_denominator: u64,
    },
    /// The fact's truth level may not carry the offered fact.
    #[error("usage/cost truth level {truth:?} may not carry {fact}")]
    TruthNotAdmittedForFact {
        /// The truth level the caller used.
        truth: UsageTruth,
        /// The fact that was offered.
        fact: &'static str,
    },
    /// The bounded bucket store is full.
    #[error("usage/cost bucket store is full at its declared bound of {buckets} buckets")]
    BucketStoreFull {
        /// The declared bucket bound that was reached.
        buckets: usize,
    },
}

/// Bounded store of usage and cost facts, held separately from the metric
/// registry.
///
/// A bucket is a current reading rather than a ledger entry, so recording again
/// for the same key replaces that fact. A cumulative ledger is not this store.
///
/// This type exposes no total. [`Self::keys`] returns bucket identities and each
/// accessor returns one bucket's own fact, so a reader must name the scope and
/// the truth level it means; there is no method that could be used to compute an
/// overall cost, an overall latency, or a single performance figure.
#[derive(Clone, Debug, Default)]
pub struct UsageCostStore {
    facts: BTreeMap<UsageKey, UsageCostRecord>,
    refused_facts: u64,
}

impl UsageCostStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the usage figures of one bucket.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::TruthNotAdmittedForFact`] when the key's truth
    /// level is [`UsageTruth::NotExposed`], which carries a withheld denominator
    /// through [`Self::record_not_exposed`] instead, and
    /// [`UsageCostError::BucketStoreFull`] when the bounded store has no room
    /// for a new bucket.
    pub fn record_usage(
        &mut self,
        key: &UsageKey,
        facts: &UsageFacts,
    ) -> Result<(), UsageCostError> {
        if !key.truth.admits_observed_figure() {
            return Err(UsageCostError::TruthNotAdmittedForFact {
                truth: key.truth,
                fact: USAGE_FACT,
            });
        }
        self.entry(key)?.usage = Some(*facts);
        Ok(())
    }

    /// Records the call counts known to have happened but not exposed as
    /// figures.
    ///
    /// This is the `unknown/not_exposed` level's only admitted fact. I16.9
    /// states that missing telemetry means missing observability and is never
    /// evidence that no event occurred, so the denominator is preserved here
    /// rather than being reported as a zero.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::TruthNotAdmittedForFact`] when the key's truth
    /// level is not [`UsageTruth::NotExposed`], and
    /// [`UsageCostError::BucketStoreFull`] when the bounded store has no room
    /// for a new bucket.
    pub fn record_not_exposed(
        &mut self,
        key: &UsageKey,
        withheld: &CallCounts,
    ) -> Result<(), UsageCostError> {
        if key.truth != UsageTruth::NotExposed {
            return Err(UsageCostError::TruthNotAdmittedForFact {
                truth: key.truth,
                fact: WITHHELD_FACT,
            });
        }
        self.entry(key)?.withheld = Some(*withheld);
        Ok(())
    }

    /// Records one subscription quota reading, kept as a fraction, a reset and a
    /// source.
    ///
    /// An ELIOT estimate may not carry a quota reading: an estimate is a
    /// countable-resource magnitude, not a subscription window.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::TruthNotAdmittedForFact`] when the key's truth
    /// level is [`UsageTruth::EliotEstimate`] or [`UsageTruth::NotExposed`], and
    /// [`UsageCostError::BucketStoreFull`] when the bounded store has no room
    /// for a new bucket.
    pub fn record_quota(
        &mut self,
        key: &UsageKey,
        quota: &SubscriptionQuota,
    ) -> Result<(), UsageCostError> {
        if matches!(
            key.truth,
            UsageTruth::EliotEstimate | UsageTruth::NotExposed
        ) {
            return Err(UsageCostError::TruthNotAdmittedForFact {
                truth: key.truth,
                fact: QUOTA_FACT,
            });
        }
        self.entry(key)?.quota = Some(quota.clone());
        Ok(())
    }

    /// Records one provider-contract currency amount.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::TruthNotAdmittedForFact`] when the key's truth
    /// level is not one of the two provider money sources, so an ELIOT estimate
    /// or a runtime observation can never be filed as a provider amount, and
    /// [`UsageCostError::BucketStoreFull`] when the bounded store has no room for
    /// a new bucket.
    pub fn record_billed_cost(
        &mut self,
        key: &UsageKey,
        cost: &BilledCost,
    ) -> Result<(), UsageCostError> {
        if !key.truth.admits_billed_currency() {
            return Err(UsageCostError::TruthNotAdmittedForFact {
                truth: key.truth,
                fact: BILLED_FACT,
            });
        }
        self.entry(key)?.billed_cost = Some(cost.clone());
        Ok(())
    }

    /// Records one ELIOT cost estimate.
    ///
    /// # Errors
    ///
    /// Returns [`UsageCostError::TruthNotAdmittedForFact`] when the key's truth
    /// level is not [`UsageTruth::EliotEstimate`], and
    /// [`UsageCostError::BucketStoreFull`] when the bounded store has no room for
    /// a new bucket.
    pub fn record_estimated_cost(
        &mut self,
        key: &UsageKey,
        estimate: &CostEstimate,
    ) -> Result<(), UsageCostError> {
        if key.truth != UsageTruth::EliotEstimate {
            return Err(UsageCostError::TruthNotAdmittedForFact {
                truth: key.truth,
                fact: ESTIMATE_FACT,
            });
        }
        self.entry(key)?.estimated_cost = Some(estimate.clone());
        Ok(())
    }

    /// Returns the fact stored for `key`, when one exists.
    #[must_use]
    pub fn fact(&self, key: &UsageKey) -> Option<&UsageCostRecord> {
        self.facts.get(key)
    }

    /// Every bucket identity currently stored, in key order.
    pub fn keys(&self) -> impl Iterator<Item = &UsageKey> + '_ {
        self.facts.keys()
    }

    /// Buckets currently stored.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.facts.len()
    }

    /// Buckets refused because the bounded store was full.
    #[must_use]
    pub fn refused_facts(&self) -> u64 {
        self.refused_facts
    }

    fn entry(&mut self, key: &UsageKey) -> Result<&mut UsageCostRecord, UsageCostError> {
        if let Some(record) = self.facts.get_mut(key) {
            return Ok(record);
        }
        if self.facts.len() >= MAX_USAGE_COST_BUCKETS {
            self.refused_facts = self.refused_facts.saturating_add(1);
            return Err(UsageCostError::BucketStoreFull {
                buckets: MAX_USAGE_COST_BUCKETS,
            });
        }
        let record = UsageCostRecord::empty(key.clone());
        Ok(self.facts.entry(key.clone()).or_insert(record))
    }
}
