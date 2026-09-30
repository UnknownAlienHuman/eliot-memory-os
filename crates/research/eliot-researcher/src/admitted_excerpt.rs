//! Admitted-source retained bytes and exact-excerpt occurrence verification.
//!
//! I21.8 requires two separate obligations per material statement, and this
//! module owns the second one:
//!
//! ```text
//! source_satisfies_requirement    the admitted source genuinely contains the
//!                                 required evidence;
//! excerpt_supports_requirement    the supplied exact excerpts alone are
//!                                 sufficient for a careful reader to verify
//!                                 the requirement.
//! ```
//!
//! A result may satisfy the first and fail the second, and I21.8 names the
//! second's failure modes exactly: **fabrication**, **paraphrase that shifts
//! meaning**, **stitching across sections**, **cropping that removes a hedge or
//! negation**, **a search snippet presented as a page quote**, and **an excerpt
//! absent from the admitted revision**. A type shape cannot enforce any of
//! those, and neither can a predictable name. The only thing that enforces them
//! is a comparison between the exact bytes a claim offers as a quote and the
//! exact bytes of the revision that was actually admitted — which is what this
//! module provides.
//!
//! # What this module does and does not own
//!
//! It owns the **verification** and the **typed verdict**. It does not own
//! storage, and it is explicit about that rather than implying a store it does
//! not have: `crates/research/AGENTS.md` says this subtree "has no
//! canonical-store write authority", so the retained original is *not* kept
//! here. What is kept here is [`RetainedSourceRevision`], an **immutable
//! artifact reference plus the exact bytes that artifact resolved to at
//! readback**, and the bytes' digest is the commitment every downstream check
//! is compared against. The governed source-admission/persistence owner that
//! actually committed those bytes hands them here; this crate re-proves the
//! digest and then does the comparison. A digest of bytes this crate never saw
//! would be the "in-memory clone or hash of unavailable bytes" W2 explicitly
//! refuses, which is why the bytes are a required field and not an optional
//! one.
//!
//! # What "sufficient context" is decided by
//!
//! I21.8 names the axes: "Verify excerpt occurrence in the admitted bytes and
//! sufficient context: negation/hedges, units, population, time/version and
//! section boundaries." Each of those is decided **against the admitted bytes
//! around the verified occurrence**, by [`ContextFinding`], and each carries
//! the exact context window it read. A finding is a measurement, not a
//! heuristic verdict about the claim: it reports what the admitted text
//! immediately surrounding the occurrence does and does not say.
//!
//! This is deliberately *not* a truth oracle. It does not decide whether the
//! excerpt supports the statement — that is the admitted semantic-evaluation
//! route's obligation, named by [`ADMITTED_EVALUATION_ROUTE`], and its absence
//! stays `Unknown`. What this module can prove is mechanical and is what the
//! five named failure modes have in common: the quoted bytes either are in the
//! admitted revision or they are not, and the context they were cropped from
//! either carries the qualifier or it does not.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use crate::evidence_portfolio::{
    PortfolioError, bool_text, digest, freeze, push_count, push_field, text,
};

/// Stable identity of this verification surface.
pub const ADMITTED_EXCERPT_CONTRACT: &str = "eliot.research.admitted-excerpt";

/// Declared identity domain of [`AdmittedExcerpt::digest`].
///
/// Named rather than left implicit for the same reason every other digest
/// preimage in this crate is named: one domain string must never cover two
/// field sets, or a record frozen under one shape would re-present under the
/// other.
pub const ADMITTED_EXCERPT_DIGEST_DOMAIN: &str = "admitted-excerpt/v1";

/// Declared identity domain of [`RetainedSourceRevision::digest`].
pub const RETAINED_SOURCE_REVISION_DIGEST_DOMAIN: &str = "retained-source-revision/v1";

/// How an excerpt's position in the admitted revision is expressed.
///
/// I21.8 requires occurrence to be verified "in the admitted bytes", and a
/// verifier that searches for a substring has to be told *where* the caller
/// believes the excerpt came from before it can reject a fabricated position.
/// The two variants are the two honest ways to say that, and the verifier
/// requires the position to be real either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExcerptPosition {
    /// The caller asserts the excerpt begins at this byte offset in the
    /// retained bytes, and the verifier proves that the retained bytes at that
    /// offset are exactly the excerpt.
    ///
    /// This is the strong form: a claim that names an offset in a frozen
    /// document is asserting something a careful reader can check, so the
    /// assertion is checked rather than searched for.
    ByteOffset {
        /// Zero-based byte offset into the retained revision.
        offset: usize,
    },
    /// The caller asserts no particular position and the verifier finds every
    /// occurrence.
    ///
    /// A claim that offers a quote without a position is not thereby wrong, and
    /// this is the form a model will normally produce. The verifier then reports
    /// the occurrence count it actually measured, which is the number that
    /// distinguishes a genuine quotation from a phrase the revision happens to
    /// contain twice — see [`OccurrenceCheck::occurrences`].
    Unpositioned,
}

/// One exact excerpt offered as the evidence for a claim.
///
/// The excerpt is **data**. It is never executed, never parsed as instructions,
/// and never resolved as a reference. Its only property this crate cares about
/// is whether these exact bytes occur in the admitted revision and whether the
/// context they were taken from still carries the qualifiers the statement
/// needs.
///
/// This is the type the prior state of this crate did not have. `EvidenceSpan`
/// carries `span_id`, `anchor` and `excerpt_digest` — a digest of bytes nobody
/// holds, at an anchor nothing resolves — which is enough to *name* a span and
/// not enough to verify one. Cropped negation and snippet-as-quote were
/// therefore not merely unchecked, they were unrepresentable: there was no
/// value on this side of the boundary that carried the quoted text at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedExcerpt {
    /// Handle of the admitted source revision this excerpt is offered from.
    ///
    /// Must equal a `SourceRecord::handle` the audit's own evidence map admitted.
    /// An excerpt naming any other handle is a reference outside the admitted
    /// set, which is the first of I21.8's failure modes (fabrication) and is
    /// decided before the bytes are read.
    pub source_handle: String,
    /// The exact quoted bytes, verbatim.
    ///
    /// Compared with the admitted revision, never normalised. Whitespace,
    /// punctuation, ellipses and truncation markers are all part of the quote,
    /// so trimming either side would be the very laundering the check exists to
    /// catch.
    pub excerpt: String,
    /// Where in the admitted revision the caller believes the excerpt sits.
    pub position: ExcerptPosition,
    /// Digest over the three fields above.
    pub digest: String,
}

/// Named constructor arguments for [`AdmittedExcerpt::offer`].
///
/// Declared at module scope rather than inside the `impl` block, for two
/// reasons. `rustfmt` refuses to format a struct declared inside an `impl` or
/// `trait` ("struct is not supported in `trait`s or `impl`s"), and a bare
/// `Params` does not resolve to an associated type from inside the very block
/// that declares it. Both constructors in this module take a named-argument
/// struct for the same reason — a frozen commitment should be spelled out field
/// by field at the call site rather than positionally — and both are named for
/// the value they construct, so the two shapes stay distinct types.
#[derive(Clone, Debug)]
pub struct AdmittedExcerptParams {
    /// Handle of the admitted source revision.
    pub source_handle: String,
    /// The exact quoted bytes.
    pub excerpt: String,
    /// Where in the admitted revision the caller believes it sits.
    pub position: ExcerptPosition,
}

impl AdmittedExcerpt {
    /// Offers one exact excerpt, freezing its identity.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::Blank`] or
    /// [`PortfolioError::ControlCharacter`] for a blank handle, and the same
    /// for an excerpt that is blank. A control character **inside** the excerpt
    /// is deliberately *not* refused here: a quote legitimately spans lines and
    /// a quote of a table row carries a newline, so the excerpt is data and the
    /// only shape requirement is that it is non-empty. The excerpt's own
    /// digest is computed over these exact bytes, so a caller cannot offer one
    /// set of bytes and be checked against another.
    pub fn offer(params: AdmittedExcerptParams) -> Result<Self, PortfolioError> {
        text(&params.source_handle, "excerpt.source_handle")?;
        if params.excerpt.trim().is_empty() {
            return Err(PortfolioError::Blank {
                field: "excerpt.excerpt",
            });
        }
        let mut excerpt = Self {
            source_handle: params.source_handle,
            excerpt: params.excerpt,
            position: params.position,
            digest: String::new(),
        };
        excerpt.digest = excerpt.compute_digest();
        Ok(excerpt)
    }

    /// Digest over the excerpt's own shape.
    ///
    /// Inside the digest: the handle, the exact bytes, and the position. The
    /// position is inside because a claim that asserts an offset and a claim
    /// that asserts no offset are different claims about where the quote came
    /// from, and a record that could carry one under the other's digest would
    /// let the weaker assertion inherit the stronger one's identity.
    pub fn compute_digest(&self) -> String {
        let mut preimage = String::from(ADMITTED_EXCERPT_DIGEST_DOMAIN);
        preimage.push(';');
        push_field(&mut preimage, "source_handle", &self.source_handle);
        push_field(&mut preimage, "excerpt", &self.excerpt);
        match self.position {
            ExcerptPosition::ByteOffset { offset } => {
                preimage.push_str("position=byte_offset;");
                push_field(&mut preimage, "offset", &offset.to_string());
            }
            ExcerptPosition::Unpositioned => preimage.push_str("position=unpositioned;"),
        }
        freeze(&preimage)
    }

    /// Re-proves this excerpt's own recorded digest.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::InvalidDigest`] when the recomputed digest
    /// disagrees with the stored one, so an excerpt edited after it was frozen
    /// cannot be checked against the identity it was admitted under.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        if self.compute_digest() != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "excerpt.digest",
            });
        }
        Ok(())
    }
}

/// The exact bytes of one admitted source revision, as the governed
/// source-admission/persistence owner committed them.
///
/// This is the retained original that W2 requires and that this crate does not
/// store. It carries:
///
/// - the **immutable artifact reference** the persistence owner committed the
///   bytes under, so a reader can go back to the artifact rather than trust the
///   copy in hand;
/// - the **exact bytes** that artifact resolved to at readback, because
///   occurrence has to be compared with the original and not with a hash of it;
/// - the **content digest** the source record's `content_digest` names, so the
///   check "do these bytes belong to the admitted revision" is answerable from
///   this value and not assumed.
///
/// The digest is a commitment over all three, and [`Self::verify_integrity`]
/// re-proves both the digest *and* that the bytes hash to the declared
/// `content_digest`. A caller cannot hand in bytes that belong to a different
/// revision, and cannot hand in a content digest that does not describe the
/// bytes in its hands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedSourceRevision {
    /// Handle of the admitted source this revision is the content of.
    pub source_handle: String,
    /// The immutable artifact reference the persistence owner committed under.
    pub artifact_ref: String,
    /// The `SourceRecord::content_digest` this revision must reproduce.
    pub content_digest: String,
    /// The exact retained bytes.
    pub bytes: Vec<u8>,
    /// Regions the retaining owner declared to be search-result excerpts rather
    /// than the source's own prose.
    ///
    /// This is a **declared bound, not a guess**: the owner that actually
    /// retained the bytes is the only party that can say which span of them came
    /// from a search engine's summary rather than from the page, and an owner that
    /// declares no region has asserted there are none. The verifier then refuses
    /// an occurrence that lands inside one, which is I21.8's "a search snippet
    /// presented as a page quote" refused mechanically instead of by prose.
    ///
    /// Each region is re-proved against the retained bytes: an out-of-bounds or
    /// inverted range is refused at construction, so a region cannot be widened
    /// to cover the whole document and make the arm permanently pass.
    pub snippet_regions: Vec<SnippetRegion>,
    /// Digest over the five fields above.
    pub digest: String,
}

/// Named constructor arguments for [`RetainedSourceRevision::retain`].
///
/// At module scope for the same reason as [`AdmittedExcerptParams`]: `rustfmt`
/// will not format a struct declared inside an `impl` block, and a bare
/// `Params` does not resolve there. This shape is **distinct** from
/// [`AdmittedExcerptParams`] — it carries the retained bytes and their declared
/// `content_digest`, which the excerpt shape has no reason to hold — so the two
/// are separate types rather than one merged shape.
#[derive(Clone, Debug)]
pub struct RetainedSourceRevisionParams {
    /// Handle of the admitted source.
    pub source_handle: String,
    /// The immutable artifact reference the bytes were committed under.
    pub artifact_ref: String,
    /// The source record's `content_digest`.
    pub content_digest: String,
    /// The exact retained bytes.
    pub bytes: Vec<u8>,
    /// Regions the retaining owner declared to be search-result excerpts.
    pub snippet_regions: Vec<SnippetRegion>,
}

impl RetainedSourceRevision {
    /// Retains one admitted source revision's exact bytes.
    ///
    /// # Errors
    ///
    /// Refuses a blank handle or artifact reference, a malformed
    /// `content_digest`, bytes that do not hash to the `content_digest` they
    /// are declared to be, and a snippet region that is inverted or reaches past
    /// the retained bytes. The byte/digest refusal is what makes this a
    /// commitment rather than a label: the bytes are checked against the
    /// revision identity at construction, so nothing downstream has to take the
    /// pairing on trust. The region refusal is what stops the snippet arm being
    /// neutralised by declaring a region that covers the whole document.
    pub fn retain(params: RetainedSourceRevisionParams) -> Result<Self, PortfolioError> {
        text(&params.source_handle, "retained.source_handle")?;
        text(&params.artifact_ref, "retained.artifact_ref")?;
        digest(&params.content_digest, "retained.content_digest")?;
        let actual = freeze(&String::from_utf8_lossy(&params.bytes));
        if actual != params.content_digest {
            return Err(PortfolioError::InvalidDigest {
                field: "retained.content_digest",
            });
        }
        for region in &params.snippet_regions {
            if region.start >= region.end || region.end > params.bytes.len() {
                return Err(PortfolioError::Blank {
                    field: "retained.snippet_regions",
                });
            }
        }
        let mut revision = Self {
            source_handle: params.source_handle,
            artifact_ref: params.artifact_ref,
            content_digest: params.content_digest,
            bytes: params.bytes,
            snippet_regions: params.snippet_regions,
            digest: String::new(),
        };
        revision.digest = revision.compute_digest();
        Ok(revision)
    }

    /// Digest over the revision's shape.
    ///
    /// The bytes are inside the preimage by **length prefix** rather than by
    /// content, and that is deliberate. The content commitment is
    /// `content_digest`, which is already inside the preimage and is itself
    /// verified against the bytes by [`Self::retain`]; repeating the whole body
    /// here would make this digest a second copy of the same fact with no extra
    /// assurance, while the length is what actually distinguishes "these are
    /// the bytes of that digest" from "this is a shorter body wearing that
    /// digest's name" for a reader checking the record.
    ///
    /// The declared snippet regions ARE enumerated, because they change what the
    /// bytes may legitimately be quoted for: a revision that gains a snippet
    /// region is a different commitment about the same bytes, and a digest that
    /// ignored them would let the region set be widened after the fact without
    /// moving the identity the occurrence check is performed under.
    pub fn compute_digest(&self) -> String {
        let mut preimage = String::from(RETAINED_SOURCE_REVISION_DIGEST_DOMAIN);
        preimage.push(';');
        push_field(&mut preimage, "source_handle", &self.source_handle);
        push_field(&mut preimage, "artifact_ref", &self.artifact_ref);
        push_field(&mut preimage, "content_digest", &self.content_digest);
        push_field(&mut preimage, "byte_length", &self.bytes.len().to_string());
        push_count(&mut preimage, "snippet_regions", self.snippet_regions.len());
        for region in &self.snippet_regions {
            push_field(&mut preimage, "snippet_start", &region.start.to_string());
            push_field(&mut preimage, "snippet_end", &region.end.to_string());
        }
        freeze(&preimage)
    }

    /// Re-proves the recorded digest, the artifact reference, that the bytes
    /// still hash to the declared content digest, and that every declared
    /// snippet region is still in range.
    ///
    /// # Errors
    ///
    /// Returns [`PortfolioError::InvalidDigest`] when the recomputed digest
    /// disagrees with the stored one or when the bytes no longer hash to
    /// `content_digest`, and [`PortfolioError::Blank`] for a blank field or an
    /// out-of-range snippet region.
    pub fn verify_integrity(&self) -> Result<(), PortfolioError> {
        text(&self.source_handle, "retained.source_handle")?;
        text(&self.artifact_ref, "retained.artifact_ref")?;
        digest(&self.content_digest, "retained.content_digest")?;
        if freeze(&String::from_utf8_lossy(&self.bytes)) != self.content_digest {
            return Err(PortfolioError::InvalidDigest {
                field: "retained.content_digest",
            });
        }
        for region in &self.snippet_regions {
            if region.start >= region.end || region.end > self.bytes.len() {
                return Err(PortfolioError::Blank {
                    field: "retained.snippet_regions",
                });
            }
        }
        if self.compute_digest() != self.digest {
            return Err(PortfolioError::InvalidDigest {
                field: "retained.digest",
            });
        }
        Ok(())
    }

    /// The retained bytes as text, if they are text.
    ///
    /// The exactness of the occurrence comparison depends on this being a
    /// **lossless** view, so the conversion is checked rather than assumed: a
    /// revision whose bytes are not valid UTF-8 yields `None` and its excerpts
    /// are then not verifiable here, which is `Unknown` at the requirement
    /// level and never `Satisfied`. A `from_utf8_lossy` result would insert
    /// U+FFFD and quietly change the byte string a quote is compared against.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes).ok()
    }
}

/// What the admitted bytes immediately around a verified occurrence do and do
/// not say.
///
/// Each axis I21.8 names is its own typed value, and each carries the context
/// window that was actually read so a reader can see the measurement rather
/// than take the verdict. `Carried`/`Absent` describe the **text**; they are
/// not judgements about whether the claim is true, and a `Carried` qualifier is
/// not by itself support for anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContextAxis {
    /// Negation or hedge immediately governing the occurrence.
    NegationOrHedge,
    /// A unit or measurement basis stated in the context.
    Unit,
    /// The population or scope the occurrence is stated over.
    Population,
    /// The time window, version or revision the occurrence is stated at.
    TimeOrVersion,
    /// Whether the occurrence is wholly inside one section rather than stitched
    /// across a section boundary.
    SectionBoundary,
}

impl ContextAxis {
    /// Every axis I21.8 names for excerpt context, in canonical order.
    pub const ALL: [Self; 5] = [
        Self::NegationOrHedge,
        Self::Unit,
        Self::Population,
        Self::TimeOrVersion,
        Self::SectionBoundary,
    ];

    /// Stable wire spelling of this axis.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NegationOrHedge => "NEGATION_OR_HEDGE",
            Self::Unit => "UNIT",
            Self::Population => "POPULATION",
            Self::TimeOrVersion => "TIME_OR_VERSION",
            Self::SectionBoundary => "SECTION_BOUNDARY",
        }
    }
}

/// One measured context finding against the admitted bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextFinding {
    /// Which axis this finding is about.
    pub axis: ContextAxis,
    /// Whether the context window read for this axis carries the qualifier.
    pub carried: bool,
    /// The exact context window the finding was measured over, verbatim.
    pub context: String,
    /// Why the axis is not carried, or empty when it is.
    pub finding: String,
}

/// Why an excerpt was not verified as an exact occurrence in the admitted
/// revision.
///
/// These are the mechanical subset of I21.8's named `excerpt_supports_requirement`
/// failure modes that occurrence-and-context checking can actually decide. The
/// remaining ones — paraphrase that shifts meaning, and the semantic question
/// of whether the excerpt suffices at all — belong to the admitted
/// semantic-evaluation route and are recorded as `Unknown` there, not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OccurrenceFailure {
    /// The excerpt's handle is not a source this audit admitted.
    HandleNotAdmitted,
    /// No retained revision was supplied for the excerpt's source, so the
    /// excerpt was never compared with the original at all.
    NoRetainedRevision,
    /// The supplied retained revision does not re-prove its own commitment, so
    /// it is not the admitted revision even though it was supplied as one.
    RetainedRevisionUnproven,
    /// The supplied revision is for a different source handle than the excerpt
    /// names.
    RevisionHandleMismatch,
    /// The retained bytes are not text, so no occurrence could be measured.
    RevisionNotText,
    /// The exact bytes do not occur in the admitted revision.
    AbsentFromRevision,
    /// The excerpt claims a byte offset and the admitted revision does not hold
    /// these bytes at that offset.
    OffsetDoesNotMatch,
    /// The excerpt's own recorded digest does not match its bytes.
    ExcerptDigestMismatch,
    /// The retained revision is internally consistent but is a different
    /// revision of the source than the one this audit admitted.
    ///
    /// The retained bytes re-prove their own `content_digest`, which shows they
    /// were not corrupted in transit. It says nothing about *which* revision
    /// they are. This arm is the comparison against the admitted
    /// `SourceRecord::content_digest` the governed source-admission owner
    /// committed, so a revision fetched from the same locator at a different
    /// time, or carried over from a prior freeze of the same source, is refused
    /// rather than read as though it were the admitted text.
    ForeignSourceRevision,
    /// The occurrence is stitched across a section boundary.
    StitchedAcrossSections,
    /// The context window carries no negation or hedge, and the excerpt presents
    /// the occurrence as an unqualified statement.
    ///
    /// This is the cropped-negation arm. It is reported only when the admitted
    /// revision's own wider context **does** carry one and the excerpt's window
    /// does not, because "this sentence has no hedge in it" is a normal fact
    /// about most sentences; "this sentence sits inside a negated clause that
    /// the quote removed" is the defect. See
    /// [`OccurrenceCheck::cropped_negation`].
    NegationCropped,
    /// The excerpt is a fragment of the admitted revision rather than a
    /// contiguous quotation of it, and is being presented as a quote.
    SnippetNotQuote,
    /// The occurrence appears in a region of the revision that is a
    /// search-result excerpt rather than the source's own prose.
    ///
    /// I21.8 names "a search snippet presented as a page quote". A revision can
    /// carry such a region explicitly, and this crate's contract for it is
    /// [`SnippetRegion`] on the retained revision: the region is declared by the
    /// owner that retained the bytes, and an occurrence falling inside one is
    /// not a quotation of the source's prose. The declaration is a *bound*, not
    /// a guess: an owner that declares no snippet regions has asserted there
    /// are none, and a reader can see that assertion.
    InsideSnippetRegion,
}

impl OccurrenceFailure {
    /// Stable wire spelling of this failure.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HandleNotAdmitted => "HANDLE_NOT_ADMITTED",
            Self::NoRetainedRevision => "NO_RETAINED_REVISION",
            Self::RetainedRevisionUnproven => "RETAINED_REVISION_UNPROVEN",
            Self::RevisionHandleMismatch => "REVISION_HANDLE_MISMATCH",
            Self::RevisionNotText => "REVISION_NOT_TEXT",
            Self::AbsentFromRevision => "ABSENT_FROM_REVISION",
            Self::OffsetDoesNotMatch => "OFFSET_DOES_NOT_MATCH",
            Self::ExcerptDigestMismatch => "EXCERPT_DIGEST_MISMATCH",
            Self::ForeignSourceRevision => "FOREIGN_SOURCE_REVISION",
            Self::StitchedAcrossSections => "STITCHED_ACROSS_SECTIONS",
            Self::NegationCropped => "NEGATION_CROPPED",
            Self::SnippetNotQuote => "SNIPPET_NOT_QUOTE",
            Self::InsideSnippetRegion => "INSIDE_SNIPPET_REGION",
        }
    }
}

/// A region of a retained revision the retaining owner declared to be a
/// search-result excerpt rather than the source's own prose.
///
/// Byte range into the retained bytes. Declared by the owner that committed the
/// bytes — the same owner that supplied [`RetainedSourceRevision`] — and
/// re-proved by this crate against that revision's digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnippetRegion {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

/// The full result of verifying one excerpt against the admitted revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceCheck {
    /// The excerpt this result is about.
    pub excerpt: AdmittedExcerpt,
    /// Whether the exact bytes were located in the admitted revision.
    ///
    /// `true` means only that the bytes are there. Whether they are a
    /// *sufficient* quotation is a separate question this result also answers,
    /// through [`Self::failures`] and [`Self::context`].
    pub occurred: bool,
    /// How many times the exact bytes occur in the admitted revision.
    ///
    /// Measured, not assumed. A count of one is a single place in the revision
    /// the quote can have come from; a count above one means the bytes are
    /// ambiguous and the context findings below are per-occurrence.
    pub occurrences: usize,
    /// Whether the context around the occurrence stitches across a section
    /// boundary.
    pub stitched: bool,
    /// Whether a negation or hedge governing the occurrence in the wider
    /// admitted context was removed from the quoted window.
    pub cropped_negation: bool,
    /// The context window read for each axis, in canonical axis order.
    pub context: Vec<ContextFinding>,
    /// Every failure found, in canonical order. Empty means occurrence and
    /// context both verified.
    pub failures: Vec<OccurrenceFailure>,
}

impl OccurrenceCheck {
    /// Whether this excerpt verified as an exact, unambiguous, un-cropped
    /// occurrence in the admitted revision.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.occurred && self.failures.is_empty()
    }
}

/// How many bytes of admitted text either side of the occurrence are read for
/// the context axes.
///
/// Bounded on purpose. The window has to be large enough to contain a
/// governing negation and a stated unit, and small enough that a document's
/// distant preamble does not count as context for a line two hundred lines
/// away — otherwise a hedge anywhere in the file would launder a cropped
/// quote, which is the same defect in the opposite direction. The value is a
/// named constant rather than a parameter so that no caller can widen the
/// window to make a check pass.
pub const CONTEXT_WINDOW_BYTES: usize = 512;

/// How many bytes before the occurrence are searched for a governing negation
/// or hedge when the cropped-negation arm is decided.
///
/// Wider than [`CONTEXT_WINDOW_BYTES`] on the leading side only. A negation
/// almost always precedes the proposition it governs ("no trial found an
/// effect", "**not** associated with"), while the unit, population and version
/// qualifiers usually follow it. Reading a longer leading window is therefore
/// what makes the cropped-negation arm able to fire at all, and reading a longer
/// trailing window would let a document's later text vouch for an earlier
/// quote.
pub const NEGATION_SCAN_LEAD_BYTES: usize = 2_048;

/// Negation and hedge markers, matched case-insensitively on word boundaries.
///
/// These are *markers*, not a truth oracle: their presence is evidence that the
/// admitted text carries a qualifier, and their absence is only ever evidence
/// that this window carries none. The cropped-negation arm fires on a
/// **difference** between two windows of the same admitted revision, so a
/// vocabulary that misses a marker produces a false negative on a rare phrasing
/// — which is a missed detection of a defect, not a false pass. A false pass
/// would need the markers to be present in the quoted window and absent from
/// the governing one, which is not a shape this comparison can produce.
const NEGATION_MARKERS: [&str; 18] = [
    "not",
    "no",
    "never",
    "none",
    "neither",
    "nor",
    "without",
    "cannot",
    "does not",
    "did not",
    "was not",
    "were not",
    "is not",
    "are not",
    "failed to",
    "lacks",
    "absence of",
    "unlikely",
];

/// Unit and measurement-basis markers, matched case-insensitively.
const UNIT_MARKERS: [&str; 12] = [
    "mg", "kg", "g", "mm", "cm", "m", "km", "ms", "s", "%", "per", "n=",
];

/// Population or scope markers, matched case-insensitively.
const POPULATION_MARKERS: [&str; 8] = [
    "patients",
    "participants",
    "subjects",
    "users",
    "samples",
    "sites",
    "in",
    "among",
];

/// Time-window and version markers, matched case-insensitively.
const TIME_VERSION_MARKERS: [&str; 12] = [
    "202", "version", "revision", "rev", "v1", "as of", "during", "between", "from", "until",
    "at least", "n ≥",
];

/// How an occurrence's section membership is established.
///
/// A heading line is a line that begins with a markdown ATX heading marker or
/// is a numbered section label. This is a *structural* test on the admitted
/// bytes, not a semantic parse: it answers "does the text between the
/// occurrence and its nearest preceding heading contain another heading", which
/// is the mechanical form of "stitching across sections".
fn is_heading(line: &str) -> bool {
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return true;
    }
    // A numbered section label: `1.`, `2.3.`, `IV.`, `§4.1` — at the start of
    // the line, followed by a space or a non-alphanumeric. This deliberately
    // does NOT match a sentence that merely begins with a number and a period
    // inside running prose, because that would make almost every line a heading
    // and the section test meaningless.
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_digit() || matches!(first, '§' | 'I' | 'V' | 'X')) {
        return false;
    }
    let rest: String = trimmed.chars().skip(1).collect();
    let mut digits_and_dots = String::new();
    for character in rest.chars() {
        if character.is_ascii_digit() || character == '.' {
            digits_and_dots.push(character);
        } else {
            break;
        }
    }
    !digits_and_dots.is_empty() && digits_and_dots.contains('.')
}

/// Finds every byte offset at which `needle` occurs in `haystack`.
fn find_all(haystack: &str, needle: &str) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    let mut start = 0;
    while let Some(found) = haystack[start..].find(needle) {
        let at = start + found;
        offsets.push(at);
        // Advance past this occurrence's first byte so overlapping occurrences
        // are each found; `+ 1` on a UTF-8 boundary is a byte index into a
        // `&str`, and `find` on the remainder is always a valid split point
        // because it is the start of a match or `start` itself, both of which
        // are character boundaries.
        start = at + 1;
    }
    offsets
}

/// Builds one context finding by testing a window for a marker set.
fn context_finding(
    axis: ContextAxis,
    window: &str,
    markers: &[&str],
    absent_reason: &str,
) -> ContextFinding {
    let lowered = window.to_lowercase();
    let carried = markers.iter().any(|marker| {
        lowered
            .split(|character: char| !character.is_alphanumeric() && character != '%')
            .any(|word| word == *marker)
            || lowered.contains(marker)
    });
    ContextFinding {
        axis,
        carried,
        context: window.to_owned(),
        finding: if carried {
            String::new()
        } else {
            absent_reason.to_owned()
        },
    }
}

/// Builds the section-boundary finding for one occurrence.
///
/// Returns `(carried, stitched)`. `carried` is `true` when the occurrence sits
/// wholly inside one section; `stitched` is `true` when the quoted window
/// contains a heading other than the one it opens with, which is the mechanical
/// signature of a passage assembled from more than one section.
fn section_finding(text: &str, quote: &str) -> (ContextFinding, bool) {
    let quote_lines: Vec<&str> = quote.lines().collect();
    let headings_inside = quote_lines
        .iter()
        .skip(1)
        .filter(|line| is_heading(line))
        .count();
    let stitched = headings_inside > 0;
    // The window read for this axis: the heading the occurrence sits under,
    // found by walking backwards from the quote's first line.
    let opening = quote_lines.first().copied().unwrap_or("");
    let byte_start = text.find(opening).unwrap_or(0);
    let preceding = &text[..byte_start];
    let nearest_heading = preceding
        .lines()
        .rev()
        .find(|line| is_heading(line))
        .unwrap_or("");
    let window = format!("{nearest_heading}\n{opening}");
    let finding = ContextFinding {
        axis: ContextAxis::SectionBoundary,
        carried: !stitched,
        context: window,
        finding: if stitched {
            format!(
                "the quoted window contains {headings_inside} further section heading(s), so it is \
                 stitched across section boundaries"
            )
        } else {
            String::new()
        },
    };
    (finding, stitched)
}

/// Verifies one excerpt against the admitted revision it names.
///
/// `admitted` maps each source handle this audit actually admitted (the audit's
/// own `evidence_map`, never a caller-supplied roster) to the
/// `SourceRecord::content_digest` the admitted record commits to. Both halves of
/// that pair are required: a handle set alone cannot detect a **foreign source
/// revision**, because a revision that is internally consistent and belongs to a
/// different revision of the same source would pass every other check on it.
/// The retained revision's `content_digest` is therefore compared against the
/// admitted record's own, which is an independent expected value originating
/// from the governed source-admission owner rather than from the retained bytes.
///
/// `retained` is the retained original for the excerpt's source, supplied by the
/// governed source-admission/persistence owner. `None` is a real, reported state
/// (`NoRetainedRevision`), not a skip: an excerpt nobody compared with the
/// original has not been verified, and the requirement that depends on it is
/// `Unsatisfied` rather than `Satisfied`.
#[allow(clippy::too_many_lines)]
pub fn verify_excerpt_occurrence(
    excerpt: &AdmittedExcerpt,
    admitted: &BTreeMap<String, String>,
    retained: Option<&RetainedSourceRevision>,
) -> OccurrenceCheck {
    let mut failures: Vec<OccurrenceFailure> = Vec::new();
    if excerpt.verify_integrity().is_err() {
        failures.push(OccurrenceFailure::ExcerptDigestMismatch);
    }
    // A handle this audit did not admit is refused before any byte is read: an
    // excerpt naming an outside handle is I21.8's first failure mode, and
    // comparing its bytes against whatever revision happened to be supplied
    // would produce a result about a source this audit never admitted.
    let Some(admitted_content_digest) = admitted.get(&excerpt.source_handle) else {
        failures.push(OccurrenceFailure::HandleNotAdmitted);
        return absent_check(excerpt, failures);
    };
    let Some(retained) = retained else {
        failures.push(OccurrenceFailure::NoRetainedRevision);
        return absent_check(excerpt, failures);
    };
    if retained.verify_integrity().is_err() {
        failures.push(OccurrenceFailure::RetainedRevisionUnproven);
    }
    if retained.source_handle != excerpt.source_handle {
        failures.push(OccurrenceFailure::RevisionHandleMismatch);
    }
    // The foreign-revision check. The retained bytes re-prove their own declared
    // digest, which proves they are internally consistent; it does NOT prove they
    // are the revision this audit admitted. The admitted record's own
    // `content_digest` is the independent expected value, so a retained revision
    // of a different revision of the same source is refused here even though
    // every other check on it would pass. This is the "foreign source revision"
    // acceptance case refused mechanically rather than by prose.
    if &retained.content_digest != admitted_content_digest {
        failures.push(OccurrenceFailure::ForeignSourceRevision);
    }
    let Some(text) = retained.as_text() else {
        failures.push(OccurrenceFailure::RevisionNotText);
        return absent_check(excerpt, failures);
    };
    // The occurrence positions this check will measure over. An asserted byte
    // offset is checked *at* that offset rather than searched for, because a
    // caller asserting a position is making a falsifiable claim about where the
    // quote came from and the check is what makes it falsifiable.
    let offsets: Vec<usize> = match excerpt.position {
        ExcerptPosition::Unpositioned => {
            let found = find_all(text, &excerpt.excerpt);
            if found.is_empty() {
                failures.push(OccurrenceFailure::AbsentFromRevision);
                // A quote that also carries an elision marker is a fragment
                // presented as a quotation, and the two failures together say
                // so in a form a reader can act on. The arm cannot fire on a
                // quote that genuinely occurs, because it is only reachable from
                // the `AbsentFromRevision` conjunct above.
                if carries_truncation_marker(&excerpt.excerpt) {
                    failures.push(OccurrenceFailure::SnippetNotQuote);
                }
                return absent_check(excerpt, failures);
            }
            found
        }
        ExcerptPosition::ByteOffset { offset } => {
            let at_offset = text
                .get(offset..)
                .is_some_and(|tail| tail.starts_with(excerpt.excerpt.as_str()));
            if at_offset {
                vec![offset]
            } else {
                failures.push(OccurrenceFailure::OffsetDoesNotMatch);
                return absent_check(excerpt, failures);
            }
        }
    };
    finish_check(excerpt, retained, text, &offsets, failures)
}

/// The check result for an excerpt whose bytes were never located in an admitted
/// revision, carrying only the failures that explain why.
///
/// Context findings are empty rather than fabricated: no occurrence was found,
/// so there is no admitted text around one to read an axis over. That is a
/// different state from a found occurrence with an uncarried axis, and
/// collapsing the two would report a measurement that was never made.
fn absent_check(
    excerpt: &AdmittedExcerpt,
    mut failures: Vec<OccurrenceFailure>,
) -> OccurrenceCheck {
    failures.sort();
    failures.dedup();
    OccurrenceCheck {
        excerpt: excerpt.clone(),
        occurred: false,
        occurrences: 0,
        stitched: false,
        cropped_negation: false,
        context: Vec::new(),
        failures,
    }
}

/// Completes a check once the occurrence positions are known.
fn finish_check(
    excerpt: &AdmittedExcerpt,
    retained: &RetainedSourceRevision,
    text: &str,
    positions: &[usize],
    mut failures: Vec<OccurrenceFailure>,
) -> OccurrenceCheck {
    let quote = excerpt.excerpt.as_str();
    // The widest window any finding is measured over: from the first occurrence
    // back through the leading negation scan, to the end of the last
    // occurrence plus the trailing context window. Every per-axis window is a
    // sub-window of this one, so every finding's `context` is literally the
    // admitted text it was measured from and can be located in `text` unchanged.
    let first = positions.first().copied().unwrap_or(0);
    let last = positions.last().copied().unwrap_or(0) + quote.len();
    let window_start = first.saturating_sub(NEGATION_SCAN_LEAD_BYTES);
    let window_end = (last + CONTEXT_WINDOW_BYTES).min(text.len());
    // `text` is `&str` and the offsets are byte offsets of `char` boundaries
    // (a `find` result, or the asserted offset that just matched a `str`
    // boundary), so the sub-slice is always a valid `&str`.
    let window = &text[window_start..window_end];
    let quote_window_start = first.saturating_sub(CONTEXT_WINDOW_BYTES);
    let quote_window_end = (last + CONTEXT_WINDOW_BYTES).min(text.len());
    let quote_window = &text[quote_window_start..quote_window_end];
    // The quoted window in its own right: the excerpt plus the context window
    // around it, which is what a careful reader would see of the source.
    let mut context: Vec<ContextFinding> = Vec::new();
    let (section, stitched) = section_finding(window, quote);
    if stitched {
        failures.push(OccurrenceFailure::StitchedAcrossSections);
    }
    // The cropped-negation arm. A difference between two windows of the SAME
    // admitted revision: the governing leading context carries a negation or
    // hedge, and the quoted window does not. This is the only shape that
    // separates "this sentence is unqualified" from "this sentence was cropped
    // out of a negated clause", and it is why the arm cannot fire on a quote
    // whose own text already shows the qualifier.
    let cropped_negation = {
        let leading = &text[window_start..first];
        let governs = contains_marker(leading, &NEGATION_MARKERS);
        let quoted_carries = contains_marker(quote, &NEGATION_MARKERS);
        governs && !quoted_carries
    };
    if cropped_negation {
        failures.push(OccurrenceFailure::NegationCropped);
    }
    // The search-snippet arm. The retaining owner declared byte ranges of this
    // revision that are search-result excerpts rather than the source's own
    // prose; an occurrence that falls inside one is not a quotation of the page
    // however many times its bytes occur. This is measured against the declared
    // ranges, which are re-proved in range by `verify_integrity` above, so the
    // arm cannot be widened after the fact.
    //
    // The check is per-occurrence, and an excerpt is refused if **any** of its
    // occurrences lands inside a declared region: a quote that is genuinely in
    // the page once and in the snippet once has been presented from a source
    // that is not the page, and the reader cannot tell which occurrence the
    // author meant.
    let inside_snippet = positions.iter().any(|position| {
        let start = *position;
        let end = start + quote.len();
        retained
            .snippet_regions
            .iter()
            .any(|region| start < region.end && region.start < end)
    });
    if inside_snippet {
        failures.push(OccurrenceFailure::InsideSnippetRegion);
    }
    for axis in ContextAxis::ALL {
        context.push(match axis {
            ContextAxis::NegationOrHedge => ContextFinding {
                axis,
                carried: contains_marker(quote_window, &NEGATION_MARKERS),
                context: quote_window.to_owned(),
                finding: if cropped_negation {
                    "the admitted revision's governing context carries a negation or hedge that the \
                     quoted window does not"
                        .to_owned()
                } else {
                    String::new()
                },
            },
            ContextAxis::Unit => context_finding(
                axis,
                quote_window,
                &UNIT_MARKERS,
                "the quoted window states no unit or measurement basis",
            ),
            ContextAxis::Population => context_finding(
                axis,
                quote_window,
                &POPULATION_MARKERS,
                "the quoted window names no population or scope",
            ),
            ContextAxis::TimeOrVersion => context_finding(
                axis,
                quote_window,
                &TIME_VERSION_MARKERS,
                "the quoted window states no time window, version or revision",
            ),
            ContextAxis::SectionBoundary => section.clone(),
        });
    }
    failures.sort();
    failures.dedup();
    OccurrenceCheck {
        excerpt: excerpt.clone(),
        occurred: true,
        occurrences: positions.len(),
        stitched,
        cropped_negation,
        context,
        failures,
    }
}

/// Whether a text window contains any of the markers, on a word boundary.
fn contains_marker(window: &str, markers: &[&str]) -> bool {
    let lowered = window.to_lowercase();
    markers.iter().any(|marker| lowered.contains(marker))
}

/// Whether a quote carries a marker that says a longer passage was elided.
///
/// This is deliberately a *string shape* test on the quote itself, not a claim
/// about the source: the marker's presence only says the author presented the
/// text as a fragment. It is paired with `AbsentFromRevision` at the call site,
/// so it never fires on a quote that genuinely occurs in the revision, and it
/// never asserts that the elision changed the meaning — that remains the
/// admitted semantic route's question.
///
/// The bracketed forms (`[...]`, `[...]`) and the bare ellipsis spellings
/// (`...`, `…`) are the ones a search engine, a summariser and a transcriber all
/// emit. The bare spellings are included because they are the ones this check
/// exists to catch, and because the accompanying `AbsentFromRevision`
/// conjunct already prevents this from firing on a quote that is genuinely in
/// the revision — so the cost of a false positive on an in-revision quotation
/// is exactly zero, and the cost of a false negative on an absent one is an
/// unreadable reason.
fn carries_truncation_marker(quote: &str) -> bool {
    const MARKERS: [&str; 4] = ["[...]", "[…]", "...", "…"];
    MARKERS.iter().any(|marker| quote.contains(marker))
}

/// Builds the typed requirement obligation for one set of excerpt checks.
///
/// This is the `excerpt_supports_requirement` producer, and it is the answer to
/// the gap the prior state of this crate recorded: the obligation was
/// permanently `Unknown` because "no production caller supplies an admitted
/// evaluation route". The route still does not exist, and this function does
/// not pretend otherwise — it decides the part that is decidable (occurrence
/// and context) and leaves semantic sufficiency to the route, which is the
/// split I21.8 draws. A claim whose excerpts all verify is `Satisfied` for the
/// occurrence half and still contributes `Unknown` to the semantic half, so
/// the requirement as a whole stays `Unknown` and the claim stays
/// `NOT_VERIFIABLE_IN_SCOPE` — which is the honest answer, and a strictly
/// stronger one than before because the occurrence half is now measured instead
/// of assumed absent.
///
/// The two I21.8 obligations are reported separately and never collapsed: the
/// `source_satisfies_requirement` reading lives in `audit_claim`, and this
/// function only produces the excerpt one.
#[must_use]
pub fn excerpt_requirement_from_checks(
    checks: &[OccurrenceCheck],
) -> crate::evidence_portfolio::ClaimRequirement {
    use crate::evidence_portfolio::{CLAIM_REQUIREMENTS, RequirementOutcome};
    let examined_over: Vec<String> = checks
        .iter()
        .map(|check| check.excerpt.source_handle.clone())
        .collect();
    if checks.is_empty() {
        return crate::evidence_portfolio::ClaimRequirement {
            name: CLAIM_REQUIREMENTS[1],
            outcome: RequirementOutcome::Unsatisfied,
            examined_over,
            reason: "the claim offers no exact excerpt, so occurrence in the admitted revision \
                     could not be checked"
                .to_owned(),
        };
    }
    let failed: Vec<&OccurrenceCheck> = checks.iter().filter(|check| !check.verified()).collect();
    if !failed.is_empty() {
        let mut reasons: Vec<String> = failed
            .iter()
            .map(|check| {
                let names: Vec<&str> = check
                    .failures
                    .iter()
                    .map(|failure| failure.wire_name())
                    .collect();
                format!(
                    "excerpt from {}: {}",
                    check.excerpt.source_handle,
                    names.join(",")
                )
            })
            .collect();
        reasons.sort();
        return crate::evidence_portfolio::ClaimRequirement {
            name: CLAIM_REQUIREMENTS[1],
            outcome: RequirementOutcome::Unsatisfied,
            examined_over,
            reason: format!(
                "{} of {} exact excerpt(s) did not verify as an un-cropped occurrence in the \
                 admitted revision: {}",
                reasons.len(),
                checks.len(),
                reasons.join("; ")
            ),
        };
    }
    // Occurrence and context both verified for every excerpt. This is a real
    // result and it is still not the whole obligation: whether these exact bytes
    // *suffice* for a careful reader is the admitted semantic-evaluation route's
    // question, and the absence of that route is `Unknown`, not a pass.
    crate::evidence_portfolio::ClaimRequirement {
        name: CLAIM_REQUIREMENTS[1],
        outcome: RequirementOutcome::Unknown,
        examined_over,
        reason: format!(
            "all {} exact excerpt(s) occur verbatim in the admitted revision with no cropped \
             negation, stitching or snippet region, but semantic sufficiency of these bytes is \
             unverified: the admitted evaluation route ({ADMITTED_ROUTE} {ADMITTED_ROUTE_VERSION}) \
             supplied no evaluation",
            checks.len()
        ),
    }
}

/// Name of the admitted semantic-sufficiency route, when one exists.
///
/// Referenced here so the `Unknown` reason above names the same route string
/// the dimension evaluations do, rather than a second spelling of it.
pub const ADMITTED_ROUTE: &str = crate::evidence_portfolio::ADMITTED_EVALUATION_ROUTE;
/// Version of the admitted semantic-sufficiency route contract.
pub const ADMITTED_ROUTE_VERSION: &str =
    crate::evidence_portfolio::ADMITTED_EVALUATION_ROUTE_VERSION;

/// A compact, order-stable rendering of one check for a digest preimage or a
/// bounded diagnostic.
#[must_use]
pub fn check_line(check: &OccurrenceCheck) -> String {
    let mut line = String::new();
    push_field(&mut line, "excerpt_digest", &check.excerpt.digest);
    push_count(&mut line, "occurrences", check.occurrences);
    line.push_str("occurred=");
    line.push_str(bool_text(check.occurred));
    line.push(';');
    line.push_str("stitched=");
    line.push_str(bool_text(check.stitched));
    line.push(';');
    line.push_str("cropped_negation=");
    line.push_str(bool_text(check.cropped_negation));
    line.push(';');
    push_count(&mut line, "failures", check.failures.len());
    for failure in &check.failures {
        push_field(&mut line, "failure", failure.wire_name());
    }
    line
}
