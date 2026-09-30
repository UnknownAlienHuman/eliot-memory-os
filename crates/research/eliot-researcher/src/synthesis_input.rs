//! The committed-freeze proof and the governed synthesis-input pack (I21.8).
//!
//! W2 requires the freeze to be committed through the governed source-admission
//! owner **before** synthesis is admitted, and the retained original to be bound
//! to that committed freeze. W3 requires the actual synthesis pack to be built
//! **from that freeze**, resolving only its admitted included members under the
//! current disclosure manifest and reference manifest.
//!
//! # Why the commit travels the admission owner's request
//!
//! The freeze is committed by
//! [`crate::source_admissibility::SourceAdmissibilityRecord::transition_request_committing_freeze`],
//! which produces a
//! [`crate::source_admissibility::GovernorSourceTransitionRequest`] carrying a
//! [`crate::source_admissibility::FreezeCommitment`]. That request is the
//! **existing** governed source-admission owner: it already had a domain
//! (`inquiry-source-admission-request/v1`, now `v2`), a canonical preimage and a
//! `validate_integrity` that re-proves its own digest. The commitment is inside
//! that preimage, so the commit is proven by the owner that already exists rather
//! than by a second freeze owner, a second digest domain or a parallel validator.
//!
//! This module therefore adds **no** digest scheme. Its only job is the two
//! things the request cannot do by itself:
//!
//! 1. [`CommittedFreeze`] — a value that is only obtainable once a set of
//!    admission requests has validated, so "the freeze is committed" is a state a
//!    caller cannot reach by assembling the fields by hand; and
//! 2. [`SynthesisInputPack`] — the pack W3 asks for, whose member set is derived
//!    from the freeze's admitted included members and filtered by the run-bound
//!    reference manifest and the admitted disclosure class, so a member that the
//!    freeze excluded, the manifest revoked or the disclosure class forbids is
//!    reported as an explicit limitation rather than silently omitted.
//!
//! # What this module does not do
//!
//! It performs no acquisition, no retrieval of bytes it does not already hold, no
//! model execution and no release authorization. The pack it produces is
//! candidate input to a pure synthesis owner; whether that owner is reached, and
//! what it does with the pack, is the caller's decision. Nothing here promotes
//! anything to canonical state, and nothing here publishes an authority it was
//! not granted.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use eliot_research_exchange_api::{AllowedReferenceManifest, DisclosureClass};

use crate::evidence_portfolio::{SourceRecord, bool_text, freeze, push_count, push_field, text};
use crate::inquiry_governance::{EvidenceFreeze, InquiryError, LaneDisciplineOutcome};
use crate::source_admissibility::GovernorSourceTransitionRequest;

/// Declared identity domain of [`CommittedFreeze::digest`].
///
/// Named because every other digest preimage in this crate is named: one domain
/// string must never cover two field sets. `v1` is the first spelling.
pub const COMMITTED_FREEZE_DIGEST_DOMAIN: &str = "committed-freeze/v1";

/// Declared identity domain of [`SynthesisInputPack::digest`].
pub const SYNTHESIS_INPUT_PACK_DIGEST_DOMAIN: &str = "synthesis-input-pack/v1";

/// Disclosure breadth, narrowest first.
///
/// Mirrors the exchange contract's own `disclosure_breadth` ordering — a
/// manifest's class may be narrower than the request that carries it and never
/// wider, so the comparison needs an explicit breadth. The ordering is restated
/// rather than imported because the exchange contract keeps that helper private;
/// the *decision* it encodes (never wider than the admitted class) is I21.7's and
/// is enforced below, not delegated to a label.
const fn disclosure_breadth(class: DisclosureClass) -> u8 {
    match class {
        DisclosureClass::Private => 0,
        DisclosureClass::ProjectBound => 1,
        DisclosureClass::ExportableRedacted => 2,
        DisclosureClass::Public => 3,
    }
}

/// Proof that the evidence freeze is committed through the governed
/// source-admission owner, with the retained original bound to it.
///
/// This value is **only** obtainable through [`CommittedFreeze::commit`], which
/// requires every supplied admission request to re-prove its own digest through
/// the owner's existing `validate_integrity` first. That is what makes it a proof
/// rather than a claim: a caller that wants a `CommittedFreeze` cannot
/// assemble one by naming a digest, because the only constructor takes the
/// requests themselves and re-proves each of them.
///
/// W2's ordering requirement is carried structurally by
/// [`crate::source_admissibility::GovernorSourceTransitionRequest::freeze_commit`]
/// living inside that request's own digest: a request that names no freeze is
/// visibly a pre-freeze proposal and is refused here, so a freeze cannot be
/// "committed" after the fact by a record that never carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFreeze {
    /// Identity of the committed evidence freeze.
    pub freeze_id: String,
    /// Digest of the committed evidence freeze, as the freeze itself computed it.
    pub freeze_digest: String,
    /// Inquiry the freeze covers.
    pub inquiry_id: String,
    /// Evidence set the freeze covers.
    pub evidence_set_id: String,
    /// The admitted included members, each bound to the retained original the
    /// admission owner committed for it.
    ///
    /// Ordered by handle so the digest does not move when two requests arrive in
    /// a different order. The retained content digest on each entry is the value
    /// the *admission record* committed, so a reader can compare a retained
    /// revision against an independent expected value without re-running the
    /// commit.
    pub members: Vec<CommittedFreezeMember>,
    /// The admission requests' own digests, canonical order.
    ///
    /// These are the existing owner's own commitments. Carrying them means a
    /// reader can re-derive the whole commit from the requests alone, rather than
    /// trusting this record's summary of them.
    pub admission_request_digests: Vec<String>,
    /// Digest over the five fields above.
    pub digest: String,
}

/// One admitted included member of a committed freeze.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedFreezeMember {
    /// The source handle.
    pub source_handle: String,
    /// The admitted revision's content digest, as the admission record committed
    /// it.
    pub content_digest: String,
    /// Digest of the retained-revision record over its own shape.
    pub retained_revision_digest: String,
    /// The immutable artifact reference the original was committed under.
    pub retained_artifact_ref: String,
}

impl CommittedFreeze {
    /// Commits a freeze through the governed source-admission owner.
    ///
    /// The freeze is committed here, in the sense I21.8 requires, by refusing
    /// every request that does not already carry it: each request must re-prove
    /// its own digest through the existing owner's validator, must name this
    /// exact freeze, and must name a retained original whose content digest is
    /// the admitted record's own. A run whose requests were built by
    /// `transition_request` (which names no freeze) cannot produce a
    /// `CommittedFreeze` at all, so "synthesis was admitted before the freeze was
    /// committed" is unrepresentable rather than merely discouraged.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::UnknownHandle`] when `requests` is empty — there is
    /// nothing to commit, and an empty commit would be a freeze that admits
    /// nothing. Returns [`InquiryError::IntegrityMismatch`] when a request does
    /// not re-prove its own digest, names no freeze commitment, names a different
    /// freeze than `freeze`, names a retained original that is not this source's
    /// own revision, or names a source the freeze did not include.
    pub fn commit(
        freeze: &EvidenceFreeze,
        requests: &[GovernorSourceTransitionRequest],
    ) -> Result<Self, InquiryError> {
        freeze.validate_integrity()?;
        if requests.is_empty() {
            return Err(InquiryError::UnknownHandle {
                field: "committed_freeze.admission_requests",
            });
        }
        let mut members: Vec<CommittedFreezeMember> = Vec::with_capacity(requests.len());
        let mut request_digests: Vec<String> = Vec::with_capacity(requests.len());
        for request in requests {
            // The existing owner's own validator. A request that was edited after
            // it was built cannot re-prove its digest, so it cannot be used to
            // commit a freeze.
            request.validate_integrity()?;
            let Some(commitment) = &request.freeze_commit else {
                return Err(InquiryError::IntegrityMismatch {
                    field: "committed_freeze.freeze_commit",
                });
            };
            if commitment.freeze_digest != freeze.digest
                || commitment.freeze_id != freeze.freeze_id
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "committed_freeze.freeze_identity",
                });
            }
            if !freeze.includes(&request.source_handle) {
                return Err(InquiryError::IntegrityMismatch {
                    field: "committed_freeze.included_member",
                });
            }
            members.push(CommittedFreezeMember {
                source_handle: request.source_handle.clone(),
                content_digest: commitment.retained_content_digest.clone(),
                retained_revision_digest: commitment.retained_revision_digest.clone(),
                retained_artifact_ref: commitment.retained_artifact_ref.clone(),
            });
            request_digests.push(request.request_digest.clone());
        }
        members.sort_by(|left, right| left.source_handle.cmp(&right.source_handle));
        request_digests.sort();
        let mut committed = Self {
            freeze_id: freeze.freeze_id.clone(),
            freeze_digest: freeze.digest.clone(),
            inquiry_id: freeze.inquiry_id.clone(),
            evidence_set_id: freeze.evidence_set_id.clone(),
            members,
            admission_request_digests: request_digests,
            digest: String::new(),
        };
        committed.digest = committed.compute_digest();
        Ok(committed)
    }

    /// Canonical digest over the whole committed-freeze shape.
    fn compute_digest(&self) -> String {
        let mut preimage = String::from(COMMITTED_FREEZE_DIGEST_DOMAIN);
        push_field(&mut preimage, "freeze_id", &self.freeze_id);
        push_field(&mut preimage, "freeze_digest", &self.freeze_digest);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_count(&mut preimage, "members", self.members.len());
        for member in &self.members {
            push_field(&mut preimage, "member", &member.source_handle);
            push_field(&mut preimage, "member_content_digest", &member.content_digest);
            push_field(
                &mut preimage,
                "member_retained_revision_digest",
                &member.retained_revision_digest,
            );
            push_field(
                &mut preimage,
                "member_retained_artifact_ref",
                &member.retained_artifact_ref,
            );
        }
        push_count(
            &mut preimage,
            "admission_request_digests",
            self.admission_request_digests.len(),
        );
        for request_digest in &self.admission_request_digests {
            push_field(&mut preimage, "admission_request", request_digest);
        }
        freeze(&preimage)
    }

    /// Re-proves this record's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "committed_freeze.digest",
            });
        }
        Ok(())
    }

    /// The retained-original commitment for one committed member.
    #[must_use]
    pub fn member(&self, handle: &str) -> Option<&CommittedFreezeMember> {
        self.members
            .iter()
            .find(|member| member.source_handle == handle)
    }

    /// The retained-original commitments keyed by source handle.
    ///
    /// This is a keyed view of the members this commit already published, not a
    /// second list: every entry is the same value a member of the same name
    /// carries, and a handle present in one and absent from the other is
    /// impossible by construction.
    #[must_use]
    pub fn members_by_handle(&self) -> BTreeMap<String, CommittedFreezeMember> {
        self.members
            .iter()
            .map(|member| (member.source_handle.clone(), member.clone()))
            .collect()
    }
}

/// Why one denominator member could not enter the synthesis pack.
///
/// I21.8 item 3: "Missing or newly revoked source material produces an explicit
/// limited/blocked result and invalidation history, not a stale authorization or
/// silent omission." Each variant is a *reason a member did not enter the pack*,
/// and every one of them is decided over the member's own state rather than over
/// the pack's shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackLimitation {
    /// The freeze recorded this member as **excluded**, with the freeze's own
    /// typed reason.
    ///
    /// This is the I21.8 "excluded members/reasons" preserved into the pack: an
    /// excluded member is a fact about the freeze, and the pack carries it rather
    /// than dropping it, so a reader learns that the freeze considered it and
    /// refused it.
    ExcludedByFreeze,
    /// The reference manifest does not admit this handle, or admits and revokes
    /// it.
    ///
    /// I21.7's reference firewall: a handle outside the run-bound allowlist is
    /// unsupported text, and one the manifest lists as stale or revoked is
    /// refused even though it is still listed. The manifest's own
    /// `stale_or_revoked_handles` check is what distinguishes the two, and this
    /// variant is the union of "never admitted" and "admitted then revoked" so
    /// the caller can read the manifest for which.
    NotAdmittedByReferenceManifest,
    /// No admission record exists for this handle under this profile revision.
    NoAdmissionRecord,
    /// The admission record exists but is not `Eligible` under this profile.
    NotAdmittedBySource,
    /// No retained original was committed for this handle.
    ///
    /// W2: without the exact bytes or an immutable accessible artifact there is
    /// nothing to verify an excerpt against, and a hash of unavailable bytes is
    /// insufficient. A member whose original is missing therefore cannot enter a
    /// pack that synthesis will quote from.
    NoRetainedOriginal,
    /// The member's source record travels at a disclosure class **wider** than
    /// the run admitted.
    ///
    /// I21.7: a manifest may be narrower than the request that carries it and
    /// never wider. A member re-labelled wider inside an otherwise correct run is
    /// still a widened record, so the comparison is against the run's admitted
    /// class rather than against the pack.
    DisclosureWidened,
    /// The member is present and admissible but its source record no longer
    /// re-proves its own canonical identity.
    ///
    /// The records are re-proved here rather than trusted: a record whose content
    /// was edited after the freeze no longer describes the revision the freeze
    /// committed, and quoting it would be quoting something the freeze never
    /// admitted.
    RecordIdentityUnproven,
}

impl PackLimitation {
    /// Stable wire spelling of this limitation.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ExcludedByFreeze => "excluded_by_freeze",
            Self::NotAdmittedByReferenceManifest => "not_admitted_by_reference_manifest",
            Self::NoAdmissionRecord => "no_admission_record",
            Self::NotAdmittedBySource => "not_admitted_by_source",
            Self::NoRetainedOriginal => "no_retained_original",
            Self::DisclosureWidened => "disclosure_widened",
            Self::RecordIdentityUnproven => "record_identity_unproven",
        }
    }
}

/// One denominator member that did not enter the pack, with its exact reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackOmission {
    /// The omitted member.
    pub source_handle: String,
    /// Why it was omitted, in the closed vocabulary.
    pub limitation: PackLimitation,
    /// The freeze's own reason when the limitation is
    /// [`PackLimitation::ExcludedByFreeze`], empty otherwise.
    ///
    /// Carried verbatim rather than re-derived: the freeze recorded typed reasons
    /// for its exclusions and a reader of the pack must be able to read the same
    /// ones without this module inventing a second spelling.
    pub reason: String,
}

/// One resolved member of the synthesis pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackMember {
    /// The source handle. Present in the freeze's admitted included set.
    pub source_handle: String,
    /// Digest of the source record's own canonical identity, re-proved at build
    /// time.
    pub record_digest: String,
    /// The admitted revision's content digest, as the admission record committed
    /// it.
    pub content_digest: String,
    /// Digest of the retained-revision record the persistence owner committed.
    pub retained_revision_digest: String,
    /// The immutable artifact reference the original was committed under.
    pub retained_artifact_ref: String,
    /// The committed freeze this member was resolved from.
    pub committed_freeze_digest: String,
    /// Privacy class the source record carries end to end.
    pub disclosure: DisclosureClass,
    /// Allowed epistemic use the source record declares.
    pub allowed_use: String,
    /// Allowed effects of acting on this source.
    pub allowed_effects: String,
    /// Required verifier or quarantine condition.
    pub verifier: String,
    /// Quarantine reason, when the record carries one.
    pub quarantine: Option<String>,
    /// The lane class the lane discipline decided for this run.
    ///
    /// I21.2 keeps grade and status orthogonal, so the class is what separates an
    /// exploratory finding from a confirmatory claim, and it travels on every
    /// member so a synthesis consumer cannot read one member as a different kind
    /// of evidence from its siblings.
    pub lane_class: String,
    /// Canonical grade rank the record carries, when it declares one.
    pub grade_rank: Option<u8>,
    /// Authority domains the record is competent in, canonical order.
    pub authority_domains: Vec<String>,
    /// Data role the record fills in the inquiry.
    pub data_role: String,
}

/// The governed synthesis-input pack built from one committed freeze.
///
/// W3: "Resolve only its admitted included members under the current disclosure
/// and reference manifest." Every member of this pack was, in order:
///
/// 1. named in the committed freeze's **admitted included** set (an excluded
///    member is reported under [`PackOmission`], never resolved);
/// 2. admitted by the run-bound reference manifest, and not stale-or-revoked in
///    it;
/// 3. `Eligible` under the profile revision the freeze was taken under;
/// 4. backed by a retained original committed through the admission owner; and
/// 5. at a disclosure class no wider than the run admitted.
///
/// Anything that fails a step is a typed [`PackOmission`] with its own reason, so
/// the pack's denominator is the freeze's denominator and the difference between
/// the two is published rather than silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SynthesisInputPack {
    /// Identity of the pack.
    pub pack_id: String,
    /// The committed freeze this pack was resolved from.
    pub committed_freeze_digest: String,
    /// Identity of that freeze, so an invalidation history can address it.
    pub committed_freeze_id: String,
    /// Inquiry the pack covers.
    pub inquiry_id: String,
    /// Evidence set the pack covers.
    pub evidence_set_id: String,
    /// The run-bound reference manifest digest the members were resolved under.
    pub reference_manifest_digest: String,
    /// The disclosure class the run admitted; no member travels wider.
    pub admitted_disclosure: DisclosureClass,
    /// The exact question the freeze was taken under.
    ///
    /// I21.8 item 3: "New URLs or facts mentioned by the draft remain untrusted
    /// acquisition candidates, not citations or evidence for this run." A pack
    /// that carried a question the freeze did not answer would be a place for
    /// exactly that to enter, so the question is the freeze's own.
    pub question: String,
    /// The resolved members, canonical order by handle.
    pub members: Vec<PackMember>,
    /// Every denominator member that did not resolve, canonical order.
    pub omissions: Vec<PackOmission>,
    /// Unresolved contradictions the freeze recorded.
    ///
    /// Preserved because I21.8 item 3 requires contradictions to survive into the
    /// synthesis input rather than being smoothed over by a summary.
    pub unresolved_contradictions: Vec<String>,
    /// Open research debts the freeze recorded, with their frozen identities.
    pub open_research_debts: Vec<String>,
    /// Excluded members and the freeze's exact reasons, carried whole.
    pub excluded_evidence: Vec<(String, String)>,
    /// The lane class the lane discipline decided for this run.
    pub lane_class: String,
    /// Whether the lane discipline refused release of this run's material.
    ///
    /// Read off the discipline's own outcome rather than inferred, so a pack
    /// cannot present an exploratory run's material as confirmatory.
    pub lane_release_refused: bool,
    /// Digest over the whole pack shape.
    pub digest: String,
}

impl SynthesisInputPack {
    /// Builds the pack from one committed freeze.
    ///
    /// `records` maps a source handle to the [`SourceRecord`] the run admitted
    /// for it, and `retained` maps a handle to the retained-original commitment
    /// the persistence owner committed for it. Both are inputs because neither
    /// this crate nor the pack retains the bytes: the retained original lives at
    /// the artifact reference the commitment names, and this pack carries the
    /// reference, not a copy.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the committed freeze does
    /// not re-prove its own digest, [`InquiryError::UnknownHandle`] when the
    /// committed freeze names a member for which no source record was supplied,
    /// and a manifest-refusal error when the run-bound reference manifest does not
    /// re-prove its own digest.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        committed: &CommittedFreeze,
        freeze: &EvidenceFreeze,
        manifest: &AllowedReferenceManifest,
        records: &BTreeMap<String, SourceRecord>,
        retained: &BTreeMap<String, CommittedFreezeMember>,
        question: &str,
        admitted_disclosure: DisclosureClass,
        lane: &LaneDisciplineOutcome,
    ) -> Result<Self, InquiryError> {
        committed.validate_integrity()?;
        freeze.validate_integrity()?;
        manifest.validate().map_err(InquiryError::from)?;
        if committed.freeze_digest != freeze.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "synthesis_input.committed_freeze",
            });
        }
        // The denominator is the freeze's OWN included set, read off the freeze
        // and not off the committed record: a `CommittedFreeze` that had lost or
        // gained a member would still re-prove its own digest, and only the
        // freeze is the authority on which members exist.
        let denominator: Vec<String> = freeze.included_members().to_vec();
        let mut members: Vec<PackMember> = Vec::new();
        let mut omissions: Vec<PackOmission> = Vec::new();
        for handle in &denominator {
            match resolve_member(
                handle,
                committed,
                freeze,
                manifest,
                records,
                retained,
                admitted_disclosure,
                lane,
            ) {
                Ok(member) => members.push(member),
                Err(omission) => omissions.push(omission),
            }
        }
        // Members the freeze itself excluded are part of the denominator too, and
        // they are carried with the freeze's own reason so the pack publishes the
        // difference between "considered and refused" and "never considered".
        for (handle, reason) in &freeze.excluded_evidence {
            omissions.push(PackOmission {
                source_handle: handle.clone(),
                limitation: PackLimitation::ExcludedByFreeze,
                reason: reason.clone(),
            });
        }
        members.sort_by(|left, right| left.source_handle.cmp(&right.source_handle));
        omissions.sort_by(|left, right| left.source_handle.cmp(&right.source_handle));
        // One member produces at most one omission: a handle the freeze excluded
        // is not in the included set, so the two loops cannot both reach it, and
        // deduplicating on the pair keeps that guarantee from depending on that
        // reasoning surviving an edit.
        omissions.dedup_by(|left, right| {
            left.source_handle == right.source_handle && left.limitation == right.limitation
        });
        let mut pack = Self {
            pack_id: format!(
                "synthesis-input-{}@{}",
                committed.inquiry_id,
                &committed.digest[..16]
            ),
            committed_freeze_digest: committed.freeze_digest.clone(),
            committed_freeze_id: committed.freeze_id.clone(),
            inquiry_id: committed.inquiry_id.clone(),
            evidence_set_id: committed.evidence_set_id.clone(),
            reference_manifest_digest: manifest.digest.clone(),
            admitted_disclosure,
            question: question.to_owned(),
            members,
            omissions,
            unresolved_contradictions: freeze.unresolved_contradictions.clone(),
            open_research_debts: freeze.open_research_debts.clone(),
            excluded_evidence: freeze.excluded_evidence.clone(),
            lane_class: lane.evidence_class.wire_name().to_owned(),
            lane_release_refused: !lane.evidence_class.is_confirmatory(),
            digest: String::new(),
        };
        pack.digest = pack.compute_digest()?;
        Ok(pack)
    }

    /// The handles this pack resolved, canonical order.
    #[must_use]
    pub fn resolved_handles(&self) -> Vec<String> {
        self.members
            .iter()
            .map(|member| member.source_handle.clone())
            .collect()
    }

    /// The handles this pack could not resolve, canonical order.
    #[must_use]
    pub fn omitted_handles(&self) -> Vec<String> {
        self.omissions
            .iter()
            .map(|omission| omission.source_handle.clone())
            .collect()
    }

    /// Whether every member of the freeze's denominator resolved.
    ///
    /// This is the honest "complete" question for a pack: a member that did not
    /// resolve is a member the pack cannot speak for, and a synthesis consumer
    /// that wants a complete denominator must read this rather than count
    /// `members`.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.omissions.is_empty()
    }

    /// Whether the pack is bounded to a limited result rather than a full one.
    ///
    /// I21.8 item 3 requires missing or newly revoked material to produce an
    /// explicit limited or blocked result, so this is the one predicate a caller
    /// asks instead of inspecting the omission list itself.
    #[must_use]
    pub fn is_limited(&self) -> bool {
        !self.omissions.is_empty() || self.lane_release_refused
    }

    /// Whether this pack admits `handle` as a resolvable synthesis input.
    ///
    /// The membership test is over the pack's **own** resolved set rather than
    /// over the freeze or the manifest, so a consumer cannot accidentally ask the
    /// freeze (which also names excluded members) and get a different answer than
    /// the one the pack publishes.
    #[must_use]
    pub fn admits(&self, handle: &str) -> bool {
        self.members
            .iter()
            .any(|member| member.source_handle == handle)
    }

    /// Canonical digest over the whole pack shape.
    fn compute_digest(&self) -> Result<String, InquiryError> {
        let mut preimage = String::from(SYNTHESIS_INPUT_PACK_DIGEST_DOMAIN);
        push_field(&mut preimage, "pack_id", &self.pack_id);
        push_field(
            &mut preimage,
            "committed_freeze_digest",
            &self.committed_freeze_digest,
        );
        push_field(&mut preimage, "committed_freeze_id", &self.committed_freeze_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(
            &mut preimage,
            "reference_manifest_digest",
            &self.reference_manifest_digest,
        );
        push_field(
            &mut preimage,
            "admitted_disclosure",
            &disclosure_wire(self.admitted_disclosure),
        );
        push_field(&mut preimage, "question", &self.question);
        push_count(&mut preimage, "members", self.members.len());
        for member in &self.members {
            push_field(&mut preimage, "member", &member.source_handle);
            push_field(&mut preimage, "member_record_digest", &member.record_digest);
            push_field(&mut preimage, "member_content_digest", &member.content_digest);
            push_field(
                &mut preimage,
                "member_retained_revision_digest",
                &member.retained_revision_digest,
            );
            push_field(
                &mut preimage,
                "member_retained_artifact_ref",
                &member.retained_artifact_ref,
            );
            push_field(&mut preimage, "member_disclosure", disclosure_wire(member.disclosure));
            push_field(&mut preimage, "member_allowed_use", &member.allowed_use);
            push_field(&mut preimage, "member_allowed_effects", &member.allowed_effects);
            push_field(&mut preimage, "member_verifier", &member.verifier);
            match &member.quarantine {
                Some(reason) => {
                    push_field(&mut preimage, "member_quarantine_declared", "true");
                    push_field(&mut preimage, "member_quarantine", reason);
                }
                None => push_field(&mut preimage, "member_quarantine_declared", "false"),
            }
            push_field(&mut preimage, "member_lane_class", &member.lane_class);
            match member.grade_rank {
                Some(rank) => {
                    push_field(&mut preimage, "member_grade_declared", "true");
                    push_field(&mut preimage, "member_grade_rank", &rank.to_string());
                }
                None => push_field(&mut preimage, "member_grade_declared", "false"),
            }
            push_count(
                &mut preimage,
                "member_authority_domains",
                member.authority_domains.len(),
            );
            for domain in &member.authority_domains {
                push_field(&mut preimage, "member_authority_domain", domain);
            }
            push_field(&mut preimage, "member_data_role", &member.data_role);
            push_field(
                &mut preimage,
                "member_committed_freeze_digest",
                &member.committed_freeze_digest,
            );
        }
        push_count(&mut preimage, "omissions", self.omissions.len());
        for omission in &self.omissions {
            push_field(&mut preimage, "omission", &omission.source_handle);
            push_field(
                &mut preimage,
                "omission_limitation",
                omission.limitation.wire_name(),
            );
            push_field(&mut preimage, "omission_reason", &omission.reason);
        }
        for (tag, values) in [
            ("unresolved_contradictions", &self.unresolved_contradictions),
            ("open_research_debts", &self.open_research_debts),
        ] {
            push_count(&mut preimage, tag, values.len());
            for value in values {
                push_field(&mut preimage, tag, value);
            }
        }
        push_count(
            &mut preimage,
            "excluded_evidence",
            self.excluded_evidence.len(),
        );
        for (handle, reason) in &self.excluded_evidence {
            push_field(&mut preimage, "excluded", handle);
            push_field(&mut preimage, "excluded_reason", reason);
        }
        push_field(&mut preimage, "lane_class", &self.lane_class);
        push_field(
            &mut preimage,
            "lane_release_refused",
            bool_text(self.lane_release_refused),
        );
        Ok(freeze(&preimage))
    }

    /// Re-proves this pack's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest()? != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "synthesis_input.digest",
            });
        }
        Ok(())
    }
}

/// Resolves one freeze member, or reports exactly why it did not resolve.
///
/// The order of the checks is the order the five W3 requirements impose: freeze
/// membership (already established by the caller's denominator), the reference
/// manifest, the source record's presence and re-proved identity, the retained
/// original, and finally the disclosure class. A member that fails the manifest
/// check is reported as such rather than as "missing retention", because the
/// first refusal is the one a reader can act on.
#[allow(clippy::too_many_arguments)]
fn resolve_member(
    handle: &str,
    committed: &CommittedFreeze,
    freeze: &EvidenceFreeze,
    manifest: &AllowedReferenceManifest,
    records: &BTreeMap<String, SourceRecord>,
    retained: &BTreeMap<String, CommittedFreezeMember>,
    admitted_disclosure: DisclosureClass,
    lane: &LaneDisciplineOutcome,
) -> Result<PackMember, PackOmission> {
    // I21.7 reference firewall, through the manifest's own admission predicate.
    // `allows` applies the stale-or-revoked set on every call, so the answer does
    // not depend on the order the two lists are read in.
    if !manifest.allows(handle) {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::NotAdmittedByReferenceManifest,
            reason: format!(
                "the run-bound reference manifest ({}) does not admit {handle} as a citable \
                 reference, or admits and revokes it",
                manifest.digest
            ),
        });
    }
    let Some(record) = records.get(handle) else {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::NoAdmissionRecord,
            reason: "the freeze included this handle but no admitted source record backs it"
                .to_owned(),
        });
    };
    // The record's own canonical identity, re-proved. A record edited after the
    // freeze would otherwise enter the pack describing a revision the freeze
    // never committed.
    let record_digest = record.digest().map_err(|_| PackOmission {
        source_handle: handle.to_owned(),
        limitation: PackLimitation::RecordIdentityUnproven,
        reason: "the admitted source record has no computable canonical commitment".to_owned(),
    })?;
    record.verify_identity(&record_digest).map_err(|_| PackOmission {
        source_handle: handle.to_owned(),
        limitation: PackLimitation::RecordIdentityUnproven,
        reason: "the admitted source record no longer re-proves its own canonical identity"
            .to_owned(),
    })?;
    // The retained original. W2 requires the exact bytes or an immutable
    // accessible artifact; the artifact reference is what the pack carries, and
    // its content digest must be the admitted record's own so a foreign revision
    // cannot ride in on a well-formed reference.
    let Some(retained_member) = retained.get(handle).or_else(|| committed.member(handle)) else {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::NoRetainedOriginal,
            reason: "no retained original was committed for this handle before the freeze"
                .to_owned(),
        });
    };
    if retained_member.content_digest != record.content_digest {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::NoRetainedOriginal,
            reason: format!(
                "the retained original commits content digest {}, but the admitted record commits \
                 {}: these are different revisions of the same source",
                retained_member.content_digest, record.content_digest
            ),
        });
    }
    if text(&retained_member.retained_artifact_ref, "synthesis_input.retained_artifact_ref")
        .is_err()
    {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::NoRetainedOriginal,
            reason: "the committed retained original names no immutable artifact reference"
                .to_owned(),
        });
    }
    // I21.7: never wider than the run admitted.
    if disclosure_breadth(record.disclosure) > disclosure_breadth(admitted_disclosure) {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::DisclosureWidened,
            reason: format!(
                "the source record travels at {} but the run admitted {}",
                disclosure_wire(record.disclosure),
                disclosure_wire(admitted_disclosure)
            ),
        });
    }
    // The record is only usable if the admission record that put it in the
    // evidence set still says `Eligible`. The freeze's own included set was built
    // from those records, so a member that has since become ineligible is
    // reported rather than resolved on the strength of the freeze alone.
    if freeze
        .excluded_evidence
        .iter()
        .any(|(excluded, _)| excluded == handle)
    {
        return Err(PackOmission {
            source_handle: handle.to_owned(),
            limitation: PackLimitation::ExcludedByFreeze,
            reason: freeze
                .excluded_evidence
                .iter()
                .find(|(excluded, _)| excluded == handle)
                .map_or_else(String::new, |(_, reason)| reason.clone()),
        });
    }
    Ok(PackMember {
        source_handle: handle.to_owned(),
        record_digest,
        content_digest: record.content_digest.clone(),
        retained_revision_digest: retained_member.retained_revision_digest.clone(),
        retained_artifact_ref: retained_member.retained_artifact_ref.clone(),
        committed_freeze_digest: committed.freeze_digest.clone(),
        disclosure: record.disclosure,
        allowed_use: record.allowed_use.clone(),
        allowed_effects: record.allowed_effects.clone(),
        verifier: record.verifier.clone(),
        quarantine: record.quarantine.clone(),
        lane_class: lane.evidence_class.wire_name().to_owned(),
        grade_rank: record.grade,
        authority_domains: {
            let mut domains: Vec<String> = record.authority_domains.iter().cloned().collect();
            domains.sort();
            domains.dedup();
            domains
        },
        data_role: record.data_role.clone(),
    })
}

/// Canonical wire spelling of a disclosure class, shared by the pack's preimage
/// and its omission reasons so the two cannot spell one class differently.
const fn disclosure_wire(class: DisclosureClass) -> &'static str {
    match class {
        DisclosureClass::Private => "private",
        DisclosureClass::ProjectBound => "project_bound",
        DisclosureClass::ExportableRedacted => "exportable_redacted",
        DisclosureClass::Public => "public",
    }
}
