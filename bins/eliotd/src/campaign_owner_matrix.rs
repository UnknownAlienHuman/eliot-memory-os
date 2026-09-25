//! Closed composition of the authenticated campaign owner-publication matrix.
//!
//! The daemon obtains non-Task-Controller rows through the authenticated
//! campaign-source read route before this module is used. This module only
//! joins those immutable publications with the four Task Controller rows and
//! delegates the closed denominator check to the Governor owner. It never
//! accepts caller-supplied owner rows, source heads, or replacement material.

use eliot_governor::{TaskControllerCampaignSources, assemble_task_owner_matrix};
use eliot_store_api::CampaignSourcePublication;

/// Join an authenticated owner-read set with the Task Controller's native rows.
///
/// Every input is revalidated by the Governor assembler, including publisher
/// role, owner identity, exact recipe reference, current read receipt, source
/// head state, and owner-produced history. Explicitly absent recipe roles are
/// accounted for by the recipe and do not require fabricated rows.
pub fn assemble_authenticated_campaign_owner_publications(
    task_sources: &TaskControllerCampaignSources,
    owner_publications: Vec<CampaignSourcePublication>,
) -> Result<Vec<CampaignSourcePublication>, String> {
    assemble_task_owner_matrix(task_sources, owner_publications).map_err(|error| error.to_string())
}
