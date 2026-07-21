use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Eq,
            Hash,
            JsonSchema,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            pub fn new_v7() -> Self {
                Self(Uuid::now_v7())
            }

            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                Display::fmt(&self.0, f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

id_type!(AgentId);
id_type!(AgentSessionId);
id_type!(ActionLeaseId);
id_type!(ActionRequestId);
id_type!(AgentRunId);
id_type!(BlackboardItemId);
id_type!(MailboxMessageId);
id_type!(ModuleId);
id_type!(PatchRequestId);
id_type!(PatchRunId);
id_type!(ProjectId);
id_type!(SessionId);
id_type!(SkillId);
id_type!(TaskId);
id_type!(VerifierRunId);
id_type!(WorkItemId);
id_type!(WorkLeaseId);
id_type!(WorktreeLeaseRequestId);
id_type!(WorktreeLeaseId);
id_type!(CandidateDiffId);
id_type!(WriteId);
id_type!(OperationId);
id_type!(ClaimId);
id_type!(EvidenceId);
id_type!(VerificationId);
id_type!(ReceiptId);
id_type!(ReplayCaseId);
id_type!(ReplaySetId);
id_type!(ReplayRunId);
id_type!(DreamCandidateId);
id_type!(EvalCaseId);
id_type!(EvalSuiteId);
id_type!(EvalDatasetManifestId);
id_type!(EvalRunId);
id_type!(EvalVerdictId);
id_type!(EvalFailureClusterId);
id_type!(BenchmarkIntegrityReceiptId);
id_type!(HarnessExperimentRecordId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MemoryRevision(u64);

impl MemoryRevision {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProjectSequence(u64);

impl ProjectSequence {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}
