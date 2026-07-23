use eliot_engine::CueIndexService;
use eliot_store::CanonicalStore;
use std::sync::Arc;

pub(super) struct UlRuntime {
    pub cue_index: Arc<CueIndexService>,
}

impl UlRuntime {
    pub fn new(store: CanonicalStore) -> Self {
        Self {
            cue_index: Arc::new(CueIndexService::new(store)),
        }
    }
}
