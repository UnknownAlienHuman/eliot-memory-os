use eliot_engine::{CueIndexService, InjectionPlanner, TouchedSetRegistry, WriterHandle};
use eliot_store::CanonicalStore;
use std::sync::Arc;

pub(super) struct UlRuntime {
    pub cue_index: Arc<CueIndexService>,
    pub touched: Arc<TouchedSetRegistry>,
    pub planner: Arc<InjectionPlanner>,
}

impl UlRuntime {
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let touched = Arc::new(TouchedSetRegistry::new());
        let planner = Arc::new(InjectionPlanner::new(
            Arc::clone(&cue_index),
            store,
            writer,
            Arc::clone(&touched),
        ));
        Self {
            cue_index,
            touched,
            planner,
        }
    }
}
