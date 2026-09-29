//! Exact queue identity joins; numeric equality alone is not correspondence.
use eliot_runtime_contracts::{
    AdmittedHotPathManifest, RegisteredOperation, RegisteredQueueSettings,
    RunningBuildRegistration, admit_hot_path_manifest, bind_hot_path_manifest_set,
};
use std::{error::Error, path::Path};

fn inputs() -> Result<(AdmittedHotPathManifest, RunningBuildRegistration), Box<dyn Error>> {
    let admitted = admit_hot_path_manifest(
        Path::new("eliot-kernel"),
        include_bytes!("../../../../bins/eliot-kernel/hot-path.toml"),
    )?;
    let registration = RunningBuildRegistration {
        service: "eliot-kernel".to_owned(),
        operations: [
            ("local_read_claim", 8 * 1024 * 1024),
            ("local_read", 4 * 1024 * 1024),
            ("local_read_result", 4 * 1024 * 1024),
        ]
        .into_iter()
        .map(|(operation, max_bytes)| RegisteredOperation {
            operation: operation.to_owned(),
            queue: RegisteredQueueSettings {
                queue_id: operation.to_owned(),
                max_items: 64,
                max_bytes,
            },
        })
        .collect(),
    };
    // Every negative starts from the same genuinely admitted positive.
    assert_eq!(
        bind_hot_path_manifest_set(&admitted.set, &registration)?.len(),
        3
    );
    Ok((admitted, registration))
}

#[test]
fn exact_shipped_operation_and_queue_bindings_pass() -> Result<(), Box<dyn Error>> {
    inputs()?;
    Ok(())
}

#[test]
fn changed_declared_queue_is_not_equal_numeric_capacity() -> Result<(), Box<dyn Error>> {
    let (mut admitted, registration) = inputs()?;
    admitted.set.supported_operations[0].queues_and_capacity[0].queue_id = "foreign".to_owned();
    assert!(bind_hot_path_manifest_set(&admitted.set, &registration).is_err());
    Ok(())
}

#[test]
fn changed_registered_queue_is_refused() -> Result<(), Box<dyn Error>> {
    let (admitted, mut registration) = inputs()?;
    registration.operations[0].queue.queue_id = "foreign".to_owned();
    assert!(bind_hot_path_manifest_set(&admitted.set, &registration).is_err());
    Ok(())
}

#[test]
fn extra_foreign_queue_cannot_share_one_registered_queue() -> Result<(), Box<dyn Error>> {
    let (mut admitted, registration) = inputs()?;
    let mut extra = admitted.set.supported_operations[0].queues_and_capacity[0].clone();
    extra.queue_id = "foreign".to_owned();
    admitted.set.supported_operations[0]
        .queues_and_capacity
        .push(extra);
    assert!(bind_hot_path_manifest_set(&admitted.set, &registration).is_err());
    Ok(())
}

#[test]
fn missing_operation_and_changed_limits_remain_refused() -> Result<(), Box<dyn Error>> {
    let (admitted, registration) = inputs()?;
    let mut missing = registration.clone();
    missing.operations.remove(1);
    assert!(bind_hot_path_manifest_set(&admitted.set, &missing).is_err());
    let mut changed = registration;
    changed.operations[0].queue.max_bytes += 1;
    assert!(bind_hot_path_manifest_set(&admitted.set, &changed).is_err());
    Ok(())
}
