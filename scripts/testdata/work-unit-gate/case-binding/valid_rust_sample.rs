// Finite deterministic Rust test fixtures for case binding (#851)
#![allow(dead_code)]

// WORK_UNIT_CASE: 851/1
#[test]
fn test_plain_rust() {
    assert_eq!(2 + 2, 4);
}

// WORK_UNIT_CASE: 851/2
#[tokio::test]
async fn test_tokio_async() {
    let result = async { 42 }.await;
    assert_eq!(result, 42);
}

// WORK_UNIT_CASE: 851/3
#[allow(unused_variables)]
#[should_panic(expected = "boom")]
#[test]
fn test_inert_attributes() {
    panic!("boom");
}

fn helper_function() -> i32 {
    // let fake = "// WORK_UNIT_CASE: 851/99";
    42
}
