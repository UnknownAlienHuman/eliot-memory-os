#[test]
fn tiny_ok_a() {
    assert_eq!(1 + 1, 2);
}

#[test]
fn tiny_ok_b() {
    assert_eq!(2 + 2, 4);
}

#[test]
fn tiny_fail() {
    assert_eq!(1, 2);
}

#[test]
#[ignore]
fn tiny_ignored() {
    assert_eq!(1, 1);
}
