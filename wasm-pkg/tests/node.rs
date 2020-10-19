#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use wasm_package::multiply;

#[wasm_bindgen_test]
fn smoke_test() {
    assert_eq!(1 + 1, 2);
}

#[wasm_bindgen_test]
fn test_multiply() {
    let n1: u32 = 100;
    let n2: u32 = 100;

    let result = multiply(n1, n2);

    assert_eq!(result, 10000);
}
