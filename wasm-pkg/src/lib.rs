mod utils;

use std::ops::Rem;
use std::ptr;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

// imports the javascript window.alert function
#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

// exports the rust function: greet
#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

#[wasm_bindgen]
pub fn multiply(n1: u32, n2: u32) -> u32 {
    let result = n1.overflowing_mul(n2);
    match result {
        (number, false) => number,
        (_, true) => 0,
    }
}

#[wasm_bindgen]
pub fn add(n1: u64, n2: u64) -> u64 {
    let result = n1.overflowing_add(n2);
    match result {
        (number, false) => number,
        (_, true) => 0,
    }
}

#[wasm_bindgen]
pub fn power(base: u32, power: u32) -> u32 {
    let result = base.overflowing_pow(power);
    match result {
        (number, false) => number,
        (_, true) => 0,
    }
}

#[wasm_bindgen]
pub fn modulo(base: u32, modulus: u32) -> u32 {
    base.rem(modulus)
}

#[wasm_bindgen(js_name = powerOverflow)]
pub fn power_overflow(base: u32, power: u32) -> u32 {
    let result = base.overflowing_pow(power);
    match result {
        (number, false) => number,
        (_, true) => 0,
    }
}

#[wasm_bindgen]
pub fn take_pointer_by_value(x: *mut u8) {

}

#[wasm_bindgen]
pub fn return_pointer() -> *mut u8 {
    ptr::null_mut()
}

#[wasm_bindgen]
pub fn take_number_slice_by_exclusive_ref(x: &mut [u32]) {}