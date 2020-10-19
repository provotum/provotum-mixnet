mod utils;

use std::ops::Rem;
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
    n1 * n2
}

#[wasm_bindgen]
pub fn power(base: u32, power: u32) -> u32 {
    base.pow(power)
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
