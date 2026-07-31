#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = simple_encrypt::crypto::random_domain_key().expect("OS RNG");
    let keys = vec![key];
    // Nudge inputs past the probe so the structural parser and chunk
    // authentication are exercised; malformed input must fail, never
    // panic.
    let mut input = Vec::with_capacity(data.len() + 8);
    input.extend_from_slice(&simple_encrypt::consts::BIN_MAGIC);
    input.extend_from_slice(data);
    let _ = simple_encrypt::binmode::authenticate_first(&keys, "fuzz", &input);
    let _ = simple_encrypt::binmode::decrypt(&keys, "fuzz", &input);
});
