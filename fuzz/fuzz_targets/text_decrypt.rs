#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let key = simple_encrypt::crypto::random_domain_key().expect("OS RNG");
    let keys = vec![key];
    // Nudge inputs past the probe so the unit parser and authentication
    // paths are exercised; malformed input must fail, never panic.
    let mut input = Vec::with_capacity(data.len() + 24);
    input.extend_from_slice(b"#simple-encrypt v1 text\n");
    input.extend_from_slice(data);
    let _ = simple_encrypt::textmode::authenticate_first(&keys, "fuzz", &input);
    let _ = simple_encrypt::textmode::decrypt(&keys, "fuzz", &input);
});
