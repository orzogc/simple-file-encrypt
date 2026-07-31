#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Hostile configs must fail cleanly, never panic.
    let _ = simple_encrypt::config::parse(data);
});
