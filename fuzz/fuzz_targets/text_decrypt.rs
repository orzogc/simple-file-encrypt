#![no_main]

use libfuzzer_sys::fuzz_target;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fuzz_target!(|data: &[u8]| {
    // A fixed key keeps iterations fast and deterministic; the key
    // value is irrelevant to panic-safety.
    let keys = vec![zeroize::Zeroizing::new([0x42u8; 32])];
    // Split between the two header forms by the first byte so both the
    // units path and the empty-marker path are exercised; malformed
    // input must fail, never panic.
    let mut input = Vec::with_capacity(data.len() + 48);
    if data.first().is_some_and(|b| b & 1 == 1) {
        input.extend_from_slice(b"#simple-encrypt v1 text ");
        for (i, v) in data.iter().skip(1).take(22).enumerate() {
            if i == 21 {
                // Canonical final character (four trailing bits zero).
                input.push(b"AQgw"[(v % 4) as usize]);
            } else {
                input.push(B64[(v % 64) as usize]);
            }
        }
        input.push(b'\n');
        input.extend_from_slice(data.get(23..).unwrap_or(&[]));
    } else {
        input.extend_from_slice(b"#simple-encrypt v1 text\n");
        input.extend_from_slice(data.get(1..).unwrap_or(&[]));
    }
    let _ = simple_encrypt::textmode::authenticate_first(&keys, "fuzz", &input);
    let _ = simple_encrypt::textmode::decrypt(&keys, "fuzz", &input);
});
