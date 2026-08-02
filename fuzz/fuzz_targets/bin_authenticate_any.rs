#![no_main]

use libfuzzer_sys::fuzz_target;
use simple_file_encrypt::binmode;
use simple_file_encrypt::crypto::{ScanBudget, UnitScan};

// The binary any-unit scan (structure-parsing and grid paths alike)
// and the header-blind prefix grid must never panic, and a budget cut
// must never harden a verdict — see text_authenticate_any.rs.
fuzz_target!(|data: &[u8]| {
    let keys = vec![zeroize::Zeroizing::new([0x42u8; 32])];
    let (budget_bytes, rest) = data.split_at(data.len().min(2));
    let budget = budget_bytes.iter().fold(0u64, |a, &b| a << 8 | u64::from(b));
    let mut input = Vec::with_capacity(rest.len() + 8);
    // Keep the magic so the input reaches past the probe like real
    // classification input would; the rest (header fields included)
    // is attacker-shaped.
    input.extend_from_slice(&[0x89, 0x53, 0x45, 0x4E, 0x43, 0x0D, 0x0A, 0x1A]);
    input.extend_from_slice(rest);

    let full = binmode::authenticate_any(&keys, "fuzz", &input, &mut ScanBudget::with(u64::MAX));
    let cut = binmode::authenticate_any(&keys, "fuzz", &input, &mut ScanBudget::with(budget));
    match full {
        UnitScan::Found(i) => {
            assert!(cut == UnitScan::Found(i) || cut == UnitScan::Inconclusive);
        }
        UnitScan::NoMatch => {
            assert!(matches!(cut, UnitScan::NoMatch | UnitScan::Inconclusive));
        }
        UnitScan::Inconclusive => unreachable!("an unbudgeted scan cannot be inconclusive"),
    }

    let _ = binmode::authenticate_any_prefix(&keys, "fuzz", &input, &mut ScanBudget::with(budget));
});
