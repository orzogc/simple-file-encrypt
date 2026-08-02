#![no_main]

use libfuzzer_sys::fuzz_target;
use simple_file_encrypt::crypto::{ScanBudget, UnitScan};
use simple_file_encrypt::textmode;

// The any-unit ownership scan must never panic, and a budget cut must
// never harden its verdict: whatever the (fuzz-chosen, usually tiny)
// budget, the cut scan may report Inconclusive where the unbudgeted
// one was decisive, but never flip between Found and NoMatch — the
// invariant `rekey --prune` relies on.
fuzz_target!(|data: &[u8]| {
    let keys = vec![zeroize::Zeroizing::new([0x42u8; 32])];
    let (budget_bytes, rest) = data.split_at(data.len().min(2));
    let budget = budget_bytes.iter().fold(0u64, |a, &b| a << 8 | u64::from(b));
    let mut input = Vec::with_capacity(rest.len() + 32);
    input.extend_from_slice(b"#simple-file-encrypt v1 text\n");
    input.extend_from_slice(rest);

    let full = textmode::authenticate_any(&keys, "fuzz", &input, &mut ScanBudget::with(u64::MAX));
    let cut = textmode::authenticate_any(&keys, "fuzz", &input, &mut ScanBudget::with(budget));
    match full {
        UnitScan::Found(i) => {
            assert!(cut == UnitScan::Found(i) || cut == UnitScan::Inconclusive);
        }
        UnitScan::NoMatch => {
            assert!(matches!(cut, UnitScan::NoMatch | UnitScan::Inconclusive));
        }
        UnitScan::Inconclusive => unreachable!("an unbudgeted scan cannot be inconclusive"),
    }
});
