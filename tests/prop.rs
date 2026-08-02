//! Property tests: encryption round-trips losslessly for arbitrary byte
//! sequences in both modes, ciphertext is deterministic, and unit-region
//! tampering never yields a successful decryption.

use proptest::prelude::*;
use simple_file_encrypt::consts::TEXT_HEADER_V1;
use simple_file_encrypt::crypto::{DomainKey, FileKeys};
use simple_file_encrypt::probe::{Probe, probe};
use simple_file_encrypt::{binmode, textmode};
use zeroize::Zeroizing;

fn keys() -> Vec<DomainKey> {
    vec![Zeroizing::new([7u8; 32]), Zeroizing::new([9u8; 32])]
}

/// Arbitrary bytes, biased toward newline-heavy content so line
/// splitting gets exercised.
fn content_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop_oneof![3 => any::<u8>(), 1 => Just(b'\n'), 1 => Just(b'\r')],
        0..4096,
    )
}

proptest! {
    #[test]
    fn text_round_trip_is_lossless(content in content_strategy()) {
        let ks = keys();
        let fk = FileKeys::derive(&ks[0], "p/q.txt");
        let ct = textmode::encrypt(&fk, "p/q.txt", &content).unwrap();
        prop_assert_eq!(probe(&ct), Probe::TextV1);
        let (pt, idx) = textmode::decrypt(&ks, "p/q.txt", &ct).unwrap();
        prop_assert_eq!(pt, content.clone());
        prop_assert_eq!(idx, 0);
        // Determinism: same input, same bytes.
        prop_assert_eq!(textmode::encrypt(&fk, "p/q.txt", &content).unwrap(), ct);
    }

    #[test]
    fn binary_round_trip_is_lossless(content in prop::collection::vec(any::<u8>(), 0..200_000)) {
        let ks = keys();
        let fk = FileKeys::derive(&ks[1], "blob.bin");
        let ct = binmode::encrypt(&fk, "blob.bin", &content).unwrap();
        prop_assert_eq!(probe(&ct), Probe::Binary);
        let (pt, idx) = binmode::decrypt(&ks, "blob.bin", &ct).unwrap();
        prop_assert_eq!(pt, content.clone());
        prop_assert_eq!(idx, 1);
        prop_assert_eq!(binmode::encrypt(&fk, "blob.bin", &content).unwrap(), ct);
    }

    /// Flipping any bit in the unit region of a text ciphertext must
    /// fail decryption (format or authentication error) — a successful
    /// forgery would need a 128-bit SIV collision.
    #[test]
    fn text_unit_tampering_is_rejected(
        content in prop::collection::vec(any::<u8>(), 1..512),
        pos_seed in any::<usize>(),
        bit in 0u8..8,
    ) {
        let ks = keys();
        let fk = FileKeys::derive(&ks[0], "p/q.txt");
        let mut ct = textmode::encrypt(&fk, "p/q.txt", &content).unwrap();
        // Everything after the newline-terminated header line.
        let unit_region = (TEXT_HEADER_V1.len() + 1)..ct.len();
        prop_assume!(!unit_region.is_empty());
        let pos = unit_region.start + pos_seed % unit_region.len();
        ct[pos] ^= 1 << bit;
        let tampered = textmode::decrypt(&ks, "p/q.txt", &ct);
        prop_assert!(tampered.is_err());
    }

    /// Same for binary ciphertext: any bit flip anywhere must be caught
    /// by header validation, chunk authentication, or the file tag.
    #[test]
    fn binary_tampering_is_rejected(
        content in prop::collection::vec(any::<u8>(), 0..4096),
        pos_seed in any::<usize>(),
        bit in 0u8..8,
    ) {
        let ks = keys();
        let fk = FileKeys::derive(&ks[0], "blob.bin");
        let mut ct = binmode::encrypt(&fk, "blob.bin", &content).unwrap();
        let pos = pos_seed % ct.len();
        ct[pos] ^= 1 << bit;
        // A flip inside the 8-byte magic makes it probe as plaintext;
        // everything else must decrypt to an error.
        if probe(&ct) == Probe::Binary {
            prop_assert!(binmode::decrypt(&ks, "blob.bin", &ct).is_err());
        } else {
            prop_assert!(pos < 8);
        }
    }

    /// Ciphertext length reveals exactly the plaintext line lengths —
    /// and nothing about the content: two same-shape plaintexts yield
    /// same-shape ciphertexts.
    #[test]
    fn text_ciphertext_size_depends_only_on_shape(lens in prop::collection::vec(0usize..64, 1..20)) {
        let ks = keys();
        let fk = FileKeys::derive(&ks[0], "p/q.txt");
        let a: Vec<u8> = lens.iter().flat_map(|&l| "a".repeat(l).into_bytes().into_iter().chain(*b"\n")).collect();
        let b: Vec<u8> = lens.iter().flat_map(|&l| "b".repeat(l).into_bytes().into_iter().chain(*b"\n")).collect();
        let ca = textmode::encrypt(&fk, "p/q.txt", &a).unwrap();
        let cb = textmode::encrypt(&fk, "p/q.txt", &b).unwrap();
        prop_assert_eq!(ca.len(), cb.len());
    }
}
