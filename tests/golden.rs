//! Golden fixtures pinning the v1 wire format and the whole derivation
//! chain (Argon2id → KEK → ring wrap → per-path keys → unit/binary
//! ciphertext). If any of these change, the format has changed:
//! that requires a version bump, not a fixture update.

use simple_encrypt::crypto::{self, FileKeys, KdfParams};
use simple_encrypt::error::Error;
use simple_encrypt::{binmode, hexutil, textmode};
use zeroize::Zeroizing;

const GOLDEN_SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const GOLDEN_KDF: KdfParams = KdfParams {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};
const GOLDEN_PATH: &str = "dir/hello.txt";

const KEK_HEX: &str = "02c85df2805a75428bbb03c08c1ee8401a80f901ccb292840b461fb155de711034578f33a42046f0626e49727e1471ff053b7b488c03eef858a486f9aa80f9ec";
const WRAP0_HEX: &str = "2cbad57de77b5107a846b30cf3546d5c59686dc97c9519aaa7f377f4548707e275f362c3bbf6fc6dac51d7c92c601c31";
const WRAP1_HEX: &str = "ffdc403cb5677ffa74f4b64f6f773ac6d26aeeaf12755b507e3aaea9f993539ed84202d88d790ed26d21ec476e6fc6fd";
const TEXT_CT: &str =
    "#simple-encrypt v1 text\nacMIkanpzdkzFyPmbQ6L7LZLCB/F\n8Vi0tcGqcGiE6FKLVjsBh7pwVkKo\n";
const EMPTY_CT: &str = "#simple-encrypt v1 text NZxiLoqGBlG4/6x8mgFkQQ\n";
const BIN_CT_HEX: &str = "8953454e430d0a1a01000000000000003ed1f462de5d93e2c3c6a35b5b6e270c32e4eccb251ffd077f9f103b03efc782b7ede02e7ccf7709b57e1b6917a73d0b184a0f8624aeef4692a8a309d173";
const BIG_CT_LEN: usize = 65716;
const BIG_CT_B3: &str = "6918037cd572b2cea3daa7e70d0b7b87df07ca85c7bb3007e3ec8a7a6997fa1e";

fn golden_file_key() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([0x42u8; 32])
}

#[test]
fn kek_derivation_is_pinned() {
    let kek = crypto::derive_kek("golden password", &GOLDEN_SALT, &GOLDEN_KDF).unwrap();
    assert_eq!(hexutil::encode(kek.as_ref()), KEK_HEX);
}

#[test]
fn ring_wrap_is_pinned_and_position_bound() {
    let kek = crypto::derive_kek("golden password", &GOLDEN_SALT, &GOLDEN_KDF).unwrap();
    let dk0 = Zeroizing::new([0xa0u8; 32]);
    let dk1 = Zeroizing::new([0xa1u8; 32]);
    let wrapped = crypto::wrap_ring(&kek, &[dk0.clone(), dk1.clone()]);
    assert_eq!(hexutil::encode(&wrapped[0]), WRAP0_HEX);
    assert_eq!(hexutil::encode(&wrapped[1]), WRAP1_HEX);

    let unwrapped = crypto::unwrap_ring(&kek, &wrapped).unwrap();
    assert_eq!(unwrapped[0].as_ref(), dk0.as_ref());
    assert_eq!(unwrapped[1].as_ref(), dk1.as_ref());

    // The same key wrapped alone (ring length 1) yields different bytes:
    // the AD binds the ring length.
    let alone = crypto::wrap_ring(&kek, std::slice::from_ref(&dk0));
    assert_ne!(hexutil::encode(&alone[0]), WRAP0_HEX);
}

#[test]
fn text_ciphertext_is_pinned() {
    let fk = FileKeys::derive(&golden_file_key(), GOLDEN_PATH);
    let ct = textmode::encrypt(&fk, GOLDEN_PATH, b"hello\nworld\n").unwrap();
    assert_eq!(std::str::from_utf8(&ct).unwrap(), TEXT_CT);

    let keys = vec![golden_file_key()];
    let (pt, idx) = textmode::decrypt(&keys, GOLDEN_PATH, TEXT_CT.as_bytes()).unwrap();
    assert_eq!((pt.as_slice(), idx), (&b"hello\nworld\n"[..], 0));

    // The same content under a different path yields different units.
    let other = FileKeys::derive(&golden_file_key(), "dir/other.txt");
    assert_ne!(
        textmode::encrypt(&other, "dir/other.txt", b"hello\nworld\n").unwrap(),
        ct
    );
}

#[test]
fn empty_marker_is_pinned() {
    let fk = FileKeys::derive(&golden_file_key(), GOLDEN_PATH);
    let ct = textmode::encrypt(&fk, GOLDEN_PATH, b"").unwrap();
    assert_eq!(std::str::from_utf8(&ct).unwrap(), EMPTY_CT);

    let keys = vec![golden_file_key()];
    let (pt, _) = textmode::decrypt(&keys, GOLDEN_PATH, EMPTY_CT.as_bytes()).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn binary_ciphertext_is_pinned() {
    let fk = FileKeys::derive(&golden_file_key(), GOLDEN_PATH);
    let ct = binmode::encrypt(&fk, GOLDEN_PATH, b"\x00\x01\x02binary body").unwrap();
    assert_eq!(hexutil::encode(&ct), BIN_CT_HEX);

    let keys = vec![golden_file_key()];
    let (pt, idx) = binmode::decrypt(&keys, GOLDEN_PATH, &ct).unwrap();
    assert_eq!((pt.as_slice(), idx), (&b"\x00\x01\x02binary body"[..], 0));

    // Two-chunk fixture: length and content hash pinned.
    let big: Vec<u8> = (0..65536 + 100).map(|i| (i % 251) as u8).collect();
    let big_ct = binmode::encrypt(&fk, GOLDEN_PATH, &big).unwrap();
    assert_eq!(big_ct.len(), BIG_CT_LEN);
    assert_eq!(blake3::hash(&big_ct).to_string(), BIG_CT_B3);
    assert_eq!(
        binmode::decrypt(&keys, GOLDEN_PATH, &big_ct).unwrap().0,
        big
    );
}

#[test]
fn wrong_password_is_detected_by_the_wrap() {
    let kek = crypto::derive_kek("golden password", &GOLDEN_SALT, &GOLDEN_KDF).unwrap();
    let wrapped = crypto::wrap_ring(&kek, &[golden_file_key()]);
    let bad = crypto::derive_kek("wrong password", &GOLDEN_SALT, &GOLDEN_KDF).unwrap();
    assert!(matches!(
        crypto::unwrap_ring(&bad, &wrapped),
        Err(Error::WrongPassword)
    ));
}
