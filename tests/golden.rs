//! Golden fixtures pinning the v1 wire format and the whole derivation
//! chain (Argon2id → KEK → ring wrap → per-path keys → unit/binary
//! ciphertext). If any of these change, the format has changed:
//! that requires a version bump, not a fixture update.

use simple_file_encrypt::crypto::{self, FileKeys, KdfParams};
use simple_file_encrypt::error::Error;
use simple_file_encrypt::{binmode, hexutil, textmode};
use zeroize::Zeroizing;

const GOLDEN_SALT: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const GOLDEN_KDF: KdfParams = KdfParams {
    memory_kib: 8,
    iterations: 1,
    parallelism: 1,
};
const GOLDEN_PATH: &str = "dir/hello.txt";

const KEK_HEX: &str = "02c85df2805a75428bbb03c08c1ee8401a80f901ccb292840b461fb155de711034578f33a42046f0626e49727e1471ff053b7b488c03eef858a486f9aa80f9ec";
const WRAP0_HEX: &str = "eba06ed3bcd06a23298afab93ea32b5a813b10b9b0ff42362d14617523b7adaaef980a61e1cc0c6cff90647d0c672bb2";
const WRAP1_HEX: &str = "ff5d885824eed72f246882eb407610ee63b1c2f1dcdc9be359377e38acb68156a9681c4098903662bff2384ae84277ee";
const TEXT_CT: &str =
    "#simple-file-encrypt v1 text\nsLEZnqFE/IDpOOFx9phV4JIKmr9x\n9lDpBk9esSXSIPKYGsK7OKdusULV\n";
const EMPTY_CT: &str = "#simple-file-encrypt v1 text YQ8q13UJE6xg2QvQEmsLCg\n";
const BIN_CT_HEX: &str = "8953454e430d0a1a0100000000000000a0f6677b3308242740f945f253d33bbede3d7cdb6e7f32e73dd36922326df716de0a2e0a308a12f95b69dbcfb52ff2e2c6f37402cc54671bab73f0a877a2";
const BIG_CT_LEN: usize = 65716;
const BIG_CT_B3: &str = "23c14c8aa77021d6ed8a5e60ec8c3c58e7bb665910862e6ec057ca46942c565f";

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
