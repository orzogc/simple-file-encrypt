//! Cryptographic core: Argon2id KDF with tiered parameter validation,
//! the envelope key hierarchy, key-ring wrapping, and AES-CMAC-SIV unit
//! encryption through the raw (nonce-free) SIV interface.
//!
//! Specified in `docs/crypto.md`; byte layouts in `docs/format.md`.

use aes_siv::KeyInit;
use aes_siv::siv::Aes256Siv;
use zeroize::Zeroizing;

use crate::consts::*;
use crate::error::{Error, Result};

/// Associated-data prefix for wrapping ring entries; `le64(ring_len)` and
/// `le64(index)` are appended.
pub const AD_WRAP_PREFIX: &[u8] = b"github.com/orzogc/simple-encrypt v1 domain key wrap";
/// BLAKE3 `derive_key` context for the per-file unit key.
pub const CTX_UNIT: &str = "github.com/orzogc/simple-encrypt v1 unit key";
/// BLAKE3 `derive_key` context for the binary whole-file tag key.
pub const CTX_FILE_TAG: &str = "github.com/orzogc/simple-encrypt v1 binary file tag key";
/// Associated data of every text-line unit.
pub const AD_TEXT: &[u8] = b"github.com/orzogc/simple-encrypt v1 text unit";
/// Associated data of the authenticated empty-file marker.
pub const AD_TEXT_EMPTY: &[u8] = b"github.com/orzogc/simple-encrypt v1 text empty file";
/// Associated-data prefix of binary chunks; `le64(index)` and a
/// last-chunk flag byte are appended.
pub const AD_BIN_PREFIX: &[u8] = b"github.com/orzogc/simple-encrypt v1 binary chunk";

/// A 64-byte key-encryption key derived from the password via Argon2id.
pub type Kek = Zeroizing<[u8; KEK_LEN]>;
/// A 32-byte random domain key (one ring entry's plaintext).
pub type DomainKey = Zeroizing<[u8; DOMAIN_KEY_LEN]>;

/// Validated Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Pass count.
    pub iterations: u32,
    /// Lane count.
    pub parallelism: u32,
}

impl KdfParams {
    /// The defaults written by `init`.
    pub const DEFAULT: KdfParams = KdfParams {
        memory_kib: KDF_DEFAULT_MEMORY_KIB,
        iterations: KDF_DEFAULT_ITERATIONS,
        parallelism: KDF_DEFAULT_PARALLELISM,
    };

    /// Whether this cost exceeds the defaults in any dimension (such a
    /// cost is announced before Argon2 runs).
    pub fn exceeds_default(&self) -> bool {
        self.memory_kib > KDF_DEFAULT_MEMORY_KIB
            || self.iterations > KDF_DEFAULT_ITERATIONS
            || self.parallelism > KDF_DEFAULT_PARALLELISM
    }
}

/// CLI override flags for the KDF policy tiers.
#[derive(Debug, Clone, Copy, Default)]
pub struct KdfGate {
    /// `--allow-weak-kdf`: accept parameters below the security floor.
    pub allow_weak: bool,
    /// `--allow-expensive-kdf`: accept parameters above the resource ceiling.
    pub allow_expensive: bool,
}

/// Validates the structural tiers that apply regardless of flags:
/// validity (hard) and the absolute caps (hard even with flags).
/// Inputs are raw config integers, bounds-checked before conversion.
pub fn validate_kdf_structural(
    memory_kib: u64,
    iterations: u64,
    parallelism: u64,
) -> Result<KdfParams> {
    // Validity tier.
    if parallelism < 1 {
        return Err(Error::Kdf(
            "invalid KDF parameters: parallelism must be >= 1".into(),
        ));
    }
    if iterations < 1 {
        return Err(Error::Kdf(
            "invalid KDF parameters: iterations must be >= 1".into(),
        ));
    }
    let min_memory = parallelism
        .checked_mul(8)
        .ok_or_else(|| Error::Kdf("KDF parameter overflow".into()))?;
    if memory_kib < min_memory {
        return Err(Error::Kdf(format!(
            "invalid KDF parameters: memory_kib must be >= 8 * parallelism (= {min_memory})"
        )));
    }
    // Absolute caps (hard errors even with override flags).
    if memory_kib > 4_194_304 {
        return Err(Error::Kdf(
            "KDF parameters exceed the absolute cap: memory_kib > 4194304 (4 GiB)".into(),
        ));
    }
    if iterations > 1024 {
        return Err(Error::Kdf(
            "KDF parameters exceed the absolute cap: iterations > 1024".into(),
        ));
    }
    if parallelism > 64 {
        return Err(Error::Kdf(
            "KDF parameters exceed the absolute cap: parallelism > 64".into(),
        ));
    }
    let product = memory_kib
        .checked_mul(iterations)
        .ok_or_else(|| Error::Kdf("KDF parameter overflow".into()))?;
    if product > 67_108_864 {
        return Err(Error::Kdf(
            "KDF parameters exceed the absolute cap: memory_kib * iterations > 67108864 (64 GiB·passes)".into(),
        ));
    }
    // The absolute caps guarantee these fit in u32.
    Ok(KdfParams {
        memory_kib: u32::try_from(memory_kib).expect("capped above"),
        iterations: u32::try_from(iterations).expect("capped above"),
        parallelism: u32::try_from(parallelism).expect("capped above"),
    })
}

/// Enforces the flag-gated policy tiers (security floor and resource
/// ceiling); called before Argon2 runs.
pub fn check_kdf_policy(p: &KdfParams, gate: &KdfGate) -> Result<()> {
    if !gate.allow_weak && (p.memory_kib < 19456 || p.iterations < 2) {
        return Err(Error::Kdf(format!(
            "KDF parameters are below the security floor (memory_kib >= 19456 and iterations >= 2; \
             got memory_kib = {}, iterations = {}); pass --allow-weak-kdf to accept them",
            p.memory_kib, p.iterations
        )));
    }
    if !gate.allow_expensive {
        let product = u64::from(p.memory_kib) * u64::from(p.iterations);
        if p.memory_kib > 262_144 || p.iterations > 64 || product > 2_097_152 || p.parallelism > 4 {
            return Err(Error::Kdf(format!(
                "KDF parameters exceed the resource ceiling (memory_kib <= 262144, iterations <= 64, \
                 memory_kib * iterations <= 2097152, parallelism <= 4; got memory_kib = {}, \
                 iterations = {}, parallelism = {}); pass --allow-expensive-kdf to run them anyway",
                p.memory_kib, p.iterations, p.parallelism
            )));
        }
    }
    Ok(())
}

/// Derives the 64-byte KEK from the password with Argon2id v1.3.
///
/// The password is used as the exact UTF-8 bytes supplied; policy tiers
/// must have been checked by the caller.
pub fn derive_kek(password: &str, salt: &[u8; SALT_LEN], params: &KdfParams) -> Result<Kek> {
    let a2_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEK_LEN),
    )
    .map_err(|e| Error::Kdf(format!("invalid Argon2 parameters: {e}")))?;
    let a2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        a2_params,
    );
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    a2.hash_password_into(password.as_bytes(), salt, kek.as_mut())
        .map_err(|e| Error::Kdf(format!("Argon2 failed: {e}")))?;
    Ok(kek)
}

/// Builds the wrap associated data binding ring length `n` and entry
/// index `i`.
pub fn ad_wrap(n: u64, i: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_WRAP_PREFIX.len() + 16);
    ad.extend_from_slice(AD_WRAP_PREFIX);
    ad.extend_from_slice(&n.to_le_bytes());
    ad.extend_from_slice(&i.to_le_bytes());
    ad
}

/// Wraps an ordered ring of domain keys under one KEK, binding each
/// entry to the ring length and its position.
pub fn wrap_ring(kek: &Kek, keys: &[DomainKey]) -> Vec<[u8; WRAPPED_KEY_LEN]> {
    let n = keys.len() as u64;
    let mut siv = Aes256Siv::new(kek.as_ref().into());
    keys.iter()
        .enumerate()
        .map(|(i, key)| {
            let out = siv
                .encrypt([ad_wrap(n, i as u64)], key.as_ref())
                .expect("SIV encryption with one header component cannot fail");
            <[u8; WRAPPED_KEY_LEN]>::try_from(out.as_slice())
                .expect("SIV(16) || CT(32) is 48 bytes")
        })
        .collect()
}

/// Unwraps the whole ring under one KEK.
///
/// A failure on entry 0 is the password check ([`Error::WrongPassword`]);
/// a failure on a later entry means the ring does not unwrap consistently
/// and the config is corrupt ([`Error::RingCorrupt`]).
pub fn unwrap_ring(kek: &Kek, wrapped: &[[u8; WRAPPED_KEY_LEN]]) -> Result<Vec<DomainKey>> {
    let n = wrapped.len() as u64;
    let mut siv = Aes256Siv::new(kek.as_ref().into());
    let mut keys = Vec::with_capacity(wrapped.len());
    for (i, entry) in wrapped.iter().enumerate() {
        let pt = siv
            .decrypt([ad_wrap(n, i as u64)], entry.as_slice())
            .map_err(|_| {
                if i == 0 {
                    Error::WrongPassword
                } else {
                    Error::RingCorrupt { index: i }
                }
            })?;
        let mut key = Zeroizing::new([0u8; DOMAIN_KEY_LEN]);
        key.copy_from_slice(&pt);
        // The decrypted buffer holds key material; wipe it.
        drop(Zeroizing::new(pt));
        keys.push(key);
    }
    Ok(keys)
}

/// Per-file key material derived from one domain key and the canonical
/// relative path.
pub struct FileKeys {
    /// 64-byte AES-SIV key for every unit of this file.
    unit_key: Zeroizing<[u8; UNIT_KEY_LEN]>,
    /// Intermediate keyed-hash output; input to further derivations.
    file_km: Zeroizing<[u8; 32]>,
}

impl FileKeys {
    /// Derives the file keys: `file_km = keyed_hash(domain_key, path)`,
    /// `unit_key = derive_key_xof(CTX_UNIT, file_km, 64)`.
    pub fn derive(domain_key: &DomainKey, canonical_path: &str) -> FileKeys {
        let mut file_km = Zeroizing::new([0u8; 32]);
        blake3::Hasher::new_keyed(domain_key)
            .update(canonical_path.as_bytes())
            .finalize_xof()
            .fill(file_km.as_mut());
        let mut unit_key = Zeroizing::new([0u8; UNIT_KEY_LEN]);
        blake3::Hasher::new_derive_key(CTX_UNIT)
            .update(file_km.as_ref())
            .finalize_xof()
            .fill(unit_key.as_mut());
        FileKeys { unit_key, file_km }
    }

    /// Encrypts one unit: returns `SIV(16) || ciphertext`.
    pub fn unit_encrypt(&self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        Aes256Siv::new(self.unit_key.as_ref().into())
            .encrypt([ad], plaintext)
            .expect("SIV encryption with one header component cannot fail")
    }

    /// Decrypts and authenticates one unit; `None` on authentication
    /// failure (the SIV comparison is constant-time inside the cipher).
    pub fn unit_decrypt(&self, ad: &[u8], unit: &[u8]) -> Option<Vec<u8>> {
        Aes256Siv::new(self.unit_key.as_ref().into())
            .decrypt([ad], unit)
            .ok()
    }

    /// Computes the binary whole-file tag over the header, the plaintext
    /// length, the chunk count, and the ordered chunk SIVs.
    pub fn file_tag(
        &self,
        header: &[u8; BIN_HEADER_LEN],
        plaintext_len: u64,
        sivs: &[[u8; SIV_LEN]],
    ) -> blake3::Hash {
        let mut tag_key = Zeroizing::new([0u8; 32]);
        blake3::Hasher::new_derive_key(CTX_FILE_TAG)
            .update(self.file_km.as_ref())
            .finalize_xof()
            .fill(tag_key.as_mut());
        let mut hasher = blake3::Hasher::new_keyed(&tag_key);
        hasher.update(header);
        hasher.update(&plaintext_len.to_le_bytes());
        hasher.update(&(sivs.len() as u64).to_le_bytes());
        for siv in sivs {
            hasher.update(siv);
        }
        hasher.finalize()
    }
}

/// Builds the associated data of binary chunk `index`.
pub fn ad_bin(index: u64, last: bool) -> Vec<u8> {
    let mut ad = Vec::with_capacity(AD_BIN_PREFIX.len() + 9);
    ad.extend_from_slice(AD_BIN_PREFIX);
    ad.extend_from_slice(&index.to_le_bytes());
    ad.push(u8::from(last));
    ad
}

/// Fills a fixed-size buffer from the OS CSPRNG.
pub fn random_array<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    use rand::TryRng;
    let mut buf = Zeroizing::new([0u8; N]);
    rand::rngs::SysRng
        .try_fill_bytes(buf.as_mut())
        .map_err(|e| Error::Io {
            op: "reading OS randomness for",
            path: "(csprng)".into(),
            source: e.into(),
        })?;
    Ok(buf)
}

/// Generates a fresh random domain key.
pub fn random_domain_key() -> Result<DomainKey> {
    random_array::<DOMAIN_KEY_LEN>()
}

/// Generates a fresh random KDF salt.
pub fn random_salt() -> Result<[u8; SALT_LEN]> {
    Ok(*random_array::<SALT_LEN>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> Kek {
        let mut kek = Zeroizing::new([0u8; KEK_LEN]);
        for (i, b) in kek.iter_mut().enumerate() {
            *b = i as u8;
        }
        kek
    }

    fn test_keys(n: usize) -> Vec<DomainKey> {
        (0..n)
            .map(|i| {
                let mut k = Zeroizing::new([0u8; DOMAIN_KEY_LEN]);
                k.fill(i as u8 + 1);
                k
            })
            .collect()
    }

    #[test]
    fn ring_round_trip_and_order_binding() {
        let kek = test_kek();
        let keys = test_keys(3);
        let wrapped = wrap_ring(&kek, &keys);
        let unwrapped = unwrap_ring(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped.len(), 3);
        for (a, b) in keys.iter().zip(&unwrapped) {
            assert_eq!(a.as_ref(), b.as_ref());
        }

        // Swapping entries breaks the position binding.
        let mut swapped = wrapped.clone();
        swapped.swap(1, 2);
        assert!(matches!(
            unwrap_ring(&kek, &swapped),
            Err(Error::RingCorrupt { index: 1 })
        ));

        // Tail truncation changes the ring length and breaks entry 0 too.
        assert!(matches!(
            unwrap_ring(&kek, &wrapped[..2]),
            Err(Error::WrongPassword)
        ));

        // Duplicating an entry fails at the duplicate's position.
        let mut dup = wrapped.clone();
        dup.push(wrapped[2]);
        assert!(matches!(unwrap_ring(&kek, &dup), Err(Error::WrongPassword)));

        // A wrong KEK fails as a wrong password.
        let mut bad = test_kek();
        bad[0] ^= 1;
        assert!(matches!(
            unwrap_ring(&bad, &wrapped),
            Err(Error::WrongPassword)
        ));
    }

    #[test]
    fn unit_encryption_is_deterministic_and_authenticated() {
        let keys = test_keys(1);
        let fk = FileKeys::derive(&keys[0], "a/b.txt");
        let c1 = fk.unit_encrypt(AD_TEXT, b"hello");
        let c2 = fk.unit_encrypt(AD_TEXT, b"hello");
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 5 + SIV_LEN);
        assert_eq!(fk.unit_decrypt(AD_TEXT, &c1).unwrap(), b"hello");

        // Tampering with any byte fails authentication.
        for i in 0..c1.len() {
            let mut t = c1.clone();
            t[i] ^= 1;
            assert!(fk.unit_decrypt(AD_TEXT, &t).is_none());
        }
        // A different AD fails authentication.
        assert!(fk.unit_decrypt(AD_TEXT_EMPTY, &c1).is_none());
        // A different path yields different ciphertext.
        let fk2 = FileKeys::derive(&keys[0], "a/c.txt");
        assert_ne!(fk2.unit_encrypt(AD_TEXT, b"hello"), c1);
        // Zero-length plaintext is a valid input: SIV only.
        let empty = fk.unit_encrypt(AD_TEXT, b"");
        assert_eq!(empty.len(), SIV_LEN);
        assert_eq!(fk.unit_decrypt(AD_TEXT, &empty).unwrap(), b"");
    }

    #[test]
    fn kdf_tier_validation() {
        // Validity tier.
        assert!(validate_kdf_structural(65536, 3, 0).is_err());
        assert!(validate_kdf_structural(65536, 0, 1).is_err());
        assert!(validate_kdf_structural(7, 1, 1).is_err());
        // Absolute caps, regardless of flags.
        assert!(validate_kdf_structural(4_194_305, 1, 1).is_err());
        assert!(validate_kdf_structural(65536, 1025, 1).is_err());
        assert!(validate_kdf_structural(65536, 3, 65).is_err());
        assert!(validate_kdf_structural(4_194_304, 17, 1).is_err()); // product > 64 GiB·passes
        // Policy tiers.
        let default = KdfParams::DEFAULT;
        assert!(check_kdf_policy(&default, &KdfGate::default()).is_ok());
        let weak = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        assert!(check_kdf_policy(&weak, &KdfGate::default()).is_err());
        assert!(
            check_kdf_policy(
                &weak,
                &KdfGate {
                    allow_weak: true,
                    allow_expensive: false
                }
            )
            .is_ok()
        );
        let expensive = KdfParams {
            memory_kib: 262_145,
            iterations: 2,
            parallelism: 1,
        };
        assert!(check_kdf_policy(&expensive, &KdfGate::default()).is_err());
        assert!(
            check_kdf_policy(
                &expensive,
                &KdfGate {
                    allow_weak: false,
                    allow_expensive: true
                }
            )
            .is_ok()
        );
        let product_heavy = KdfParams {
            memory_kib: 262_144,
            iterations: 9,
            parallelism: 1,
        };
        assert!(check_kdf_policy(&product_heavy, &KdfGate::default()).is_err());
    }

    #[test]
    fn kek_derivation_matches_parameters() {
        let salt = [7u8; SALT_LEN];
        let params = KdfParams {
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        };
        let k1 = derive_kek("pw", &salt, &params).unwrap();
        let k2 = derive_kek("pw", &salt, &params).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());
        let k3 = derive_kek("pw2", &salt, &params).unwrap();
        assert_ne!(k1.as_ref(), k3.as_ref());
    }
}
