//! Binary-mode ciphertext: 64 KiB AES-SIV chunks with index/last-flag
//! associated data, plus a deterministic whole-file tag that binds the
//! header, lengths, and the ordered chunk SIVs (see `docs/format.md`).

use crate::consts::*;
use crate::crypto::{DomainKey, FileKeys, ad_bin};
use crate::error::{Error, Result};

/// On-disk size of a full chunk: `CHUNK_SIZE + SIV_LEN`.
const CHUNK_DISK: usize = CHUNK_SIZE + SIV_LEN;

/// The 16-byte v1 binary header.
fn header_v1() -> [u8; BIN_HEADER_LEN] {
    let mut h = [0u8; BIN_HEADER_LEN];
    h[..8].copy_from_slice(&BIN_MAGIC);
    h[8] = 0x01; // version
    h
}

/// Encrypts plaintext in binary mode. `path` is used only for error
/// context; the keys must already be derived for this path.
pub fn encrypt(fk: &FileKeys, path: &str, content: &[u8]) -> Result<Vec<u8>> {
    let len = content.len() as u64;
    let chunk_count = content.len().div_ceil(CHUNK_SIZE).max(1) as u64;
    let ct_size = BIN_HEADER_LEN as u64 + len + SIV_LEN as u64 * chunk_count + FILE_TAG_LEN as u64;
    if ct_size > MAX_FILE_SIZE {
        return Err(Error::Limit(format!(
            "`{path}`: binary ciphertext would be {ct_size} bytes, exceeding the {MAX_FILE_SIZE}-byte cap"
        )));
    }

    let header = header_v1();
    let mut out = Vec::with_capacity(ct_size as usize);
    out.extend_from_slice(&header);
    let mut sivs: Vec<[u8; SIV_LEN]> = Vec::with_capacity(chunk_count as usize);
    // An empty plaintext is exactly one zero-length chunk.
    let chunks: Vec<&[u8]> = if content.is_empty() {
        vec![&[][..]]
    } else {
        content.chunks(CHUNK_SIZE).collect()
    };
    for (i, chunk) in chunks.iter().enumerate() {
        let last = i == chunks.len() - 1;
        let unit = fk.unit_encrypt(&ad_bin(i as u64, last), chunk);
        sivs.push(
            <[u8; SIV_LEN]>::try_from(&unit[..SIV_LEN]).expect("unit starts with a 16-byte SIV"),
        );
        out.extend_from_slice(&unit);
    }
    let tag = fk.file_tag(&header, len, &sivs);
    out.extend_from_slice(tag.as_bytes());
    Ok(out)
}

/// One chunk's extent inside the ciphertext body, plus its AD inputs.
struct ChunkPlan {
    /// Byte range within the chunk region.
    start: usize,
    end: usize,
    /// Last-chunk flag bound into the AD.
    last: bool,
}

/// Structurally parses a binary ciphertext: header fields, chunk
/// boundaries, and overall lengths. No cryptography.
fn parse_structure(path: &str, ct: &[u8]) -> Result<Vec<ChunkPlan>> {
    // 16-byte header + at least one (possibly empty) chunk + 32-byte tag.
    if ct.len() < BIN_HEADER_LEN + SIV_LEN + FILE_TAG_LEN {
        return Err(Error::format(
            path,
            "binary ciphertext shorter than the 64-byte minimum",
        ));
    }
    debug_assert_eq!(ct[..8], BIN_MAGIC, "caller probes before parsing");
    let version = ct[8];
    if version != 0x01 {
        if version > 0x01 {
            return Err(Error::NewerVersion(format!(
                "`{path}`: binary ciphertext version {version}"
            )));
        }
        return Err(Error::format(
            path,
            format!("invalid binary ciphertext version {version}"),
        ));
    }
    if ct[9] != 0 {
        return Err(Error::format(path, "non-zero flags byte in binary header"));
    }
    if ct[10..BIN_HEADER_LEN].iter().any(|&b| b != 0) {
        return Err(Error::format(
            path,
            "non-zero reserved bytes in binary header",
        ));
    }

    let body_len = ct.len() - BIN_HEADER_LEN - FILE_TAG_LEN;
    let mut chunks = Vec::with_capacity(body_len / CHUNK_DISK + 1);
    let mut remaining = body_len;
    let mut offset = 0usize;
    while remaining > CHUNK_DISK {
        chunks.push(ChunkPlan {
            start: offset,
            end: offset + CHUNK_DISK,
            last: false,
        });
        offset += CHUNK_DISK;
        remaining -= CHUNK_DISK;
    }
    if remaining < SIV_LEN {
        return Err(Error::format(path, "binary ciphertext truncated mid-chunk"));
    }
    if remaining == SIV_LEN && !chunks.is_empty() {
        return Err(Error::format(path, "zero-length chunk at a non-zero index"));
    }
    chunks.push(ChunkPlan {
        start: offset,
        end: offset + remaining,
        last: true,
    });
    Ok(chunks)
}

/// Selects the ring key that authenticates the first chunk. Returns the
/// key index and the derived file keys.
fn select_key(
    keys: &[DomainKey],
    path: &str,
    ct: &[u8],
    first: &ChunkPlan,
) -> Result<(usize, FileKeys)> {
    let body = &ct[BIN_HEADER_LEN..];
    let unit = &body[first.start..first.end];
    for (i, key) in keys.iter().enumerate() {
        let fk = FileKeys::derive(key, path);
        if fk.unit_decrypt(&ad_bin(0, first.last), unit).is_some() {
            return Ok((i, fk));
        }
    }
    Err(Error::auth(path, crate::textmode::FIRST_UNIT_AUTH_HINT))
}

/// Authenticates only the first chunk against the ring (after full
/// structural validation); used by `encrypt` to decide skip/migrate.
/// Returns the authenticating key index.
pub fn authenticate_first(keys: &[DomainKey], path: &str, ct: &[u8]) -> Result<usize> {
    let chunks = parse_structure(path, ct)?;
    Ok(select_key(keys, path, ct, &chunks[0])?.0)
}

/// Decrypts a binary ciphertext, trying ring keys in order on the first
/// chunk, requiring every later chunk to authenticate under the same
/// key, and verifying the whole-file tag in constant time. Returns the
/// plaintext and the ring-key index used.
pub fn decrypt(keys: &[DomainKey], path: &str, ct: &[u8]) -> Result<(Vec<u8>, usize)> {
    let chunks = parse_structure(path, ct)?;
    let (idx, fk) = select_key(keys, path, ct, &chunks[0])?;

    let header: &[u8; BIN_HEADER_LEN] = ct[..BIN_HEADER_LEN].try_into().expect("length checked");
    let body = &ct[BIN_HEADER_LEN..ct.len() - FILE_TAG_LEN];
    let trailer: [u8; FILE_TAG_LEN] = ct[ct.len() - FILE_TAG_LEN..]
        .try_into()
        .expect("length checked");

    let mut out: Vec<u8> = Vec::with_capacity(body.len() - chunks.len() * SIV_LEN);
    let mut sivs: Vec<[u8; SIV_LEN]> = Vec::with_capacity(chunks.len());
    for (i, plan) in chunks.iter().enumerate() {
        let unit = &body[plan.start..plan.end];
        let pt = fk.unit_decrypt(&ad_bin(i as u64, plan.last), unit).ok_or_else(|| {
            Error::auth(
                path,
                format!(
                    "binary chunk {i} does not authenticate under the ring key that authenticated \
                     chunk 0: corrupted, reordered, or truncated ciphertext — or a merge that mixed \
                     chunks from before and after a rekey (re-resolve taking the whole file from one side)"
                ),
            )
        })?;
        sivs.push(<[u8; SIV_LEN]>::try_from(&unit[..SIV_LEN]).expect("chunk has at least a SIV"));
        out.extend_from_slice(&pt);
    }
    if out.len() as u64 > MAX_FILE_SIZE {
        return Err(Error::Limit(format!(
            "`{path}`: decrypted plaintext exceeds the {MAX_FILE_SIZE}-byte cap"
        )));
    }
    let computed = fk.file_tag(header, out.len() as u64, &sivs);
    // blake3::Hash equality is constant-time.
    if computed != blake3::Hash::from_bytes(trailer) {
        return Err(Error::auth(
            path,
            "whole-file tag mismatch: chunks were substituted from another version of this file",
        ));
    }
    Ok((out, idx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn keys(n: usize) -> Vec<DomainKey> {
        (0..n)
            .map(|i| {
                let mut k = Zeroizing::new([0u8; DOMAIN_KEY_LEN]);
                k.fill(i as u8 + 0x10);
                k
            })
            .collect()
    }

    fn round_trip(content: &[u8]) -> Vec<u8> {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        let ct = encrypt(&fk, "blob", content).unwrap();
        let (pt, idx) = decrypt(&ks, "blob", &ct).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(pt, content);
        ct
    }

    #[test]
    fn round_trips_and_sizes() {
        let ct = round_trip(b"");
        assert_eq!(ct.len(), 64); // header + empty chunk SIV + tag
        round_trip(b"x");
        round_trip(&vec![7u8; CHUNK_SIZE - 1]);
        let ct = round_trip(&vec![7u8; CHUNK_SIZE]);
        assert_eq!(ct.len(), 16 + CHUNK_SIZE + 16 + 32); // exactly one chunk
        let ct = round_trip(&vec![7u8; CHUNK_SIZE + 1]);
        assert_eq!(ct.len(), 16 + (CHUNK_SIZE + 1) + 32 + 32); // two chunks
        round_trip(&vec![9u8; 3 * CHUNK_SIZE + 17]);
        // Deterministic.
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        assert_eq!(
            encrypt(&fk, "blob", b"data").unwrap(),
            encrypt(&fk, "blob", b"data").unwrap()
        );
    }

    #[test]
    fn header_strictness() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        let ct = encrypt(&fk, "blob", b"data").unwrap();

        let mut newer = ct.clone();
        newer[8] = 0x02;
        assert!(matches!(
            decrypt(&ks, "blob", &newer),
            Err(Error::NewerVersion(_))
        ));
        let mut flags = ct.clone();
        flags[9] = 0x01;
        assert!(matches!(
            decrypt(&ks, "blob", &flags),
            Err(Error::Format { .. })
        ));
        let mut reserved = ct.clone();
        reserved[12] = 0x01;
        assert!(matches!(
            decrypt(&ks, "blob", &reserved),
            Err(Error::Format { .. })
        ));
        assert!(matches!(
            decrypt(&ks, "blob", &ct[..40]),
            Err(Error::Format { .. })
        ));
    }

    #[test]
    fn tamper_rejections() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        let two_chunks: Vec<u8> = (0..CHUNK_SIZE + 100).map(|i| i as u8).collect();
        let ct = encrypt(&fk, "blob", &two_chunks).unwrap();

        // Flip a body byte: chunk authentication fails.
        let mut t = ct.clone();
        t[BIN_HEADER_LEN + 20] ^= 1;
        assert!(matches!(decrypt(&ks, "blob", &t), Err(Error::Auth { .. })));

        // Truncating at the first chunk boundary: it becomes the final
        // chunk and fails its last-flag AD.
        let truncated = &ct[..BIN_HEADER_LEN + CHUNK_DISK];
        let mut t = truncated.to_vec();
        t.extend_from_slice(&ct[ct.len() - FILE_TAG_LEN..]); // keep a 32-byte trailer
        assert!(matches!(decrypt(&ks, "blob", &t), Err(Error::Auth { .. })));

        // Appending data shifts every boundary and fails.
        let mut t = ct.clone();
        t.extend_from_slice(&[0u8; 8]);
        assert!(decrypt(&ks, "blob", &t).is_err());

        // Flip a tag byte: whole-file tag mismatch.
        let mut t = ct.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        let err = decrypt(&ks, "blob", &t).unwrap_err();
        assert!(err.to_string().contains("tag"));

        // Wrong path fails on the first chunk.
        assert!(matches!(
            decrypt(&ks, "other", &ct),
            Err(Error::Auth { .. })
        ));
    }

    #[test]
    fn cross_version_chunk_splice_hits_the_file_tag() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        let mut v1 = vec![0x41u8; CHUNK_SIZE];
        v1.extend_from_slice(b"tail");
        let mut v2 = vec![0x42u8; CHUNK_SIZE];
        v2.extend_from_slice(b"tail");
        let ct1 = encrypt(&fk, "blob", &v1).unwrap();
        let mut spliced = encrypt(&fk, "blob", &v2).unwrap();
        // Substitute v1's chunk 0 (same index, same path, same key):
        // every unit authenticates, only the file tag catches it.
        spliced[BIN_HEADER_LEN..BIN_HEADER_LEN + CHUNK_DISK]
            .copy_from_slice(&ct1[BIN_HEADER_LEN..BIN_HEADER_LEN + CHUNK_DISK]);
        let err = decrypt(&ks, "blob", &spliced).unwrap_err();
        assert!(err.to_string().contains("tag"), "got: {err}");
    }

    #[test]
    fn zero_length_chunk_only_at_index_zero() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "blob");
        // Craft: one full chunk followed by a bare-SIV (empty) chunk.
        let full = vec![1u8; CHUNK_SIZE];
        let ct = encrypt(&fk, "blob", &full).unwrap(); // single full chunk
        let empty_unit = fk.unit_encrypt(&ad_bin(1, true), b"");
        let mut crafted = ct[..BIN_HEADER_LEN + CHUNK_DISK].to_vec();
        crafted.extend_from_slice(&empty_unit);
        crafted.extend_from_slice(&[0u8; FILE_TAG_LEN]);
        let err = decrypt(&ks, "blob", &crafted).unwrap_err();
        assert!(err.to_string().contains("zero-length chunk"), "got: {err}");
    }

    #[test]
    fn ring_key_selection() {
        let ks = keys(3);
        let fk_old = FileKeys::derive(&ks[2], "blob");
        let ct = encrypt(&fk_old, "blob", b"old epoch data").unwrap();
        let (pt, idx) = decrypt(&ks, "blob", &ct).unwrap();
        assert_eq!((pt.as_slice(), idx), (&b"old epoch data"[..], 2));
        assert_eq!(authenticate_first(&ks, "blob", &ct).unwrap(), 2);
        // A pruned ring no longer decrypts it.
        assert!(matches!(
            decrypt(&ks[..2], "blob", &ct),
            Err(Error::Auth { .. })
        ));
    }
}
