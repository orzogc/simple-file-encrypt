//! Text-mode ciphertext: one deterministic AES-SIV unit per plaintext
//! line, base64-encoded, LF-framed (see `docs/format.md`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;

use crate::consts::*;
use crate::crypto::{AD_TEXT, AD_TEXT_EMPTY, DomainKey, FileKeys};
use crate::error::{Error, Result};

/// Splits plaintext into lines at `\n` (terminators not included; `\r`
/// stays inside the line) and reports whether the content ended with a
/// newline. Empty content yields no lines.
pub fn split_lines(content: &[u8]) -> (Vec<&[u8]>, bool) {
    if content.is_empty() {
        return (Vec::new(), false);
    }
    let trailing = content.ends_with(b"\n");
    let body = if trailing {
        &content[..content.len() - 1]
    } else {
        content
    };
    // `body` has no trailing newline left, so a plain split is exact.
    (body.split(|&b| b == b'\n').collect(), trailing)
}

/// Exact line count of non-empty content, computed without
/// materializing the line slices, so the `MAX_UNITS` cap can be
/// enforced before allocating per-line bookkeeping (a hostile
/// newline-only input would otherwise cost ~17x its size in slices).
fn count_lines(content: &[u8]) -> u64 {
    let newlines = content.iter().filter(|&&b| b == b'\n').count() as u64;
    if content.ends_with(b"\n") {
        newlines
    } else {
        newlines + 1
    }
}

/// Errors when non-empty content (or a unit region) holds more than
/// `MAX_UNITS` lines.
fn check_line_count(path: &str, content: &[u8], what: &str) -> Result<()> {
    let lines = count_lines(content);
    if lines > MAX_UNITS {
        return Err(Error::Limit(format!(
            "`{path}`: {lines} {what} exceed the {MAX_UNITS}-line cap for text mode; \
             add the path to `force_binary` in the config"
        )));
    }
    Ok(())
}

/// Exact base64 (standard, no padding) length of `n` input bytes.
fn b64_len(n: u64) -> u64 {
    4 * (n / 3)
        + match n % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

/// Computes the exact text ciphertext size for the given line lengths,
/// without doing any cryptographic work.
fn ciphertext_size(line_lens: &[u64], trailing: bool) -> u64 {
    let header = TEXT_HEADER_V1.len() as u64 + 1;
    let units: u64 = line_lens.iter().map(|&l| b64_len(l + SIV_LEN as u64)).sum();
    let separators = line_lens.len().saturating_sub(1) as u64;
    header + units + separators + u64::from(trailing)
}

/// Encrypts plaintext in text mode. `path` is used only for error
/// context; the keys must already be derived for this path.
pub fn encrypt(fk: &FileKeys, path: &str, content: &[u8]) -> Result<Vec<u8>> {
    if content.is_empty() {
        let marker = fk.unit_encrypt(AD_TEXT_EMPTY, b"");
        let mut out = String::with_capacity(TEXT_HEADER_V1.len() + 1 + EMPTY_MARKER_B64_LEN + 1);
        out.push_str(TEXT_HEADER_V1);
        out.push(' ');
        out.push_str(&STANDARD_NO_PAD.encode(&marker));
        out.push('\n');
        return Ok(out.into_bytes());
    }

    check_line_count(path, content, "lines")?;
    let (lines, trailing) = split_lines(content);
    let line_lens: Vec<u64> = lines.iter().map(|l| l.len() as u64).collect();
    if let Some(&too_long) = line_lens.iter().find(|&&l| l > MAX_LINE_LEN) {
        return Err(Error::Limit(format!(
            "`{path}`: a {too_long}-byte line exceeds the {MAX_LINE_LEN}-byte single-line cap; \
             add the path to `force_binary` in the config"
        )));
    }
    let size = ciphertext_size(&line_lens, trailing);
    if size > MAX_FILE_SIZE {
        return Err(Error::Limit(format!(
            "`{path}`: text ciphertext would be {size} bytes, exceeding the {MAX_FILE_SIZE}-byte cap; \
             add the path to `force_binary` in the config"
        )));
    }

    let mut out = String::with_capacity(size as usize);
    out.push_str(TEXT_HEADER_V1);
    out.push('\n');
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&STANDARD_NO_PAD.encode(fk.unit_encrypt(AD_TEXT, line)));
    }
    if trailing {
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// A parsed text ciphertext header.
enum Header<'a> {
    /// Plain header; unit lines follow.
    Units(&'a [u8]),
    /// Empty-file marker header; nothing may follow.
    Marker([u8; SIV_LEN]),
}

/// Parses and strictly validates the header line, returning what follows.
fn parse_header<'a>(path: &str, ct: &'a [u8]) -> Result<Header<'a>> {
    let nl = ct
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| Error::format(path, "text header line is not terminated by a newline"))?;
    let line = &ct[..nl];
    let rest = &ct[nl + 1..];
    if line == TEXT_HEADER_V1.as_bytes() {
        if rest.is_empty() {
            return Err(Error::format(path, "bare text header with no unit lines"));
        }
        return Ok(Header::Units(rest));
    }
    if let Some(marker_b64) = line
        .strip_prefix(TEXT_HEADER_V1.as_bytes())
        .and_then(|r| r.strip_prefix(b" "))
    {
        if !rest.is_empty() {
            return Err(Error::format(
                path,
                "content after the empty-file marker header",
            ));
        }
        if marker_b64.len() != EMPTY_MARKER_B64_LEN {
            return Err(Error::format(
                path,
                "malformed empty-file marker (wrong length)",
            ));
        }
        let marker = decode_unit(path, marker_b64)?;
        let marker: [u8; SIV_LEN] = marker
            .try_into()
            .map_err(|_| Error::format(path, "malformed empty-file marker (not 16 bytes)"))?;
        return Ok(Header::Marker(marker));
    }
    // The caller probes before decrypting, so this is defensive.
    Err(Error::format(
        path,
        "unrecognized `#simple-file-encrypt` header: ciphertext from a newer tool, or colliding plaintext",
    ))
}

/// Strictly decodes one base64 unit line: standard alphabet, no padding,
/// canonical (non-zero trailing bits rejected), at least one SIV.
fn decode_unit(path: &str, line: &[u8]) -> Result<Vec<u8>> {
    let s = std::str::from_utf8(line)
        .map_err(|_| Error::format(path, "unit line contains bytes outside the base64 alphabet"))?;
    if line.len() as u64 > b64_len(MAX_UNIT_DECODED) {
        return Err(Error::Limit(format!(
            "`{path}`: a unit line exceeds the {MAX_UNIT_DECODED}-byte decoded cap"
        )));
    }
    let decoded = STANDARD_NO_PAD.decode(s).map_err(|e| {
        Error::format(
            path,
            format!("malformed or non-canonical base64 unit line: {e}"),
        )
    })?;
    if decoded.len() < SIV_LEN {
        return Err(Error::format(
            path,
            "unit line decodes to fewer than 16 bytes",
        ));
    }
    Ok(decoded)
}

/// The message attached to a first-unit authentication failure.
pub const FIRST_UNIT_AUTH_HINT: &str = "the first unit does not authenticate under any ring key: \
     foreign or corrupted ciphertext, a file moved or renamed while encrypted (keys are path-bound), \
     or ciphertext from a pruned key epoch (an older config from git history may still decrypt it)";

/// Selects the ring key that authenticates `(ad, unit)`, trying entries
/// in order (entry 0 = current). Returns the key index and derived keys.
fn select_key(keys: &[DomainKey], path: &str, ad: &[u8], unit: &[u8]) -> Result<(usize, FileKeys)> {
    for (i, key) in keys.iter().enumerate() {
        let fk = FileKeys::derive(key, path);
        if fk.unit_decrypt(ad, unit).is_some() {
            return Ok((i, fk));
        }
    }
    Err(Error::auth(path, FIRST_UNIT_AUTH_HINT))
}

/// Authenticates only the first unit (or the empty-file marker) against
/// the ring; used by `encrypt` to decide skip/migrate cheaply. Returns
/// the authenticating key index. Only the first line is inspected:
/// splitting the whole input into line slices would let a hostile
/// newline-dense file cost ~17x its size in allocations before any
/// check runs.
pub fn authenticate_first(keys: &[DomainKey], path: &str, ct: &[u8]) -> Result<usize> {
    match parse_header(path, ct)? {
        Header::Marker(marker) => Ok(select_key(keys, path, AD_TEXT_EMPTY, &marker)?.0),
        Header::Units(rest) => {
            let first_line = rest
                .split(|&b| b == b'\n')
                .next()
                .expect("rest is non-empty");
            let first = decode_unit(path, first_line)?;
            Ok(select_key(keys, path, AD_TEXT, &first)?.0)
        }
    }
}

/// Scans every unit line for one that authenticates under any ring
/// key: the arbiter between damaged ciphertext of this domain and
/// foreign content once full decryption has failed. Any authenticating
/// unit — not just the first — proves the content was encrypted here,
/// so a destroyed first line must not let `rekey --prune` drop the key
/// the surviving lines still need.
///
/// The first line is skipped whatever its form (a valid header, a
/// damaged one, or the empty-file marker — whose junk-followed form
/// stays decisively foreign, as nothing recoverable is lost). Lines
/// that fail to decode are skipped, not fatal: damage is the expected
/// input. At most `MAX_UNITS` lines are examined — a valid ciphertext
/// of this domain never holds more, so appended lines past that point
/// cannot be its units. A hit ends the scan; the full-scan worst case
/// is reserved for content that authenticates nowhere.
pub fn authenticate_any(keys: &[DomainKey], path: &str, ct: &[u8]) -> Option<usize> {
    let nl = ct.iter().position(|&b| b == b'\n')?;
    let body = &ct[nl + 1..];
    let fks: Vec<FileKeys> = keys.iter().map(|k| FileKeys::derive(k, path)).collect();
    for (n, line) in body.split(|&b| b == b'\n').enumerate() {
        if n as u64 >= MAX_UNITS {
            break;
        }
        let Ok(unit) = decode_unit(path, line) else {
            continue;
        };
        for (i, fk) in fks.iter().enumerate() {
            if fk.unit_decrypt(AD_TEXT, &unit).is_some() {
                return Some(i);
            }
        }
    }
    None
}

/// Decrypts a text ciphertext, trying ring keys in order on the first
/// unit and requiring every later unit to authenticate under the same
/// key. Returns the plaintext and the ring-key index used.
pub fn decrypt(keys: &[DomainKey], path: &str, ct: &[u8]) -> Result<(Vec<u8>, usize)> {
    match parse_header(path, ct)? {
        Header::Marker(marker) => {
            let (idx, _) = select_key(keys, path, AD_TEXT_EMPTY, &marker)?;
            Ok((Vec::new(), idx))
        }
        Header::Units(rest) => {
            check_line_count(path, rest, "unit lines")?;
            let (unit_lines, trailing) = split_lines(rest);
            let first = decode_unit(path, unit_lines[0])?;
            let (idx, fk) = select_key(keys, path, AD_TEXT, &first)?;
            let mut out: Vec<u8> = Vec::new();
            for (n, line) in unit_lines.iter().enumerate() {
                let unit = decode_unit(path, line)?;
                let pt = fk.unit_decrypt(AD_TEXT, &unit).ok_or_else(|| {
                    Error::auth(
                        path,
                        format!(
                            "unit line {} does not authenticate under the ring key that authenticated \
                             the first unit; possibly a merge that interleaved lines from before and \
                             after a rekey — re-resolve the merge taking whole files from one side, \
                             or decrypt both sides first and merge as plaintext",
                            n + 1
                        ),
                    )
                })?;
                if n > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(&pt);
                if out.len() as u64 > MAX_FILE_SIZE {
                    return Err(Error::Limit(format!(
                        "`{path}`: decrypted plaintext exceeds the {MAX_FILE_SIZE}-byte cap"
                    )));
                }
            }
            if trailing {
                out.push(b'\n');
            }
            Ok((out, idx))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn keys(n: usize) -> Vec<DomainKey> {
        (0..n)
            .map(|i| {
                let mut k = Zeroizing::new([0u8; DOMAIN_KEY_LEN]);
                k.fill(i as u8 + 1);
                k
            })
            .collect()
    }

    fn round_trip(content: &[u8]) -> Vec<u8> {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "f.txt");
        let ct = encrypt(&fk, "f.txt", content).unwrap();
        let (pt, idx) = decrypt(&ks, "f.txt", &ct).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(pt, content);
        ct
    }

    #[test]
    fn split_lines_mapping() {
        assert_eq!(split_lines(b""), (vec![], false));
        assert_eq!(split_lines(b"\n"), (vec![&b""[..]], true));
        assert_eq!(split_lines(b"abc"), (vec![&b"abc"[..]], false));
        assert_eq!(split_lines(b"abc\n"), (vec![&b"abc"[..]], true));
        assert_eq!(split_lines(b"abc\r\n"), (vec![&b"abc\r"[..]], true));
        assert_eq!(
            split_lines(b"a\n\nb"),
            (vec![&b"a"[..], &b""[..], &b"b"[..]], false)
        );
    }

    #[test]
    fn round_trips_and_layout() {
        let ct = round_trip(b"");
        assert_eq!(ct.len(), TEXT_HEADER_V1.len() + 1 + 22 + 1);
        assert!(ct.ends_with(b"\n"));

        let ct = round_trip(b"\n");
        let hdr = TEXT_HEADER_V1.len() + 1;
        assert_eq!(&ct[..hdr], b"#simple-file-encrypt v1 text\n");
        assert!(ct.ends_with(b"\n"));
        assert_eq!(ct.len(), hdr + 22 + 1); // one empty-line unit

        let ct = round_trip(b"abc");
        assert!(!ct.ends_with(b"\n")); // trailing-newline mirroring

        round_trip(b"abc\n");
        round_trip(b"abc\r\n");
        round_trip(b"a\n\nb\nc");
        round_trip("héllo wörld\n\u{1F512}\n".as_bytes());
    }

    #[test]
    fn deterministic_and_line_independent() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "f.txt");
        let a = encrypt(&fk, "f.txt", b"one\ntwo\nthree\n").unwrap();
        let b = encrypt(&fk, "f.txt", b"one\ntwo\nthree\n").unwrap();
        assert_eq!(a, b);
        // Editing line 2 leaves lines 1 and 3 byte-identical.
        let c = encrypt(&fk, "f.txt", b"one\nTWO\nthree\n").unwrap();
        let al: Vec<&[u8]> = a.split(|&x| x == b'\n').collect();
        let cl: Vec<&[u8]> = c.split(|&x| x == b'\n').collect();
        assert_eq!(al[1], cl[1]);
        assert_ne!(al[2], cl[2]);
        assert_eq!(al[3], cl[3]);
        // Equal lines produce equal ciphertext lines within one path.
        let d = encrypt(&fk, "f.txt", b"one\none\n").unwrap();
        let dl: Vec<&[u8]> = d.split(|&x| x == b'\n').collect();
        assert_eq!(dl[1], dl[2]);
    }

    #[test]
    fn strict_decoding_rejections() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "f.txt");
        let ct = encrypt(&fk, "f.txt", b"hello\n").unwrap();

        // Bare header.
        assert!(matches!(
            decrypt(&ks, "f.txt", b"#simple-file-encrypt v1 text\n"),
            Err(Error::Format { .. })
        ));
        // Unterminated header.
        assert!(matches!(
            decrypt(&ks, "f.txt", b"#simple-file-encrypt v1 text"),
            Err(Error::Format { .. })
        ));
        // Marker header with trailing content.
        let empty_ct = encrypt(&fk, "f.txt", b"").unwrap();
        let mut with_extra = empty_ct.clone();
        with_extra.extend_from_slice(b"AAAA\n");
        assert!(matches!(
            decrypt(&ks, "f.txt", &with_extra),
            Err(Error::Format { .. })
        ));
        // Padding characters are rejected.
        let mut padded = ct.clone();
        padded.extend_from_slice(b"QQ==\n");
        assert!(matches!(
            decrypt(&ks, "f.txt", &padded),
            Err(Error::Format { .. })
        ));
        // Non-canonical base64 (non-zero trailing bits): "QR" decodes 1
        // byte but has trailing bits set.
        let mut noncanon = ct.clone();
        noncanon.extend_from_slice(b"QR\n");
        assert!(matches!(
            decrypt(&ks, "f.txt", &noncanon),
            Err(Error::Format { .. })
        ));
        // Too-short unit (< 16 bytes decoded).
        let mut short = ct.clone();
        short.extend_from_slice(b"QUFB\n");
        assert!(matches!(
            decrypt(&ks, "f.txt", &short),
            Err(Error::Format { .. })
        ));
        // Tampered unit fails authentication.
        let mut tampered = ct.clone();
        let pos = tampered.len() - 3;
        tampered[pos] = if tampered[pos] == b'A' { b'B' } else { b'A' };
        assert!(matches!(
            decrypt(&ks, "f.txt", &tampered),
            Err(Error::Auth { .. })
        ));
        // Wrong path fails authentication.
        assert!(matches!(
            decrypt(&ks, "other.txt", &ct),
            Err(Error::Auth { .. })
        ));
    }

    #[test]
    fn ring_key_selection_and_mixed_epoch() {
        let ks = keys(2);
        let fk_old = FileKeys::derive(&ks[1], "f.txt");
        let ct_old = encrypt(&fk_old, "f.txt", b"a\nb\n").unwrap();
        let (pt, idx) = decrypt(&ks, "f.txt", &ct_old).unwrap();
        assert_eq!((pt.as_slice(), idx), (&b"a\nb\n"[..], 1));
        assert_eq!(authenticate_first(&ks, "f.txt", &ct_old).unwrap(), 1);

        // Mixed epochs: first unit from the old key, second from the new.
        let fk_new = FileKeys::derive(&ks[0], "f.txt");
        let ct_new = encrypt(&fk_new, "f.txt", b"a\nb\n").unwrap();
        let old_lines: Vec<&[u8]> = ct_old.split(|&x| x == b'\n').collect();
        let new_lines: Vec<&[u8]> = ct_new.split(|&x| x == b'\n').collect();
        let mixed = [old_lines[0], old_lines[1], new_lines[2], b""].join(&b'\n');
        let err = decrypt(&ks, "f.txt", &mixed).unwrap_err();
        assert!(matches!(err, Error::Auth { .. }));
        assert!(err.to_string().contains("rekey"));
    }

    #[test]
    fn line_count_cap_hits_before_any_cryptography() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "f.txt");
        // MAX_UNITS + 1 empty lines: rejected by the pre-count, well
        // before any per-line allocation or encryption.
        let content = vec![b'\n'; (MAX_UNITS + 1) as usize];
        assert!(matches!(
            encrypt(&fk, "f.txt", &content),
            Err(Error::Limit(_))
        ));
        // Decrypt side: a unit region with too many lines is rejected
        // before any base64 decoding (the lines need not be valid).
        let mut ct = Vec::from(&b"#simple-file-encrypt v1 text\n"[..]);
        ct.extend(std::iter::repeat_n(&b"A\n"[..], (MAX_UNITS + 1) as usize).flatten());
        let err = decrypt(&ks, "f.txt", &ct).unwrap_err();
        assert!(matches!(err, Error::Limit(_)), "got: {err}");
        assert!(err.to_string().contains("force_binary"));
    }

    #[test]
    fn authenticate_first_reads_only_the_first_line() {
        let ks = keys(1);
        let fk = FileKeys::derive(&ks[0], "f.txt");
        // A valid first unit followed by millions of newlines: the
        // authentication decision must not materialize per-line slices.
        let mut ct = encrypt(&fk, "f.txt", b"hello\n").unwrap();
        ct.extend(std::iter::repeat_n(b'\n', 4_000_000));
        assert_eq!(authenticate_first(&ks, "f.txt", &ct).unwrap(), 0);
        // An invalid first unit with a dense tail fails as a format error.
        let mut bad = Vec::from(&b"#simple-file-encrypt v1 text\n"[..]);
        bad.extend_from_slice(b"AA\n");
        bad.extend(std::iter::repeat_n(b'\n', 4_000_000));
        assert!(matches!(
            authenticate_first(&ks, "f.txt", &bad),
            Err(Error::Format { .. })
        ));
    }

    #[test]
    fn authenticate_any_finds_surviving_units() {
        let ks = keys(2);
        let fk = FileKeys::derive(&ks[1], "f.txt");
        let ct = encrypt(&fk, "f.txt", b"one\ntwo\n").unwrap();
        let lines: Vec<&[u8]> = ct.split(|&x| x == b'\n').collect();

        // First unit destroyed (invalid base64): the second still
        // authenticates under ring entry 1.
        let broken = [lines[0], b"!!!not-base64!!!", lines[2], b""].join(&b'\n');
        assert!(authenticate_first(&ks, "f.txt", &broken).is_err());
        assert_eq!(authenticate_any(&ks, "f.txt", &broken), Some(1));

        // First unit replaced by a well-formed unit of another path:
        // still recognized through the second unit.
        let alien = FileKeys::derive(&ks[0], "other.txt").unit_encrypt(AD_TEXT, b"x");
        let alien_b64 = STANDARD_NO_PAD.encode(&alien);
        let swapped = [lines[0], alien_b64.as_bytes(), lines[2], b""].join(&b'\n');
        assert_eq!(authenticate_any(&ks, "f.txt", &swapped), Some(1));

        // A damaged header line (probing as unrecognized) still leaves
        // the unit lines recognizable.
        let bad_header = [
            &b"#simple-file-encrypt v1 texx"[..],
            lines[1],
            lines[2],
            b"",
        ]
        .join(&b'\n');
        assert_eq!(authenticate_any(&ks, "f.txt", &bad_header), Some(1));

        // Every unit destroyed, foreign content, or a wrong path: no hit.
        let all_bad = [lines[0], b"AAAA", b"BBBB", b""].join(&b'\n');
        assert_eq!(authenticate_any(&ks, "f.txt", &all_bad), None);
        assert_eq!(authenticate_any(&ks, "moved.txt", &ct), None);
        assert_eq!(authenticate_any(&ks, "f.txt", b"no newline at all"), None);

        // The empty-file marker with appended junk stays unrecognized:
        // the marker line is the header line and is skipped, and the
        // junk authenticates nowhere (a documented residual — the
        // recoverable plaintext is empty, so nothing is lost).
        let empty_ct = encrypt(&fk, "f.txt", b"").unwrap();
        let mut with_junk = empty_ct.clone();
        with_junk.extend_from_slice(b"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ\n");
        assert_eq!(authenticate_any(&ks, "f.txt", &with_junk), None);
    }

    #[test]
    fn empty_marker_authenticity() {
        let ks = keys(1);
        // A marker built without the key must not authenticate.
        let fake = format!("{TEXT_HEADER_V1} {}\n", "A".repeat(22));
        assert!(matches!(
            decrypt(&ks, "f.txt", fake.as_bytes()),
            Err(Error::Auth { .. })
        ));
        // Non-canonical marker (trailing bits) is a format error.
        let fk = FileKeys::derive(&ks[0], "f.txt");
        let good = String::from_utf8(encrypt(&fk, "f.txt", b"").unwrap()).unwrap();
        let mut bad = good.clone().into_bytes();
        let last = bad.len() - 2;
        bad[last] = b'B'; // 'B' = 000001 in base64: sets trailing bits
        assert!(matches!(
            decrypt(&ks, "f.txt", &bad),
            Err(Error::Format { .. })
        ));
    }
}
