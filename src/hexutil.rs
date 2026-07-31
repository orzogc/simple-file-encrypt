//! Minimal lowercase-hex encode/decode.
//!
//! The config format mandates lowercase hex; decoding is strict so every
//! value has exactly one accepted encoding.

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble < 16"));
        out.push(char::from_digit(u32::from(b & 0xf), 16).expect("nibble < 16"));
    }
    out
}

/// Decodes strict lowercase hex; rejects uppercase, odd length, and
/// non-hex characters.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        out.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Some(out)
}

/// Decodes one lowercase hex digit.
fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn rejects_uppercase_odd_and_junk() {
        assert!(decode("AB").is_none());
        assert!(decode("a").is_none());
        assert!(decode("zz").is_none());
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }
}
