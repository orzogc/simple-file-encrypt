//! Keyless ciphertext probe (see `docs/format.md`).
//!
//! A probe hit does not prove valid ciphertext of this domain; commands
//! authenticate the first unit before trusting it.

use crate::consts::*;

/// Result of probing a file's leading bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// First 8 bytes equal `BIN_MAGIC`.
    Binary,
    /// First line is one of the two exact v1 text header forms.
    TextV1,
    /// First line starts with `#simple-file-encrypt` but is no exact v1
    /// header: newer-tool ciphertext or colliding plaintext.
    TextUnrecognized,
    /// No probe hit: treated as plaintext.
    Plain,
}

impl Probe {
    /// Whether this is a probe hit (the file "looks encrypted",
    /// recognized or not).
    pub fn is_hit(self) -> bool {
        self != Probe::Plain
    }

    /// Whether the file counts as encrypted for keyless reports
    /// (`status`, `check`): an exact v1 form or the binary magic.
    pub fn is_encrypted(self) -> bool {
        matches!(self, Probe::Binary | Probe::TextV1)
    }
}

/// Probes leading file content.
pub fn probe(content: &[u8]) -> Probe {
    if content.len() >= BIN_MAGIC.len() && content[..BIN_MAGIC.len()] == BIN_MAGIC {
        return Probe::Binary;
    }
    let (first_line, terminated) = match content.iter().position(|&b| b == b'\n') {
        Some(i) => (&content[..i], true),
        None => (content, false),
    };
    if !first_line.starts_with(TEXT_MAGIC_PREFIX.as_bytes()) {
        return Probe::Plain;
    }
    // Both exact v1 header forms are newline-terminated.
    if terminated && is_exact_v1_header(first_line) {
        Probe::TextV1
    } else {
        Probe::TextUnrecognized
    }
}

/// Whether a first line (without its `\n`) is one of the two exact v1
/// header forms: the plain header, or the header plus one space and a
/// canonical 22-character base64 empty-file marker.
pub fn is_exact_v1_header(line: &[u8]) -> bool {
    if line == TEXT_HEADER_V1.as_bytes() {
        return true;
    }
    let Some(rest) = line.strip_prefix(TEXT_HEADER_V1.as_bytes()) else {
        return false;
    };
    let Some(marker) = rest.strip_prefix(b" ") else {
        return false;
    };
    if marker.len() != EMPTY_MARKER_B64_LEN
        || !marker
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
    {
        return false;
    }
    // 22 base64 characters carry 132 bits for 128 bits of data: the
    // final character's four trailing bits must be zero (canonical),
    // so only 'A', 'Q', 'g', 'w' are valid there.
    matches!(marker[EMPTY_MARKER_B64_LEN - 1], b'A' | b'Q' | b'g' | b'w')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_classification() {
        assert_eq!(probe(b"\x89SENC\r\n\x1a\x01rest"), Probe::Binary);
        assert_eq!(probe(b"#simple-file-encrypt v1 text\nAAAA"), Probe::TextV1);
        assert_eq!(probe(b"#simple-file-encrypt v1 text\n"), Probe::TextV1);
        // Both exact forms are newline-terminated.
        assert_eq!(
            probe(b"#simple-file-encrypt v1 text"),
            Probe::TextUnrecognized
        );
        // Marker form: exactly 22 base64 chars after one space, with a
        // canonical final character (four trailing bits zero).
        let marker = "#simple-file-encrypt v1 text AAAAAAAAAAAAAAAAAAAAAA\n";
        assert_eq!(probe(marker.as_bytes()), Probe::TextV1);
        assert_eq!(
            probe(b"#simple-file-encrypt v1 text AAAAAAAAAAAAAAAAAAAAAB\n"),
            Probe::TextUnrecognized
        );
        assert_eq!(
            probe(b"#simple-file-encrypt v1 text AAAAAAAAAAAAAAAAAAAAAA"),
            Probe::TextUnrecognized
        );
        // Wrong marker length, extra spaces, or other suffixes are unrecognized.
        assert_eq!(
            probe(b"#simple-file-encrypt v1 text AAAA\n"),
            Probe::TextUnrecognized
        );
        assert_eq!(
            probe(b"#simple-file-encrypt v1 text  \n"),
            Probe::TextUnrecognized
        );
        assert_eq!(
            probe(b"#simple-file-encrypt v2 text\n"),
            Probe::TextUnrecognized
        );
        assert_eq!(probe(b"#simple-file-encrypted\n"), Probe::TextUnrecognized);
        assert_eq!(probe(b"#simple-file-encrypt"), Probe::TextUnrecognized);
        // No hit.
        assert_eq!(probe(b"hello\n"), Probe::Plain);
        assert_eq!(probe(b""), Probe::Plain);
        assert_eq!(
            probe(b"#simple\n#simple-file-encrypt v1 text\n"),
            Probe::Plain
        );
        // Truncated magic is plain.
        assert_eq!(probe(b"\x89SENC\r\n"), Probe::Plain);
    }
}
