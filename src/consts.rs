//! Normative constants of format version 1 (see `docs/format.md`).

/// The single format version covering config schema, ciphertext layouts,
/// and all derivation/AD context strings.
pub const FORMAT_VERSION: u64 = 1;

/// Domain config file name; the directory containing it is the domain root.
pub const CONFIG_NAME: &str = ".simple-file-encrypt.toml";

/// Prefix of temporary files used for atomic replacement.
pub const TMP_PREFIX: &str = ".simple-file-encrypt.tmp.";

/// Number of random alphanumeric characters in a temp-file name.
pub const TMP_RAND_LEN: usize = 16;

/// KDF salt length in bytes (32 lowercase hex chars in the config).
pub const SALT_LEN: usize = 16;

/// Domain key length in bytes.
pub const DOMAIN_KEY_LEN: usize = 32;

/// KEK (Argon2id output) and per-file unit key length in bytes: the
/// `AEAD_AES_SIV_CMAC_512` key size.
pub const KEK_LEN: usize = 64;

/// Per-file unit key length in bytes.
pub const UNIT_KEY_LEN: usize = 64;

/// SIV length in bytes; also the per-unit ciphertext overhead.
pub const SIV_LEN: usize = 16;

/// Wrapped key-ring entry length in bytes: `SIV(16) || CT(32)`.
pub const WRAPPED_KEY_LEN: usize = SIV_LEN + DOMAIN_KEY_LEN;

/// Binary-mode whole-file tag length in bytes.
pub const FILE_TAG_LEN: usize = 32;

/// Binary-mode plaintext chunk size in bytes (`CHUNK_SIZE + SIV_LEN` on disk).
pub const CHUNK_SIZE: usize = 65536;

/// Text-mode probe prefix: any first line starting with this is a probe hit.
pub const TEXT_MAGIC_PREFIX: &str = "#simple-file-encrypt";

/// Exact v1 text header line content (without the terminating newline).
pub const TEXT_HEADER_V1: &str = "#simple-file-encrypt v1 text";

/// Binary-mode magic: `"\x89SENC\r\n\x1a"`.
pub const BIN_MAGIC: [u8; 8] = [0x89, 0x53, 0x45, 0x4E, 0x43, 0x0D, 0x0A, 0x1A];

/// Binary-mode header length in bytes (magic + version + flags + reserved).
pub const BIN_HEADER_LEN: usize = 16;

/// Base64 length of the 16-byte empty-file marker.
pub const EMPTY_MARKER_B64_LEN: usize = 22;

/// Keyless-probe read window in bytes: must hold the longest exact v1
/// header line — the empty-file marker form (`TEXT_HEADER_V1` + one
/// space + `EMPTY_MARKER_B64_LEN` chars + newline, 52 bytes) — so a
/// probe can classify it from the prefix alone.
pub const PROBE_PREFIX_LEN: usize = 64;

/// Length of the longest exact v1 header line: the marker form,
/// `TEXT_HEADER_V1` + one space + the marker + the newline.
const LONGEST_HEADER_LINE: usize = TEXT_HEADER_V1.len() + 1 + EMPTY_MARKER_B64_LEN + 1;

// A tool rename or header change must never silently shrink the probe
// window below the longest header line.
const _: () = assert!(
    PROBE_PREFIX_LEN >= LONGEST_HEADER_LINE,
    "the probe window must hold the longest exact header line"
);

/// Hard cap on plaintext and ciphertext file sizes: 256 MiB.
pub const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;

/// Hard cap on a single plaintext line: 64 MiB.
pub const MAX_LINE_LEN: u64 = 64 * 1024 * 1024;

/// Hard cap on a single decoded unit: `MAX_LINE_LEN + SIV_LEN`.
pub const MAX_UNIT_DECODED: u64 = MAX_LINE_LEN + SIV_LEN as u64;

/// Hard cap on units (lines) per text file: 2^22.
pub const MAX_UNITS: u64 = 1 << 22;

/// Hard cap on files per operation, after directory expansion.
pub const MAX_FILES_PER_OP: usize = 65536;

/// Hard cap on directory entries examined during one expansion or
/// descendant scan, counting every visited entry (files, directories,
/// skipped specials), so hostile trees cannot exhaust memory or time
/// before the file cap applies.
pub const MAX_SCANNED_ENTRIES: usize = 1 << 20;

/// Hard cap on directory recursion depth during expansion and `init`'s
/// descendant scan.
pub const MAX_WALK_DEPTH: usize = 128;

/// Hard cap on the total byte length of all paths retained by one
/// expansion — selected files, visited (sweep) directories, skipped
/// symlinks/specials, and missing entries — so long names cannot
/// exhaust memory within the file and entry caps.
pub const MAX_PATH_BYTES: usize = 64 * 1024 * 1024;

/// Hard cap on the config file size: 1 MiB.
pub const MAX_CONFIG_SIZE: u64 = 1024 * 1024;

/// Hard cap on `paths`, `force_binary`, and `excludes` entries together.
pub const MAX_CONFIG_ENTRIES: usize = 65536;

/// Hard cap on key-ring entries.
pub const MAX_RING_LEN: usize = 64;

/// Hard cap on password length in bytes.
pub const MAX_PASSWORD_LEN: usize = 4096;

/// Argon2id defaults written by `init` (RFC 9106 memory-constrained
/// recommendation, with a single lane for single-threaded simplicity).
pub const KDF_DEFAULT_MEMORY_KIB: u32 = 65536;
/// Default Argon2id pass count.
pub const KDF_DEFAULT_ITERATIONS: u32 = 3;
/// Default Argon2id lane count.
pub const KDF_DEFAULT_PARALLELISM: u32 = 1;

/// Environment variable providing the (old) password non-interactively.
pub const ENV_PASSWORD: &str = "SIMPLE_FILE_ENCRYPT_PASSWORD";

/// Environment variable providing `passwd`'s new password non-interactively.
pub const ENV_NEW_PASSWORD: &str = "SIMPLE_FILE_ENCRYPT_NEW_PASSWORD";
