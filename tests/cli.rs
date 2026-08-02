//! CLI integration tests for the `simple-file-encrypt` binary (the test
//! surface listed in `docs/design.md`, semantics from `docs/cli.md`).
//!
//! Every test creates its own temporary domain. Passwords are passed via
//! per-command environment variables (never `std::env::set_var`, which
//! would leak across parallel tests), and every command runs with
//! `--allow-weak-kdf` plus tiny Argon2 parameters so the suite is fast.

use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;

/// Default domain password used by most tests.
const PW: &str = "test password";
/// Domain config file name.
const CONFIG: &str = ".simple-file-encrypt.toml";
/// Exact v1 text header (without the terminating newline).
const TEXT_HEADER: &str = "#simple-file-encrypt v1 text";
/// Binary-mode magic bytes.
const BIN_MAGIC: [u8; 8] = [0x89, 0x53, 0x45, 0x4E, 0x43, 0x0D, 0x0A, 0x1A];

/// Captured outcome of one CLI invocation.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Asserts the exit code, dumping both streams on mismatch.
    #[track_caller]
    fn expect_code(self, want: i32) -> Run {
        assert_eq!(
            self.code, want,
            "exit code {} != {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, want, self.stdout, self.stderr
        );
        self
    }
}

/// Asserts that `hay` contains `needle`, printing the haystack on failure.
#[track_caller]
fn assert_contains(hay: &str, needle: &str) {
    assert!(hay.contains(needle), "expected {needle:?} in:\n{hay}");
}

/// Builds a command with a clean password environment (external
/// variables removed) and the global `--allow-weak-kdf` flag.
fn se(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("simple-file-encrypt").unwrap();
    c.current_dir(dir);
    c.env_remove("SIMPLE_FILE_ENCRYPT_PASSWORD");
    c.env_remove("SIMPLE_FILE_ENCRYPT_NEW_PASSWORD");
    c.arg("--allow-weak-kdf");
    c
}

/// Runs a prepared command and captures exit code and both streams.
fn run(mut cmd: Command) -> Run {
    let out = cmd.output().expect("failed to run simple-file-encrypt");
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Runs a subcommand with the password supplied via the environment.
fn run_pw(dir: &Path, pw: &str, args: &[&str]) -> Run {
    let mut c = se(dir);
    c.env("SIMPLE_FILE_ENCRYPT_PASSWORD", pw);
    c.args(args);
    run(c)
}

/// Runs a subcommand with no password source at all (stdin is empty).
fn run_nopw(dir: &Path, args: &[&str]) -> Run {
    let mut c = se(dir);
    c.args(args);
    run(c)
}

/// Initializes a domain in `root` with fast (weak) KDF parameters.
#[track_caller]
fn init_domain(root: &Path) {
    run_pw(
        root,
        PW,
        &["init", "--memory-kib", "8", "--iterations", "1"],
    )
    .expect_code(0);
}

/// Writes a file below `root`, creating parent directories.
fn write_file(root: &Path, rel: &str, content: &[u8]) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Reads a file below `root`.
fn read_file(root: &Path, rel: &str) -> Vec<u8> {
    fs::read(root.join(rel)).unwrap()
}

/// Absolute path of the domain config.
fn config_path(root: &Path) -> PathBuf {
    root.join(CONFIG)
}

/// Reads the domain config as text.
fn read_config(root: &Path) -> String {
    fs::read_to_string(config_path(root)).unwrap()
}

/// Extracts the `wrapped_keys` entries (96-hex strings) from the config.
fn wrapped_keys_of(root: &Path) -> Vec<String> {
    let cfg = read_config(root);
    let start = cfg.find("wrapped_keys = [").unwrap();
    let end = start + cfg[start..].find(']').unwrap();
    cfg[start..end]
        .lines()
        .filter_map(|l| {
            l.trim()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix("\","))
        })
        .map(str::to_owned)
        .collect()
}

/// Rewrites the config's `wrapped_keys` array with the given entries.
fn set_wrapped_keys(root: &Path, keys: &[String]) {
    let cfg = read_config(root);
    let start = cfg.find("wrapped_keys = [").unwrap();
    let end = start + cfg[start..].find(']').unwrap() + 1;
    let mut block = String::from("wrapped_keys = [\n");
    for k in keys {
        block.push_str("    \"");
        block.push_str(k);
        block.push_str("\",\n");
    }
    block.push(']');
    fs::write(
        config_path(root),
        format!("{}{}{}", &cfg[..start], block, &cfg[end..]),
    )
    .unwrap();
}

/// Extracts the hex salt from the config.
fn salt_of(root: &Path) -> String {
    let cfg = read_config(root);
    let start = cfg.find("salt = \"").unwrap() + "salt = \"".len();
    let end = start + cfg[start..].find('"').unwrap();
    cfg[start..end].to_owned()
}

/// Removes a managed `paths` entry by editing the config directly.
fn remove_managed_entry(root: &Path, rel: &str) {
    let cfg = read_config(root);
    let line = format!("    \"{rel}\",\n");
    assert!(cfg.contains(&line), "entry {rel} not found in config");
    fs::write(config_path(root), cfg.replacen(&line, "", 1)).unwrap();
}

/// Whether a status/check-style line with the given state names `rel`.
fn status_line(stdout: &str, state: &str, rel: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.starts_with(state) && l.contains(rel))
}

/// Retries `f` until it yields a value, for about two seconds.
///
/// Needed only where a test re-acquires a lock it just dropped: an
/// flock held by this (multi-threaded) test process can outlive its
/// handle for a moment when a child forked by a parallel test inherited
/// the descriptor and has not exec'd yet.
#[track_caller]
fn eventually<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    for _ in 0..100 {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("timed out waiting for: {what}");
}

/// Flips the first character of the first unit line (line index 1) of a
/// text ciphertext, keeping the base64 alphabet and canonicality intact.
fn tamper_first_unit(root: &Path, rel: &str) {
    let ct = String::from_utf8(read_file(root, rel)).unwrap();
    let mut lines: Vec<String> = ct.lines().map(str::to_owned).collect();
    let first = lines[1].remove(0);
    lines[1].insert(0, if first == 'A' { 'B' } else { 'A' });
    let mut out = lines.join("\n");
    if ct.ends_with('\n') {
        out.push('\n');
    }
    fs::write(root.join(rel), out).unwrap();
}

// ---------------------------------------------------------------------
// Basic flows
// ---------------------------------------------------------------------

#[test]
fn init_add_encrypt_status_decrypt_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let env_content: &[u8] = b"SECRET=hunter2\nTOKEN=abc\n";
    let inner_content: &[u8] = b"line one\nline two"; // no trailing newline
    write_file(root, ".env", env_content);
    write_file(root, "secrets/inner.txt", inner_content);

    let r = run_pw(
        root,
        PW,
        &["init", "--memory-kib", "8", "--iterations", "1"],
    )
    .expect_code(0);
    assert_contains(&r.stdout, "initialized");
    assert!(config_path(root).exists());

    // `add` needs no password.
    let r = run_nopw(root, &["add", ".env", "secrets"]).expect_code(0);
    assert_contains(&r.stdout, "added .env");
    assert_contains(&r.stdout, "added secrets");
    let cfg = read_config(root);
    assert_contains(&cfg, "\".env\"");
    assert_contains(&cfg, "\"secrets\"");

    // Encrypt the managed list (no arguments).
    let r = run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_contains(&r.stdout, "encrypted .env");
    assert_contains(&r.stdout, "encrypted secrets/inner.txt");
    let env_ct = read_file(root, ".env");
    assert!(env_ct.starts_with(TEXT_HEADER.as_bytes()));
    // Trailing-newline mirroring: the source had no final newline.
    let inner_ct = read_file(root, "secrets/inner.txt");
    assert!(inner_ct.starts_with(TEXT_HEADER.as_bytes()));
    assert!(!inner_ct.ends_with(b"\n"));

    // `status` needs no password and reports the encrypted state.
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "encrypted", ".env"));
    assert!(status_line(&r.stdout, "encrypted", "secrets/inner.txt"));

    // Decrypt restores the exact original bytes.
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted .env");
    assert_contains(&r.stdout, "decrypted secrets/inner.txt");
    assert_eq!(read_file(root, ".env"), env_content);
    assert_eq!(read_file(root, "secrets/inner.txt"), inner_content);
}

#[test]
fn modes_and_edge_content_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let empty: &[u8] = b"";
    let crlf: &[u8] = b"alpha\r\nbeta\r\n";
    let newline_only: &[u8] = b"\n";
    let nulls: &[u8] = b"\x00\x01\x02binary\x00body";
    write_file(root, "empty.txt", empty);
    write_file(root, "crlf.txt", crlf);
    write_file(root, "nl.txt", newline_only);
    write_file(root, "nulls.bin", nulls);
    init_domain(root);

    run_pw(
        root,
        PW,
        &["encrypt", "empty.txt", "crlf.txt", "nl.txt", "nulls.bin"],
    )
    .expect_code(0);

    // Empty plaintext: a single marker-header line, nothing else.
    let empty_ct = read_file(root, "empty.txt");
    assert!(empty_ct.starts_with(format!("{TEXT_HEADER} ").as_bytes()));
    assert_eq!(empty_ct.iter().filter(|&&b| b == b'\n').count(), 1);
    // CRLF stays inside the encrypted line; ciphertext is LF-framed text.
    assert!(read_file(root, "crlf.txt").starts_with(TEXT_HEADER.as_bytes()));
    // NUL bytes select binary mode.
    assert_eq!(&read_file(root, "nulls.bin")[..8], &BIN_MAGIC);

    // `status` marks the binary-mode file (and only it).
    let r = run_nopw(root, &["status"]).expect_code(0);
    let bin_line = r.stdout.lines().find(|l| l.contains("nulls.bin")).unwrap();
    assert_contains(bin_line, "[binary]");
    assert!(bin_line.starts_with("encrypted"));
    let crlf_line = r.stdout.lines().find(|l| l.contains("crlf.txt")).unwrap();
    assert!(!crlf_line.contains("[binary]"));

    // Byte-exact round trip for every mode and edge case.
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_eq!(read_file(root, "empty.txt"), empty);
    assert_eq!(read_file(root, "crlf.txt"), crlf);
    assert_eq!(read_file(root, "nl.txt"), newline_only);
    assert_eq!(read_file(root, "nulls.bin"), nulls);
}

#[test]
fn encrypt_is_idempotent_and_deterministic() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "f.txt", b"one\ntwo\nthree\n");
    init_domain(root);

    run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(0);
    let ct1 = read_file(root, "f.txt");

    // Second encrypt skips; the ciphertext bytes do not change.
    let r = run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(0);
    assert_contains(&r.stdout, "skipped f.txt (already encrypted)");
    assert_eq!(read_file(root, "f.txt"), ct1);

    // Editing one line changes only that unit line.
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    write_file(root, "f.txt", b"one\nTWO\nthree\n");
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    let ct2 = read_file(root, "f.txt");
    let l1: Vec<&[u8]> = ct1.split(|&b| b == b'\n').collect();
    let l2: Vec<&[u8]> = ct2.split(|&b| b == b'\n').collect();
    assert_eq!(l1.len(), l2.len());
    assert_eq!(l1[0], l2[0]); // header
    assert_eq!(l1[1], l2[1]); // "one"
    assert_ne!(l1[2], l2[2]); // edited line
    assert_eq!(l1[3], l2[3]); // "three"

    // decrypt -> encrypt of unchanged content is byte-identical.
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_eq!(read_file(root, "f.txt"), ct2);

    // Restoring the original content reproduces the original ciphertext.
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    write_file(root, "f.txt", b"one\ntwo\nthree\n");
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_eq!(read_file(root, "f.txt"), ct1);
}

#[test]
fn explicit_targets_auto_add_and_config_stability() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let content: &[u8] = b"api_key = xyz\n";
    write_file(root, "u.txt", content);
    init_domain(root);

    // Encrypting an unmanaged file auto-adds it before encrypting.
    let r = run_pw(root, PW, &["encrypt", "u.txt"]).expect_code(0);
    assert_contains(&r.stdout, "added u.txt");
    assert_contains(&r.stdout, "encrypted u.txt");
    assert_contains(&read_config(root), "\"u.txt\"");

    // An already-encrypted file named explicitly is re-added too.
    remove_managed_entry(root, "u.txt");
    assert!(!read_config(root).contains("\"u.txt\""));
    let r = run_pw(root, PW, &["encrypt", "u.txt"]).expect_code(0);
    assert_contains(&r.stdout, "added u.txt");
    assert_contains(&r.stdout, "skipped u.txt (already encrypted)");
    assert_contains(&read_config(root), "\"u.txt\"");

    // A nonexistent explicit target is an error.
    let r = run_pw(root, PW, &["encrypt", "nope.txt"]).expect_code(1);
    assert_contains(&r.stderr, "does not exist on disk");

    // `decrypt` never modifies the managed list.
    let cfg_before = read_config(root);
    run_pw(root, PW, &["decrypt", "u.txt"]).expect_code(0);
    assert_eq!(read_config(root), cfg_before);
    assert_eq!(read_file(root, "u.txt"), content);
}

// ---------------------------------------------------------------------
// Probe collisions and flags
// ---------------------------------------------------------------------

#[test]
fn assume_plaintext_escape_hatch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);

    // Plaintext masquerading as v1 ciphertext: a valid header and a
    // canonical base64 line that cannot authenticate.
    let masked: &[u8] = b"#simple-file-encrypt v1 text\nAAAAAAAAAAAAAAAAAAAAAAAA\n";
    write_file(root, "fake.txt", masked);
    let r = run_pw(root, PW, &["encrypt", "fake.txt"]).expect_code(1);
    assert_contains(&r.stderr, "assume-plaintext");
    assert_eq!(read_file(root, "fake.txt"), masked); // untouched

    let r = run_pw(root, PW, &["encrypt", "--assume-plaintext", "fake.txt"]).expect_code(0);
    assert_contains(&r.stderr, "treating unauthenticated probe hit as plaintext");
    assert_contains(&r.stdout, "encrypted fake.txt");
    assert_ne!(read_file(root, "fake.txt"), masked);
    run_pw(root, PW, &["decrypt", "fake.txt"]).expect_code(0);
    assert_eq!(read_file(root, "fake.txt"), masked);

    // A `#simple-file-encrypt` first line that is no exact v1 header.
    let unrec: &[u8] = b"#simple-file-encrypt v9 x\npayload\n";
    write_file(root, "unrec.txt", unrec);
    let r = run_pw(root, PW, &["encrypt", "unrec.txt"]).expect_code(1);
    assert_contains(&r.stderr, "no exact v1 header");
    run_pw(root, PW, &["encrypt", "--assume-plaintext", "unrec.txt"]).expect_code(0);
    run_pw(root, PW, &["decrypt", "unrec.txt"]).expect_code(0);
    assert_eq!(read_file(root, "unrec.txt"), unrec);

    // The flag requires explicit paths.
    let r = run_pw(root, PW, &["encrypt", "--assume-plaintext"]).expect_code(1);
    assert_contains(&r.stderr, "requires explicit paths");
}

#[test]
fn decrypt_require_encrypted_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "p.txt", b"still plaintext\n");
    init_domain(root);

    let r = run_pw(root, PW, &["decrypt", "p.txt"]).expect_code(0);
    assert_contains(&r.stdout, "skipped p.txt (not encrypted)");

    let r = run_pw(root, PW, &["decrypt", "--require-encrypted", "p.txt"]).expect_code(1);
    assert_contains(&r.stderr, "not encrypted");
}

// ---------------------------------------------------------------------
// Managed-list bookkeeping
// ---------------------------------------------------------------------

#[test]
fn add_remove_bookkeeping() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "n.txt", b"note\n");
    write_file(root, "d/inner.txt", b"inner\n");
    write_file(root, "stray.txt", b"stray\n");
    init_domain(root);

    // Duplicate adds are reported, not duplicated.
    run_nopw(root, &["add", "n.txt"]).expect_code(0);
    let r = run_nopw(root, &["add", "n.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already managed");

    // Adding a directory prunes the file entries it covers.
    run_nopw(root, &["add", "d/inner.txt"]).expect_code(0);
    let r = run_nopw(root, &["add", "d"]).expect_code(0);
    assert_contains(&r.stdout, "now covered by");
    assert_contains(&r.stdout, "added d");
    let cfg = read_config(root);
    assert!(!cfg.contains("\"d/inner.txt\""));
    assert_contains(&cfg, "\"d\"");
    let r = run_nopw(root, &["add", "d/inner.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already covered by the managed entry `d`");

    // Adding a nonexistent path warns but succeeds.
    let r = run_nopw(root, &["add", "ghost.txt"]).expect_code(0);
    assert_contains(&r.stderr, "does not exist on disk");
    assert_contains(&read_config(root), "\"ghost.txt\"");
    run_nopw(root, &["remove", "ghost.txt"]).expect_code(0);

    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // Removing an encrypted entry is refused; --force overrides.
    let r = run_nopw(root, &["remove", "n.txt"]).expect_code(1);
    assert_contains(&r.stderr, "decrypt it first");
    // A directory entry covering encrypted files is refused too.
    let r = run_nopw(root, &["remove", "d"]).expect_code(1);
    assert_contains(&r.stderr, "decrypt it first");
    // A path covered by a directory entry is not an exact entry.
    let r = run_nopw(root, &["remove", "d/inner.txt"]).expect_code(1);
    assert_contains(&r.stderr, "covered by the managed directory entry `d`");
    // An unmanaged path cannot be removed.
    let r = run_nopw(root, &["remove", "stray.txt"]).expect_code(1);
    assert_contains(&r.stderr, "not a managed path");

    let r = run_nopw(root, &["remove", "--force", "n.txt"]).expect_code(0);
    assert_contains(&r.stderr, "force-removing");
    assert_contains(&r.stdout, "removed n.txt");
    assert!(!read_config(root).contains("\"n.txt\""));

    // After decryption the directory entry can be removed normally.
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    let r = run_nopw(root, &["remove", "d"]).expect_code(0);
    assert_contains(&r.stdout, "removed d");
}

// ---------------------------------------------------------------------
// Read-only scans
// ---------------------------------------------------------------------

#[test]
fn status_and_check_mixed_states() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "enc.txt", b"secret\n");
    write_file(root, "plain.txt", b"exposed\n");
    write_file(root, "unrec.txt", b"#simple-file-encrypt v9 x\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "enc.txt"]).expect_code(0);
    run_nopw(root, &["add", "plain.txt", "gone.txt", "unrec.txt"]).expect_code(0);

    // `status` reports every state and exits 0 regardless.
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "encrypted", "enc.txt"));
    assert!(status_line(&r.stdout, "plaintext", "plain.txt"));
    assert!(status_line(&r.stdout, "missing", "gone.txt"));
    assert!(status_line(&r.stdout, "unrecognized", "unrec.txt"));

    // `check` lists offenders (exit 1), ignores missing files, and
    // needs no password (none is provided here).
    let r = run_nopw(root, &["check"]).expect_code(1);
    assert!(status_line(&r.stdout, "plaintext", "plain.txt"));
    assert!(status_line(&r.stdout, "unrecognized", "unrec.txt"));
    assert!(!r.stdout.contains("enc.txt"));
    assert!(!r.stdout.contains("gone.txt"));

    // All existing managed files encrypted: exit 0.
    fs::remove_file(root.join("unrec.txt")).unwrap();
    run_pw(root, PW, &["encrypt", "plain.txt"]).expect_code(0);
    run_nopw(root, &["check"]).expect_code(0);
}

#[test]
fn verify_authentication_and_exit_codes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"alpha\nbeta\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "a.txt"]).expect_code(0);
    let good_ct = read_file(root, "a.txt");

    // Everything authenticates: exit 0.
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "verified a.txt");

    // Plaintext and missing files are reported but do not fail verify.
    write_file(root, "plain.txt", b"not encrypted\n");
    run_nopw(root, &["add", "plain.txt", "gone.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "plaintext plain.txt");
    assert_contains(&r.stdout, "missing gone.txt");

    // An unrecognized header is a failure; the scan still continues.
    write_file(root, "unrec.txt", b"#simple-file-encrypt v9 x\n");
    run_nopw(root, &["add", "unrec.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED unrec.txt");
    assert_contains(&r.stdout, "verified a.txt");
    fs::remove_file(root.join("unrec.txt")).unwrap();

    // A single flipped base64 character fails authentication: exit 1.
    tamper_first_unit(root, "a.txt");
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED a.txt");
    write_file(root, "a.txt", &good_ct);
    run_pw(root, PW, &["verify"]).expect_code(0);

    // A wrong password is an operational error: exit 2.
    let r = run_pw(root, "wrong password", &["verify"]).expect_code(2);
    assert_contains(&r.stderr, "wrong password");
}

// ---------------------------------------------------------------------
// passwd and rekey
// ---------------------------------------------------------------------

#[test]
fn passwd_rewraps_ring_only() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "s.txt", b"k=v\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "s.txt"]).expect_code(0);
    let ct = read_file(root, "s.txt");
    let old_salt = salt_of(root);

    // Change the password via the two environment variables.
    const NEW_PW: &str = "brand new pw";
    let mut c = se(root);
    c.env("SIMPLE_FILE_ENCRYPT_PASSWORD", PW);
    c.env("SIMPLE_FILE_ENCRYPT_NEW_PASSWORD", NEW_PW);
    c.arg("passwd");
    let r = run(c).expect_code(0);
    assert_contains(&r.stdout, "password changed");
    assert_contains(&r.stderr, "revoke"); // the non-revocation warning

    // Ciphertext bytes are untouched; the salt rotated; ring length 1.
    assert_eq!(read_file(root, "s.txt"), ct);
    assert_ne!(salt_of(root), old_salt);
    assert_eq!(wrapped_keys_of(root).len(), 1);

    // The old password no longer unwraps the ring; the new one does.
    let r = run_pw(root, PW, &["verify"]).expect_code(2);
    assert_contains(&r.stderr, "wrong password");
    run_pw(root, NEW_PW, &["verify"]).expect_code(0);

    // Both passwords can also come from stdin, one per line.
    const THIRD_PW: &str = "third pw";
    let mut c = se(root);
    c.arg("passwd");
    c.write_stdin(format!("{NEW_PW}\n{THIRD_PW}\n"));
    run(c).expect_code(0);
    run_pw(root, THIRD_PW, &["verify"]).expect_code(0);
    run_pw(root, THIRD_PW, &["decrypt"]).expect_code(0);
    assert_eq!(read_file(root, "s.txt"), b"k=v\n");
}

#[test]
fn rekey_migration_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"a1\na2\n");
    write_file(root, "b.txt", b"b\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "a.txt", "b.txt"]).expect_code(0);
    let old_a = read_file(root, "a.txt");

    // Fresh rekey: mint, then migrate every managed ciphertext.
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stdout, "minted a new domain key");
    assert_contains(&r.stdout, "migrated a.txt");
    assert_contains(&r.stdout, "migrated b.txt");
    assert_eq!(wrapped_keys_of(root).len(), 2);
    let new_a = read_file(root, "a.txt");
    assert_ne!(new_a, old_a);
    run_pw(root, PW, &["verify"]).expect_code(0);

    // An old-epoch file resurfacing is authentic: pending migration.
    write_file(root, "a.txt", &old_a);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "pending migration a.txt");

    // A fresh rekey refuses while the rotation is unfinished.
    let r = run_pw(root, PW, &["rekey"]).expect_code(1);
    assert_contains(&r.stderr, "unfinished rotation");
    assert_contains(&r.stderr, "--continue");

    // `rekey --continue` migrates the straggler deterministically.
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    assert_contains(&r.stdout, "migrated a.txt");
    assert_contains(&r.stdout, "skipped b.txt (already encrypted)");
    assert_eq!(read_file(root, "a.txt"), new_a);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert!(!r.stdout.contains("pending migration"));
}

#[test]
fn rekey_prune_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"payload\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "a.txt"]).expect_code(0);
    let old_ct = read_file(root, "a.txt");

    run_pw(root, PW, &["rekey"]).expect_code(0);
    let cur_ct = read_file(root, "a.txt");
    let pre_keys = wrapped_keys_of(root);
    assert_eq!(pre_keys.len(), 2);

    // Prune refuses while an old-epoch file exists.
    write_file(root, "a.txt", &old_ct);
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    assert_eq!(read_file(root, "a.txt"), cur_ct);

    // Prune refuses when an exact managed entry is missing from disk.
    fs::remove_file(root.join("a.txt")).unwrap();
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "missing from disk");
    assert_contains(&r.stderr, "remove");
    write_file(root, "a.txt", &cur_ct);

    // Converged: prune rewrites the ring as one entry under a new salt.
    let pre_salt = salt_of(root);
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert_contains(&r.stdout, "pruned 1 old key epoch");
    let post_keys = wrapped_keys_of(root);
    assert_eq!(post_keys.len(), 1);
    assert_ne!(salt_of(root), pre_salt);

    // Pruning again is a no-op.
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert_contains(&r.stdout, "nothing to prune");

    // A pruned-epoch ciphertext fails closed with the history hint.
    write_file(root, "a.txt", &old_ct);
    let r = run_pw(root, PW, &["decrypt", "a.txt"]).expect_code(1);
    assert_contains(&r.stderr, "pruned");
    assert_contains(&r.stderr, "history");
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED a.txt");

    // Re-attaching a pre-prune wrapper to the pruned config fails: the
    // prune rotated the salt, so old wrappers cannot come back.
    set_wrapped_keys(root, &[post_keys[0].clone(), pre_keys[1].clone()]);
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "wrong password");
}

#[test]
fn key_ring_tamper_matrix_and_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let plaintext: &[u8] = b"x\ny\n";
    write_file(root, "f.txt", plaintext);
    init_domain(root);
    run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(0);
    let gen1_cfg = read_config(root);
    let gen1_ct = read_file(root, "f.txt");

    run_pw(root, PW, &["rekey"]).expect_code(0);
    let gen2_cfg = read_config(root);
    let keys = wrapped_keys_of(root);
    assert_eq!(keys.len(), 2);
    let (k0, k1) = (keys[0].clone(), keys[1].clone());

    // Any reordering, dropping, or duplicating of ring entries makes
    // every password-using command fail (the wrap AD binds ring length
    // and position).
    let mutations: Vec<Vec<String>> = vec![
        vec![k1.clone(), k0.clone()],             // swap
        vec![k1.clone()],                         // drop head
        vec![k0.clone()],                         // drop tail
        vec![k0.clone(), k1.clone(), k1.clone()], // duplicate
    ];
    for m in &mutations {
        fs::write(config_path(root), &gen2_cfg).unwrap();
        set_wrapped_keys(root, m);
        let r = run_pw(root, PW, &["decrypt"]).expect_code(1);
        assert!(
            r.stderr.contains("wrong password") || r.stderr.contains("corrupt key ring"),
            "unexpected error: {}",
            r.stderr
        );
    }

    // A forged tail entry unwraps entry 0 but exposes the corrupt ring.
    fs::write(config_path(root), &gen2_cfg).unwrap();
    set_wrapped_keys(root, &[k0.clone(), "0".repeat(96)]);
    let r = run_pw(root, PW, &["decrypt"]).expect_code(1);
    assert_contains(&r.stderr, "corrupt key ring");

    // Sanity: the intact config still verifies.
    fs::write(config_path(root), &gen2_cfg).unwrap();
    run_pw(root, PW, &["verify"]).expect_code(0);

    // A three-entry ring adds the middle-entry cases: drop the middle,
    // insert a forgery, or swap the head into the middle.
    run_pw(root, PW, &["rekey"]).expect_code(0);
    let keys3 = wrapped_keys_of(root);
    assert_eq!(keys3.len(), 3);
    let gen3_cfg = read_config(root);
    let mutations3: Vec<Vec<String>> = vec![
        vec![keys3[0].clone(), keys3[2].clone()], // drop middle
        vec![keys3[1].clone(), keys3[0].clone(), keys3[2].clone()], // head into middle
        vec![
            keys3[0].clone(),
            "f".repeat(96), // inserted forgery
            keys3[1].clone(),
            keys3[2].clone(),
        ],
    ];
    for m in &mutations3 {
        fs::write(config_path(root), &gen3_cfg).unwrap();
        set_wrapped_keys(root, m);
        let r = run_pw(root, PW, &["decrypt"]).expect_code(1);
        assert!(
            r.stderr.contains("wrong password") || r.stderr.contains("corrupt key ring"),
            "unexpected error: {}",
            r.stderr
        );
    }
    // Sanity: the intact three-entry config still verifies.
    fs::write(config_path(root), &gen3_cfg).unwrap();
    run_pw(root, PW, &["verify"]).expect_code(0);

    // Rolling back the complete config generation together with its
    // ciphertext is cryptographically accepted (pinned by design).
    fs::write(config_path(root), &gen1_cfg).unwrap();
    write_file(root, "f.txt", &gen1_ct);
    run_pw(root, PW, &["decrypt", "f.txt"]).expect_code(0);
    assert_eq!(read_file(root, "f.txt"), plaintext);
}

// ---------------------------------------------------------------------
// Boundaries and protected paths
// ---------------------------------------------------------------------

#[test]
fn repository_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let outer = tmp.path();
    fs::create_dir(outer.join(".git")).unwrap(); // repository boundary
    let root = outer.join("repo");
    fs::create_dir(&root).unwrap();
    write_file(&root, "top.txt", b"top\n");
    // A `.git` *file* marks a nested repository (submodule/worktree).
    write_file(&root, "sub/.git", b"gitdir: ../.git/modules/sub\n");
    write_file(&root, "sub/secret.txt", b"inner secret\n");
    fs::write(outer.join("outside.txt"), b"outside\n").unwrap();
    init_domain(&root);

    // A target inside the nested repository resolves to no domain.
    let r = run_pw(&root, PW, &["encrypt", "sub/secret.txt"]).expect_code(1);
    assert_contains(&r.stderr, "outside any simple-file-encrypt domain");

    // A target outside the domain root resolves to no domain either.
    let r = run_pw(&root, PW, &["encrypt", "../outside.txt"]).expect_code(1);
    assert_contains(&r.stderr, "outside any simple-file-encrypt domain");

    // Recursion skips the nested repository with a note.
    let r = run_pw(&root, PW, &["encrypt", "."]).expect_code(0);
    assert_contains(&r.stdout, "encrypted top.txt");
    assert_contains(&r.stderr, "skipping nested repository `sub`");
    assert_eq!(read_file(&root, "sub/secret.txt"), b"inner secret\n");
}

#[test]
fn nested_init_refused() {
    // A domain above refuses `init` below (and in the same directory).
    let tmp_a = tempfile::tempdir().unwrap();
    let root_a = tmp_a.path();
    fs::create_dir(root_a.join(".git")).unwrap();
    init_domain(root_a);
    let r = run_pw(
        root_a,
        PW,
        &["init", "--memory-kib", "8", "--iterations", "1"],
    )
    .expect_code(1);
    assert_contains(&r.stderr, "already exists in this directory");
    let sub = root_a.join("subdir");
    fs::create_dir(&sub).unwrap();
    let r = run_pw(
        &sub,
        PW,
        &["init", "--memory-kib", "8", "--iterations", "1"],
    )
    .expect_code(1);
    assert_contains(&r.stderr, "a domain already exists at");

    // A domain below refuses `init` above.
    let tmp_b = tempfile::tempdir().unwrap();
    let root_b = tmp_b.path();
    fs::create_dir(root_b.join(".git")).unwrap();
    let sub_b = root_b.join("sub");
    fs::create_dir(&sub_b).unwrap();
    init_domain(&sub_b);
    let r = run_pw(
        root_b,
        PW,
        &["init", "--memory-kib", "8", "--iterations", "1"],
    )
    .expect_code(1);
    assert_contains(&r.stderr, "below this directory");
}

#[test]
fn protected_targets_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let attrs: &[u8] = b"*.env -text\n";
    write_file(root, ".gitattributes", attrs);
    write_file(root, "g.txt", b"hello\n");
    init_domain(root);

    // git- and tool-critical files cannot be targeted or managed.
    let r = run_pw(root, PW, &["encrypt", ".gitattributes"]).expect_code(1);
    assert_contains(&r.stderr, "cannot target");
    let r = run_nopw(root, &["add", ".gitattributes"]).expect_code(1);
    assert_contains(&r.stderr, "cannot target");
    let r = run_pw(root, PW, &["encrypt", CONFIG]).expect_code(1);
    assert_contains(&r.stderr, "cannot target");

    // Recursion silently skips them.
    let r = run_pw(root, PW, &["encrypt", "."]).expect_code(0);
    assert_contains(&r.stdout, "encrypted g.txt");
    assert_eq!(read_file(root, ".gitattributes"), attrs);
}

// ---------------------------------------------------------------------
// Locking, hard links, renames
// ---------------------------------------------------------------------

#[test]
fn domain_lock_excludes_concurrent_instances() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "f.txt", b"data\n");
    init_domain(root);
    run_nopw(root, &["add", "f.txt"]).expect_code(0);

    // An exclusive lock held elsewhere blocks writers and readers.
    {
        let dir = fs::File::open(root).unwrap();
        dir.try_lock().unwrap();
        let r = run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(1);
        assert_contains(&r.stderr, "another simple-file-encrypt instance");
        let r = run_nopw(root, &["status"]).expect_code(1);
        assert_contains(&r.stderr, "another simple-file-encrypt instance");
    }

    // A shared lock lets readers through but still blocks writers.
    {
        let dir = fs::File::open(root).unwrap();
        eventually("shared lock after the exclusive one was dropped", || {
            dir.try_lock_shared().ok()
        });
        run_nopw(root, &["status"]).expect_code(0);
        let r = run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(1);
        assert_contains(&r.stderr, "another simple-file-encrypt instance");
    }

    // With all locks released the command succeeds.
    let r = eventually("encrypt succeeding after all locks were dropped", || {
        let r = run_pw(root, PW, &["encrypt", "f.txt"]);
        (r.code == 0).then_some(r)
    });
    assert_contains(&r.stdout, "encrypted f.txt");
}

#[test]
fn hard_link_refusals() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"top secret\n");
    init_domain(root);
    fs::hard_link(root.join("a.txt"), root.join("alias.txt")).unwrap();

    // Encrypting a multi-link plaintext would leave a plaintext alias.
    let r = run_pw(root, PW, &["encrypt", "a.txt"]).expect_code(1);
    assert_contains(&r.stderr, "hard links");
    assert_eq!(read_file(root, "a.txt"), b"top secret\n");

    // Two paths resolving to one inode in one operation are an error.
    let r = run_pw(root, PW, &["encrypt", "a.txt", "alias.txt"]).expect_code(1);
    assert_contains(&r.stderr, "same file");

    // Resolving the link clears the refusal.
    fs::remove_file(root.join("alias.txt")).unwrap();
    run_pw(root, PW, &["encrypt", "a.txt"]).expect_code(0);
}

#[test]
fn renamed_ciphertext_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "s.txt", b"secret\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "s.txt"]).expect_code(0);

    // Keys are path-bound: a renamed ciphertext cannot decrypt, and the
    // error names the cause.
    fs::rename(root.join("s.txt"), root.join("moved.txt")).unwrap();
    let r = run_pw(root, PW, &["decrypt", "moved.txt"]).expect_code(1);
    assert_contains(&r.stderr, "renamed");
    assert_contains(&r.stderr, "path-bound");
}

// ---------------------------------------------------------------------
// Miscellaneous hardening
// ---------------------------------------------------------------------

#[test]
fn empty_password_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "f.txt", b"data\n");
    init_domain(root);

    let mut c = se(root);
    c.env("SIMPLE_FILE_ENCRYPT_PASSWORD", "");
    c.args(["encrypt", "f.txt"]);
    let r = run(c).expect_code(1);
    assert_contains(&r.stderr, "must not be empty");
}

#[test]
fn stale_temp_files_swept() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "x.txt", b"x\n");
    init_domain(root);
    let stale = root.join(".simple-file-encrypt.tmp.ABCDEFGH01234567");
    fs::write(&stale, b"crash leftover").unwrap();

    // Any exclusive-lock command sweeps stale temp files.
    let r = run_nopw(root, &["add", "x.txt"]).expect_code(0);
    assert!(!stale.exists());
    assert_contains(&r.stderr, "removed stale temp file");
}

#[test]
fn config_strictness() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    let good = read_config(root);

    // Unknown keys are rejected.
    fs::write(config_path(root), format!("{good}\nmystery_knob = true\n")).unwrap();
    let r = run_nopw(root, &["status"]).expect_code(1);
    assert_contains(&r.stderr, "config error");

    // A newer version fails closed with the upgrade hint.
    fs::write(
        config_path(root),
        good.replace("version = 1", "version = 2"),
    )
    .unwrap();
    let r = run_nopw(root, &["status"]).expect_code(1);
    assert_contains(&r.stderr, "upgrade simple-file-encrypt");
}

#[test]
fn usage_errors_exit_one() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // clap usage errors exit 1 (never 2, which check/verify reserve).
    let mut c = se(root);
    c.arg("frobnicate");
    let r = run(c);
    assert_eq!(r.code, 1, "stderr: {}", r.stderr);

    // Help output is not an error.
    let mut c = se(root);
    c.arg("--help");
    run(c).expect_code(0);
}

// ---------------------------------------------------------------------
// Regressions from the spec-compliance review
// ---------------------------------------------------------------------

/// `remove` must not claim `removed …` for entries whose removal was
/// never persisted: a later entry's refusal aborts the whole rewrite.
#[test]
fn remove_reports_only_persisted_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"a\n");
    write_file(root, "b.txt", b"b\n");
    init_domain(root);
    run_nopw(root, &["add", "a.txt", "b.txt"]).expect_code(0);
    run_pw(root, PW, &["encrypt", "b.txt"]).expect_code(0);

    // a.txt is removable, but b.txt is encrypted: the command fails and
    // nothing may be reported (or persisted) as removed.
    let r = run_nopw(root, &["remove", "a.txt", "b.txt"]).expect_code(1);
    assert!(
        !r.stdout.contains("removed a.txt"),
        "claimed an unpersisted removal:\n{}",
        r.stdout
    );
    assert_contains(&read_config(root), "\"a.txt\"");
}

/// Encrypting an explicit file already covered by a managed directory
/// entry must not add a redundant exact entry (it is already managed).
#[test]
fn auto_add_respects_directory_coverage() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "secrets/x.txt", b"x\n");
    init_domain(root);
    run_nopw(root, &["add", "secrets"]).expect_code(0);

    let r = run_pw(root, PW, &["encrypt", "secrets/x.txt"]).expect_code(0);
    assert_contains(&r.stdout, "encrypted secrets/x.txt");
    let cfg = read_config(root);
    assert!(
        !cfg.contains("secrets/x.txt"),
        "redundant entry written:\n{cfg}"
    );
    assert_contains(&cfg, "\"secrets\"");
}

/// The write side refuses to grow the config beyond what `load`
/// accepts, instead of bricking the domain (config caps are enforced
/// both ways). The size cap is unit-tested; this exercises the
/// entry-count cap end to end.
#[test]
fn config_caps_are_enforced_on_the_write_side() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);

    // Hand-grow the config to exactly the entry-count cap (valid to load).
    let entries: Vec<String> = (0..65536).map(|i| format!("\"p{i:05}\"")).collect();
    let cfg = read_config(root);
    let grown = cfg.replace(
        "paths = []",
        &format!("paths = [\n{}\n]", entries.join(",\n")),
    );
    fs::write(config_path(root), &grown).unwrap();
    run_nopw(root, &["status"]).expect_code(0); // still loads

    // One more entry would cross the cap: `add` must fail without
    // touching the config instead of writing an unloadable one.
    write_file(root, "one-more.txt", b"x\n");
    let r = run_nopw(root, &["add", "one-more.txt"]).expect_code(1);
    assert_contains(&r.stderr, "entries");
    assert_eq!(
        read_config(root),
        grown,
        "config was rewritten despite the cap"
    );
    run_nopw(root, &["status"]).expect_code(0); // and still loads
}

// ---------------------------------------------------------------------
// Hostile filesystem states
// ---------------------------------------------------------------------

#[test]
fn managed_ancestor_symlink_escape_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("repo");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(root.join("managed")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write_file(&root, "managed/secret.txt", b"secret\n");
    fs::write(outside.join("secret.txt"), b"outside\n").unwrap();
    init_domain(&root);
    run_pw(&root, PW, &["add", "managed/secret.txt"]).expect_code(0);

    // Replace the managed directory with a symlink out of the domain
    // (a hostile commit can carry exactly this change).
    fs::remove_dir_all(root.join("managed")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("managed")).unwrap();
    let stray = outside.join(".simple-file-encrypt.tmp.ABCDEFGH01234567");
    fs::write(&stray, b"precious\n").unwrap();

    // The stored entry must not be followed out of the domain.
    let r = run_pw(&root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "symlink");
    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"outside\n");

    // Commands that sweep (`add` sweeps the parents of managed entries)
    // must not reach through the symlink either.
    let r = run_nopw(&root, &["add", "other.txt"]);
    assert_eq!(r.code, 0, "stderr: {}", r.stderr);
    assert_contains(&r.stderr, "not sweeping");
    assert!(stray.exists(), "the sweep must stay inside the domain");
}

#[test]
fn config_must_be_a_regular_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);

    // A symlinked config is refused at open (O_NOFOLLOW).
    let real = root.join("real.toml");
    fs::rename(config_path(root), &real).unwrap();
    std::os::unix::fs::symlink(&real, config_path(root)).unwrap();
    let r = run_nopw(root, &["status"]).expect_code(1);
    assert_contains(&r.stderr, "opening");
    fs::remove_file(config_path(root)).unwrap();

    // A FIFO config fails fast instead of blocking the read.
    let mk = std::process::Command::new("mkfifo")
        .arg(config_path(root))
        .status()
        .unwrap();
    assert!(mk.success());
    let mut c = se(root);
    c.args(["status"])
        .timeout(std::time::Duration::from_secs(30));
    let r = run(c).expect_code(1);
    assert_contains(&r.stderr, "not a regular file");
}

#[test]
fn newline_dense_probe_hit_stays_cheap() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    // The first-unit check must not materialize per-line slices of a
    // newline-dense tail (~17x memory amplification before the fix).
    let mut content = Vec::from(&b"#simple-file-encrypt v1 text\nAAAA\n"[..]);
    content.extend(std::iter::repeat_n(b'\n', 8_000_000));
    write_file(root, "dense.txt", &content);
    run_pw(root, PW, &["add", "dense.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "dense.txt");
    assert_contains(&r.stderr, "fewer than 16 bytes");
}

#[test]
fn temp_name_lookalikes_survive_the_sweep() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "x.txt", b"x\n");
    init_domain(root);
    let lookalikes = [
        ".simple-file-encrypt.tmp.notes",
        ".simple-file-encrypt.tmp.abc",
        ".simple-file-encrypt.tmp.ABCDEFGH0123456789",
        ".simple-file-encrypt.tmp.ABCDEFGH0123456!",
    ];
    for name in lookalikes {
        write_file(root, name, b"keep\n");
    }
    run_nopw(root, &["add", "x.txt"]).expect_code(0);
    for name in lookalikes {
        assert!(root.join(name).exists(), "{name} must survive the sweep");
    }
}

#[test]
fn rekey_continue_rejects_mixed_epoch_files() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "m.txt", b"l1\nl2\nl3\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "m.txt"]).expect_code(0);
    let old_ct = read_file(root, "m.txt");
    run_pw(root, PW, &["rekey"]).expect_code(0);
    let new_ct = read_file(root, "m.txt");

    // Splice a file whose first unit belongs to the current epoch and
    // whose later units belong to the old one (a bad merge can produce
    // exactly this).
    let new_lines: Vec<&[u8]> = new_ct.split(|&b| b == b'\n').collect();
    let old_lines: Vec<&[u8]> = old_ct.split(|&b| b == b'\n').collect();
    let mixed = [new_lines[0], new_lines[1], old_lines[2], old_lines[3], b""].join(&b'\n');
    write_file(root, "m.txt", &mixed);

    // --continue must not report success over a deeply damaged file.
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully authenticate");
    assert_contains(&r.stderr, "resolve the file manually");
    // prune must not point back at --continue either (no advice loop).
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    assert_contains(&r.stderr, "resolve the file manually");
    // The ring stays untouched.
    assert_eq!(wrapped_keys_of(root).len(), 2);
}

#[test]
fn prune_refuses_symlinked_managed_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "s.txt", b"data\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "s.txt"]).expect_code(0);
    run_pw(root, PW, &["rekey"]).expect_code(0);

    fs::remove_file(root.join("s.txt")).unwrap();
    std::os::unix::fs::symlink("/nonexistent-target", root.join("s.txt")).unwrap();
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "symlink or special file");
    assert_eq!(wrapped_keys_of(root).len(), 2);
}

#[test]
fn control_characters_in_paths_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    let evil = "evil\nFAILED fake.txt";
    write_file(root, evil, b"x\n");

    // Minting refuses control characters and reports them escaped.
    let r = run_nopw(root, &["add", evil]).expect_code(1);
    assert_contains(&r.stderr, "control character");
    assert_contains(&r.stderr, "evil\\nFAILED");
    assert!(
        !r.stderr.contains("evil\nFAILED"),
        "raw injection: {}",
        r.stderr
    );
    let r = run_pw(root, PW, &["encrypt", evil]).expect_code(1);
    assert_contains(&r.stderr, "control character");

    // A hostile stored entry fails at load, shown in escaped form.
    let cfg = read_config(root).replace("paths = []", "paths = [\"evil\\nfake.txt\"]");
    fs::write(config_path(root), cfg).unwrap();
    let r = run_nopw(root, &["status"]).expect_code(1);
    assert_contains(&r.stderr, "control character");
    assert_contains(&r.stderr, "evil\\nfake.txt");
}

#[test]
fn broken_pipe_exits_141_instead_of_panicking() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    // Enough output to overflow the pipe buffer after the reader leaves.
    for i in 0..4000 {
        write_file(root, &format!("dir/f{i:04}.txt"), b"x\n");
    }
    run_nopw(root, &["add", "dir"]).expect_code(0);

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_simple-file-encrypt"))
        .arg("--allow-weak-kdf")
        .arg("status")
        .current_dir(root)
        .env_remove("SIMPLE_FILE_ENCRYPT_PASSWORD")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    use std::io::Read;
    let mut buf = [0u8; 1024];
    let _ = stdout.read(&mut buf);
    drop(stdout); // the consumer is gone; further writes hit EPIPE
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(141));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(!stderr.contains("panic"), "stderr: {stderr}");
}

#[test]
fn auto_add_registers_all_files_before_encrypting() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    write_file(root, "d/a.txt", b"a\n");
    write_file(root, "d/b.txt", b"b\n");
    // One config rewrite covers the whole directory, before any file is
    // encrypted (no per-file rewrite storm).
    let r = run_pw(root, PW, &["encrypt", "d"]).expect_code(0);
    let first_enc = r.stdout.find("encrypted ").unwrap();
    let last_add = r.stdout.rfind("added ").unwrap();
    assert!(
        last_add < first_enc,
        "all registrations must precede encryption:\n{}",
        r.stdout
    );
    let cfg = read_config(root);
    assert!(cfg.contains("d/a.txt") && cfg.contains("d/b.txt"));
}

#[test]
fn auto_add_merges_a_large_batch_in_one_pass() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Existing managed entries sorting *after* the new batch, so under
    // per-file insertion every new entry landed at the front of the
    // list (the quadratic worst case the batched merge replaced); the
    // behavior must be identical either way.
    for i in 0..40 {
        write_file(root, &format!("zz/f{i:02}.txt"), b"old\n");
    }
    init_domain(root);
    run_pw(root, PW, &["encrypt", "zz"]).expect_code(0);
    for i in 0..1500 {
        write_file(
            root,
            &format!("aa/f{i:04}.txt"),
            format!("s{i}\n").as_bytes(),
        );
    }
    let r = run_pw(root, PW, &["encrypt", "aa"]).expect_code(0);
    assert_contains(&r.stdout, "added aa/f0000.txt");
    assert_contains(&r.stdout, "added aa/f1499.txt");
    assert_eq!(read_config(root).matches("\"aa/f").count(), 1500);

    // The merged list is a working managed list: re-encrypting adds
    // nothing (every file is covered and already encrypted), and the
    // ciphertext decrypts.
    let r = run_pw(root, PW, &["encrypt", "aa"]).expect_code(0);
    assert!(!r.stdout.contains("added "), "no re-adds:\n{}", r.stdout);
    assert_contains(&r.stdout, "skipped aa/f0000.txt (already encrypted)");
    run_pw(root, PW, &["decrypt", "aa/f0777.txt"]).expect_code(0);
    assert_eq!(read_file(root, "aa/f0777.txt"), b"s777\n");
}

#[test]
fn overlong_password_input_is_bounded() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "f.txt", b"x\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "f.txt"]).expect_code(0);
    // A newline-free stream far past the 4096-byte cap is rejected from
    // a bounded read, not buffered whole first.
    let mut c = se(root);
    c.args(["verify"]);
    c.write_stdin("A".repeat(1 << 20));
    let r = run(c).expect_code(2);
    assert_contains(&r.stderr, "4096");
}

#[test]
fn discovered_control_char_names_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    write_file(root, "d/evil\nINJECTED", b"x\n");

    // A managed directory walk must not mint the name into a canonical
    // path (key derivation and output would both be poisoned).
    run_nopw(root, &["add", "d"]).expect_code(0);
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "control character");
    assert!(
        !r.stderr.contains("evil\nINJECTED"),
        "raw injection: {}",
        r.stderr
    );

    // An explicit directory walk fails the same way.
    let r = run_pw(root, PW, &["encrypt", "d"]).expect_code(1);
    assert_contains(&r.stderr, "control character");
}

#[test]
fn scans_and_continue_report_skipped_special_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "s.txt", b"data\n");
    init_domain(root);
    run_pw(root, PW, &["encrypt", "s.txt"]).expect_code(0);
    run_pw(root, PW, &["rekey"]).expect_code(0);

    // Replace the managed file with a symlink: content now unverifiable.
    fs::remove_file(root.join("s.txt")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("s.txt")).unwrap();

    // status names the state in its report (exit stays 0: report, not gate).
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert_contains(&r.stdout, "symlink");
    assert_contains(&r.stdout, "s.txt");

    // check must not pass a gate over unverifiable managed content.
    let r = run_nopw(root, &["check"]).expect_code(1);
    assert_contains(&r.stdout, "symlink");
    assert_contains(&r.stdout, "s.txt");

    // verify fails it explicitly.
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED s.txt");

    // --continue must not claim the rotation is complete.
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "never verified");

    // A symlink *child* inside a managed directory is caught the same way.
    write_file(root, "sub/real.txt", b"real\n");
    run_nopw(root, &["add", "sub"]).expect_code(0);
    std::os::unix::fs::symlink("/etc/passwd", root.join("sub/link.txt")).unwrap();
    let r = run_nopw(root, &["check"]).expect_code(1);
    assert_contains(&r.stdout, "sub/link.txt");
}

#[test]
fn prune_with_single_entry_ring_short_circuits() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "f.txt", b"x\n");
    init_domain(root);
    // A missing managed entry does not matter when there is nothing to
    // prune: no convergence check runs at all.
    run_nopw(root, &["add", "gone.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert_contains(&r.stdout, "nothing to prune");
}

#[test]
fn symlinked_domain_root_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real-domain");
    let caller = tmp.path().join("caller");
    fs::create_dir_all(&real).unwrap();
    fs::create_dir_all(&caller).unwrap();
    write_file(&real, "s.txt", b"data\n");
    init_domain(&real);
    std::os::unix::fs::symlink(&real, caller.join("alias")).unwrap();

    // An explicit argument reaching the domain through a symlinked
    // root must be refused, not followed into the other domain.
    let r = run_pw(&caller, PW, &["encrypt", "alias/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "symlink");
    // The file was not touched.
    assert_eq!(read_file(&real, "s.txt"), b"data\n");
}

#[test]
fn concurrent_parent_child_init_never_nests() {
    for _ in 0..10 {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join(".git")).unwrap();
        fs::create_dir(root.join("sub")).unwrap();

        let spawn_init = |dir: &Path| {
            std::process::Command::new(env!("CARGO_BIN_EXE_simple-file-encrypt"))
                .args([
                    "--allow-weak-kdf",
                    "init",
                    "--memory-kib",
                    "8",
                    "--iterations",
                    "1",
                ])
                .current_dir(dir)
                .env("SIMPLE_FILE_ENCRYPT_PASSWORD", PW)
                .env_remove("SIMPLE_FILE_ENCRYPT_NEW_PASSWORD")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut pa = spawn_init(root);
        let mut pb = spawn_init(&root.join("sub"));
        let _ = pa.wait().unwrap();
        let _ = pb.wait().unwrap();
        let configs = [root.join(CONFIG), root.join("sub").join(CONFIG)]
            .iter()
            .filter(|p| p.exists())
            .count();
        assert!(configs <= 1, "nested domains were created concurrently");
    }
}

// Linux-only: APFS rejects non-UTF-8 file names at creation time
// (EILSEQ), so the scenario cannot be constructed on macOS (the
// refusal itself would apply there too, e.g. on mounted volumes).
#[cfg(target_os = "linux")]
#[test]
fn discovered_non_utf8_names_are_refused() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    fs::create_dir(root.join("d")).unwrap();
    fs::write(
        PathBuf::from(OsStr::from_bytes(root.join("d").as_os_str().as_bytes()))
            .join(OsStr::from_bytes(b"evil-\xff.txt")),
        b"plaintext\n",
    )
    .unwrap();
    run_nopw(root, &["add", "d"]).expect_code(0);

    // A non-UTF-8 name cannot feed key derivation; every command that
    // expands the directory must fail, never silently skip the file.
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "not valid UTF-8");
    let r = run_nopw(root, &["check"]).expect_code(2);
    assert_contains(&r.stderr, "not valid UTF-8");
    let r = run_pw(root, PW, &["verify"]).expect_code(2);
    assert_contains(&r.stderr, "not valid UTF-8");
}

#[test]
fn symlinked_component_above_discovered_root_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tmp.path().join("outside-parent");
    let caller = tmp.path().join("caller");
    fs::create_dir_all(outside.join("subdomain")).unwrap();
    fs::create_dir_all(&caller).unwrap();
    write_file(&outside.join("subdomain"), "s.txt", b"data\n");
    init_domain(&outside.join("subdomain"));
    std::os::unix::fs::symlink(&outside, caller.join("alias")).unwrap();

    // `alias` is introduced by the argument itself (below the cwd), so
    // the "any component of an explicit argument" rule covers it even
    // though the discovered root's final component is a real directory.
    let r = run_pw(&caller, PW, &["encrypt", "alias/subdomain/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "crosses the symlink");
    assert_eq!(read_file(&outside.join("subdomain"), "s.txt"), b"data\n");
}

#[test]
fn add_and_remove_binary_marks_force_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "data.txt", b"plain text\n");
    write_file(root, "d/inner.txt", b"inner\n");
    init_domain(root);

    // add --binary: managed AND marked, status shows the marker.
    let r = run_nopw(root, &["add", "--binary", "data.txt", "d"]).expect_code(0);
    assert_contains(&r.stdout, "added data.txt");
    assert_contains(&r.stdout, "marked data.txt as always-binary");
    assert_contains(&r.stdout, "marked d as always-binary");
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert_contains(&r.stdout, "data.txt [binary]");
    assert_contains(&r.stdout, "d/inner.txt [binary]");

    // Re-marking is reported, not duplicated.
    let r = run_nopw(root, &["add", "--binary", "data.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already managed");
    assert_contains(&r.stdout, "already marked binary");
    assert_eq!(read_config(root).matches("data.txt").count(), 2);

    // Text content is encrypted in binary mode anyway.
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert!(read_file(root, "data.txt").starts_with(&BIN_MAGIC));

    // remove --binary: unmarked but still managed; the mode reverts
    // only after a decrypt + encrypt cycle.
    let r = run_nopw(root, &["remove", "--binary", "data.txt"]).expect_code(0);
    assert_contains(&r.stdout, "unmarked data.txt");
    assert_contains(&r.stderr, "not re-encrypted automatically");
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert!(read_file(root, "data.txt").starts_with(TEXT_HEADER.as_bytes()));
    assert!(read_file(root, "d/inner.txt").starts_with(&BIN_MAGIC));

    // The entry is gone; removing it again errors, and the file stays
    // managed.
    let r = run_nopw(root, &["remove", "--binary", "data.txt"]).expect_code(1);
    assert_contains(&r.stderr, "not a `force_binary` entry");
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert_contains(&r.stdout, "encrypted    data.txt");
    // --binary and --force conflict.
    run_nopw(root, &["remove", "--binary", "--force", "data.txt"]).expect_code(1);
}

#[test]
fn add_prunes_descendants_only_for_real_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    // A missing path keeps descendant entries (its type is unknown).
    run_nopw(root, &["add", "a/b"]).expect_code(0);
    run_nopw(root, &["add", "a"]).expect_code(0);
    assert!(
        read_config(root).contains("\"a/b\""),
        "descendant lost: {}",
        read_config(root)
    );

    // A regular file cannot cover descendants: hard conflict (the
    // entry was added while the file did not yet exist).
    run_nopw(root, &["add", "f/c"]).expect_code(0);
    write_file(root, "f", b"x\n");
    let r = run_nopw(root, &["add", "f"]).expect_code(1);
    assert_contains(&r.stderr, "a file cannot cover them");
    assert!(read_config(root).contains("\"f/c\""));

    // A real directory prunes as documented.
    fs::create_dir_all(root.join("d")).unwrap();
    run_nopw(root, &["add", "d/e"]).expect_code(0);
    let r = run_nopw(root, &["add", "d"]).expect_code(0);
    assert_contains(&r.stdout, "dropped the redundant entry");
    assert!(!read_config(root).contains("\"d/e\""));
}

#[test]
fn verify_reports_large_plaintext_without_reading_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    // A sparse plaintext file beyond the 256 MiB cap: verify must
    // still report "plaintext" (exit 0), not fail on the cap.
    let big = root.join("big.bin");
    fs::write(&big, b"").unwrap();
    fs::File::options()
        .write(true)
        .open(&big)
        .unwrap()
        .set_len(257 * 1024 * 1024)
        .unwrap();
    run_nopw(root, &["add", "big.bin"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "plaintext big.bin");
}

#[test]
fn remove_binary_defers_warnings_until_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "a.txt", b"a\n");
    init_domain(root);
    run_nopw(root, &["add", "--binary", "a.txt"]).expect_code(0);
    // First arg succeeds in memory, second fails: nothing is committed,
    // so no reversion warning may be printed at all.
    let r = run_nopw(root, &["remove", "--binary", "a.txt", "ghost.txt"]).expect_code(1);
    assert_contains(&r.stderr, "ghost.txt` is not a `force_binary` entry");
    assert!(
        !r.stderr.contains("reverts to automatic mode choice"),
        "warning leaked before commit: {}",
        r.stderr
    );
    assert!(read_config(root).contains("a.txt"));

    // The committed path prints the warning after the rewrite.
    let r = run_nopw(root, &["remove", "--binary", "a.txt"]).expect_code(0);
    assert_contains(&r.stderr, "reverts to automatic mode choice");
}

#[test]
fn status_marks_skipped_special_force_binary_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "s.txt", b"data\n");
    init_domain(root);
    run_nopw(root, &["add", "--binary", "s.txt"]).expect_code(0);
    fs::remove_file(root.join("s.txt")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("s.txt")).unwrap();
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert_contains(&r.stdout, "symlink     s.txt [binary]");
}

#[test]
fn symlink_warning_flood_is_summarized() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    fs::create_dir(root.join("links")).unwrap();
    for i in 0..25 {
        std::os::unix::fs::symlink("/nonexistent", root.join(format!("links/l{i:02}"))).unwrap();
    }
    run_nopw(root, &["add", "links"]).expect_code(0);
    // 20 individual warnings (the in-tree cap), one summary for the
    // remaining 5 — a tree full of symlinks must not flood stderr.
    let r = run_nopw(root, &["check"]).expect_code(1);
    assert_eq!(
        r.stderr.matches("skipping `links/").count(),
        20,
        "stderr:\n{}",
        r.stderr
    );
    assert_contains(&r.stderr, "5 more symlinks or special files were skipped");
    // All 25 still count as offenders for the gate.
    assert_eq!(r.stdout.matches("symlink").count(), 25, "{}", r.stdout);
}

#[test]
fn managed_entry_through_file_ancestor_reports_the_conflict() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    init_domain(root);
    // Entry added while `a` did not exist; `a` then appears as a file.
    run_nopw(root, &["add", "a/b"]).expect_code(0);
    write_file(root, "a", b"now a file\n");
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "not a directory");
    assert_contains(&r.stderr, "a/b");
}

// macOS-only: exercises the case-insensitive-volume re-spelling path.
// Whether the volume actually folds case is probed at run time (APFS
// and HFS+ can be formatted either way), so on a case-sensitive volume
// the test skips instead of failing.
#[cfg(target_os = "macos")]
#[test]
#[expect(
    clippy::print_stderr,
    reason = "tests cannot skip at run time; a silent pass would hide that nothing ran"
)]
fn case_insensitive_volume_respells_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fs::write(root.join("CaseProbe"), b"").unwrap();
    let insensitive = root.join("caseprobe").exists();
    fs::remove_file(root.join("CaseProbe")).unwrap();
    if !insensitive {
        eprintln!("skipping: the test volume is case-sensitive");
        return;
    }
    init_domain(root);
    write_file(root, "Secrets/Inner.txt", b"x\n");
    // Reference the file with a different case spelling: minting must
    // re-spell to the on-disk name so key derivation stays stable.
    let r = run_nopw(root, &["add", "secrets/inner.txt"]).expect_code(0);
    assert_contains(&r.stdout, "added Secrets/Inner.txt");
    // Two alias spellings of one file dedup to a single canonical
    // target instead of tripping the same-inode aliasing error.
    let r = run_pw(
        root,
        PW,
        &["encrypt", "SECRETS/INNER.TXT", "secrets/inner.txt"],
    )
    .expect_code(0);
    assert_eq!(
        r.stdout.matches("encrypted Secrets/Inner.txt").count(),
        1,
        "{}",
        r.stdout
    );
}

// ---------------------------------------------------------------------
// Excludes
// ---------------------------------------------------------------------

#[test]
fn exclude_add_remove_bookkeeping() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/keep.txt", b"keep\n");
    write_file(root, "d/skip.txt", b"skip\n");
    init_domain(root);

    // The empty config renders no `excludes` key at all, so configs not
    // using the feature stay loadable by older versions.
    assert!(!read_config(root).contains("excludes"));

    let r = run_nopw(root, &["add", "--exclude", "d/skip.txt"]).expect_code(0);
    assert_contains(&r.stdout, "excluded d/skip.txt");
    assert_contains(&read_config(root), "excludes = [");
    assert_contains(&read_config(root), "\"d/skip.txt\"");

    // Duplicate excludes are reported, not duplicated.
    let r = run_nopw(root, &["add", "--exclude", "d/skip.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already excluded");

    // A real directory entry collapses the entries it covers.
    let r = run_nopw(root, &["add", "--exclude", "d"]).expect_code(0);
    assert_contains(
        &r.stdout,
        "now covered by `d`; dropped the redundant excludes entry",
    );
    assert_contains(&r.stdout, "excluded d");
    assert!(!read_config(root).contains("\"d/skip.txt\""));
    let r = run_nopw(root, &["add", "--exclude", "d/skip.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already covered by the excludes entry `d`");

    // Removal errors: covered-but-not-an-entry, and not-an-entry.
    let r = run_nopw(root, &["remove", "--exclude", "d/skip.txt"]).expect_code(1);
    assert_contains(&r.stderr, "covered by the excludes entry `d`");
    let r = run_nopw(root, &["remove", "--exclude", "stray.txt"]).expect_code(1);
    assert_contains(&r.stderr, "not an excludes entry");

    let r = run_nopw(root, &["remove", "--exclude", "d"]).expect_code(0);
    assert_contains(&r.stdout, "removed d from excludes");
    assert_contains(&r.stderr, "eligible for encryption again");
    // Empty again: the key disappears from the rendered config.
    assert!(!read_config(root).contains("excludes"));

    // A not-yet-existing path can be excluded (pre-declared), warned.
    let r = run_nopw(root, &["add", "--exclude", "ghost.txt"]).expect_code(0);
    assert_contains(&r.stderr, "does not exist on disk");
    run_nopw(root, &["remove", "--exclude", "ghost.txt"]).expect_code(0);

    // The domain root cannot be excluded.
    let r = run_nopw(root, &["add", "--exclude", "."]).expect_code(1);
    assert_contains(&r.stderr, "domain root");

    // Flag combinations rejected by the CLI.
    run_nopw(root, &["add", "--exclude", "--binary", "d/skip.txt"]).expect_code(1);
    run_nopw(root, &["add", "--force", "d/skip.txt"]).expect_code(1);
    run_nopw(root, &["remove", "--exclude", "--force", "d"]).expect_code(1);
    run_nopw(root, &["remove", "--exclude", "--binary", "d"]).expect_code(1);
}

#[test]
fn exclude_refuses_contradictions_with_the_managed_list() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret\n");
    write_file(root, "other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d/s.txt"]).expect_code(0);

    // Excluding an exact managed entry (or a directory covering one)
    // would fully shadow it: refused, `remove` first.
    let r = run_nopw(root, &["add", "--exclude", "d/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "would fully shadow the managed entry (d/s.txt)");
    let r = run_nopw(root, &["add", "--exclude", "d"]).expect_code(1);
    assert_contains(&r.stderr, "would fully shadow the managed entry (d/s.txt)");

    run_nopw(root, &["remove", "d/s.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "d/s.txt"]).expect_code(0);

    // The reverse direction: an excluded path cannot be managed.
    let r = run_nopw(root, &["add", "d/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "it is excluded");
    let r = run_nopw(root, &["add", "--binary", "d/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "it is excluded");
    // Managing a directory *above* an exclusion is the intended use.
    let r = run_nopw(root, &["add", "d"]).expect_code(0);
    assert_contains(&r.stdout, "added d");

    // A hand-edited contradiction fails closed at load time: append the
    // managed entry to the existing `excludes` block by hand.
    run_nopw(root, &["add", "other.txt"]).expect_code(0);
    let cfg = read_config(root);
    let broken = cfg.replace("\"d/s.txt\",", "\"d/s.txt\",\n    \"other.txt\",");
    assert_ne!(broken, cfg);
    fs::write(config_path(root), broken).unwrap();
    let r = run_nopw(root, &["status"]).expect_code(1);
    assert_contains(&r.stderr, "contradiction");
}

#[test]
fn encrypt_skips_excluded_paths_and_refuses_naming_them() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/keep.txt", b"keep\n");
    write_file(root, "d/skip.txt", b"skip\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "d/skip.txt"]).expect_code(0);

    // Managed expansion skips the excluded file (with a count note).
    let r = run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_contains(&r.stdout, "encrypted d/keep.txt");
    assert_contains(&r.stderr, "skipping 1 excluded file(s)");
    assert!(!r.stdout.contains("d/skip.txt"));
    assert_eq!(read_file(root, "d/skip.txt"), b"skip\n");

    // The keyless gate treats excluded plaintext as intentional, both
    // via the managed list and via explicit arguments.
    run_nopw(root, &["check"]).expect_code(0);
    run_nopw(root, &["check", "d"]).expect_code(0);
    run_nopw(root, &["check", "d/skip.txt"]).expect_code(0);

    // Naming an excluded path is a hard error, --assume-plaintext or not.
    let r = run_pw(root, PW, &["encrypt", "d/skip.txt"]).expect_code(1);
    assert_contains(&r.stderr, "it is excluded");
    let r = run_pw(root, PW, &["encrypt", "--assume-plaintext", "d/skip.txt"]).expect_code(1);
    assert_contains(&r.stderr, "it is excluded");

    // Explicit directory expansion filters exclusions and never
    // auto-adds excluded files.
    write_file(root, "e/x.txt", b"x\n");
    write_file(root, "e/y.txt", b"y\n");
    run_nopw(root, &["add", "--exclude", "e/y.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["encrypt", "e"]).expect_code(0);
    assert_contains(&r.stdout, "added e/x.txt");
    assert_contains(&r.stdout, "encrypted e/x.txt");
    // The excluded file is not auto-added: it appears in the `excludes`
    // block only, never in `paths`.
    let cfg = read_config(root);
    let start = cfg.find("paths = [").unwrap();
    let paths_block = &cfg[start..start + cfg[start..].find(']').unwrap()];
    assert!(paths_block.contains("e/x.txt"), "{cfg}");
    assert!(!paths_block.contains("e/y.txt"), "{cfg}");
    assert_eq!(read_file(root, "e/y.txt"), b"y\n");

    // A managed directory whose whole content is excluded is "nothing
    // to do" — and needs no password (none is supplied here).
    let tmp2 = tempfile::tempdir().unwrap();
    let root2 = tmp2.path();
    write_file(root2, "d2/only.txt", b"only\n");
    init_domain(root2);
    run_nopw(root2, &["add", "d2"]).expect_code(0);
    run_nopw(root2, &["add", "--exclude", "d2/only.txt"]).expect_code(0);
    let r = run_nopw(root2, &["encrypt"]).expect_code(0);
    assert_contains(&r.stdout, "nothing to do");
}

#[test]
fn exclude_refuses_encrypted_content_and_decrypt_recovers_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret\n");
    write_file(root, "d/sub/t.txt", b"tee\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // Excluding a path that probes as encrypted is refused: the
    // ciphertext would be hidden from `encrypt` and `rekey`.
    let r = run_nopw(root, &["add", "--exclude", "d/s.txt"]).expect_code(1);
    assert_contains(&r.stderr, "probes as encrypted; decrypt it first");
    assert_contains(&r.stderr, "`add --exclude --force` overrides");
    // A directory covering encrypted files is refused the same way.
    let r = run_nopw(root, &["add", "--exclude", "d/sub"]).expect_code(1);
    assert_contains(&r.stderr, "d/sub/t.txt");
    assert_contains(&r.stderr, "probes as encrypted");

    // --force creates the stranded state, loudly.
    let r = run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);
    assert_contains(&r.stderr, "force-excluding");

    // `status` reports the anomaly; `check` stays exempt (keyless, it
    // cannot tell stranded from foreign); `verify` is authoritative.
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "excluded", "d/s.txt"));
    run_nopw(root, &["check"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "excluded path holds valid ciphertext");

    // `remove` of the covering directory entry still sees the hidden
    // ciphertext and refuses to strand it further.
    let r = run_nopw(root, &["remove", "d"]).expect_code(1);
    assert_contains(&r.stderr, "decrypt it first");

    // `decrypt` is the repair channel: the stranded file is recovered.
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    assert_eq!(read_file(root, "d/s.txt"), b"secret\n");
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert!(!r.stdout.contains("FAILED"));
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(!status_line(&r.stdout, "excluded", "d/s.txt"));

    // Re-encrypting leaves the excluded file alone now.
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_eq!(read_file(root, "d/s.txt"), b"secret\n");
}

#[test]
fn exclude_manages_foreign_looking_content() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/real.txt", b"real\n");
    let mut fake = BIN_MAGIC.to_vec();
    fake.extend_from_slice(b"not really ciphertext");
    write_file(root, "d/fake.bin", &fake);
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);

    // A probe collision inside a managed directory blocks every
    // encrypt run — the situation excludes exist to resolve.
    let r = run_pw(root, PW, &["encrypt"]).expect_code(1);
    assert_contains(&r.stderr, "d/fake.bin");

    run_nopw(root, &["add", "--exclude", "--force", "d/fake.bin"]).expect_code(0);
    let r = run_pw(root, PW, &["encrypt"]).expect_code(0);
    assert_contains(&r.stdout, "encrypted d/real.txt");

    // `status` surfaces the probe hit as an `excluded` line (keyless,
    // it cannot tell foreign from stranded); excluded plaintext under
    // `d` would not be listed at all.
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "excluded", "d/fake.bin"));

    // decrypt leaves it untouched (noted, never a hard error that
    // would block the run).
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/real.txt");
    assert_contains(&r.stderr, "does not authenticate");
    assert_eq!(read_file(root, "d/fake.bin"), fake);

    // The gates pass over it: check is exempt, verify authenticates it
    // as foreign and ignores it.
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["check"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "ignored");

    // Key rotation converges past foreign content: it holds nothing of
    // this domain to strand.
    run_pw(root, PW, &["rekey"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert_eq!(read_file(root, "d/fake.bin"), fake);
}

#[test]
fn rekey_convergence_refuses_excluded_ciphertext() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // A fresh rekey proceeds but warns: the excluded ciphertext stays
    // on its old key.
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "hidden from migration");
    assert_eq!(wrapped_keys_of(root).len(), 2);

    // Convergence claims refuse it.
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "still holds valid ciphertext of this domain");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    assert_eq!(wrapped_keys_of(root).len(), 2);

    // Recover the file (explicitly named, still excluded), then the
    // rotation can finish and prune.
    let r = run_pw(root, PW, &["decrypt", "d/s.txt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    assert_contains(&r.stdout, "rotation complete");
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert_eq!(wrapped_keys_of(root).len(), 1);
    assert_eq!(read_file(root, "d/s.txt"), b"secret\n");
}

#[test]
fn exclude_probes_tolerate_hostile_names_in_hands_off_trees() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/real.txt", b"real\n");
    // A control-character name is valid UTF-8 and creatable everywhere;
    // the non-UTF-8 variant is Linux-only (APFS rejects such names at
    // creation time).
    write_file(root, "d/weird/evil\nname", b"plain");
    #[cfg(target_os = "linux")]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        fs::write(
            root.join("d/weird").join(OsStr::from_bytes(b"bad\xffname")),
            b"plain",
        )
        .unwrap();
    }
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);

    // Excluding a plaintext tree that contains hostile names — the
    // kind of content this feature exists to fence off — must work
    // without `--force`: the probe walks the candidate as if it were
    // already excluded, so the relaxed name rules apply.
    run_nopw(root, &["add", "--exclude", "d/weird"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // `remove` of the covering managed entry probes through the
    // excluded subtree without tripping the strict name rules: it is
    // refused for the real ciphertext, not for the hostile name…
    let r = run_nopw(root, &["remove", "d"]).expect_code(1);
    assert_contains(&r.stderr, "d/real.txt");
    assert_contains(&r.stderr, "decrypt it first");
    // …and succeeds normally once everything is plaintext, without
    // needing `remove --force` (which would skip that protection).
    run_pw(root, PW, &["decrypt"]).expect_code(0);
    run_nopw(root, &["remove", "d"]).expect_code(0);
}

/// Grows the file to one byte past the 256 MiB cap (sparse), leaving
/// its existing content as the prefix.
fn grow_past_cap(root: &Path, rel: &str) {
    let f = fs::OpenOptions::new()
        .append(true)
        .open(root.join(rel))
        .unwrap();
    f.set_len(256 * 1024 * 1024 + 1).unwrap();
}

#[test]
fn oversize_magic_bearing_junk_is_ambiguous_until_moved_out() {
    use std::io::Write as _;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/real.txt", b"real\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);

    // A sparse file over the 256 MiB cap that starts with the binary
    // magic but has an invalid header (version 0). No over-cap probe
    // hit is ever read as foreign: a prefix cannot disprove ownership
    // — damage can break a real ciphertext's header, or push its
    // surviving chunks past the window (an earlier version read a
    // broken header as decisively foreign, which let one flipped byte
    // hide an intact first chunk and unblock `rekey --prune`). The
    // junk blocks convergence until it is moved out of the tree.
    fs::create_dir_all(root.join("d")).unwrap();
    let mut f = fs::File::create(root.join("d/huge.bin")).unwrap();
    f.write_all(&BIN_MAGIC).unwrap();
    f.set_len(256 * 1024 * 1024 + 1).unwrap(); // version byte stays 0
    drop(f);
    run_nopw(root, &["add", "--exclude", "--force", "d/huge.bin"]).expect_code(0);

    run_pw(root, PW, &["encrypt"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/huge.bin");
    assert_contains(&r.stdout, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // Moving the junk out of the tree resolves it.
    fs::remove_file(root.join("d/huge.bin")).unwrap();
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn oversize_binary_with_damaged_header_and_intact_chunk_still_blocks() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/b.bin", &vec![0u8; 65536 + 100]); // two chunks
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/b.bin"]).expect_code(0);

    // Break only the header's version byte, keep every chunk intact,
    // and grow past the cap. The intact first chunk sits inside the
    // bounded window and authenticates regardless of the header
    // (chunk associated data does not involve it) — the header-blind
    // grid must prove ownership instead of guessing foreign.
    let original = read_file(root, "d/b.bin");
    let mut damaged = original.clone();
    damaged[8] = 0x02; // version 1 -> 2
    fs::write(root.join("d/b.bin"), &damaged).unwrap();
    grow_past_cap(root, "d/b.bin");

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/b.bin");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // The refusals kept the old key: the restored ciphertext recovers.
    fs::write(root.join("d/b.bin"), &original).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/b.bin (excluded; recovered)");
    assert_eq!(read_file(root, "d/b.bin"), vec![0u8; 65536 + 100]);
}

#[test]
fn oversize_ambiguous_binary_blocks_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // A single-chunk binary ciphertext (NUL content below one chunk).
    write_file(root, "d/tiny.bin", &[0u8, 1, 2, 3]);
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/tiny.bin"]).expect_code(0);

    // Grown past the cap, its single chunk's extent — and thus its
    // last-chunk AD — cannot be recovered from a prefix: ambiguous,
    // and convergence must not treat "cannot rule out ours" as
    // foreign (the previous behavior let `rekey --prune` drop the key
    // this ciphertext needs).
    let original = read_file(root, "d/tiny.bin");
    grow_past_cap(root, "d/tiny.bin");

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/tiny.bin");
    assert_contains(&r.stdout, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "cannot be conclusively classified");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stderr, "restore the original bytes");

    // Restoring the original bytes resolves the ambiguity.
    fs::write(root.join("d/tiny.bin"), &original).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/tiny.bin (excluded; recovered)");
    assert_eq!(read_file(root, "d/tiny.bin"), [0u8, 1, 2, 3]);
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn nested_repository_boundaries_block_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/vendor/s.txt", b"secret\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // The directory was encrypted first and became a repository
    // boundary afterwards: the walk can no longer see inside, so
    // convergence must refuse instead of letting `rekey --prune` drop
    // the key `d/vendor/s.txt` still needs.
    write_file(root, "d/vendor/.git", b"gitdir: elsewhere\n");

    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "boundary", "d/vendor"));
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "boundary d/vendor");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "not audited");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "nested repository `d/vendor`");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // `remove` of the covering entry is refused too: the probe cannot
    // see past the boundary, and removal would hide whatever it holds
    // from `rekey` — the exact bypass the refusal exists to close.
    let r = run_nopw(root, &["remove", "d"]).expect_code(1);
    assert_contains(&r.stderr, "cannot be probed");
    assert_contains(&r.stderr, "`remove --force`");

    // Removing the boundary lets decrypt reach the file again (the old
    // key is still in the ring because prune refused), after which the
    // rotation converges.
    fs::remove_file(root.join("d/vendor/.git")).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/vendor/s.txt");
    assert_eq!(read_file(root, "d/vendor/s.txt"), b"secret\n");
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn oversize_excluded_own_ciphertext_still_blocks_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // Two lines so the text ciphertext holds a complete first unit,
    // and a NUL-bearing file large enough for two binary chunks, so
    // the bounded first-chunk check has a full non-last chunk to
    // authenticate.
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/b.bin", &vec![0u8; 130 * 1024]);
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/b.bin"]).expect_code(0);

    // Valid ciphertext with data appended past the size cap: its first
    // unit still authenticates, so it is provably this domain's — the
    // audited fix for "over-cap is assumed foreign", which would have
    // let `rekey --prune` drop the key it needs. Both modes are
    // exercised: text (header + first unit line) and binary (header +
    // first full chunk).
    let original = read_file(root, "d/s.txt");
    let original_bin = read_file(root, "d/b.bin");
    grow_past_cap(root, "d/s.txt");
    grow_past_cap(root, "d/b.bin");

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "FAILED d/b.bin");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    // A fresh rekey warns and proceeds (an epoch can start with
    // pending content); the convergence claims refuse.
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "hidden from migration");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stderr, "exceeds the file-size cap");
    assert_contains(&r.stderr, "restore the original content");

    // Restoring the original bytes makes them recoverable again, and
    // the rotation can converge.
    fs::write(root.join("d/s.txt"), &original).unwrap();
    fs::write(root.join("d/b.bin"), &original_bin).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    assert_contains(&r.stdout, "decrypted d/b.bin (excluded; recovered)");
    assert_eq!(read_file(root, "d/s.txt"), b"secret one\nsecret two\n");
    assert_eq!(read_file(root, "d/b.bin"), vec![0u8; 130 * 1024]);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn damaged_excluded_ciphertext_is_reported_as_ours() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"one\ntwo\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // Damage the second unit: the first still authenticates, so the
    // content is provably this domain's — not foreign.
    let ct = String::from_utf8(read_file(root, "d/s.txt")).unwrap();
    let mut lines: Vec<String> = ct.lines().map(str::to_owned).collect();
    let c = lines[2].remove(0);
    lines[2].insert(0, if c == 'A' { 'B' } else { 'A' });
    fs::write(root.join("d/s.txt"), lines.join("\n") + "\n").unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");

    // decrypt leaves it untouched with a note that points at damage,
    // not at foreign content.
    let damaged = read_file(root, "d/s.txt");
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stderr, "damaged or mixing key epochs");
    assert_eq!(read_file(root, "d/s.txt"), damaged);
}

#[test]
fn destroyed_first_unit_excluded_ciphertext_still_blocks_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/b.bin", &vec![0u8; 65536 + 100]); // two binary chunks
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/b.bin"]).expect_code(0);

    // Destroy the *first* unit of each while later units survive. Full
    // decryption and first-unit authentication both fail, which the
    // audited gap classified as foreign — verify passed and `rekey
    // --prune` dropped the key the surviving units still need.
    let original = read_file(root, "d/s.txt");
    let original_bin = read_file(root, "d/b.bin");
    tamper_first_unit(root, "d/s.txt");
    let mut bin = original_bin.clone();
    bin[16 + 10] ^= 1; // inside chunk 0
    fs::write(root.join("d/b.bin"), &bin).unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "FAILED d/b.bin");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "hidden from migration");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // The refusals kept the old key in the ring: restoring the
    // original ciphertext recovers the plaintext.
    fs::write(root.join("d/s.txt"), &original).unwrap();
    fs::write(root.join("d/b.bin"), &original_bin).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    assert_contains(&r.stdout, "decrypted d/b.bin (excluded; recovered)");
    assert_eq!(read_file(root, "d/s.txt"), b"secret one\nsecret two\n");
    assert_eq!(read_file(root, "d/b.bin"), vec![0u8; 65536 + 100]);
}

#[test]
fn truncated_or_appended_excluded_binary_is_still_ours() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/trunc.bin", &vec![0u8; 3 * 65536]);
    write_file(root, "d/app.bin", &vec![0u8; 65536 + 100]);
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/trunc.bin"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/app.bin"]).expect_code(0);

    // Truncation into the middle of a chunk reparses self-consistently
    // with shifted boundaries; appending shifts the parsed extents the
    // same way. In both cases the intact leading chunks still sit on
    // the fixed grid and prove the content is this domain's.
    let ct = read_file(root, "d/trunc.bin");
    fs::write(root.join("d/trunc.bin"), &ct[..16 + 65552 + 7]).unwrap();
    let mut ct = read_file(root, "d/app.bin");
    ct.extend_from_slice(b"junk appended by another tool");
    fs::write(root.join("d/app.bin"), &ct).unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/trunc.bin");
    assert_contains(&r.stdout, "FAILED d/app.bin");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
}

#[test]
fn oversize_excluded_text_with_destroyed_first_unit_blocks_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // First unit destroyed *and* grown past the cap: the bounded scan
    // must still find the surviving second unit in the cap-sized
    // prefix instead of writing the file off as foreign.
    tamper_first_unit(root, "d/s.txt");
    grow_past_cap(root, "d/s.txt");

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
}

#[test]
fn unrecognized_header_with_surviving_units_is_still_ours() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // The header line is as damageable as any unit: a one-byte change
    // makes it probe as unrecognized, but the intact unit lines still
    // prove the content is this domain's.
    let ct = String::from_utf8(read_file(root, "d/s.txt")).unwrap();
    let bad = ct.replacen("v1 text\n", "v1 texz\n", 1);
    assert_ne!(ct, bad);
    fs::write(root.join("d/s.txt"), bad).unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // `decrypt` cannot repair a damaged header and reads no password
    // for a keyless note; it points at `verify` as the keyed arbiter
    // instead of guessing between ours-but-damaged and foreign.
    let r = run_nopw(root, &["decrypt", "d/s.txt"]).expect_code(0);
    assert_contains(&r.stderr, "run `verify`");
}

#[test]
fn surviving_unit_behind_a_line_flood_still_blocks_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // Insert 2^22 undecodable junk lines between the header and the
    // intact units. A line-count scan cutoff once stopped right here
    // and read the file as foreign — verify passed and `rekey --prune`
    // dropped the key the units past the flood still need.
    let ct = read_file(root, "d/s.txt");
    let header_end = ct.iter().position(|&b| b == b'\n').unwrap() + 1;
    let mut flooded = ct[..header_end].to_vec();
    flooded.extend(std::iter::repeat_n(&b"!\n"[..], 1 << 22).flatten());
    flooded.extend_from_slice(&ct[header_end..]);
    fs::write(root.join("d/s.txt"), &flooded).unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "a unit authenticates under ring entry");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "does not fully decrypt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // The refusals kept the old key: the restored ciphertext recovers.
    fs::write(root.join("d/s.txt"), &ct).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    assert_eq!(read_file(root, "d/s.txt"), b"secret one\nsecret two\n");
}

#[test]
fn oversize_excluded_text_with_prepended_flood_is_ambiguous() {
    use std::io::{Seek as _, SeekFrom, Write as _};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/s.txt", b"secret one\nsecret two\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/s.txt"]).expect_code(0);

    // Push the real units past the cap-sized prefix: header, then a
    // sparse NUL flood past the cap, then the original unit lines.
    // The prefix scan cannot see the units, and that absence must
    // read as ambiguous (blocking convergence) — not as foreign, the
    // classification that would let `rekey --prune` drop their key.
    let ct = read_file(root, "d/s.txt");
    let header_end = ct.iter().position(|&b| b == b'\n').unwrap() + 1;
    let f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(root.join("d/s.txt"))
        .unwrap();
    let mut f = f;
    f.write_all(&ct[..header_end]).unwrap();
    f.set_len(256 * 1024 * 1024 + 1).unwrap();
    f.seek(SeekFrom::End(0)).unwrap();
    f.write_all(b"\n").unwrap();
    f.write_all(&ct[header_end..]).unwrap();
    drop(f);

    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED d/s.txt");
    assert_contains(&r.stdout, "cannot be conclusively classified");
    run_pw(root, PW, &["rekey"]).expect_code(0); // mint, so prune has work
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // Restoring the original bytes resolves it.
    fs::write(root.join("d/s.txt"), &ct).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/s.txt (excluded; recovered)");
    assert_eq!(read_file(root, "d/s.txt"), b"secret one\nsecret two\n");
}

#[test]
fn exact_managed_directory_becoming_a_repository_is_a_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "vendor/s.txt", b"secret\n");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "vendor", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // The exact managed entry itself becomes a repository root. That
    // must be recorded like a boundary discovered inside a walk —
    // reported by the read-only scans and refused by the convergence
    // claims — not a hard error that aborts every audit-style command.
    write_file(root, "vendor/.git", b"gitdir: elsewhere\n");

    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "boundary", "vendor"));
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "boundary vendor");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "not audited");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "nested repository `vendor`");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");
    // `remove vendor` is stopped even earlier, by domain resolution:
    // an explicit argument that is itself a repository root resolves
    // to no domain. Clearing this state starts with moving the `.git`
    // entry aside, exactly as the convergence refusal advises.
    let r = run_nopw(root, &["remove", "vendor"]).expect_code(1);
    assert_contains(&r.stderr, "outside any simple-file-encrypt domain");

    // Removing the boundary lets everything converge again.
    fs::remove_file(root.join("vendor/.git")).unwrap();
    let r = run_pw(root, PW, &["decrypt", "vendor/s.txt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted vendor/s.txt");
    assert_eq!(read_file(root, "vendor/s.txt"), b"secret\n");
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn empty_marker_with_appended_data_stays_foreign() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/empty.txt", b"");
    write_file(root, "d/other.txt", b"other\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/empty.txt"]).expect_code(0);

    // A marker header with appended junk stays decisively foreign (the
    // documented residual): the marker line is the header line, no
    // unit line can vouch for the file, and the recoverable plaintext
    // is empty — so nothing blocks, and nothing is lost.
    let mut ct = read_file(root, "d/empty.txt");
    ct.extend_from_slice(b"QUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ\n");
    fs::write(root.join("d/empty.txt"), &ct).unwrap();

    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "ignored");
    run_pw(root, PW, &["rekey"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
}

#[test]
fn nested_repository_under_exclusion_is_hands_off() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/keep.txt", b"keep\n");
    write_file(root, "vault/s.txt", b"secret\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_nopw(root, &["add", "vault/s.txt"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["remove", "--force", "vault/s.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "vault"]).expect_code(0);

    // While the exclusion is walkable, the guards see the stranded
    // ciphertext.
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED vault/s.txt");
    run_pw(root, PW, &["rekey"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);

    // A `.git` entry turns the excluded tree into a nested repository:
    // hands-off by double declaration (exclusion + repository
    // boundary), silently invisible to every guard. This fixates the
    // documented residual of the threat model — the prune below
    // discards the key `vault/s.txt` still needs; decrypt before
    // excluding, deleting, or turning directories into repositories.
    write_file(root, "vault/.git", b"gitdir: elsewhere\n");
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert!(
        !r.stdout.contains("vault"),
        "excluded repo must be invisible:\n{}",
        r.stdout
    );
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);

    // Removing the boundary afterwards does not help: the key is gone,
    // and the stranded ciphertext now authenticates under nothing.
    fs::remove_file(root.join("vault/.git")).unwrap();
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert_contains(&r.stdout, "ignored");
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stderr, "does not authenticate");
    let left = read_file(root, "vault/s.txt");
    assert!(
        left.starts_with(TEXT_HEADER.as_bytes()),
        "still ciphertext, untouched"
    );
    assert_ne!(left, b"secret\n");
}

#[test]
fn decrypt_exempts_excluded_paths_from_require_encrypted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/enc.txt", b"enc\n");
    write_file(root, "d/note.md", b"plain notes\n");
    write_file(root, "d/odd.txt", b"#simple-file-encrypt v9 x\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "d/note.md"]).expect_code(0);
    // The unrecognized header probes as encrypted: --force required.
    run_nopw(root, &["add", "--exclude", "--force", "d/odd.txt"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // Excluded plaintext and unrecognized content are exempt from
    // --require-encrypted; the managed file still decrypts.
    let r = run_pw(root, PW, &["decrypt", "--require-encrypted"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/enc.txt");
    assert_contains(&r.stderr, "unrecognized `#simple-file-encrypt` header");
    assert_eq!(read_file(root, "d/note.md"), b"plain notes\n");
    assert_eq!(read_file(root, "d/odd.txt"), b"#simple-file-encrypt v9 x\n");

    // A domain whose only content is excluded non-recoverable material:
    // nothing to do, and no password is read (none is supplied).
    let tmp2 = tempfile::tempdir().unwrap();
    let root2 = tmp2.path();
    write_file(root2, "d2/odd.txt", b"#simple-file-encrypt v9 x\n");
    init_domain(root2);
    run_nopw(root2, &["add", "d2"]).expect_code(0);
    run_nopw(root2, &["add", "--exclude", "--force", "d2/odd.txt"]).expect_code(0);
    let r = run_nopw(root2, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "nothing to do");
}

#[test]
fn force_binary_normalization_and_dead_mark_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/inner.txt", b"inner\n");
    write_file(root, "zz.txt", b"zz\n");
    init_domain(root);

    // Marks are kept sorted in the rendered config regardless of the
    // order they were added in.
    run_nopw(root, &["add", "--binary", "zz.txt", "d/inner.txt"]).expect_code(0);
    let cfg = read_config(root);
    let start = cfg.find("force_binary = [").unwrap();
    let block = &cfg[start..start + cfg[start..].find(']').unwrap()];
    assert!(
        block.find("d/inner.txt").unwrap() < block.find("zz.txt").unwrap(),
        "{block}"
    );

    // A real directory mark collapses the marks it now covers; a mark
    // covered by it is reported, not duplicated; removing a covered
    // path names the covering mark.
    let r = run_nopw(root, &["add", "--binary", "d"]).expect_code(0);
    assert_contains(&r.stdout, "dropped the redundant force_binary entry");
    assert!(!read_config(root).contains("\"d/inner.txt\""));
    let r = run_nopw(root, &["add", "--binary", "d/inner.txt"]).expect_code(0);
    assert_contains(&r.stdout, "already covered by the force_binary entry `d`");
    let r = run_nopw(root, &["remove", "--binary", "d/inner.txt"]).expect_code(1);
    assert_contains(&r.stderr, "covered by the force_binary entry `d`");

    // A mark whose path names nothing on disk is silently ineffective:
    // `status` warns about it — but not about an exact managed entry,
    // whose absence already shows as a `missing … [binary]` line.
    run_nopw(root, &["add", "--binary", "ghost.csv"]).expect_code(0);
    run_nopw(root, &["remove", "ghost.csv"]).expect_code(0);
    run_nopw(root, &["add", "--binary", "ghost2.csv"]).expect_code(0);
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert_contains(
        &r.stderr,
        "force_binary entry `ghost.csv` matches nothing on disk",
    );
    assert!(!r.stderr.contains("ghost2.csv"), "{}", r.stderr);
    assert!(status_line(&r.stdout, "missing", "ghost2.csv"));

    // Once the path exists the warning disappears.
    write_file(root, "ghost.csv", b"now here\n");
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(!r.stderr.contains("matches nothing"), "{}", r.stderr);
}

#[test]
fn independent_exclusions_are_audited() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "orphan.txt", b"secret\n");
    write_file(root, "d/managed.txt", b"managed\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);

    // The audited gap: encrypt a file, force-remove its entry, then
    // force-exclude it — an exclusion no managed entry covers, which
    // the expansion previously never walked.
    run_pw(root, PW, &["encrypt", "orphan.txt"]).expect_code(0);
    run_nopw(root, &["remove", "--force", "orphan.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "orphan.txt"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);

    // Every audit surface sees the independent exclusion.
    let r = run_nopw(root, &["status"]).expect_code(0);
    assert!(status_line(&r.stdout, "excluded", "orphan.txt"));
    let r = run_pw(root, PW, &["verify"]).expect_code(1);
    assert_contains(&r.stdout, "FAILED orphan.txt");
    let r = run_pw(root, PW, &["rekey"]).expect_code(0);
    assert_contains(&r.stderr, "hidden from migration");
    let r = run_pw(root, PW, &["rekey", "--continue"]).expect_code(1);
    assert_contains(&r.stderr, "orphan.txt");
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(1);
    assert_contains(&r.stderr, "cannot prune");

    // The argument-less decrypt is the repair channel here too.
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted orphan.txt (excluded; recovered)");
    assert_eq!(read_file(root, "orphan.txt"), b"secret\n");
    run_pw(root, PW, &["rekey", "--continue"]).expect_code(0);
    run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    run_pw(root, PW, &["verify"]).expect_code(0);

    // A pre-declared exclusion for a nonexistent path stays silent:
    // no bogus "missing managed path" warnings from the audit roots,
    // and no refusal anywhere.
    run_nopw(root, &["add", "--exclude", "ghost.txt"]).expect_code(0);
    let r = run_pw(root, PW, &["verify"]).expect_code(0);
    assert!(!r.stdout.contains("ghost.txt"), "{}", r.stdout);
    assert!(!r.stderr.contains("ghost.txt"), "{}", r.stderr);
    let r = run_pw(root, PW, &["rekey", "--prune"]).expect_code(0);
    assert!(!r.stderr.contains("ghost.txt"), "{}", r.stderr);

    // A pre-declared exclusion whose ancestor later becomes a regular
    // file is silently unreachable — not an error that would brick
    // every scan while `remove --exclude` cannot mint the path either.
    run_nopw(root, &["add", "--exclude", "future/cache.bin"]).expect_code(0);
    write_file(root, "future", b"now a file\n");
    run_nopw(root, &["status"]).expect_code(0);
    run_pw(root, PW, &["verify"]).expect_code(0);
}

#[test]
fn excluded_recovery_reports_serial_failures() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_file(root, "d/a.txt", b"aaa\n");
    write_file(root, "d/b.txt", b"bbb\n");
    init_domain(root);
    run_nopw(root, &["add", "d"]).expect_code(0);
    run_pw(root, PW, &["encrypt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/a.txt"]).expect_code(0);
    run_nopw(root, &["add", "--exclude", "--force", "d/b.txt"]).expect_code(0);

    // A read-only directory makes the first recovery replacement fail:
    // the repair pass reports completed / failed / not attempted like
    // the main pass instead of aborting without a summary.
    fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o555)).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(1);
    assert_contains(&r.stderr, "failed:\n  d/a.txt");
    assert_contains(&r.stderr, "not attempted (1):\n  d/b.txt");

    fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o755)).unwrap();
    let r = run_pw(root, PW, &["decrypt"]).expect_code(0);
    assert_contains(&r.stdout, "decrypted d/a.txt (excluded; recovered)");
    assert_contains(&r.stdout, "decrypted d/b.txt (excluded; recovered)");
    assert_eq!(read_file(root, "d/a.txt"), b"aaa\n");
    assert_eq!(read_file(root, "d/b.txt"), b"bbb\n");
}
