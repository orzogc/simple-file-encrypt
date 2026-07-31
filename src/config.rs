//! The domain config `.simple-encrypt.toml`: strict loading and
//! validation, and the stable rendered form the tool writes
//! (see `docs/format.md`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::consts::*;
use crate::crypto::{KdfParams, validate_kdf_structural};
use crate::error::{Error, Result};
use crate::fsops::{self, Snapshot};
use crate::{hexutil, paths};

/// Raw config schema; unknown keys anywhere are rejected.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    version: u64,
    salt: String,
    wrapped_keys: Vec<String>,
    kdf: RawKdf,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    force_binary: Vec<String>,
}

/// Raw `[kdf]` table.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKdf {
    algorithm: String,
    memory_kib: u64,
    iterations: u64,
    parallelism: u64,
}

/// A validated domain config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// KDF salt.
    pub salt: [u8; SALT_LEN],
    /// Wrapped key ring, newest first (entry 0 = current).
    pub wrapped_keys: Vec<[u8; WRAPPED_KEY_LEN]>,
    /// Validated Argon2id parameters.
    pub kdf: KdfParams,
    /// Managed paths: canonical relative paths, kept sorted and deduplicated.
    pub paths: Vec<String>,
    /// Binary-mode overrides, hand-maintained or appended by
    /// `add --binary` / `remove --binary`; the loaded order is
    /// preserved verbatim on rewrite (the tool only appends/removes).
    pub force_binary: Vec<String>,
}

impl Config {
    /// Whether binary mode is forced for this canonical relative path
    /// (an exact entry or a covering directory entry).
    pub fn is_force_binary(&self, rel: &str) -> bool {
        self.force_binary
            .iter()
            .any(|e| paths::is_covered_by(rel, e))
    }

    /// Whether the exact entry is in the managed list.
    pub fn is_managed(&self, rel: &str) -> bool {
        self.paths.binary_search_by(|e| e.as_str().cmp(rel)).is_ok()
    }
}

/// A config loaded from disk, with the snapshot used to detect
/// concurrent modification when rewriting.
pub struct LoadedConfig {
    /// The domain root directory (owner of the config).
    pub root: PathBuf,
    /// The validated config.
    pub config: Config,
    /// Snapshot of the config file at load time.
    snap: Snapshot,
}

/// Validates a `paths` / `force_binary` entry at load time.
fn validate_entry(kind: &str, entry: &str) -> Result<()> {
    // The entry is hostile-input content; escape it in messages.
    let shown = crate::report::escape_str(entry);
    if let Err(reason) = paths::validate_canonical(entry) {
        return Err(Error::Config(format!(
            "`{kind}` entry `{shown}` is not a canonical relative path: {reason}"
        )));
    }
    if let Some(reason) = paths::forbidden_reason(entry) {
        return Err(Error::Config(format!(
            "`{kind}` entry `{shown}` is not allowed: {reason}"
        )));
    }
    Ok(())
}

/// Parses and validates config file content.
pub fn parse(content: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(content)
        .map_err(|_| Error::Config("config file is not valid UTF-8".into()))?;

    // Check the version first, leniently, so a config from a newer tool
    // yields "upgrade" instead of "unknown field". The parser's
    // diagnostics quote the (hostile) input; sanitize them.
    let value: toml::Value = toml::from_str(text).map_err(|e| {
        Error::Config(format!(
            "invalid TOML: {}",
            crate::report::escape_opaque(&e.to_string())
        ))
    })?;
    match value.get("version") {
        None => return Err(Error::Config("missing `version`".into())),
        Some(toml::Value::Integer(v)) => {
            if u64::try_from(*v) != Ok(FORMAT_VERSION) {
                if *v > FORMAT_VERSION as i64 {
                    return Err(Error::NewerVersion(format!("config version {v}")));
                }
                return Err(Error::Config(format!("unsupported config version {v}")));
            }
        }
        Some(_) => return Err(Error::Config("`version` must be an integer".into())),
    }

    let raw: RawConfig = toml::from_str(text)
        .map_err(|e| Error::Config(crate::report::escape_opaque(&e.to_string()).into_owned()))?;
    debug_assert_eq!(
        raw.version, FORMAT_VERSION,
        "version was checked in the lenient pass"
    );

    let salt_bytes = hexutil::decode(&raw.salt)
        .filter(|b| b.len() == SALT_LEN)
        .ok_or_else(|| {
            Error::Config(format!(
                "`salt` must be exactly {} lowercase hex characters",
                SALT_LEN * 2
            ))
        })?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().expect("length checked");

    if raw.wrapped_keys.is_empty() || raw.wrapped_keys.len() > MAX_RING_LEN {
        return Err(Error::Config(format!(
            "`wrapped_keys` must have 1 to {MAX_RING_LEN} entries"
        )));
    }
    let mut wrapped_keys = Vec::with_capacity(raw.wrapped_keys.len());
    for entry in &raw.wrapped_keys {
        let bytes = hexutil::decode(entry)
            .filter(|b| b.len() == WRAPPED_KEY_LEN)
            .ok_or_else(|| {
                Error::Config(format!(
                    "each `wrapped_keys` entry must be exactly {} lowercase hex characters",
                    WRAPPED_KEY_LEN * 2
                ))
            })?;
        wrapped_keys
            .push(<[u8; WRAPPED_KEY_LEN]>::try_from(bytes.as_slice()).expect("length checked"));
    }

    if raw.kdf.algorithm != "argon2id" {
        return Err(Error::Config(format!(
            "unsupported KDF algorithm `{}` (expected `argon2id`)",
            raw.kdf.algorithm
        )));
    }
    let kdf = validate_kdf_structural(raw.kdf.memory_kib, raw.kdf.iterations, raw.kdf.parallelism)?;

    if raw.paths.len().saturating_add(raw.force_binary.len()) > MAX_CONFIG_ENTRIES {
        return Err(Error::Config(format!(
            "`paths` plus `force_binary` exceed {MAX_CONFIG_ENTRIES} entries"
        )));
    }
    for entry in &raw.paths {
        validate_entry("paths", entry)?;
    }
    for entry in &raw.force_binary {
        validate_entry("force_binary", entry)?;
    }
    let mut managed = raw.paths;
    managed.sort_unstable();
    managed.dedup();

    Ok(Config {
        salt,
        wrapped_keys,
        kdf,
        paths: managed,
        force_binary: raw.force_binary,
    })
}

/// Loads and validates the domain config of `root`.
pub fn load(root: &Path) -> Result<LoadedConfig> {
    let path = root.join(CONFIG_NAME);
    let data = fsops::read_capped(&path, MAX_CONFIG_SIZE, "config file")?;
    let config = parse(&data.content)?;
    Ok(LoadedConfig {
        root: root.to_path_buf(),
        config,
        snap: data.snap,
    })
}

/// Escapes a string as a TOML basic string.
fn toml_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\u{7F}' => {
                out.push_str(&format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Renders a string-array field, one entry per line.
fn render_list(out: &mut String, name: &str, entries: &[String]) {
    if entries.is_empty() {
        out.push_str(name);
        out.push_str(" = []\n");
        return;
    }
    out.push_str(name);
    out.push_str(" = [\n");
    for e in entries {
        out.push_str("    ");
        out.push_str(&toml_quote(e));
        out.push_str(",\n");
    }
    out.push_str("]\n");
}

/// Renders the config in the tool's stable form. `paths` is written in
/// ascending byte order, deduplicated; `force_binary` verbatim. The
/// `[kdf]` table comes last so every other key stays top-level.
pub fn render(cfg: &Config) -> String {
    let mut paths_sorted = cfg.paths.clone();
    paths_sorted.sort_unstable();
    paths_sorted.dedup();

    let mut out = String::with_capacity(1024);
    out.push_str(
        "# Managed by simple-encrypt. `salt`, `wrapped_keys`, and [kdf] are\n\
         # security-critical: do not edit them by hand.\n",
    );
    out.push_str(&format!("version = {FORMAT_VERSION}\n\n"));
    out.push_str("# 16 random bytes, lowercase hex.\n");
    out.push_str(&format!("salt = \"{}\"\n\n", hexutil::encode(&cfg.salt)));
    out.push_str(
        "# Key ring: AES-SIV(kek, domain_key), 48 bytes (96 hex chars) each,\n\
         # newest first — entry 0 is the current key. Older entries keep\n\
         # pre-`rekey` ciphertext decryptable until `rekey --prune`.\n",
    );
    let wrapped: Vec<String> = cfg
        .wrapped_keys
        .iter()
        .map(|w| hexutil::encode(w))
        .collect();
    render_list(&mut out, "wrapped_keys", &wrapped);
    out.push('\n');
    out.push_str(
        "# Managed paths: files and directories (recursive), canonical relative\n\
         # paths (no trailing slash; directory-ness is resolved at run time).\n\
         # Maintained by the tool: ascending byte order, deduplicated.\n",
    );
    render_list(&mut out, "paths", &paths_sorted);
    out.push('\n');
    out.push_str(
        "# Maintained by hand or by `add --binary` / `remove --binary`: paths\n\
         # (files or directories) always encrypted in binary (whole-file) mode,\n\
         # even if their content looks like text. The tool only appends/removes.\n",
    );
    render_list(&mut out, "force_binary", &cfg.force_binary);
    out.push('\n');
    out.push_str("[kdf]\nalgorithm = \"argon2id\"\n");
    out.push_str(&format!(
        "memory_kib = {}\niterations = {}\nparallelism = {}\n",
        cfg.kdf.memory_kib, cfg.kdf.iterations, cfg.kdf.parallelism
    ));
    out
}

/// Renders a config for writing, refusing to produce one that `load`
/// would reject: the write side enforces the entry-count and file-size
/// caps too, so the tool can never brick its own domain.
fn render_checked(cfg: &Config) -> Result<String> {
    if cfg.paths.len().saturating_add(cfg.force_binary.len()) > MAX_CONFIG_ENTRIES {
        return Err(Error::Limit(format!(
            "the config would hold more than {MAX_CONFIG_ENTRIES} `paths` plus `force_binary` entries"
        )));
    }
    let rendered = render(cfg);
    if rendered.len() as u64 > MAX_CONFIG_SIZE {
        return Err(Error::Limit(format!(
            "the config would be {} bytes, exceeding the {MAX_CONFIG_SIZE}-byte cap",
            rendered.len()
        )));
    }
    debug_assert!(
        parse(rendered.as_bytes()).is_ok(),
        "rendered config must reparse"
    );
    Ok(rendered)
}

/// Creates the config exclusively (`init`); fails if it already exists.
pub fn create_new(root: &Path, cfg: &Config) -> Result<()> {
    let rendered = render_checked(cfg)?;
    fsops::create_exclusive(&root.join(CONFIG_NAME), rendered.as_bytes(), 0o644)
}

impl LoadedConfig {
    /// Atomically rewrites the config with the current in-memory state,
    /// refusing if the file changed since it was loaded or if the result
    /// would violate a load-time cap.
    ///
    /// The rename is the commit point, but durability matters here: a
    /// crash that rolls the config rename back while already-migrated
    /// files persist would strand ciphertext no on-disk config can
    /// decrypt. When durability (or the read-back) is unconfirmed, the
    /// rewrite reports failure so dependent work stops — the new config
    /// is nonetheless visible, and re-running resumes from it.
    pub fn rewrite(&mut self) -> Result<()> {
        let rendered = render_checked(&self.config)?;
        let path = self.root.join(CONFIG_NAME);
        let replaced = fsops::atomic_replace(&path, &self.snap, rendered.as_bytes())?;
        if !replaced.durable || replaced.snap.is_none() {
            return Err(Error::Usage(format!(
                "the config `{}` was replaced, but its post-commit state could not be confirmed \
                 (see the warnings above); nothing that depends on the new config was written — \
                 re-run the command to resume from the visible config",
                crate::report::escape_path(&path)
            )));
        }
        self.snap = replaced.snap.expect("checked above");
        self.config.paths.sort_unstable();
        self.config.paths.dedup();
        Ok(())
    }

    /// Errors when the config file on disk no longer matches the
    /// snapshot taken at load (or the last rewrite): another program
    /// replaced it mid-operation, so ciphertext written under the
    /// in-memory ring might be undecryptable by the on-disk config. The
    /// advisory lock excludes other simple-encrypt instances, not git
    /// or editors; a race inside the stat window remains (accepted, see
    /// `docs/threat-model.md`).
    pub fn ensure_fresh(&self) -> Result<()> {
        let path = self.root.join(CONFIG_NAME);
        let md =
            std::fs::symlink_metadata(&path).map_err(|e| Error::io("re-checking", &path, e))?;
        if !self.snap.matches(&Snapshot::of(&md)) {
            return Err(Error::Usage(format!(
                "`{}` changed on disk since it was loaded (another program rewrote it); \
                 refusing to write ciphertext the on-disk config might not decrypt — re-run the command",
                crate::report::escape_path(&path)
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Config {
        Config {
            salt: [0xab; SALT_LEN],
            wrapped_keys: vec![[0x11; WRAPPED_KEY_LEN], [0x22; WRAPPED_KEY_LEN]],
            kdf: KdfParams::DEFAULT,
            paths: vec!["b.txt".into(), "a dir/©.txt".into()],
            force_binary: vec!["zz".into(), "blob.bin".into()],
        }
    }

    #[test]
    fn render_parse_round_trip() {
        let cfg = sample();
        let parsed = parse(render(&cfg).as_bytes()).unwrap();
        assert_eq!(parsed.salt, cfg.salt);
        assert_eq!(parsed.wrapped_keys, cfg.wrapped_keys);
        assert_eq!(parsed.kdf, cfg.kdf);
        assert_eq!(
            parsed.paths,
            vec!["a dir/©.txt".to_string(), "b.txt".to_string()]
        );
        // force_binary preserved verbatim, order included.
        assert_eq!(parsed.force_binary, cfg.force_binary);
    }

    #[test]
    fn strict_load_failures() {
        let good = render(&sample());
        // Unknown key.
        let bad = format!("{good}\nunknown_key = 1\n");
        assert!(parse(bad.as_bytes()).is_err());
        // Newer version.
        let bad = good.replace("version = 1", "version = 2");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::NewerVersion(_))));
        // Uppercase hex salt.
        let bad = good.replace(&hexutil::encode(&[0xab; SALT_LEN]), &"AB".repeat(SALT_LEN));
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Wrong algorithm.
        let bad = good.replace("argon2id", "argon2i");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Empty ring.
        let mut cfg = sample();
        cfg.wrapped_keys.clear();
        assert!(parse(render(&cfg).as_bytes()).is_err());
        // Non-canonical path entry.
        let bad = good.replace("\"b.txt\"", "\"b/../b.txt\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Forbidden entry.
        let bad = good.replace("\"b.txt\"", "\".gitattributes\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        let bad = good.replace("\"blob.bin\"", "\".git/x\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Trailing slash.
        let bad = good.replace("\"b.txt\"", "\"b/\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Negative KDF integer.
        let bad = good.replace("iterations = 3", "iterations = -1");
        assert!(parse(bad.as_bytes()).is_err());
    }

    #[test]
    fn write_side_enforces_load_time_caps() {
        // The tool must never write a config it would refuse to load.
        let dir = tempfile::tempdir().unwrap();

        // Entry-count cap.
        let mut cfg = sample();
        cfg.force_binary.clear();
        cfg.paths = (0..=MAX_CONFIG_ENTRIES).map(|i| format!("f{i}")).collect();
        assert!(matches!(create_new(dir.path(), &cfg), Err(Error::Limit(_))));

        // Rendered-size cap: a few hundred deep paths cross 1 MiB while
        // staying far below the entry-count cap.
        let mut cfg = sample();
        cfg.paths = (0..300)
            .map(|i| format!("{}/{i}", "d/".repeat(2040).trim_end_matches('/')))
            .collect();
        assert!(matches!(create_new(dir.path(), &cfg), Err(Error::Limit(_))));

        // A reasonable config still writes and reloads.
        let cfg = sample();
        create_new(dir.path(), &cfg).unwrap();
        assert!(load(dir.path()).is_ok());
    }

    #[test]
    fn rewrite_aborts_when_durability_is_unconfirmed() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = sample();
        create_new(dir.path(), &cfg).unwrap();
        let mut loaded = load(dir.path()).unwrap();
        loaded.config.paths.push("x.txt".into());

        fsops::set_injected_sync_failure(true);
        let err = loaded.rewrite().unwrap_err();
        fsops::set_injected_sync_failure(false);

        // The caller must stop, but the new config is nonetheless
        // visible on disk: a retry resumes from it.
        assert!(err.to_string().contains("re-run"), "got: {err}");
        let reloaded = load(dir.path()).unwrap();
        assert!(reloaded.config.paths.contains(&"x.txt".to_owned()));
    }

    #[test]
    fn ensure_fresh_detects_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = sample();
        create_new(dir.path(), &cfg).unwrap();
        let loaded = load(dir.path()).unwrap();
        assert!(loaded.ensure_fresh().is_ok());
        // In-place modification: mtime changes.
        std::fs::write(dir.path().join(CONFIG_NAME), render(&cfg)).unwrap();
        assert!(loaded.ensure_fresh().is_err());
        // Same-content replacement via rename: the inode changes.
        let loaded = load(dir.path()).unwrap();
        let tmp = dir.path().join("staging.tmp");
        std::fs::write(&tmp, render(&cfg)).unwrap();
        std::fs::rename(&tmp, dir.path().join(CONFIG_NAME)).unwrap();
        assert!(loaded.ensure_fresh().is_err());
    }

    #[test]
    fn version_check_precedes_unknown_fields() {
        // A v2 config with unknown fields must say "newer", not "unknown".
        let text = "version = 2\nfuture_field = true\n";
        assert!(matches!(
            parse(text.as_bytes()),
            Err(Error::NewerVersion(_))
        ));
    }
}
