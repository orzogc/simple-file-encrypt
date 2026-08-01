//! The domain config `.simple-file-encrypt.toml`: strict loading and
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
    #[serde(default)]
    excludes: Vec<String>,
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
    /// Binary-mode overrides, maintained by `add --binary` /
    /// `remove --binary`: paths (files or directories) always encrypted
    /// in binary mode; kept sorted and deduplicated (order never had a
    /// semantic effect — coverage is an any-match).
    pub force_binary: Vec<String>,
    /// Excluded paths: canonical relative paths (files or directories,
    /// recursive) never selected for encryption; kept sorted and
    /// deduplicated. An entry that equals or covers an exact `paths`
    /// entry is a load-time error (a fully shadowed managed entry is a
    /// contradiction); an entry strictly below a managed directory
    /// entry is the intended use.
    pub excludes: Vec<String>,
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

    /// Returns the `excludes` entry covering this canonical relative
    /// path (an exact entry or a covering directory entry), if any.
    pub fn covering_exclude(&self, rel: &str) -> Option<&str> {
        self.excludes
            .iter()
            .find(|e| paths::is_covered_by(rel, e))
            .map(String::as_str)
    }
}

/// Returns a managed `paths` entry that `exclude` equals or covers, if
/// any. `paths_sorted` must be in ascending byte order: entries covered
/// by `exclude` are `exclude` itself and the contiguous run prefixed by
/// `exclude` + `/`, so two binary searches replace a full scan.
fn find_shadowed_entry<'a>(paths_sorted: &'a [String], exclude: &str) -> Option<&'a str> {
    if let Ok(i) = paths_sorted.binary_search_by(|p| p.as_str().cmp(exclude)) {
        return Some(&paths_sorted[i]);
    }
    let prefix = format!("{exclude}/");
    let i = paths_sorted.partition_point(|p| p.as_str() < prefix.as_str());
    (i < paths_sorted.len() && paths_sorted[i].starts_with(&prefix))
        .then(|| paths_sorted[i].as_str())
}

/// Rejects a config whose `excludes` fully shadow a managed entry: such
/// an entry could never be selected, which is a contradiction, and —
/// worse — hand-editing one in could strand still-encrypted content
/// outside `rekey`'s reach. Both lists must be sorted.
fn check_exclude_contradictions(paths_sorted: &[String], excludes_sorted: &[String]) -> Result<()> {
    for exclude in excludes_sorted {
        if let Some(shadowed) = find_shadowed_entry(paths_sorted, exclude) {
            return Err(Error::Config(format!(
                "`excludes` entry `{}` {} the managed `paths` entry `{}`; a fully shadowed managed \
                 entry is a contradiction — `remove` the managed entry or `remove --exclude` the \
                 exclusion",
                crate::report::escape_str(exclude),
                if shadowed == exclude {
                    "equals"
                } else {
                    "covers"
                },
                crate::report::escape_str(shadowed),
            )));
        }
    }
    Ok(())
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
        // The value is hostile-input content; escape it in the message.
        return Err(Error::Config(format!(
            "unsupported KDF algorithm `{}` (expected `argon2id`)",
            crate::report::escape_str(&raw.kdf.algorithm)
        )));
    }
    let kdf = validate_kdf_structural(raw.kdf.memory_kib, raw.kdf.iterations, raw.kdf.parallelism)?;

    if raw
        .paths
        .len()
        .saturating_add(raw.force_binary.len())
        .saturating_add(raw.excludes.len())
        > MAX_CONFIG_ENTRIES
    {
        return Err(Error::Config(format!(
            "`paths`, `force_binary`, and `excludes` together exceed {MAX_CONFIG_ENTRIES} entries"
        )));
    }
    for entry in &raw.paths {
        validate_entry("paths", entry)?;
    }
    for entry in &raw.force_binary {
        validate_entry("force_binary", entry)?;
    }
    for entry in &raw.excludes {
        validate_entry("excludes", entry)?;
    }
    let mut managed = raw.paths;
    managed.sort_unstable();
    managed.dedup();
    let mut force_binary = raw.force_binary;
    force_binary.sort_unstable();
    force_binary.dedup();
    let mut excludes = raw.excludes;
    excludes.sort_unstable();
    excludes.dedup();
    check_exclude_contradictions(&managed, &excludes)?;

    Ok(Config {
        salt,
        wrapped_keys,
        kdf,
        paths: managed,
        force_binary,
        excludes,
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

/// Renders the config in the tool's stable form. All three path lists
/// are written in ascending byte order, deduplicated (`excludes` only
/// when non-empty, so configs not using the feature stay loadable by
/// older versions). The `[kdf]` table comes last so every other key
/// stays top-level.
pub fn render(cfg: &Config) -> String {
    let mut paths_sorted = cfg.paths.clone();
    paths_sorted.sort_unstable();
    paths_sorted.dedup();
    let mut force_binary_sorted = cfg.force_binary.clone();
    force_binary_sorted.sort_unstable();
    force_binary_sorted.dedup();
    let mut excludes_sorted = cfg.excludes.clone();
    excludes_sorted.sort_unstable();
    excludes_sorted.dedup();

    let mut out = String::with_capacity(1024);
    out.push_str(
        "# Managed by simple-file-encrypt. `salt`, `wrapped_keys`, and [kdf] are\n\
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
    if !excludes_sorted.is_empty() {
        out.push_str(
            "# Excluded paths: files and directories (recursive) never selected for\n\
             # encryption, even under a managed directory. Maintained by the tool:\n\
             # ascending byte order, deduplicated. Older versions of\n\
             # simple-file-encrypt refuse a config that carries this key.\n",
        );
        render_list(&mut out, "excludes", &excludes_sorted);
        out.push('\n');
    }
    out.push_str(
        "# Maintained by `add --binary` / `remove --binary`: paths (files or\n\
         # directories) always encrypted in binary (whole-file) mode, even if\n\
         # their content looks like text. Ascending byte order, deduplicated.\n",
    );
    render_list(&mut out, "force_binary", &force_binary_sorted);
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
    if cfg
        .paths
        .len()
        .saturating_add(cfg.force_binary.len())
        .saturating_add(cfg.excludes.len())
        > MAX_CONFIG_ENTRIES
    {
        return Err(Error::Limit(format!(
            "the config would hold more than {MAX_CONFIG_ENTRIES} `paths`, `force_binary`, and \
             `excludes` entries"
        )));
    }
    // The write side enforces the shadowing rule too: the tool must
    // never produce a config that `load` would reject.
    let mut paths_sorted = cfg.paths.clone();
    paths_sorted.sort_unstable();
    paths_sorted.dedup();
    let mut excludes_sorted = cfg.excludes.clone();
    excludes_sorted.sort_unstable();
    excludes_sorted.dedup();
    check_exclude_contradictions(&paths_sorted, &excludes_sorted)?;
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
        self.config.force_binary.sort_unstable();
        self.config.force_binary.dedup();
        self.config.excludes.sort_unstable();
        self.config.excludes.dedup();
        Ok(())
    }

    /// Errors when the config file on disk no longer matches the
    /// snapshot taken at load (or the last rewrite): another program
    /// replaced it mid-operation, so ciphertext written under the
    /// in-memory ring might be undecryptable by the on-disk config. The
    /// advisory lock excludes other simple-file-encrypt instances, not git
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
            excludes: Vec::new(),
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
        // force_binary is normalized like the other lists: ascending
        // byte order, deduplicated (order never had a semantic effect).
        assert_eq!(
            parsed.force_binary,
            vec!["blob.bin".to_string(), "zz".to_string()]
        );
        let mut cfg = sample();
        cfg.force_binary.push("zz".into());
        let parsed = parse(render(&cfg).as_bytes()).unwrap();
        assert_eq!(
            parsed.force_binary,
            vec!["blob.bin".to_string(), "zz".to_string()]
        );
    }

    #[test]
    fn excludes_round_trip_and_omission_when_empty() {
        // Without excludes the key is absent, so configs not using the
        // feature stay loadable by older tool versions.
        assert!(!render(&sample()).contains("excludes"));

        let mut cfg = sample();
        cfg.paths = vec!["secrets".into()];
        cfg.excludes = vec![
            "secrets/readme.md".into(),
            "other/skip".into(),
            "secrets/readme.md".into(), // duplicate: dropped on render
        ];
        let rendered = render(&cfg);
        assert!(rendered.contains("excludes = ["));
        let parsed = parse(rendered.as_bytes()).unwrap();
        assert_eq!(
            parsed.excludes,
            vec!["other/skip".to_string(), "secrets/readme.md".to_string()]
        );
        // Coverage lookup finds exact and directory entries.
        assert_eq!(parsed.covering_exclude("other/skip/x"), Some("other/skip"));
        assert_eq!(
            parsed.covering_exclude("secrets/readme.md"),
            Some("secrets/readme.md")
        );
        assert_eq!(parsed.covering_exclude("secrets/token"), None);
        assert_eq!(parsed.covering_exclude(""), None);
    }

    #[test]
    fn excludes_entries_are_validated_like_paths() {
        let mut cfg = sample();
        cfg.excludes = vec!["ok.txt".into()];
        let good = render(&cfg);
        // Non-canonical entry.
        let bad = good.replace("\"ok.txt\"", "\"a/../ok.txt\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        // Forbidden entry: git- and tool-critical names are never
        // encrypted anyway, so claiming them is refused as misleading.
        let bad = good.replace("\"ok.txt\"", "\".gitattributes\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
        let bad = good.replace("\"ok.txt\"", "\".git/x\"");
        assert!(matches!(parse(bad.as_bytes()), Err(Error::Config(_))));
    }

    #[test]
    fn shadowed_managed_entries_are_contradictions() {
        // An exclude equal to an exact managed entry: load-time error.
        let mut cfg = sample();
        cfg.excludes = vec!["b.txt".into()];
        let err = parse(render(&cfg).as_bytes()).unwrap_err();
        assert!(err.to_string().contains("contradiction"), "got: {err}");

        // An exclude covering an exact managed entry: same error.
        let mut cfg = sample();
        cfg.excludes = vec!["a dir".into()];
        let err = parse(render(&cfg).as_bytes()).unwrap_err();
        assert!(err.to_string().contains("covers"), "got: {err}");

        // The write side refuses the same shape, so the tool can never
        // brick its own domain.
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = sample();
        cfg.excludes = vec!["b.txt".into()];
        assert!(create_new(dir.path(), &cfg).is_err());

        // An exclude strictly below a managed directory entry is the
        // intended use; a shadowed `force_binary` entry is a dormant
        // preference (it applies again once the exclusion is removed).
        let mut cfg = sample();
        cfg.paths = vec!["secrets".into()];
        cfg.excludes = vec!["secrets/readme.md".into(), "zz".into()];
        assert!(parse(render(&cfg).as_bytes()).is_ok());

        // Sibling with a common prefix is not coverage (`ab` vs `a`).
        let mut cfg = sample();
        cfg.paths = vec!["ab".into()];
        cfg.excludes = vec!["a".into()];
        assert!(parse(render(&cfg).as_bytes()).is_ok());
    }

    #[test]
    fn entry_cap_counts_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = sample();
        cfg.paths.clear();
        cfg.force_binary.clear();
        cfg.excludes = (0..=MAX_CONFIG_ENTRIES).map(|i| format!("e{i}")).collect();
        assert!(matches!(create_new(dir.path(), &cfg), Err(Error::Limit(_))));
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
    fn hostile_kdf_algorithm_is_escaped_in_errors() {
        let good = render(&sample());
        // A raw ESC (0x1B) is not legal inside a TOML basic string, so
        // this exercises the *parser diagnostics* path: the parser
        // quotes the hostile input and the message must be sanitized.
        let bad = good.replace("argon2id", "\u{1b}[31mPWN\u{1b}[0m");
        let err = parse(bad.as_bytes()).unwrap_err();
        let shown = err.to_string();
        assert!(shown.contains("invalid TOML"), "wrong branch: {shown}");
        assert!(!shown.contains('\u{1b}'), "raw escape byte in: {shown}");

        // The same payload smuggled through legal TOML `\uXXXX` escapes
        // parses fine and must reach the algorithm check itself, whose
        // message quotes the (decoded, hostile) value escaped.
        let bad = good.replace("argon2id", "\\u001B[31mPWN\\u001B[0m");
        let err = parse(bad.as_bytes()).unwrap_err();
        let shown = err.to_string();
        assert!(
            shown.contains("unsupported KDF algorithm"),
            "wrong branch: {shown}"
        );
        assert!(!shown.contains('\u{1b}'), "raw escape byte in: {shown}");
        assert!(shown.contains("\\u{1B}"), "missing escaped form: {shown}");
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
