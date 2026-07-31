//! `init`: create a fresh domain config in the current directory
//! (see `docs/cli.md`). Inside a repository it takes an exclusive lock
//! on the repository root across the nesting re-check and the `O_EXCL`
//! create, so two concurrent `init`s cannot create nested domains;
//! outside a repository `O_EXCL` is the only guard (documented).

use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::consts::{CONFIG_NAME, MAX_SCANNED_ENTRIES, MAX_WALK_DEPTH};
use crate::crypto::{self, KdfGate, KdfParams};
use crate::error::{Error, Result};
use crate::{fsops, paths, pwinput, report};

/// Options of the `init` command.
pub struct InitOpts {
    /// Argon2id memory override (KiB).
    pub memory_kib: Option<u64>,
    /// Argon2id pass-count override.
    pub iterations: Option<u64>,
    /// Argon2id lane-count override.
    pub parallelism: Option<u64>,
    /// KDF policy override flags.
    pub gate: KdfGate,
}

/// Scans descendants of `dir` for a domain config, skipping `.git`
/// entries and never entering nested repositories. Depth and the total
/// number of visited entries are capped so a hostile tree cannot
/// exhaust the stack or run unbounded.
fn find_descendant_config(
    dir: &Path,
    depth: usize,
    scanned: &mut usize,
) -> Result<Option<PathBuf>> {
    if depth > MAX_WALK_DEPTH {
        return Err(Error::Limit(format!(
            "`{}`: directory nesting exceeds the {MAX_WALK_DEPTH}-level cap",
            report::escape_path(dir)
        )));
    }
    for entry in std::fs::read_dir(dir).map_err(|e| Error::io("listing", dir, e))? {
        *scanned += 1;
        if *scanned > MAX_SCANNED_ENTRIES {
            return Err(Error::Limit(format!(
                "the descendant config scan examined more than {MAX_SCANNED_ENTRIES} entries"
            )));
        }
        let entry = entry.map_err(|e| Error::io("listing", dir, e))?;
        if entry.file_name() == ".git" {
            continue;
        }
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| Error::io("inspecting", &path, e))?;
        if !ft.is_dir() {
            continue;
        }
        // A nested repository gets its own domain; do not enter it.
        if paths::exists_probe(&path.join(".git"))? {
            continue;
        }
        if paths::exists_probe(&path.join(CONFIG_NAME))? {
            return Ok(Some(path.join(CONFIG_NAME)));
        }
        if let Some(found) = find_descendant_config(&path, depth + 1, scanned)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Refuses when a domain already exists above or below `cwd`: an
/// ancestor scan with the same repository-boundary rule as domain
/// resolution, then a descendant scan that skips nested repositories.
fn refuse_nested_domains(cwd: &Path) -> Result<()> {
    if let Some(existing) = paths::discover_domain(cwd)? {
        if existing == cwd {
            return Err(Error::Usage(format!(
                "`{CONFIG_NAME}` already exists in this directory"
            )));
        }
        return Err(Error::Usage(format!(
            "a domain already exists at `{}`; nested domains are not supported within one repository",
            report::escape_path(&existing)
        )));
    }
    if let Some(found) = find_descendant_config(cwd, 0, &mut 0)? {
        return Err(Error::Usage(format!(
            "a domain config already exists below this directory, at `{}`; \
             nested domains are not supported within one repository",
            report::escape_path(&found)
        )));
    }
    Ok(())
}

/// The nearest ancestor of `start` containing a `.git` entry (file or
/// directory), if any: the repository whose root coordinates `init`.
fn find_repo_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join(".git").symlink_metadata().is_ok() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Creates the config, serializing against a concurrent `init` anywhere
/// else in the same repository: two of them could otherwise both pass
/// the nesting scans (one in an ancestor, one in a descendant) and
/// create nested domains. The lock is taken only after the interactive
/// part, and the nesting check is repeated under it. Outside a
/// repository there is no shared lock point and the residual race is
/// documented; `O_EXCL` still guards the config file itself.
fn create_config(cwd: &Path, cfg: &Config) -> Result<()> {
    let Some(repo_root) = find_repo_root(cwd) else {
        return config::create_new(cwd, cfg);
    };
    let _guard = fsops::lock_dir(&repo_root, true)?;
    refuse_nested_domains(cwd)?;
    config::create_new(cwd, cfg)
}

/// Runs the `init` command.
pub fn init(opts: &InitOpts) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|e| Error::io("resolving", "current directory", e))?;

    // Pre-scan for a good early error; the authoritative re-check
    // happens under the lock in `create_config`.
    refuse_nested_domains(&cwd)?;

    let kdf = super::merge_kdf_overrides(
        &KdfParams::DEFAULT,
        opts.memory_kib,
        opts.iterations,
        opts.parallelism,
    )?;
    let password = pwinput::primary(true)?;
    let salt = crypto::random_salt()?;
    let domain_key = crypto::random_domain_key()?;
    let kek = super::derive_kek_checked(&password, &salt, &kdf, &opts.gate)?;
    let wrapped_keys = crypto::wrap_ring(&kek, std::slice::from_ref(&domain_key));

    let cfg = Config {
        salt,
        wrapped_keys,
        kdf,
        paths: Vec::new(),
        force_binary: Vec::new(),
    };
    create_config(&cwd, &cfg)?;
    report::out(format!(
        "initialized `{}`",
        report::escape_path(&cwd.join(CONFIG_NAME))
    ));
    report::note(
        "commit the config together with the ciphertext, and mark managed paths `-text` in \
         .gitattributes so git never converts their line endings (see docs/cli.md)",
    );
    Ok(())
}
