//! `init`: create a fresh domain config in the current directory
//! (see `docs/cli.md`). Needs no lock: `O_EXCL` is the guard.

use std::path::{Path, PathBuf};

use crate::config::{self, Config};
use crate::consts::{CONFIG_NAME, MAX_SCANNED_ENTRIES, MAX_WALK_DEPTH};
use crate::crypto::{self, KdfGate, KdfParams};
use crate::error::{Error, Result};
use crate::{paths, pwinput, report};

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
        if path.join(".git").symlink_metadata().is_ok() {
            continue;
        }
        if path.join(CONFIG_NAME).symlink_metadata().is_ok() {
            return Ok(Some(path.join(CONFIG_NAME)));
        }
        if let Some(found) = find_descendant_config(&path, depth + 1, scanned)? {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

/// Runs the `init` command.
pub fn init(opts: &InitOpts) -> Result<()> {
    let cwd =
        std::env::current_dir().map_err(|e| Error::io("resolving", "current directory", e))?;

    // Refuse nested domains: an ancestor scan with the same
    // repository-boundary rule as domain resolution, then a descendant
    // scan that skips nested repositories.
    if let Some(existing) = paths::discover_domain(&cwd) {
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
    if let Some(found) = find_descendant_config(&cwd, 0, &mut 0)? {
        return Err(Error::Usage(format!(
            "a domain config already exists below this directory, at `{}`; \
             nested domains are not supported within one repository",
            report::escape_path(&found)
        )));
    }

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
    config::create_new(&cwd, &cfg)?;
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
