//! `add` and `remove`: managed-list bookkeeping. Neither reads a
//! password or touches file content (see `docs/cli.md`).

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::probe::probe;
use crate::select::{self, Origin};
use crate::{fsops, paths, report};

/// Sweeps stale temp files next to the managed entries and the
/// invocation's own arguments.
fn sweep(domain: &super::Domain, rels: &[String]) {
    fsops::sweep_temps(
        domain.root(),
        super::lexical_sweep_dirs(domain.root(), &domain.loaded.config.paths)
            .into_iter()
            .chain(super::lexical_sweep_dirs(domain.root(), rels)),
    );
}

/// Runs the `add` command: canonicalize and insert entries. With
/// `binary`, each path is additionally marked `force_binary` (always
/// encrypted in binary mode), so binary mode needs no hand edit of the
/// config.
///
/// State-changing lines (`added …`) are printed only after the config
/// rewrite has been committed, so the output never claims more than the
/// disk holds.
pub fn add(arg_paths: &[PathBuf], binary: bool) -> Result<()> {
    let (mut domain, rels) = super::open_domain(arg_paths, true)?;
    sweep(&domain, &rels);

    let mut announcements: Vec<String> = Vec::new();
    for rel in &rels {
        if rel.is_empty() {
            return Err(Error::Usage(
                "cannot add the domain root itself; add files or subdirectories".into(),
            ));
        }
        let abs = domain.root().join(rel);
        match abs.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => report::warn(format!(
                "`{rel}` does not exist on disk (yet); adding it anyway"
            )),
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
            Ok(md) if !md.is_file() && !md.is_dir() => {
                report::warn(format!(
                    "`{rel}` is not a regular file or directory; it will be skipped when encrypting"
                ));
            }
            Ok(_) => {}
        }

        // Already present or covered by a managed directory entry?
        if let Some(covering) = domain
            .loaded
            .config
            .paths
            .iter()
            .find(|e| paths::is_covered_by(rel, e))
            .cloned()
        {
            if covering == *rel {
                report::out(format!("`{rel}` is already managed"));
            } else {
                report::out(format!(
                    "`{rel}` is already covered by the managed entry `{covering}`"
                ));
            }
        } else {
            // Adding a directory prunes entries it now covers.
            let covered: Vec<String> = domain
                .loaded
                .config
                .paths
                .iter()
                .filter(|e| paths::is_covered_by(e, rel))
                .cloned()
                .collect();
            for e in covered {
                announcements.push(format!(
                    "`{e}` is now covered by `{rel}`; dropped the redundant entry"
                ));
                domain.loaded.config.paths.retain(|x| *x != e);
            }
            super::insert_sorted(&mut domain.loaded.config.paths, rel);
            announcements.push(format!("added {rel}"));
        }

        // Binary marking is independent of the managed-list outcome: a
        // path already managed still needs its mark. Appended at the end
        // so hand-maintained order is preserved.
        if binary {
            if domain.loaded.config.force_binary.contains(rel) {
                report::out(format!("`{rel}` is already marked binary"));
            } else {
                domain.loaded.config.force_binary.push(rel.clone());
                announcements.push(format!("marked {rel} as always-binary (force_binary)"));
            }
        }
    }
    if !announcements.is_empty() {
        domain.loaded.rewrite()?;
        for line in announcements {
            report::out(line);
        }
    }
    Ok(())
}

/// Runs the `remove` command: remove exact entries, refusing (without
/// `--force`) to strand ciphertext. With `--binary`, remove exact
/// `force_binary` entries instead — the managed list is untouched, so
/// the file stays managed and simply reverts to automatic mode choice.
/// `removed …` lines are printed only after the config rewrite has
/// been committed.
pub fn remove(arg_paths: &[PathBuf], force: bool, binary: bool) -> Result<()> {
    let (mut domain, rels) = super::open_domain(arg_paths, true)?;
    sweep(&domain, &rels);

    let mut announcements: Vec<String> = Vec::new();
    for rel in &rels {
        if rel.is_empty() {
            return Err(Error::Usage(
                "the domain root is not a managed entry".into(),
            ));
        }
        if binary {
            if !domain.loaded.config.force_binary.contains(rel) {
                return Err(Error::Usage(format!(
                    "`{rel}` is not a `force_binary` entry"
                )));
            }
            domain.loaded.config.force_binary.retain(|e| e != rel);
            announcements.push(format!("unmarked {rel} as always-binary (force_binary)"));
            report::warn(format!(
                "`{rel}` reverts to automatic mode choice; existing binary ciphertext is not \
                 re-encrypted automatically — decrypt and re-encrypt to change its mode"
            ));
            continue;
        }
        if !domain.loaded.config.paths.contains(rel) {
            if let Some(covering) = domain
                .loaded
                .config
                .paths
                .iter()
                .find(|e| paths::is_covered_by(rel, e))
            {
                return Err(Error::Usage(format!(
                    "`{rel}` is covered by the managed directory entry `{covering}`, not an entry itself; \
                     remove that entry instead"
                )));
            }
            return Err(Error::Usage(format!("`{rel}` is not a managed path")));
        }

        if force {
            report::warn(format!(
                "force-removing `{rel}`: if it (or anything under it) still holds valid ciphertext, \
                 that file is now hidden from `rekey` and will be stranded on the old key after a rotation"
            ));
        } else {
            refuse_if_encrypted(&domain, rel)?;
        }
        domain.loaded.config.paths.retain(|e| e != rel);
        announcements.push(format!("removed {rel}"));
    }
    domain.loaded.rewrite()?;
    for line in announcements {
        report::out(line);
    }
    Ok(())
}

/// Refuses removal when the entry's file — or, for a directory entry,
/// any file beneath it — probes as encrypted.
fn refuse_if_encrypted(domain: &super::Domain, rel: &str) -> Result<()> {
    let expanded = select::expand(domain.root(), &[(rel.to_owned(), Origin::Managed)])?;
    for file in &expanded.files {
        let prefix = fsops::read_prefix(&file.abs, 64)?;
        if probe(&prefix).is_hit() {
            return Err(Error::Usage(format!(
                "`{}` probes as encrypted; decrypt it first — removing the entry would strand \
                 ciphertext outside `rekey`'s reach (`remove --force` overrides)",
                file.rel
            )));
        }
    }
    Ok(())
}
