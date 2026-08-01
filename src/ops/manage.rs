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
/// config. With `exclude`, the paths go to `excludes` (never encrypted)
/// instead of the managed list; `force` (valid only with `exclude`)
/// skips the still-encrypted refusal.
///
/// State-changing lines (`added …`) are printed only after the config
/// rewrite has been committed, so the output never claims more than the
/// disk holds.
pub fn add(arg_paths: &[PathBuf], binary: bool, exclude: bool, force: bool) -> Result<()> {
    let (mut domain, rels) = super::open_domain(arg_paths, true)?;
    sweep(&domain, &rels);
    if exclude {
        return add_excludes(&mut domain, &rels, force);
    }

    let mut announcements: Vec<String> = Vec::new();
    let mut textish_added = false;
    for rel in &rels {
        if rel.is_empty() {
            return Err(Error::Usage(
                "cannot add the domain root itself; add files or subdirectories".into(),
            ));
        }
        // Managing an excluded path is a contradiction (its entry could
        // never be selected); the user resolves the intent first.
        if let Some(via) = domain.loaded.config.covering_exclude(rel) {
            return Err(Error::Usage(format!(
                "cannot add `{rel}`: it is excluded (covered by the excludes entry `{via}`); \
                 run `remove --exclude {via}` first"
            )));
        }
        let abs = domain.root().join(rel);
        // The on-disk kind decides coverage pruning: only a real
        // directory can cover descendants.
        let on_disk = match abs.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report::warn(format!(
                    "`{rel}` does not exist on disk (yet); adding it anyway"
                ));
                None
            }
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
            Ok(md) if !md.is_file() && !md.is_dir() => {
                report::warn(format!(
                    "`{rel}` is not a regular file or directory; it will be skipped when encrypting"
                ));
                None
            }
            Ok(md) => Some(md.file_type()),
        };

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
            // Adding a directory prunes entries it now covers — but
            // only when it really is a directory on disk right now.
            let covered: Vec<String> = domain
                .loaded
                .config
                .paths
                .iter()
                .filter(|e| paths::is_covered_by(e, rel))
                .cloned()
                .collect();
            if on_disk.is_some_and(|ft| ft.is_file()) && !covered.is_empty() {
                return Err(Error::Usage(format!(
                    "`{rel}` is a regular file, but the managed list contains entries beneath it ({}); \
                     a file cannot cover them — remove those entries or replace the file with a directory",
                    covered.join(", ")
                )));
            }
            if on_disk.is_some_and(|ft| ft.is_dir()) {
                for e in covered {
                    announcements.push(format!(
                        "`{e}` is now covered by `{rel}`; dropped the redundant entry"
                    ));
                    domain.loaded.config.paths.retain(|x| *x != e);
                }
            }
            super::insert_sorted(&mut domain.loaded.config.paths, rel);
            announcements.push(format!("added {rel}"));
            if !binary && !domain.loaded.config.is_force_binary(rel) {
                textish_added = true;
            }
        }

        // Binary marking is independent of the managed-list outcome: a
        // path already managed still needs its mark. The list gets the
        // same bookkeeping as the others: sorted insertion, coverage
        // dedup, and a real directory mark collapses marks it covers.
        if binary {
            if let Some(covering) = domain
                .loaded
                .config
                .force_binary
                .iter()
                .find(|e| paths::is_covered_by(rel, e))
                .cloned()
            {
                if covering == *rel {
                    report::out(format!("`{rel}` is already marked binary"));
                } else {
                    report::out(format!(
                        "`{rel}` is already covered by the force_binary entry `{covering}`"
                    ));
                }
            } else {
                if on_disk.is_some_and(|ft| ft.is_dir()) {
                    let covered: Vec<String> = domain
                        .loaded
                        .config
                        .force_binary
                        .iter()
                        .filter(|e| paths::is_covered_by(e, rel))
                        .cloned()
                        .collect();
                    for e in covered {
                        announcements.push(format!(
                            "`{e}` is now covered by `{rel}`; dropped the redundant force_binary \
                             entry"
                        ));
                        domain.loaded.config.force_binary.retain(|x| *x != e);
                    }
                }
                super::insert_sorted(&mut domain.loaded.config.force_binary, rel);
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
    // One note per command, at the decision point — not per file.
    if textish_added {
        report::note(super::TEXT_MODE_NOTE);
    }
    Ok(())
}

/// `add --exclude`: register never-encrypt entries. Refuses entries
/// that would fully shadow an exact managed entry (the user `remove`s
/// those first — which itself refuses to strand ciphertext), and —
/// without `force` — entries whose content probes as encrypted, since
/// exclusion would hide that ciphertext from `encrypt` and `rekey`.
/// `force` exists for content that only *looks* encrypted (a probe
/// collision or foreign ciphertext), which exclusion is the clean way
/// to manage.
fn add_excludes(domain: &mut super::Domain, rels: &[String], force: bool) -> Result<()> {
    let mut announcements: Vec<String> = Vec::new();
    let mut deferred_warnings: Vec<String> = Vec::new();
    for rel in rels {
        if rel.is_empty() {
            return Err(Error::Usage(
                "cannot exclude the domain root itself; exclude files or subdirectories".into(),
            ));
        }
        let abs = domain.root().join(rel);
        let on_disk = match abs.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report::warn(format!(
                    "`{rel}` does not exist on disk (yet); excluding it anyway"
                ));
                None
            }
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
            Ok(md) if !md.is_file() && !md.is_dir() => {
                report::warn(format!(
                    "`{rel}` is not a regular file or directory; expansion skips it either way"
                ));
                None
            }
            Ok(md) => Some(md.file_type()),
        };

        // Already present or covered by an excludes directory entry?
        if let Some(covering) = domain
            .loaded
            .config
            .excludes
            .iter()
            .find(|e| paths::is_covered_by(rel, e))
            .cloned()
        {
            if covering == *rel {
                report::out(format!("`{rel}` is already excluded"));
            } else {
                report::out(format!(
                    "`{rel}` is already covered by the excludes entry `{covering}`"
                ));
            }
            continue;
        }

        // Refuse to shadow exact managed entries: `remove` them first.
        let shadowed: Vec<String> = domain
            .loaded
            .config
            .paths
            .iter()
            .filter(|p| paths::is_covered_by(p, rel))
            .cloned()
            .collect();
        if !shadowed.is_empty() {
            return Err(Error::Usage(format!(
                "cannot exclude `{rel}`: it would fully shadow the managed {} ({}); \
                 `remove` {} first",
                if shadowed.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                shadowed.join(", "),
                if shadowed.len() == 1 { "it" } else { "them" },
            )));
        }

        // Refuse to hide content that probes as encrypted. The probe
        // walks the candidate as if it were already excluded (relaxed
        // rules beneath it), so a tree with hostile names — one this
        // feature exists to fence off — can still be probed and, when
        // plaintext, excluded without `--force`.
        if on_disk.is_some() {
            if force {
                deferred_warnings.push(format!(
                    "force-excluding `{rel}`: if it (or anything under it) still holds valid \
                     ciphertext of this domain, that ciphertext is hidden from `encrypt` and \
                     `rekey` — `verify` and `rekey --continue`/`--prune` will flag it, and \
                     `decrypt` can still recover it"
                ));
            } else {
                let mut probe_excludes = domain.loaded.config.excludes.clone();
                super::insert_sorted(&mut probe_excludes, rel);
                if let Some(hit) = first_encrypted_under(domain, rel, &probe_excludes)? {
                    return Err(Error::Usage(format!(
                        "`{hit}` probes as encrypted; decrypt it first — excluding it would hide \
                         the ciphertext from `encrypt` and `rekey` (`add --exclude --force` \
                         overrides, for content that only looks encrypted)"
                    )));
                }
            }
        }

        // A real directory entry collapses excludes entries it covers.
        if on_disk.is_some_and(|ft| ft.is_dir()) {
            let covered: Vec<String> = domain
                .loaded
                .config
                .excludes
                .iter()
                .filter(|e| paths::is_covered_by(e, rel))
                .cloned()
                .collect();
            for e in covered {
                announcements.push(format!(
                    "`{e}` is now covered by `{rel}`; dropped the redundant excludes entry"
                ));
                domain.loaded.config.excludes.retain(|x| *x != e);
            }
        }
        super::insert_sorted(&mut domain.loaded.config.excludes, rel);
        announcements.push(format!("excluded {rel}"));
    }
    if !announcements.is_empty() {
        domain.loaded.rewrite()?;
        for line in announcements {
            report::out(line);
        }
    }
    // Deferred like the announcements: an earlier error aborts the
    // rewrite, and the output must not claim a change that never
    // reached the disk.
    for line in deferred_warnings {
        report::warn(line);
    }
    Ok(())
}

/// Runs the `remove` command: remove exact entries, refusing (without
/// `--force`) to strand ciphertext. With `--binary`, remove exact
/// `force_binary` entries instead — the managed list is untouched, so
/// the file stays managed and simply reverts to automatic mode choice.
/// With `--exclude`, remove exact `excludes` entries: the paths become
/// eligible for encryption again. `removed …` lines are printed only
/// after the config rewrite has been committed.
pub fn remove(arg_paths: &[PathBuf], force: bool, binary: bool, exclude: bool) -> Result<()> {
    let (mut domain, rels) = super::open_domain(arg_paths, true)?;
    sweep(&domain, &rels);

    let mut announcements: Vec<String> = Vec::new();
    let mut deferred_warnings: Vec<String> = Vec::new();
    for rel in &rels {
        if rel.is_empty() {
            return Err(Error::Usage(
                "the domain root is not a managed entry".into(),
            ));
        }
        if exclude {
            if !domain.loaded.config.excludes.contains(rel) {
                if let Some(covering) = domain
                    .loaded
                    .config
                    .excludes
                    .iter()
                    .find(|e| paths::is_covered_by(rel, e))
                {
                    return Err(Error::Usage(format!(
                        "`{rel}` is covered by the excludes entry `{covering}`, not an entry \
                         itself; remove that entry instead"
                    )));
                }
                return Err(Error::Usage(format!("`{rel}` is not an excludes entry")));
            }
            domain.loaded.config.excludes.retain(|e| e != rel);
            announcements.push(format!("removed {rel} from excludes"));
            deferred_warnings.push(format!(
                "`{rel}` is eligible for encryption again; the next `encrypt` run encrypts it \
                 where it is managed or explicitly targeted"
            ));
            continue;
        }
        if binary {
            if !domain.loaded.config.force_binary.contains(rel) {
                if let Some(covering) = domain
                    .loaded
                    .config
                    .force_binary
                    .iter()
                    .find(|e| paths::is_covered_by(rel, e))
                {
                    return Err(Error::Usage(format!(
                        "`{rel}` is covered by the force_binary entry `{covering}`, not an entry \
                         itself; remove that entry instead"
                    )));
                }
                return Err(Error::Usage(format!(
                    "`{rel}` is not a `force_binary` entry"
                )));
            }
            domain.loaded.config.force_binary.retain(|e| e != rel);
            announcements.push(format!("unmarked {rel} as always-binary (force_binary)"));
            // Deferred like the announcements: a later failure aborts
            // the rewrite, and the output must not claim a change that
            // never reached the disk.
            deferred_warnings.push(format!(
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
            // Deferred too: it describes the completed removal.
            deferred_warnings.push(format!(
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
    for line in deferred_warnings {
        report::warn(line);
    }
    Ok(())
}

/// Refuses removal when the entry's file — or, for a directory entry,
/// any file beneath it — probes as encrypted.
fn refuse_if_encrypted(domain: &super::Domain, rel: &str) -> Result<()> {
    if let Some(hit) = first_encrypted_under(domain, rel, &domain.loaded.config.excludes)? {
        return Err(Error::Usage(format!(
            "`{hit}` probes as encrypted; decrypt it first — removing the entry would strand \
             ciphertext outside `rekey`'s reach (`remove --force` overrides)"
        )));
    }
    Ok(())
}

/// Returns the first path equal to or beneath `rel` (directories
/// expanded) that probes as encrypted. Content hidden by an exclusion
/// would be stranded all the same, so the excluded files are probed
/// too; `excludes` steers only the walk *rules* — the caller passes the
/// entries whose subtrees deserve the relaxed treatment (silently
/// ignored symlinks and hostile names), so a hands-off tree cannot
/// hard-error the very refusal that protects it.
fn first_encrypted_under(
    domain: &super::Domain,
    rel: &str,
    excludes: &[String],
) -> Result<Option<String>> {
    let expanded = select::expand(
        domain.root(),
        &[(rel.to_owned(), Origin::Managed)],
        excludes,
    )?;
    let candidates = expanded
        .files
        .iter()
        .map(|f| (&f.abs, &f.rel))
        .chain(expanded.excluded.iter().map(|e| (&e.abs, &e.rel)));
    for (abs, rel) in candidates {
        let prefix = fsops::read_prefix(abs, crate::consts::PROBE_PREFIX_LEN)?;
        if probe(&prefix).is_hit() {
            return Ok(Some(rel.clone()));
        }
    }
    Ok(None)
}
