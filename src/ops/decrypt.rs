//! `decrypt` (alias `d`): decrypt managed or explicit files in place
//! (see `docs/cli.md`). The mode comes from the ciphertext;
//! `force_binary` and the managed list are not modified.

use std::path::PathBuf;

use crate::crypto::KdfGate;
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, Origin};
use crate::{binmode, fsops, report, textmode};

use super::run_serial;

/// Options of the `decrypt` command.
pub struct DecryptOpts {
    /// Explicit targets; empty means "every managed file".
    pub paths: Vec<PathBuf>,
    /// Hard-error on files without a ciphertext probe hit instead of
    /// skipping them with a note.
    pub require_encrypted: bool,
    /// KDF policy override flags.
    pub gate: KdfGate,
}

/// Runs the `decrypt` command.
pub fn decrypt(opts: &DecryptOpts) -> Result<()> {
    let (domain, rels) = super::open_domain(&opts.paths, true)?;
    let entries: Vec<(String, Origin)> = if rels.is_empty() {
        domain
            .loaded
            .config
            .paths
            .iter()
            .map(|p| (p.clone(), Origin::Managed))
            .collect()
    } else {
        rels.into_iter()
            .map(|r| (r, Origin::Explicit { named: true }))
            .collect()
    };
    let expanded = select::expand(domain.root(), &entries, &domain.loaded.config.excludes)?;
    if let Some(missing) = expanded.missing_explicit.first() {
        return Err(Error::Usage(format!("`{missing}` does not exist on disk")));
    }
    for missing in &expanded.missing_managed {
        report::warn(format!("managed path `{missing}` does not exist on disk"));
    }
    // Sweep the parents of all managed *and* explicit targets.
    fsops::sweep_temps(
        domain.root(),
        expanded
            .sweep_dirs
            .iter()
            .cloned()
            .chain(super::lexical_sweep_dirs(
                domain.root(),
                &domain.loaded.config.paths,
            )),
    );
    // Excluded paths are decrypt's repair channel: ciphertext hidden by
    // an exclusion (a hand edit, a merge, a checkout from history) is
    // exactly what decrypt must return to plaintext. Probe hits count
    // as work to do; excluded plaintext is skipped and exempt from
    // `--require-encrypted` (its plaintext is intentional).
    let mut recover: Vec<&select::ExcludedFile> = Vec::new();
    for ex in &expanded.excluded {
        let prefix = fsops::read_prefix(&ex.abs, crate::consts::PROBE_PREFIX_LEN)?;
        match probe(&prefix) {
            Probe::TextV1 | Probe::Binary => recover.push(ex),
            Probe::TextUnrecognized => report::note(format!(
                "`{}` is excluded and has an unrecognized `#simple-file-encrypt` header; left untouched",
                ex.rel
            )),
            Probe::Plain => {
                if ex.named {
                    report::out(format!("skipped {} (excluded, not encrypted)", ex.rel));
                }
            }
        }
    }
    if expanded.files.is_empty() && recover.is_empty() {
        report::out("nothing to do");
        return Ok(());
    }
    let keys = super::read_password_and_unlock(&domain.loaded, &opts.gate)?;

    run_serial(&expanded.files, |file| {
        let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
        let (pt, _) = match probe(&data.content) {
            Probe::Plain => {
                if opts.require_encrypted {
                    return Err(Error::Usage(format!(
                        "`{}` is not encrypted (--require-encrypted); a stripped or replaced file would \
                         otherwise pass silently",
                        file.rel
                    )));
                }
                return Ok(Some(format!("skipped {} (not encrypted)", file.rel)));
            }
            Probe::TextUnrecognized => {
                return Err(Error::format(
                    file.rel.clone(),
                    "the first line starts with `#simple-file-encrypt` but is no exact v1 header: \
                     ciphertext from a newer tool, or plaintext colliding with the probe",
                ));
            }
            Probe::TextV1 => textmode::decrypt(keys.as_slice(), &file.rel, &data.content)?,
            Probe::Binary => binmode::decrypt(keys.as_slice(), &file.rel, &data.content)?,
        };
        if file.nlink > 1 {
            report::warn(format!(
                "`{}` has {} hard links; the other links keep the previous (encrypted) content",
                file.rel, file.nlink
            ));
        }
        domain.loaded.ensure_fresh()?;
        fsops::atomic_replace(&file.abs, &data.snap, &pt)?;
        Ok(Some(format!("decrypted {}", file.rel)))
    })?;

    // Recovery pass over excluded probe hits: this domain's ciphertext
    // is decrypted; content that fails authentication is noted and left
    // untouched — deliberately excluded foreign-looking content must
    // never block a full decrypt. I/O errors still abort.
    for ex in recover {
        let data = match fsops::read_capped(&ex.abs, crate::consts::MAX_FILE_SIZE, "file") {
            Ok(data) => data,
            // Both sides of the size cap are enforced, so an over-cap
            // probe hit cannot be this domain's ciphertext.
            Err(Error::Limit(_)) => {
                report::note(format!(
                    "`{}` is excluded and probes as encrypted but exceeds the file-size cap, so \
                     it cannot be this domain's ciphertext; left untouched",
                    ex.rel
                ));
                continue;
            }
            Err(e) => return Err(e),
        };
        let kind = probe(&data.content);
        let result = match kind {
            Probe::TextV1 => textmode::decrypt(keys.as_slice(), &ex.rel, &data.content),
            Probe::Binary => binmode::decrypt(keys.as_slice(), &ex.rel, &data.content),
            // The file changed since the prefix probe; leave it alone.
            _ => continue,
        };
        match result {
            Ok((pt, _)) => {
                if ex.nlink > 1 {
                    report::warn(format!(
                        "`{}` has {} hard links; the other links keep the previous (encrypted) \
                         content",
                        ex.rel, ex.nlink
                    ));
                }
                domain.loaded.ensure_fresh()?;
                fsops::atomic_replace(&ex.abs, &data.snap, &pt)?;
                report::out(format!("decrypted {} (excluded; recovered)", ex.rel));
            }
            Err(e @ Error::Io { .. }) => return Err(e),
            Err(_) => {
                // Ours-but-damaged and foreign content get distinct
                // notes: the former needs manual resolution, and
                // pointing at "foreign" would send the user the wrong
                // way.
                let first = match kind {
                    Probe::TextV1 => {
                        textmode::authenticate_first(keys.as_slice(), &ex.rel, &data.content).ok()
                    }
                    Probe::Binary => {
                        binmode::authenticate_first(keys.as_slice(), &ex.rel, &data.content).ok()
                    }
                    _ => None,
                };
                if let Some(idx) = first {
                    report::note(format!(
                        "`{}` is excluded and holds this domain's ciphertext (first unit \
                         authenticates under ring entry {idx}) but does not fully decrypt — \
                         damaged or mixing key epochs; left untouched, resolve it manually",
                        ex.rel
                    ));
                } else {
                    report::note(format!(
                        "`{}` is excluded and probes as encrypted but does not authenticate \
                         under this domain's keys; left untouched",
                        ex.rel
                    ));
                }
            }
        }
    }
    Ok(())
}
