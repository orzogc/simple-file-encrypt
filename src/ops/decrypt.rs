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
    let expanded = select::expand(domain.root(), &entries)?;
    if let Some(missing) = expanded.missing_explicit.first() {
        return Err(Error::Usage(format!("`{missing}` does not exist on disk")));
    }
    for missing in &expanded.missing_managed {
        report::warn(format!("managed path `{missing}` does not exist on disk"));
    }
    // Sweep the parents of all managed *and* explicit targets.
    fsops::sweep_temps(
        expanded
            .sweep_dirs
            .iter()
            .cloned()
            .chain(super::lexical_sweep_dirs(
                domain.root(),
                &domain.loaded.config.paths,
            )),
    );
    if expanded.files.is_empty() {
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
                    "the first line starts with `#simple-encrypt` but is no exact v1 header: \
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
        fsops::atomic_replace(&file.abs, &data.snap, &pt)?;
        Ok(Some(format!("decrypted {}", file.rel)))
    })
}
