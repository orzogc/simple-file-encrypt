//! `decrypt` (alias `d`): decrypt managed or explicit files in place
//! (see `docs/cli.md`). The mode comes from the ciphertext;
//! `force_binary` and the managed list are not modified.

use std::path::PathBuf;

use crate::crypto::{DomainKey, KdfGate};
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, Origin};
use crate::{binmode, fsops, report, textmode};

use super::{Domain, run_serial};

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
    // Without arguments the audit entries are used, so independent
    // exclusions (paths outside every managed entry) are visible to
    // the repair pass too — not only exclusions under managed trees.
    let entries: Vec<(String, Origin)> = if rels.is_empty() {
        super::audit_entries(&domain.loaded.config)
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
    let mut recover: Vec<select::TargetFile> = Vec::new();
    for ex in &expanded.excluded {
        let prefix = fsops::read_prefix(&ex.abs, crate::consts::PROBE_PREFIX_LEN)?;
        match probe(&prefix) {
            Probe::TextV1 | Probe::Binary => recover.push(select::TargetFile {
                rel: ex.rel.clone(),
                abs: ex.abs.clone(),
                named: ex.named,
                explicit: false,
            }),
            // Not queued for recovery: the damaged header makes a full
            // decrypt impossible, so there is nothing to restore, and
            // reading a password just to sharpen this note would break
            // the password-only-when-needed contract. `verify` is the
            // keyed arbiter for this shape.
            Probe::TextUnrecognized => report::note(format!(
                "`{}` is excluded and has an unrecognized `#simple-file-encrypt` header; left \
                 untouched — run `verify` to check whether its unit lines still authenticate \
                 as this domain's",
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
        warn_hard_links(&file.rel, data.snap.nlink);
        domain.loaded.ensure_fresh()?;
        fsops::atomic_replace(&file.abs, &data.snap, &pt)?;
        Ok(Some(format!("decrypted {}", file.rel)))
    })?;

    // Recovery pass over excluded probe hits, with the same serial
    // stop-at-first-error semantics and completed/failed/not-attempted
    // report as the main pass. This domain's ciphertext is decrypted;
    // content that fails authentication is noted and left untouched —
    // deliberately excluded foreign-looking content must never block a
    // full decrypt.
    run_serial(&recover, |ex| recover_excluded(&domain, &keys, ex))
}

/// Warns when the file about to be replaced has other hard links (they
/// keep the previous, encrypted content).
fn warn_hard_links(rel: &str, nlink: u64) {
    if nlink > 1 {
        report::warn(format!(
            "`{rel}` has {nlink} hard links; the other links keep the previous (encrypted) content"
        ));
    }
}

/// Processes one excluded probe hit of the repair pass: decrypt it when
/// it is this domain's ciphertext, note and leave everything else.
fn recover_excluded(
    domain: &Domain,
    keys: &[DomainKey],
    ex: &select::TargetFile,
) -> Result<Option<String>> {
    let data = match fsops::read_capped(&ex.abs, crate::consts::MAX_FILE_SIZE, "file") {
        Ok(data) => data,
        // Too large to decrypt in memory: classify from a bounded
        // prefix. A surviving unit of this domain means damaged
        // (possibly appended-to) ciphertext worth pointing at;
        // anything else is foreign and left alone.
        Err(Error::Limit(_)) => {
            let prefix = fsops::read_prefix(&ex.abs, crate::consts::PROBE_PREFIX_LEN)?;
            match super::classify_oversize_excluded(keys, &ex.rel, &ex.abs, probe(&prefix))? {
                super::ExcludedCiphertext::PartiallyAuthentic(idx) => report::note(format!(
                    "`{}` is excluded and holds this domain's ciphertext (a unit \
                     authenticates under ring entry {idx}) but exceeds the file-size cap — \
                     appended-to or damaged; left untouched, restore the original content \
                     manually (e.g. from git)",
                    ex.rel
                )),
                super::ExcludedCiphertext::Ambiguous => report::note(format!(
                    "`{}` is excluded and cannot be conclusively classified (over-cap content, \
                     or a unit scan cut short by its work budget) — if it is this domain's \
                     ciphertext, restore the original bytes; left untouched",
                    ex.rel
                )),
                _ => report::note(format!(
                    "`{}` is excluded, probes as encrypted, and exceeds the file-size cap, but \
                     nothing in it authenticates under this domain's keys; left untouched",
                    ex.rel
                )),
            }
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    let kind = probe(&data.content);
    let result = match kind {
        Probe::TextV1 => textmode::decrypt(keys, &ex.rel, &data.content),
        Probe::Binary => binmode::decrypt(keys, &ex.rel, &data.content),
        // The file changed since the prefix probe; leave it alone.
        _ => return Ok(None),
    };
    match result {
        Ok((pt, _)) => {
            warn_hard_links(&ex.rel, data.snap.nlink);
            domain.loaded.ensure_fresh()?;
            fsops::atomic_replace(&ex.abs, &data.snap, &pt)?;
            Ok(Some(format!("decrypted {} (excluded; recovered)", ex.rel)))
        }
        Err(e @ Error::Io { .. }) => Err(e),
        Err(_) => {
            // Ours-but-damaged and foreign content get distinct notes:
            // the former needs manual resolution, and pointing at
            // "foreign" would send the user the wrong way. Any
            // surviving unit proves ownership, so the scan does not
            // stop at the first one.
            let mut budget = crate::crypto::ScanBudget::full();
            let scan = match kind {
                Probe::TextV1 => {
                    textmode::authenticate_any(keys, &ex.rel, &data.content, &mut budget)
                }
                Probe::Binary => {
                    binmode::authenticate_any(keys, &ex.rel, &data.content, &mut budget)
                }
                _ => crate::crypto::UnitScan::NoMatch,
            };
            match scan {
                crate::crypto::UnitScan::Found(idx) => report::note(format!(
                    "`{}` is excluded and holds this domain's ciphertext (a unit \
                     authenticates under ring entry {idx}) but does not fully decrypt — damaged \
                     or mixing key epochs; left untouched, resolve it manually",
                    ex.rel
                )),
                crate::crypto::UnitScan::Inconclusive => report::note(format!(
                    "`{}` is excluded and cannot be conclusively classified (the unit-scan \
                     work budget ran out) — if it is this domain's ciphertext, restore the \
                     original bytes; left untouched",
                    ex.rel
                )),
                crate::crypto::UnitScan::NoMatch => report::note(format!(
                    "`{}` is excluded and probes as encrypted but does not authenticate under \
                     this domain's keys; left untouched",
                    ex.rel
                )),
            }
            Ok(None)
        }
    }
}
