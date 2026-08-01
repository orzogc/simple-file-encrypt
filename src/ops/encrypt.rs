//! `encrypt` (alias `e`): encrypt managed or explicit files in place,
//! with probe/skip/migration rules and encrypt-time auto-add
//! (see `docs/cli.md`).

use std::path::PathBuf;

use crate::crypto::{DomainKey, KdfGate};
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, Origin, TargetFile};
use crate::{binmode, fsops, report, textmode};

use super::{Domain, Mode, insert_sorted, pick_mode, refuse_hard_links, run_serial};

/// Options of the `encrypt` command.
pub struct EncryptOpts {
    /// Explicit targets; empty means "every managed file".
    pub paths: Vec<PathBuf>,
    /// Treat probe hits that fail authentication as plaintext, for
    /// files named on the command line.
    pub assume_plaintext: bool,
    /// KDF policy override flags.
    pub gate: KdfGate,
}

/// Runs the `encrypt` command.
pub fn encrypt(opts: &EncryptOpts) -> Result<()> {
    if opts.assume_plaintext && opts.paths.is_empty() {
        return Err(Error::Usage(
            "--assume-plaintext requires explicit paths (never managed-list expansion)".into(),
        ));
    }
    let (mut domain, rels) = super::open_domain(&opts.paths, true)?;
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
    if expanded.files.is_empty() {
        report::out("nothing to do");
        return Ok(());
    }
    let keys = super::read_password_and_unlock(&domain.loaded, &opts.gate)?;
    encrypt_pass(
        &mut domain,
        &keys,
        &expanded.files,
        opts.assume_plaintext,
        true,
    )
}

/// What `encrypt` decided to do with one file.
enum Action {
    /// Valid ciphertext under the current key in the configured mode.
    Skip,
    /// Plaintext (or assumed plaintext): encrypt it.
    Encrypt,
    /// Valid ciphertext, but under an old key or the wrong mode:
    /// decrypt in memory and re-encrypt.
    Migrate(Probe),
}

/// Decides the action for one file's content per the probe, the key
/// ring, and the configured mode.
fn plan(
    domain: &Domain,
    keys: &[DomainKey],
    file: &TargetFile,
    content: &[u8],
    assume_plaintext: bool,
) -> Result<Action> {
    let assume = |e: Error| -> Result<Action> {
        if file.named && assume_plaintext {
            report::warn(format!(
                "`{}`: treating unauthenticated probe hit as plaintext (--assume-plaintext)",
                file.rel
            ));
            return Ok(Action::Encrypt);
        }
        if file.named {
            return Err(Error::Usage(format!(
                "{e}; if this is plaintext that merely looks encrypted, re-run with \
                 `encrypt --assume-plaintext {}`",
                file.rel
            )));
        }
        Err(e)
    };
    match probe(content) {
        Probe::Plain => Ok(Action::Encrypt),
        Probe::Binary => match binmode::authenticate_first(keys, &file.rel, content) {
            // Binary-mode ciphertext under the current key is never
            // re-encrypted here: the reverse mode change (binary→text)
            // is not detected automatically.
            Ok(0) => Ok(Action::Skip),
            Ok(_) => Ok(Action::Migrate(Probe::Binary)),
            Err(e) => assume(e),
        },
        Probe::TextV1 => match textmode::authenticate_first(keys, &file.rel, content) {
            Ok(idx) => {
                if domain.loaded.config.is_force_binary(&file.rel) {
                    // Stored mode is text but binary is now configured.
                    Ok(Action::Migrate(Probe::TextV1))
                } else if idx == 0 {
                    Ok(Action::Skip)
                } else {
                    Ok(Action::Migrate(Probe::TextV1))
                }
            }
            Err(e) => assume(e),
        },
        Probe::TextUnrecognized => assume(Error::format(
            file.rel.clone(),
            "the first line starts with `#simple-encrypt` but is no exact v1 header: \
             ciphertext from a newer tool, or plaintext colliding with the probe",
        )),
    }
}

/// The encrypt/migrate pass shared by `encrypt` and `rekey`: encrypts
/// plaintext files, migrates old-key or wrong-mode ciphertext, skips
/// up-to-date files, and (when `auto_add` is set) records explicit
/// files in the managed list before writing them.
pub(crate) fn encrypt_pass(
    domain: &mut Domain,
    keys: &[DomainKey],
    files: &[TargetFile],
    assume_plaintext: bool,
    auto_add: bool,
) -> Result<()> {
    // Pre-register every explicit file that needs a managed entry in a
    // single config rewrite, before any file is encrypted: an
    // interruption can never leave an encrypted file untracked, and a
    // directory of new files costs one rewrite instead of one per file.
    // A file already covered by a managed directory entry is managed
    // and gets no redundant entry; a registered file that is never
    // encrypted (the run aborts early) is ordinary managed plaintext.
    if auto_add {
        let mut added: Vec<String> = Vec::new();
        for file in files {
            if file.explicit
                && !domain
                    .loaded
                    .config
                    .paths
                    .iter()
                    .any(|e| crate::paths::is_covered_by(&file.rel, e))
                && insert_sorted(&mut domain.loaded.config.paths, &file.rel)
            {
                added.push(file.rel.clone());
            }
        }
        if !added.is_empty() {
            domain.loaded.rewrite()?;
            for rel in &added {
                report::out(format!("added {rel}"));
            }
            if added
                .iter()
                .any(|rel| !domain.loaded.config.is_force_binary(rel))
            {
                report::note(super::TEXT_MODE_NOTE);
            }
        }
    }

    run_serial(files, |file| {
        let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
        let action = plan(domain, keys, file, &data.content, assume_plaintext)?;

        match action {
            Action::Skip => Ok(Some(format!("skipped {} (already encrypted)", file.rel))),
            Action::Encrypt => {
                refuse_hard_links(file, "encrypting it")?;
                let mode = pick_mode(&domain.loaded, &file.rel, &data.content);
                let ct = super::encrypt_content(keys, &file.rel, mode, &data.content)?;
                domain.loaded.ensure_fresh()?;
                fsops::atomic_replace(&file.abs, &data.snap, &ct)?;
                Ok(Some(format!("encrypted {}", file.rel)))
            }
            Action::Migrate(stored) => {
                refuse_hard_links(file, "migrating it")?;
                // Decrypt in memory only; plaintext never touches disk.
                let (pt, _) = match stored {
                    Probe::Binary => binmode::decrypt(keys, &file.rel, &data.content)?,
                    _ => textmode::decrypt(keys, &file.rel, &data.content)?,
                };
                let mode = pick_mode(&domain.loaded, &file.rel, &pt);
                let ct = super::encrypt_content(keys, &file.rel, mode, &pt)?;
                domain.loaded.ensure_fresh()?;
                fsops::atomic_replace(&file.abs, &data.snap, &ct)?;
                let mode_note = if stored == Probe::TextV1 && mode == Mode::Binary {
                    " to binary mode"
                } else {
                    ""
                };
                Ok(Some(format!("migrated {}{mode_note}", file.rel)))
            }
        }
    })
}
