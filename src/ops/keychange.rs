//! `passwd` and `rekey`: key-ring maintenance. `passwd` re-wraps the
//! ring (no ciphertext change); `rekey` prepends a fresh domain key and
//! migrates ciphertext in memory (see `docs/cli.md`).

use crate::crypto::{self, KdfGate};
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, Origin, TargetFile};
use crate::{binmode, fsops, pwinput, report, textmode};

use super::Domain;

/// Options of the `passwd` command (KDF overrides apply to the new
/// wrapping).
pub struct PasswdOpts {
    /// Argon2id memory override (KiB).
    pub memory_kib: Option<u64>,
    /// Argon2id pass-count override.
    pub iterations: Option<u64>,
    /// Argon2id lane-count override.
    pub parallelism: Option<u64>,
    /// KDF policy override flags.
    pub gate: KdfGate,
}

/// Runs the `passwd` command: re-wrap the whole ring under a fresh salt
/// and the new password. No file content is read or written.
pub fn passwd(opts: &PasswdOpts) -> Result<()> {
    let (mut domain, _) = super::open_domain(&[], true)?;
    fsops::sweep_temps(
        domain.root(),
        super::lexical_sweep_dirs(domain.root(), &domain.loaded.config.paths),
    );

    let old_password = pwinput::old_password()?;
    let keys = super::unlock_ring(&domain.loaded, &opts.gate, &old_password)?;
    let new_password = pwinput::new_password()?;

    let kdf = super::merge_kdf_overrides(
        &domain.loaded.config.kdf,
        opts.memory_kib,
        opts.iterations,
        opts.parallelism,
    )?;
    let salt = crypto::random_salt()?;
    let kek = super::derive_kek_checked(&new_password, &salt, &kdf, &opts.gate)?;
    domain.loaded.config.salt = salt;
    domain.loaded.config.kdf = kdf;
    domain.loaded.config.wrapped_keys = crypto::wrap_ring(&kek, &keys);
    domain.loaded.rewrite()?;

    report::out("password changed; no ciphertext was touched");
    report::warn(
        "`passwd` does not revoke the old password: the old wrapped ring stays in git history and \
         the domain keys are unchanged, so anyone who knows the old password and can read the \
         repository history can decrypt everything — including future content. For a compromised \
         password, run `passwd` and then `rekey`.",
    );
    Ok(())
}

/// Which rekey variant to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyMode {
    /// Mint a fresh domain key, prepend it, migrate everything.
    Fresh,
    /// Resume an interrupted rotation: migrate without minting.
    Continue,
    /// Drop old ring entries once every managed encrypted file
    /// authenticates under the current key.
    Prune,
}

/// Runs the `rekey` command.
pub fn rekey(mode: RekeyMode, gate: &KdfGate) -> Result<()> {
    let (mut domain, _) = super::open_domain(&[], true)?;
    let entries: Vec<(String, Origin)> = domain
        .loaded
        .config
        .paths
        .iter()
        .map(|p| (p.clone(), Origin::Managed))
        .collect();
    let expanded = select::expand(domain.root(), &entries)?;
    fsops::sweep_temps(domain.root(), expanded.sweep_dirs.clone());

    let password = pwinput::primary(false)?;
    let keys = super::unlock_ring(&domain.loaded, gate, &password)?;

    match mode {
        RekeyMode::Prune => {
            return prune(&mut domain, &password, gate, &keys, &expanded);
        }
        RekeyMode::Continue => {
            // Content that exists but could not be verified (a symlink
            // or special managed path) blocks convergence, exactly as
            // in --prune.
            if let Some(skipped) = expanded.skipped_special.first() {
                return Err(Error::Usage(format!(
                    "managed path `{}` is a symlink or special file and was skipped, so its content \
                     was never verified — resolve it (or `remove` the covering entry) first",
                    skipped.rel
                )));
            }
            for missing in &expanded.missing_managed {
                report::warn(format!(
                    "managed path `{missing}` is missing; it will migrate when it reappears"
                ));
            }
            super::encrypt_pass(&mut domain, &keys, &expanded.files, false, false)?;
            // Skip/migrate decisions authenticate the first unit only;
            // a file can still be mixed-epoch or damaged deeper in. The
            // rotation is finished only when everything fully
            // authenticates under the current key.
            ensure_all_current(&keys, &expanded.files)?;
            if expanded.missing_managed.is_empty() {
                report::out("rotation complete: every managed ciphertext uses the current key");
            } else {
                report::out(
                    "rotation complete for everything on disk; \
                     missing managed paths will migrate when they reappear",
                );
            }
            return Ok(());
        }
        RekeyMode::Fresh => {}
    }

    // Refuse to mint another key while an earlier rotation is unfinished.
    if domain.loaded.config.wrapped_keys.len() > 1 {
        let stale = find_old_epoch_file(&keys, &expanded.files)?;
        if let Some(rel) = stale {
            return Err(Error::Usage(format!(
                "unfinished rotation: `{rel}` still authenticates under an older ring key; \
                 run `rekey --continue` (or `encrypt`) to finish the existing rotation first"
            )));
        }
    }
    if domain.loaded.config.wrapped_keys.len() >= crate::consts::MAX_RING_LEN {
        return Err(Error::Limit(format!(
            "the key ring already has {} entries (the maximum); run `rekey --prune` once converged",
            domain.loaded.config.wrapped_keys.len()
        )));
    }

    // Mint: prepend a fresh domain key, re-wrap everything under a
    // fresh salt, and commit the config before touching any file, so an
    // interruption leaves every file decryptable under a ring key.
    let mut new_keys = vec![crypto::random_domain_key()?];
    new_keys.extend(keys);
    let salt = crypto::random_salt()?;
    let kek = super::derive_kek_checked(&password, &salt, &domain.loaded.config.kdf, gate)?;
    domain.loaded.config.salt = salt;
    domain.loaded.config.wrapped_keys = crypto::wrap_ring(&kek, &new_keys);
    domain.loaded.rewrite()?;
    report::out(format!(
        "minted a new domain key (ring now has {} entries)",
        new_keys.len()
    ));

    for missing in &expanded.missing_managed {
        report::warn(format!(
            "managed path `{missing}` is missing; it will migrate when it reappears"
        ));
    }
    super::encrypt_pass(&mut domain, &new_keys, &expanded.files, false, false)
}

/// Finds a managed file whose first unit authenticates under a
/// non-current ring key, if any. First-unit authentication failures
/// are hard errors here; damage deeper in a file is only discovered
/// during the migration pass (after the new ring entry is safely
/// committed), never silently skipped.
fn find_old_epoch_file(keys: &[crypto::DomainKey], files: &[TargetFile]) -> Result<Option<String>> {
    for file in files {
        let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
        let idx = match probe(&data.content) {
            Probe::Plain => continue,
            Probe::TextUnrecognized => {
                return Err(Error::format(
                    file.rel.clone(),
                    "the first line starts with `#simple-encrypt` but is no exact v1 header; \
                     resolve it before rekeying",
                ));
            }
            Probe::TextV1 => textmode::authenticate_first(keys, &file.rel, &data.content)?,
            Probe::Binary => binmode::authenticate_first(keys, &file.rel, &data.content)?,
        };
        if idx > 0 {
            return Ok(Some(file.rel.clone()));
        }
    }
    Ok(None)
}

/// Fully authenticates every encrypted managed file under the current
/// ring key (entry 0). A first-unit check would miss mixed-epoch and
/// deeply damaged files, so this is the convergence bar for
/// `rekey --continue` and `rekey --prune`.
fn ensure_all_current(keys: &[crypto::DomainKey], files: &[TargetFile]) -> Result<()> {
    let current = &keys[..1];
    for file in files {
        let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
        let failed = match probe(&data.content) {
            Probe::Plain => None,
            Probe::TextUnrecognized => {
                Some("has an unrecognized `#simple-encrypt` header".to_owned())
            }
            Probe::TextV1 => textmode::decrypt(current, &file.rel, &data.content)
                .err()
                .map(|e| e.to_string()),
            Probe::Binary => binmode::decrypt(current, &file.rel, &data.content)
                .err()
                .map(|e| e.to_string()),
        };
        if let Some(reason) = failed {
            // Old-epoch content migrates with `--continue`; anything
            // else needs manual resolution — never advise a loop.
            let migratable = match probe(&data.content) {
                Probe::TextV1 => textmode::decrypt(keys, &file.rel, &data.content).is_ok(),
                Probe::Binary => binmode::decrypt(keys, &file.rel, &data.content).is_ok(),
                _ => false,
            };
            let advice = if migratable {
                "run `rekey --continue` (or `encrypt`) to migrate it first"
            } else {
                "resolve the file manually first (it is damaged or mixes key epochs)"
            };
            return Err(Error::Usage(format!(
                "`{}` does not fully authenticate under the current key ({reason}); {advice}",
                file.rel
            )));
        }
    }
    Ok(())
}

/// `rekey --prune`: verify convergence under the current key, then
/// rewrite the ring as a single freshly-wrapped entry under a fresh
/// salt, so pre-prune wrappers can never be re-attached.
fn prune(
    domain: &mut Domain,
    password: &str,
    gate: &KdfGate,
    keys: &[crypto::DomainKey],
    expanded: &select::Expanded,
) -> Result<()> {
    // Nothing to drop: no convergence check is needed at all.
    let dropped = domain.loaded.config.wrapped_keys.len() - 1;
    if dropped == 0 {
        report::out("the key ring already has a single entry; nothing to prune");
        return Ok(());
    }
    // Every exact managed entry — file or directory — must exist on
    // disk: the path could return from a stash or branch still
    // encrypted under an old key.
    for entry in &domain.loaded.config.paths {
        let abs = domain.root().join(entry);
        match abs.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(Error::Usage(format!(
                    "managed path `{entry}` is missing from disk; it could return from a stash or branch \
                     still encrypted under an old key — `remove` the entry first if it is truly gone"
                )));
            }
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
            Ok(md) if !md.file_type().is_file() && !md.file_type().is_dir() => {
                return Err(Error::Usage(format!(
                    "managed path `{entry}` is a symlink or special file, so its content was never \
                     verified — resolve it (or `remove` the entry) before pruning"
                )));
            }
            Ok(_) => {}
        }
    }
    // Entries skipped during expansion are likewise unverified; prune
    // must not converge past them.
    if let Some(skipped) = expanded.skipped_special.first() {
        return Err(Error::Usage(format!(
            "managed path `{}` is a symlink or special file and was skipped, so its content \
             was never verified — resolve it (or `remove` the covering entry) before pruning",
            skipped.rel
        )));
    }
    // Every managed encrypted file must fully authenticate under the
    // current key.
    ensure_all_current(keys, &expanded.files).map_err(|e| {
        if let Error::Usage(msg) = e {
            Error::Usage(format!("cannot prune: {msg}"))
        } else {
            e
        }
    })?;

    let retained = vec![keys[0].clone()];
    let salt = crypto::random_salt()?;
    let kek = super::derive_kek_checked(password, &salt, &domain.loaded.config.kdf, gate)?;
    domain.loaded.config.salt = salt;
    domain.loaded.config.wrapped_keys = crypto::wrap_ring(&kek, &retained);
    domain.loaded.rewrite()?;
    report::out(format!(
        "pruned {dropped} old key epoch(s); the ring now has a single entry"
    ));
    report::note(
        "configs already committed to git history keep the full ring; pruning limits what the \
         current checkout exposes, not what a history reader with the current password can reach",
    );
    Ok(())
}
