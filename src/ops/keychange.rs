//! `passwd` and `rekey`: key-ring maintenance. `passwd` re-wraps the
//! ring (no ciphertext change); `rekey` prepends a fresh domain key and
//! migrates ciphertext in memory (see `docs/cli.md`).

use crate::crypto::{self, KdfGate};
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, TargetFile};
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
    // The audit entries include independent exclusions as roots: an
    // exclusion outside every managed entry can hide this domain's
    // ciphertext just as well as one below a managed directory, and
    // rotation must see it to warn or refuse.
    let entries = super::audit_entries(&domain.loaded.config);
    let expanded = select::expand(domain.root(), &entries, &domain.loaded.config.excludes)?;
    fsops::sweep_temps(domain.root(), expanded.sweep_dirs.clone());

    let password = pwinput::primary(false)?;
    let keys = super::unlock_ring(&domain.loaded, gate, &password)?;

    // Excluded paths holding this domain's ciphertext are hidden from
    // the migration pass: `--continue` and `--prune` refuse to converge
    // past them; a fresh rekey warns, consistent with its tolerance for
    // missing paths (both catch up once resolved).
    let excluded_hits = scan_excluded_ciphertext(&keys, &expanded.excluded)?;

    match mode {
        RekeyMode::Prune => {
            return prune(
                &mut domain,
                &password,
                gate,
                &keys,
                &expanded,
                &excluded_hits,
            );
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
            if let Some(boundary) = expanded.skipped_boundaries.first() {
                return Err(Error::Usage(boundary_message(boundary)));
            }
            if let Some(hit) = excluded_hits.first() {
                return Err(Error::Usage(excluded_hit_message(hit)));
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

    for boundary in &expanded.skipped_boundaries {
        report::warn(format!(
            "nested repository `{boundary}` sits inside a managed tree and is not audited; \
             anything this domain encrypted there before it became a repository stays on its \
             old key"
        ));
    }
    for hit in &excluded_hits {
        report::warn(match hit.kind {
            super::ExcludedCiphertext::Ambiguous => format!(
                "excluded path `{}` cannot be conclusively classified (over-cap content, or a \
                 unit scan cut short by its work budget); if it is this domain's ciphertext it \
                 stays on its old key — restore the original bytes or move it out of the tree",
                hit.rel
            ),
            _ => format!(
                "excluded path `{}` holds this domain's ciphertext and is hidden from \
                 migration; it stays on its old key — decrypt it or `remove --exclude` the \
                 covering entry",
                hit.rel
            ),
        });
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
                    "the first line starts with `#simple-file-encrypt` but is no exact v1 header; \
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

/// An excluded path that key rotation must not converge past, found by
/// [`scan_excluded_ciphertext`]: content that authenticates under some
/// ring key, or over-cap content that cannot be ruled out as this
/// domain's.
struct ExcludedHit {
    /// Canonical relative path.
    rel: String,
    /// How the content relates to the ring (never `Foreign`).
    kind: super::ExcludedCiphertext,
}

/// Scans the excluded files for content that authenticates under any
/// ring key: such ciphertext is hidden from the migration pass, so key
/// rotation must not silently converge past it. Foreign-looking probe
/// hits (authenticating under no key) are exactly what
/// `add --exclude --force` exists for and are ignored.
fn scan_excluded_ciphertext(
    keys: &[crypto::DomainKey],
    excluded: &[select::ExcludedFile],
) -> Result<Vec<ExcludedHit>> {
    let mut hits = Vec::new();
    for ex in excluded {
        let prefix = fsops::read_prefix(&ex.abs, crate::consts::PROBE_PREFIX_LEN)?;
        let prefix_kind = probe(&prefix);
        if !prefix_kind.is_hit() {
            continue;
        }
        let data = match fsops::read_capped(&ex.abs, crate::consts::MAX_FILE_SIZE, "file") {
            Ok(data) => data,
            // Too large to authenticate whole: classify from a bounded
            // prefix. A surviving unit of this domain — valid
            // ciphertext with data appended past the cap, or damage —
            // must block convergence like any in-cap damaged file;
            // foreign blobs still authenticate under no key and block
            // nothing.
            Err(Error::Limit(_)) => {
                if let kind @ (super::ExcludedCiphertext::PartiallyAuthentic(_)
                | super::ExcludedCiphertext::Ambiguous) =
                    super::classify_oversize_excluded(keys, &ex.rel, &ex.abs, prefix_kind)?
                {
                    hits.push(ExcludedHit {
                        rel: ex.rel.clone(),
                        kind,
                    });
                }
                continue;
            }
            Err(e) => return Err(e),
        };
        let kind = probe(&data.content);
        match super::classify_excluded_ciphertext(keys, &ex.rel, &data.content, kind) {
            kind @ (super::ExcludedCiphertext::Authentic(_)
            | super::ExcludedCiphertext::PartiallyAuthentic(_)
            | super::ExcludedCiphertext::Ambiguous) => hits.push(ExcludedHit {
                rel: ex.rel.clone(),
                kind,
            }),
            super::ExcludedCiphertext::Foreign => {}
        }
    }
    Ok(hits)
}

/// The convergence-refusal message for a nested repository discovered
/// inside a managed tree.
fn boundary_message(boundary: &str) -> String {
    format!(
        "nested repository `{boundary}` sits inside a managed tree; its contents were never \
         audited, and anything this domain encrypted there before it became a repository would \
         be stranded — decrypt such files first (temporarily moving its `.git` entry aside lets \
         `decrypt` reach them), then move the repository out of the managed tree or, if it \
         stays in place, `remove --force` the covering entry (a plain `remove` refuses while \
         the boundary blocks its probe)"
    )
}

/// The convergence-refusal message for one excluded ciphertext hit.
fn excluded_hit_message(hit: &ExcludedHit) -> String {
    match hit.kind {
        super::ExcludedCiphertext::Authentic(idx) => format!(
            "excluded path `{}` still holds valid ciphertext of this domain (ring entry {idx}), \
             hidden from migration — decrypt it (`decrypt {}`) or `remove --exclude` the \
             covering entry first",
            hit.rel, hit.rel
        ),
        super::ExcludedCiphertext::PartiallyAuthentic(idx) => format!(
            "excluded path `{}` holds this domain's ciphertext (a unit authenticates under \
             ring entry {idx}) but does not fully decrypt — it is damaged or mixes key epochs; \
             resolve it manually first",
            hit.rel
        ),
        super::ExcludedCiphertext::Ambiguous => format!(
            "excluded path `{}` cannot be conclusively classified (over-cap content, or a unit \
             scan cut short by its work budget) — it may be this domain's ciphertext hidden \
             from migration; restore the original bytes or move the file out of the tree first",
            hit.rel
        ),
        super::ExcludedCiphertext::Foreign => unreachable!("foreign content is never a hit"),
    }
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
                Some("has an unrecognized `#simple-file-encrypt` header".to_owned())
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
    excluded_hits: &[ExcludedHit],
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
    // A nested repository inside a managed tree was never audited: a
    // directory can be encrypted first and become a boundary later, so
    // pruning past one could drop the very key its contents need.
    if let Some(boundary) = expanded.skipped_boundaries.first() {
        return Err(Error::Usage(format!(
            "cannot prune: {}",
            boundary_message(boundary)
        )));
    }
    // Excluded paths holding this domain's ciphertext would be stranded
    // for good by dropping the ring entries they authenticate under.
    if let Some(hit) = excluded_hits.first() {
        return Err(Error::Usage(format!(
            "cannot prune: {}",
            excluded_hit_message(hit)
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
