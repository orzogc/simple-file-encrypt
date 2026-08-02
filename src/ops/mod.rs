//! Command implementations (see `docs/cli.md`) and their shared
//! plumbing: domain resolution, locking, ring unlocking, and the
//! serial stop-at-first-error processing report.

mod decrypt;
mod encrypt;
mod init;
mod keychange;
mod manage;
mod scan;

pub use decrypt::{DecryptOpts, decrypt};
pub(crate) use encrypt::encrypt_pass;
pub use encrypt::{EncryptOpts, encrypt};
pub use init::{InitOpts, init};
pub use keychange::{PasswdOpts, RekeyMode, passwd, rekey};
pub use manage::{add, remove};
pub use scan::{ScanOutcome, check, status, verify};

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::config::{self, LoadedConfig};
use crate::crypto::{self, DomainKey, KdfGate, KdfParams, Kek};
use crate::error::{Error, Result};
use crate::fsops::{self, DirLock};
use crate::select::TargetFile;
use crate::{paths, report};

/// An opened domain: root, held lock, and loaded config.
pub struct Domain {
    /// The loaded (and rewritable) config; `loaded.root` is the domain root.
    pub loaded: LoadedConfig,
    /// The advisory lock, held until drop.
    _lock: DirLock,
}

impl Domain {
    /// The domain root directory.
    pub fn root(&self) -> &Path {
        &self.loaded.root
    }
}

/// Resolves the domain for an invocation, locks it, loads the config,
/// and mints the explicit arguments into canonical relative paths
/// (`""` = the domain root directory).
pub fn open_domain(args: &[PathBuf], exclusive: bool) -> Result<(Domain, Vec<String>)> {
    let cwd =
        std::env::current_dir().map_err(|e| Error::io("resolving", "current directory", e))?;
    let mut root: Option<PathBuf> = None;
    let mut abs_args = Vec::with_capacity(args.len());
    if args.is_empty() {
        root = paths::discover_domain(&cwd)?;
    } else {
        for arg in args {
            let abs = paths::lexical_absolute(&cwd, arg);
            let start = paths::resolution_start(&abs)?;
            let this = paths::discover_domain(&start)?.ok_or_else(|| {
                Error::Usage(format!(
                    "`{}` is outside any simple-file-encrypt domain (no `.simple-file-encrypt.toml` found)",
                    report::escape_path(arg)
                ))
            })?;
            check_arg_root_components(&cwd, &this)?;
            match &root {
                None => root = Some(this),
                Some(r) if *r == this => {}
                Some(r) => {
                    return Err(Error::Usage(format!(
                        "targets resolve to different domains (`{}` and `{}`); operate on one domain at a time",
                        report::escape_path(r),
                        report::escape_path(&this)
                    )));
                }
            }
            abs_args.push(abs);
        }
    }
    let root = root.ok_or_else(|| {
        Error::Usage("not inside a simple-file-encrypt domain (no `.simple-file-encrypt.toml` found up to the repository boundary)".into())
    })?;
    // The discovered root must be a real directory: a symlinked root
    // would make the lexical containment checks of `mint` meaningless
    // (they cover only components *below* the root). Ancestors of the
    // root itself are the user's own environment (e.g. a symlinked
    // home or /tmp) and are not policed.
    let root_md =
        std::fs::symlink_metadata(&root).map_err(|e| Error::io("inspecting", &root, e))?;
    if root_md.file_type().is_symlink() {
        return Err(Error::Usage(format!(
            "the domain root `{}` is itself a symlink; resolve it to the real directory and run from there",
            report::escape_path(&root)
        )));
    }
    let lock = fsops::lock_dir(&root, exclusive)?;
    let loaded = config::load(&root)?;

    let mut rels = Vec::with_capacity(abs_args.len());
    for (abs, arg) in abs_args.iter().zip(args) {
        let rel = paths::mint(&root, abs)?;
        if !rel.is_empty()
            && let Some(reason) = paths::forbidden_reason(&rel)
        {
            return Err(Error::Usage(format!(
                "cannot target `{}`: {reason}",
                report::escape_path(arg)
            )));
        }
        rels.push(rel);
    }
    Ok((
        Domain {
            loaded,
            _lock: lock,
        },
        rels,
    ))
}

/// Rejects when any component of the discovered domain root below its
/// common prefix with `cwd` is a symlink. Those components were
/// introduced by the explicit argument itself, so the documented "any
/// component of an explicit argument" rule covers them; the root's own
/// ancestors above the common prefix are the user's environment (a
/// symlinked home or `/tmp`) and are not policed.
fn check_arg_root_components(cwd: &Path, root: &Path) -> Result<()> {
    let common = cwd
        .components()
        .zip(root.components())
        .take_while(|(a, b)| a == b)
        .count();
    let mut cur = PathBuf::new();
    for (i, comp) in root.components().enumerate() {
        cur.push(comp.as_os_str());
        if i < common {
            continue;
        }
        let md = std::fs::symlink_metadata(&cur).map_err(|e| Error::io("inspecting", &cur, e))?;
        if md.file_type().is_symlink() {
            return Err(Error::Usage(format!(
                "the path to the domain root crosses the symlink `{}`; \
                 resolve it and run from the real directory",
                report::escape_path(&cur)
            )));
        }
    }
    Ok(())
}

/// Enforces the KDF policy tiers, announces an above-default cost, and
/// derives the KEK.
pub fn derive_kek_checked(
    password: &str,
    salt: &[u8; crate::consts::SALT_LEN],
    params: &KdfParams,
    gate: &KdfGate,
) -> Result<Kek> {
    crypto::check_kdf_policy(params, gate)?;
    if params.exceeds_default() {
        report::note(format!(
            "deriving the key-encryption key with Argon2id: {} KiB memory x {} passes",
            params.memory_kib, params.iterations
        ));
    }
    crypto::derive_kek(password, salt, params)
}

/// Derives the KEK from the password and unwraps the whole key ring
/// (entry 0 = current). A wrong password fails here, before any file is
/// touched.
pub fn unlock_ring(
    loaded: &LoadedConfig,
    gate: &KdfGate,
    password: &str,
) -> Result<Vec<DomainKey>> {
    let kek = derive_kek_checked(password, &loaded.config.salt, &loaded.config.kdf, gate)?;
    crypto::unwrap_ring(&kek, &loaded.config.wrapped_keys)
}

/// Reads the primary password and unlocks the ring.
pub fn read_password_and_unlock(loaded: &LoadedConfig, gate: &KdfGate) -> Result<Vec<DomainKey>> {
    let password = crate::pwinput::primary(false)?;
    unlock_ring(loaded, gate, &password)
}

/// Merges CLI KDF overrides over base parameters and validates the
/// result structurally.
pub fn merge_kdf_overrides(
    base: &KdfParams,
    memory_kib: Option<u64>,
    iterations: Option<u64>,
    parallelism: Option<u64>,
) -> Result<KdfParams> {
    crypto::validate_kdf_structural(
        memory_kib.unwrap_or(u64::from(base.memory_kib)),
        iterations.unwrap_or(u64::from(base.iterations)),
        parallelism.unwrap_or(u64::from(base.parallelism)),
    )
}

/// Sweep-directory set for commands that do not expand targets
/// (`add`, `remove`, `passwd`): the domain root plus the lexical parent
/// of every managed entry.
pub fn lexical_sweep_dirs(root: &Path, entries: &[String]) -> Vec<PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    for rel in entries {
        // The empty entry denotes the root itself, whose parent lies
        // outside the domain and must never be swept.
        if rel.is_empty() {
            continue;
        }
        if let Some(parent) = root.join(rel).parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs
}

/// The one-line integrity reminder shown when paths start being
/// managed without a `force_binary` mark.
pub(crate) const TEXT_MODE_NOTE: &str = "text mode (the default when content has no NUL bytes) \
     authenticates each line but not the file as a whole: deleted, reordered, duplicated, or \
     resurrected lines go undetected — use `add --binary` where order or presence matters";

/// Inserts an entry into a sorted, deduplicated list; returns whether
/// the list changed.
pub fn insert_sorted(list: &mut Vec<String>, entry: &str) -> bool {
    match list.binary_search_by(|e| e.as_str().cmp(entry)) {
        Ok(_) => false,
        Err(pos) => {
            list.insert(pos, entry.to_owned());
            true
        }
    }
}

/// Runs `process` serially over the targets, stopping at the first
/// error and reporting the completed / failed / not-attempted lists on
/// stderr. `process` returns the finished progress line (e.g.
/// `encrypted a.txt`), or `None` for silent completion.
pub fn run_serial<F>(files: &[TargetFile], mut process: F) -> Result<()>
where
    F: FnMut(&TargetFile) -> Result<Option<String>>,
{
    let mut completed: Vec<String> = Vec::new();
    for (i, file) in files.iter().enumerate() {
        match process(file) {
            Ok(line) => {
                if let Some(line) = line {
                    report::out(&line);
                    completed.push(line);
                }
            }
            Err(e) => {
                report::errline(format!(
                    "aborted at the first error; {} of {} file(s) processed",
                    i,
                    files.len()
                ));
                if !completed.is_empty() {
                    report::errline(format!(
                        "completed ({}):\n  {}",
                        completed.len(),
                        completed.join("\n  ")
                    ));
                }
                report::errline(format!("failed:\n  {}", file.rel));
                let rest: Vec<&str> = files[i + 1..].iter().map(|f| f.rel.as_str()).collect();
                if !rest.is_empty() {
                    report::errline(format!(
                        "not attempted ({}):\n  {}",
                        rest.len(),
                        rest.join("\n  ")
                    ));
                }
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Expansion entries for the audit-style commands — `status`, `verify`,
/// `decrypt` without arguments, and `rekey`: every managed entry, plus
/// every `excludes` entry no managed entry covers, as an audit root.
/// An exclusion outside every managed entry would otherwise never be
/// walked, hiding stranded ciphertext from the very scans that promise
/// to flag it. Exclusions covered by a managed entry are reached by
/// the managed walk itself (a covering *file* entry means the excluded
/// path cannot exist on disk), so only the independent ones become
/// roots. `encrypt` and `check` do not consume excluded content and
/// keep their plain managed entries.
pub(crate) fn audit_entries(config: &config::Config) -> Vec<(String, crate::select::Origin)> {
    use crate::select::Origin;
    let mut entries: Vec<(String, Origin)> = config
        .paths
        .iter()
        .map(|p| (p.clone(), Origin::Managed))
        .collect();
    for exclude in &config.excludes {
        if paths::covering_entry(&config.paths, exclude).is_none() {
            entries.push((exclude.clone(), Origin::Exclusion));
        }
    }
    entries
}

/// How content under an excluded path that probes as ciphertext relates
/// to this domain's key ring. Exclusion hides a file from `encrypt` and
/// `rekey` migration, so its holding *our* ciphertext is a stranding
/// hazard — while deliberately excluded foreign-looking content (the
/// `add --exclude --force` use case) must stay ignorable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExcludedCiphertext {
    /// Fully decrypts under the given ring entry: stranded ciphertext.
    Authentic(usize),
    /// At least one unit (text line or binary chunk) authenticates
    /// under the given ring entry but the file does not fully decrypt:
    /// this domain's ciphertext, damaged (a destroyed unit,
    /// truncation, appended data) or mixing key epochs — manual
    /// resolution. Any surviving unit proves ownership; requiring the
    /// *first* unit would let one destroyed line or chunk disguise the
    /// rest as foreign and un-block `rekey --prune`.
    PartiallyAuthentic(usize),
    /// The scan could not settle ownership: an over-cap binary hit
    /// with a valid header whose first full chunk does not
    /// authenticate (a single-chunk ciphertext with appended data is
    /// unrecognizable from any prefix), an over-cap text hit with no
    /// surviving unit inside the cap-sized prefix (prepended damage
    /// can push real units past any prefix), or a unit scan whose
    /// work budget ran out before every candidate was tried. Treated
    /// like this domain's ciphertext where it matters: key rotation
    /// must not converge past what it cannot rule out.
    Ambiguous,
    /// A *complete* unit scan authenticated under no ring key:
    /// foreign or moved content — or this domain's ciphertext with
    /// *every* unit destroyed, which no key ring can tell apart (a
    /// documented residual). Never produced by a scan cut short.
    Foreign,
}

/// Classifies an excluded probe hit against the ring. `kind` must be
/// the probe of `content`. An unrecognized text header still gets its
/// unit lines scanned — the header line is as damageable as any unit,
/// and only the lines can prove ownership.
pub(crate) fn classify_excluded_ciphertext(
    keys: &[DomainKey],
    rel: &str,
    content: &[u8],
    kind: crate::probe::Probe,
) -> ExcludedCiphertext {
    use crate::probe::Probe;
    let mut budget = crypto::ScanBudget::full();
    let full = match kind {
        Probe::TextV1 => crate::textmode::decrypt(keys, rel, content).map(|(_, idx)| idx),
        Probe::Binary => crate::binmode::decrypt(keys, rel, content).map(|(_, idx)| idx),
        Probe::TextUnrecognized => {
            let scan = crate::textmode::authenticate_any(keys, rel, content, &mut budget);
            return scan_verdict(scan);
        }
        Probe::Plain => return ExcludedCiphertext::Foreign,
    };
    match full {
        Ok(idx) => ExcludedCiphertext::Authentic(idx),
        Err(_) => {
            let scan = match kind {
                Probe::TextV1 => crate::textmode::authenticate_any(keys, rel, content, &mut budget),
                Probe::Binary => crate::binmode::authenticate_any(keys, rel, content, &mut budget),
                _ => unreachable!("handled above"),
            };
            scan_verdict(scan)
        }
    }
}

/// Maps a unit-scan outcome over *complete* in-cap content to a
/// classification: only a finished scan may call content foreign; a
/// scan cut short by the work budget stays ambiguous and blocks key
/// rotation like anything else that cannot be ruled out as ours.
fn scan_verdict(scan: crypto::UnitScan) -> ExcludedCiphertext {
    match scan {
        crypto::UnitScan::Found(idx) => ExcludedCiphertext::PartiallyAuthentic(idx),
        crypto::UnitScan::NoMatch => ExcludedCiphertext::Foreign,
        crypto::UnitScan::Inconclusive => ExcludedCiphertext::Ambiguous,
    }
}

/// Bounded classification for an excluded probe hit whose file exceeds
/// the in-memory cap. A prefix scan can prove ownership — any
/// surviving unit inside it is decisive — but never disprove it: an
/// over-cap file is a modified one by definition (valid ciphertext
/// fits under the cap), and prepended damage can push surviving units
/// past any prefix, so "nothing found" degrades to `Ambiguous`, not
/// `Foreign`. `Authentic` is never produced (the whole file cannot be
/// checked); the hit is at best `PartiallyAuthentic` — this domain's
/// ciphertext with data appended past the cap, or otherwise damaged —
/// which blocks key-rotation convergence exactly like an in-cap
/// damaged file.
///
/// Binary hits are decided from a header-plus-one-chunk window: a
/// valid header whose first chunk fails authentication is `Ambiguous`,
/// never plain foreign — a single-chunk ciphertext of this domain with
/// appended data is unrecognizable from any prefix, and an over-cap
/// file cannot be intact ciphertext of *any* domain (the cap binds
/// both sides), so a well-formed v1 binary header there is
/// realistically ciphertext-plus-junk of some kind. Ambiguity already
/// blocks convergence exactly like a proven-ours hit, so scanning the
/// remaining chunks could only sharpen the message, not the outcome —
/// not worth a cap-sized read plus a full grid scan per run (the
/// in-cap classifier has no such conservative fallback, which is why
/// it does scan every unit). Text hits get the cap-sized line scan,
/// and one *without* a surviving unit stays `Ambiguous` too: a prefix
/// can never disprove ownership — prepended damage pushes real units
/// past any window. The one over-cap shape read as foreign is a
/// structurally invalid binary header: junk that would additionally
/// need a broken header to be ours (see `docs/cli.md`).
pub(crate) fn classify_oversize_excluded(
    keys: &[DomainKey],
    rel: &str,
    abs: &Path,
    kind: crate::probe::Probe,
) -> Result<ExcludedCiphertext> {
    use crate::probe::Probe;
    Ok(match kind {
        Probe::Binary => {
            let window =
                crate::consts::BIN_HEADER_LEN + crate::consts::CHUNK_SIZE + crate::consts::SIV_LEN;
            let prefix = fsops::read_prefix(abs, window)?;
            match crate::binmode::authenticate_first_bounded(keys, rel, &prefix) {
                Ok(idx) => ExcludedCiphertext::PartiallyAuthentic(idx),
                // A valid header whose first chunk fails: ambiguous,
                // which blocks convergence just like a proven hit.
                Err(Error::Auth { .. }) => ExcludedCiphertext::Ambiguous,
                // Structural failures (bad magic, version, flags) are
                // decisive: over-cap junk with a broken header would
                // need two independent kinds of damage to be ours.
                Err(_) => ExcludedCiphertext::Foreign,
            }
        }
        // Text units are line-independent, so any surviving unit in
        // the cap-sized prefix is decisive proof of ownership. The
        // reverse is not decisive: prepended damage can push real
        // units past any prefix, and an over-cap file cannot be
        // intact ciphertext of *any* domain anyway (the cap binds
        // both sides), so a v1-headed over-cap text hit without a
        // surviving unit stays ambiguous rather than foreign. A
        // damaged header line (probing as unrecognized) gets the same
        // scan.
        Probe::TextV1 | Probe::TextUnrecognized => {
            let big = fsops::read_prefix(abs, crate::consts::MAX_FILE_SIZE as usize)?;
            let mut budget = crypto::ScanBudget::full();
            match crate::textmode::authenticate_any(keys, rel, &big, &mut budget) {
                crypto::UnitScan::Found(idx) => ExcludedCiphertext::PartiallyAuthentic(idx),
                crypto::UnitScan::NoMatch | crypto::UnitScan::Inconclusive => {
                    ExcludedCiphertext::Ambiguous
                }
            }
        }
        Probe::Plain => ExcludedCiphertext::Foreign,
    })
}

/// Refuses to replace a file with more than one hard link when
/// (re-)encrypting: the other links would keep a stale alias. `nlink`
/// comes from the read-time snapshot, so a link created after target
/// expansion is still caught.
pub fn refuse_hard_links(rel: &str, nlink: u64, action: &str) -> Result<()> {
    if nlink > 1 {
        return Err(Error::Usage(format!(
            "`{rel}` has {nlink} hard links; {action} would leave the other links pointing at a \
             stale copy — resolve the links first"
        )));
    }
    Ok(())
}

/// The plaintext modes a file can be encrypted in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Per-line deterministic encryption.
    Text,
    /// Chunked whole-file encryption with a file tag.
    Binary,
}

/// Picks the mode for a plaintext: `force_binary` match or NUL byte in
/// the content mean binary, everything else is text.
pub fn pick_mode(loaded: &LoadedConfig, rel: &str, content: &[u8]) -> Mode {
    if loaded.config.is_force_binary(rel) || content.contains(&0) {
        Mode::Binary
    } else {
        Mode::Text
    }
}

/// Encrypts content in the given mode under the current (index 0) key.
pub fn encrypt_content(
    keys: &[DomainKey],
    rel: &str,
    mode: Mode,
    content: &[u8],
) -> Result<Vec<u8>> {
    let fk = crypto::FileKeys::derive(&keys[0], rel);
    match mode {
        Mode::Text => crate::textmode::encrypt(&fk, rel, content),
        Mode::Binary => crate::binmode::encrypt(&fk, rel, content),
    }
}

/// Password wrapped in `Zeroizing` for the commands that read it once
/// up front.
pub type Password = Zeroizing<String>;
