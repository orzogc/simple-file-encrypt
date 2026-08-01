//! Target selection: expanding managed entries and explicit arguments
//! into the deduplicated list of regular files one invocation operates
//! on, applying the skip and boundary rules of `docs/cli.md`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::consts::{
    CONFIG_NAME, MAX_FILES_PER_OP, MAX_PATH_BYTES, MAX_SCANNED_ENTRIES, MAX_WALK_DEPTH,
};
use crate::error::{Error, Result};
use crate::{paths, report};

/// Where a target entry came from; decides auto-add and
/// `--assume-plaintext` eligibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// From the config's managed list.
    Managed,
    /// From an explicit command-line argument.
    Explicit {
        /// Whether the file itself was named (not reached via a named
        /// directory).
        named: bool,
    },
}

/// One regular file selected for processing.
#[derive(Debug, Clone)]
pub struct TargetFile {
    /// Canonical relative path (authoritative bytes for key derivation).
    pub rel: String,
    /// Absolute on-disk path.
    pub abs: PathBuf,
    /// Whether the file was literally named on the command line
    /// (`--assume-plaintext` applies only to these).
    pub named: bool,
    /// Whether the file was reached via an explicit argument
    /// (auto-add applies to these).
    pub explicit: bool,
    /// Hard-link count at scan time.
    pub nlink: u64,
}

/// A managed path skipped because it is a symlink or special file:
/// never processed, but scans and key rotation must treat it as
/// unverified content rather than silently converge past it.
#[derive(Debug, Clone)]
pub struct SkippedSpecial {
    /// Canonical relative path.
    pub rel: String,
    /// Whether it is a symlink (vs. another non-regular kind).
    pub symlink: bool,
}

/// A regular file covered by an `excludes` entry: never selected for
/// encryption, but recorded so commands can see what exclusion hides —
/// `decrypt` recovers stranded ciphertext, `verify` and
/// `rekey --continue`/`--prune` refuse to converge past it, `status`
/// reports it.
#[derive(Debug, Clone)]
pub struct ExcludedFile {
    /// Canonical relative path.
    pub rel: String,
    /// Absolute on-disk path.
    pub abs: PathBuf,
    /// The `excludes` entry covering this file.
    pub via: String,
    /// Whether the file was literally named on the command line.
    pub named: bool,
    /// Hard-link count at scan time.
    pub nlink: u64,
}

/// The result of expanding one invocation's entries.
#[derive(Debug)]
pub struct Expanded {
    /// Selected regular files, in ascending canonical-path order.
    pub files: Vec<TargetFile>,
    /// Managed entries that do not exist on disk (warned, not errors).
    pub missing_managed: Vec<String>,
    /// Explicit arguments that do not exist on disk (policy is per
    /// command: error for `encrypt`/`decrypt`, ignored for `check`,
    /// reported for `verify`).
    pub missing_explicit: Vec<String>,
    /// Managed paths skipped because they are symlinks or special
    /// files: never processed, but `rekey --prune` must treat them as
    /// unverified content rather than converge past them.
    pub skipped_special: Vec<SkippedSpecial>,
    /// Regular files covered by an `excludes` entry, in ascending
    /// canonical-path order: never selected, but visible to the
    /// commands that must see what exclusion hides.
    pub excluded: Vec<ExcludedFile>,
    /// Directories to sweep for stale temp files: the domain root, the
    /// parents of all entries, and every directory visited.
    pub sweep_dirs: BTreeSet<PathBuf>,
}

/// Traversal budgets. Production uses the normative constants; unit
/// tests inject smaller values so the enforcement logic is testable
/// without building million-entry trees.
#[derive(Clone, Copy)]
struct Budgets {
    /// Cap on selected regular files (`MAX_FILES_PER_OP`).
    max_files: usize,
    /// Cap on directory entries examined (`MAX_SCANNED_ENTRIES`).
    max_scanned: usize,
    /// Cap on total retained path bytes (`MAX_PATH_BYTES`).
    max_path_bytes: usize,
}

impl Budgets {
    /// The normative limits of `consts.rs`.
    const DEFAULT: Budgets = Budgets {
        max_files: MAX_FILES_PER_OP,
        max_scanned: MAX_SCANNED_ENTRIES,
        max_path_bytes: MAX_PATH_BYTES,
    };
}

/// After this many individual "skipping" warnings for symlinks and
/// special files, the rest are summarized in one final warning, so a
/// hostile tree full of them cannot flood stderr.
const MAX_SPECIAL_WARNINGS: usize = 20;

/// Expands entries (canonical relative paths tagged with their origin)
/// into the target file list. `""` denotes the domain root directory.
/// `excludes` must be sorted, deduplicated canonical relative paths
/// (the loaded config form); covered files are recorded, not selected.
pub fn expand(root: &Path, entries: &[(String, Origin)], excludes: &[String]) -> Result<Expanded> {
    expand_with_budgets(root, entries, excludes, Budgets::DEFAULT)
}

/// [`expand`] with injectable budgets (see [`Budgets`]).
fn expand_with_budgets(
    root: &Path,
    entries: &[(String, Origin)],
    excludes: &[String],
    budgets: Budgets,
) -> Result<Expanded> {
    debug_assert!(
        excludes.is_sorted(),
        "excludes must be sorted for exact-match lookup"
    );
    let mut exp = Expander {
        root,
        excludes,
        files: BTreeMap::new(),
        excluded: BTreeMap::new(),
        missing_managed: Vec::new(),
        missing_explicit: Vec::new(),
        skipped_special: Vec::new(),
        sweep_dirs: BTreeSet::new(),
        count: 0,
        scanned: 0,
        path_bytes: 0,
        budgets,
    };
    exp.add_sweep_dir(root)?;
    for (rel, origin) in entries {
        exp.add_entry(rel, *origin)?;
    }
    let suppressed = exp
        .skipped_special
        .len()
        .saturating_sub(MAX_SPECIAL_WARNINGS);
    if suppressed > 0 {
        report::warn(format!(
            "…and {suppressed} more symlinks or special files were skipped \
             (individual warnings suppressed)"
        ));
    }

    // Two different canonical paths must not share an inode: hard links
    // or case-insensitive aliases would desynchronize plain/cipher state.
    let mut seen: HashMap<(u64, u64), &str> = HashMap::new();
    for file in exp.files.values() {
        let md = file
            .abs
            .symlink_metadata()
            .map_err(|e| Error::io("inspecting", &file.abs, e))?;
        use std::os::unix::fs::MetadataExt;
        if let Some(other) = seen.insert((md.dev(), md.ino()), &file.rel) {
            return Err(Error::Usage(format!(
                "`{}` and `{other}` are the same file (hard links or case-insensitive aliases); \
                 resolve the aliasing first",
                file.rel
            )));
        }
    }

    Ok(Expanded {
        files: exp.files.into_values().collect(),
        missing_managed: exp.missing_managed,
        missing_explicit: exp.missing_explicit,
        skipped_special: exp.skipped_special,
        excluded: exp.excluded.into_values().collect(),
        sweep_dirs: exp.sweep_dirs,
    })
}

/// Internal expansion state.
struct Expander<'a> {
    root: &'a Path,
    /// Sorted, deduplicated `excludes` entries in force.
    excludes: &'a [String],
    files: BTreeMap<String, TargetFile>,
    excluded: BTreeMap<String, ExcludedFile>,
    missing_managed: Vec<String>,
    missing_explicit: Vec<String>,
    skipped_special: Vec<SkippedSpecial>,
    sweep_dirs: BTreeSet<PathBuf>,
    count: usize,
    /// Directory entries examined so far (hostile-tree budget).
    scanned: usize,
    /// Total byte length of retained paths (long-name budget): every
    /// path stored in any result collection is charged here.
    path_bytes: usize,
    /// The limits in force (constants outside unit tests).
    budgets: Budgets,
}

impl<'a> Expander<'a> {
    /// The `excludes` entry covering `rel` (exact or an ancestor), if
    /// any. Used once per expansion entry; during a walk, ancestor
    /// coverage is carried by the walk state and children need only
    /// [`Self::exact_exclude`].
    fn covering_exclude(&self, rel: &str) -> Option<&'a str> {
        let excludes: &'a [String] = self.excludes;
        excludes
            .iter()
            .find(|e| paths::is_covered_by(rel, e))
            .map(String::as_str)
    }

    /// The `excludes` entry exactly equal to `rel`, if any.
    fn exact_exclude(&self, rel: &str) -> Option<&'a str> {
        let excludes: &'a [String] = self.excludes;
        excludes
            .binary_search_by(|e| e.as_str().cmp(rel))
            .ok()
            .map(|i| excludes[i].as_str())
    }

    /// Records one excluded regular file, deduplicating repeats.
    fn add_excluded(
        &mut self,
        rel: &str,
        abs: PathBuf,
        named: bool,
        via: &str,
        md: &std::fs::Metadata,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        if let Some(existing) = self.excluded.get_mut(rel) {
            existing.named |= named;
            return Ok(());
        }
        self.charge_path(rel.len())?;
        self.excluded.insert(
            rel.to_owned(),
            ExcludedFile {
                rel: rel.to_owned(),
                abs,
                via: via.to_owned(),
                named,
                nlink: md.nlink(),
            },
        );
        Ok(())
    }

    /// Charges `len` bytes against the retained-path budget. Every path
    /// the expansion keeps — selected file, sweep directory, skipped
    /// special, or missing entry — is charged, so no result collection
    /// can outgrow the budget on a hostile tree.
    fn charge_path(&mut self, len: usize) -> Result<()> {
        self.path_bytes += len;
        if self.path_bytes > self.budgets.max_path_bytes {
            return Err(Error::Limit(format!(
                "expanded paths exceed the {}-byte total path budget",
                self.budgets.max_path_bytes
            )));
        }
        Ok(())
    }

    /// Records a directory in the sweep set, charging its path bytes
    /// when it is new.
    fn add_sweep_dir(&mut self, dir: &Path) -> Result<()> {
        if self.sweep_dirs.insert(dir.to_path_buf()) {
            self.charge_path(dir.as_os_str().len())?;
        }
        Ok(())
    }

    /// Records a missing entry, charging its path bytes.
    fn add_missing(&mut self, rel: &str, origin: Origin) -> Result<()> {
        self.charge_path(rel.len())?;
        match origin {
            Origin::Managed => self.missing_managed.push(rel.to_owned()),
            Origin::Explicit { .. } => self.missing_explicit.push(rel.to_owned()),
        }
        Ok(())
    }

    /// Records a skipped symlink/special path, charging its path bytes
    /// and warning individually up to `MAX_SPECIAL_WARNINGS` (the rest
    /// are summarized once at the end of the expansion).
    fn skip_special(&mut self, rel: String, symlink: bool, msg: String) -> Result<()> {
        self.charge_path(rel.len())?;
        if self.skipped_special.len() < MAX_SPECIAL_WARNINGS {
            report::warn(msg);
        }
        self.skipped_special.push(SkippedSpecial { rel, symlink });
        Ok(())
    }

    /// Handles one entry: a file, a directory (recursed), or a missing
    /// path.
    fn add_entry(&mut self, rel: &str, origin: Origin) -> Result<()> {
        let abs = if rel.is_empty() {
            self.root.to_path_buf()
        } else {
            self.root.join(rel)
        };
        // The domain root itself is already swept; its parent lies
        // outside the domain and must never be touched.
        if !rel.is_empty()
            && let Some(parent) = abs.parent()
        {
            self.add_sweep_dir(parent)?;
        }
        if origin == Origin::Managed {
            self.check_ancestors(rel)?;
        }
        let md = match abs.symlink_metadata() {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.add_missing(rel, origin)?;
                return Ok(());
            }
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
        };
        // The domain root (`""`) is never covered; managed entries
        // cannot be covered either (a load-time contradiction), so a
        // hit here means an explicit argument inside an exclusion.
        let excluded_via = self.covering_exclude(rel);
        let ft = md.file_type();
        if ft.is_dir() {
            if let Some(via) = excluded_via {
                // An excluded directory is still walked — `decrypt`
                // recovery and `verify`/`rekey` convergence must see
                // what exclusion hides — but a nested repository is
                // never entered, silently here (nothing would be
                // selected from it anyway).
                if paths::exists_probe(&abs.join(".git"))? {
                    return Ok(());
                }
                self.check_foreign_config(rel, &abs)?;
                return self.walk_dir(rel, &abs, origin, 0, Some(via));
            }
            // The entry itself may be a nested-repository root or hold a
            // foreign config (the domain root is exempt); ancestors were
            // checked above, children are checked during the walk.
            if !rel.is_empty() {
                self.check_boundary(rel, &abs)?;
            }
            return self.walk_dir(rel, &abs, origin, 0, None);
        }
        if ft.is_file() {
            if let Some(via) = excluded_via {
                let named = matches!(origin, Origin::Explicit { named: true });
                return self.add_excluded(rel, abs, named, via, &md);
            }
            return self.add_file(rel, abs, origin, &md);
        }
        // Symlink or special file (FIFO, socket, device). Under an
        // exclusion it is simply not the tool's business: not selected,
        // not warned about, and not recorded as unverified content (it
        // cannot hold ciphertext recoverable at this path).
        if excluded_via.is_some() {
            return Ok(());
        }
        let kind = if ft.is_symlink() {
            "a symlink"
        } else {
            "not a regular file"
        };
        match origin {
            Origin::Explicit { .. } => Err(Error::Usage(format!(
                "`{rel}` is {kind}; only regular files can be processed"
            ))),
            Origin::Managed => self.skip_special(
                rel.to_owned(),
                ft.is_symlink(),
                format!("skipping managed path `{rel}`: {kind}"),
            ),
        }
    }

    /// For a managed entry, requires that every intermediate directory
    /// between the root and the entry is a real directory (never a
    /// symlink) crossing no repository boundary and holding no foreign
    /// domain config. A stored entry is re-checked on every run: a
    /// directory replaced by a symlink since it was added must not
    /// redirect operations outside the domain.
    fn check_ancestors(&self, rel: &str) -> Result<()> {
        let mut dir = self.root.to_path_buf();
        let Some((parents, _last)) = rel.rsplit_once('/') else {
            return Ok(());
        };
        for comp in parents.split('/') {
            dir.push(comp);
            let md = match dir.symlink_metadata() {
                Ok(md) => md,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(()); // Missing prefix: handled as a missing entry.
                }
                Err(e) => return Err(Error::io("inspecting", &dir, e)),
            };
            let ft = md.file_type();
            if ft.is_symlink() {
                return Err(Error::Usage(format!(
                    "managed path `{rel}` passes through the symlink `{}`; \
                     refusing to follow it outside the domain",
                    report::escape_path(&dir)
                )));
            }
            if !ft.is_dir() {
                // Mirrors `add`'s "a file cannot cover them" conflict:
                // a clear error beats the raw ENOTDIR the entry's own
                // stat would otherwise produce.
                return Err(Error::Usage(format!(
                    "managed path `{rel}` passes through `{}`, which is not a directory; \
                     remove the entry or restore the directory",
                    report::escape_path(&dir)
                )));
            }
            self.check_boundary(rel, &dir)?;
        }
        Ok(())
    }

    /// Errors when `dir` (a directory below the root) is a nested
    /// repository or holds a foreign domain config.
    fn check_boundary(&self, rel: &str, dir: &Path) -> Result<()> {
        if paths::exists_probe(&dir.join(".git"))? {
            return Err(Error::Usage(format!(
                "`{rel}` lies inside the nested repository `{}`; it needs its own simple-file-encrypt domain",
                report::escape_path(dir)
            )));
        }
        self.check_foreign_config(rel, dir)
    }

    /// Errors when `dir` holds a foreign domain config. A structural
    /// domain violation, checked even under an exclusion.
    fn check_foreign_config(&self, _rel: &str, dir: &Path) -> Result<()> {
        if paths::exists_probe(&dir.join(CONFIG_NAME))? {
            return Err(Error::Usage(format!(
                "found a foreign `{CONFIG_NAME}` below the domain root, in `{}`; \
                 nested domains are not supported within one repository",
                report::escape_path(dir)
            )));
        }
        Ok(())
    }

    /// Records one regular file, deduplicating repeats.
    fn add_file(
        &mut self,
        rel: &str,
        abs: PathBuf,
        origin: Origin,
        md: &std::fs::Metadata,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let (named, explicit) = match origin {
            Origin::Managed => (false, false),
            Origin::Explicit { named } => (named, true),
        };
        if let Some(existing) = self.files.get_mut(rel) {
            existing.named |= named;
            existing.explicit |= explicit;
            return Ok(());
        }
        self.count += 1;
        if self.count > self.budgets.max_files {
            return Err(Error::Limit(format!(
                "more than {} files selected in one invocation",
                self.budgets.max_files
            )));
        }
        self.charge_path(rel.len())?;
        self.files.insert(
            rel.to_owned(),
            TargetFile {
                rel: rel.to_owned(),
                abs,
                named,
                explicit,
                nlink: md.nlink(),
            },
        );
        Ok(())
    }

    /// Recursively walks a directory, applying the skip rules. `depth`
    /// bounds recursion and every visited entry counts against the scan
    /// budget, so hostile trees cannot exhaust memory or time before
    /// the file cap applies. Entries are streamed, never collected: the
    /// final list order comes from `files` being a `BTreeMap`, so no
    /// per-directory name vector (or its sorting) is needed.
    ///
    /// `excluded_via` carries the covering `excludes` entry when this
    /// directory lies inside an exclusion. Beneath one, regular files
    /// are recorded as excluded instead of selected, and the strict
    /// name rules are relaxed: symlinks, special files, and names that
    /// are non-UTF-8 or contain control characters are ignored
    /// silently — they cannot hold ciphertext recoverable at their
    /// path, and exclusion already declares the content off-limits. A
    /// foreign domain config stays a hard error, and nested
    /// repositories are still never entered. Budgets apply unchanged.
    fn walk_dir(
        &mut self,
        rel: &str,
        abs: &Path,
        origin: Origin,
        depth: usize,
        excluded_via: Option<&'a str>,
    ) -> Result<()> {
        if depth > MAX_WALK_DEPTH {
            return Err(Error::Limit(format!(
                "`{rel}`: directory nesting exceeds the {MAX_WALK_DEPTH}-level cap"
            )));
        }
        self.add_sweep_dir(abs)?;
        // Children of an explicit directory are not "named".
        let child_origin = match origin {
            Origin::Managed => Origin::Managed,
            Origin::Explicit { .. } => Origin::Explicit { named: false },
        };
        for entry in std::fs::read_dir(abs).map_err(|e| Error::io("listing", abs, e))? {
            self.scanned += 1;
            if self.scanned > self.budgets.max_scanned {
                return Err(Error::Limit(format!(
                    "directory expansion examined more than {} entries",
                    self.budgets.max_scanned
                )));
            }
            let name = entry.map_err(|e| Error::io("listing", abs, e))?.file_name();
            let name_str = name.to_str().map(str::to_owned);
            let child_abs = abs.join(&name);
            let md = match child_abs.symlink_metadata() {
                Ok(md) => md,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(Error::io("inspecting", &child_abs, e)),
            };
            let child_rel = |name_str: &str| {
                if rel.is_empty() {
                    name_str.to_owned()
                } else {
                    format!("{rel}/{name_str}")
                }
            };
            // `.git` entries (files or directories) are always skipped.
            if name.as_os_str() == ".git" {
                continue;
            }
            if md.file_type().is_dir() {
                let Some(ns) = name_str else {
                    if excluded_via.is_some() {
                        continue;
                    }
                    return Err(Error::Usage(format!(
                        "`{}`: file name is not valid UTF-8",
                        report::escape_path(&child_abs)
                    )));
                };
                if excluded_via.is_some() {
                    if paths::has_control(&ns) {
                        continue;
                    }
                } else {
                    reject_control_name(&child_abs, &ns)?;
                }
                let crel = child_rel(&ns);
                // A subdirectory with a `.git` entry is a nested
                // repository: never entered (silently so under an
                // exclusion — nothing would be selected from it).
                if paths::exists_probe(&child_abs.join(".git"))? {
                    if excluded_via.is_none() {
                        report::note(format!("skipping nested repository `{crel}`"));
                    }
                    continue;
                }
                if paths::exists_probe(&child_abs.join(CONFIG_NAME))? {
                    return Err(Error::Usage(format!(
                        "found a foreign `{CONFIG_NAME}` below the domain root, in `{crel}`; \
                         nested domains are not supported within one repository"
                    )));
                }
                let child_via = excluded_via.or_else(|| self.exact_exclude(&crel));
                self.walk_dir(&crel, &child_abs, child_origin, depth + 1, child_via)?;
                continue;
            }
            // Non-directory entries with non-UTF-8 names cannot become
            // canonical paths (key derivation would have no stable
            // input); refuse rather than silently leave plaintext
            // behind — naming one explicitly already fails at minting.
            // Under an exclusion the plaintext is intentional, so such
            // names are tolerated and ignored instead.
            let Some(ns) = name_str else {
                if excluded_via.is_some() {
                    continue;
                }
                return Err(Error::Usage(format!(
                    "`{}`: file name is not valid UTF-8; simple-file-encrypt refuses such names",
                    report::escape_path(&child_abs)
                )));
            };
            if excluded_via.is_some() {
                if paths::has_control(&ns) {
                    continue;
                }
            } else {
                reject_control_name(&child_abs, &ns)?;
            }
            // The domain config itself, temp files, and git metadata
            // files are never processed.
            if rel.is_empty() && ns == CONFIG_NAME {
                continue;
            }
            if paths::is_temp_name(&ns) {
                continue;
            }
            if ns == ".gitattributes" || ns == ".gitmodules" {
                continue;
            }
            if ns == CONFIG_NAME {
                return Err(Error::Usage(format!(
                    "found a foreign `{CONFIG_NAME}` below the domain root, at `{}`; \
                     nested domains are not supported within one repository",
                    child_rel(&ns)
                )));
            }
            let crel = child_rel(&ns);
            let via = excluded_via.or_else(|| self.exact_exclude(&crel));
            if md.file_type().is_file() {
                match via {
                    Some(v) => self.add_excluded(&crel, child_abs, false, v, &md)?,
                    None => self.add_file(&crel, child_abs, child_origin, &md)?,
                }
            } else if via.is_some() {
                // Symlink or special file under an exclusion: hands-off.
            } else if md.file_type().is_symlink() {
                let msg = format!("skipping `{crel}`: a symlink");
                self.skip_special(crel, true, msg)?;
            } else {
                let msg = format!("skipping `{crel}`: not a regular file");
                self.skip_special(crel, false, msg)?;
            }
        }
        Ok(())
    }
}

/// A discovered name that contains a control character is a hard
/// error: it must never reach key derivation, the managed list, or the
/// output. Minting rejects such names for explicit arguments and
/// stored entries; recursion applies the same rule to discovered ones.
fn reject_control_name(abs: &Path, name: &str) -> Result<()> {
    if paths::has_control(name) {
        return Err(Error::Usage(format!(
            "`{}`: a file name contains a control character; simple-file-encrypt refuses such names",
            report::escape_path(abs)
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::TMP_PREFIX;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn expansion_skips_and_orders() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("b.txt"));
        touch(&root.join("a/z.txt"));
        touch(&root.join("a/y.txt"));
        touch(&root.join(CONFIG_NAME));
        touch(&root.join(".gitattributes"));
        touch(&root.join("a/.gitattributes"));
        touch(&root.join(format!("{TMP_PREFIX}stale00000000000")));
        std::fs::create_dir_all(root.join(".git")).unwrap();
        touch(&root.join(".git/config"));
        // Nested repository: skipped.
        touch(&root.join("vendor/.git"));
        touch(&root.join("vendor/secret.txt"));

        let exp = expand(
            root,
            &[(String::new(), Origin::Explicit { named: true })],
            &[],
        )
        .unwrap();
        let rels: Vec<&str> = exp.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["a/y.txt", "a/z.txt", "b.txt"]);
        assert!(exp.files.iter().all(|f| f.explicit && !f.named));
        assert!(exp.sweep_dirs.contains(&root.join("a")));
        // Targeting the root must never put the root's *parent* (outside
        // the domain) into the sweep set.
        assert!(!exp.sweep_dirs.contains(root.parent().unwrap()));
    }

    #[test]
    fn foreign_config_is_a_hard_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("sub/x.txt"));
        touch(&root.join("sub").join(CONFIG_NAME));
        let err = expand(root, &[(String::new(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("foreign"));
        // A managed entry reaching through it errors too.
        let err = expand(root, &[("sub/x.txt".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("foreign"));
    }

    #[test]
    fn managed_entry_inside_nested_repo_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("vendor/.git"));
        touch(&root.join("vendor/inner.txt"));
        let err = expand(root, &[("vendor/inner.txt".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("nested repository"));
        // The directory entry itself being a nested-repository root is
        // caught too, not only files beneath it.
        let err = expand(root, &[("vendor".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("nested repository"));
    }

    #[test]
    fn managed_entry_through_symlinked_ancestor_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"x").unwrap();
        std::fs::create_dir(root.join("managed")).unwrap();
        // Replace the directory with a symlink pointing outside.
        std::fs::remove_dir(root.join("managed")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("managed")).unwrap();

        // The stored entry must not be followed out of the domain.
        let err = expand(root, &[("managed/secret.txt".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("symlink"), "got: {err}");
        // A stored directory entry that is itself a symlink is skipped
        // with a warning and recorded, not walked.
        let exp = expand(root, &[("managed".into(), Origin::Managed)], &[]).unwrap();
        assert!(exp.files.is_empty());
        let skipped: Vec<&str> = exp.skipped_special.iter().map(|s| s.rel.as_str()).collect();
        assert_eq!(skipped, ["managed"]);
        assert!(exp.skipped_special[0].symlink);
    }

    #[test]
    fn discovered_control_char_names_are_hard_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("d/evil\nINJECTED"));
        // Recursion must not mint a control-char path into the file
        // list — neither via a managed directory nor an explicit one.
        let err = expand(root, &[("d".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("control character"), "got: {err}");
        let err = expand(root, &[("d".into(), Origin::Explicit { named: true })], &[]).unwrap_err();
        assert!(err.to_string().contains("control character"), "got: {err}");
    }

    #[test]
    fn managed_entry_through_file_ancestor_is_a_clear_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("a"));
        // A stored entry whose ancestor became a regular file must get
        // a clear conflict message, not a raw ENOTDIR I/O error.
        let err = expand(root, &[("a/b".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
        let err = expand(root, &[("a/b/c".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "got: {err}");
    }

    /// Small-budget variants: the enforcement logic is exercised with
    /// injected limits so no test needs a million-entry tree.
    fn tiny(max_files: usize, max_scanned: usize, max_path_bytes: usize) -> Budgets {
        Budgets {
            max_files,
            max_scanned,
            max_path_bytes,
        }
    }

    #[test]
    fn path_budget_covers_all_retained_paths() {
        let all = (String::new(), Origin::Managed);

        // Selected regular files are charged (canonical rel bytes).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let base = root.as_os_str().len();
        touch(&root.join("some-regular-file.txt"));
        let err = expand_with_budgets(
            root,
            std::slice::from_ref(&all),
            &[],
            tiny(usize::MAX, usize::MAX, base + 4),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path budget"), "got: {err}");

        // Visited directories are charged (absolute sweep-path bytes),
        // even when the tree holds no regular file at all.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let base = root.as_os_str().len();
        std::fs::create_dir_all(root.join("empty-but-deep/nested")).unwrap();
        let err = expand_with_budgets(
            root,
            std::slice::from_ref(&all),
            &[],
            tiny(usize::MAX, usize::MAX, base + 4),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path budget"), "got: {err}");

        // Skipped symlinks/specials are charged.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let base = root.as_os_str().len();
        std::os::unix::fs::symlink("/nonexistent", root.join("long-symlink-name")).unwrap();
        let err = expand_with_budgets(
            root,
            std::slice::from_ref(&all),
            &[],
            tiny(usize::MAX, usize::MAX, base + 4),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path budget"), "got: {err}");

        // Missing managed entries are charged.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let base = root.as_os_str().len();
        let err = expand_with_budgets(
            root,
            &[("missing-very-long-entry".into(), Origin::Managed)],
            &[],
            tiny(usize::MAX, usize::MAX, base + 4),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path budget"), "got: {err}");

        // Within budget, the same shapes succeed.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("ok.txt"));
        let exp = expand_with_budgets(root, &[all], &[], Budgets::DEFAULT).unwrap();
        assert_eq!(exp.files.len(), 1);
    }

    #[test]
    fn file_and_scan_budgets_are_enforced() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("a"));
        touch(&root.join("b"));
        touch(&root.join("c"));

        let all = (String::new(), Origin::Managed);
        let err = expand_with_budgets(
            root,
            std::slice::from_ref(&all),
            &[],
            tiny(2, usize::MAX, usize::MAX),
        )
        .unwrap_err();
        assert!(err.to_string().contains("more than 2 files"), "got: {err}");

        let err = expand_with_budgets(
            root,
            std::slice::from_ref(&all),
            &[],
            tiny(usize::MAX, 2, usize::MAX),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("more than 2 entries"),
            "got: {err}"
        );

        let exp = expand_with_budgets(root, &[all], &[], tiny(3, 3, usize::MAX)).unwrap();
        assert_eq!(exp.files.len(), 3);
    }

    #[test]
    fn special_warning_flood_is_capped_but_all_are_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for i in 0..(MAX_SPECIAL_WARNINGS + 5) {
            std::os::unix::fs::symlink("/nonexistent", root.join(format!("l{i:03}"))).unwrap();
        }
        // Every special is recorded for scans and rotation even though
        // only the first MAX_SPECIAL_WARNINGS were individually warned
        // about (stderr behavior is covered by the CLI tests).
        let exp = expand(root, &[(String::new(), Origin::Managed)], &[]).unwrap();
        assert_eq!(exp.skipped_special.len(), MAX_SPECIAL_WARNINGS + 5);
    }

    #[test]
    fn missing_and_dedup_and_hardlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("a/x.txt"));

        let exp = expand(
            root,
            &[
                ("a".into(), Origin::Managed),
                ("a/x.txt".into(), Origin::Explicit { named: true }),
                ("gone.txt".into(), Origin::Managed),
                ("gone2.txt".into(), Origin::Explicit { named: true }),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(exp.files.len(), 1);
        assert!(exp.files[0].named && exp.files[0].explicit);
        assert_eq!(exp.missing_managed, ["gone.txt"]);
        assert_eq!(exp.missing_explicit, ["gone2.txt"]);

        // Hard-linked pair under two canonical paths: error.
        std::fs::hard_link(root.join("a/x.txt"), root.join("a/link.txt")).unwrap();
        let err = expand(root, &[("a".into(), Origin::Managed)], &[]).unwrap_err();
        assert!(err.to_string().contains("same file"));
    }

    #[test]
    fn excludes_route_files_out_of_selection() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("keep.txt"));
        touch(&root.join("skip.txt"));
        touch(&root.join("sub/a.txt"));
        touch(&root.join("exdir/b.txt"));
        touch(&root.join("exdir/deeper/c.txt"));
        let excludes = ["exdir".to_owned(), "skip.txt".to_owned()];

        let exp = expand(
            root,
            &[(String::new(), Origin::Explicit { named: true })],
            &excludes,
        )
        .unwrap();
        let rels: Vec<&str> = exp.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["keep.txt", "sub/a.txt"]);
        let ex: Vec<(&str, &str)> = exp
            .excluded
            .iter()
            .map(|e| (e.rel.as_str(), e.via.as_str()))
            .collect();
        assert_eq!(
            ex,
            [
                ("exdir/b.txt", "exdir"),
                ("exdir/deeper/c.txt", "exdir"),
                ("skip.txt", "skip.txt"),
            ]
        );
        // Children reached through the root walk are not "named".
        assert!(exp.excluded.iter().all(|e| !e.named));
        // Excluded directories are still visited (their temps are swept).
        assert!(exp.sweep_dirs.contains(&root.join("exdir/deeper")));

        // A directly named excluded file is routed, flagged as named.
        let exp = expand(
            root,
            &[("skip.txt".into(), Origin::Explicit { named: true })],
            &excludes,
        )
        .unwrap();
        assert!(exp.files.is_empty());
        assert_eq!(exp.excluded.len(), 1);
        assert!(exp.excluded[0].named);

        // A named directory inside an exclusion is walked in excluded
        // mode: everything beneath it is excluded, nothing selected.
        let exp = expand(
            root,
            &[("exdir/deeper".into(), Origin::Explicit { named: true })],
            &excludes,
        )
        .unwrap();
        assert!(exp.files.is_empty());
        let ex: Vec<&str> = exp.excluded.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(ex, ["exdir/deeper/c.txt"]);
    }

    #[test]
    fn excluded_subtrees_relax_name_and_special_rules() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("exdir/ok.txt"));
        std::os::unix::fs::symlink("/nonexistent", root.join("exdir/link")).unwrap();
        // Non-UTF-8 and control-character names: hard errors during a
        // normal walk, tolerated and ignored beneath an exclusion.
        std::fs::write(
            root.join("exdir").join(OsStr::from_bytes(b"bad\xff.txt")),
            b"x",
        )
        .unwrap();
        touch(&root.join("exdir/evil\nname"));
        let excludes = ["exdir".to_owned()];

        let exp = expand(root, &[(String::new(), Origin::Managed)], &excludes).unwrap();
        assert!(exp.files.is_empty());
        // Only the clean regular file is recorded; the symlink and the
        // hostile names are silently ignored — in particular they never
        // reach `skipped_special`, so they cannot block `rekey --prune`.
        let ex: Vec<&str> = exp.excluded.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(ex, ["exdir/ok.txt"]);
        assert!(exp.skipped_special.is_empty());

        // The same names outside an exclusion stay hard errors.
        let err = expand(root, &[(String::new(), Origin::Managed)], &[]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("not valid UTF-8") || msg.contains("control character"),
            "got: {msg}"
        );

        // A named excluded symlink is a silent no-op, not the usual
        // "only regular files" error: exclusion means hands-off.
        let exp = expand(
            root,
            &[("exdir/link".into(), Origin::Explicit { named: true })],
            &excludes,
        )
        .unwrap();
        assert!(exp.files.is_empty() && exp.excluded.is_empty());
    }

    #[test]
    fn excluded_subtrees_keep_domain_boundaries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // A nested repository inside an exclusion is never entered.
        touch(&root.join("exdir/vendor/.git"));
        touch(&root.join("exdir/vendor/inner.txt"));
        touch(&root.join("exdir/ok.txt"));
        let excludes = ["exdir".to_owned()];
        let exp = expand(root, &[(String::new(), Origin::Managed)], &excludes).unwrap();
        let ex: Vec<&str> = exp.excluded.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(ex, ["exdir/ok.txt"]);
        // An excluded entry that is itself a nested-repository root is
        // silently skipped, not walked.
        let exp = expand(
            root,
            &[("exdir/vendor".into(), Origin::Explicit { named: true })],
            &["exdir".to_owned()],
        )
        .unwrap();
        assert!(exp.files.is_empty() && exp.excluded.is_empty());

        // A foreign domain config is a hard error even under an
        // exclusion: a structural violation, not an encryption choice.
        touch(&root.join("exdir/sub").join(CONFIG_NAME));
        let err = expand(root, &[(String::new(), Origin::Managed)], &excludes).unwrap_err();
        assert!(err.to_string().contains("foreign"), "got: {err}");
    }

    #[test]
    fn exclusion_uses_boundary_aware_coverage() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("ex/inner.txt"));
        touch(&root.join("extra.txt"));
        // `extra.txt` shares the byte prefix `ex` but is not covered.
        let exp = expand(
            root,
            &[(String::new(), Origin::Managed)],
            &["ex".to_owned()],
        )
        .unwrap();
        let rels: Vec<&str> = exp.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, ["extra.txt"]);
        let ex: Vec<&str> = exp.excluded.iter().map(|e| e.rel.as_str()).collect();
        assert_eq!(ex, ["ex/inner.txt"]);
    }

    #[test]
    fn excluded_paths_are_charged_against_budgets() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let base = root.as_os_str().len();
        touch(&root.join("exdir/some-long-excluded-name.txt"));
        let err = expand_with_budgets(
            root,
            &[(String::new(), Origin::Managed)],
            &["exdir".to_owned()],
            tiny(usize::MAX, usize::MAX, base + 8),
        )
        .unwrap_err();
        assert!(err.to_string().contains("path budget"), "got: {err}");
    }
}
