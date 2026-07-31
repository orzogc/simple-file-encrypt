//! Target selection: expanding managed entries and explicit arguments
//! into the deduplicated list of regular files one invocation operates
//! on, applying the skip and boundary rules of `docs/cli.md`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use crate::consts::{CONFIG_NAME, MAX_FILES_PER_OP, TMP_PREFIX};
use crate::error::{Error, Result};
use crate::report;

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
    /// Directories to sweep for stale temp files: the domain root, the
    /// parents of all entries, and every directory visited.
    pub sweep_dirs: BTreeSet<PathBuf>,
}

/// Expands entries (canonical relative paths tagged with their origin)
/// into the target file list. `""` denotes the domain root directory.
pub fn expand(root: &Path, entries: &[(String, Origin)]) -> Result<Expanded> {
    let mut exp = Expander {
        root,
        files: BTreeMap::new(),
        missing_managed: Vec::new(),
        missing_explicit: Vec::new(),
        sweep_dirs: BTreeSet::from([root.to_path_buf()]),
        count: 0,
    };
    for (rel, origin) in entries {
        exp.add_entry(rel, *origin)?;
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
        sweep_dirs: exp.sweep_dirs,
    })
}

/// Internal expansion state.
struct Expander<'a> {
    root: &'a Path,
    files: BTreeMap<String, TargetFile>,
    missing_managed: Vec<String>,
    missing_explicit: Vec<String>,
    sweep_dirs: BTreeSet<PathBuf>,
    count: usize,
}

impl Expander<'_> {
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
            self.sweep_dirs.insert(parent.to_path_buf());
        }
        if origin == Origin::Managed {
            self.check_ancestors(rel)?;
        }
        let md = match abs.symlink_metadata() {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match origin {
                    Origin::Managed => self.missing_managed.push(rel.to_owned()),
                    Origin::Explicit { .. } => self.missing_explicit.push(rel.to_owned()),
                }
                return Ok(());
            }
            Err(e) => return Err(Error::io("inspecting", &abs, e)),
        };
        let ft = md.file_type();
        if ft.is_dir() {
            // The entry itself may be a nested-repository root or hold a
            // foreign config (the domain root is exempt); ancestors were
            // checked above, children are checked during the walk.
            if !rel.is_empty() {
                self.check_boundary(rel, &abs)?;
            }
            return self.walk_dir(rel, &abs, origin);
        }
        if ft.is_file() {
            return self.add_file(rel, abs, origin, &md);
        }
        // Symlink or special file (FIFO, socket, device).
        let kind = if ft.is_symlink() {
            "a symlink"
        } else {
            "not a regular file"
        };
        match origin {
            Origin::Explicit { .. } => Err(Error::Usage(format!(
                "`{rel}` is {kind}; only regular files can be processed"
            ))),
            Origin::Managed => {
                report::warn(format!("skipping managed path `{rel}`: {kind}"));
                Ok(())
            }
        }
    }

    /// For a managed entry, requires that no intermediate directory
    /// between the root and the entry crosses a repository boundary or
    /// holds a foreign domain config.
    fn check_ancestors(&self, rel: &str) -> Result<()> {
        let mut dir = self.root.to_path_buf();
        let Some((parents, _last)) = rel.rsplit_once('/') else {
            return Ok(());
        };
        for comp in parents.split('/') {
            dir.push(comp);
            if !dir.is_dir() {
                return Ok(()); // Missing prefix: handled as a missing entry.
            }
            self.check_boundary(rel, &dir)?;
        }
        Ok(())
    }

    /// Errors when `dir` (a directory below the root) is a nested
    /// repository or holds a foreign domain config.
    fn check_boundary(&self, rel: &str, dir: &Path) -> Result<()> {
        if dir.join(".git").symlink_metadata().is_ok() {
            return Err(Error::Usage(format!(
                "`{rel}` lies inside the nested repository `{}`; it needs its own simple-encrypt domain",
                dir.display()
            )));
        }
        if dir.join(CONFIG_NAME).symlink_metadata().is_ok() {
            return Err(Error::Usage(format!(
                "found a foreign `{CONFIG_NAME}` below the domain root, in `{}`; \
                 nested domains are not supported within one repository",
                dir.display()
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
        if self.count > MAX_FILES_PER_OP {
            return Err(Error::Limit(format!(
                "more than {MAX_FILES_PER_OP} files selected in one invocation"
            )));
        }
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

    /// Recursively walks a directory in ascending name order, applying
    /// the skip rules.
    fn walk_dir(&mut self, rel: &str, abs: &Path, origin: Origin) -> Result<()> {
        self.sweep_dirs.insert(abs.to_path_buf());
        // Children of an explicit directory are not "named".
        let child_origin = match origin {
            Origin::Managed => Origin::Managed,
            Origin::Explicit { .. } => Origin::Explicit { named: false },
        };
        let mut names: Vec<std::ffi::OsString> = Vec::new();
        for entry in std::fs::read_dir(abs).map_err(|e| Error::io("listing", abs, e))? {
            names.push(entry.map_err(|e| Error::io("listing", abs, e))?.file_name());
        }
        names.sort_unstable();
        for name in names {
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
                    return Err(Error::Usage(format!(
                        "`{}`: file name is not valid UTF-8",
                        child_abs.display()
                    )));
                };
                let crel = child_rel(&ns);
                // A subdirectory with a `.git` entry is a nested
                // repository: never entered.
                if child_abs.join(".git").symlink_metadata().is_ok() {
                    report::note(format!("skipping nested repository `{crel}`"));
                    continue;
                }
                if child_abs.join(CONFIG_NAME).symlink_metadata().is_ok() {
                    return Err(Error::Usage(format!(
                        "found a foreign `{CONFIG_NAME}` below the domain root, in `{crel}`; \
                         nested domains are not supported within one repository"
                    )));
                }
                self.walk_dir(&crel, &child_abs, child_origin)?;
                continue;
            }
            // Non-directory entries with non-UTF-8 names cannot become
            // canonical paths; skip with a warning (explicitly naming
            // one fails at minting instead).
            let Some(ns) = name_str else {
                report::warn(format!(
                    "skipping `{}`: file name is not valid UTF-8",
                    child_abs.display()
                ));
                continue;
            };
            // The domain config itself, temp files, and git metadata
            // files are never processed.
            if rel.is_empty() && ns == CONFIG_NAME {
                continue;
            }
            if ns.starts_with(TMP_PREFIX) {
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
            if md.file_type().is_file() {
                self.add_file(&crel, child_abs, child_origin, &md)?;
            } else if md.file_type().is_symlink() {
                report::warn(format!("skipping `{crel}`: a symlink"));
            } else {
                report::warn(format!("skipping `{crel}`: not a regular file"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let exp = expand(root, &[(String::new(), Origin::Explicit { named: true })]).unwrap();
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
        let err = expand(root, &[(String::new(), Origin::Managed)]).unwrap_err();
        assert!(err.to_string().contains("foreign"));
        // A managed entry reaching through it errors too.
        let err = expand(root, &[("sub/x.txt".into(), Origin::Managed)]).unwrap_err();
        assert!(err.to_string().contains("foreign"));
    }

    #[test]
    fn managed_entry_inside_nested_repo_is_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        touch(&root.join("vendor/.git"));
        touch(&root.join("vendor/inner.txt"));
        let err = expand(root, &[("vendor/inner.txt".into(), Origin::Managed)]).unwrap_err();
        assert!(err.to_string().contains("nested repository"));
        // The directory entry itself being a nested-repository root is
        // caught too, not only files beneath it.
        let err = expand(root, &[("vendor".into(), Origin::Managed)]).unwrap_err();
        assert!(err.to_string().contains("nested repository"));
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
        )
        .unwrap();
        assert_eq!(exp.files.len(), 1);
        assert!(exp.files[0].named && exp.files[0].explicit);
        assert_eq!(exp.missing_managed, ["gone.txt"]);
        assert_eq!(exp.missing_explicit, ["gone2.txt"]);

        // Hard-linked pair under two canonical paths: error.
        std::fs::hard_link(root.join("a/x.txt"), root.join("a/link.txt")).unwrap();
        let err = expand(root, &[("a".into(), Origin::Managed)]).unwrap_err();
        assert!(err.to_string().contains("same file"));
    }
}
