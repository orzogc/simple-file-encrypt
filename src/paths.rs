//! Canonical relative paths and domain resolution (see `docs/format.md`
//! and `docs/cli.md`).
//!
//! A canonical relative path is minted once, when a path enters the
//! system; stored bytes are authoritative afterwards and feed key
//! derivation exactly as recorded.

use std::path::{Component, Path, PathBuf};

use crate::consts::{CONFIG_NAME, TMP_PREFIX, TMP_RAND_LEN};
use crate::error::{Error, Result};

/// File names that no command may touch and no config entry may claim.
const PROTECTED_FINAL: [&str; 3] = [".gitattributes", ".gitmodules", CONFIG_NAME];

/// Whether `s` contains a C0, DEL, or C1 control character. Such
/// characters are banned from canonical paths so a hostile file name
/// cannot inject lines or terminal sequences into the tool's output.
pub fn has_control(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        u < 0x20 || (0x7F..=0x9F).contains(&u)
    })
}

/// Whether `name` is exactly a tool temp-file name:
/// `.simple-file-encrypt.tmp.<16 alnum>`. Only exact matches are swept as
/// stale temps; lookalikes (`.simple-file-encrypt.tmp.notes`) are ordinary
/// user files.
pub fn is_temp_name(name: &str) -> bool {
    let Some(rand) = name.strip_prefix(TMP_PREFIX) else {
        return false;
    };
    rand.len() == TMP_RAND_LEN && rand.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Validates an already-canonical relative path (a stored config entry):
/// non-empty, `/`-separated, no leading/trailing `/`, no empty segments,
/// no `.` or `..` segments, no control characters.
pub fn validate_canonical(entry: &str) -> Result<(), String> {
    if entry.is_empty() {
        return Err("empty path".into());
    }
    if entry.starts_with('/') {
        return Err("absolute path".into());
    }
    if entry.ends_with('/') {
        return Err("trailing `/`".into());
    }
    for seg in entry.split('/') {
        match seg {
            "" => return Err("empty path segment".into()),
            "." | ".." => return Err(format!("`{seg}` segment")),
            _ => {}
        }
    }
    if has_control(entry) {
        return Err("contains a control character".into());
    }
    Ok(())
}

/// Returns why an entry may not be claimed or targeted, if it is a
/// tool- or git-critical path: any component named `.git`, or a final
/// component of `.gitattributes`, `.gitmodules`, or the domain config.
pub fn forbidden_reason(entry: &str) -> Option<String> {
    if entry.split('/').any(|seg| seg == ".git") {
        return Some("it contains a `.git` component".into());
    }
    let last = entry.rsplit('/').next().unwrap_or(entry);
    if PROTECTED_FINAL.contains(&last) {
        return Some(format!(
            "`{last}` must stay readable as plaintext for git and simple-file-encrypt"
        ));
    }
    if is_temp_name(last) {
        return Some("it is a simple-file-encrypt temp file".into());
    }
    None
}

/// Lexically normalizes `arg` against `cwd`: resolves `.`/`..` by path
/// arithmetic alone, never resolving symlinks.
pub fn lexical_absolute(cwd: &Path, arg: &Path) -> PathBuf {
    let joined = if arg.is_absolute() {
        arg.to_path_buf()
    } else {
        cwd.join(arg)
    };
    let mut out = PathBuf::new();
    for comp in joined.components() {
        match comp {
            Component::RootDir => out = PathBuf::from("/"),
            // Prefix is Windows-only (unsupported platform).
            Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
                if out.as_os_str().is_empty() {
                    out = PathBuf::from("/");
                }
            }
            Component::Normal(c) => out.push(c),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

/// Probes `path` for existence without following a final symlink:
/// `true` when it exists, `false` when it does not. Probe errors other
/// than `NotFound` (permissions, I/O) are propagated — boundary and
/// containment probes must fail closed, never silently degrade.
pub fn exists_probe(path: &Path) -> Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io("inspecting", path, e)),
    }
}

/// Walks up from `start` looking for the domain config, stopping at
/// repository boundaries: in each directory the config is looked for
/// first, then a `.git` entry (file or directory). Returns the domain
/// root, or `None` when the walk ends outside any domain.
pub fn discover_domain(start: &Path) -> Result<Option<PathBuf>> {
    let mut dir = start.to_path_buf();
    loop {
        if exists_probe(&dir.join(CONFIG_NAME))? {
            return Ok(Some(dir));
        }
        if exists_probe(&dir.join(".git"))? {
            return Ok(None);
        }
        if !dir.pop() {
            return Ok(None);
        }
    }
}

/// The directory domain resolution starts from for an explicit path
/// argument: the argument itself when it is a directory, otherwise its
/// parent (which is also the fallback for nonexistent arguments).
pub fn resolution_start(abs: &Path) -> Result<PathBuf> {
    match abs.symlink_metadata() {
        Ok(md) if md.file_type().is_dir() => Ok(abs.to_path_buf()),
        Ok(_) => Ok(parent_or_root(abs)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(parent_or_root(abs)),
        Err(e) => Err(Error::io("inspecting", abs, e)),
    }
}

/// The parent of `abs`, or `/` when it has none.
fn parent_or_root(abs: &Path) -> PathBuf {
    abs.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// Mints a canonical relative path from a lexically-normalized absolute
/// argument: requires containment in the domain root, rejects symlinks
/// anywhere in the path, and re-spells every existing component with the
/// filesystem-reported name (defusing case-insensitive volumes), keeping
/// the typed spelling for any missing suffix.
///
/// Returns `""` when `abs` is the domain root itself.
pub fn mint(root: &Path, abs: &Path) -> Result<String> {
    let rel = abs.strip_prefix(root).map_err(|_| {
        Error::Usage(format!(
            "`{}` lies outside the domain rooted at `{}`",
            crate::report::escape_path(abs),
            crate::report::escape_path(root)
        ))
    })?;
    let mut canonical = String::new();
    let mut cur = root.to_path_buf();
    let mut missing = false;
    for comp in rel.components() {
        let Component::Normal(typed) = comp else {
            return Err(Error::Usage(format!(
                "`{}`: unexpected path component after normalization",
                crate::report::escape_path(abs)
            )));
        };
        let typed = typed
            .to_str()
            .ok_or_else(|| {
                Error::Usage(format!(
                    "`{}` is not valid UTF-8",
                    crate::report::escape_path(abs)
                ))
            })?
            .to_owned();
        let spelled = if missing {
            typed
        } else {
            let candidate = cur.join(&typed);
            match candidate.symlink_metadata() {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Not found: keep the typed spelling from here on.
                    missing = true;
                    typed
                }
                Err(e) => return Err(Error::io("inspecting", &candidate, e)),
                Ok(md) if md.file_type().is_symlink() => {
                    return Err(Error::Usage(format!(
                        "`{}` is or contains a symlink (`{}`); simple-file-encrypt refuses symlinked targets",
                        crate::report::escape_path(abs),
                        crate::report::escape_path(&candidate)
                    )));
                }
                Ok(md) => respell(&cur, &typed, &md)?,
            }
        };
        if has_control(&spelled) {
            return Err(Error::Usage(format!(
                "`{}`: a path component contains a control character; \
                 simple-file-encrypt refuses such names",
                crate::report::escape_path(abs)
            )));
        }
        if !canonical.is_empty() {
            canonical.push('/');
        }
        canonical.push_str(&spelled);
        cur.push(&spelled);
    }
    Ok(canonical)
}

/// Re-spells one existing component with the name the filesystem
/// reports for it: byte-exact when the directory listing contains the
/// typed name, otherwise the listed name with the same `(device,
/// inode)` (a case-insensitive alias). Falls back to the typed spelling
/// if enumeration cannot find it (e.g. a race).
fn respell(dir: &Path, typed: &str, md: &std::fs::Metadata) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    let entries = std::fs::read_dir(dir).map_err(|e| Error::io("listing", dir, e))?;
    let mut alias: Option<String> = None;
    for entry in entries {
        let entry = entry.map_err(|e| Error::io("listing", dir, e))?;
        let name = entry.file_name();
        if name.as_os_str().as_encoded_bytes() == typed.as_bytes() {
            return Ok(typed.to_owned());
        }
        if alias.is_none()
            && let Ok(emd) = entry.path().symlink_metadata()
            && emd.dev() == md.dev()
            && emd.ino() == md.ino()
        {
            alias = Some(
                name.to_str()
                    .ok_or_else(|| {
                        Error::Usage(format!(
                            "`{}`: filesystem-reported name is not valid UTF-8",
                            crate::report::escape_path(dir)
                        ))
                    })?
                    .to_owned(),
            );
        }
    }
    Ok(alias.unwrap_or_else(|| typed.to_owned()))
}

/// Whether `path` equals `entry` or lies under it (lexical coverage;
/// directory-ness is resolved against the filesystem at use time).
pub fn is_covered_by(path: &str, entry: &str) -> bool {
    path == entry
        || (path.len() > entry.len()
            && path.starts_with(entry)
            && path.as_bytes()[entry.len()] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_validation() {
        assert!(validate_canonical("a").is_ok());
        assert!(validate_canonical("a/b/c.txt").is_ok());
        assert!(validate_canonical("").is_err());
        assert!(validate_canonical("/a").is_err());
        assert!(validate_canonical("a/").is_err());
        assert!(validate_canonical("a//b").is_err());
        assert!(validate_canonical("./a").is_err());
        assert!(validate_canonical("a/../b").is_err());
    }

    #[test]
    fn forbidden_entries() {
        assert!(forbidden_reason(".git/config").is_some());
        assert!(forbidden_reason("a/.git").is_some());
        assert!(forbidden_reason(".gitattributes").is_some());
        assert!(forbidden_reason("sub/.gitmodules").is_some());
        assert!(forbidden_reason(".simple-file-encrypt.toml").is_some());
        assert!(forbidden_reason("a/.simple-file-encrypt.toml").is_some());
        assert!(forbidden_reason(&format!("{TMP_PREFIX}0123456789abcdef")).is_some());
        assert!(forbidden_reason(".gitignore").is_none());
        assert!(forbidden_reason("a/gitattributes").is_none());
        assert!(forbidden_reason("git/a").is_none());
    }

    #[test]
    fn lexical_normalization() {
        let cwd = Path::new("/home/user/repo");
        assert_eq!(
            lexical_absolute(cwd, Path::new("a/b")),
            PathBuf::from("/home/user/repo/a/b")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("./a/./b")),
            PathBuf::from("/home/user/repo/a/b")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("a/../b")),
            PathBuf::from("/home/user/repo/b")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("../../x")),
            PathBuf::from("/home/x")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("/abs/p")),
            PathBuf::from("/abs/p")
        );
        assert_eq!(
            lexical_absolute(cwd, Path::new("../../../../../..")),
            PathBuf::from("/")
        );
    }

    #[test]
    fn domain_discovery_stops_at_git_boundary() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("repo/sub/deep")).unwrap();
        std::fs::write(root.join("repo").join(CONFIG_NAME), "x").unwrap();
        assert_eq!(
            discover_domain(&root.join("repo/sub/deep")).unwrap(),
            Some(root.join("repo"))
        );

        // A nested repository boundary (a `.git` file) ends the walk.
        std::fs::write(root.join("repo/sub/.git"), "gitdir: elsewhere").unwrap();
        assert_eq!(discover_domain(&root.join("repo/sub/deep")).unwrap(), None);
        // The config is looked for before `.git` in the same directory.
        std::fs::write(root.join("repo/sub").join(CONFIG_NAME), "x").unwrap();
        assert_eq!(
            discover_domain(&root.join("repo/sub/deep")).unwrap(),
            Some(root.join("repo/sub"))
        );
        // No config above and no boundary: outside any domain.
        assert_eq!(discover_domain(root).unwrap(), None);
    }

    #[test]
    fn minting_respells_and_rejects() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/file.txt"), "x").unwrap();

        assert_eq!(
            mint(root, &root.join("sub/file.txt")).unwrap(),
            "sub/file.txt"
        );
        assert_eq!(mint(root, root).unwrap(), "");
        // Missing suffix keeps the typed spelling.
        assert_eq!(
            mint(root, &root.join("sub/New.txt")).unwrap(),
            "sub/New.txt"
        );
        assert_eq!(
            mint(root, &root.join("ghost/dir/x")).unwrap(),
            "ghost/dir/x"
        );
        // Outside the root.
        assert!(mint(root, Path::new("/etc/passwd")).is_err());
        // Symlinks are rejected, both as final component and mid-path.
        std::os::unix::fs::symlink(root.join("sub/file.txt"), root.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("dirlink")).unwrap();
        assert!(mint(root, &root.join("link.txt")).is_err());
        assert!(mint(root, &root.join("dirlink/file.txt")).is_err());
    }

    #[test]
    fn coverage_is_boundary_aware() {
        assert!(is_covered_by("a/b", "a"));
        assert!(is_covered_by("a", "a"));
        assert!(!is_covered_by("ab", "a"));
        assert!(!is_covered_by("a", "a/b"));
    }
}
