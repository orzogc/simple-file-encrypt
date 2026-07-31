//! Filesystem primitives: capped whole-file reads, the atomic
//! temp+rename replacement dance, domain-root locking, and stale
//! temp-file sweeping (see `docs/cli.md`).

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::consts::{TMP_PREFIX, TMP_RAND_LEN};
use crate::error::{Error, Result};
use crate::report;

/// Identity and freshness of a file at read time, re-checked before the
/// rename that replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Size in bytes.
    pub size: u64,
    /// Modification time (seconds, nanoseconds).
    pub mtime: (i64, i64),
    /// Full `st_mode` (permission bits are restored after rename).
    pub mode: u32,
    /// Hard-link count.
    pub nlink: u64,
}

impl Snapshot {
    /// Captures a snapshot from stat metadata.
    pub fn of(md: &Metadata) -> Snapshot {
        Snapshot {
            dev: md.dev(),
            ino: md.ino(),
            size: md.size(),
            mtime: (md.mtime(), md.mtime_nsec()),
            mode: md.mode(),
            nlink: md.nlink(),
        }
    }

    /// Whether the file is still the one this snapshot was taken of.
    fn matches(&self, other: &Snapshot) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
    }
}

/// A whole file read into memory together with its snapshot.
pub struct FileData {
    /// The file content.
    pub content: Vec<u8>,
    /// Identity/freshness at read time.
    pub snap: Snapshot,
}

/// Reads a regular file whole, enforcing a size cap (violations are
/// errors, not truncations) and detecting concurrent modification
/// during the read.
pub fn read_capped(path: &Path, cap: u64, what: &str) -> Result<FileData> {
    let mut file = File::open(path).map_err(|e| Error::io("opening", path, e))?;
    let md = file
        .metadata()
        .map_err(|e| Error::io("inspecting", path, e))?;
    if md.size() > cap {
        return Err(Error::Limit(format!(
            "`{}`: {} is {} bytes, exceeding the {cap}-byte cap",
            path.display(),
            what,
            md.size()
        )));
    }
    let snap = Snapshot::of(&md);
    let mut content = Vec::with_capacity(md.size() as usize);
    file.read_to_end(&mut content)
        .map_err(|e| Error::io("reading", path, e))?;
    if content.len() as u64 != snap.size {
        return Err(Error::io(
            "reading",
            path,
            std::io::Error::other(
                "file changed size while being read; retry when nothing else is writing it",
            ),
        ));
    }
    Ok(FileData { content, snap })
}

/// Reads at most `n` leading bytes of a file; enough for the keyless
/// ciphertext probe without pulling a large file into memory.
pub fn read_prefix(path: &Path, n: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| Error::io("opening", path, e))?;
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    let mut handle = file.take(n as u64);
    loop {
        match handle.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Error::io("reading", path, e)),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Generates a random temp-file name: `.simple-encrypt.tmp.<16 alnum>`.
fn random_temp_name() -> Result<String> {
    const ALPHABET: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::with_capacity(TMP_PREFIX.len() + TMP_RAND_LEN);
    name.push_str(TMP_PREFIX);
    let mut picked = 0;
    while picked < TMP_RAND_LEN {
        // Rejection sampling keeps the choice unbiased.
        for byte in crate::crypto::random_array::<32>()?.iter() {
            if *byte < 248 {
                name.push(ALPHABET[(byte % 62) as usize] as char);
                picked += 1;
                if picked == TMP_RAND_LEN {
                    break;
                }
            }
        }
    }
    Ok(name)
}

/// Deletes the temp file on drop unless disarmed after a successful
/// rename.
struct TempGuard {
    path: PathBuf,
    armed: bool,
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Creates a fresh `0600` temp file in `dir` with `O_EXCL | O_NOFOLLOW`.
fn create_temp(dir: &Path) -> Result<(File, TempGuard)> {
    loop {
        let candidate = dir.join(random_temp_name()?);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&candidate)
        {
            Ok(file) => {
                return Ok((
                    file,
                    TempGuard {
                        path: candidate,
                        armed: true,
                    },
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::io("creating temp file", candidate, e)),
        }
    }
}

/// Fsyncs a directory so a rename inside it is durable.
fn fsync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).map_err(|e| Error::io("opening directory", dir, e))?;
    d.sync_all()
        .map_err(|e| Error::io("fsyncing directory", dir, e))
}

/// Atomically replaces `path` with `content` via a `0600` temp file:
/// write, fsync, re-check that the target is still the file described
/// by `expect`, rename while still `0600`, restore the original
/// permission bits through the open descriptor, fsync again, fsync the
/// directory. Returns the new file's snapshot.
pub fn atomic_replace(path: &Path, expect: &Snapshot, content: &[u8]) -> Result<Snapshot> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::Usage(format!("`{}` has no parent directory", path.display())))?;
    let (mut file, guard) = create_temp(dir)?;
    file.write_all(content)
        .map_err(|e| Error::io("writing temp file", &guard.path, e))?;
    file.sync_all()
        .map_err(|e| Error::io("fsyncing temp file", &guard.path, e))?;

    // Re-check immediately before the rename that the target was not
    // concurrently modified; fail this file instead of destroying the
    // concurrent change. Best-effort: a race within the window remains.
    let current = std::fs::symlink_metadata(path).map_err(|e| Error::io("re-checking", path, e))?;
    if !expect.matches(&Snapshot::of(&current)) {
        return Err(Error::io(
            "replacing",
            path,
            std::io::Error::other(
                "the file was modified by another program mid-operation; not overwriting it",
            ),
        ));
    }

    std::fs::rename(&guard.path, path)
        .map_err(|e| Error::io("renaming temp file over", path, e))?;
    let mut guard = guard;
    guard.armed = false;

    // Restore the original permission bits only after the rename, so a
    // crash leaves permissions too strict, never too loose.
    file.set_permissions(Permissions::from_mode(expect.mode & 0o7777))
        .map_err(|e| Error::io("restoring permissions of", path, e))?;
    file.sync_all()
        .map_err(|e| Error::io("fsyncing", path, e))?;
    fsync_dir(dir)?;
    Ok(Snapshot::of(
        &file
            .metadata()
            .map_err(|e| Error::io("inspecting", path, e))?,
    ))
}

/// Creates `path` exclusively (`O_EXCL`) with the given content and
/// permission bits, fsyncing the file and its directory. Used by `init`.
pub fn create_exclusive(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| Error::Usage(format!("`{}` has no parent directory", path.display())))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Usage(format!("`{}` already exists", path.display()))
            } else {
                Error::io("creating", path, e)
            }
        })?;
    file.write_all(content)
        .map_err(|e| Error::io("writing", path, e))?;
    file.sync_all()
        .map_err(|e| Error::io("fsyncing", path, e))?;
    fsync_dir(dir)
}

/// An advisory lock on the domain root directory, held for the life of
/// the command. The directory is never renamed by the tool, so the lock
/// stays valid across config rewrites.
pub struct DirLock {
    _file: File,
}

/// Takes a non-blocking advisory `flock` on the domain root directory:
/// exclusive for writers, shared for pure readers.
pub fn lock_dir(root: &Path, exclusive: bool) -> Result<DirLock> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(root)
        .map_err(|e| Error::io("opening domain root", root, e))?;
    let res = if exclusive {
        file.try_lock()
    } else {
        file.try_lock_shared()
    };
    match res {
        Ok(()) => Ok(DirLock { _file: file }),
        Err(std::fs::TryLockError::WouldBlock) => Err(Error::Locked {
            root: root.to_path_buf(),
        }),
        Err(std::fs::TryLockError::Error(e)) => Err(Error::io("locking domain root", root, e)),
    }
}

/// Deletes stale `.simple-encrypt.tmp.*` files from the given
/// directories (deduplicated). Failures are warnings, not errors; the
/// exclusive lock guarantees no live instance owns them.
pub fn sweep_temps<I: IntoIterator<Item = PathBuf>>(dirs: I) -> usize {
    let mut removed = 0;
    let unique: std::collections::BTreeSet<PathBuf> = dirs.into_iter().collect();
    for dir in unique {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                report::warn(format!(
                    "cannot sweep `{}` for stale temp files: {e}",
                    dir.display()
                ));
                continue;
            }
        };
        for entry in entries.flatten() {
            if !entry.file_name().to_string_lossy().starts_with(TMP_PREFIX) {
                continue;
            }
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                continue;
            }
            let path = entry.path();
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    removed += 1;
                    report::note(format!("removed stale temp file `{}`", path.display()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => report::warn(format!(
                    "cannot remove stale temp file `{}`: {e}",
                    path.display()
                )),
            }
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_replace_preserves_permissions_and_rejects_races() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.txt");
        std::fs::write(&target, b"old").unwrap();
        std::fs::set_permissions(&target, Permissions::from_mode(0o640)).unwrap();
        let read = read_capped(&target, 1024, "file").unwrap();

        let snap = atomic_replace(&target, &read.snap, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o640);
        assert_eq!(snap.size, 3);

        // A concurrent modification after the read fails the replace.
        let read = read_capped(&target, 1024, "file").unwrap();
        std::fs::write(&target, b"concurrent change").unwrap();
        let err = atomic_replace(&target, &read.snap, b"lost update").unwrap_err();
        assert!(err.to_string().contains("modified by another program"));
        assert_eq!(std::fs::read(&target).unwrap(), b"concurrent change");
        // No temp file leaks.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn read_capped_enforces_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("big");
        std::fs::write(&target, vec![0u8; 100]).unwrap();
        assert!(read_capped(&target, 99, "file").is_err());
        assert!(read_capped(&target, 100, "file").is_ok());
    }

    #[test]
    fn dir_lock_excludes_second_instance() {
        let dir = tempfile::tempdir().unwrap();
        let _shared1 = lock_dir(dir.path(), false).unwrap();
        let _shared2 = lock_dir(dir.path(), false).unwrap();
        assert!(matches!(
            lock_dir(dir.path(), true),
            Err(Error::Locked { .. })
        ));
        drop((_shared1, _shared2));
        let _excl = lock_dir(dir.path(), true).unwrap();
        assert!(matches!(
            lock_dir(dir.path(), false),
            Err(Error::Locked { .. })
        ));
    }

    #[test]
    fn sweep_removes_only_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep.txt");
        let tmp = dir.path().join(format!("{TMP_PREFIX}abcdef0123456789"));
        std::fs::write(&keep, b"k").unwrap();
        std::fs::write(&tmp, b"t").unwrap();
        assert_eq!(sweep_temps([dir.path().to_path_buf()]), 1);
        assert!(keep.exists());
        assert!(!tmp.exists());
    }
}
