//! Filesystem primitives: capped whole-file reads, the atomic
//! temp+rename replacement dance, domain-root locking, and stale
//! temp-file sweeping (see `docs/cli.md`).

use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

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
    /// Mode and link count are compared too: a hard link created (the
    /// other name would keep a stale alias) or a permission change (a
    /// concurrent `chmod` the restore step would silently undo)
    /// mid-operation fails the file instead of being papered over.
    pub fn matches(&self, other: &Snapshot) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
            && self.mode == other.mode
            && self.nlink == other.nlink
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
///
/// The open uses `O_NOFOLLOW` and the descriptor is required to be a
/// regular file, so a symlink, FIFO, or device fails fast instead of
/// blocking the read or streaming without end. The read itself is
/// bounded at `cap + 1` bytes: a file growing past the cap mid-read is
/// rejected before it can allocate beyond the cap.
pub fn read_capped(path: &Path, cap: u64, what: &str) -> Result<FileData> {
    let file = open_no_follow(path)?;
    let md = file
        .metadata()
        .map_err(|e| Error::io("inspecting", path, e))?;
    require_regular(path, &md, what)?;
    if md.size() > cap {
        return Err(Error::Limit(format!(
            "`{}`: {} is {} bytes, exceeding the {cap}-byte cap",
            report::escape_path(path),
            what,
            md.size()
        )));
    }
    let snap = Snapshot::of(&md);
    let mut content = Vec::with_capacity(md.size() as usize);
    // Read at most cap + 1 bytes: one byte past the cap proves the file
    // grew (or lied about its size) without an unbounded allocation.
    let mut limited = file.take(cap.saturating_add(1));
    limited
        .read_to_end(&mut content)
        .map_err(|e| Error::io("reading", path, e))?;
    if content.len() as u64 > cap {
        return Err(Error::Limit(format!(
            "`{}`: {} exceeds the {cap}-byte cap (it grew while being read)",
            report::escape_path(path),
            what
        )));
    }
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

/// Opens `path` read-only without following a symlinked final component
/// and without blocking on a FIFO (`O_NONBLOCK` returns immediately;
/// the caller's regular-file check then rejects it). `O_NONBLOCK` is a
/// no-op for the regular files that pass the check.
fn open_no_follow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::io("opening", path, e))
}

/// Requires the opened file to be a regular file: anything else (FIFO,
/// socket, device) must never be read as content.
fn require_regular(path: &Path, md: &Metadata, what: &str) -> Result<()> {
    if !md.file_type().is_file() {
        return Err(Error::Usage(format!(
            "`{}`: {} is not a regular file",
            report::escape_path(path),
            what
        )));
    }
    Ok(())
}

/// Reads at most `n` leading bytes of a regular file; enough for the
/// keyless ciphertext probe without pulling a large file into memory.
pub fn read_prefix(path: &Path, n: usize) -> Result<Vec<u8>> {
    let file = open_no_follow(path)?;
    let md = file
        .metadata()
        .map_err(|e| Error::io("inspecting", path, e))?;
    require_regular(path, &md, "probe target")?;
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

/// Generates a random temp-file name: `.simple-file-encrypt.tmp.<16 alnum>`.
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

/// The outcome of a committed rename (see [`atomic_replace`]): the new
/// content is visible; this reports how much of the post-commit work
/// succeeded so callers can decide what may depend on it.
#[derive(Debug)]
pub struct Replaced {
    /// Snapshot of the new file; `None` when even the read-back failed.
    pub snap: Option<Snapshot>,
    /// Whether every durability step (file fsync, directory fsync)
    /// succeeded. `false` means a crash may roll the rename back, so
    /// dependent writes must not proceed on the assumption it sticks.
    pub durable: bool,
}

/// Atomically replaces `path` with `content` via a `0600` temp file:
/// write, fsync, re-check that the target is still the file described
/// by `expect`, rename while still `0600`, restore the original
/// permission bits through the open descriptor, fsync again, fsync the
/// directory.
///
/// The rename is the commit point: a failure after it (chmod, fsync,
/// read-back) is a loud warning folded into the returned [`Replaced`],
/// not an error, because the content is already visible — reporting
/// the file as untouched would be a lie. Callers whose invariants
/// depend on durability (the config) must check `durable`.
pub fn atomic_replace(path: &Path, expect: &Snapshot, content: &[u8]) -> Result<Replaced> {
    let dir = path.parent().ok_or_else(|| {
        Error::Usage(format!(
            "`{}` has no parent directory",
            report::escape_path(path)
        ))
    })?;
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

    // Past the rename the content is committed; a failure below must
    // not be reported as if the file were still in its old state. Warn
    // loudly instead: permissions may be left at 0600 (too strict,
    // never too loose) and durability is uncertain until a later sync.
    if let Err(e) = file.set_permissions(Permissions::from_mode(expect.mode & 0o7777)) {
        report::warn(format!(
            "`{}` was replaced, but restoring its permission bits failed: {e}; \
             its permission bits are 0600 or stricter now (0600 masked by umask)",
            report::escape_path(path)
        ));
    }
    let mut durable = true;
    if let Err(e) = sync_committed_file(&file) {
        durable = false;
        report::warn(format!(
            "`{}` was replaced, but fsyncing it failed: {e}; a crash may lose the new content",
            report::escape_path(path)
        ));
    }
    if let Err(e) = sync_committed_dir(dir) {
        durable = false;
        report::warn(format!(
            "`{}` was replaced, but fsyncing its directory failed: {e}; a crash may lose the new content",
            report::escape_path(path)
        ));
    }
    let snap = match file.metadata() {
        Ok(md) => Some(Snapshot::of(&md)),
        Err(e) => {
            report::warn(format!(
                "`{}` was replaced, but reading its new state back failed: {e}",
                report::escape_path(path)
            ));
            None
        }
    };
    Ok(Replaced { snap, durable })
}

/// Post-commit fsync of the replaced file, with the test-only fault
/// injection point for the durability paths.
fn sync_committed_file(file: &File) -> std::io::Result<()> {
    if injected_sync_failure() {
        return Err(std::io::Error::other("injected fsync failure"));
    }
    file.sync_all()
}

/// Post-commit fsync of the containing directory, with the test-only
/// fault injection point for the durability paths.
fn sync_committed_dir(dir: &Path) -> Result<()> {
    if injected_sync_failure() {
        return Err(Error::io(
            "fsyncing directory",
            dir,
            std::io::Error::other("injected fsync failure"),
        ));
    }
    fsync_dir(dir)
}

/// Whether a post-commit sync should artificially fail (tests only).
/// Thread-local so parallel tests never inject into each other.
#[cfg(test)]
fn injected_sync_failure() -> bool {
    INJECT_SYNC_FAILURE.with(std::cell::Cell::get)
}

/// Always `false` in non-test builds: no injection machinery remains.
#[cfg(not(test))]
fn injected_sync_failure() -> bool {
    false
}

#[cfg(test)]
thread_local! {
    static INJECT_SYNC_FAILURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Arms (or disarms) artificial failure of the post-commit fsyncs on
/// the current thread, for durability-path tests.
#[cfg(test)]
pub(crate) fn set_injected_sync_failure(fail: bool) {
    INJECT_SYNC_FAILURE.with(|f| f.set(fail));
}

/// Creates `path` exclusively (`O_EXCL`) with the given content and
/// permission bits, fsyncing the file and its directory. Used by `init`.
/// A failure after creation removes the file: a half-written config
/// must not strand the directory (every later `init` would refuse it as
/// "already exists").
pub fn create_exclusive(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        Error::Usage(format!(
            "`{}` has no parent directory",
            report::escape_path(path)
        ))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Usage(format!("`{}` already exists", report::escape_path(path)))
            } else {
                Error::io("creating", path, e)
            }
        })?;
    // O_EXCL proves we created the file, so removing it on failure is
    // safe; the guard is disarmed only after everything is durable.
    let mut guard = TempGuard {
        path: path.to_path_buf(),
        armed: true,
    };
    file.write_all(content)
        .map_err(|e| Error::io("writing", path, e))?;
    file.sync_all()
        .map_err(|e| Error::io("fsyncing", path, e))?;
    fsync_dir(dir)?;
    guard.armed = false;
    Ok(())
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

/// Why a sweep directory is skipped without an error.
enum SweepSkip {
    /// Does not exist (or a component does not): nothing to sweep.
    Missing,
    /// Escapes the domain or crosses a symlink: sweeping it could
    /// delete files outside the domain. Reported as a warning.
    Unsafe,
    /// A component could not be inspected (permissions, I/O): stale
    /// temps may linger, so this is warned about, not silent.
    Unreadable(std::io::Error),
}

/// Verifies that `dir` is the domain root or a descendant of it
/// reachable through real directories only. A symlink anywhere between
/// the root and `dir` would redirect the sweep outside the domain.
fn check_sweep_dir(root: &Path, dir: &Path) -> std::result::Result<(), SweepSkip> {
    let Ok(rel) = dir.strip_prefix(root) else {
        return Err(SweepSkip::Unsafe);
    };
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        let Component::Normal(name) = comp else {
            return Err(SweepSkip::Unsafe);
        };
        cur.push(name);
        match cur.symlink_metadata() {
            Ok(md) if md.file_type().is_symlink() => return Err(SweepSkip::Unsafe),
            Ok(md) if md.file_type().is_dir() => {}
            // A non-directory component means `dir` cannot exist as a
            // directory: nothing to sweep.
            Ok(_) => return Err(SweepSkip::Missing),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SweepSkip::Missing);
            }
            Err(e) => return Err(SweepSkip::Unreadable(e)),
        }
    }
    Ok(())
}

/// Deletes stale temp files from the given directories (deduplicated):
/// entries whose names match the tool's temp namespace exactly
/// (`.simple-file-encrypt.tmp.<16 alnum>`). Directories must lie below
/// `root` without crossing a symlink. Failures are warnings, not
/// errors; the exclusive lock guarantees no live instance owns them.
pub fn sweep_temps<I: IntoIterator<Item = PathBuf>>(root: &Path, dirs: I) -> usize {
    let mut removed = 0;
    let unique: std::collections::BTreeSet<PathBuf> = dirs.into_iter().collect();
    for dir in unique {
        match check_sweep_dir(root, &dir) {
            Ok(()) => {}
            Err(SweepSkip::Missing) => continue,
            Err(SweepSkip::Unsafe) => {
                report::warn(format!(
                    "not sweeping `{}` for stale temp files: not a real directory below the domain root",
                    report::escape_path(&dir)
                ));
                continue;
            }
            Err(SweepSkip::Unreadable(e)) => {
                report::warn(format!(
                    "not sweeping `{}` for stale temp files: cannot inspect it: {e}",
                    report::escape_path(&dir)
                ));
                continue;
            }
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                report::warn(format!(
                    "cannot sweep `{}` for stale temp files: {e}",
                    report::escape_path(&dir)
                ));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    report::warn(format!(
                        "cannot fully list `{}` for stale temp files: {e}",
                        report::escape_path(&dir)
                    ));
                    continue;
                }
            };
            let is_temp = entry
                .file_name()
                .to_str()
                .is_some_and(crate::paths::is_temp_name);
            if !is_temp {
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
                    report::note(format!(
                        "removed stale temp file `{}`",
                        report::escape_path(&path)
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => report::warn(format!(
                    "cannot remove stale temp file `{}`: {e}",
                    report::escape_path(&path)
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

        let replaced = atomic_replace(&target, &read.snap, b"new").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&target).unwrap().mode() & 0o7777, 0o640);
        assert!(replaced.durable);
        assert_eq!(replaced.snap.expect("read-back succeeds").size, 3);

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
    fn post_commit_sync_failure_marks_the_outcome_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t.txt");
        std::fs::write(&target, b"old").unwrap();
        let read = read_capped(&target, 1024, "file").unwrap();

        set_injected_sync_failure(true);
        let replaced = atomic_replace(&target, &read.snap, b"new").unwrap();
        set_injected_sync_failure(false);

        // The rename committed; only durability is unconfirmed.
        assert!(!replaced.durable);
        assert!(replaced.snap.is_some());
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
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
    fn sweep_removes_only_exact_temp_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let keep = root.join("keep.txt");
        let tmp = root.join(format!("{TMP_PREFIX}abcdef0123456789"));
        // Lookalikes outside the exact namespace must survive.
        let short = root.join(format!("{TMP_PREFIX}abc"));
        let long = root.join(format!("{TMP_PREFIX}abcdef0123456789ff"));
        let notes = root.join(format!("{TMP_PREFIX}notes"));
        let punct = root.join(format!("{TMP_PREFIX}abcdef012345678!"));
        for p in [&keep, &tmp, &short, &long, &notes, &punct] {
            std::fs::write(p, b"x").unwrap();
        }
        assert_eq!(sweep_temps(root, [root.to_path_buf()]), 1);
        assert!(!tmp.exists());
        for p in [&keep, &short, &long, &notes, &punct] {
            assert!(p.exists(), "{} must survive the sweep", p.display());
        }
    }

    #[test]
    fn sweep_never_follows_symlinked_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(root.join("managed")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let stray = outside.join(format!("{TMP_PREFIX}abcdef0123456789"));
        std::fs::write(&stray, b"x").unwrap();
        // Replace the real directory with a symlink pointing outside.
        std::fs::remove_dir(root.join("managed")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("managed")).unwrap();

        assert_eq!(sweep_temps(&root, [root.join("managed")]), 0);
        assert!(stray.exists(), "the sweep must not follow the symlink");
        // The root itself is still swept.
        std::fs::write(root.join(format!("{TMP_PREFIX}abcdef0123456789")), b"x").unwrap();
        assert_eq!(sweep_temps(&root, [root.clone()]), 1);
    }

    #[test]
    fn read_capped_rejects_symlinks_and_non_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("t");
        std::fs::write(&target, b"data").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_capped(&link, 1024, "file").is_err());
        assert!(read_prefix(&link, 16).is_err());
        // A directory is not a regular file either.
        assert!(read_capped(dir.path(), 1024, "file").is_err());
    }

    #[test]
    fn snapshot_matches_covers_mode_and_links() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap();
        // Pin the baseline permissions: `fs::write` honors the umask,
        // and a 0o?77 umask would otherwise make the later chmod a
        // no-op.
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        let snap = |p: &Path| Snapshot::of(&std::fs::symlink_metadata(p).unwrap());
        let base = snap(&path);
        assert!(base.matches(&snap(&path)));

        // A concurrent chmod must fail the freshness check: the
        // restore step would otherwise silently undo it.
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        assert!(!base.matches(&snap(&path)));
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

        // A hard link created mid-operation must fail it too: the new
        // name would keep a stale alias after the rename.
        let taken = snap(&path);
        std::fs::hard_link(&path, dir.path().join("l")).unwrap();
        assert!(!taken.matches(&snap(&path)));
    }

    /// `/proc` files report size 0 but yield content: they exercise the
    /// bounded read and the growth-detection branch.
    #[cfg(target_os = "linux")]
    #[test]
    fn read_capped_bounds_files_that_grow_while_reading() {
        let proc = Path::new("/proc/self/status");
        // Reports size 0 (<= cap) but yields far more than 16 bytes:
        // the bounded read must trip the cap, not allocate freely.
        let err = read_capped(proc, 16, "file").err().expect("must fail");
        assert!(matches!(err, Error::Limit(_)), "got: {err}");
        // With a generous cap the drift is caught by the size check.
        let err = read_capped(proc, u64::MAX, "file")
            .err()
            .expect("must fail");
        assert!(err.to_string().contains("changed size"), "got: {err}");
    }
}
