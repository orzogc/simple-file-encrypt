# simple-encrypt — CLI Semantics

Binary name: `simple-encrypt`. Subcommands: `init`, `encrypt` (`e`),
`decrypt` (`d`), `add`, `remove`, `status`, `check`, `verify`,
`passwd` (`p`), `rekey`.

Human-readable progress goes to stdout, errors and warnings to stderr.
Output is line-oriented and stable enough for scripting, but not a
promised machine interface.

## Domain resolution

Every command except `init` locates the **domain config** by walking up
from a starting directory until a `.simple-encrypt.toml` is found:

- with explicit path arguments: from the argument itself when it is a
  directory, otherwise from its parent directory (so `encrypt .` at the
  domain root finds the root's own config);
- without arguments: from the current working directory.

The walk stops at repository boundaries: in each directory the config
is looked for first, then a `.git` entry (file or directory) — a
directory that has a `.git` but no config ends the walk with "outside
any domain". A domain therefore never spans into a nested repository
(a submodule needs its own `init`), and a config lying outside the
repository that contains the target is never picked up — the config
must live in the same repository as its ciphertext.

All targets of one invocation must resolve to the **same** domain; mixing
domains is an error. A target outside any domain is an error. Explicit
arguments must lie inside the domain root after canonicalization
(containment checks are lexical; spellings come from directory
enumeration — see [format.md](format.md)); an explicit argument that is
a symlink — or any of whose components is detected to be one — is an
error. The discovered domain root itself must not be a symlink either,
and neither may any component the explicit argument introduced between
the working directory and that root (a hostile checkout can plant such
a link); only the root's ancestors *above* the working directory — the
user's own environment, such as a symlinked home directory or `/tmp` —
are trusted unchecked. Managed
entries from the config are re-checked on every run: if any directory
between the domain root and a stored entry has become a symlink, the
command refuses to follow it instead of operating outside the domain.

Nested domains are rejected within one repository: `init` refuses when
the current directory, an ancestor, or a descendant directory already
has a config — the ancestor scan follows the same repository-boundary
rule as domain resolution (it stops where the walk above stops), and
the descendant scan does not enter nested repositories, so a config
outside the current repository never blocks `init` (a submodule gets
its own domain). Traversal treats a foreign `.simple-encrypt.toml`
below the domain root as a hard error.

## Locking

Commands take an advisory `flock` on the **domain root directory** (an
`O_DIRECTORY` descriptor; no lock file, nothing to commit or ignore):
exclusive for anything that may write — `encrypt`, `decrypt`, `add`,
`remove`, `passwd`, `rekey` — and shared for pure readers — `status`,
`check`, `verify`. The directory is never renamed by the tool, so the
lock stays valid across config rewrites (a lock on the config file
itself would be stranded on the old inode the moment the file is
rename-replaced). The lock is non-blocking: if another instance holds
it, the command fails with a clear message. `init` creates the config
with `O_EXCL`, and inside a repository additionally takes the exclusive
lock on the **repository root** across its nesting re-check and the
create, so two concurrent `init`s (e.g. one in a parent directory, one
in a child) cannot both succeed and create nested domains; outside a
repository there is no shared lock point and that residual race is
accepted. Advisory locks may be ineffective on
some network filesystems; do not run concurrent instances there. The
lock excludes other simple-encrypt instances only — see the
mid-operation re-validation below for other programs.

## Password input

`encrypt`, `decrypt`, `verify`, `passwd`, `rekey`, and `init` need the
password — `encrypt` and `decrypt` only when at least one regular file
is selected (their nothing-to-do contract below); `add`, `remove`,
`status`, and `check` never do.

Sources, in priority order:

1. `SIMPLE_ENCRYPT_PASSWORD` environment variable (may be visible to
   other same-user processes via `/proc`;
   see [threat-model.md](threat-model.md));
2. interactive prompt without echo when stdin is a TTY — `init` and the
   new password of `passwd` are prompted twice and must match;
3. otherwise the first line of stdin (trailing newline stripped, no
   confirmation) — for pipes and scripts.

`passwd` needs two passwords. The old one comes from the sources above;
the new one comes from `SIMPLE_ENCRYPT_NEW_PASSWORD` when set, otherwise
it is prompted twice on a TTY, otherwise it is read as the next line of
stdin (a script pipes both passwords on two lines). A password that
cannot be obtained from any source is an error.

Passwords must be valid UTF-8, non-empty, at most 4096 bytes, and are
used as the exact bytes supplied — no Unicode normalization
(see [crypto.md](crypto.md)). The stdin reader is itself bounded: it
stops just past the limit instead of buffering an unbounded stream
first. The password is checked by unwrapping the key ring before any
selected file's content is read or replaced; target expansion
(directory listings and file metadata only) and stale-temp sweeping
run earlier. A mismatch aborts immediately.

KDF-related global options, honored by every command that runs Argon2:
`--allow-weak-kdf` and `--allow-expensive-kdf`
(see [crypto.md](crypto.md) for the tiers).

## File selection

- **Managed paths** (`paths` in the config) may be files or directories;
  directories are expanded recursively at run time. One invocation
  operates on at most 65536 files after expansion (hard error beyond).
  Traversal itself is budgeted too: at most 2^20 directory entries
  examined per expansion (and per `init` descendant scan), at most
  128 levels of nesting, and at most 64 MiB of retained path bytes —
  selected files, visited directories, skipped symlinks/specials, and
  missing entries all count — so hostile trees cannot exhaust memory
  or time before the file cap applies.
- Canonical paths never contain control characters (see
  [format.md](format.md)); a target or recursively discovered name
  containing one is a hard error, and any path the tool prints is
  control-character-escaped regardless. The same hard error applies to
  a name that is not valid UTF-8 at all: it cannot feed key derivation,
  so it is refused rather than skipped — never silently left as
  plaintext behind an otherwise-passing gate.
- Only **regular files** are processed. During recursion, FIFOs,
  sockets, device nodes, and symlinks are skipped with a warning
  (individual warnings are capped at a small number per run; a longer
  tail is summarized in one line); naming one explicitly is an error.
- Any directory entry named `.git` — file or directory (linked
  worktrees and submodules use a `.git` *file*) — is always skipped and
  cannot be named explicitly. A **subdirectory** containing a `.git`
  entry is a nested-repository boundary: recursion and `init`'s
  descendant scan do not enter it (noted), and explicit arguments
  inside it resolve to no domain (domain resolution stops at repository
  boundaries — see above). The domain root itself is exempt, so a
  domain rooted in a linked worktree works.
- During expansion the tool also skips the domain config itself, temp
  files, and any file named `.gitattributes` or `.gitmodules` — git
  must read those as plaintext, and encrypting `.gitattributes` would
  destroy the very `-text` protection the ciphertext depends on.
  Explicitly naming the domain config, a `.gitattributes`, or a
  `.gitmodules` is an error. The temp-file namespace is exactly
  `.simple-encrypt.tmp.<16 alphanumeric characters>`: such names are
  reserved to the tool (skipped, swept when stale, refused as targets);
  merely similar names are ordinary user files.
- After expansion, targets with the same canonical path (a file named
  directly and again via a covering directory entry) are silently
  deduplicated. Two *different* canonical paths resolving to the same
  `(device, inode)` — hard-linked pairs, case-insensitive aliases — are
  an error.
- A file about to be encrypted (or migrated) is refused when its link
  count is greater than 1: after the rename the other hard links would
  silently keep a stale alias — plaintext when encrypting, old-epoch
  ciphertext (invisible to `rekey --prune`'s convergence check) when
  migrating. `decrypt` only warns in the mirror case.
- `force_binary` applies to a file when its canonical relative path
  equals an entry or is under a directory entry.

### Encrypt-time bookkeeping (auto-add)

`encrypt` with explicit arguments also works on files that are not yet
managed. Every such **file** is added to `paths` in a single atomic
config rewrite *before* any file is encrypted — so an interruption can
never leave an encrypted file untracked, and a directory of new files
costs one rewrite instead of one per file. A file registered but never
reached (the run aborts early) is simply managed plaintext. This keeps
the managed list the source of truth for `status`, `check`, `verify`,
and `rekey`, which must be able to find every encrypted file.
Directories passed explicitly are expanded to files; the directory
itself is not added.

### Probe, skip, migration, and collision rules

For each candidate file, `encrypt` branches on the probe
(see [format.md](format.md)):

- **Content starts with `BIN_MAGIC`**: authenticate the first chunk
  against the key ring. Success under the current key → already
  encrypted, skip. Success under an older ring key → **migrate**
  (below). Failure → hard error: foreign ciphertext, corrupted, moved
  from another path — or plaintext that happens to begin with
  `BIN_MAGIC` (see `--assume-plaintext`).
- **First line starts with `#simple-encrypt`**: a first line that is
  not an exact v1 header form is a hard error — ciphertext from a
  newer tool, or colliding plaintext; version fail-closed is never
  relaxed implicitly. For an exact v1 header, authenticate the
  empty-file marker or the first unit line against the ring: current
  key and the stored mode matches the configured one → skip; older
  ring key, or a text-mode file now matched by `force_binary` →
  **migrate**; failure (including a bare header with no units) → hard
  error listing the possible causes.
- **No probe hit**: pick the mode (`force_binary` → binary; content
  contains NUL → binary; else text) and encrypt.

**Migration** re-encrypts a file that is valid ciphertext but not in
its target state: it is decrypted in memory and re-encrypted under the
current key and the currently configured mode, via the usual atomic
replace — plaintext never touches the disk. This is how old-key
ciphertext converges after a `rekey` and how a file newly added to
`force_binary` changes mode. (The reverse mode change is not detected
automatically: a binary-mode ciphertext may be legitimately binary, so
removing a `force_binary` entry takes effect the next time the file is
decrypted and re-encrypted.)

`encrypt --assume-plaintext <PATHS…>` is the explicit, dangerous escape
hatch for the collision errors above: for files named on the command
line (never for managed-list expansion), a probe hit that **fails**
authentication is treated as plaintext and encrypted normally. A
successful authentication is never overridden — valid ciphertext of
this domain cannot be double-encrypted. This is also the only way to
manage plaintext that genuinely starts with `BIN_MAGIC` or a
`#simple-encrypt` line.

The authentication check on skipped files costs one SIV verification
per ring key tried, not a full decryption.

`decrypt` ignores `force_binary` (the mode comes from the ciphertext):
no probe hit → skip with a note (or a hard error under
`--require-encrypted`, for scripts that must not silently pass a
plaintext or magic-stripped file); a `#simple-encrypt` first line that
is not an exact v1 header form → hard error; a marker header → decrypts
to an empty file; otherwise decrypt, trying ring keys in order, with
authentication, format, or version failures as hard errors. The ring
key is selected per file (by the first unit); a file whose later units
stop authenticating may be a mixed-epoch merge artifact (see `rekey`) —
the error message names this cause.

## Atomicity and failure semantics

- Every file replacement writes `.simple-encrypt.tmp.<16 random alnum>`
  in the target's directory, created `0600` with `O_EXCL | O_NOFOLLOW`;
  content is written and fsynced, the temp is renamed over the target
  **while still `0600`**, then the target's original permission bits
  are restored with `fchmod` through the still-open descriptor, the
  descriptor is fsynced again, and the directory is fsynced. Plaintext
  therefore never sits in a group- or world-readable temp file, and a
  crash between rename and `fchmod` leaves permissions too strict, not
  too loose. Config rewrites use the same mechanism. Once the rename
  has happened the content is committed: a failure in the later steps
  (chmod, fsync) is reported as a **warning naming what did happen**
  (permissions left at `0600`, durability uncertain), never as if the
  file were still in its old state. For the config specifically, an
  unconfirmed post-commit state additionally **aborts the command
  before any dependent ciphertext is written**: a crash may roll the
  config rename back, and files migrated to a key the rolled-back
  config does not hold would be undecryptable — re-running resumes
  from the visible config.
- Immediately before the rename, the tool re-checks that the target is
  still the file it read: same `(device, inode)`, size, and mtime. A
  mismatch (an editor or build tool rewrote it mid-operation) fails
  that file instead of destroying the concurrent change. The check is
  best-effort — a race within the window remains possible
  (see [threat-model.md](threat-model.md)). The config gets the same
  treatment: before writing any ciphertext, the tool verifies that
  `.simple-encrypt.toml` is still the file it loaded, so a mid-run
  replacement (a `git checkout` in another terminal) aborts the command
  instead of producing ciphertext the on-disk config cannot decrypt.
- At the start of every exclusive-lock command, stale temp files are
  deleted from the domain root and from the parent directories of all
  managed and explicit targets — not merely "when encountered", so a
  crashed run's temp next to a single-file entry is found too. Only
  names matching the reserved namespace exactly are removed, and only
  from directories reachable from the root without crossing a symlink
  (a replaced directory is warned about and skipped). The lock
  guarantees the temps cannot belong to a live instance. The sweep
  covers *this run's* targets only: a temp left next to an unmanaged
  explicit target of a crashed run is removed when that directory
  takes part in a later operation (re-running the same command removes
  it).
- Multi-file operations that modify files (`encrypt`, `decrypt`,
  `rekey`) run serially and **stop at the first error**, then report
  three lists: completed, failed (with the reason), and not attempted.
  Read-only scans (`status`, `check`, `verify`) instead examine
  everything and report all findings. There is no rollback — every
  completed file is individually valid, `status` shows the mixed state,
  and git history is the recovery mechanism for anything worse.
- Only Unix permission bits are preserved. Timestamps change, and
  ownership, POSIX ACLs, extended attributes, security labels
  (e.g. SELinux), and file flags are not carried over to the new inode
  created by temp + rename — files that must keep such metadata should
  not be managed by this tool. Immutable files fail naturally at rename
  time.

## Commands

### `init`

Create `.simple-encrypt.toml` in the current directory (refusal rules
under Domain resolution): prompt for the password (twice on a TTY),
generate a random 16-byte salt and 32-byte domain key, wrap the domain
key as the ring's sole entry, and write the config with default KDF
parameters and empty lists.

Options: `--memory-kib <n>`, `--iterations <n>`, `--parallelism <n>` to
override the initial Argon2id parameters (validated per
[crypto.md](crypto.md)).

### `encrypt [PATHS…]` (alias `e`)

Without arguments: encrypt every managed file, applying the skip and
migration rules above; a managed path that does not exist on disk is a
warning. With arguments: encrypt the given files/directories inside the
domain, auto-adding unmanaged files; an explicit argument that does not
exist on disk is an error. `--assume-plaintext` as specified above.
The password is read only when there is work to do: an empty target
set prints `nothing to do` and exits 0 without it.

### `decrypt [PATHS…]` (alias `d`)

Mirror of `encrypt` plus `--require-encrypted` (see above), including
the password-only-when-needed contract. Does not modify the managed
list.

### `add [--binary] <PATHS…>`

Canonicalize each path and insert it into `paths` (files or
directories; deduplicated, sorted). An entry already covered by a
managed directory is reported and not duplicated; adding a directory
prunes entries it now covers (reported) — but only when the path is a
real directory on disk: adding a regular file that would lexically
cover existing entries is a hard error (a file cannot cover them), and
adding a not-yet-existing path keeps those entries. Warns when a path
does not exist on disk. Does not encrypt anything and needs no
password. When this command registers paths not marked `force_binary`,
it prints a one-line reminder that text mode authenticates units, not
whole files.

With `--binary`, each path is additionally marked in `force_binary`
(always encrypted in binary mode) — the marking is independent of the
managed-list outcome, so an already-managed path can be marked with a
later `add --binary`. New marks are appended, preserving any
hand-maintained order. A text-mode ciphertext under a newly marked
path is migrated to binary by the next `encrypt`.

### `remove [--binary] <PATHS…>`

Remove exact entries from `paths`. Refuses to remove an entry whose
file probes as encrypted (or, for a directory entry, that covers any
such file) — decrypt first, so removal cannot silently strand
ciphertext outside `rekey`'s reach. `--force` skips that refusal
unconditionally (`remove` takes no password, so it cannot tell valid
ciphertext from foreign or colliding content): it exists for files
`decrypt` cannot process, and its warning states that force-removing a
still-valid ciphertext entry hides the file from `rekey`. Removing an
entry whose file no longer exists is allowed. A path covered by a
directory entry but not itself an entry is an error (the message names
the covering entry).

With `--binary`, remove exact entries from `force_binary` instead (an
entry that does not exist is an error): the managed list is untouched,
so the file stays managed and reverts to automatic mode choice.
Existing binary ciphertext is **not** re-encrypted automatically —
decrypt and re-encrypt to change its mode.

### `status`

For every managed file (directories expanded), print its state —
`encrypted`, `plaintext`, `missing`, `symlink`/`special` (a managed
path that exists only as a symlink or other non-regular file), or
`unrecognized` (a `#simple-encrypt`-prefixed first line that is no
exact v1 header) — plus a `binary` marker where `force_binary` applies
or the stored mode is binary. Needs no password. Exit code 0
regardless of states (it is a report, not a gate); an I/O error while
probing aborts with exit 1.

### `check [PATHS…]`

Gate for CI and hooks: exit 0 when every managed file that exists on
disk is encrypted (probe only — `check` needs no password and therefore
cannot verify decryptability), exit 1 listing every offender (plaintext,
a symlink or special managed path — its content was never probed — or
an unrecognized `#simple-encrypt`-prefixed header), exit 2 on
operational errors. With arguments, the given files and directories are
checked instead, managed or not. Missing files are ignored.

`check` is an accident gate, not tamper detection: it accepts any
content that merely starts with the encryption magic, and it knows
nothing about decryptability. Use `verify` for authenticated checking;
use the pre-commit recipe below to run `check` against the **staged
tree** rather than the working tree.

### `verify [PATHS…]`

Fully authenticate ciphertext without writing anything: unwrap the key
ring, then decrypt every managed encrypted file (or the given paths) in
memory, verifying every unit and, for binary files, the file tag.
`verify` judges the authenticity of files that probe as encrypted:
plaintext and missing files are reported but do **not** affect the exit
code; symlink or special managed paths, unrecognized headers, and
authentication failures are recorded as failures and the scan
continues; files that authenticate only under an older ring key are
reported as pending migration (authentic — exit 0). Exit 0 when all
encrypted files authenticate, exit 1 listing every failure, exit 2 on
operational errors. The complete CI gate is `check && verify`:
encryptedness and authenticity. Read the result with the integrity
model in mind: for text mode, `verify` proves every *unit* is
authentic — that each line was legitimately produced for this path —
**not** that the file as a whole (its set, order, and count of lines)
ever existed; whole-file integrity is what binary mode's file tag
provides. This is also the
command that detects deep corruption (`encrypt`'s skip check only
authenticates the first unit).

### `passwd` (alias `p`)

Change the password by re-wrapping the key ring — no file content is
read or written:

1. unwrap every ring entry with the old password;
2. generate a fresh salt, derive the new KEK with the new password
   (applying any `--memory-kib`/`--iterations`/`--parallelism`
   overrides), re-wrap **all** ring entries;
3. rewrite the config atomically.

Ciphertext does not change, so branches and history merge cleanly
across a password change, and interruption at any point leaves a fully
consistent config (old or new — the rename is the commit point).

**`passwd` does not revoke the old password.** The old wrapped ring
remains in git history and the domain keys are unchanged: anyone who
knows the old password and can read the repository history can unwrap
them and decrypt everything — including content committed *after* the
change. `passwd` is for changing what you type, not for responding to
compromise. The command prints exactly this warning. For a compromised
or weak old password, run `passwd` then `rekey`.

Changing only the KDF parameters is `passwd` with the same password
supplied as both old and new.

### `rekey`

Rotate the domain key — the response to a possibly compromised domain
key. If the **password** may be compromised, run `passwd` first;
`rekey` alone never changes the password. `rekey`:

1. unwraps the ring and scans for an unfinished rotation (any managed
   file whose first unit authenticates under a non-current ring key);
   if one is found, it refuses to mint another key — rerun as
   `rekey --continue` to resume the existing rotation instead. The
   scan authenticates first units only; damage deeper in a file
   surfaces as an error during the migration pass (after the new ring
   entry is safely committed), never as a silent skip;
2. generates a fresh domain key and salt and atomically rewrites the
   config with the new key prepended to `wrapped_keys` (every entry
   re-wrapped under the new salt's KEK);
3. runs a full `encrypt` pass over the managed list: plaintext files
   are encrypted, old-key ciphertext is migrated — each file decrypted
   in memory and re-encrypted under the new key via atomic replace.
   **Migration never writes decrypted plaintext to disk**; files that
   already sit as plaintext in the working tree simply get encrypted.

Interruption anywhere is safe: both keys stay in the config, so every
file remains decryptable, and `rekey --continue` — or a plain
`encrypt`, which performs the same migration — finishes the job.
Missing managed files are reported and left alone; they migrate
whenever they reappear. After its migration pass, `rekey --continue`
**fully authenticates every managed ciphertext under the current key**
before reporting success: skip decisions authenticate only the first
unit, so a mixed-epoch or deeply damaged file would otherwise pass
silently. A file that fails this bar needs manual resolution (the error
says so) — `--continue` never loops advice with `--prune`. It likewise
refuses to declare completion while a managed path exists only as a
symlink or special file: its content was never verified.

A fresh `rekey`, by contrast, may start a new epoch while managed
paths are missing or skipped: exit 0 then means the epoch started and
everything *processed* was migrated — not that every managed path was
verified. The old key is retained either way, and pending paths
migrate when they reappear; full convergence is what `--continue` and
`--prune` check.

Old ring entries are **kept by default**: complete files from any
retained epoch — on other branches, in stashes, in missed files — stay
decryptable. One caveat: a *line-level* merge resolution that
interleaves units from before and after a rekey produces a mixed-epoch
file that no single key decrypts; the authentication error names this
cause, and the fix is to re-resolve the merge taking whole files from
one side (or decrypt both sides first and merge as plaintext). The
cost of retention is that the current password unlocks every retained
epoch.

`rekey --prune` drops the older entries once every managed encrypted
file fully authenticates under the current key. It hard-errors when
any exact managed path entry — file **or directory** — is missing from
disk: the path could return from a stash or branch still encrypted
under an old key; `remove` the entry first if it is truly gone. The
same refusal applies to a managed entry that exists only as a symlink
or special file, and to anything expansion had to skip: their content
was never verified, so they are not convergence. For a directory entry
that exists, prune can only verify the files currently visible beneath
it — it cannot prove other branches hold none.
Cryptographically, prune is a full ring rewrite: unwrap the whole
ring, verify convergence, generate a fresh salt (and thus a fresh KEK
from the same password), re-wrap the retained current key as a ring of
length 1, and atomically replace the config — pre-prune wrappers can
never be re-attached to the pruned generation. Pruning trims the
**current config only**: configs already committed to git history keep
the full ring, so it limits what a stolen current checkout exposes,
not what a history reader with the current password can reach — see
[threat-model.md](threat-model.md). The command reports how many
epochs were dropped.

Rotation protects content encrypted afterwards; anyone who holds an old
password can still read pre-rekey content from git history, and nothing
retroactively unpublishes that short of rewriting history.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including "nothing to do") |
| 1 | failure: wrong password, authentication/format error, I/O error, usage error — and, for `check`/`verify`, "violations found" |
| 2 | `check`/`verify` only: operational error while checking |
| 141 | the output consumer went away (broken pipe) — the status a SIGPIPE-killed Unix tool would report, so a truncated `check \| head` can never pass silently |

Usage errors exit 1 like every other failure; the implementation must
override clap's default exit code 2, which would collide with the
`check`/`verify` meaning above.

## Git integration recipes

The tool never invokes git; the recipes below live in git's own
configuration.

### Line endings: mark ciphertext `-text`

Text ciphertext is byte-exact, LF-framed. Any EOL conversion on
checkout (`core.autocrlf`, `eol=crlf`, `text=auto`) corrupts it — the
failure is closed (header and base64 parsing reject CRLF) but the
domain becomes unusable on such checkouts. Add the managed paths to
`.gitattributes` with EOL normalization disabled:

```gitattributes
.env            -text
secrets/**      -text
```

Never apply clean/smudge filters or `working-tree-encoding` to managed
paths, and keep formatters and pre-commit fixers (trailing-whitespace,
end-of-file rewriters) away from them.

### Pre-commit hook: check the staged tree

A hook that probes the working tree can be bypassed by staging
plaintext before encrypting, and cannot see a staged config. Export the
**index** and run `check` inside it, once per domain found in the
export (domains need not sit at the repository root, and one repository
may hold several sibling domains):

```bash
#!/bin/bash
set -eu
umask 077
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
git checkout-index --all --prefix="$tmp/"
while IFS= read -r -d '' cfg; do
    (cd "$(dirname "$cfg")" && simple-encrypt check) || exit 1
done < <(find "$tmp" -type f -name .simple-encrypt.toml -print0)
```

This checks each staged config together with its staged contents, and
passes when the export contains no domain at all. Note that
`checkout-index` runs git's checkout conversions: the exported bytes
equal the index blobs only where managed paths carry `-text` and no
filters — exactly what the attributes recipe above establishes. With
misconfigured attributes the export is no longer the literal index
bytes, and the probe is byte-strict: EOL conversion makes valid
ciphertext probe as *unrecognized*, so the gate **fails closed** and
blocks the commit rather than passing anything suspect. `mktemp -d`
plus `umask 077` keep the export
private; staged plaintext briefly exists under `$TMPDIR` — point it at
a tmpfs if that matters. A domain config must itself be tracked for the
export to contain it — which it must be anyway, since ciphertext is
useless without it. One accepted gap: a commit that deletes a config
leaves no domain in the export and the hook passes — it gates
plaintext, not the recoverability of ciphertext left behind without
its config.

### Typical flow

```console
$ simple-encrypt init                 # once per repository
$ simple-encrypt add .env secrets/
$ simple-encrypt e                    # encrypt everything managed
$ git add -A && git commit
$ simple-encrypt d                    # work on plaintext locally
$ simple-encrypt e                    # re-encrypt before committing again
```

Rename a managed file while it is *plaintext* (path-bound keys):

```console
$ simple-encrypt d secrets/old.env
$ git mv secrets/old.env secrets/new.env
$ simple-encrypt remove secrets/old.env   # if it was an exact entry
$ simple-encrypt e secrets/new.env        # auto-adds the new path
```
