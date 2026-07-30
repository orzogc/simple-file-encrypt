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

All targets of one invocation must resolve to the **same** domain; mixing
domains is an error. A target outside any domain is an error. Explicit
arguments must lie inside the domain root after canonicalization, which
is lexical and replaces each component with the filesystem-reported
spelling (see [format.md](format.md)); an explicit argument that is a
symlink — or any of whose components is detected to be one — is an error.

Nested domains are rejected: `init` refuses to run when the current
directory, any ancestor, or any descendant directory already has a
config, and traversal treats a foreign `.simple-encrypt.toml` below the
domain root as a hard error.

## Locking

Commands take an advisory `flock` on the **domain root directory** (an
`O_DIRECTORY` descriptor; no lock file, nothing to commit or ignore):
exclusive for anything that may write — `encrypt`, `decrypt`, `add`,
`remove`, `passwd`, `rekey` — and shared for pure readers — `status`,
`check`, `verify`. The directory is never renamed by the tool, so the
lock stays valid across config rewrites (a lock on the config file
itself would be stranded on the old inode the moment the file is
rename-replaced). The lock is non-blocking: if another instance holds
it, the command fails with a clear message. `init` needs no lock: it
creates the config with `O_EXCL`. Advisory locks may be ineffective on
some network filesystems; do not run concurrent instances there.

## Password input

`encrypt`, `decrypt`, `verify`, `passwd`, `rekey`, and `init` need the
password; `add`, `remove`, `status`, and `check` never do.

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

Passwords must be valid UTF-8, non-empty, and at most 4096 bytes. The
password is checked by unwrapping the domain key before any file is
touched; a mismatch aborts immediately.

KDF-related global options, honored by every command that runs Argon2:
`--allow-weak-kdf` and `--allow-expensive-kdf`
(see [crypto.md](crypto.md) for the tiers).

## File selection

- **Managed paths** (`paths` in the config) may be files or directories;
  directories are expanded recursively at run time.
- During expansion the tool always skips: the domain config itself, any
  `.git` directory and everything under it, and stale
  `.simple-encrypt.tmp.*` files. Symbolic links are never followed: a
  symlink found during recursion is skipped with a warning.
- Explicitly naming the domain config, or anything under a `.git`
  directory, is an error.
- After expansion, targets with the same canonical path (a file named
  directly and again via a covering directory entry) are silently
  deduplicated. Two *different* canonical paths resolving to the same
  `(device, inode)` — hard-linked pairs, case-insensitive aliases — are
  an error.
- A plaintext file about to be encrypted is refused when its link count
  is greater than 1: the other hard links would silently keep a
  plaintext alias after encryption. The check applies only to files
  entering encryption (already-encrypted files are skipped as usual);
  `decrypt` only warns in the mirror case.
- `force_binary` applies to a file when its canonical relative path
  equals an entry or is under a directory entry.

### Encrypt-time bookkeeping (auto-add)

`encrypt` with explicit arguments also works on files that are not yet
managed. Each such **file** is added to `paths` (config rewritten
atomically) *before* it is encrypted — and a file that turns out to be
already encrypted (after passing the authentication check below) is
added as well — so an interruption can never leave an encrypted file
untracked. This keeps the managed list the source of truth for `status`,
`check`, `verify`, and `rekey`, which must be able to find every
encrypted file. Directories passed explicitly are expanded to files; the
directory itself is not added.

### Probe, skip, and collision rules

For each candidate file, `encrypt` branches on the probe
(see [format.md](format.md)) and on whether `force_binary` applies:

- **Content starts with `BIN_MAGIC`**: authenticate the first chunk with
  the current keys. Success → already encrypted, skip. Failure → hard
  error: foreign ciphertext, corrupted, moved from another path — or
  plaintext that happens to begin with `BIN_MAGIC`, which this tool
  cannot manage (no in-band escape exists).
- **First line starts with `#simple-encrypt`, not forced binary**: if the
  first line is not an exact v1 header form → hard error naming both
  possibilities (ciphertext from a newer tool, or colliding plaintext —
  for which the error suggests `force_binary`). Otherwise authenticate
  the empty-file marker or the first unit line: success → already
  encrypted, skip; failure (including a bare header with no units) →
  hard error listing the possible causes (foreign / corrupted / moved —
  or colliding plaintext, again suggesting `force_binary`).
- **First line starts with `#simple-encrypt`, forced binary**: if the
  file carries an exact v1 header and its marker or first unit
  authenticates → hard error: it is encrypted in text mode but now
  forced binary — decrypt it first, then re-encrypt (the migration path
  after adding existing text ciphertext to `force_binary`). Anything
  else — non-exact header forms included — is treated as plaintext and
  encrypted in binary mode, with a warning. This unconditional fallback
  is what makes `force_binary` an effective escape hatch for any text
  whose first line collides with the `#simple-encrypt` prefix.
- **No probe hit**: pick the mode (`force_binary` → binary; content
  contains NUL → binary; else text) and encrypt.

The authentication check on skipped files costs one SIV verification per
file, not a full decryption.

`decrypt` ignores `force_binary` (the mode comes from the ciphertext):
no probe hit → skip with a note (or a hard error under
`--require-encrypted`, for scripts that must not silently pass a
plaintext or magic-stripped file); a `#simple-encrypt` first line that is
not an exact v1 header form → hard error; a marker header → decrypts to
an empty file; otherwise decrypt, with authentication, format, or
version failures as hard errors.

## Atomicity and failure semantics

- Every file replacement writes `.simple-encrypt.tmp.<16 random alnum>`
  in the target's directory, created with mode `0600`; content is
  written and fsynced, the file is then chmodded to the target's
  permission bits, renamed over the target, and the directory is
  fsynced. Plaintext never sits in a group- or world-readable temp file.
  Config rewrites use the same mechanism.
- At the start of every exclusive-lock command, stale
  `.simple-encrypt.tmp.*` files are deleted from the domain root and
  from the parent directories of all managed and explicit targets — not
  merely "when encountered", so a crashed run's temp next to a
  single-file entry is found too. The lock guarantees they cannot belong
  to a live instance.
- Multi-file operations that modify files (`encrypt`, `decrypt`, the
  `rekey` phases) run serially and **stop at the first error**, then
  report three lists: completed, failed (with the reason), and not
  attempted. Read-only scans (`status`, `check`, `verify`) instead
  examine everything and report all findings. There is no rollback —
  every completed file is individually valid, `status` shows the mixed
  state, and git history is the recovery mechanism for anything worse.
- File timestamps are not preserved; permission bits are.

## Commands

### `init`

Create `.simple-encrypt.toml` in the current directory (refusal rules
under Domain resolution): prompt for the password (twice on a TTY),
generate a random 16-byte salt and 32-byte domain key, wrap the domain
key, and write the config with default KDF parameters and empty lists.

Options: `--memory-kib <n>`, `--iterations <n>`, `--parallelism <n>` to
override the initial Argon2id parameters (validated per
[crypto.md](crypto.md)).

### `encrypt [PATHS…]` (alias `e`)

Without arguments: encrypt every managed file (skipping already-encrypted
ones as above); a managed path that does not exist on disk is a warning.
With arguments: encrypt the given files/directories inside the domain,
auto-adding unmanaged files; an explicit argument that does not exist on
disk is an error.

### `decrypt [PATHS…]` (alias `d`)

Mirror of `encrypt` plus `--require-encrypted` (see above). Does not
modify the managed list.

### `add <PATHS…>`

Canonicalize each path and insert it into `paths` (files or directories;
deduplicated, sorted). An entry already covered by a managed directory
is reported and not duplicated; adding a directory prunes entries it now
covers (reported). Warns when a path does not exist on disk. Does not
encrypt anything and needs no password.

### `remove <PATHS…>`

Remove exact entries from `paths`. Refuses to remove an entry whose file
probes as encrypted (or, for a directory entry, that covers any such
file) — decrypt first, so removal cannot silently strand ciphertext
outside `rekey`'s reach. `--force` skips that refusal unconditionally
(`remove` takes no password, so it cannot tell valid ciphertext from
foreign or colliding content): it exists for files `decrypt` cannot
process, and its warning states that force-removing a still-valid
ciphertext entry hides the file from `rekey`, stranding it under the
old domain key. Removing an entry whose file no longer exists is
allowed. A path covered by a directory entry but not itself an entry is
an error (the message names the covering entry).

### `status`

For every managed file (directories expanded), print its state —
`encrypted`, `plaintext`, `missing`, or `unrecognized` (a
`#simple-encrypt`-prefixed first line that is no exact v1 header) — plus
a `binary` marker where `force_binary` applies or the stored mode is
binary. Needs no password. Exit code 0 regardless of states (it is a
report, not a gate); an I/O error while probing aborts with exit 1.

### `check [PATHS…]`

Gate for CI and hooks: exit 0 when every managed file that exists on
disk is encrypted (probe only — `check` needs no password and therefore
cannot verify decryptability), exit 1 listing every offender (plaintext,
or an unrecognized `#simple-encrypt`-prefixed header), exit 2 on
operational errors. With arguments, the given files and directories are
checked instead, managed or not. Missing files are ignored.

`check --stdin <PATH>` probes content read from stdin as if it were the
file at canonical path `PATH`: exit 0 when the path is unmanaged or the
content probes encrypted, exit 1 otherwise. This lets a git hook check
**staged** content (see the recipe below) while the tool itself stays
git-free.

`check` is an accident gate, not tamper detection: it accepts any
content that merely starts with the encryption magic, and it knows
nothing about decryptability. Use `verify` for authenticated checking.

### `verify [PATHS…]`

Fully authenticate ciphertext without writing anything: unwrap the
domain key, then decrypt every managed encrypted file (or the given
paths) in memory, verifying every unit and, for binary files, the file
tag. Plaintext and missing files are reported and skipped; unrecognized
headers and authentication failures are recorded as failures and the
scan continues. Exit 0 when everything authenticates, exit 1 listing
every failure, exit 2 on operational errors. This is the command that detects deep corruption
(`encrypt`'s skip check only authenticates the first unit).

### `passwd` (alias `p`)

Change the password by re-wrapping the domain key — no file content is
read or written:

1. unwrap the domain key with the old password;
2. generate a fresh salt, derive the new KEK with the new password
   (applying any `--memory-kib`/`--iterations`/`--parallelism`
   overrides), re-wrap the **same** domain key;
3. rewrite the config atomically.

Ciphertext does not change, so branches and history merge cleanly across
a password change, and interruption at any point leaves a fully
consistent config (old or new — the rename is the commit point).

**`passwd` does not revoke the old password.** The old wrapped key
remains in git history, and the domain key is unchanged: anyone who
knows the old password and can read the repository history can unwrap it
and decrypt everything — including content committed *after* the change.
`passwd` is for changing what you type, not for responding to
compromise. The command prints exactly this warning. For a compromised
or weak old password, run `passwd` then `rekey`.

Changing only the KDF parameters is `passwd` with the same password
supplied as both old and new.

### `rekey`

Rotate the domain key itself — the compromise response. Three phases,
each interruption-safe:

1. **Decrypt all**: unwrap the current domain key, then decrypt every
   managed encrypted file. Interruption leaves the old config and a mix
   of plaintext and old-key ciphertext: rerun `rekey`, or `decrypt`,
   with the current password. A managed file that probes encrypted but
   fails authentication aborts the run with the file named — fix or
   `remove --force` the offender and rerun.
2. **Swap config**: generate a fresh domain key and salt, wrap under the
   current password, rewrite the config atomically (the commit point).
3. **Encrypt all**: re-encrypt every managed file under the new domain
   key. Interruption leaves the new config plus plaintext remainder:
   `encrypt` finishes the job.

Among managed files, old-key and new-key ciphertext can never coexist
(ciphertext hidden from the managed list — hand-edited configs,
`remove --force` — is on its own). During `rekey` the
whole domain is plaintext on disk (inherent to rotation); every
ciphertext changes afterwards, which is the point. Content encrypted
under the old domain key remains readable, via git history, to anyone
holding the old password — rotation protects what comes after, and
nothing can retroactively unpublish history short of rewriting it.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including "nothing to do") |
| 1 | failure: wrong password, authentication/format error, I/O error, usage error — and, for `check`/`verify`, "violations found" |
| 2 | `check`/`verify` only: operational error while checking |

Usage errors exit 1 like every other failure; the implementation must
override clap's default exit code 2, which would collide with the
`check`/`verify` meaning above.

## Git integration recipe

The tool never invokes git. For a pre-commit gate that checks what is
actually being committed (the **index**, not the working tree), install
`.git/hooks/pre-commit`:

```bash
#!/bin/bash
git diff --cached --name-only -z --diff-filter=ACMR |
while IFS= read -r -d '' f; do
    git show ":$f" | simple-encrypt check --stdin "$f" || exit 1
done
```

A plain `simple-encrypt check` in a hook inspects only the working tree
and can be bypassed by staging plaintext before encrypting — treat that
form as a convenience check, not a gate.

A typical flow:

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
