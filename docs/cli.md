# simple-encrypt — CLI Semantics

Binary name: `simple-encrypt`. Subcommands: `init`, `encrypt` (`e`),
`decrypt` (`d`), `add`, `remove`, `status`, `check`, `passwd` (`p`).

Human-readable progress goes to stdout, errors and warnings to stderr.
Output is line-oriented and stable enough for scripting, but not a promised
machine interface.

## Domain resolution

Every command except `init` locates the **domain config** by walking up from
a starting directory until a `.simple-encrypt.toml` is found:

- with explicit path arguments: from the argument itself when it is a
  directory, otherwise from its parent directory (so `encrypt .` at the
  domain root finds the root's own config);
- without arguments: from the current working directory.

All targets of one invocation must resolve to the **same** domain; mixing
domains is an error. A target outside any domain is an error (there is no
salt to encrypt with). Explicit arguments must also lie inside the domain
root after canonicalization, which is purely lexical — symlinks are never
resolved (see [format.md](format.md)).

Nested domains are rejected: `init` refuses to run when the current
directory, any ancestor, or any descendant directory already has a config,
and traversal treats a foreign `.simple-encrypt.toml` below the domain
root as a hard error.

## Password input

Commands that touch file content (`encrypt`, `decrypt`, `passwd`) and `init`
need the password; `add`, `remove`, `status`, and `check` never do.

Sources, in priority order:

1. `SIMPLE_ENCRYPT_PASSWORD` environment variable (may be visible to other
   same-user processes via `/proc`; see [threat-model.md](threat-model.md));
2. interactive prompt without echo when stdin is a TTY — `init` and the new
   password of `passwd` are prompted twice and must match;
3. otherwise the first line of stdin (trailing newline stripped, no
   confirmation) — for pipes and scripts.

`passwd` needs two passwords. The old one comes from the sources above;
the new one comes from `SIMPLE_ENCRYPT_NEW_PASSWORD` when set, otherwise
it is prompted twice on a TTY, otherwise it is read as the next line of
stdin (a script pipes both passwords on two lines). A password that
cannot be obtained from any source is an error.

Passwords must be valid UTF-8. Empty passwords are rejected. The password
is checked against the config verifier before any file is touched; a
mismatch aborts immediately.

## File selection

- **Managed paths** (`paths` in the config) may be files or directories;
  directories are expanded recursively at run time.
- During expansion the tool always skips: the domain config itself, any
  `.git` directory and everything under it, and stale `.simple-encrypt.tmp.*`
  files (which are deleted with a notice when encountered). Symbolic links
  are never followed: a symlink found during recursion is skipped with a
  warning, and an explicit argument that is a symlink — or any of whose
  path components is detected to be one — is an error.
- Explicitly naming the domain config, or anything under a `.git`
  directory, is an error.
- `force_binary` applies to a file when its canonical relative path equals
  an entry or is under a directory entry.

### Encrypt-time bookkeeping (auto-add)

`encrypt` with explicit arguments also works on files that are not yet
managed. Each such **file** is added to `paths` (config rewritten
atomically) *before* it is encrypted — and a file that turns out to be
already encrypted (after passing the authentication check below) is added
as well — so an interruption can never leave an encrypted file untracked. This keeps the managed list the source of truth
for `status`, `check`, and — critically — `passwd`, which must be able to
find every encrypted file to avoid stranding ciphertext under an old
password. Directories passed explicitly are expanded to files; the
directory itself is not added.

### Probe, skip, and collision rules

For each candidate file, `encrypt` branches on the probe
(see [format.md](format.md)) and on whether `force_binary` applies:

- **Content starts with `BIN_MAGIC`**: authenticate the first chunk with
  the current keys. Success → already encrypted, skip. Failure → hard
  error: the file is foreign ciphertext, corrupted, moved from another
  path — or plaintext that happens to begin with `BIN_MAGIC`, which this
  tool cannot manage (no in-band escape exists).
- **First line starts with `#simple-encrypt`, not forced binary**: if the
  first line is not exactly the v1 header → hard error (newer tool, or
  malformed). If the file is exactly the header line → encrypted empty
  file, skip. Otherwise authenticate the first line: success → already
  encrypted, skip; failure → hard error listing the possible causes
  (foreign / corrupted / moved — or plaintext whose first line collides
  with the header, for which the error suggests `force_binary`).
- **First line starts with `#simple-encrypt`, forced binary**: if the file
  is exactly the header line or its first line authenticates → hard
  error: it is encrypted in text mode but now forced binary — decrypt it
  first, then re-encrypt (this is the migration path after adding existing
  text ciphertext to `force_binary`). Otherwise it is treated as plaintext
  and encrypted in binary mode, with a warning — this is what makes
  `force_binary` an effective escape hatch for text that collides with
  the header.
- **No probe hit**: pick the mode (`force_binary` → binary; content
  contains NUL → binary; else text) and encrypt.

The authentication check on skipped files costs one AEAD open (including
the nonce conformance check) per file, not a full decryption.

`decrypt` ignores `force_binary` (the mode comes from the ciphertext):
no probe hit → skip with a note; a `#simple-encrypt` first line that is
not the exact v1 header → hard error; a header-only file → decrypts to an
empty file; otherwise decrypt, with authentication, format, or version
failures as hard errors.

## Atomicity and failure semantics

- Every file replacement writes `.simple-encrypt.tmp.<16 random alnum>` in
  the target's directory, copies the target's permission bits, fsyncs the
  temp file, renames it over the target, then fsyncs the directory. Config
  rewrites use the same mechanism.
- Multi-file operations run serially and **stop at the first error**,
  then report three lists: completed, failed (with the reason), and not
  attempted. There is no rollback — every completed file is individually
  valid, `status` shows the mixed state, and git history is the recovery
  mechanism for anything worse.
- Concurrent invocations on the same domain are unsupported (no locking);
  the stale-temp cleanup assumes it is the only running instance.
- File timestamps are not preserved; permission bits are.

## Commands

### `init`

Create `.simple-encrypt.toml` in the current directory: refuse if the
current directory, any ancestor, or any descendant directory (`.git`
excluded from the scan) already has one; prompt for the password (twice on
a TTY); generate a random 16-byte salt; write the config with the
verifier, default KDF parameters, and empty lists.

Options: `--memory-kib <n>`, `--iterations <n>`, `--parallelism <n>` to
override the initial Argon2id parameters (validated per
[crypto.md](crypto.md)).

### `encrypt [PATHS…]` (alias `e`)

Without arguments: encrypt every managed file (skipping already-encrypted
ones as above); a managed path that does not exist on disk is a warning,
not an error. With arguments: encrypt the given files/directories inside
the domain, auto-adding unmanaged files as described above; an explicit
argument that does not exist on disk is an error.

### `decrypt [PATHS…]` (alias `d`)

Mirror of `encrypt`: without arguments, decrypt every managed file;
with arguments, decrypt the given paths. Does not modify the managed list.

### `add <PATHS…>`

Canonicalize each path and insert it into `paths` (files or directories;
deduplicated, sorted; an entry already covered by a managed directory is
reported and not duplicated). Warns when a path does not exist on disk.
Does not encrypt anything and needs no password.

### `remove <PATHS…>`

Remove exact entries from `paths`. Refuses to remove an entry whose file
probes as encrypted (or, for a directory entry, that covers any such
file) — decrypt first, so removal can never strand ciphertext outside
`passwd`'s reach. `--force` overrides the refusal for a file that cannot
be decrypted (foreign ciphertext, corruption, or magic-colliding content)
after an explicit warning. Removing an entry whose file no longer exists
is allowed. A path covered by a directory entry but not itself an entry is
an error (the message names the covering entry).

### `status`

For every managed file (directories expanded), print its state —
`encrypted`, `plaintext`, or `missing` — plus a `binary` marker where
`force_binary` applies or the stored mode is binary. Needs no password.
Exit code 0 regardless of states (it is a report, not a gate); an I/O
error while reading a file for the probe aborts the report with exit 1.

### `check [PATHS…]`

Gate for CI and hooks: exit 0 when every managed file that exists on disk
is encrypted (probe only — `check` needs no password and therefore cannot
verify decryptability), exit 1 listing every plaintext offender, exit 2 on
operational errors. With arguments, the given files and directories are
checked instead, managed or not. Missing files are ignored.

Two documented blind spots. First, `check` inspects the working tree only;
content staged in git is out of scope (commit with `git commit -a` or
re-stage after encrypting — see the hook recipe below). Second, being
probe-only, it accepts any file that merely *starts* with the encryption
magic; the encrypt rules never leave such plaintext behind, so hitting
this requires hand-crafted content — the residual risk is recorded in
[threat-model.md](threat-model.md).

### `passwd` (alias `p`)

Change the password (and optionally the KDF parameters) in three phases,
each of which leaves the domain in a single-password state even if
interrupted:

1. **Decrypt all**: verify the old password against the stored verifier,
   then decrypt every managed file that is currently encrypted. An
   interruption here leaves old-password config + a mix of plaintext and
   old-password ciphertext: rerun `passwd`, or `decrypt`, with the old
   password. A managed file that probes encrypted but fails
   authentication aborts the run with the file named; already-decrypted
   files stay decrypted (still a single-password state) — fix or
   `remove --force` the offender and rerun.
2. **Swap config**: generate a fresh salt, derive the new verifier from the
   new password (applying any `--memory-kib`/`--iterations`/`--parallelism`
   overrides), and rewrite the config atomically. This single rename is the
   commit point between "old domain" and "new domain".
3. **Encrypt all**: re-encrypt every managed file with the new password.
   An interruption here leaves new-password config + plaintext remainder:
   `encrypt` with the new password finishes the job.

Old- and new-password ciphertext can never coexist because phase 3 starts
only after phase 1 decrypted everything and phase 2 committed the new
config. Changing only the KDF parameters is the same flow with the same
password supplied as both old and new.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success (including "nothing to do") |
| 1 | failure: wrong password, authentication/format error, I/O error, usage error — and, for `check`, "plaintext files found" |
| 2 | `check` only: operational error while checking |

## Git integration recipe

The tool never invokes git. For a pre-commit safety net, add
`.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec simple-encrypt check
```

`check`'s working-tree limitation applies (see above). A typical flow:

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
