# simple-encrypt — Threat Model

This tool makes a deliberate, unusual trade: it encrypts text files line
by line, deterministically, so that ciphertext diffs and merges like
text. That buys git ergonomics and costs confidentiality of *structure*.
This document states exactly what is and is not protected. The README
must carry the same message; users who skip this page should still not be
surprised.

## Assets

- The plaintext content of managed files (tokens, credentials, private
  notes, small binary secrets).
- The password and the domain keys.

## Adversaries

Two classes, with very different coverage:

- **Passive reader of ciphertext at rest** (primary): a repository
  hosting provider, someone who leaks or steals a clone or backup, a
  future reader of git history. Reads every committed version of the
  ciphertext and the domain config; runs offline computation. Cannot run
  code on the user's machine and cannot cause encryptions of chosen data.
- **Active repository writer** (secondary, limited coverage): can modify
  ciphertext, config, and history. Against this adversary the tool
  offers *unit-level* authenticity, the binary file tag, and a
  tamper-evident key ring (length- and position-bound wrap AD: within
  one config generation, no reordering, subsetting, or splicing of
  entries can redirect future encryption to a retired, possibly
  compromised key). Rolling back the **complete config** to a
  historically valid generation is not detected — if the password has
  not changed since, that generation unwraps consistently; countering
  it needs protected or signed history. Nothing more is offered; see
  the integrity limits below. Full protection against a hostile writer
  is out of scope.

## Guarantees

- **Content confidentiality, conditional on unpredictability**: the
  scheme is deterministic authenticated encryption (AES-SIV). Ciphertext
  reveals unit equality and exact lengths, and nothing else — which
  protects a unit's content only to the extent that content is
  unpredictable *given* the revealed information. High-entropy content
  (random tokens, cryptographic keys, sufficiently long and
  unpredictable private text) is protected by the password and KDF;
  low-entropy, high-frequency, or format-predictable lines can be
  identified or confirmed without any key (see the leakage inventory).
  Do not read "encrypted" as "hidden" for structure or boilerplate.
- **Unit authenticity**: no ciphertext unit (line, empty-file marker, or
  chunk) that was never legitimately produced for that exact file path
  can be created without the key; tampering with a unit's bytes is
  detected. This is *not* file-level integrity — see below.
- **Binary file integrity**: a binary ciphertext additionally carries a
  whole-file tag binding chunk order, count, lengths, and header;
  recombining chunks from different versions is detected. Only
  whole-file rollback to a complete older ciphertext survives.
- **Wrong-password detection**: unwrapping the key ring fails fast,
  before any file is touched.
- **Deterministic re-encryption**: within one key epoch, unchanged
  plaintext never churns ciphertext; `passwd` and KDF upgrades churn
  nothing at all. `rekey` starts a new epoch and rewrites every
  ciphertext by design.

## Leakage inventory (accepted by design)

All lengths below are **exact**, not approximate — base64 character
counts and ciphertext sizes invert uniquely to plaintext sizes.

1. **Structure of text files**: the exact number of lines, the exact
   byte length of every line, whether the file ends with a newline, and
   exactly which lines changed between any two committed versions. This
   is the same information a git diff of the ciphertext shows — that is
   the point, and the leak.
2. **Line equality within a file**: identical plaintext lines in one
   file have identical ciphertext lines — also across the git history
   of that path, across branches, and across clones or forks (they
   share the config and domain key) — **within one key epoch**. A
   `rekey` rewrites every ciphertext, so direct equality does not span
   epochs; but if the rekey commit changed no content, the git diff's
   line-position correspondence still links old and new ciphertext, so
   positional analysis can carry knowledge across the boundary.
   Reverting a line is visible as the old ciphertext returning (same
   epoch). High-frequency short lines (empty lines, `}`, `true`,
   boilerplate) are realistically identifiable by frequency analysis
   alone. Cross-*file* equality is hidden (per-path keys).
3. **Known-plaintext dictionaries**: if the plaintext of any committed
   version of a file is known (it was once public, or partially
   guessable), every one of its lines yields a ciphertext→plaintext
   dictionary entry valid for all other versions of that path within
   the same key epoch — and, via the positional correlation above,
   often effectively across a rekey as well.
4. **Binary files**: the exact plaintext length, and which 64 KiB
   regions changed between versions.
5. **Confirmation attacks**: anyone who can get a guessed line encrypted
   under the victim's key at the same path (e.g. a collaborator
   proposing config lines) confirms the guess by comparing ciphertext.
   Deterministic encryption cannot prevent this.
6. **Offline password guessing**: the config's salt, KDF parameters, and
   wrapped key ring allow testing password guesses at Argon2id cost —
   even if no ciphertext leaks at all, the wrapped ring alone suffices
   as a test target. Password entropy and the KDF parameters are the
   only defenses; there is no server to rate-limit.

## Integrity limits (accepted by design)

- **Text mode has unit integrity only.** An attacker with write access
  can compose a file that was never legitimately encrypted, out of
  authentic units: delete security-relevant lines, reorder lines whose
  meaning is order-dependent, duplicate lines so a later value overrides
  an earlier one, resurrect a revoked token from history, or mix lines
  from historical versions of the same path **encrypted under the same
  key epoch** (mixed-epoch files fail authentication; a complete
  old-epoch file remains replayable while its key is retained). None of
  this is detected by decryption. This is the price of line-level
  merge; review of git history is the countermeasure.
- **Whole-file rollback** (text and binary): any file can be reverted to
  a complete older ciphertext undetected by the tool — including
  replaying the authenticated empty-file marker from a version that was
  legitimately empty.
- **Git history is a recovery source, not a cryptographic control.**
  History itself can be force-pushed, rewritten, or rolled back together
  with config and ciphertext. Treating it as rollback protection
  requires protecting *it*: protected branches, signed commits or tags,
  or an out-of-band record of trusted commit IDs.
- **Unauthenticated framing**: the binary header and the text header
  line carry no tag of their own (the binary header is covered by the
  file tag once parsing succeeds, but a corrupted magic prevents parsing
  entirely). Corrupting the magic makes the file probe as plaintext,
  which `decrypt` skips with only a note — `decrypt --require-encrypted`
  turns that into an error, and `check` flags such a file as an
  offender.

## Password change vs. key rotation

`passwd` re-wraps the key ring and **does not revoke** the old
password: the old wrapped ring stays in git history and the domain keys
are unchanged, so the old password keeps decrypting everything,
including future commits. Routine "I want to type something else"
changes are safe; compromise response is `passwd` **then `rekey`**,
which prepends a fresh domain key and migrates every managed file to it
in memory — no plaintext is written to disk in the process. Older ring
entries are retained by default so ciphertext on unmerged branches
stays decryptable; the trade-off is that the current password unlocks
every retained epoch. `rekey --prune` narrows that for the **current
config only**: configs already committed to history keep the full
ring, so pruning limits what a stolen current checkout exposes — not
what a reader of git history with the current password can reach;
historical revocation would require rewriting that history. Even
`rekey` only protects content committed afterwards — nothing
retroactively removes what an old password could already read from
history.

## Out of scope

- **A compromised machine**: malware, a hostile local user, memory
  scraping. Zeroization of keys and passwords is best-effort hygiene,
  not a defense.
- **The decrypted working tree**: while files are decrypted they are
  ordinary plaintext on disk; the tool does not shorten that window.
- **Secure deletion.** In-place encryption cannot erase plaintext that
  ever existed: old filesystem blocks, copy-on-write snapshots,
  journals, editor swap/backup files, OS page cache and swap, backups,
  and anything already committed to git history all survive
  `temp + rename`. If plaintext must never have touched persistent
  storage, this tool cannot provide that.
- **Local race conditions (TOCTOU)**: path checks (symlink detection,
  containment) are lexical checks followed by separate opens; a local
  attacker racing between a check and its use can redirect that access.
  Closing this needs `openat2`-style descriptor-relative traversal,
  deliberately not done in v1. The **static** case is not conceded: a
  directory already replaced by a symlink (e.g. by a hostile commit) is
  detected and refused on every run, and the config must be a real,
  non-symlinked regular file — the residual gap is only the race, which
  matters against local active attackers who are out of scope anyway.
- **Active attackers with an encryption oracle** beyond the confirmation
  attack above: the deterministic design concedes adaptive
  chosen-plaintext games.
- **Metadata beyond file contents**: filenames, file count, sizes,
  commit times and messages are plainly visible in git regardless.
- **Availability**: an attacker who can write can destroy ciphertext;
  git history is the recovery path.

## Operational risks and mitigations

| Risk | Stance |
|---|---|
| Losing `.simple-encrypt.toml` | Ciphertext is undecryptable without it (salt and the wrapped key ring live there). It is committed next to the ciphertext; git is the backup. |
| `SIMPLE_ENCRYPT_PASSWORD` in the environment | Visible to same-user processes via `/proc`; prefer the interactive prompt outside CI. |
| Crash during decryption | May leave a `.simple-encrypt.tmp.*` containing plaintext (mode `0600`) until the next exclusive-lock run sweeps the domain root and all target directories; treat as a plaintext spill. |
| Concurrent runs on one domain | Guarded by an advisory `flock` on the domain root directory; the second instance fails fast. Advisory locks may not work on network filesystems — avoid concurrent use there. |
| Another program rewriting a file mid-operation | The advisory lock excludes only other simple-encrypt instances. Before replacing a file the tool re-checks `(device, inode)`, size, and mtime against what it read and fails that file on mismatch; the config is likewise re-verified against its load-time snapshot before any ciphertext is written, so a mid-run config swap (e.g. `git checkout`) aborts instead of producing undecryptable files. A race inside either window remains. |
| git EOL or filter conversion | Text ciphertext is byte-exact and LF-framed: mark managed paths `-text` in `.gitattributes`, and never apply clean/smudge filters or `working-tree-encoding` to them. A CRLF checkout fails closed as a format error. The tool itself refuses to encrypt `.gitattributes` and `.gitmodules`. |
| File metadata beyond mode bits | Only Unix permission bits survive temp + rename: ownership, POSIX ACLs, extended attributes, security labels, and file flags are not preserved and may alter access semantics — keep files that depend on them out of managed paths. |
| Hard links | `encrypt` refuses files with link count > 1: the other links would keep a readable plaintext alias. Resolve the links first. |
| Moving/renaming an encrypted file | Decryption fails (path-bound keys). Rename in plaintext state; the auth-failure message hints at this cause. |
| Hostile config in a cloned repo | The config must be a real regular file (no symlink, FIFO, or device) and is read under a hard byte cap; KDF cost is tiered (security floor, flag-gated ceiling, absolute hard caps) with checked arithmetic; above-default cost is announced before Argon2 runs; unknown keys and versions are rejected; path entries cannot escape the domain root (stored entries are re-checked for symlinked ancestors on every run, and temp-file sweeping never crosses a symlink); file-size, line-count, file-count, ring-size, config-size, and traversal limits bound memory and CPU. |
| Hand-editing `paths` in the config | Deleting the entry of a still-encrypted file hides it from `rekey`, stranding it under the old domain key after a rotation. Use `remove`, which refuses exactly this. |
| Plaintext crafted to start with the magic | Probe-only `check` would pass it. `encrypt` errors on such files unless the user explicitly passes `--assume-plaintext`; use `verify` for authenticated checking. |
| Staged-but-plaintext content in git | Working-tree `check` cannot see the index; use the pre-commit recipe in [cli.md](cli.md), which exports the index with `git checkout-index` and runs `check` against the staged tree (staged config included). |
| macOS case/normalization-insensitive volumes | Arguments are re-spelled from directory listings, so typed case cannot poison key derivation; residual Unicode-normalization mismatches fail closed as authentication errors. ASCII filenames avoid the issue. |

## Choosing a tool

- Need line-diffable encrypted files in git, and the leakage above is
  acceptable for your data (typical: high-entropy tokens, personal
  configs in a private repo) → **simple-encrypt**.
- Need to hide file structure and change patterns, want whole-file
  encryption with transactional robustness →
  **git-simple-encrypt**.
- Need multi-recipient/asymmetric encryption or public-audience threat
  models → **age** / **git-crypt** class tools.
