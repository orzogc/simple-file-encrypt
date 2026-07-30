# simple-encrypt — Threat Model

This tool makes a deliberate, unusual trade: it encrypts text files line by
line, deterministically, so that ciphertext diffs and merges like text. That
buys git ergonomics and costs confidentiality of *structure*. This document
states exactly what is and is not protected. The README must carry the same
message; users who skip this page should still not be surprised.

## Assets

- The plaintext content of managed files (tokens, credentials, private
  notes, small binary secrets).
- The password.

## In-scope adversary

A **passive reader of the ciphertext at rest**: a repository hosting
provider, someone who leaks or steals a clone or backup, a future reader of
git history. They can read every committed version of the ciphertext and the
domain config, and can run offline computation against them. They cannot run
code on the user's machine and cannot cause the user to encrypt chosen data.

## Guarantees (against the in-scope adversary)

- **Content confidentiality per unit**: recovering the bytes of any line
  (text mode) or chunk (binary mode) requires the password. The scheme is
  deterministic authenticated encryption: it reveals unit equality and
  nothing else about unit contents.
- **No forgery**: no ciphertext unit that was never legitimately produced
  for that exact file path can be created without the key. Tampering with a
  unit's bytes is detected on decryption.
- **Wrong-password detection**: operations fail fast against the config
  verifier; mixed-password domains cannot arise from typos.
- **Deterministic re-encryption**: unchanged plaintext never churns
  ciphertext, so git history stays small and reviewable.

## Leakage inventory (accepted by design)

Ordered roughly by how much it usually matters:

1. **Line equality within a file** (text mode): identical plaintext lines in
   one file have identical ciphertext lines — also across the git history of
   that file (reverting a line is visible as the old ciphertext returning).
   High-frequency short lines (empty lines, `}`, `true`, boilerplate) are
   realistically identifiable by frequency analysis. Cross-*file* equality
   is hidden (per-path keys).
2. **Structure** (text mode): the number of lines, each line's approximate
   length (base64 of length + 40), and exactly which lines changed between
   commits. This is the same information the git diff shows — that is the
   point, and the leak.
3. **File size** (binary mode): plaintext length is visible within chunk
   granularity; which 64 KiB regions changed is visible across versions.
4. **Confirmation attacks**: anyone who can get their own guessed line
   encrypted under the victim's key *at the same file path* (e.g. a
   collaborator proposing config lines) can confirm a guess by comparing
   ciphertext. Deterministic encryption cannot prevent this.
5. **Offline password guessing**: the config's salt, KDF parameters, and
   verifier — or any ciphertext unit — allow testing password guesses at
   Argon2id cost. Defense is password entropy and the KDF parameters; there
   is no server to rate-limit.

## Integrity limits (accepted by design)

- **Text mode**: only individual lines are authenticated. Reordering,
  deleting, duplicating whole lines, truncating the file, and splicing
  authentic lines from *older versions of the same file* are undetectable
  by the tool. Rollback and splice protection comes from git history review,
  not from the cryptography.
- **Binary mode**: chunk order and count are authenticated (index + last
  flag), but a chunk can be replaced by the same-index chunk from an older
  version of the same file undetectably.
- **Whole-file rollback**: an attacker with write access can revert any file
  to an older ciphertext; git history is the defense.
- **Unauthenticated framing**: the binary header and the text header line
  carry no tag of their own. Corrupting them makes the file probe as
  plaintext, which `decrypt` then skips silently — but `check` flags such
  a file as a plaintext offender, which surfaces the damage.

## Out of scope

- **A compromised machine**: malware, a hostile local user, memory scraping.
  Zeroization of keys and passwords is best-effort hygiene, not a defense.
- **The decrypted working tree**: while files are decrypted they are ordinary
  plaintext on disk; the tool does not shorten that window and `check` only
  warns before commits.
- **Active attackers with an encryption oracle** beyond the confirmation
  attack above (e.g. adaptive chosen-plaintext games): the deterministic
  design concedes these.
- **Traffic/metadata beyond the repository**: filenames, file count, commit
  times, and commit messages are plainly visible in git regardless.
- **Availability**: an attacker who can write to the repository can destroy
  ciphertext; git history is the recovery path.

## Operational risks and mitigations

| Risk | Stance |
|---|---|
| Losing `.simple-encrypt.toml` | Ciphertext is undecryptable without it (salt lives there). It is committed next to the ciphertext; git is the backup. |
| `SIMPLE_ENCRYPT_PASSWORD` in the environment | Visible to same-user processes via `/proc`; prefer the interactive prompt outside CI. |
| Crash during decryption | May leave a `.simple-encrypt.tmp.*` containing plaintext until the next run cleans it; treat as a plaintext spill. |
| Concurrent runs on one domain | Unsupported; no lock. Do not do it. |
| Moving/renaming an encrypted file | Decryption fails (path-bound keys). Rename in plaintext state; the auth-failure message hints at this cause. |
| Hostile config in a cloned repo | KDF parameters are bounded before running Argon2 (no memory/CPU bomb); unknown keys and versions are rejected; path entries cannot escape the domain root. |
| Staged-but-plaintext content in git | `check` reads the working tree only; use `git commit -a` or re-stage after encrypting. |
| Hand-editing `paths` in the config | Deleting the entry of a still-encrypted file hides it from `passwd`, stranding it under the old password after a change. Use `remove`, which refuses exactly this. |
| Plaintext crafted to start with the magic | Probe-only `check` would pass it. `encrypt` errors on such files instead of producing them, so this needs deliberate hand-crafting; treat `check` as an accident gate, not tamper detection. |

## Choosing a tool

- Need line-diffable encrypted files in git, and the leakage above is
  acceptable for your data (typical: high-entropy tokens, personal configs
  in a private repo) → **simple-encrypt**.
- Need to hide file structure and change patterns, want whole-file
  encryption with transactional robustness → **git-simple-encrypt**.
- Need multi-recipient/asymmetric encryption or public-audience threat
  models → **age** / **git-crypt** class tools.
