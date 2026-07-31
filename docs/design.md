# simple-encrypt — Design Overview

`simple-encrypt` is a command-line tool that encrypts and decrypts local
files in place with a single password. It is designed so that encrypted
files behave well inside a git repository — ciphertext is line-diffable,
mergeable, and deterministic — while the tool itself never talks to git.

This document is the entry point. Detailed specifications live in:

| Document | Contents |
|---|---|
| [crypto.md](crypto.md) | Key hierarchy (envelope), AES-SIV usage, KDF tiers |
| [format.md](format.md) | Normative wire formats: config file, text and binary ciphertext |
| [cli.md](cli.md) | Command semantics, locking, file selection, failure semantics |
| [threat-model.md](threat-model.md) | Adversaries, guarantees, leakage inventory, non-goals |

## Goals

- **Simple**: one password, one config file, no daemon, no git plumbing,
  no transaction journal. Small, auditable codebase.
- **Git-friendly ciphertext**: re-encrypting unchanged content yields
  byte-identical ciphertext; for text files, encryption is per line, so
  `git diff` shows exactly which lines changed and textual merges of
  ciphertext work when different lines were edited. Password changes
  touch no ciphertext at all.
- **Honest security**: the confidentiality trade-offs of deterministic
  per-line encryption are documented, not hidden. See
  [threat-model.md](threat-model.md).
- **Fail closed**: malformed input, unknown versions, unknown config
  keys, non-canonical encodings, and authentication failures are hard
  errors, never silent fallbacks.

## Non-goals

- Not a replacement for [git-simple-encrypt](https://github.com/orzogc/git-simple-encrypt)
  when confidentiality of structure matters. That tool hides line-level
  patterns; this one deliberately exposes them for diffability.
- No multi-user key management, no asymmetric recipients, no OS keyring
  integration.
- No clean/smudge filters, hooks management, or any git subprocess calls.
- No protection against an attacker who runs code on the user's machine,
  and no secure deletion of plaintext that ever touched disk.
- Windows is not supported (see Platforms below).

## Core concepts

- **Domain**: a directory tree rooted at the directory containing a
  `.simple-encrypt.toml` file (the **domain config**). Every operation
  resolves its targets to exactly one domain by walking up from the
  target path (like git discovering `.git`). Nested domains are
  rejected.
- **Domain config**: a TOML file committed alongside the ciphertext. It
  holds the format version, the Argon2id parameters, the KDF salt, the
  **wrapped key ring**, the list of **managed paths**, and the
  `force_binary` list. Ciphertext is useless without its domain config —
  they must be kept (and committed) together.
- **Envelope keys**: file keys descend from a random 32-byte domain
  key; the password (via Argon2id) only wraps domain keys in the
  config's ordered key ring (entry 0 = current). `passwd` re-wraps the
  ring (cheap, no ciphertext change, no revocation); `rekey` prepends a
  fresh key and migrates ciphertext to it in memory (the compromise
  response), retaining older entries so nothing becomes undecryptable
  until `rekey --prune`.
- **Modes**: each file is encrypted in **text mode** (per line) or
  **binary mode** (whole file, chunked, plus a whole-file tag). Files
  whose content contains a NUL byte, and files matched by
  `force_binary`, use binary mode; everything else uses text mode. The
  mode is recorded in the ciphertext itself.
- **In-place operation**: encryption and decryption replace the file at
  the same path. Encrypted files are recognized by magic, not by
  extension.
- **Determinism**: ciphertext is a pure function of
  `(domain key, canonical relative path, content)` — no timestamps, no
  randomness at encryption time, no caches. The password, salt, and KDF
  parameters only gate access to the domain key.

## Key design decisions

1. **Single password + envelope encryption, zero persistence.** The
   password never touches disk; it wraps random domain keys stored in
   the config as an ordered key ring (AES-SIV wrap, whose
   authentication doubles as the password check — no separate
   verifier). This makes `passwd` and KDF upgrades free of ciphertext
   churn and keeps branches mergeable across them, at a documented
   cost: `passwd` alone does not revoke a compromised old password —
   only the `passwd` + `rekey` combination does, and only for content
   encrypted afterwards (`rekey` alone rotates the domain key, not the
   password). Retained ring entries keep pre-`rekey` ciphertext on
   unmerged branches decryptable until explicitly pruned.
2. **AES-CMAC-SIV (RFC 5297, AES-256) as the only cipher.**
   Deterministic authenticated encryption with a standardized
   specification and formal analysis, used through its nonce-free
   deterministic interface (implementations must call the raw SIV API,
   not the nonce-based AEAD wrapper — see [crypto.md](crypto.md)). One
   primitive replaces the AEAD + synthetic-nonce + conformance-check
   composition it was chosen over, and per-unit overhead is 16 bytes.
   Sub-key derivation uses BLAKE3 with globally unique context strings.
3. **Per-line deterministic encryption for text.** The point of the
   tool. Equal lines produce equal ciphertext lines (within one path),
   so git works naturally. The leakage — exact line lengths and counts,
   equality within a path and across its history and clones,
   change locations — is accepted and documented. Users who cannot
   accept it force binary mode or use a different tool.
4. **Domain salt in the config, per-file subkeys from paths.** No salt
   cache, no git dependency; per-path keys remove cross-file equality.
   Consequence: renaming a file changes (and, while encrypted, breaks)
   its ciphertext — rename in plaintext state.
5. **Line-independent integrity; binary whole-file tag.** Text units are
   authenticated individually and nothing binds them together: line
   reordering, deletion, duplication, truncation, and cross-version
   splicing are undetectable — the price of mergeability, with git
   history review as the countermeasure. Binary mode has no merge story
   to protect, so it additionally carries a deterministic whole-file tag
   that detects chunk splicing while preserving locality (a local edit
   changes one chunk plus the trailer). An authenticated empty-file
   marker gives emptiness the same unit-level authenticity as any
   content (a historically empty version can still be replayed, like
   any whole-file rollback).
6. **No compression.** Keeps the dependency set small, preserves
   binary-mode locality, and avoids ciphertext churn from compressor
   version drift. A flags byte is reserved for the future.
7. **Per-file atomicity only; no transactions.** Each file is replaced
   via a `0600` temp file + fsync + rename (permissions restored only
   after the rename, so crash remnants are never too permissive), with
   a pre-rename re-check that the target was not concurrently modified.
   Multi-file operations stop at the first error and report what was
   and was not done. `rekey` prepends a fresh key to the ring and
   migrates each file in memory — migration never writes decrypted
   plaintext to disk, and an interruption leaves every file decryptable
   under a ring key.
8. **Serial execution, advisory locking.** One process per domain,
   enforced by a non-blocking `flock` on the domain root directory (no
   lock file to commit or ignore, and immune to the config's own
   rename-replacement, which would strand a lock held on the config
   file). Protected files are small and few; parallelism is not worth
   the complexity.
9. **Hostile-input budgets everywhere.** KDF parameters are validated in
   three tiers (validity, security floor, resource ceiling) with
   explicit override flags; file, line, config, and password sizes are
   hard-capped; base64 must be canonical so every plaintext has exactly
   one valid ciphertext.

## Comparison with git-simple-encrypt

| | git-simple-encrypt | simple-encrypt |
|---|---|---|
| Granularity | whole file (64 KiB chunks, AAD chain) | per line (text), chunked + file tag (binary) |
| Cipher | XChaCha20-Poly1305, derived nonces | AES-SIV (RFC 5297), nonce-free |
| Ciphertext diff/merge | opaque | line-level |
| Structure leakage | file changed / unchanged only | exact line lengths, equality, positions |
| Key model | password → per-file Argon2 | password-wrapped domain key (envelope) |
| Password change | full re-encryption | re-wrap only (`rekey` rotates via in-memory migration) |
| Salt | per file, in header + cache | per domain, in committed config |
| Password check | HEAD anchor via git | unwrap of the domain key |
| git dependency | required (subprocess plumbing) | none |
| Atomicity | two-phase commit + journal | per-file temp + rename |
| Code size | ~15k lines | small by design |

## Operational consequences

- **Config and ciphertext are a pair.** Copying an encrypted file out of
  the domain (or losing `.simple-encrypt.toml`) makes it undecryptable.
  In git they live in the same repository, which is the intended
  deployment.
- **`passwd` is not revocation.** The old wrapped ring stays in git
  history and the domain keys are unchanged. Compromise response is
  `passwd` + `rekey`, and even that only protects future content — see
  [threat-model.md](threat-model.md).
- **Renames require plaintext.** Decrypt → move → re-encrypt. Decrypting
  a moved ciphertext fails authentication (path-bound keys); the error
  message hints at this cause.
- **Crash windows.** A crash can leave a stale `.simple-encrypt.tmp.*`
  file (mode `0600`; during decryption it contains plaintext). Every
  exclusive-lock run sweeps the domain root and all target parent
  directories. Treat a crash during decryption as a potential plaintext
  spill — and note that in-place encryption never securely erases old
  plaintext from disk, snapshots, or git history.
- **Memory model.** Files are processed whole in memory, with a 256 MiB
  hard cap and a 2²² cap on lines per text file; peak memory is a small
  multiple of the file size (input, output, and encoding buffers
  coexist). The tool targets small secret files; it is not a streaming
  encryptor.
- **Large line-count files.** Each line costs ~22 bytes plus one third
  of its own length (base64); a file with hundreds of thousands of lines
  grows noticeably. Use `force_binary` for such files.

## Engineering

- **Language**: Rust, edition 2024, MSRV 1.88.
- **Crate shape**: single binary crate `simple-encrypt` with an internal
  `lib.rs` so integration tests can call the library API. The library
  API is not public and carries no stability promise.
- **Dependencies** (intentionally lean): `clap` (derive CLI), `argon2`,
  `aes-siv` (RFC 5297 AEAD), `blake3`, `rand`, `zeroize`, `base64`,
  `serde` + `toml`, `thiserror` (typed core errors), `anyhow` (CLI
  boundary), `rpassword`, `tempfile`, `fs4` (advisory file locking).
  Dev: `proptest`, `assert_cmd`.
- **Platforms**: Linux and macOS are supported and tested in CI; on
  macOS, case-insensitive volumes are handled by re-spelling paths from
  directory listings, with residual Unicode-normalization edge cases
  documented as fail-closed. Windows is neither tested nor supported.
- **Testing**: unit tests (line splitting, path canonicalization, probe,
  determinism, tamper rejection, text detection, KDF tier validation),
  property tests (encrypt/decrypt round-trip is lossless for arbitrary
  byte sequences), CLI integration tests (end-to-end flows,
  `passwd`/`rekey` interruption and migration semantics, locking,
  `check`/`verify`, git worktree and submodule `.git`-file boundaries),
  and golden fixtures with a fixed password/salt/domain key that pin the
  wire format and the derivation chain, so accidental format breaks fail
  loudly.
- **CI**: GitHub Actions on Linux + macOS: `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test`.

## Versioning

A single format version (currently **1**) covers the config schema, both
ciphertext formats, and all derivation/AD context strings. The tool
refuses to operate on a config or ciphertext with a newer version, and
refuses unknown config keys. Any breaking change bumps the version
everywhere at once.
