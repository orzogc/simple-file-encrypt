# simple-encrypt — Design Overview

`simple-encrypt` is a command-line tool that encrypts and decrypts local files
in place with a single password. It is designed so that encrypted files behave
well inside a git repository — ciphertext is line-diffable, mergeable, and
deterministic — while the tool itself never talks to git.

This document is the entry point. Detailed specifications live in:

| Document | Contents |
|---|---|
| [crypto.md](crypto.md) | Key hierarchy, nonce derivation, AEAD usage, verifier |
| [format.md](format.md) | Normative wire formats: config file, text and binary ciphertext |
| [cli.md](cli.md) | Command semantics, file selection, failure semantics |
| [threat-model.md](threat-model.md) | Guarantees, leakage inventory, non-goals |

## Goals

- **Simple**: one password, one config file, no daemon, no git plumbing, no
  transaction journal. Small, auditable codebase.
- **Git-friendly ciphertext**: re-encrypting unchanged content yields
  byte-identical ciphertext; for text files, encryption is per line, so
  `git diff` shows exactly which lines changed and textual merges of
  ciphertext work when different lines were edited.
- **Honest security**: the confidentiality trade-offs of deterministic
  per-line encryption are documented, not hidden. See
  [threat-model.md](threat-model.md).
- **Fail closed**: malformed input, unknown versions, unknown config keys, and
  authentication failures are hard errors, never silent fallbacks.

## Non-goals

- Not a replacement for [git-simple-encrypt](https://github.com/orzogc/git-simple-encrypt)
  when strong confidentiality of structure matters. That tool hides line-level
  patterns; this one deliberately exposes them for diffability.
- No multi-user key management, no asymmetric recipients, no keyrings.
- No clean/smudge filters, hooks management, or any git subprocess calls.
- No protection against an attacker who can run code on the user's machine.
- Windows is not supported (see Platforms below).

## Core concepts

- **Domain**: a directory tree rooted at the directory containing a
  `.simple-encrypt.toml` file (the **domain config**). Every operation
  resolves its targets to exactly one domain by walking up from the target
  path (like git discovering `.git`). Nested domains are rejected.
- **Domain config**: a TOML file committed alongside the ciphertext. It holds
  the format version, the Argon2id parameters, the domain salt, the password
  verifier, the list of **managed paths**, and the `force_binary` list.
  Ciphertext is useless without its domain config — they must be kept (and
  committed) together.
- **Modes**: each file is encrypted in **text mode** (per line) or **binary
  mode** (whole file, chunked). Files whose content contains a NUL byte, and
  files matched by `force_binary`, use binary mode; everything else uses text
  mode. The mode is recorded in the ciphertext itself.
- **In-place operation**: encryption and decryption replace the file at the
  same path. Encrypted files are recognized by magic (a header line for text
  mode, magic bytes for binary mode), not by file extension.
- **Determinism**: ciphertext is a pure function of
  `(password, domain salt, KDF parameters, canonical relative path, content)`.
  Nothing else — no timestamps, no randomness at encryption time, no caches.

## Key design decisions

Each decision below was weighed against alternatives; the rationale is what
matters for future maintenance.

1. **Single password, Argon2id, zero persistence.** The password never touches
   disk. Scripts use the `SIMPLE_ENCRYPT_PASSWORD` environment variable.
2. **Per-line deterministic encryption for text.** The point of the tool.
   Equal lines produce equal ciphertext lines (within one file), so git works
   naturally. The resulting leakage (line equality, line count, line lengths,
   change locations) is accepted and documented. Users who cannot accept it
   should force binary mode or use a different tool.
3. **Domain salt in the config file, per-file subkeys from paths.** The salt
   is public by definition, so it can be committed. Per-file keys are derived
   from the master key and the canonical relative path, which removes
   cross-file ciphertext equality without any salt cache or git dependency.
   Consequence: renaming a file changes (and, for an already-encrypted file,
   breaks) its ciphertext — rename in plaintext state (decrypt, move,
   re-encrypt).
4. **Password verifier in the config file.** Every operation that needs the
   password checks it against a stored verifier first, so a wrong password
   fails immediately and mixed-password states cannot be created. The
   verifier adds no attack surface: any ciphertext line already allows
   offline password testing; password strength and Argon2id are the only real
   defenses either way.
5. **Line-independent integrity; no AAD chain.** Each line (or binary chunk)
   is authenticated independently. Line reordering, deletion, duplication,
   truncation, and cross-version splicing are not detected — that is the
   price of mergeability, and rollback protection is delegated to git
   history. Binary chunks bind `(chunk index, is-last flag)` so chunk
   reordering and truncation *are* detected, but no chain links chunks, so a
   local edit in a large binary changes only local ciphertext.
6. **No compression.** Keeps the dependency set small, preserves binary-mode
   locality, and avoids ciphertext churn from compressor version drift.
   A flags byte is reserved in the binary header for the future.
7. **Per-file atomicity only; no transactions.** Each file is replaced via
   temp file + fsync + rename. Multi-file operations stop at the first error
   and report what was and was not done. Password changes use a three-phase
   flow (decrypt all → swap config → encrypt all) that structurally cannot
   mix old- and new-password ciphertext; see [cli.md](cli.md).
8. **Serial execution, no locking.** Protected files are small and few;
   parallelism is not worth the complexity. Concurrent invocations on the
   same domain are unsupported and documented as such.

## Comparison with git-simple-encrypt

| | git-simple-encrypt | simple-encrypt |
|---|---|---|
| Granularity | whole file (64 KiB chunks, AAD chain) | per line (text), chunked (binary) |
| Ciphertext diff/merge | opaque | line-level |
| Structure leakage | file changed / unchanged only | line equality, lengths, positions |
| Salt | per file, in header + cache | per domain, in committed config |
| Password check | HEAD anchor via git | verifier in config |
| git dependency | required (subprocess plumbing) | none |
| Atomicity | two-phase commit + journal | per-file temp + rename |
| Code size | ~15k lines | small by design |

## Operational consequences

- **Config and ciphertext are a pair.** Copying an encrypted file out of the
  domain (or losing `.simple-encrypt.toml`) makes it undecryptable. Back them
  up together; in git they live in the same repository, which is the intended
  deployment.
- **Renames require plaintext.** Decrypt → move → re-encrypt. Decrypting a
  moved ciphertext fails authentication (path-bound keys); the error message
  hints at this cause.
- **Crash windows.** A crash can leave a stale `.simple-encrypt.tmp.*` file;
  during decryption it may contain plaintext. Stale temp files are deleted
  when a later run encounters them. Treat a crash during decryption as a
  potential plaintext spill (same stance as git-simple-encrypt).
- **Memory model.** Files are processed whole in memory. The tool targets
  small secret files (well under 100 MB); it is not a streaming encryptor.
- **Large line-count files.** Each line costs ~54 bytes plus one third of
  its own length (base64); a file with hundreds of thousands of lines
  grows noticeably. Use `force_binary` for such files.

## Engineering

- **Language**: Rust, edition 2024, MSRV 1.88.
- **Crate shape**: single binary crate `simple-encrypt` with an internal
  `lib.rs` so integration tests can call the library API. The library API is
  not public and carries no stability promise.
- **Dependencies** (intentionally lean): `clap` (derive CLI), `argon2`,
  `chacha20poly1305` (XChaCha20-Poly1305), `blake3`, `rand`, `zeroize`,
  `base64`, `serde` + `toml`, `thiserror` (typed core errors), `anyhow`
  (CLI boundary), `rpassword`, `tempfile`. Dev: `proptest`, `assert_cmd`.
- **Platforms**: Linux and macOS are supported and tested in CI. Windows is
  neither tested nor supported: path-derived subkeys interact badly with
  case-insensitive filesystems, and the code assumes Unix path semantics.
- **Testing**: unit tests (line splitting, path canonicalization, probe,
  determinism, tamper rejection, text detection), property tests
  (encrypt/decrypt round-trip is lossless for arbitrary byte sequences),
  CLI integration tests (end-to-end flows, `passwd` interruption semantics,
  `check`/`status`), and golden fixtures with a fixed password/salt that pin
  the wire format so accidental format breaks fail loudly.
- **CI**: GitHub Actions on Linux + macOS: `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test`.

## Versioning

A single format version (currently **1**) covers the config schema and both
ciphertext formats. The tool refuses to operate on a config or ciphertext
with a newer version, and refuses unknown config keys. Any breaking change to
derivation contexts, AAD strings, or wire layout bumps the version.
