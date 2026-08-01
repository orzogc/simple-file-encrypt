# simple-file-encrypt — Design Overview

`simple-file-encrypt` is a command-line tool that encrypts and decrypts local
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

- Not a structure-hiding encryptor. When confidentiality of line-level
  patterns matters, whole-file tools (`age`, `git-crypt`) are the right
  shape; this one deliberately exposes those patterns for diffability
  (see the comparison below).
- No multi-user key management, no asymmetric recipients, no OS keyring
  integration.
- No clean/smudge filters, hooks management, or any git subprocess calls.
- No protection against an attacker who runs code on the user's machine,
  and no secure deletion of plaintext that ever touched disk.
- Windows is not supported (see Platforms below).

## Core concepts

- **Domain**: a directory tree rooted at the directory containing a
  `.simple-file-encrypt.toml` file (the **domain config**). Every operation
  resolves its targets to exactly one domain by walking up from the
  target path (like git discovering `.git`), stopping at repository
  boundaries. Nested domains are rejected within one repository.
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
  `(domain key, canonical relative path, mode, content)` — no
  timestamps, no randomness at encryption time, no caches. The
  password, salt, and KDF parameters only gate access to the domain
  key.

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
   equality within a path and across its history and clones (scoped to
   one key epoch; a `rekey` breaks direct equality, though positional
   correlation may remain), change locations — is accepted and
   documented. Users who cannot accept it force binary mode or use a
   different tool.
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
   explicit override flags; file, line, config, password, and traversal
   sizes are hard-capped; base64 must be canonical so, in a fixed mode,
   every plaintext has exactly one valid ciphertext (the same content
   has different valid ciphertexts in text and binary mode — see
   [format.md](format.md)).

## Comparison with age and git-crypt

The closest widely used alternatives solve adjacent problems with
different trades:

| | `age` | `git-crypt` | simple-file-encrypt |
|---|---|---|---|
| Shape | standalone file encryptor | git clean/smudge filter | standalone in-place CLI, never calls git |
| Granularity | whole file | whole file | per line (text), chunked + file tag (binary) |
| Determinism | randomized per encryption | deterministic (nonce from a content HMAC) | deterministic per line |
| Ciphertext diff/merge | opaque, churns on every re-encryption | opaque, stable for unchanged content | line-level diff and textual merge |
| Structure leakage | total length only | per-file changed/unchanged, length | exact line lengths, counts, equality, change positions |
| Recipients | X25519 / ssh keys / scrypt passphrase, multi-recipient | one symmetric key, GPG-wrapped per collaborator | one password, no multi-recipient |
| Key rotation | re-encrypt to new recipients | no built-in rekey | `passwd` re-wraps (no ciphertext churn); `rekey` migrates in memory |
| git dependency | none | required (filters) | none |
| Working tree | explicit encrypt/decrypt | transparent (plaintext checkout) | explicit in-place encrypt/decrypt |
| Size limits | streaming | streaming | whole file in memory, 256 MiB cap |

In short: `age` hides structure but churns ciphertext on every
encryption; `git-crypt` hides structure with stable ciphertext, bound
to git filters and hard to rekey; simple-file-encrypt trades structure
confidentiality for line-level diff and merge.

## Operational consequences

- **Config and ciphertext are a pair.** Copying an encrypted file out of
  the domain (or losing `.simple-file-encrypt.toml`) makes it undecryptable.
  In git they live in the same repository, which is the intended
  deployment.
- **`passwd` is not revocation.** The old wrapped ring stays in git
  history and the domain keys are unchanged. Compromise response is
  `passwd` + `rekey`, and even that only protects future content — see
  [threat-model.md](threat-model.md).
- **Renames require plaintext.** Decrypt → move → re-encrypt. Decrypting
  a moved ciphertext fails authentication (path-bound keys); the error
  message hints at this cause.
- **Crash windows.** A crash can leave a stale `.simple-file-encrypt.tmp.*`
  file (mode `0600`; during decryption it contains plaintext). Every
  exclusive-lock run sweeps the domain root and all target parent
  directories. Treat a crash during decryption as a potential plaintext
  spill — and note that in-place encryption never securely erases old
  plaintext from disk, snapshots, or git history.
- **Memory model.** Files are processed whole in memory, with a 256 MiB
  hard cap and a 2²² cap on lines per text file; peak memory is a
  bounded multiple of the file size — a small one for typical content
  (input, output, and encoding buffers coexist), but newline-dense
  text adds per-line bookkeeping and can reach ~17–20x the input size
  (see [format.md](format.md)). The tool targets small secret files;
  it is not a streaming encryptor.
- **Large line-count files.** Each line costs ~22 bytes plus one third
  of its own length (base64); a file with hundreds of thousands of lines
  grows noticeably. Use `force_binary` for such files.

## Engineering

- **Language**: Rust, edition 2024, MSRV 1.89 (`std` file locking).
- **Crate shape**: single binary crate `simple-file-encrypt` with an internal
  `lib.rs` so integration tests can call the library API. The library
  API is not public and carries no stability promise.
- **Dependencies** (intentionally lean): `clap` (derive CLI), `argon2`,
  `aes-siv` (RFC 5297 AEAD), `blake3`, `rand`, `zeroize`, `base64`,
  `serde` + `toml`, `rpassword`, `libc` (Unix open flags). The
  `zeroize` features of `argon2` and `cmac`/`aes` are enabled via
  feature unification (see [crypto.md](crypto.md) hygiene). The direct
  `aes`/`cmac` deps exist only for that unification: a PR bumping
  `aes-siv` must align them in the same PR (Dependabot ignores them;
  CI's feature-unification assertion catches a split). Advisory
  locking uses `std`'s native
  `File::try_lock` (stable since 1.89); temp files are created by hand
  (`O_EXCL | O_NOFOLLOW`, CSPRNG names) so no temp-file crate is
  needed. Dev: `proptest`, `assert_cmd`, `tempfile`.
- **Platforms**: Linux and macOS are supported and tested in CI; on
  macOS, case-insensitive volumes are handled by re-spelling paths from
  directory listings, with residual Unicode-normalization edge cases
  documented as fail-closed. Windows is neither tested nor supported.
- **Testing**: unit tests (line splitting, path canonicalization, probe,
  determinism, tamper rejection, text detection, KDF tier validation,
  bounded reads, temp-sweep matching and sweep symlink safety), property
  tests (encrypt/decrypt round-trip is lossless for arbitrary byte
  sequences), CLI integration tests (end-to-end flows, `rekey` rotation
  and resume (`--continue`) semantics, locking, `check`/`verify`,
  synthesized `.git`-file repository boundaries (the worktree/submodule
  shape), and hostile filesystem states: symlinked managed ancestors
  and domain roots (including argument-introduced ones), non-regular
  configs, control-character or non-UTF-8 names (typed and
  discovered), newline-dense probe hits, broken-pipe output,
  skipped-special scan/rotation semantics, concurrent
  parent/child `init`), a key-ring tamper matrix over two- and
  three-entry rings (swap / drop head, middle, or tail / insert /
  duplicate / re-attach pre-prune wrappers → all rejected; whole-config
  rollback → cryptographically accepted by design and pinned as such;
  intact old-epoch file decrypts and migrates; mixed-epoch file fails;
  post-prune old-epoch file fails with the history hint), and golden
  fixtures with a fixed password/salt/domain key that pin the wire
  format and the derivation chain, so accidental format breaks fail
  loudly. Post-commit fsync failures are fault-injected through a
  test-only thread-local hook; kill/crash mid-rename remains covered
  by design review and the failure-semantics spec, not by tests.
- **CI**: GitHub Actions on Linux + macOS, with every action pinned to
  a full commit SHA (Dependabot bumps them) and every cargo invocation
  `--locked` (a manifest/lockfile mismatch fails instead of silently
  regenerating the lock): `cargo fmt --check`,
  `cargo clippy -- -D warnings`, `cargo test`, a `cargo deny` job for
  advisories and licenses, a feature-unification assertion that the
  `zeroize` features of `aes`/`cmac` apply to the single version of
  each crate in the tree, full test runs against both musl release
  targets (`x86_64` and `aarch64` Linux, statically linked — C
  compilation for blake3's aarch64 NEON goes through the
  cargo-zigbuild shims in `ci/`, with the Zig toolchain download
  verified against a SHA-256 pinned in-repo), and a short `cargo fuzz`
  smoke over the config parser and both ciphertext decoders (targets
  in `fuzz/`; the corpus is cached between runs, committed seeds in
  `fuzz/seeds/` guarantee format-boundary coverage on a cold cache,
  and crash inputs are uploaded as artifacts).
  `unsafe_code` is denied crate-wide.
- **Release**: pushing a `v*` tag runs the whole CI suite (reused via
  `workflow_call`), then builds stripped release archives
  (`x86_64`/`aarch64-unknown-linux-musl` — statically linked, runs on
  any distribution — and `aarch64-apple-darwin`) with SHA-256
  checksums and keyless (Sigstore) build-provenance attestations, and
  publishes them to GitHub Releases; the tag must match the crate
  version in `Cargo.toml`.

## Versioning

A single format version (currently **1**) covers the config schema, both
ciphertext formats, and all derivation/AD context strings. The tool
refuses to operate on a config or ciphertext with a newer version, and
refuses unknown config keys. Any breaking change bumps the version
everywhere at once.
