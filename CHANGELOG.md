# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The on-disk
format has its own single version (currently **1**, see
[docs/format.md](docs/format.md)), covering the config schema, both
ciphertext layouts, and all derivation strings.

## [Unreleased]

### Added

- **Excluded paths** (`excludes` in the domain config, maintained with
  `add --exclude` / `remove --exclude`): files and directories that are
  never selected for encryption, even under a managed directory — for
  keeping a README, an example file, or probe-colliding foreign content
  plaintext inside an otherwise-encrypted tree. Exclusion is guarded
  against stranding ciphertext: an entry may not shadow an exact
  managed entry (load-time error), `add --exclude` refuses content that
  probes as encrypted (`--force` overrides, for content that only looks
  encrypted), `decrypt` recovers excluded ciphertext, `check` exempts
  excluded paths, `verify` flags this domain's ciphertext hidden by an
  exclusion, and `rekey --continue`/`--prune` refuse to converge past
  it. See `docs/cli.md` and `docs/format.md`.

### Changed

- `force_binary` is now normalized like the other config lists: written
  in ascending byte order, deduplicated (order never had a semantic
  effect, and hand-written comments never survived a config rewrite
  anyway). `add --binary` reports marks covered by an existing
  directory mark and collapses marks a new directory mark covers;
  `remove --binary` names the covering mark when an exact entry is
  missing.
- `status` warns about `force_binary` entries that name nothing on
  disk: such an entry is silently ineffective and the file it was meant
  to cover would encrypt in text mode, leaking its line structure.

### Fixed

- **Independent exclusions are audited.** An `excludes` entry outside
  every managed entry was previously never walked, so `status`,
  `verify`, argument-less `decrypt`, and `rekey` were blind to
  ciphertext hidden there — `rekey --prune` could drop the old key such
  a file needed. The audit-style commands now expand those entries as
  roots of their own, restoring every documented guard (found by
  external review).
- **Over-cap excluded probe hits are no longer assumed foreign.** A
  valid ciphertext with data appended past the 256 MiB cap is
  recognized by bounded first-unit authentication (binary: header plus
  first chunk; text: header plus first unit line) and blocks
  key-rotation convergence like any damaged file, instead of letting
  `rekey --prune` discard its key. One residual is documented: a
  single-chunk binary ciphertext with appended data reads as foreign.
- **Excluded records are bounded.** Excluded files retained for the
  audit-style commands are capped at 65536 (like selected files) and
  every retained string is charged against the 64 MiB expansion
  budget; `encrypt` keeps only a count and `check` retains nothing, so
  a huge excluded tree no longer materializes unbounded state.
- Coverage lookups (`force_binary`, `excludes`) now binary-search the
  sorted lists per path ancestor instead of scanning them, removing a
  quadratic hot path a 65536-entry config could exploit.
- Concurrent-modification detection also compares permissions and
  hard-link count, and hard-link refusals use the read-time link count
  instead of the expansion-time one, narrowing the race windows.
- `add`'s informational "already managed/excluded" lines are deferred
  until the config rewrite commits, and `decrypt`'s excluded-recovery
  pass reports completed/failed/not-attempted like every other
  multi-file pass.
- Release archives now include `docs/`, `SECURITY.md`, `CHANGELOG.md`,
  and the Chinese README (the README links them); the crates.io
  package includes them too.
- **Nested-repository boundaries no longer pass as convergence.** A
  directory can be encrypted first and only later become a submodule
  or nested checkout; the walk never enters boundaries, so
  `rekey --continue`/`--prune` previously vouched past ciphertext
  hidden there and prune could drop its key. Boundaries inside managed
  trees are now recorded: `status`/`verify` report them, a fresh
  `rekey` warns, and `--continue`/`--prune` refuse (found by external
  review).
- **Ambiguous over-cap binary hits block convergence.** An over-cap
  excluded binary probe hit with a valid header whose first chunk does
  not authenticate is indistinguishable from a single-chunk ciphertext
  of this domain with appended data; it previously passed as foreign,
  letting `rekey --prune` drop the key. It is now classified as
  ambiguous: `verify` fails it and `--continue`/`--prune` refuse until
  the original bytes are restored or the file is moved out.
- Overlapping expansion roots (`paths = ["d", "d/sub"]`, overlapping
  exclusions) walk each real directory once, deduplicated by identity:
  excluded counts stay accurate and the scan budget charges actual
  work.
- `encrypt`'s auto-add and the `add`/`remove` coverage lookups use the
  sorted-list ancestor search instead of linear scans.

### Compatibility

- The config schema stays at format version 1. The `excludes` key is
  written only when non-empty, so configs not using the feature remain
  loadable by 0.1.x; a config that carries the key is rejected by 0.1.x
  as an unknown field (fail-closed). The versioning contract now states
  this additive-key policy explicitly (see `docs/format.md`).

## [0.1.0] - 2026-08-01

Initial release.

### Added

- In-place encryption and decryption of local files with a single
  password; encrypted files are recognized by content, not extension.
- **Text mode**: deterministic per-line encryption (AES-CMAC-SIV,
  RFC 5297), so ciphertext is line-diffable and mergeable in git, and
  unchanged content re-encrypts byte-identically. The confidentiality
  trade-offs are documented in
  [docs/threat-model.md](docs/threat-model.md).
- **Binary mode** (NUL-containing or `force_binary`-matched files):
  chunked whole-file encryption with a file tag that detects chunk
  reordering and cross-version splicing.
- **Envelope key model**: an Argon2id-derived key wraps random domain
  keys in a committed key ring — `passwd` re-wraps (no ciphertext
  churn), `rekey` rotates the domain key and migrates ciphertext in
  memory, `rekey --prune` drops retired epochs after verifying
  convergence.
- Domain config `.simple-file-encrypt.toml` with managed paths and
  `force_binary` overrides; strict validation, unknown keys rejected.
- Commands: `init`, `encrypt` (`e`), `decrypt` (`d`), `add`, `remove`,
  `status`, `check` (keyless CI gate), `verify` (authenticated scan),
  `passwd` (`p`), `rekey`.
- Safety mechanics: atomic `0600` temp + rename replacement with
  fsync, stale-temp sweeping, advisory per-domain locking,
  repository-boundary and symlink refusal, hostile-input resource
  budgets, and tiered KDF cost validation.
- Platforms: Linux and macOS. CI publishes release archives for both —
  static Linux binaries (x86_64/aarch64, musl) and macOS (Apple
  silicon) — with SHA-256 checksums and provenance attestations.

[Unreleased]: https://github.com/orzogc/simple-file-encrypt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/orzogc/simple-file-encrypt/releases/tag/v0.1.0
