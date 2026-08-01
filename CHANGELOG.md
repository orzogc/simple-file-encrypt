# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The on-disk
format has its own single version (currently **1**, see
[docs/format.md](docs/format.md)), covering the config schema, both
ciphertext layouts, and all derivation strings.

## [0.2.0] - 2026-08-01

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

### Compatibility

- The config schema stays at format version 1. The `excludes` key is
  written only when non-empty, so configs not using the feature remain
  loadable by 0.1.x; a config that carries the key is rejected by 0.1.x
  as an unknown field (fail-closed).

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

[0.1.0]: https://github.com/orzogc/simple-file-encrypt/releases/tag/v0.1.0
