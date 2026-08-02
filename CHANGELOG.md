# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The on-disk
format has its own single version (currently **1**, see
[docs/format.md](docs/format.md)), covering the config schema, both
ciphertext layouts, and all derivation strings.

## [0.2.0] - 2026-08-02

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
- **Excluded-content ownership classification**, the machinery behind
  those guards. Every excluded probe hit is checked against the whole
  key ring: full decryption — or **any surviving unit** (text line or
  binary chunk) — proves the content is this domain's, fails
  `verify`, and blocks `rekey --continue`/`--prune` until it is
  decrypted, restored, or un-excluded. The scan is built to find
  survivors: shredded lines are skipped for free with no line-count
  cutoff, binary chunks are matched header-blind on the fixed chunk
  grid plus a length-only layout (a damaged header or first unit
  hides nothing), and a damaged text header still gets its unit lines
  scanned. "Foreign" — the verdict that lets rotation proceed — is
  only ever the result of a *complete* scan within a per-file
  cryptographic work budget; a scan cut short by the budget, or
  bounded to the cap-sized window of an over-cap file, blocks
  convergence as **ambiguous** instead, and no over-cap probe hit is
  ever read as foreign (a prefix can prove ownership, never disprove
  it). Independent exclusions outside every managed entry are
  expanded as audit roots so the same guards see them; excluded
  records are capped and budgeted like selected files; the work
  budget joins the resource-limits table in `docs/format.md`. The
  genuinely indistinguishable residual shapes are documented in
  `docs/cli.md` and the threat model, and the scanners are pinned by
  budget-cut property tests and seeded fuzz targets. Hardened across
  four rounds of external review.

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

- **Nested-repository boundaries no longer pass as convergence.** A
  directory can be encrypted first and only later become a submodule
  or nested checkout; the walk never enters boundaries, so
  `rekey --continue`/`--prune` previously vouched past ciphertext
  hidden there and prune could drop its key. Boundaries inside
  managed trees are now recorded — including a managed directory
  entry that itself became a repository root, which previously
  hard-errored every audit-style command — so `status`/`verify`
  report them, a fresh `rekey` warns, and `--continue`/`--prune`
  refuse; explicit arguments naming a repository root keep the hard
  error (found by external review).
- Concurrent-modification snapshots compare permissions, hard-link
  count, and the inode change time on top of `(device, inode)`, size,
  and mtime; whole-file reads re-stat their open descriptor on
  completion; and hard-link refusals use the read-time link count
  instead of the expansion-time one — narrowing the windows a
  mid-operation rewrite, chmod, or new hard link could slip through
  (a same-size rewrite that restores the mtime still moves the
  ctime, which cannot be set from userspace).
- Coverage lookups (`force_binary`, `excludes`) binary-search the
  sorted lists per path ancestor instead of scanning them, and
  `encrypt`'s auto-add batches new entries into one sorted merge
  instead of a per-file `Vec::insert` — both were quadratic hot
  paths under a 65536-entry config; `remove` finds managed entries
  by binary search.
- Overlapping expansion roots (`paths = ["d", "d/sub"]`, overlapping
  exclusions) walk each real directory once, deduplicated by
  identity: excluded counts stay accurate and the scan budget charges
  actual work.
- `add`'s informational "already managed/excluded" lines are deferred
  until the config rewrite commits, so the output never claims a
  change that failed to reach the disk.
- Release archives now include `docs/`, `SECURITY.md`,
  `CHANGELOG.md`, and the Chinese README (the README links them); the
  crates.io package includes them too.
- A `v*` tag push no longer runs the CI suite twice (once for the
  tag, once through the release workflow's call).

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

[0.2.0]: https://github.com/orzogc/simple-file-encrypt/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/orzogc/simple-file-encrypt/releases/tag/v0.1.0
