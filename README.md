# simple-file-encrypt

[简体中文](README_zh-CN.md)

`simple-file-encrypt` encrypts and decrypts local files in place with a
single password, producing ciphertext that behaves well inside a git
repository: text files are encrypted **per line, deterministically**, so
ciphertext is line-diffable and mergeable, and re-encrypting unchanged
content yields byte-identical output. The tool itself never talks to
git.

## ⚠️ Read this before trusting it with your data

The git ergonomics are bought with a deliberate confidentiality trade:

- Ciphertext reveals the **exact number of lines, the exact byte length
  of every line**, and exactly which lines changed between versions.
- **Equal lines produce equal ciphertext lines** within one file (and
  across that file's git history, branches, and clones, within one key
  epoch). High-frequency short lines (`}`, empty lines, boilerplate)
  are realistically identifiable by frequency analysis alone; anyone
  who knows any committed version of a file gets a
  ciphertext→plaintext dictionary for its lines.
- Deterministic encryption protects content only to the extent it is
  **unpredictable**: random tokens and keys are protected, while
  guessable config lines can be confirmed — but only via a
  known-plaintext dictionary (any committed version of the file) or an
  encryption oracle at the same path, not from ciphertext alone.
- Text mode has **unit-level integrity only**: an attacker with write
  access can reorder, delete, duplicate, or resurrect authentic lines
  undetected. That is the price of line-level merging; review git
  history for changes you did not make.

If you need to hide file structure and change patterns, use
[git-simple-encrypt](https://github.com/orzogc/git-simple-encrypt) or an
`age`/`git-crypt`-class tool instead. The full analysis is in
[docs/threat-model.md](docs/threat-model.md) — please read it.

## How it works

- One password wraps random 32-byte **domain keys** (Argon2id →
  AES-CMAC-SIV key wrap) stored in a committed config,
  `.simple-file-encrypt.toml`. Ciphertext is useless without that config —
  keep them together in the same repository.
- Every unit (a text line, an empty-file marker, or a 64 KiB binary
  chunk) is encrypted with **AES-CMAC-SIV (RFC 5297, AES-256)** under a
  per-file key derived with BLAKE3 from the domain key and the file's
  repository-relative path. No nonces, no randomness at encryption
  time: ciphertext is a pure function of `(domain key, path, mode,
  content)`.
- Files containing NUL bytes (or matched by `force_binary`) use binary
  mode: chunked, with a whole-file tag that detects chunk splicing.
- `passwd` re-wraps the key ring and touches no ciphertext — but does
  **not** revoke the old password (git history keeps the old wrapped
  ring). Compromise response is `passwd` **then `rekey`**, which mints a
  fresh domain key and migrates every file in memory.

## Quick start

```console
$ cd your-repo
$ simple-file-encrypt init                 # once; prompts for the password
$ simple-file-encrypt add .env secrets/
$ simple-file-encrypt e                    # encrypt everything managed
$ git add -A && git commit
$ simple-file-encrypt d                    # work on plaintext locally
$ simple-file-encrypt e                    # re-encrypt before committing
```

Mark managed paths `-text` in `.gitattributes` so git never converts
their line endings (text ciphertext is byte-exact and LF-framed):

```gitattributes
.env            -text
secrets/**      -text
```

## Commands

| Command | Effect |
|---|---|
| `init` | Create `.simple-file-encrypt.toml` in the current directory |
| `encrypt` (`e`) `[PATHS…]` | Encrypt managed or given files in place (auto-adds new ones) |
| `decrypt` (`d`) `[PATHS…]` | Decrypt managed or given files in place |
| `add` / `remove <PATHS…>` | Maintain the managed list (no password needed) |
| `status` | Report each managed file's state (no password) |
| `check [PATHS…]` | CI gate: exit 0 iff everything probes as encrypted (no password) |
| `verify [PATHS…]` | Fully authenticate ciphertext in memory; `check && verify` is the complete gate |
| `passwd` (`p`) | Change the password (re-wrap only; **not** revocation) |
| `rekey [--continue] [--prune]` | Rotate the domain key and migrate ciphertext |

Details, locking, failure semantics, and git integration recipes (a
pre-commit hook that checks the **staged** tree) are in
[docs/cli.md](docs/cli.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/design.md](docs/design.md) | Design overview and rationale |
| [docs/crypto.md](docs/crypto.md) | Key hierarchy, AES-SIV usage, KDF tiers |
| [docs/format.md](docs/format.md) | Normative wire formats |
| [docs/cli.md](docs/cli.md) | Command semantics |
| [docs/threat-model.md](docs/threat-model.md) | What is and is not protected |

## Practical limits

- Files are processed whole in memory: 256 MiB per file, 2²² lines per
  text file. Renaming a managed file requires decrypting first (keys
  are path-bound). Hard-linked files are refused. Linux and macOS only.
- Honesty note: the design composes standardized, well-analyzed pieces
  (RFC 5297 AES-CMAC-SIV, BLAKE3, Argon2id), but the composition as a
  whole has not received independent cryptographic review.

## License

MIT
