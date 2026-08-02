# simple-file-encrypt — File Formats (Normative)

This document is the byte-level source of truth for format version **1**.
Key derivation and associated-data strings are specified in
[crypto.md](crypto.md).

General strictness rule: anything not explicitly allowed here is a hard
error — unknown versions, unknown config keys, non-zero reserved bytes,
malformed or non-canonical unit encodings, out-of-range lengths. The tool
never guesses, and in a fixed mode every plaintext has exactly one valid
ciphertext (the same content has different valid ciphertexts in text and
binary mode, and both may exist over a file's lifetime).

## Canonical relative paths

Config entries and key derivation both use the **canonical relative path**
of a file: its path relative to the domain root (the directory containing
`.simple-file-encrypt.toml`), with:

- `/` as the separator;
- no leading `./`, no trailing `/`, no empty segments, no `.` or `..`
  segments;
- valid UTF-8 (paths that are not valid UTF-8 are rejected);
- no C0, DEL, or C1 control characters (so a file name can never inject
  lines or terminal control sequences into the tool's output);
- bytes used exactly as given — no Unicode normalization and no case
  folding.

A canonical relative path is **minted** from user input by one pipeline:
normalize lexically (path arithmetic alone — `.`/`..` resolved against
the working directory; symlinks are never resolved), require the result
to fall inside the domain root, then re-spell every component that
exists on disk with the **filesystem-reported name** (as returned by
directory enumeration — this defuses case-insensitive filesystems such
as macOS APFS), keeping the typed spelling for any missing suffix (an
`add` of a not-yet-created file, a `remove` of a deleted one).
Recursion uses directory-reported names by construction.

Minting happens when a path enters the system: resolving an explicit
argument, or storing an entry via `add`/auto-add. Afterwards the
**stored bytes are authoritative**: config entries are fed to key
derivation exactly as recorded and are never re-spelled at use time, so
keys stay stable even if on-disk case later drifts on a
case-insensitive volume (opening still succeeds there; on
case-sensitive filesystems the drift is visible as a missing file).
Unicode normalization differences can still cause mismatches on macOS —
always fail-closed as authentication errors, never wrong plaintext —
and ASCII filenames avoid the issue entirely.

Directory entries use the same form as file entries; whether an entry
denotes a directory is resolved against the filesystem at the moment it is
used. The canonical relative path is the exact byte string fed to
`blake3::keyed_hash` for per-file key derivation. Renaming a file
therefore changes its keys: rename in plaintext state.

## Domain config: `.simple-file-encrypt.toml`

```toml
# Managed by simple-file-encrypt. `salt`, `wrapped_keys`, and [kdf] are
# security-critical: do not edit them by hand.
version = 1

# 16 random bytes, lowercase hex.
salt = "9f86d081884c7d659a2feaa0c55ad015"

# Key ring: AES-SIV(kek, domain_key), 48 bytes (96 hex chars) each,
# newest first — entry 0 is the current key. Older entries keep
# pre-`rekey` ciphertext decryptable until `rekey --prune`.
wrapped_keys = [
    "b5bb…(96 hex chars)…09e2",
]

# Managed paths: files and directories (recursive), canonical relative
# paths (no trailing slash; directory-ness is resolved at run time).
# Maintained by the tool: ascending byte order, deduplicated.
paths = [
    ".env",
    "secrets",
]

# Excluded paths: files and directories (recursive) never selected for
# encryption, even under a managed directory. Maintained by the tool:
# ascending byte order, deduplicated. Older versions of
# simple-file-encrypt refuse a config that carries this key.
excludes = [
    "secrets/README.md",
]

# Maintained by `add --binary` / `remove --binary`: paths (files or
# directories) always encrypted in binary (whole-file) mode, even if
# their content looks like text. Ascending byte order, deduplicated.
force_binary = [
    "secrets/huge-export.csv",
]

[kdf]
algorithm = "argon2id"
memory_kib = 65536
iterations = 3
parallelism = 1
```

The `[kdf]` table comes last: everything after a TOML table header
belongs to that table, so top-level keys must precede it. The values
above are examples; the comments and layout are byte-for-byte what the
tool writes.

Validation on load (all failures are hard errors):

- `version` must equal `1`; greater values mean "produced by a newer
  tool".
- Unknown keys anywhere in the file are rejected
  (`deny_unknown_fields`), so typos cannot silently disable protection.
- `salt`: exactly 32 lowercase hex chars. `wrapped_keys`: 1 to 64
  entries, each exactly 96 lowercase hex chars; each entry must unwrap
  under associated data bound to the ring length and its position
  (see [crypto.md](crypto.md)), so any reordering, dropping (tail
  truncation included), inserting, or duplicating of entries within a
  config generation is detected.
- `algorithm` must be `"argon2id"`. Parameter tiers (validity floor,
  security floor, resource ceiling): see [crypto.md](crypto.md).
- Every `paths` / `force_binary` / `excludes` entry must be a valid
  canonical relative path; a hand-edited entry that violates the rules
  (e.g. a trailing `/`) is a load-time error. A trailing `/` in
  command-line input is stripped before storing.
- No entry may target tool- or git-critical files: an entry with any
  component named `.git`, or whose final component is `.gitattributes`,
  `.gitmodules`, or `.simple-file-encrypt.toml`, is a load-time error — the
  managed list must never claim paths that every command would refuse
  to touch (and an `excludes` entry for them would be misleading: they
  are never encrypted anyway).
- No `excludes` entry may equal or cover an exact `paths` entry: a fully
  shadowed managed entry is a contradiction (it could never be
  selected), and hand-editing one in could strand still-encrypted
  content — a load-time error. An `excludes` entry strictly below a
  managed *directory* entry is the intended use. A `force_binary` entry
  covered by an exclusion is allowed: the mark is dormant while the
  exclusion stands and applies again once it is removed.
- `paths`, `force_binary`, and `excludes` may be empty or absent
  (treated as empty). The tool omits the `excludes` key entirely when
  the list is empty, so configs not using the feature remain loadable
  by tool versions that predate it; a config that carries the key is
  rejected by those versions as an unknown field (fail-closed).
- The config file itself must not exceed 1 MiB, and `paths`,
  `force_binary`, and `excludes` together must not exceed 65536 entries.

`init` creates the config with `O_EXCL`; `add`, `remove`, `passwd`,
`rekey`, and `encrypt` (auto-add) rewrite it atomically (temp + rename).
All three path lists are tool-maintained — `paths` by `add`/`remove`,
`force_binary` by `add --binary`/`remove --binary`, `excludes` by
`add --exclude`/`remove --exclude` (see [cli.md](cli.md)) — and written
in ascending byte order, deduplicated. Hand edits still load when they
pass validation (the CLI is preferred: it mints canonical spellings —
see above — where a hand-typed path can silently mismatch), but any
rewrite re-renders the stable form: user comments and ordering inside
the file do not survive.

## Ciphertext probe

A file is considered encrypted (keylessly) if and only if:

- its first 8 bytes equal `BIN_MAGIC` (binary mode), or
- its first line starts with `#simple-file-encrypt` (text mode).

Probe refinements:

- A first line that starts with `#simple-file-encrypt` but is not one of the
  two exact v1 header forms below is "unrecognized": ciphertext from a
  newer tool, or colliding plaintext. Write commands treat it as a hard
  error — version handling is never relaxed implicitly; the explicit
  `encrypt --assume-plaintext` escape is specified in [cli.md](cli.md).
  Read-only commands report it without aborting: `status` shows
  `unrecognized`, `check` counts it as an offender, `verify` records it
  as a failure.
- A probe hit does not prove the file is *our* valid ciphertext.
  Commands that skip "already encrypted" files first authenticate the
  first unit (or the empty-file marker) against the key ring, and treat
  a failure as a hard error — foreign ciphertext, corruption, a moved
  file, or plaintext that collides with the probe. `encrypt`'s
  disambiguation, migration, and `--assume-plaintext` rules are in
  [cli.md](cli.md); that flag is also the only way to manage plaintext
  that genuinely starts with `BIN_MAGIC` (magic bytes chosen to make
  this practically impossible).

## Text ciphertext format

A text-mode ciphertext is itself a text file, framed by exact LF
bytes — any end-of-line conversion (e.g. git's `autocrlf`) corrupts it,
so managed paths must be marked `-text` in `.gitattributes`
(see [cli.md](cli.md)):

```
#simple-file-encrypt v1 text\n                     (non-empty plaintext)
<one unit line per plaintext line>

#simple-file-encrypt v1 text <22 base64 chars>\n   (empty plaintext; nothing else)
```

- **Header line**: exactly `#simple-file-encrypt v1 text`, or — for an empty
  plaintext only — that string, one space, and the 22-character base64
  empty-file marker (see [crypto.md](crypto.md)), which must be
  canonical like every unit (its four trailing bits zero). Always
  newline-terminated. A bare header with zero unit lines is malformed;
  a marker header followed by anything is malformed.
- **Unit lines**: each plaintext line (split at `\n`; `\r` stays inside
  the line; zero-length lines included) becomes one line of
  `base64_standard_nopad(SIV(16) || ciphertext)` in the same order. A
  unit line decodes to at least 16 bytes; an encrypted empty line is
  exactly 22 characters. The base64 character count uniquely determines
  the decoded length, so unit lines reveal the exact plaintext line
  length (accepted; see [threat-model.md](threat-model.md)).
- **Trailing-newline mirroring**: the last unit line ends with `\n` if
  and only if the plaintext ended with `\n`. This makes the mapping
  bijective:

  | plaintext | ciphertext |
  |---|---|
  | `` (empty) | `header + marker\n` |
  | `\n` | `header\n` + `unit("")\n` |
  | `abc` | `header\n` + `unit("abc")` |
  | `abc\n` | `header\n` + `unit("abc")\n` |
  | `abc\r\n` | `header\n` + `unit("abc\r")\n` |

Decoding rules (hard errors): a first line that is neither exact v1
header form; a header line not terminated by `\n`; a bare header with no
unit lines; a marker header with trailing content; any unit line
containing characters outside `[A-Za-z0-9+/]` or `=` padding; any
non-canonical base64 (a final symbol with non-zero trailing bits —
decoding then re-encoding must reproduce the line byte-for-byte); a unit
decoding to fewer than 16 bytes; SIV authentication failure.

## Binary ciphertext format

```
offset  size      field
0       8         BIN_MAGIC = 89 53 45 4E 43 0D 0A 1A   ("\x89SENC\r\n\x1a")
8       1         version = 0x01
9       1         flags   = 0x00   (reserved; must be zero)
10      6         reserved (must be all zero)
16      …         chunks: SIV(16) || ciphertext(chunk_len), consecutively
end-32  32        file_tag (see crypto.md; covers header, lengths, all SIVs)
```

- The plaintext is split into `ceil(len / 65536)` chunks (minimum one):
  every chunk except the final one is exactly 65536 bytes, and the final
  chunk holds the remainder — between 1 and 65536 bytes for a non-empty
  plaintext. An empty plaintext is exactly one zero-length chunk. A
  zero-length chunk at any index other than 0 is invalid: encryption
  never produces one and decryption rejects it.
- On-disk chunk size is `chunk_len + 16`; a full chunk is 65552 bytes.
  The minimum valid binary ciphertext is 64 bytes (16-byte header +
  one empty chunk + 32-byte file tag). Total ciphertext length uniquely
  determines the exact plaintext length (accepted leakage).

Parsing (hard errors on any violation):

```
remaining = file_len - 16 - 32       # header and trailer; must be ≥ 16
index = 0
while remaining > 65552:
    read chunk of 65552 bytes, decrypt with AD_BIN(index, last = false)
    remaining -= 65552; index += 1
error if remaining < 16, or if remaining == 16 and index > 0
read final chunk of `remaining` bytes, decrypt with AD_BIN(index, last = true)
verify file_tag over header, lengths, and all chunk SIVs (constant time)
```

Truncating at a chunk boundary turns a non-last chunk into the final one
and fails its AD; truncating mid-chunk fails the length check; reordering
fails the index binding; substituting a same-index chunk from an older
version fails the file tag; appending data fails everything.

## Resource limits

Hostile inputs must exhaust neither memory nor CPU. Hard limits
(violations are errors, not truncations):

| Limit | Value | Enforced by |
|---|---|---|
| Plaintext file size | 256 MiB | encrypt (input) and decrypt (output) |
| Ciphertext file size | 256 MiB | encrypt (output) and decrypt (input) |
| Single plaintext line | 64 MiB | encrypt (the error suggests `force_binary`) |
| Single decoded unit | 64 MiB + 16 | decrypt |
| Units (lines) per text file | 4194304 (2²²) | encrypt and decrypt (the error suggests `force_binary`) |
| Selected files per operation (after expansion) | 65536 | all commands |
| Directory entries examined per expansion or `init` scan | 1048576 (2²⁰) | expansion, `init` descendant scan |
| Directory recursion depth | 128 | expansion, `init` descendant scan |
| Excluded-file records retained per expansion (audit-style commands; `encrypt`/`check` retain none) | 65536 | expansion |
| Retained path bytes per expansion (selected and excluded records charge every string they keep — relative path twice, absolute path, covering entry — plus visited directories, skipped specials, missing entries) | 64 MiB | expansion |
| Config file size | 1 MiB | config load |
| `paths` + `force_binary` + `excludes` entries | 65536 | config load |
| `wrapped_keys` entries | 64 | config load |
| Password length | 4096 bytes | all password input |
| Ownership-scan work budget per excluded probe hit | 4 GiB processed-byte equivalents (each authentication attempt charges the unit's length + 128) | the any-unit scan of excluded-content classification |

The ownership-scan budget meters cryptographic work only — parsing
(line splitting, failed base64 decodes) is bounded by the file-size
caps — and running out is reported as *inconclusive*, which blocks
key rotation like ciphertext that cannot be ruled out as this
domain's, never as "foreign" (see [cli.md](cli.md) under `rekey`). It
covers a complete scan of any format-valid in-cap file under a ring
of several keys; content packed with more decodable pseudo-units than
the format allows can exhaust it sooner, turning an "ignored" foreign
verdict into a blocking ambiguous one. Unlike the wire-format
constants above it is an implementation bound and may be retuned in
future versions.

Both sides of every limit are enforced, so `encrypt` can never produce a
ciphertext that `decrypt` refuses: a text file whose ciphertext or line
count would exceed the caps, or a binary plaintext within ~64 KiB of
256 MiB (whose chunk overhead would push the ciphertext over), is
rejected at encryption time, before any cryptographic work. KDF cost
limits are separate (see [crypto.md](crypto.md)). Files are processed
whole in memory by design; these limits bound that, with peak memory a
bounded multiple of the file size — for typical content a small one,
but newline-dense text costs per-line bookkeeping (a slice and a
length per line, plus output) that can reach ~17–20x the input size
(see [design.md](design.md)).

## Constants

| Name | Value |
|---|---|
| `SALT_LEN` | 16 bytes (32 hex chars in config) |
| `DOMAIN_KEY_LEN` | 32 bytes |
| `WRAPPED_KEY_LEN` | 48 bytes per ring entry (96 hex chars in config) |
| `SIV_LEN` | 16 bytes (also the per-unit overhead) |
| `FILE_TAG_LEN` | 32 bytes |
| `CHUNK_SIZE` | 65536 bytes (65552 on disk) |
| `TEXT_MAGIC_PREFIX` | `#simple-file-encrypt` |
| `TEXT_HEADER_V1` | `#simple-file-encrypt v1 text` |
| `BIN_MAGIC` | `89 53 45 4E 43 0D 0A 1A` |
| `BIN_HEADER_LEN` | 16 bytes |
| Base64 | standard alphabet, no padding, canonical only |
| Hex | lowercase |

## Versioning

Format version 1 covers the config schema, both ciphertext layouts, and
all derivation/AD context strings (which embed `v1`). Within a version,
the config schema may gain **optional keys** (`excludes` is one): a
config not using them is byte-compatible in both directions, and an
older tool rejects a config that carries one as an unknown field —
fail-closed, though without the explicit "upgrade" hint a version bump
would give. Removing a key, changing the meaning of an existing one, or
touching a ciphertext layout or derivation string is an incompatible
change and bumps the version everywhere at once; the tool refuses newer
versions with a clear "upgrade simple-file-encrypt" error and refuses
unknown or legacy layouts outright.
