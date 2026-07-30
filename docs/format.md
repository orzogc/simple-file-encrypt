# simple-encrypt — File Formats (Normative)

This document is the byte-level source of truth for format version **1**.
Key derivation and AAD construction are specified in [crypto.md](crypto.md).

General strictness rule: anything not explicitly allowed here is a hard
error — unknown versions, unknown config keys, non-zero reserved bytes,
malformed ciphertext lines, out-of-range lengths. The tool never guesses.

## Canonical relative paths

Config entries and key derivation both use the **canonical relative path** of
a file: its path relative to the domain root (the directory containing
`.simple-encrypt.toml`), with:

- `/` as the separator;
- no leading `./`, no trailing `/`, no empty segments, no `.` or `..`
  segments;
- valid UTF-8 (paths that are not valid UTF-8 are rejected);
- bytes used exactly as given — no Unicode normalization and no case
  folding. On macOS, filenames that the filesystem stores in a different
  Unicode normalization than the config records can therefore fail to
  match; ASCII filenames avoid the issue entirely.

Canonicalization is purely **lexical**: command-line input (which may be
relative to the working directory and may contain `.` or `..`) is
normalized by path arithmetic alone, then required to fall inside the
domain root — symlinks are never resolved. Input whose lexical result
would leave the domain root is rejected. Directory entries use the same
form as file entries (no trailing slash); whether an entry denotes a
directory is resolved against the filesystem at the moment it is used.

The canonical relative path of a file is the exact byte string fed to
`blake3::keyed_hash` for per-file key derivation. Directory entries in the
config follow the same rules.

## Domain config: `.simple-encrypt.toml`

```toml
# Managed by simple-encrypt. `salt`, `verifier`, and [kdf] are
# security-critical: do not edit them by hand.
version = 1

# 16 random bytes, lowercase hex.
salt = "9f86d081884c7d659a2feaa0c55ad015"

# 32-byte BLAKE3 output, lowercase hex. See crypto.md.
verifier = "a3f5…(64 hex chars)…c2d1"

[kdf]
algorithm = "argon2id"
memory_kib = 19456
iterations = 2
parallelism = 1

# Managed paths: files and directories (recursive), canonical relative
# paths (no trailing slash; directory-ness is resolved at run time).
# Maintained by the tool: ascending byte order, deduplicated.
paths = [
    ".env",
    "secrets",
]

# Maintained by hand: paths (files or directories) always encrypted in
# binary (whole-file) mode, even if their content looks like text.
force_binary = [
    "secrets/huge-export.csv",
]
```

Validation on load (all failures are hard errors):

- `version` must equal `1`; greater values mean "produced by a newer tool".
- Unknown keys anywhere in the file are rejected (`deny_unknown_fields`),
  so typos cannot silently disable protection.
- `salt`: exactly 32 lowercase hex chars. `verifier`: exactly 64 lowercase
  hex chars.
- `algorithm` must be `"argon2id"`. Parameter bounds: see
  [crypto.md](crypto.md) (hostile-config protection).
- Every `paths` / `force_binary` entry must be a valid canonical relative
  path; a hand-edited entry that violates the rules (e.g. a trailing `/`)
  is a load-time error. A trailing `/` in command-line input is stripped
  before storing.
- `paths` and `force_binary` may be empty or absent (treated as empty).

The config is rewritten atomically (temp + rename) by `init`, `add`,
`remove`, `passwd`, and `encrypt` (auto-add); the tool writes the form
above with entries in ascending byte order, deduplicated. `force_binary`
is never modified by any command — it is maintained by hand.

## Ciphertext probe

A file is considered encrypted if and only if:

- its first 8 bytes equal `BIN_MAGIC` (binary mode), or
- its first line starts with `#simple-encrypt` (text mode).

Probe refinements:

- A first line that starts with `#simple-encrypt` but is not exactly the
  v1 header is a hard error everywhere (ciphertext from a newer tool, or
  malformed content).
- A file consisting of exactly the v1 header line and nothing else is the
  valid ciphertext of an empty plaintext. It contains zero units, so there
  is nothing to authenticate; it is accepted as encrypted by content alone.

A probe hit does not prove the file is *our* valid ciphertext. Commands
that skip "already encrypted" files authenticate the first unit (line or
chunk, including the nonce conformance check) with the current keys before
skipping, and treat a failure as a hard error — the file is foreign
ciphertext, corrupted, moved from another path, or plaintext that collides
with the probe. How `encrypt` disambiguates these cases, and how
`force_binary` serves as the escape hatch for colliding *text*, is
specified in [cli.md](cli.md). Plaintext whose content starts with
`BIN_MAGIC` cannot be managed by this tool at all (there is no in-band
escape); the magic bytes were chosen to make this practically impossible.

## Text ciphertext format

A text-mode ciphertext is itself a text file:

```
#simple-encrypt v1 text\n
<unit-line or empty-mirror; one per plaintext line>
```

- **Header line**: exactly `#simple-encrypt v1 text` followed by `\n`.
  Always present, always newline-terminated.
- **Unit lines**: each plaintext line (split at `\n`; `\r` stays inside the
  line; zero-length lines included) becomes one line of
  `base64_standard_nopad(nonce || ciphertext || tag)` in the same order.
  With `NONCE_LEN = 24` and `TAG_LEN = 16`, a unit decodes to at least
  40 bytes, so a unit line is at least 54 base64 characters
  (an encrypted empty line is exactly 54).
- **Trailing-newline mirroring**: the last unit line ends with `\n` if and
  only if the plaintext ended with `\n`. An empty plaintext (zero bytes)
  produces a header line and nothing else. This makes the mapping
  bijective:

  | plaintext | ciphertext |
  |---|---|
  | `` (empty) | `header\n` |
  | `\n` | `header\n` + `unit("")\n` |
  | `abc` | `header\n` + `unit("abc")` |
  | `abc\n` | `header\n` + `unit("abc")\n` |
  | `abc\r\n` | `header\n` + `unit("abc\r")\n` |

Illustrative shape (values are not real ciphertext):

```
#simple-encrypt v1 text
mJ3xX0…54+ base64 chars…Qq
T9vZaW…
```

Decoding rules (hard errors): first line not exactly the v1 header (a
`#simple-encrypt` prefix with anything else is "unsupported version");
a header line not terminated by `\n`; any unit line containing characters
outside `[A-Za-z0-9+/]`, containing `=` padding, or decoding to fewer
than 40 bytes; AEAD authentication failure; nonce conformance failure
(see [crypto.md](crypto.md)).

The AAD for every unit is the static string `simple-encrypt/v1/text`.

## Binary ciphertext format

```
offset  size  field
0       8     BIN_MAGIC = 89 53 45 4E 43 0D 0A 1A   ("\x89SENC\r\n\x1a")
8       1     version = 0x01
9       1     flags   = 0x00   (reserved; must be zero)
10      6     reserved (must be all zero)
16      …     chunks
```

`BIN_MAGIC` follows the PNG convention: a high bit set in the first byte,
`\r\n` to catch newline translation, `\x1a` to stop accidental `type`-style
display.

Chunks are stored consecutively, each as:

```
nonce (24) || ciphertext (= plaintext chunk length) || tag (16)
```

- The plaintext is split into `ceil(len / 65536)` chunks (minimum one):
  every chunk except the final one is exactly 65536 bytes, and the final
  chunk holds the remainder — between 1 and 65536 bytes for a non-empty
  plaintext (exactly 65536 when the length is a positive multiple of the
  chunk size). An empty plaintext is exactly one zero-length chunk. A
  zero-length chunk at any index other than 0 is invalid: encryption never
  produces one and decryption rejects it, so every plaintext has exactly
  one valid ciphertext.
- On-disk chunk size is therefore `plaintext_chunk_len + 40`; a full chunk
  is 65576 bytes. The minimum valid binary ciphertext is 56 bytes
  (16-byte header + one empty chunk).
- Chunk AAD binds the index and the last flag:
  `simple-encrypt/v1/bin || le64(index) || last_byte` (see
  [crypto.md](crypto.md)).

Parsing (hard errors on any violation):

```
remaining = file_len - 16            # must be ≥ 40
index = 0
while remaining > 65576:
    read chunk of 65576 bytes, decrypt with aad_bin(index, last = false)
    remaining -= 65576; index += 1
read final chunk of `remaining` bytes (40 ≤ remaining ≤ 65576),
error if remaining == 40 and index > 0    # zero-length chunk only at 0
decrypt with aad_bin(index, last = true)
```

This parse is unambiguous: every non-final chunk is exactly full, so the
final chunk is whatever remains. Truncating the file at a chunk boundary
turns a non-last chunk into the final one and fails authentication (its AAD
was created with `last = false`); truncating mid-chunk fails the length
check; reordering fails the index binding; appending data fails both.

## Constants

| Name | Value |
|---|---|
| `SALT_LEN` | 16 bytes (32 hex chars in config) |
| `KEY_LEN` | 32 bytes |
| `NONCE_LEN` | 24 bytes |
| `TAG_LEN` | 16 bytes |
| `CHUNK_SIZE` | 65536 bytes |
| `TEXT_MAGIC_PREFIX` | `#simple-encrypt` |
| `TEXT_HEADER_V1` | `#simple-encrypt v1 text` |
| `BIN_MAGIC` | `89 53 45 4E 43 0D 0A 1A` |
| `BIN_HEADER_LEN` | 16 bytes |
| Base64 | standard alphabet, no padding |
| Hex | lowercase |

## Versioning

Format version 1 covers the config schema, both ciphertext layouts, and all
derivation/AAD context strings (which embed `/v1/`). Any incompatible change
bumps the version everywhere at once; the tool refuses newer versions with a
clear "upgrade simple-encrypt" error and refuses unknown/legacy layouts
outright.
