# simple-encrypt — Cryptographic Design

This document specifies every cryptographic operation. Byte-level file
layouts are in [format.md](format.md); accepted leakage is treated fully in
[threat-model.md](threat-model.md).

Honesty note: this design composes standardized and well-analyzed pieces
(AES-SIV per RFC 5297, BLAKE3, Argon2id) in a straightforward way, but the
composition as a whole has not received independent cryptographic review.

## Primitives

| Role | Primitive | Notes |
|---|---|---|
| Password KDF | Argon2id v1.3 | 64-byte output (the wrap key); parameters in the config |
| Deterministic AEAD | AES-SIV, `AEAD_AES_SIV_CMAC_512` (RFC 5297, AES-256) | 64-byte key, 16-byte SIV; no nonce |
| PRF / KDF | BLAKE3 (`keyed_hash`, `derive_key`, XOF output where 64 bytes are needed) | |
| Randomness | OS CSPRNG | only `init`/`passwd`/`rekey` (salt, domain key) and temp-file names |

Constants:

```
SALT_LEN       = 16      DOMAIN_KEY_LEN = 32
KEK_LEN        = 64      UNIT_KEY_LEN   = 64
SIV_LEN        = 16      (per-unit overhead)
FILE_TAG_LEN   = 32      (binary mode trailer)
CHUNK_SIZE     = 65536   (binary mode)
```

## Key hierarchy (envelope encryption)

File keys descend from a random **domain key**, not from the password. The
password only wraps the domain key, so changing the password (`passwd`)
rewrites one config field and no ciphertext.

```
password  (UTF-8, non-empty)          domain_key  (32 random bytes,
salt      (16 random bytes, config)                created by init,
kdf       (argon2id params, config)                rotated only by rekey)
        |                                   |
        v                                   |
kek = Argon2id(password, salt,              |
              m, t, p, out = 64)            |
        |                                   |
        +-----------> wrapped_key = AES-SIV(kek).encrypt(
                          ad = AD_WRAP, plaintext = domain_key)
                      (48 bytes = SIV(16) || CT(32), hex in config)

domain_key
    |
    v
file_km      = blake3::keyed_hash(domain_key, canonical_relative_path)
unit_key     = blake3::derive_key_xof(CTX_UNIT, file_km, 64 bytes)
file_tag_key = blake3::derive_key(CTX_FILE_TAG, file_km)      # binary only
```

Context and associated-data strings (globally unique, frozen for v1):

```
AD_WRAP      = "github.com/orzogc/simple-encrypt v1 domain key wrap"
CTX_UNIT     = "github.com/orzogc/simple-encrypt v1 unit key"
CTX_FILE_TAG = "github.com/orzogc/simple-encrypt v1 binary file tag key"
AD_TEXT      = "github.com/orzogc/simple-encrypt v1 text unit"
AD_TEXT_EMPTY= "github.com/orzogc/simple-encrypt v1 text empty file"
AD_BIN_PREFIX= "github.com/orzogc/simple-encrypt v1 binary chunk"
```

Notes:

- `derive_key` is used only with the static context strings above, per
  BLAKE3 guidance; the dynamic input (the path) enters through
  `keyed_hash`. Per-path keys remove cross-file ciphertext equality.
- Unwrapping `wrapped_key` doubles as the password check: a wrong password
  fails the SIV authentication. There is no separate verifier.
- Ciphertext is a pure function of `(domain_key, canonical path, content)`.
  The password, salt, and KDF parameters only gate access to `domain_key`,
  which is why `passwd` and KDF upgrades never churn ciphertext.

## Unit encryption with AES-SIV

Every unit (a text line, the empty-file marker, or a binary chunk) is
encrypted with AES-SIV under the file's `unit_key`, with exactly one
associated-data component:

```
output = SIV(16 bytes) || ciphertext(len(plaintext))
```

AES-SIV is run in its deterministic mode (RFC 5297 §4: no nonce at all;
`AEAD_AES_SIV_CMAC_512` here names the key size — 64 bytes, AES-256 —
not the nonce-based RFC 5116 interface of the same name).
Decryption recomputes S2V over the associated data and the decrypted
plaintext and compares it to the stored SIV in constant time — that
comparison *is* the authentication; there is no separate tag and no
nonce-conformance step.

Associated data per unit:

```
text line          : AD_TEXT
empty-file marker  : AD_TEXT_EMPTY
binary chunk       : AD_BIN_PREFIX || le64(chunk_index) || (last ? 0x01 : 0x00)
```

Text-line AD deliberately excludes the line number and any neighbor state:
a line's ciphertext depends only on the file's keys and the line's bytes,
so editing surrounding lines does not change it. Binary chunks bind their
index (rejects reordering) and a last-chunk flag (rejects truncation at a
chunk boundary and extension).

### Security properties

- **DAE security**: AES-SIV is a standardized deterministic authenticated
  encryption scheme with a formal security treatment (RFC 5297, building
  on Rogaway–Shrimpton SIV). Under one key it reveals equality of
  `(associated data, plaintext)` pairs — plus length — and nothing else
  about the plaintext.
- **The determinism caveat applies in full** (RFC 5297 makes it
  explicitly): deterministic encryption protects content only to the
  extent the plaintext is unpredictable given everything the ciphertext
  legitimately leaks. Low-entropy units can be identified or confirmed
  without any key. See [threat-model.md](threat-model.md).
- **SIV collisions**: two *distinct* units colliding on the 128-bit SIV
  under one key would reuse the CTR keystream and leak their XOR. The
  probability is ≈ q²/2^129 for q units under one key; keys are per
  path, so q counts every unit ever encrypted for that path across all
  its versions (q = 2^20 → ≈ 2^-89).
  This is a negligible-probability failure, not an impossible one.
- **Unit authenticity only**: an attacker without the key cannot create
  any unit ciphertext that was never legitimately produced for that exact
  file path, but recombining *authentic* units is not prevented at the
  unit level. Text-mode file integrity is deliberately absent (merge
  support); binary mode adds a whole-file tag (below).

## Binary whole-file tag

Binary ciphertext ends with a 32-byte trailer:

```
file_tag = blake3::keyed_hash(
    file_tag_key,
    header(16) || le64(plaintext_len) || le64(chunk_count)
               || SIV_0 || SIV_1 || … || SIV_{n-1})
```

The tag is deterministic (inputs are), covers the header bytes, and binds
the exact multiset *and order* of chunks. It preserves locality — editing
one chunk changes that chunk and the trailer only — while rejecting
substitution of same-index chunks from older versions, which per-chunk AD
alone cannot detect. Whole-file rollback to a complete older ciphertext
remains possible (no external state); binary files do not merge in git, so
the trailer costs nothing in workflow terms. Verified in constant time.

Text mode has no file-level tag: any such tag would conflict on every
merge and defeat the per-line design. The resulting file-level integrity
gap is documented, not hidden.

## Empty-file marker (text mode)

The valid ciphertext of an empty text file is a single header line
carrying an authenticated marker: base64 of
`AES-SIV(unit_key, AD_TEXT_EMPTY, "")` (16 bytes → 22 characters; layout
in [format.md](format.md)). A bare header with no units is malformed.
Without this marker, anyone could truncate a text ciphertext to the bare
header and have it "decrypt" to an empty file with no key — the marker
makes emptiness as unforgeable as any other content.

## KDF parameters

- Defaults written by `init`: `memory_kib = 65536` (64 MiB) and
  `iterations = 3` per RFC 9106's memory-constrained recommendation,
  with `parallelism = 1` (the RFC suggests 4 lanes; one lane is this
  tool's choice for single-threaded simplicity). Affordable for a CLI
  that runs Argon2 once per command.
  With envelope encryption a later upgrade costs one `passwd`, so there is
  no reason to start low.
- Parameters live in the config and are validated in three tiers before
  Argon2 runs (the config may come from a hostile repository):

  | Tier | Rule | On violation |
  |---|---|---|
  | Validity | `parallelism ≥ 1`, `memory_kib ≥ 8 × parallelism`, `iterations ≥ 1` | hard error |
  | Security floor | `memory_kib ≥ 19456` and `iterations ≥ 2` | error unless `--allow-weak-kdf` |
  | Resource ceiling | `memory_kib ≤ 1048576` (1 GiB) and `memory_kib × iterations ≤ 8388608` and `parallelism ≤ 8` | error unless `--allow-expensive-kdf` |

- Whenever the configured cost exceeds the defaults, the tool prints the
  memory and pass count it is about to spend before running Argon2, so a
  hostile or mistyped config cannot silently stall or OOM the machine.

## Hygiene

- The password, `kek`, `domain_key`, and all derived keys live in
  `Zeroizing` buffers and are wiped on drop. Best-effort only: the OS,
  allocator, and swap may still copy memory
  (see [threat-model.md](threat-model.md)).
- All authentication comparisons (SIV verification, file tag) are
  constant-time.
- Empty passwords are rejected at every input path; passwords must be
  valid UTF-8.
- Encryption itself needs no randomness. The OS CSPRNG is used only for
  the salt and domain key (`init`, `passwd`, `rekey`) and temp-file names,
  so a weak RNG after `init` cannot compromise ciphertext.
