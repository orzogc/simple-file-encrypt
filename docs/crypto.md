# simple-encrypt — Cryptographic Design

This document specifies every cryptographic operation. Byte-level file
layouts are in [format.md](format.md); accepted leakage is treated fully in
[threat-model.md](threat-model.md).

Honesty note: this design composes standardized and well-analyzed pieces
(AES-CMAC-SIV per RFC 5297, BLAKE3, Argon2id) in a straightforward way,
but the composition as a whole has not received independent cryptographic
review.

## Primitives

| Role | Primitive | Notes |
|---|---|---|
| Password KDF | Argon2id v1.3 | 64-byte output (the wrap key); parameters in the config |
| Deterministic AEAD | AES-CMAC-SIV with AES-256 (RFC 5297 §4, deterministic / nonce-free interface) | 64-byte key (the `AEAD_AES_SIV_CMAC_512` key size), 16-byte SIV |
| PRF / KDF | BLAKE3 (`keyed_hash`, `derive_key`, XOF output where 64 bytes are needed) | |
| Randomness | OS CSPRNG | only `init`/`passwd`/`rekey` (salts, domain keys) and temp-file names |

Constants:

```
SALT_LEN       = 16      DOMAIN_KEY_LEN = 32
KEK_LEN        = 64      UNIT_KEY_LEN   = 64
SIV_LEN        = 16      (per-unit overhead)
FILE_TAG_LEN   = 32      (binary mode trailer)
CHUNK_SIZE     = 65536   (binary mode)
```

### Implementation note (Rust)

Implementations must use the **raw SIV interface** — in Rust,
`aes_siv::siv::Aes256Siv`:

```rust
let mut siv = Aes256Siv::new(unit_key.into());          // 64-byte key
let out = siv.encrypt([aad], plaintext)?;               // SIV(16) || CT
let pt  = siv.decrypt([aad], ciphertext_with_siv)?;
```

exactly one header component, no nonce anywhere. The `Aes256SivAead`
wrapper must **not** be used: it appends its nonce as a second S2V
component and produces incompatible ciphertext. The 64-byte key's halves
are consumed by the library per RFC 5297 (left half = S2V/CMAC key K1,
right half = AES-CTR key K2). Zero-length plaintexts are valid inputs.

Where 64 derived bytes are needed, the BLAKE3 XOF is used explicitly:

```rust
let mut hasher = blake3::Hasher::new_derive_key(CTX_UNIT);
hasher.update(&file_km);
hasher.finalize_xof().fill(&mut unit_key);              // 64 bytes
```

(`blake3::derive_key` itself returns exactly 32 bytes and is used where
32 suffice.)

## Key hierarchy (envelope encryption with a key ring)

File keys descend from a random **domain key**, not from the password.
The password only wraps domain keys in the config, so `passwd` rewrites
one config field and no ciphertext. The config holds an ordered ring
`wrapped_keys`; entry 0 is the **current** domain key, later entries are
older keys retained by `rekey` so pre-rotation ciphertext (other
branches, stashes, missed files) stays decryptable until explicitly
pruned.

```
password  (UTF-8, non-empty)          domain_key_i  (32 random bytes each;
salt      (16 random bytes, config)                  index 0 = current,
kdf       (argon2id params, config)                  older kept by rekey)
        |                                   |
        v                                   |
kek = Argon2id(password, salt,              |
              m, t, p, out = 64)            |
        |                                   |
        +-----------> wrapped_keys[i] = AES-SIV(kek).encrypt(
                          ad = AD_WRAP, plaintext = domain_key_i)
                      (48 bytes each = SIV(16) || CT(32), hex in config;
                       all entries wrapped under the same current KEK)

domain_key (encryption always uses entry 0; decryption tries the ring
            in order)
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
- Unwrapping `wrapped_keys[0]` doubles as the password check: a wrong
  password fails the SIV authentication. There is no separate verifier.
  A config whose ring entries do not all unwrap under the same KEK is
  corrupt (hard error).
- Ciphertext is a pure function of `(domain_key, canonical path,
  content)`. The password, salt, and KDF parameters only gate access to
  the domain keys, which is why `passwd` and KDF upgrades never churn
  ciphertext — and why `rekey`, which replaces the domain key, rewrites
  every ciphertext by design.

## Unit encryption with AES-SIV

Every unit (a text line, the empty-file marker, or a binary chunk) is
encrypted with AES-SIV under the file's `unit_key`, with exactly one
associated-data component:

```
output = SIV(16 bytes) || ciphertext(len(plaintext))
```

Decryption recomputes S2V over the associated data and the decrypted
plaintext and compares it to the stored SIV in constant time — that
comparison *is* the authentication; there is no separate tag and no
nonce anywhere in the scheme.

Associated data per unit:

```
text line          : AD_TEXT
empty-file marker  : AD_TEXT_EMPTY
binary chunk       : AD_BIN_PREFIX || le64(chunk_index) || (last ? 0x01 : 0x00)
```

Text-line AD deliberately excludes the line number and any neighbor
state: a line's ciphertext depends only on the file's keys and the
line's bytes, so editing surrounding lines does not change it. Binary
chunks bind their index (rejects reordering) and a last-chunk flag
(rejects truncation at a chunk boundary and extension).

### Security properties

- **DAE security**: AES-SIV is a standardized deterministic
  authenticated encryption scheme with a formal security treatment
  (RFC 5297, building on Rogaway–Shrimpton SIV). Under one key it
  reveals equality of `(associated data, plaintext)` pairs — plus
  length — and nothing else about the plaintext.
- **The determinism caveat applies in full** (RFC 5297 makes it
  explicitly): deterministic encryption protects content only to the
  extent the plaintext is unpredictable given everything the ciphertext
  legitimately leaks. Low-entropy units can be identified or confirmed
  without any key. See [threat-model.md](threat-model.md).
- **Masked CTR-IV collisions**: before generating the keystream, SIV
  clears one bit in each of the last two 32-bit words of the IV
  (RFC 5297), so keystream reuse requires only a collision on the
  remaining 126 bits. For q units under one key the probability is
  ≈ q²/2^127, where q counts every unit ever encrypted for that path
  across all its versions (q = 2^20 → ≈ 2^-87). Such a collision
  between distinct units would leak their XOR — a negligible
  probability, not an impossibility.
- **Unit authenticity only**: an attacker without the key cannot create
  any unit ciphertext that was never legitimately produced for that
  exact file path, but recombining *authentic* units is not prevented
  at the unit level. Text-mode file integrity is deliberately absent
  (merge support); binary mode adds a whole-file tag (below).

## Binary whole-file tag

Binary ciphertext ends with a 32-byte trailer:

```
file_tag = blake3::keyed_hash(
    file_tag_key,
    header(16) || le64(plaintext_len) || le64(chunk_count)
               || SIV_0 || SIV_1 || … || SIV_{n-1})
```

The tag is deterministic (inputs are), covers the header bytes, and
binds the exact multiset *and order* of chunks. It preserves locality —
editing one chunk changes that chunk and the trailer only — while
rejecting substitution of same-index chunks from older versions, which
per-chunk AD alone cannot detect. Whole-file rollback to a complete
older ciphertext remains possible (no external state); binary files do
not merge in git, so the trailer costs nothing in workflow terms.
Verified in constant time.

Text mode has no file-level tag: any such tag would conflict on every
merge and defeat the per-line design. The resulting file-level integrity
gap is documented, not hidden.

## Empty-file marker (text mode)

The valid ciphertext of an empty text file is a single header line
carrying an authenticated marker: base64 of
`AES-SIV(unit_key, AD_TEXT_EMPTY, "")` (16 bytes → 22 characters;
layout in [format.md](format.md)). A bare header with no units is
malformed. The marker gives emptiness the same authenticity as any
other unit: it cannot be created from nothing without the key —
though, like any unit, a marker that legitimately existed in an older
version of the path can be replayed (a whole-file rollback, see
[threat-model.md](threat-model.md)).

## KDF parameters

- Defaults written by `init`: `memory_kib = 65536` (64 MiB) and
  `iterations = 3` per RFC 9106's memory-constrained recommendation,
  with `parallelism = 1` (the RFC suggests 4 lanes; one lane is this
  tool's choice for single-threaded simplicity). Affordable for a CLI
  that runs Argon2 once per command.
- Parameters live in the config and are validated in tiers before
  Argon2 runs (the config may come from a hostile repository):

  | Tier | Rule | On violation |
  |---|---|---|
  | Validity | `parallelism ≥ 1`, `memory_kib ≥ 8 × parallelism`, `iterations ≥ 1` | hard error |
  | Security floor | `memory_kib ≥ 19456` and `iterations ≥ 2` | error unless `--allow-weak-kdf` |
  | Resource ceiling | `memory_kib ≤ 262144` (256 MiB), `memory_kib × iterations ≤ 2097152` (2 GiB·passes), `parallelism ≤ 4` | error unless `--allow-expensive-kdf` |
  | Absolute caps | `memory_kib ≤ 4194304` (4 GiB), `memory_kib × iterations ≤ 67108864` (64 GiB·passes), `parallelism ≤ 64` | hard error even with flags |

  The product is computed with checked arithmetic, and every TOML
  integer is bounds-checked before conversion to the Argon2 parameter
  types. Whenever the configured cost exceeds the defaults, the tool
  prints the memory and pass count it is about to spend before running
  Argon2. A hostile or mistyped config therefore cannot push resource
  use beyond these envelopes without an explicit flag — though costs
  inside the no-flag ceiling can still be slow on very small machines.

## Hygiene

- The password, `kek`, all domain keys, and all derived keys live in
  `Zeroizing` buffers and are wiped on drop. Best-effort only: the OS,
  allocator, and swap may still copy memory
  (see [threat-model.md](threat-model.md)).
- All authentication comparisons (SIV verification, file tag) are
  constant-time.
- Passwords must be valid UTF-8 and non-empty. The Argon2 input is the
  **exact UTF-8 byte sequence supplied by the user** — no NFC/NFD/NFKC
  normalization, no trimming beyond stripping the trailing newline of
  non-TTY input. Different byte sequences that render identically are
  different passwords.
- Ordinary encryption and decryption need no randomness at all. `init`,
  `passwd`, and `rekey` depend on the OS CSPRNG for salts and domain
  keys — a weak RNG at those moments compromises the domain. Temp-file
  names also use it, harmlessly.
