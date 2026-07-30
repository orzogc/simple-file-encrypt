# simple-encrypt — Cryptographic Design

This document specifies every cryptographic operation. Byte-level file
layouts are in [format.md](format.md); the security rationale and accepted
leakage are summarized here and treated fully in
[threat-model.md](threat-model.md).

## Primitives

| Role | Primitive | Notes |
|---|---|---|
| Password KDF | Argon2id v1.3 | parameters stored in the domain config |
| AEAD | XChaCha20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag |
| PRF / KDF | BLAKE3 (`keyed_hash`, `derive_key`) | 32-byte outputs |
| Randomness | OS CSPRNG | only used by `init` and `passwd` (salt) and for temp file names |

Constants:

```
KEY_LEN   = 32
SALT_LEN  = 16
NONCE_LEN = 24
TAG_LEN   = 16
CHUNK_SIZE = 65536 (64 KiB, binary mode)
```

## Key hierarchy

All derivations are deterministic. There is no per-file or per-operation
randomness after `init`.

```
password  (UTF-8 bytes, non-empty, no normalization)
salt      (16 random bytes, hex in config)
kdf       (argon2id parameters from config)
                    |
                    v
master_key = Argon2id(password, salt, m = memory_kib, t = iterations,
                      p = parallelism, out = 32)
                    |
        +-----------+---------------------------+
        v                                       v
verifier = blake3::derive_key(          file_km = blake3::keyed_hash(
    "simple-encrypt/v1/verifier",           key   = master_key,
    master_key)                             input = canonical_relative_path)
                                            |
                            +---------------+----------------+
                            v                                v
              enc_key = blake3::derive_key(    nonce_key = blake3::derive_key(
                  "simple-encrypt/v1/enc",         "simple-encrypt/v1/nonce",
                  file_km)                         file_km)
```

Notes on construction:

- `blake3::derive_key(context, key_material)` is used only with the static
  context strings above, per BLAKE3's usage guidance. The dynamic input (the
  file path) enters through `keyed_hash`, whose input may be arbitrary bytes.
- `canonical_relative_path` is the exact UTF-8 byte sequence defined in
  [format.md](format.md) (relative to the domain root, `/` separators, no
  Unicode normalization). Two files with different canonical paths have
  independent keys, which removes cross-file ciphertext equality.
- `enc_key` and `nonce_key` are independent; a nonce (a truncated PRF output
  under `nonce_key`) reveals nothing about the AEAD keystream.
- The version string embedded in every context (`/v1/`) ties all derived
  material to format version 1.

## Password verifier

The domain config stores `verifier = hex(derive_key("simple-encrypt/v1/verifier",
master_key))`. Every password-requiring command derives the master key and
compares (constant-time) against the stored value before touching any file.

The verifier is a one-way PRF output: it cannot be inverted to the master
key, and it enables offline password guessing no better than any ciphertext
line already does (an attacker with the repository always has AEAD tags to
test guesses against). Password strength and the Argon2id parameters are the
sole defense against offline guessing, with or without the verifier.

## Deterministic nonce derivation (SIV style)

For every encrypted unit (a text line or a binary chunk):

```
nonce = blake3::keyed_hash(nonce_key, aad || plaintext)[0 .. 24]
ct_and_tag = XChaCha20-Poly1305::encrypt(enc_key, nonce, plaintext, aad)
stored_unit = nonce || ct_and_tag
```

Decryption recomputes nothing in advance: it reads the stored nonce, runs
AEAD decryption (which authenticates `aad` and the ciphertext), and then —
as a conformance check — recomputes the nonce from the authenticated
plaintext and errors if it does not match the stored one. This detects
implementation drift and rules out ciphertexts produced with foreign nonces.

Properties:

- **Determinism**: equal `(nonce_key, aad, plaintext)` produces equal output
  bytes. This is the property that makes re-encryption stable for git.
- **Nonce reuse is harmless by construction**: under one key, the same nonce
  recurs only for identical `(aad, plaintext)`, i.e. a byte-identical unit.
  Distinct units collide on a 192-bit truncated PRF output only with
  negligible probability (birthday bound ≈ 2^-96 even after 2^48 units).
- **DAE security**: the scheme is deterministic authenticated encryption.
  It leaks exactly unit equality (under the same key and AAD) and nothing
  else about the plaintext. At line granularity that leak is significant and
  is the documented trade-off of this tool.

## Text mode (per line)

- The plaintext is split into lines at `\n` (0x0A). Line content is raw
  bytes: a `\r` before the `\n` stays in the line (CRLF round-trips), empty
  lines are ordinary zero-length lines and are encrypted like any other line.
- Every line is an independent unit with a static AAD:

  ```
  aad_text = "simple-encrypt/v1/text"
  ```

  The AAD deliberately excludes the line number and any neighbor state:
  a line's ciphertext depends only on the file's keys and the line's bytes,
  so inserting, deleting, or reordering surrounding lines does not change it.
- Consequences, accepted by design: within one file, equal lines have equal
  ciphertext; whole-line reordering, deletion, duplication, truncation, and
  splicing lines from an older version of the same file are not detected.
  No unit can be *forged* without the key: an attacker cannot inject content
  that was never legitimately encrypted for that exact file path.
- The header line and the trailing-newline mirroring rule are specified in
  [format.md](format.md).

## Binary mode (whole file, chunked)

- The plaintext is split into consecutive `CHUNK_SIZE` chunks; for a
  non-empty file the final chunk holds the remainder (1 to 65536 bytes).
  An empty file is one zero-length chunk — the only position where a
  zero-length chunk is valid — so even an empty file has an
  authentication tag. See [format.md](format.md) for the exact rules.
- Chunk AAD:

  ```
  aad_bin(i, last) = "simple-encrypt/v1/bin" || le64(i) || (last ? 0x01 : 0x00)
  ```

  Binding the index rejects chunk reordering; binding the last flag rejects
  truncation at a chunk boundary and extension. There is deliberately no
  chain (no previous-tag feedback): a chunk from an older version of the same
  file can be substituted at the same index undetected, and in exchange a
  local edit that does not shift data changes only the affected chunks'
  ciphertext.

## KDF parameters

- Defaults written by `init`: `memory_kib = 19456`, `iterations = 2`,
  `parallelism = 1` (Argon2id, 32-byte output) — the `argon2` crate
  defaults, matching OWASP guidance.
- Parameters are read from the config on every run, so domains can choose
  their own strength. Changing parameters for an existing domain goes
  through `passwd` (see [cli.md](cli.md)), which rewrites salt, verifier,
  and parameters together.
- Because the config can come from a hostile repository, parameters are
  validated before running Argon2: `8 * parallelism ≤ memory_kib ≤ 4194304`
  (4 GiB), `1 ≤ iterations ≤ 1000`, `1 ≤ parallelism ≤ 64`. Out-of-range
  values are a hard error, preventing a malicious config from turning a
  password prompt into a memory/CPU bomb.

## Hygiene

- The password, the master key, and all derived keys are held in `Zeroizing`
  buffers and wiped on drop. This is best-effort: the OS and allocator may
  still copy memory (see [threat-model.md](threat-model.md)).
- Verifier comparison is constant-time.
- Empty passwords are rejected at every input path.
- Salt generation uses the OS CSPRNG; encryption itself never needs
  randomness, so a broken RNG cannot compromise ciphertext after `init`.
