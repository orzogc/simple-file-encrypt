# Committed fuzz seeds

Minimal format-boundary seeds, passed to every CI fuzz run as a
read-only secondary corpus (`cargo fuzz run <target> fuzz/corpus/<target>
fuzz/seeds/<target>`). The cached corpus in `fuzz/corpus/` accumulates
explored coverage between runs but can be evicted; these seeds guarantee
that the deep (fully authenticated) parse paths are reachable even on a
cold cache.

Each seed is a *harness input*, not a raw ciphertext: the fuzz targets
in `fuzz_targets/` transform their input (prepending magic/headers,
mapping bytes into the base64 alphabet) before calling the library, and
the seeds are encoded to survive that transform. All cryptographic
seeds use the harness's fixed key (`[0x42; 32]`) and path (`"fuzz"`).

| Seed | Reaches |
|---|---|
| `config_parse/valid-config.toml` | full config validation of a well-formed config (with `excludes`) |
| `config_parse/excludes-shadow.toml` | the exclude-shadows-managed-entry contradiction rejection |
| `config_parse/excludes-overlap.toml` | overlapping/duplicate exclusions and a shadowed `force_binary` mark |
| `text_decrypt/valid-units` | header + two authentic unit lines, decrypts cleanly |
| `text_decrypt/valid-empty-marker` | the authenticated empty-file marker path |
| `bin_decrypt/valid-small` | one-chunk binary ciphertext incl. file tag |
| `bin_decrypt/valid-empty` | the empty-plaintext (zero-length chunk) path |

Regenerate after a format change by encrypting with the harness key and
path, then inverting the harness transform — e.g. for `bin_decrypt`,
`binmode::encrypt(&FileKeys::derive(&key, "fuzz"), "fuzz", content)`
with the 8 magic bytes stripped; for `text_decrypt`, a `0x00` selector
byte followed by the unit lines (header stripped), or a `0x01` selector
followed by the 22 marker characters mapped to their base64-alphabet
indices (final character: its index in `AQgw`). Verify a regenerated
seed by replaying the harness transform and asserting the library
decrypts it.
