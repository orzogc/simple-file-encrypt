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
| `text_authenticate_any/found-surviving-unit` | an authentic unit behind an alien one: the `Found` verdict, unreachable by mutation alone |
| `text_authenticate_any/inconclusive-budget-cut` | a budget that dies between the alien and the authentic unit: `Found` vs `Inconclusive` divergence |
| `bin_authenticate_any/found-last-chunk` | a small single-chunk ciphertext: the length-only last-chunk path |
| `bin_authenticate_any/found-grid-slot` | a full single-chunk ciphertext: the grid-slot path |
| `bin_authenticate_any/found-damaged-header` | a flipped version byte over an intact chunk: the header-blind paths |
| `bin_authenticate_any/inconclusive-budget-cut` | a budget too small for one attempt: `Found` vs `Inconclusive` divergence |

Regenerate after a format change by encrypting with the harness key and
path, then inverting the harness transform — e.g. for `bin_decrypt`,
`binmode::encrypt(&FileKeys::derive(&key, "fuzz"), "fuzz", content)`
with the 8 magic bytes stripped; for `text_decrypt`, a `0x00` selector
byte followed by the unit lines (header stripped), or a `0x01` selector
followed by the 22 marker characters mapped to their base64-alphabet
indices (final character: its index in `AQgw`). Verify a regenerated
seed by replaying the harness transform and asserting the library
decrypts it.

The `*_authenticate_any` harnesses read their first **three** bytes as
a big-endian work budget (large enough to cover one full-chunk
attempt) and treat the rest as the body: unit lines after the
implicit v1 text header, or everything after the implicit 8 magic
bytes for binary. Their seeds are therefore `budget_be24 || body`,
with the body produced exactly like the `*_decrypt` seeds above;
verify one by replaying the transform and asserting the expected
`UnitScan` under both the seed's budget and an unlimited one.
