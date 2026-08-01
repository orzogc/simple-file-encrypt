# Security Policy

## Supported Versions

simple-file-encrypt is pre-1.0 and under active development. Only the
latest release and the tip of `main` receive security fixes; there are
no backports yet.

## Reporting a Vulnerability

Please report vulnerabilities **privately** through GitHub's "Report a
vulnerability" feature (Security → Advisories) on this repository. Do
not open a public issue for an unpatched vulnerability. Reports are
acknowledged as soon as possible; expect an initial assessment within a
few days.

## Scope

The normative statement of what is and is not protected is
[docs/threat-model.md](docs/threat-model.md). Anything that contradicts
a guarantee documented there or in the other `docs/` pages is in scope
and treated as a security bug — for example:

- ciphertext recoverable without the password beyond the documented
  leakage (structure, lengths, line equality within an epoch);
- a hostile repository or config escaping the domain boundary, or
  exhausting memory/CPU past the documented budgets;
- ciphertext tampering that decrypts without an authentication error.

Issues explicitly listed as out of scope in the threat model (a
compromised machine, secure deletion of plaintext that once existed,
local TOCTOU races, availability attacks by someone who can already
write the repository) are design trade-offs, not vulnerabilities —
but reports that help narrow them are still welcome.
