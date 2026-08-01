//! Read-only scans: `status` (report), `check` (keyless CI gate), and
//! `verify` (authenticated check). These examine everything and report
//! all findings instead of stopping at the first error
//! (see `docs/cli.md`).

use std::path::PathBuf;

use crate::crypto::KdfGate;
use crate::error::{Error, Result};
use crate::probe::{Probe, probe};
use crate::select::{self, Origin};
use crate::{binmode, fsops, report, textmode};

/// Aggregate outcome of `check` / `verify`, mapped to exit codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanOutcome {
    /// Everything checked out: exit 0.
    Clean,
    /// Violations / failures found: exit 1.
    Violations,
    /// Operational errors while checking: exit 2.
    Operational,
}

impl ScanOutcome {
    /// The process exit code for this outcome.
    pub fn exit_code(self) -> u8 {
        match self {
            ScanOutcome::Clean => 0,
            ScanOutcome::Violations => 1,
            ScanOutcome::Operational => 2,
        }
    }
}

/// Builds the entry list for a scan: managed entries without arguments,
/// explicit entries otherwise.
fn scan_entries(managed: &[String], rels: Vec<String>) -> Vec<(String, Origin)> {
    if rels.is_empty() {
        managed
            .iter()
            .map(|p| (p.clone(), Origin::Managed))
            .collect()
    } else {
        rels.into_iter()
            .map(|r| (r, Origin::Explicit { named: true }))
            .collect()
    }
}

/// Runs the `status` command: prints one state line per managed file.
/// Needs no password; exit 0 regardless of states.
pub fn status() -> Result<()> {
    let (domain, _) = super::open_domain(&[], false)?;
    let entries = scan_entries(&domain.loaded.config.paths, Vec::new());
    let expanded = select::expand(domain.root(), &entries)?;

    let mut lines: Vec<(String, String)> = Vec::new();
    for missing in &expanded.missing_managed {
        let marker = domain.loaded.config.is_force_binary(missing);
        lines.push((
            missing.clone(),
            format!(
                "missing     {missing}{}",
                if marker { " [binary]" } else { "" }
            ),
        ));
    }
    for skipped in &expanded.skipped_special {
        let state = if skipped.symlink {
            "symlink    "
        } else {
            "special    "
        };
        let marker = domain.loaded.config.is_force_binary(&skipped.rel);
        lines.push((
            skipped.rel.clone(),
            format!(
                "{state} {}{}",
                skipped.rel,
                if marker { " [binary]" } else { "" }
            ),
        ));
    }
    for file in &expanded.files {
        let prefix = fsops::read_prefix(&file.abs, 64)?;
        let p = probe(&prefix);
        let state = match p {
            Probe::Binary | Probe::TextV1 => "encrypted   ",
            Probe::TextUnrecognized => "unrecognized",
            Probe::Plain => "plaintext   ",
        };
        let marker = p == Probe::Binary || domain.loaded.config.is_force_binary(&file.rel);
        lines.push((
            file.rel.clone(),
            format!(
                "{state} {}{}",
                file.rel,
                if marker { " [binary]" } else { "" }
            ),
        ));
    }
    lines.sort();
    for (_, line) in lines {
        report::out(line);
    }
    Ok(())
}

/// Runs the `check` command: exit 0 when every existing target is
/// encrypted (probe only), 1 with offenders listed, 2 on operational
/// errors. Missing files are ignored.
pub fn check(arg_paths: &[PathBuf]) -> Result<ScanOutcome> {
    let (domain, rels) = super::open_domain(arg_paths, false)?;
    let entries = scan_entries(&domain.loaded.config.paths, rels);
    let expanded = select::expand(domain.root(), &entries)?;

    let mut violations = 0usize;
    let mut operational = 0usize;
    for file in &expanded.files {
        match fsops::read_prefix(&file.abs, 64) {
            Err(e) => {
                operational += 1;
                report::errline(format!("error probing `{}`: {e}", file.rel));
            }
            Ok(prefix) => match probe(&prefix) {
                Probe::Binary | Probe::TextV1 => {}
                Probe::TextUnrecognized => {
                    violations += 1;
                    report::out(format!("unrecognized {}", file.rel));
                }
                Probe::Plain => {
                    violations += 1;
                    report::out(format!("plaintext    {}", file.rel));
                }
            },
        }
    }
    // A managed path that exists only as a symlink or special file was
    // never probed: it cannot count as encrypted for the gate.
    for skipped in &expanded.skipped_special {
        violations += 1;
        let state = if skipped.symlink {
            "symlink    "
        } else {
            "special    "
        };
        report::out(format!("{state} {}", skipped.rel));
    }
    Ok(if operational > 0 {
        ScanOutcome::Operational
    } else if violations > 0 {
        ScanOutcome::Violations
    } else {
        ScanOutcome::Clean
    })
}

/// Runs the `verify` command: fully authenticates every encrypted
/// target in memory. Plaintext and missing files are reported but do
/// not affect the exit code; unrecognized headers and authentication
/// failures do.
pub fn verify(arg_paths: &[PathBuf], gate: &KdfGate) -> Result<ScanOutcome> {
    let (domain, rels) = super::open_domain(arg_paths, false)?;
    let entries = scan_entries(&domain.loaded.config.paths, rels);
    let expanded = select::expand(domain.root(), &entries)?;
    let keys = super::read_password_and_unlock(&domain.loaded, gate)?;

    for missing in expanded
        .missing_managed
        .iter()
        .chain(&expanded.missing_explicit)
    {
        report::out(format!("missing {missing}"));
    }
    let mut failures = 0usize;
    let mut operational = 0usize;
    // A managed path that exists only as a symlink or special file has
    // no authenticatable content: it is a failure, not a skip.
    for skipped in &expanded.skipped_special {
        failures += 1;
        report::out(format!(
            "FAILED {}: managed path is {} and cannot be authenticated",
            skipped.rel,
            if skipped.symlink {
                "a symlink"
            } else {
                "not a regular file"
            }
        ));
    }
    for file in &expanded.files {
        // Probe from a short prefix first: plaintext is reported from
        // the prefix alone, so a large (or over-cap) plaintext file is
        // never pulled into memory and stays "plaintext" per the CLI
        // contract; only probe hits are read whole for authentication.
        let result = fsops::read_prefix(&file.abs, 64).and_then(|prefix| match probe(&prefix) {
            Probe::Plain => Ok(None),
            Probe::TextUnrecognized => Err(Error::format(
                file.rel.clone(),
                "the first line starts with `#simple-encrypt` but is no exact v1 header",
            )),
            Probe::TextV1 => {
                let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
                textmode::decrypt(&keys, &file.rel, &data.content).map(|(_, idx)| Some(idx))
            }
            Probe::Binary => {
                let data = fsops::read_capped(&file.abs, crate::consts::MAX_FILE_SIZE, "file")?;
                binmode::decrypt(&keys, &file.rel, &data.content).map(|(_, idx)| Some(idx))
            }
        });
        match result {
            Ok(None) => report::out(format!("plaintext {}", file.rel)),
            Ok(Some(0)) => report::out(format!("verified {}", file.rel)),
            Ok(Some(idx)) => {
                report::out(format!(
                    "pending migration {} (authenticates under ring entry {idx})",
                    file.rel
                ));
            }
            Err(e @ Error::Io { .. }) => {
                operational += 1;
                report::errline(format!("error verifying `{}`: {e}", file.rel));
            }
            Err(e) => {
                failures += 1;
                report::out(format!("FAILED {}: {e}", file.rel));
            }
        }
    }
    Ok(if operational > 0 {
        ScanOutcome::Operational
    } else if failures > 0 {
        ScanOutcome::Violations
    } else {
        ScanOutcome::Clean
    })
}
