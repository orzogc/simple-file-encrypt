//! Centralized user-facing output.
//!
//! Progress goes to stdout, warnings and notes to stderr, per
//! `docs/cli.md`. All writes handle a vanished consumer explicitly: a
//! broken pipe exits with status 141 (128 + SIGPIPE) like a
//! SIGPIPE-killed Unix tool, so pipelines and CI gates see a failure —
//! never a silent success, never a panic.

use std::borrow::Cow;
use std::io::Write;
use std::path::Path;

/// Prints a progress line to stdout.
pub fn out(msg: impl AsRef<str>) {
    emit(&mut std::io::stdout().lock(), msg.as_ref());
}

/// Prints a warning line to stderr.
pub fn warn(msg: impl AsRef<str>) {
    emit(
        &mut std::io::stderr().lock(),
        &format!("warning: {}", msg.as_ref()),
    );
}

/// Prints a note line to stderr (informational, not a warning).
pub fn note(msg: impl AsRef<str>) {
    emit(
        &mut std::io::stderr().lock(),
        &format!("note: {}", msg.as_ref()),
    );
}

/// Prints a raw line to stderr (error reports, prompts context).
pub fn errline(msg: impl AsRef<str>) {
    emit(&mut std::io::stderr().lock(), msg.as_ref());
}

/// Writes one line, flushing so progress is timely and write errors
/// surface here rather than at exit.
fn emit(w: &mut impl Write, line: &str) {
    if let Err(e) = writeln!(w, "{line}").and_then(|()| w.flush())
        && e.kind() == std::io::ErrorKind::BrokenPipe
    {
        // The consumer went away. Exit 141 (128 + SIGPIPE), the status
        // a SIGPIPE-killed Unix tool would report: a gate like
        // `check | head` must fail, not pass silently. Dropped
        // destructors may leave a temp file behind; the next
        // exclusive-lock run sweeps it.
        std::process::exit(141);
    }
    // Other write errors (ENOSPC, EIO on the console) cannot be
    // reported anywhere; ignoring them beats panicking.
}

/// Escapes an untrusted string for single-line output: C0, DEL, and C1
/// control characters become `\n`-style or `\u{XX}` sequences, so a
/// hostile name cannot inject lines or terminal control sequences.
/// Clean strings pass through unchanged.
pub fn escape_str(s: &str) -> Cow<'_, str> {
    if !crate::paths::has_control(s) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if {
                let u = c as u32;
                u < 0x20 || (0x7F..=0x9F).contains(&u)
            } =>
            {
                out.push_str(&format!("\\u{{{:02X}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Formats an OS path for output, escaping control characters (see
/// [`escape_str`]). Canonical relative paths are control-free by
/// construction; this covers absolute paths, whose ancestors the user
/// does not always control (e.g. a cloned repository's directory name).
pub fn escape_path(p: &Path) -> String {
    escape_str(&p.to_string_lossy()).into_owned()
}

/// Sanitizes an opaque third-party error message (e.g. the TOML
/// parser's diagnostics, which quote the offending input): like
/// [`escape_str`], but newlines and tabs are preserved so multi-line
/// diagnostics stay readable.
pub fn escape_opaque(s: &str) -> Cow<'_, str> {
    if !s.chars().any(|c| {
        let u = c as u32;
        (u < 0x20 && c != '\n' && c != '\t') || (0x7F..=0x9F).contains(&u)
    }) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' => out.push_str("\\r"),
            '\n' | '\t' => out.push(c),
            c if {
                let u = c as u32;
                u < 0x20 || (0x7F..=0x9F).contains(&u)
            } =>
            {
                out.push_str(&format!("\\u{{{:02X}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_is_transparent_for_clean_strings() {
        let clean = "a dir/©.txt";
        assert!(matches!(escape_str(clean), Cow::Borrowed(_)));
        assert_eq!(escape_str(clean), clean);
    }

    #[test]
    fn escaping_neutralizes_injection() {
        assert_eq!(
            escape_str("evil\nFAILED fake.txt"),
            "evil\\nFAILED fake.txt"
        );
        assert_eq!(escape_str("a\rb\tc"), "a\\rb\\tc");
        assert_eq!(escape_str("x\u{1b}[31my"), "x\\u{1B}[31my");
        assert_eq!(escape_str("x\u{85}y"), "x\\u{85}y");
        assert_eq!(escape_path(Path::new("a\nb")), "a\\nb");
    }
}
