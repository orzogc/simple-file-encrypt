//! Centralized user-facing output.
//!
//! Progress goes to stdout, warnings and notes to stderr, per
//! `docs/cli.md`. Keeping the printing here makes the lint exceptions
//! explicit and the output format easy to keep stable.

/// Prints a progress line to stdout.
#[expect(
    clippy::print_stdout,
    reason = "designated user-facing progress output"
)]
pub fn out(msg: impl AsRef<str>) {
    println!("{}", msg.as_ref());
}

/// Prints a warning line to stderr.
#[expect(clippy::print_stderr, reason = "designated user-facing warning output")]
pub fn warn(msg: impl AsRef<str>) {
    eprintln!("warning: {}", msg.as_ref());
}

/// Prints a note line to stderr (informational, not a warning).
#[expect(clippy::print_stderr, reason = "designated user-facing note output")]
pub fn note(msg: impl AsRef<str>) {
    eprintln!("note: {}", msg.as_ref());
}

/// Prints a raw line to stderr (error reports, prompts context).
#[expect(clippy::print_stderr, reason = "designated user-facing error output")]
pub fn errline(msg: impl AsRef<str>) {
    eprintln!("{}", msg.as_ref());
}
