//! Password input: environment variable, interactive no-echo prompt, or
//! stdin lines, in that priority order (see `docs/cli.md`).

use std::io::{BufRead, IsTerminal, Write};

use zeroize::{Zeroize, Zeroizing};

use crate::consts::{ENV_NEW_PASSWORD, ENV_PASSWORD, MAX_PASSWORD_LEN};
use crate::error::{Error, Result};

/// Validates a password: UTF-8 (by construction), non-empty, at most
/// 4096 bytes. The bytes are used exactly as supplied — no Unicode
/// normalization.
fn validate(pw: Zeroizing<String>, what: &str) -> Result<Zeroizing<String>> {
    if pw.is_empty() {
        return Err(Error::Password(format!("{what} must not be empty")));
    }
    if pw.len() > MAX_PASSWORD_LEN {
        return Err(Error::Password(format!(
            "{what} exceeds {MAX_PASSWORD_LEN} bytes"
        )));
    }
    Ok(pw)
}

/// Reads one password from the environment variable `env`, else an
/// interactive no-echo prompt (twice when `confirm` names a second
/// prompt), else the next line of stdin.
pub fn read_password(
    env: &str,
    prompt: &str,
    confirm: Option<&str>,
    what: &str,
) -> Result<Zeroizing<String>> {
    if let Some(var) = std::env::var_os(env) {
        let pw = var
            .into_string()
            .map_err(|_| Error::Password(format!("{env} is not valid UTF-8")))?;
        return validate(Zeroizing::new(pw), what);
    }
    if std::io::stdin().is_terminal() {
        let first = validate(prompt_tty(prompt)?, what)?;
        if let Some(confirm_prompt) = confirm {
            let second = prompt_tty(confirm_prompt)?;
            if *first != *second {
                return Err(Error::Password("passwords do not match".into()));
            }
        }
        return Ok(first);
    }
    validate(read_stdin_line(what)?, what)
}

/// Reads the primary password: `SIMPLE_ENCRYPT_PASSWORD`, prompt, or the
/// next stdin line.
pub fn primary(confirm_on_tty: bool) -> Result<Zeroizing<String>> {
    let confirm = if confirm_on_tty {
        Some("Confirm password: ")
    } else {
        None
    };
    read_password(ENV_PASSWORD, "Password: ", confirm, "password")
}

/// Reads `passwd`'s old password (never confirmed).
pub fn old_password() -> Result<Zeroizing<String>> {
    read_password(ENV_PASSWORD, "Old password: ", None, "old password")
}

/// Reads `passwd`'s new password: `SIMPLE_ENCRYPT_NEW_PASSWORD`, prompt
/// twice, or the next stdin line.
pub fn new_password() -> Result<Zeroizing<String>> {
    read_password(
        ENV_NEW_PASSWORD,
        "New password: ",
        Some("Confirm new password: "),
        "new password",
    )
}

/// Prompts on stderr and reads without echo from the TTY.
#[expect(
    clippy::print_stderr,
    reason = "interactive prompt must reach the terminal"
)]
fn prompt_tty(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let pw = rpassword::read_password()
        .map_err(|e| Error::Password(format!("cannot read password: {e}")))?;
    Ok(Zeroizing::new(pw))
}

/// Reads the next line from (non-TTY) stdin, stripping the trailing
/// newline; no confirmation.
fn read_stdin_line(what: &str) -> Result<Zeroizing<String>> {
    let mut line = String::new();
    let n = std::io::stdin().lock().read_line(&mut line).map_err(|e| {
        line.zeroize();
        Error::Password(format!("cannot read {what} from stdin: {e}"))
    })?;
    let mut line = Zeroizing::new(line);
    if n == 0 {
        return Err(Error::Password(format!(
            "no {what} available: stdin is exhausted"
        )));
    }
    if line.ends_with('\n') {
        line.pop();
    }
    Ok(line)
}
