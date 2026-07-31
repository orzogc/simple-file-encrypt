//! Typed errors of the core library.
//!
//! The CLI boundary converts these into user-facing messages and exit
//! codes; integration tests match on variants and message fragments.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All failure modes of the core library.
#[derive(Debug)]
pub enum Error {
    /// An operating-system I/O failure, annotated with the path involved.
    Io {
        /// Human-readable operation, e.g. "reading".
        op: &'static str,
        /// The path the operation targeted.
        path: PathBuf,
        /// The underlying OS error.
        source: std::io::Error,
    },

    /// The domain config is missing, malformed, or fails validation.
    Config(String),

    /// The config (or ciphertext) was produced by a newer tool version.
    NewerVersion(String),

    /// A ciphertext file violates the wire format.
    Format {
        /// The offending file (canonical relative path).
        path: String,
        /// What was violated.
        msg: String,
    },

    /// Authentication failed on a ciphertext unit, marker, or file tag.
    Auth {
        /// The offending file (canonical relative path).
        path: String,
        /// Cause candidates, spelled out for the user.
        msg: String,
    },

    /// The password failed to unwrap the key ring.
    WrongPassword,

    /// Ring entries do not all unwrap under the same KEK.
    RingCorrupt {
        /// Index of the first entry that failed to unwrap.
        index: usize,
    },

    /// KDF parameters violate a validation tier.
    Kdf(String),

    /// Another simple-encrypt instance holds the domain lock.
    Locked {
        /// The domain root directory.
        root: PathBuf,
    },

    /// Password input failed (empty, over-long, unreadable, mismatch).
    Password(String),

    /// Command usage or target-selection error (outside domain, symlink
    /// argument, forbidden path, missing explicit target, ...).
    Usage(String),

    /// A hard resource limit was exceeded.
    Limit(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Paths are escaped against terminal/log injection; the
            // string payloads are built from canonical paths (already
            // control-free) or fixed text.
            Error::Io { op, path, source } => {
                write!(f, "{op} `{}`: {source}", crate::report::escape_path(path))
            }
            Error::Config(msg) => write!(f, "config error: {msg}"),
            Error::NewerVersion(msg) => write!(f, "{msg}; upgrade simple-encrypt"),
            Error::Format { path, msg } | Error::Auth { path, msg } => {
                write!(f, "`{}`: {msg}", crate::report::escape_str(path))
            }
            Error::WrongPassword => write!(
                f,
                "wrong password (or the config's salt/wrapped_keys were corrupted)"
            ),
            Error::RingCorrupt { index } => write!(
                f,
                "corrupt key ring: entry {index} does not unwrap under the same KEK as entry 0 \
                 (the config was tampered with or corrupted)"
            ),
            Error::Locked { root } => write!(
                f,
                "another simple-encrypt instance is running on `{}`",
                crate::report::escape_path(root)
            ),
            Error::Kdf(msg) | Error::Password(msg) | Error::Usage(msg) | Error::Limit(msg) => {
                write!(f, "{msg}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl Error {
    /// Builds an [`Error::Io`] with context.
    pub fn io(op: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            op,
            path: path.into(),
            source,
        }
    }

    /// Builds an [`Error::Format`] with context.
    pub fn format(path: impl Into<String>, msg: impl Into<String>) -> Self {
        Error::Format {
            path: path.into(),
            msg: msg.into(),
        }
    }

    /// Builds an [`Error::Auth`] with context.
    pub fn auth(path: impl Into<String>, msg: impl Into<String>) -> Self {
        Error::Auth {
            path: path.into(),
            msg: msg.into(),
        }
    }
}
