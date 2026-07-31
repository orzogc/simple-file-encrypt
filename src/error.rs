//! Typed errors of the core library.
//!
//! The CLI boundary converts these into user-facing messages and exit
//! codes; integration tests match on variants and message fragments.

use std::path::PathBuf;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// All failure modes of the core library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An operating-system I/O failure, annotated with the path involved.
    #[error("{op} `{path}`: {source}")]
    Io {
        /// Human-readable operation, e.g. "reading".
        op: &'static str,
        /// The path the operation targeted.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The domain config is missing, malformed, or fails validation.
    #[error("config error: {0}")]
    Config(String),

    /// The config (or ciphertext) was produced by a newer tool version.
    #[error("{0}; upgrade simple-encrypt")]
    NewerVersion(String),

    /// A ciphertext file violates the wire format.
    #[error("`{path}`: {msg}")]
    Format {
        /// The offending file (canonical relative path).
        path: String,
        /// What was violated.
        msg: String,
    },

    /// Authentication failed on a ciphertext unit, marker, or file tag.
    #[error("`{path}`: {msg}")]
    Auth {
        /// The offending file (canonical relative path).
        path: String,
        /// Cause candidates, spelled out for the user.
        msg: String,
    },

    /// The password failed to unwrap the key ring.
    #[error("wrong password (or the config's salt/wrapped_keys were corrupted)")]
    WrongPassword,

    /// Ring entries do not all unwrap under the same KEK.
    #[error(
        "corrupt key ring: entry {index} does not unwrap under the same KEK as entry 0 \
         (the config was tampered with or corrupted)"
    )]
    RingCorrupt {
        /// Index of the first entry that failed to unwrap.
        index: usize,
    },

    /// KDF parameters violate a validation tier.
    #[error("{0}")]
    Kdf(String),

    /// Another simple-encrypt instance holds the domain lock.
    #[error("another simple-encrypt instance is running on `{root}`")]
    Locked {
        /// The domain root directory.
        root: PathBuf,
    },

    /// Password input failed (empty, over-long, unreadable, mismatch).
    #[error("{0}")]
    Password(String),

    /// Command usage or target-selection error (outside domain, symlink
    /// argument, forbidden path, missing explicit target, ...).
    #[error("{0}")]
    Usage(String),

    /// A hard resource limit was exceeded.
    #[error("{0}")]
    Limit(String),
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
