//! Internal library of the `simple-file-encrypt` binary.
//!
//! The modules are `pub` only so the integration tests and the binary
//! share one implementation; depending on this crate as a library is
//! unsupported and every module may change without notice. The
//! normative specification lives in the repository's `docs/` directory:
//! <https://github.com/orzogc/simple-file-encrypt/tree/main/docs>.

pub mod binmode;
pub mod config;
pub mod consts;
pub mod crypto;
pub mod error;
pub mod fsops;
pub mod hexutil;
pub mod ops;
pub mod paths;
pub mod probe;
pub mod pwinput;
pub mod report;
pub mod select;
pub mod textmode;

pub use error::{Error, Result};
