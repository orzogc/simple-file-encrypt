//! Internal library of the `simple-encrypt` binary.
//!
//! This crate-internal API exists so integration tests can drive the same
//! code paths as the CLI. It is not a public library and carries no
//! stability promise. The normative specification lives in `docs/`.

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
