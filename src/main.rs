//! The `simple-file-encrypt` CLI: argument parsing and exit-code mapping.
//! Command semantics live in the library's `ops` module; the normative
//! specification is `docs/cli.md`.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

use simple_file_encrypt::crypto::KdfGate;
use simple_file_encrypt::{ops, report};

/// Encrypt and decrypt local files in place with a single password,
/// producing git-friendly (line-diffable, deterministic) ciphertext.
#[derive(Parser)]
#[command(name = "simple-file-encrypt", version, about, max_term_width = 100)]
struct Cli {
    /// Accept KDF parameters below the security floor.
    #[arg(long, global = true)]
    allow_weak_kdf: bool,
    /// Accept KDF parameters above the resource ceiling.
    #[arg(long, global = true)]
    allow_expensive_kdf: bool,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    fn gate(&self) -> KdfGate {
        KdfGate {
            allow_weak: self.allow_weak_kdf,
            allow_expensive: self.allow_expensive_kdf,
        }
    }
}

/// Argon2id parameter overrides shared by `init` and `passwd`.
#[derive(Args)]
struct KdfArgs {
    /// Argon2id memory cost in KiB.
    #[arg(long, value_name = "N")]
    memory_kib: Option<u64>,
    /// Argon2id pass count.
    #[arg(long, value_name = "N")]
    iterations: Option<u64>,
    /// Argon2id lane count.
    #[arg(long, value_name = "N")]
    parallelism: Option<u64>,
}

#[derive(Subcommand)]
enum Command {
    /// Create `.simple-file-encrypt.toml` in the current directory.
    Init {
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Encrypt managed files, or the given files/directories (auto-added).
    #[command(alias = "e")]
    Encrypt {
        /// Files or directories inside the domain; defaults to every managed path.
        paths: Vec<PathBuf>,
        /// Treat a probe hit that fails authentication as plaintext
        /// (explicitly named files only; dangerous).
        #[arg(long)]
        assume_plaintext: bool,
    },
    /// Decrypt managed files, or the given files/directories.
    #[command(alias = "d")]
    Decrypt {
        /// Files or directories inside the domain; defaults to every managed path.
        paths: Vec<PathBuf>,
        /// Hard-error on files that carry no ciphertext probe instead of skipping them.
        #[arg(long)]
        require_encrypted: bool,
    },
    /// Add paths to the managed list (no encryption, no password).
    Add {
        /// Files or directories inside the domain.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Also mark the paths as `force_binary` (always binary mode).
        #[arg(long)]
        binary: bool,
    },
    /// Remove exact entries from the managed list.
    Remove {
        /// Managed entries to remove.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Skip the still-encrypted refusal (the file becomes invisible to `rekey`).
        #[arg(long)]
        force: bool,
        /// Remove the paths from `force_binary` instead of the managed list.
        #[arg(long, conflicts_with = "force")]
        binary: bool,
    },
    /// Report the state of every managed file (no password).
    Status,
    /// Gate: exit 0 iff every existing target probes as encrypted (no password).
    Check {
        /// Files or directories to check instead of the managed list.
        paths: Vec<PathBuf>,
    },
    /// Fully authenticate ciphertext in memory without writing anything.
    Verify {
        /// Files or directories to verify instead of the managed list.
        paths: Vec<PathBuf>,
    },
    /// Change the password by re-wrapping the key ring (no ciphertext change).
    #[command(alias = "p")]
    Passwd {
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Rotate the domain key and migrate ciphertext to it in memory.
    Rekey {
        /// Resume an unfinished rotation instead of minting another key.
        #[arg(long = "continue", conflicts_with = "prune")]
        continue_: bool,
        /// Drop old ring entries once every managed encrypted file uses the current key.
        #[arg(long)]
        prune: bool,
    },
}

fn main() -> ExitCode {
    // Usage errors exit 1 like every other failure; clap's default exit
    // code 2 would collide with the check/verify "operational error".
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { 1 } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    let gate = cli.gate();

    // check/verify map every setup failure to exit 2 ("operational
    // error while checking"); other commands exit 1 on any failure.
    let scanned: Result<ops::ScanOutcome, simple_file_encrypt::Error> = match &cli.command {
        Command::Check { paths } => ops::check(paths),
        Command::Verify { paths } => ops::verify(paths, &gate),
        _ => {
            let result = match cli.command {
                Command::Init { kdf } => ops::init(&ops::InitOpts {
                    memory_kib: kdf.memory_kib,
                    iterations: kdf.iterations,
                    parallelism: kdf.parallelism,
                    gate,
                }),
                Command::Encrypt {
                    paths,
                    assume_plaintext,
                } => ops::encrypt(&ops::EncryptOpts {
                    paths,
                    assume_plaintext,
                    gate,
                }),
                Command::Decrypt {
                    paths,
                    require_encrypted,
                } => ops::decrypt(&ops::DecryptOpts {
                    paths,
                    require_encrypted,
                    gate,
                }),
                Command::Add { paths, binary } => ops::add(&paths, binary),
                Command::Remove {
                    paths,
                    force,
                    binary,
                } => ops::remove(&paths, force, binary),
                Command::Status => ops::status(),
                Command::Passwd { kdf } => ops::passwd(&ops::PasswdOpts {
                    memory_kib: kdf.memory_kib,
                    iterations: kdf.iterations,
                    parallelism: kdf.parallelism,
                    gate,
                }),
                Command::Rekey { continue_, prune } => {
                    let mode = if prune {
                        ops::RekeyMode::Prune
                    } else if continue_ {
                        ops::RekeyMode::Continue
                    } else {
                        ops::RekeyMode::Fresh
                    };
                    ops::rekey(mode, &gate)
                }
                Command::Check { .. } | Command::Verify { .. } => unreachable!("handled above"),
            };
            return match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    report::errline(format!("error: {e}"));
                    ExitCode::from(1)
                }
            };
        }
    };
    match scanned {
        Ok(outcome) => ExitCode::from(outcome.exit_code()),
        Err(e) => {
            report::errline(format!("error: {e}"));
            ExitCode::from(2)
        }
    }
}
