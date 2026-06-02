//! bpolicy — userspace control-plane CLI for the BPF-LSM `file_open` enforcer.
//!
//! Subcommands: load, unload, enforce, release, status, log
//!
//! All privileged operations (`sudo -n bpftool …`) are isolated in [`bpolicy::bpf`]
//! behind the [`bpolicy::bpf::BpfOps`] trait so tests can inject a mock without
//! ever invoking sudo.

#![allow(clippy::print_stderr)] // CLI entry-point: stderr for fatal errors is intentional

use anyhow::Result;
use bpolicy::bpf::{self, BpfOps, SystemBpf};
use bpolicy::status;
use clap::{Parser, Subcommand};

/// Userspace control for the BPF-LSM `file_open` enforcer.
#[derive(Parser, Debug)]
#[command(name = "bpolicy", version, about, long_about = None)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Commands,
}

/// Available subcommands.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Load and auto-attach the BPF object, pin maps under `/sys/fs/bpf/bpolicy`.
    Load,
    /// Detach and remove all pins under `/sys/fs/bpf/bpolicy`.
    Unload,
    /// Add PIDs to the protected set.
    Enforce {
        /// PID(s) to add (repeatable).
        #[arg(long, required = true)]
        pid: Vec<u32>,
    },
    /// Remove PIDs from the protected set.
    Release {
        /// PID(s) to remove (repeatable).
        #[arg(long, required = true)]
        pid: Vec<u32>,
    },
    /// Print the current enforcer status as JSON.
    Status,
    /// Tail the kernel `trace_pipe` for bpolicy lines.
    Log {
        /// Stop after N lines (0 = tail forever).
        #[arg(short = 'n', default_value = "0")]
        n: usize,
    },
}

fn run(ops: &dyn BpfOps) -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Load => bpf::cmd_load(ops),
        Commands::Unload => bpf::cmd_unload(ops),
        Commands::Enforce { pid } => bpf::cmd_enforce(ops, &pid),
        Commands::Release { pid } => bpf::cmd_release(ops, &pid),
        Commands::Status => status::cmd_status(ops),
        Commands::Log { n } => bpf::cmd_log(ops, n),
    }
}

fn main() {
    let ops = SystemBpf::new();
    if let Err(e) = run(&ops) {
        eprintln!("bpolicy: {e}");
        std::process::exit(1);
    }
}
