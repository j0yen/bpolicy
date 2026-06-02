//! bpolicy — userspace control-plane CLI for the BPF-LSM `file_open` enforcer.
//!
//! Subcommands: load, unload, enforce, release, status, log, policy, renew
//!
//! All privileged operations (`sudo -n bpftool …`) are isolated in [`bpolicy::bpf`]
//! behind the [`bpolicy::bpf::BpfOps`] trait so tests can inject a mock without
//! ever invoking sudo.

#![allow(clippy::print_stderr)] // CLI entry-point: stderr for fatal errors is intentional

use anyhow::Result;
use bpolicy::bpf::{self, BpfOps, LoadOpts, SystemBpf};
use bpolicy::deadman::{SystemClock, SystemdWatchdog, DEFAULT_TTL_SECS, TTL_PERMANENT};
use bpolicy::policy;
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
    /// Load and auto-attach the BPF object, optionally with a named policy profile.
    Load {
        /// Named policy profile to load (default: tight — compiled defaults only).
        ///
        /// The profile must be defined in `~/.config/bpolicy/policy.toml`.
        /// Use `bpolicy policy show` to inspect what prefixes a profile adds.
        #[arg(long)]
        profile: Option<String>,
        /// Enable audit mode: evaluate but never block (log/count only).
        /// Audit mode never prompts (it blocks nothing).
        #[arg(long)]
        audit: bool,
        /// Deadman TTL in seconds (0 = permanent arm; default = 1800 = 30m).
        /// A bare `load` defaults to 30m so a bad arm self-heals.
        #[arg(long, default_value_t = DEFAULT_TTL_SECS)]
        ttl: u64,
        /// Proceed with an enforce-mode arm without the interactive confirmation.
        /// Required for an enforce arm on a TTY; headless callers should pass it.
        #[arg(long)]
        yes: bool,
    },
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
    /// Inspect and validate policy profiles.
    Policy {
        /// The policy sub-action to run.
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
    /// Renew the deadman timer, pushing `expires_at` forward.
    ///
    /// Call periodically to keep the enforcer alive. If the timer expires
    /// without a `renew`, `bpolicy unload` is called automatically.
    Renew {
        /// New TTL in seconds (0 = keep existing TTL).
        #[arg(long, default_value_t = 0)]
        ttl: u64,
    },
}

/// Sub-subcommands for `bpolicy policy`.
#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Print the resolved allow-list (defaults + profile prefixes) as JSON.
    Show {
        /// Profile to show (default: tight — compiled defaults only).
        #[arg(long)]
        profile: Option<String>,
    },
    /// Answer "would a write to this path be allowed?" for a profile (no BPF interaction).
    Check {
        /// The path to evaluate.
        path: String,
        /// Profile to check against (default: tight).
        #[arg(long)]
        profile: Option<String>,
    },
}

fn run(ops: &dyn BpfOps) -> Result<()> {
    let clock = SystemClock;
    let watchdog = SystemdWatchdog;
    let cli = Cli::parse();
    match cli.command {
        Commands::Load {
            profile,
            audit,
            ttl,
            yes,
        } => {
            let load_opts = LoadOpts {
                profile_name: profile.as_deref(),
                audit,
                ttl_secs: ttl,
                assume_yes: yes,
                clock: &clock,
                watchdog: &watchdog,
            };
            bpf::cmd_load(ops, &load_opts)
        }
        Commands::Unload => bpf::cmd_unload(ops, &watchdog),
        Commands::Enforce { pid } => bpf::cmd_enforce(ops, &pid),
        Commands::Release { pid } => bpf::cmd_release(ops, &pid),
        Commands::Status => status::cmd_status(ops),
        Commands::Log { n } => bpf::cmd_log(ops, n),
        Commands::Policy { cmd } => match cmd {
            PolicyCmd::Show { profile } => policy::cmd_policy_show(profile.as_deref()),
            PolicyCmd::Check { path, profile } => {
                policy::cmd_policy_check(&path, profile.as_deref())
            }
        },
        Commands::Renew { ttl } => {
            let ttl_opt = if ttl == TTL_PERMANENT { None } else { Some(ttl) };
            bpolicy::deadman::renew(ttl_opt, &clock, &watchdog)
        }
    }
}

fn main() {
    let ops = SystemBpf::new();
    if let Err(e) = run(&ops) {
        eprintln!("bpolicy: {e}");
        std::process::exit(1);
    }
}
