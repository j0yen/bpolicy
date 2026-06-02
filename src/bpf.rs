//! BPF operation wrappers.
//!
//! All privileged operations (`sudo -n bpftool …`) are isolated behind the
//! [`BpfOps`] trait.  Production code uses [`SystemBpf`]; tests inject a mock.
//!
//! The command structure mirrors the Python script exactly so the JSON output
//! is byte-for-byte compatible.

#![allow(clippy::print_stdout)] // CLI: stdout output is intentional for all cmd_* functions

use anyhow::{bail, Context, Result};
use serde_json::json;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

use crate::pids::pid_to_key_bytes;

/// Path where the BPF programs and maps are pinned.
pub const BPF_ROOT: &str = "/sys/fs/bpf/bpolicy";
/// The specific pin that signals the enforcer is loaded.
pub const LOADED_PIN: &str = "/sys/fs/bpf/bpolicy/file_open_check";
/// Pinned map for protected PIDs.
pub const PINNED_MAP_PIDS: &str = "/sys/fs/bpf/bpolicy/protected_pids";
/// Pinned map for stats.
pub const PINNED_MAP_STATS: &str = "/sys/fs/bpf/bpolicy/stats";
/// Default path segment relative to `$HOME` for the BPF object file.
pub const DEFAULT_BPF_OBJ_SUFFIX: &str = ".local/src/bpolicy/bpolicy.bpf.o";

/// Trait abstracting all privileged / external operations.
///
/// Implementations: [`SystemBpf`] (production), mocks in tests.
pub trait BpfOps {
    /// Returns `true` if the enforcer's pin exists (i.e., is loaded).
    fn is_loaded(&self) -> bool;

    /// Load the BPF object at `obj_path` into `bpf_root`.
    ///
    /// # Errors
    /// Returns an error if `mkdir -p` or `bpftool prog loadall` fails.
    fn load_prog(&self, obj_path: &str, bpf_root: &str) -> Result<()>;

    /// Remove `bpf_root` recursively (unload).
    ///
    /// # Errors
    /// Returns an error if `sudo rm -rf` fails.
    fn unload_prog(&self, bpf_root: &str) -> Result<()>;

    /// Update a key in a pinned BPF map with value `1`.
    ///
    /// # Errors
    /// Returns an error if `bpftool map update` fails.
    fn map_update(&self, pinned: &str, key_bytes: &[String]) -> Result<()>;

    /// Delete a key from a pinned BPF map (best-effort, no error if missing).
    ///
    /// # Errors
    /// Returns an error if spawning the subprocess fails entirely.
    fn map_delete(&self, pinned: &str, key_bytes: &[String]) -> Result<()>;

    /// Dump a pinned BPF map as JSON string (returns empty string on failure).
    fn map_dump_json(&self, pinned: &str) -> String;

    /// Tail the kernel `trace_pipe`, yielding lines matching "bpolicy", up to `n`
    /// lines (0 = infinite). Writes directly to stdout.
    ///
    /// # Errors
    /// Returns an error if `sudo cat trace_pipe` cannot be spawned.
    fn tail_trace_pipe(&self, n: usize) -> Result<()>;

    /// Return the path to the BPF object file to load.
    ///
    /// Default: respects `BPOLICY_OBJ` env var, falls back to
    /// `$HOME/.local/src/bpolicy/bpolicy.bpf.o`.
    fn obj_path(&self) -> String {
        std::env::var("BPOLICY_OBJ").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
            std::path::PathBuf::from(home)
                .join(DEFAULT_BPF_OBJ_SUFFIX)
                .to_string_lossy()
                .into_owned()
        })
    }
}

/// Production implementation that shells out to `sudo -n bpftool`.
pub struct SystemBpf;

impl SystemBpf {
    /// Construct a new `SystemBpf`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SystemBpf {
    fn default() -> Self {
        Self::new()
    }
}

impl BpfOps for SystemBpf {
    fn is_loaded(&self) -> bool {
        // /sys/fs/bpf is mode 1700 root:root — use sudo -n test -e
        Command::new("sudo")
            .args(["-n", "test", "-e", LOADED_PIN])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn load_prog(&self, obj_path: &str, bpf_root: &str) -> Result<()> {
        let status = Command::new("sudo")
            .args(["-n", "mkdir", "-p", bpf_root])
            .status()
            .context("sudo mkdir -p")?;
        if !status.success() {
            bail!("sudo mkdir -p {bpf_root}: failed");
        }
        let status = Command::new("sudo")
            .args([
                "-n", "bpftool", "prog", "loadall",
                obj_path, bpf_root, "autoattach", "pinmaps", bpf_root,
            ])
            .status()
            .context("sudo bpftool prog loadall")?;
        if !status.success() {
            bail!("bpftool prog loadall failed");
        }
        Ok(())
    }

    fn unload_prog(&self, bpf_root: &str) -> Result<()> {
        let status = Command::new("sudo")
            .args(["-n", "rm", "-rf", bpf_root])
            .status()
            .context("sudo rm -rf")?;
        if !status.success() {
            bail!("sudo rm -rf {bpf_root}: failed");
        }
        Ok(())
    }

    fn map_update(&self, pinned: &str, key_bytes: &[String]) -> Result<()> {
        let mut args = vec![
            "-n".to_owned(),
            "bpftool".to_owned(),
            "map".to_owned(),
            "update".to_owned(),
            "pinned".to_owned(),
            pinned.to_owned(),
            "key".to_owned(),
        ];
        args.extend_from_slice(key_bytes);
        args.extend_from_slice(&["value".to_owned(), "1".to_owned()]);

        let status = Command::new("sudo")
            .args(&args)
            .status()
            .context("sudo bpftool map update")?;
        if !status.success() {
            bail!("bpftool map update pinned {pinned}: failed");
        }
        Ok(())
    }

    fn map_delete(&self, pinned: &str, key_bytes: &[String]) -> Result<()> {
        let mut args = vec![
            "-n".to_owned(),
            "bpftool".to_owned(),
            "map".to_owned(),
            "delete".to_owned(),
            "pinned".to_owned(),
            pinned.to_owned(),
            "key".to_owned(),
        ];
        args.extend_from_slice(key_bytes);
        // best-effort: ignore exit code (key may not exist)
        let _ = Command::new("sudo").args(&args).status();
        Ok(())
    }

    fn map_dump_json(&self, pinned: &str) -> String {
        Command::new("sudo")
            .args(["-n", "bpftool", "-j", "map", "dump", "pinned", pinned])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    fn tail_trace_pipe(&self, n: usize) -> Result<()> {
        let mut child = Command::new("sudo")
            .args(["-n", "cat", "/sys/kernel/tracing/trace_pipe"])
            .stdout(Stdio::piped())
            .spawn()
            .context("sudo cat trace_pipe")?;

        let stdout = child.stdout.take().context("trace_pipe stdout")?;
        let reader = BufReader::new(stdout);
        let mut count = 0usize;

        for line in reader.lines() {
            match line {
                Ok(l) if l.contains("bpolicy") => {
                    println!("{l}");
                    count += 1;
                    if n > 0 && count >= n {
                        let _ = child.kill();
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }
}

/// Load the enforcer.
///
/// # Errors
/// Returns an error if the BPF object is missing or bpftool fails.
pub fn cmd_load(ops: &dyn BpfOps) -> Result<()> {
    if ops.is_loaded() {
        println!("{}", json!({"already_loaded": true}));
        return Ok(());
    }
    ops.load_prog(&ops.obj_path(), BPF_ROOT)?;
    println!("{}", json!({"loaded": true, "path": BPF_ROOT}));
    Ok(())
}

/// Unload the enforcer.
///
/// # Errors
/// Returns an error if bpftool fails.
pub fn cmd_unload(ops: &dyn BpfOps) -> Result<()> {
    if !ops.is_loaded() {
        println!("{}", json!({"already_unloaded": true}));
        return Ok(());
    }
    ops.unload_prog(BPF_ROOT)?;
    println!("{}", json!({"unloaded": true}));
    Ok(())
}

/// Enforce write restrictions on a set of PIDs.
///
/// # Errors
/// Returns an error if the enforcer is not loaded or if bpftool fails.
pub fn cmd_enforce(ops: &dyn BpfOps, pids: &[u32]) -> Result<()> {
    if !ops.is_loaded() {
        bail!("bpolicy not loaded — run: bpolicy load");
    }
    for &pid in pids {
        let key = pid_to_key_bytes(pid);
        ops.map_update(PINNED_MAP_PIDS, &key)?;
    }
    println!("{}", json!({"enforcing": pids}));
    Ok(())
}

/// Release write restrictions from a set of PIDs.
///
/// # Errors
/// Returns an error if the enforcer is not loaded or if bpftool fails.
pub fn cmd_release(ops: &dyn BpfOps, pids: &[u32]) -> Result<()> {
    if !ops.is_loaded() {
        bail!("bpolicy not loaded — run: bpolicy load");
    }
    for &pid in pids {
        let key = pid_to_key_bytes(pid);
        ops.map_delete(PINNED_MAP_PIDS, &key)?;
    }
    println!("{}", json!({"released": pids}));
    Ok(())
}

/// Tail the kernel `trace_pipe` for bpolicy lines.
///
/// # Errors
/// Returns an error if the `trace_pipe` cannot be accessed.
pub fn cmd_log(ops: &dyn BpfOps, n: usize) -> Result<()> {
    ops.tail_trace_pipe(n)
}
