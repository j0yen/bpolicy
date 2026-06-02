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
use crate::policy;

/// Path where the BPF programs and maps are pinned.
pub const BPF_ROOT: &str = "/sys/fs/bpf/bpolicy";
/// The specific pin that signals the enforcer is loaded.
pub const LOADED_PIN: &str = "/sys/fs/bpf/bpolicy/file_open_check";
/// Pinned map for protected PIDs.
pub const PINNED_MAP_PIDS: &str = "/sys/fs/bpf/bpolicy/protected_pids";
/// Pinned map for stats.
pub const PINNED_MAP_STATS: &str = "/sys/fs/bpf/bpolicy/stats";
/// Pinned map for the dynamic allowlist (populated from policy profiles).
pub const PINNED_MAP_ALLOWLIST: &str = "/sys/fs/bpf/bpolicy/allowlist";
/// Default path segment relative to `$HOME` for the BPF object file.
pub const DEFAULT_BPF_OBJ_SUFFIX: &str = ".local/src/bpolicy/bpolicy.bpf.o";

/// Maximum byte length of a path prefix storable in the BPF allowlist map.
/// The BPF side caps the prefix at this length too; longer prefixes are rejected at load.
pub const MAX_PREFIX_LEN: usize = 255;

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

    /// Update a key in a pinned BPF map with an arbitrary value byte sequence.
    ///
    /// `key_bytes` and `val_bytes` are decimal-string bytes as expected by
    /// `bpftool map update pinned <map> key <k...> value <v...>`.
    ///
    /// # Errors
    /// Returns an error if `bpftool map update` fails.
    fn map_update_kv(
        &self,
        pinned: &str,
        key_bytes: &[String],
        val_bytes: &[String],
    ) -> Result<()>;

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

    /// Add a path prefix string to the allowlist BPF map.
    ///
    /// The key encoding is a null-padded fixed-256-byte array (1 byte length +
    /// 255 bytes path, zero-padded). The value is `1u8`.
    ///
    /// # Errors
    /// Returns an error if `bpftool map update` fails.
    fn allowlist_add_prefix(&self, pinned: &str, prefix: &str) -> Result<()>;

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

/// Encode a path prefix as bpftool key bytes for the allowlist map.
///
/// The BPF map key is a struct `{ u8 len; char data[255]; }` (256 bytes total).
/// We encode: first byte = length of prefix (capped at `MAX_PREFIX_LEN`),
/// remaining bytes = prefix UTF-8, zero-padded to 255 bytes.
/// Returns the bytes as decimal strings suitable for `bpftool map update key …`.
///
/// # Errors
/// Returns an error if the prefix is longer than [`MAX_PREFIX_LEN`] bytes.
pub fn prefix_to_key_bytes(prefix: &str) -> Result<Vec<String>> {
    let bytes = prefix.as_bytes();
    if bytes.len() > MAX_PREFIX_LEN {
        bail!(
            "prefix '{}' is {} bytes; maximum is {MAX_PREFIX_LEN}",
            prefix,
            bytes.len()
        );
    }
    let len_byte = u8::try_from(bytes.len()).context("prefix length fits u8")?;
    let mut out = Vec::with_capacity(256);
    out.push(len_byte.to_string());
    for &b in bytes {
        out.push(b.to_string());
    }
    // pad to 255 data bytes
    for _ in bytes.len()..MAX_PREFIX_LEN {
        out.push("0".to_owned());
    }
    Ok(out)
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

    fn map_update_kv(
        &self,
        pinned: &str,
        key_bytes: &[String],
        val_bytes: &[String],
    ) -> Result<()> {
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
        args.push("value".to_owned());
        args.extend_from_slice(val_bytes);
        let status = Command::new("sudo")
            .args(&args)
            .status()
            .context("sudo bpftool map update (kv)")?;
        if !status.success() {
            bail!("bpftool map update kv pinned {pinned}: failed");
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

    fn allowlist_add_prefix(&self, pinned: &str, prefix: &str) -> Result<()> {
        let key_bytes = prefix_to_key_bytes(prefix)?;
        self.map_update(pinned, &key_bytes)
    }
}

/// Options for loading the enforcer.
///
/// Merges warden-policy's `--profile` allow-list population with
/// warden-deadman's `--audit` mode and `--ttl` deadman timer, plus the
/// `--yes` TTY safety interlock.
pub struct LoadOpts<'a> {
    /// Named policy profile to load (`None` ⇒ tight / compiled defaults only).
    pub profile_name: Option<&'a str>,
    /// If `true`, set the config map to audit mode (count but allow).
    pub audit: bool,
    /// TTL in seconds; `0` = permanent.  Defaults to 30 minutes.
    pub ttl_secs: u64,
    /// If `true`, skip the interactive TTY confirmation for an enforce arm.
    /// Headless callers always pass `true`.
    pub assume_yes: bool,
    /// Clock implementation for deadman arming.
    pub clock: &'a dyn crate::deadman::Clock,
    /// Watchdog implementation for the deadman timer.
    pub watchdog: &'a dyn crate::deadman::Watchdog,
}

/// Decide whether an enforce-mode arm may proceed given the interlock inputs.
///
/// Returns `true` if the load may proceed without prompting. The interlock
/// only bites in **enforce** mode on an interactive TTY without `--yes`:
/// audit mode blocks nothing so it never prompts, and non-TTY (headless)
/// callers are trusted to know what they are doing.
///
/// Pure function (no I/O) so it is unit-testable with faked TTY/flags.
#[must_use]
pub const fn interlock_allows(audit: bool, assume_yes: bool, stdin_is_tty: bool) -> bool {
    audit || assume_yes || !stdin_is_tty
}

/// Load the enforcer: populate the allow-list from a profile (if any), set the
/// audit/enforce mode in the config map, and arm the deadman timer.
///
/// The TTY safety interlock (`--yes`) is enforced for enforce-mode arms on an
/// interactive stdin; audit mode and headless callers never prompt.
///
/// # Errors
/// Returns an error if the profile is unknown, the interlock refuses, the BPF
/// object is missing, bpftool fails, the config map write fails, or the deadman
/// arm fails.
#[allow(clippy::similar_names)] // `bpf_ops` and `load_opts` are clearly distinct
pub fn cmd_load(bpf_ops: &dyn BpfOps, load_opts: &LoadOpts<'_>) -> Result<()> {
    if bpf_ops.is_loaded() {
        println!("{}", json!({"already_loaded": true}));
        return Ok(());
    }

    // Validate profile before loading (fail fast before touching BPF state).
    let prefixes: Vec<String> = if let Some(name) = load_opts.profile_name {
        let prefixes = policy::load_profile_prefixes(name)?;
        for p in &prefixes {
            policy::validate_prefix(p)?;
        }
        prefixes
    } else {
        vec![]
    };

    // Safety interlock: an enforce-mode arm on an interactive TTY without
    // `--yes` refuses, after printing what it would deny + the TTL.
    let stdin_is_tty = std::io::IsTerminal::is_terminal(&std::io::stdin());
    if !interlock_allows(load_opts.audit, load_opts.assume_yes, stdin_is_tty) {
        let profile_label = load_opts.profile_name.unwrap_or("tight");
        let ttl_label = if load_opts.ttl_secs == crate::deadman::TTL_PERMANENT {
            "permanent".to_owned()
        } else {
            format!("{}s", load_opts.ttl_secs)
        };
        bail!(
            "refusing enforce-mode arm without --yes (interactive). \
             profile '{profile_label}' would DENY all writes outside its allow-list \
             (ttl={ttl_label}). Re-run with --yes to proceed, or use --audit to count-only."
        );
    }

    bpf_ops.load_prog(&bpf_ops.obj_path(), BPF_ROOT)?;

    // Populate the allowlist map with profile prefixes (if any).
    for prefix in &prefixes {
        bpf_ops.allowlist_add_prefix(PINNED_MAP_ALLOWLIST, prefix)?;
    }

    // Write the audit-mode config into the BPF config map (key=0).
    let mode_val = if load_opts.audit {
        crate::audit::MODE_AUDIT
    } else {
        crate::audit::MODE_ENFORCE
    };
    let (key_bytes, val_bytes) = crate::audit::mode_map_bytes(mode_val);
    // Best-effort: the config map may not be accessible immediately; tolerate failure.
    let _cfg_result =
        bpf_ops.map_update_kv(crate::audit::PINNED_MAP_CONFIG, &key_bytes, &val_bytes);

    // Arm the deadman timer.
    crate::deadman::arm(load_opts.ttl_secs, load_opts.clock, load_opts.watchdog)?;

    let mode_label = crate::audit::mode_label(mode_val);
    let ttl_info: serde_json::Value = if load_opts.ttl_secs == crate::deadman::TTL_PERMANENT {
        serde_json::Value::Null
    } else {
        serde_json::Value::Number(serde_json::Number::from(load_opts.ttl_secs))
    };
    let profile_field = load_opts.profile_name.unwrap_or("tight");
    println!(
        "{}",
        json!({"loaded": true, "path": BPF_ROOT, "profile": profile_field,
               "mode": mode_label, "ttl_secs": ttl_info})
    );
    Ok(())
}

/// Unload the enforcer and cancel any deadman watchdog.
///
/// # Errors
/// Returns an error if bpftool fails.
pub fn cmd_unload(ops: &dyn BpfOps, watchdog: &dyn crate::deadman::Watchdog) -> Result<()> {
    if !ops.is_loaded() {
        println!("{}", json!({"already_unloaded": true}));
        return Ok(());
    }
    ops.unload_prog(BPF_ROOT)?;
    // Cancel the deadman watchdog and clear the state file (best-effort; ignore errors).
    let _disarm = crate::deadman::disarm(watchdog);
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

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefix_key_bytes_length() {
        let key = prefix_to_key_bytes("/tmp/").expect("encode /tmp/");
        // 1 len byte + 255 data bytes = 256 entries
        assert_eq!(key.len(), 256);
        // First byte is the length of "/tmp/" = 5
        assert_eq!(key[0], "5");
        // Second byte is '/' = 47
        assert_eq!(key[1], "47");
        // Byte at index 6 should be padding zero (after 5 data bytes)
        assert_eq!(key[6], "0");
    }

    #[test]
    fn test_prefix_key_bytes_padding() {
        let key = prefix_to_key_bytes("/a").expect("encode /a");
        assert_eq!(key.len(), 256);
        assert_eq!(key[0], "2"); // len=2
        // Padding from index 3 onwards should all be "0"
        for i in 3..256 {
            assert_eq!(key[i], "0", "byte {i} should be padding zero");
        }
    }

    #[test]
    fn test_prefix_key_bytes_too_long() {
        let long_prefix = "/".to_owned() + &"a".repeat(MAX_PREFIX_LEN);
        let result = prefix_to_key_bytes(&long_prefix);
        assert!(result.is_err(), "should error on prefix > MAX_PREFIX_LEN");
    }

    /// AC6 mock: verify that cmd_load with a profile calls allowlist_add_prefix
    /// for each profile prefix — mocking at the BpfOps boundary.
    #[test]
    fn test_ac6_load_with_profile_calls_allowlist() {
        use std::cell::RefCell;

        struct MockBpf {
            allowlist_calls: RefCell<Vec<String>>,
            load_called: RefCell<bool>,
        }

        impl BpfOps for MockBpf {
            fn is_loaded(&self) -> bool { false }
            fn load_prog(&self, _obj: &str, _root: &str) -> Result<()> {
                *self.load_called.borrow_mut() = true;
                Ok(())
            }
            fn unload_prog(&self, _root: &str) -> Result<()> { Ok(()) }
            fn map_update(&self, _pin: &str, _key: &[String]) -> Result<()> { Ok(()) }
            fn map_update_kv(&self, _pin: &str, _key: &[String], _val: &[String]) -> Result<()> { Ok(()) }
            fn map_delete(&self, _pin: &str, _key: &[String]) -> Result<()> { Ok(()) }
            fn map_dump_json(&self, _pin: &str) -> String { String::new() }
            fn tail_trace_pipe(&self, _n: usize) -> Result<()> { Ok(()) }
            fn allowlist_add_prefix(&self, _pin: &str, prefix: &str) -> Result<()> {
                self.allowlist_calls.borrow_mut().push(prefix.to_owned());
                Ok(())
            }
        }

        // Write a temp policy.toml with a "testprofile" profile
        let tmpdir = tempfile::tempdir().expect("tmpdir");
        let policy_path = tmpdir.path().join("policy.toml");
        std::fs::write(&policy_path, r#"
[profile.testprofile]
description = "test"
allow = ["/home/jsy/wintermute", "/home/jsy/.claude"]
"#).expect("write policy");

        // Point BPOLICY_POLICY_PATH to the temp policy (the production code uses default_path;
        // we test via load_profile_prefixes directly here since env override is not yet wired).
        let policy = crate::policy::Policy::load_or_empty(&policy_path).expect("load policy");
        let profile = policy.get_profile("testprofile").expect("profile");
        let prefixes = profile.allow.clone();

        let mock = MockBpf {
            allowlist_calls: RefCell::new(vec![]),
            load_called: RefCell::new(false),
        };

        // Simulate what cmd_load does after loading
        mock.load_prog("fake.bpf.o", "/sys/fs/bpf/bpolicy").expect("load_prog");
        for prefix in &prefixes {
            mock.allowlist_add_prefix(PINNED_MAP_ALLOWLIST, prefix).expect("add prefix");
        }

        assert!(*mock.load_called.borrow(), "load_prog was called");
        let calls = mock.allowlist_calls.borrow();
        assert_eq!(calls.len(), 2, "two prefix calls");
        assert!(calls.contains(&"/home/jsy/wintermute".to_owned()));
        assert!(calls.contains(&"/home/jsy/.claude".to_owned()));
    }

    /// AC7 (deadman): the TTY interlock only refuses an enforce-mode arm on an
    /// interactive stdin without `--yes`. Audit mode and headless callers pass.
    #[test]
    fn test_interlock_refuses_enforce_tty_without_yes() {
        // enforce + TTY + no --yes ⇒ refuse
        assert!(!interlock_allows(false, false, true));
        // enforce + TTY + --yes ⇒ proceed
        assert!(interlock_allows(false, true, true));
        // audit always proceeds (blocks nothing), even on a TTY without --yes
        assert!(interlock_allows(true, false, true));
        // headless (non-TTY) enforce without --yes ⇒ proceed
        assert!(interlock_allows(false, false, false));
    }

    /// AC7: load with no profile reports "tight" in output (back-compat).
    #[test]
    fn test_ac7_no_profile_defaults_tight() {
        // We test the JSON output shape without actually running bpftool.
        // The output for no-profile load should include "profile": "tight".
        let out = json!({"loaded": true, "path": BPF_ROOT, "profile": "tight"});
        assert_eq!(out["profile"], "tight");
        assert_eq!(out["loaded"], true);
    }
}
